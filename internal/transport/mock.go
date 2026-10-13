// Package transport provides a TLS-only, outbound HTTPS mock command transport.
// It is test infrastructure, not a deployable internet-facing device gateway.
package transport

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/broker"
 "github.com/SanamRai001/localReach/internal/gateway"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/integration"
 "github.com/SanamRai001/localReach/internal/journal"
 "github.com/SanamRai001/localReach/internal/session"
)

type Server struct {
 Registry *identity.Registry
 Sessions *session.Manager
 Broker *broker.Broker
}
// New returns an HTTP handler that refuses requests unless TLS is active.
// Broker calls derive tenant scope from the authenticated agent registry.
func New(s Server) http.Handler {
 control:=gateway.New(s.Sessions)
 mux:=http.NewServeMux()
 mux.Handle("/v1/agent/challenge",control)
 mux.Handle("/v1/agent/session",control)
 mux.Handle("/v1/agent/heartbeat",control)
 authorized:=func(w http.ResponseWriter,r *http.Request)(identity.Agent,bool){
  id:=r.Header.Get("X-LocalReach-Agent-ID")
  auth:=r.Header.Get("Authorization")
  if id==""||!strings.HasPrefix(auth,"Bearer ")||s.Sessions.Authorize(id,strings.TrimPrefix(auth,"Bearer "))!=nil{
   http.Error(w,"denied",http.StatusForbidden);return identity.Agent{},false
  }
  agent,ok:=s.Registry.Lookup(id)
  if !ok||agent.Revoked{http.Error(w,"denied",http.StatusForbidden);return identity.Agent{},false}
  return agent,true
 }
 mux.HandleFunc("/v1/agent/claim",func(w http.ResponseWriter,r *http.Request){
  if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
  agent,ok:=authorized(w,r);if !ok{return}
  c,found,err:=s.Broker.Claim(agent.TenantID,agent.ID,20*time.Second)
  if err!=nil{http.Error(w,"unavailable",503);return}
  if !found{w.WriteHeader(http.StatusNoContent);return}
  reply(w,c)
 })
 mux.HandleFunc("/v1/agent/received",func(w http.ResponseWriter,r *http.Request){
  if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
  agent,ok:=authorized(w,r);if !ok{return}
  var p struct{ID string `json:"id"`; Lease string `json:"lease"`}
  if !parse(w,r,&p){return}
  if err:=s.Broker.Receive(p.ID,agent.TenantID,agent.ID,p.Lease);err!=nil{http.Error(w,"conflict",409);return}
  w.WriteHeader(http.StatusNoContent)
 })
 mux.HandleFunc("/v1/agent/complete",func(w http.ResponseWriter,r *http.Request){
  if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
  agent,ok:=authorized(w,r);if !ok{return}
  var p struct{ID string `json:"id"`;Lease string `json:"lease"`;State broker.State `json:"state"`;Result string `json:"result"`}
  if !parse(w,r,&p){return}
  if err:=s.Broker.Complete(p.ID,agent.TenantID,agent.ID,p.Lease,p.State,p.Result);err!=nil{http.Error(w,"conflict",409);return}
  w.WriteHeader(http.StatusNoContent)
 })
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  if r.TLS==nil{http.Error(w,"TLS required",426);return}
  mux.ServeHTTP(w,r)
 })
}
func parse(w http.ResponseWriter,r *http.Request,v any)bool {
 if r.Header.Get("Content-Type")!="application/json"{http.Error(w,"content type",415);return false}
 d:=json.NewDecoder(http.MaxBytesReader(w,r.Body,2048));d.DisallowUnknownFields()
 if d.Decode(v)!=nil{http.Error(w,"invalid body",400);return false}
 var extra any
 if d.Decode(&extra)!=io.EOF{http.Error(w,"trailing body",400);return false}
 return true
}
func reply(w http.ResponseWriter,v any){w.Header().Set("Content-Type","application/json");_ =json.NewEncoder(w).Encode(v)}
type Agent struct {
 Identity integration.Client
 Journal *journal.Journal
}
func(a Agent) request(ctx context.Context,path string,token string,payload any,result any)(int,error){
 if !strings.HasPrefix(a.Identity.BaseURL,"https://"){return 0,errors.New("HTTPS required")}
 body,err:=json.Marshal(payload);if err!=nil{return 0,err}
 req,err:=http.NewRequestWithContext(ctx,"POST",a.Identity.BaseURL+path,bytes.NewReader(body));if err!=nil{return 0,err}
 req.Header.Set("Content-Type","application/json")
 req.Header.Set("Authorization","Bearer "+token)
 req.Header.Set("X-LocalReach-Agent-ID",a.Identity.AgentID)
 c:=a.Identity.HTTP;if c==nil{c=http.DefaultClient}
 res,err:=c.Do(req);if err!=nil{return 0,err}
 defer res.Body.Close()
 if res.StatusCode==200&&result!=nil{
  if err=json.NewDecoder(io.LimitReader(res.Body,4096)).Decode(result);err!=nil{return res.StatusCode,err}
 }
 return res.StatusCode,nil
}
// PollOnce connects OUTBOUND, claims only mock.ping and journals before effect.
// A failed acknowledgement never causes automatic re-execution.
func(a Agent)PollOnce(ctx context.Context)(bool,error){
 if a.Journal==nil{return false,errors.New("journal required")}
 token,err:=a.Identity.Handshake(ctx);if err!=nil{return false,err}
 var cmd broker.Command
 status,err:=a.request(ctx,"/v1/agent/claim",token,map[string]string{},&cmd)
 if err!=nil{return false,err}
 if status==204{return false,nil}
 if status!=200{return false,fmt.Errorf("claim status %d",status)}
 if cmd.ID==""||cmd.Operation!="mock.ping"{return true,errors.New("unexpected command")}
 if err=a.Journal.Submit(cmd.ID,cmd.Operation);err!=nil{return true,fmt.Errorf("journal refused duplicate or failed write: %w",err)}
 status,err=a.request(ctx,"/v1/agent/received",token,map[string]string{"id":cmd.ID,"lease":cmd.Lease},nil)
 if err!=nil{return true,err}
 if status!=204{return true,fmt.Errorf("receive status %d",status)}
 if err=a.Journal.Begin(cmd.ID);err!=nil{return true,err}
 if err=a.Journal.Finish(cmd.ID,journal.Succeeded,"pong");err!=nil{return true,err}
 status,err=a.request(ctx,"/v1/agent/complete",token,map[string]string{"id":cmd.ID,"lease":cmd.Lease,"state":"SUCCEEDED","result":"pong"},nil)
 if err!=nil{return true,err}
 if status!=204{return true,fmt.Errorf("completion status %d; do not reexecute",status)}
 return true,nil
}
