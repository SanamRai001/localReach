// LocalReach R1A is a local-only, disposable mock transport experiment.
// It does not implement production enrollment, TLS termination, or durable jobs.
package main

import (
 "context"
 "crypto/subtle"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "log"
 "net"
 "net/http"
 "os"
 "os/signal"
 "strings"
 "sync"
 "syscall"
 "time"
)

type Job struct {
 ID string `json:"id"`
 Operation string `json:"operation"`
 State string `json:"state"`
 Result string `json:"result,omitempty"`
}
type relay struct {
 mu sync.Mutex
 seq uint64
 jobs map[string]*Job
 pending []string
}
func newRelay()*relay{return &relay{jobs:map[string]*Job{}}}
func (r *relay) submit() Job {
 r.mu.Lock();defer r.mu.Unlock()
 r.seq++
 id:=fmt.Sprintf("mock-%d",r.seq)
 j:= &Job{ID:id,Operation:"mock.ping",State:"QUEUED"}
 r.jobs[id]=j;r.pending=append(r.pending,id)
 return *j
}
func (r *relay) next() (Job,bool){
 r.mu.Lock();defer r.mu.Unlock()
 if len(r.pending)==0{return Job{},false}
 id:=r.pending[0];r.pending=r.pending[1:]
 j:=r.jobs[id];j.State="DISPATCHED"
 return *j,true
}
func (r *relay) complete(id, result string) error {
 r.mu.Lock();defer r.mu.Unlock()
 j,ok:=r.jobs[id]
 if !ok{return errors.New("unknown job")}
 if j.State!="DISPATCHED"{return errors.New("invalid job transition")}
 j.State="SUCCEEDED";j.Result=result
 return nil
}
func (r *relay) get(id string)(Job,bool){
 r.mu.Lock();defer r.mu.Unlock()
 j,ok:=r.jobs[id];if !ok{return Job{},false}
 return *j,true
}
func handler(r *relay, token string) http.Handler {
 mux:=http.NewServeMux()
 mux.HandleFunc("/healthz",func(w http.ResponseWriter,_ *http.Request){w.Write([]byte("ok"))})
 secure:=func(next http.HandlerFunc)http.HandlerFunc{return func(w http.ResponseWriter,req *http.Request){
  h:=req.Header.Get("Authorization")
  expected:="Bearer "+token
  if subtle.ConstantTimeCompare([]byte(h),[]byte(expected))!=1{http.Error(w,"unauthorized",http.StatusUnauthorized);return}
  next(w,req)
 }}
 mux.HandleFunc("/v1/mock/jobs",secure(func(w http.ResponseWriter,req *http.Request){
  if req.Method!=http.MethodPost{http.Error(w,"method not allowed",405);return}
  if req.ContentLength>1024{http.Error(w,"payload too large",413);return}
  defer req.Body.Close()
  var payload struct{Operation string `json:"operation"`}
  d:=json.NewDecoder(http.MaxBytesReader(w,req.Body,1024));d.DisallowUnknownFields()
  if err:=d.Decode(&payload);err!=nil||payload.Operation!="mock.ping"{http.Error(w,"only mock.ping supported",400);return}
  w.Header().Set("Content-Type","application/json");w.WriteHeader(202);json.NewEncoder(w).Encode(r.submit())
 }))
 mux.HandleFunc("/v1/mock/jobs/",secure(func(w http.ResponseWriter,req *http.Request){
  if req.Method!=http.MethodGet{http.Error(w,"method not allowed",405);return}
  id:=strings.TrimPrefix(req.URL.Path,"/v1/mock/jobs/")
  j,ok:=r.get(id);if !ok{http.NotFound(w,req);return}
  w.Header().Set("Content-Type","application/json");json.NewEncoder(w).Encode(j)
 }))
 mux.HandleFunc("/v1/agent/next",secure(func(w http.ResponseWriter,req *http.Request){
  if req.Method!=http.MethodGet{http.Error(w,"method not allowed",405);return}
  j,ok:=r.next();if !ok{w.WriteHeader(204);return}
  w.Header().Set("Content-Type","application/json");json.NewEncoder(w).Encode(j)
 }))
 mux.HandleFunc("/v1/agent/complete",secure(func(w http.ResponseWriter,req *http.Request){
  if req.Method!=http.MethodPost{http.Error(w,"method not allowed",405);return}
  var p struct{ID string `json:"id"`;Result string `json:"result"`}
  err:=json.NewDecoder(http.MaxBytesReader(w,req.Body,1024)).Decode(&p)
  if err!=nil||p.Result!="pong"{http.Error(w,"bad completion",400);return}
  if err=r.complete(p.ID,p.Result);err!=nil{http.Error(w,err.Error(),409);return}
  w.WriteHeader(204)
 }))
 return mux
}
func agentStep(ctx context.Context,c *http.Client,base,token string)error{
 req,err:=http.NewRequestWithContext(ctx,"GET",base+"/v1/agent/next",nil);if err!=nil{return err}
 req.Header.Set("Authorization","Bearer "+token)
 resp,err:=c.Do(req);if err!=nil{return err}
 defer resp.Body.Close()
 if resp.StatusCode==204{return nil}
 if resp.StatusCode!=200{return fmt.Errorf("poll status %d",resp.StatusCode)}
 var j Job
 if err=json.NewDecoder(resp.Body).Decode(&j);err!=nil{return err}
 if j.Operation!="mock.ping"{return errors.New("unsupported operation")}
 body:=strings.NewReader(fmt.Sprintf(`{"id":%q,"result":"pong"}`,j.ID))
 req,err=http.NewRequestWithContext(ctx,"POST",base+"/v1/agent/complete",body);if err!=nil{return err}
 req.Header.Set("Authorization","Bearer "+token)
 req.Header.Set("Content-Type","application/json")
 resp2,err:=c.Do(req);if err!=nil{return err}
 defer resp2.Body.Close()
 if resp2.StatusCode!=204{return fmt.Errorf("completion status %d",resp2.StatusCode)}
 log.Printf("mock device completed %s",j.ID)
 return nil
}
func main(){
 mode:=flag.String("mode","server","server or agent")
 addr:=flag.String("listen","127.0.0.1:8787","loopback bind address; experimental only")
 endpoint:=flag.String("endpoint","http://127.0.0.1:8787","relay URL, experimental local-only")
 flag.Parse()
 token:=os.Getenv("LOCALREACH_DEV_TOKEN")
 if len(token)<24{log.Fatal("set LOCALREACH_DEV_TOKEN to a random value of at least 24 characters (dev only)")}
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt,syscall.SIGTERM);defer stop()
 if *mode=="server" {
  host,_,err:=net.SplitHostPort(*addr);if err!=nil{log.Fatal(err)}
  if host!="127.0.0.1"&&host!="::1"&&host!="localhost"{log.Fatal("R1A server is intentionally loopback-only")}
  srv:=&http.Server{Addr:*addr,Handler:handler(newRelay(),token),ReadHeaderTimeout:5*time.Second}
  go func(){<-ctx.Done();shutdown,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel();srv.Shutdown(shutdown)}()
  log.Printf("R1A loopback mock relay listening on %s",*addr)
  if err=srv.ListenAndServe();err!=nil&&err!=http.ErrServerClosed{log.Fatal(err)}
  return
 }
 if *mode!="agent"{log.Fatal("mode must be server or agent")}
 if !strings.HasPrefix(*endpoint,"http://127.0.0.1:")&&!strings.HasPrefix(*endpoint,"http://localhost:")&&!strings.HasPrefix(*endpoint,"http://[::1]:"){log.Fatal("R1A agent requires loopback HTTP endpoint")}
 c:=&http.Client{Timeout:5*time.Second}
 ticker:=time.NewTicker(500*time.Millisecond);defer ticker.Stop()
 for{
  if err:=agentStep(ctx,c,*endpoint,token);err!=nil&&ctx.Err()==nil{log.Printf("poll: %v",err)}
  select{case <-ctx.Done():return;case <-ticker.C:}
 }
}
