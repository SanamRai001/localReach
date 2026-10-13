// Package gateway is a TLS-only, mock-only proof of agent handshake and
// session authorization. It is not a production or public-facing gateway.
package gateway

import (
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "net/http"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/session"
)

type Handler struct{ sessions *session.Manager }
func New(manager *session.Manager) http.Handler {
 h:=&Handler{sessions:manager}
 mux:=http.NewServeMux()
 mux.HandleFunc("/v1/agent/challenge",h.challenge)
 mux.HandleFunc("/v1/agent/session",h.complete)
 mux.HandleFunc("/v1/agent/heartbeat",h.heartbeat)
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("X-Content-Type-Options","nosniff")
  if r.TLS==nil {http.Error(w,"TLS required",http.StatusUpgradeRequired);return}
  mux.ServeHTTP(w,r)
 })
}
func decode(w http.ResponseWriter,r *http.Request,to any)bool{
 if r.Header.Get("Content-Type")!="application/json"{http.Error(w,"application/json required",415);return false}
 dec:=json.NewDecoder(http.MaxBytesReader(w,r.Body,2048))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(to);err!=nil{http.Error(w,"invalid request",400);return false}
 var extra any
 if err:=dec.Decode(&extra);err==nil{http.Error(w,"trailing data",400);return false}
 return true
}
func jsonReply(w http.ResponseWriter,status int,value any){
 w.Header().Set("Content-Type","application/json")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(value)
}
func (h *Handler)challenge(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 var p struct{AgentID string `json:"agentId"`}
 if !decode(w,r,&p){return}
 if len(p.AgentID)<1||len(p.AgentID)>128{http.Error(w,"invalid agent id",400);return}
 challenge,err:=h.sessions.Begin(p.AgentID)
 if err!=nil{http.Error(w,"denied",403);return}
 jsonReply(w,200,map[string]string{"challenge":challenge})
}
func (h *Handler)complete(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 var p struct{AgentID string `json:"agentId"`;Challenge string `json:"challenge"`;Signature string `json:"signature"`}
 if !decode(w,r,&p){return}
 sig,err:=base64.RawURLEncoding.DecodeString(p.Signature)
 if err!=nil||len(sig)!=ed25519.SignatureSize{http.Error(w,"denied",403);return}
 token,err:=h.sessions.Complete(p.AgentID,p.Challenge,sig)
 if err!=nil{http.Error(w,"denied",403);return}
 jsonReply(w,200,map[string]string{"sessionToken":token,"expiresIn":"300s"})
}
func (h *Handler)heartbeat(w http.ResponseWriter,r *http.Request){
 if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
 agentID:=r.Header.Get("X-LocalReach-Agent-ID")
 if agentID==""||len(agentID)>128{http.Error(w,"denied",403);return}
 bearer:=r.Header.Get("Authorization")
 if !strings.HasPrefix(bearer,"Bearer "){http.Error(w,"denied",403);return}
 if err:=h.sessions.Authorize(agentID,strings.TrimPrefix(bearer,"Bearer "));err!=nil{http.Error(w,"denied",403);return}
 jsonReply(w,200,map[string]string{"status":"connected","serverTime":time.Now().UTC().Format(time.RFC3339)})
}
