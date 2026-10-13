package pairapi

import (
 "context"
 "encoding/json"
 "net/http"
 "time"
)
// Sessions is deliberately distinct from pairing: proof of identity is
// required for a live transport, but device permissions remain nonexistent.
type Sessions interface{
 OpenConnection(context.Context,string,string)(string,error)
 RenewConnection(context.Context,string,string,string)error
 CloseConnection(context.Context,string,string,string)error
}
type sessionFrame struct{
 Type string `json:"type"`
 AgentID string `json:"agentId"`
 Capabilities string `json:"capabilities"`
}
func(h Handler)streamSession(w http.ResponseWriter,r *http.Request){
 if h.Sessions==nil{http.Error(w,"unavailable",http.StatusServiceUnavailable);return}
 var p agentRequest
 if !decode(w,r,&p){return}
 proof,err:=decoded(p.Signature,64)
 if err!=nil{denied(w);return}
 // A fresh one-use Ed25519 challenge is consumed on the SAME request
 // that opens the authenticated stream (no transferable bearer session).
 if err=h.Pairing.VerifyResume(r.Context(),p.Organization,p.AgentID,p.Nonce,proof);err!=nil{
  denied(w);return
 }
 session,err:=h.Sessions.OpenConnection(r.Context(),p.Organization,p.AgentID)
 if err!=nil{denied(w);return}
 defer func(){
  ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
  defer cancel()
  _=h.Sessions.CloseConnection(ctx,p.Organization,p.AgentID,session)
 }()
 controller:=http.NewResponseController(w)
 w.Header().Set("Content-Type","application/x-ndjson")
 w.Header().Set("X-Accel-Buffering","no")
 w.Header().Set("Cache-Control","no-store")
 w.WriteHeader(http.StatusOK)
 send:=func(kind string)error{
  frame,err:=json.Marshal(sessionFrame{Type:kind,AgentID:p.AgentID,Capabilities:"NONE"})
  if err!=nil{return err}
  if err=controller.SetWriteDeadline(time.Now().Add(5*time.Second));err!=nil{return err}
  if _,err=w.Write(append(frame,'\n'));err!=nil{return err}
  return controller.Flush()
 }
 if err=send("connected");err!=nil{return}
 interval:=h.SessionInterval
 if interval<=0{interval=4*time.Second}
 ticker:=time.NewTicker(interval)
 defer ticker.Stop()
 for {
  select{
  case <-r.Context().Done():return
  case <-ticker.C:
   ctx,cancel:=context.WithTimeout(r.Context(),3*time.Second)
   err:=h.Sessions.RenewConnection(ctx,p.Organization,p.AgentID,session)
   cancel()
   if err!=nil{
    _=send("closed")
    return
   }
   if err=send("heartbeat");err!=nil{return}
  }
 }
}
func(h Handler)hasLiveSession()bool{return h.Sessions!=nil}
