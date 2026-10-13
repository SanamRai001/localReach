package pairapi

import (
 "context"
 "errors"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/pgpairing"
)
func TestTLSStreamOnlineHeartbeatDuplicateRevocationAndOffline(t *testing.T){
 db:=testDB(t)
 admin,_:=prepare(t,db)
 ctx:=context.Background()
 backend:=pgpairing.New(db)
 agent:=newSigner(t)
 request,err:=backend.Propose(ctx,"org","site",agent.PublicKey());if err!=nil{t.Fatal(err)}
 approval:=pgpairing.AdminDecision{
  Organization:"org",RequestID:request.RequestID,AdminID:"owner",Action:pgpairing.Approve,
  Nonce:nonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
 if _,err=backend.Decide(ctx,approval,pgpairing.SignDecision(admin.private,approval));err!=nil{t.Fatal(err)}
 challenge,err:=backend.Challenge(ctx,"org",request.RequestID);if err!=nil{t.Fatal(err)}
 enrolled,err:=backend.Enroll(ctx,"org",request.RequestID,challenge,
  pgpairing.SignEnrollment(agent.private,"org",request.RequestID,challenge));if err!=nil{t.Fatal(err)}
 id:=enrolled.AgentID.String
 server:=httptest.NewTLSServer(Handler{Pairing:backend,Sessions:backend,SessionInterval:120*time.Millisecond})
 defer server.Close()
 remote,err:=agentremote.New(server.URL,server.Client());if err!=nil{t.Fatal(err)}
 liveCtx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
 defer cancel()
 events:=make(chan bool,50)
 finished:=make(chan error,1)
 go func(){finished<-remote.StreamSession(liveCtx,"org",agent,func(ok bool){select{case events<-ok:default:}})}()
 select{
 case ok:=<-events:if !ok{t.Fatal("never authenticated live stream")}
 case <-time.After(4*time.Second):t.Fatal("first connected frame missing")
 }
 online,err:=backend.ConnectionOnline(ctx,"org",id)
 if err!=nil||!online{t.Fatalf("server has no live lease: %v",err)}
 // Active session is exclusive across a second TLS connection.
 duplicateCtx,dupCancel:=context.WithTimeout(ctx,3*time.Second)
 defer dupCancel()
 if err=remote.StreamSession(duplicateCtx,"org",agent,func(bool){});err==nil{
  t.Fatal("duplicate active stream incorrectly admitted")
 }
 // Verify we received at least one genuine heartbeat rather than only a
 // transient successful proof.
 select{
 case ok:=<-events:if !ok{t.Fatal("stream died before first heartbeat")}
 case <-time.After(3*time.Second):t.Fatal("heartbeat absent")
 }
 revoke:=approval
 revoke.Action=pgpairing.Revoke
 revoke.Nonce=nonce(t)
 revoke.IssuedAt=time.Now().Unix()
 revoke.ExpiresAt=time.Now().Add(time.Minute).Unix()
 if _,err=backend.Decide(ctx,revoke,pgpairing.SignDecision(admin.private,revoke));err!=nil{t.Fatal(err)}
 select{
 case err=<-finished:
  if err==nil{t.Fatal("revoked stream exited as successful connection")}
 case <-time.After(4*time.Second):t.Fatal("revocation did not close long-lived stream")
 }
 if !errors.Is(err,agentremote.ErrSessionClosed){t.Fatalf("unexpected session termination: %v",err)}
 online,err=backend.ConnectionOnline(ctx,"org",id)
 if err!=nil||online{t.Fatal("revoked stream still online")}
 if err=remote.StreamSession(ctx,"org",agent,func(bool){});err==nil{
  t.Fatal("revoked agent reopened stream")
 }
}
