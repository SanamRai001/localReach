package agentservice

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "testing"
 "time"
)
type fakeLiveStream struct{
 entered chan struct{}
 continueUntil chan struct{}
}
func(f *fakeLiveStream)StreamSession(ctx context.Context,org string,s Signer,onHeartbeat func(bool))error{
 onHeartbeat(true)
 close(f.entered)
 select{
 case <-f.continueUntil: onHeartbeat(false);return errors.New("network cut")
 case <-ctx.Done(): onHeartbeat(false);return ctx.Err()
 }
}
func TestLiveMonitorStatusReflectsRealStreamAndDisconnect(t *testing.T){
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 fake:=&fakeLiveStream{entered:make(chan struct{}),continueUntil:make(chan struct{})}
 m:=NewLive("org",signer{public:pub,private:priv},fake)
 m.Retry=10*time.Second // prevent rapid reconnect after forced disconnect
 ctx,cancel:=context.WithCancel(context.Background())
 done:=make(chan struct{})
 go func(){m.Run(ctx);close(done)}()
 select{case <-fake.entered:case <-time.After(2*time.Second):t.Fatal("stream did not start")}
 state:=m.Snapshot()
 if state.Connection!="ONLINE"||state.Pairing!="PAIRED"||
 state.Verification!="VERIFIED_RECENTLY"||state.Devices!="NOT_DISCOVERED"{
  t.Fatalf("wrong live status %+v",state)
 }
 close(fake.continueUntil)
 deadline:=time.Now().Add(time.Second)
 for time.Now().Before(deadline){
  if m.Snapshot().Connection=="OFFLINE"{break}
  time.Sleep(10*time.Millisecond)
 }
 if state=m.Snapshot();state.Connection!="OFFLINE"||state.Pairing!="UNVERIFIED"{
  t.Fatalf("network disconnect remained connected: %+v",state)
 }
 cancel()
 select{case <-done:case <-time.After(2*time.Second):t.Fatal("shutdown blocked")}
 if m.Snapshot().Agent!="STOPPED"{t.Fatal("monitor not stopped")}
}
func TestLiveMonitorStaleFramesCannotClaimOnline(t *testing.T){
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 m:=NewLive("org",signer{public:pub,private:priv},nil)
 m.setLive(true)
 m.mu.Lock();m.lastFrame=time.Now().Add(-20*time.Second);m.mu.Unlock()
 if v:=m.Snapshot();v.Connection!="OFFLINE"||v.Verification!="STALE"||v.Pairing!="UNVERIFIED"{
  t.Fatalf("stale live frame accepted: %+v",v)
 }
}
