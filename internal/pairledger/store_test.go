package pairledger

import (
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/ownership"
)
func newKey(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 return pub,priv
}
func TestRestartSafePairingAndRevocation(t *testing.T){
 timeNow:=time.Now()
 clock:=func()time.Time{return timeNow}
 path:=filepath.Join(t.TempDir(),"pairing.log")
 s,err:=Open(path,clock);if err!=nil{t.Fatal(err)}
 pub,private:=newKey(t)
 r,err:=s.Propose("tenant","site",pub);if err!=nil{t.Fatal(err)}
 if _,err=s.Challenge(r.ID);!errors.Is(err,ErrDenied){t.Fatal("preapproval challenge allowed")}
 if _,err=s.Decide("tenant",r.ID,false,true);!errors.Is(err,ErrDenied){t.Fatal("unauthorized approval")}
 if _,err=s.Decide("different",r.ID,true,true);!errors.Is(err,ErrDenied){t.Fatal("cross tenant approval")}
 if _,ok:=s.Get("different",r.ID);ok{t.Fatal("cross tenant request disclosed")}
 approved,err:=s.Decide("tenant",r.ID,true,true);if err!=nil||approved.State!=Approved{t.Fatalf("approve: %v %+v",err,approved)}
 if err=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(path,clock);if err!=nil{t.Fatal(err)}
 persisted,ok:=s.Get("tenant",r.ID);if !ok||persisted.State!=Approved{t.Fatal("approval did not survive restart")}
 n,err:=s.Challenge(r.ID);if err!=nil{t.Fatal(err)}
 _,attacker:=newKey(t)
 if _,err=s.Enroll(r.ID,n,SignEnrollment(attacker,r.ID,n));!errors.Is(err,ErrDenied){t.Fatal("wrong private key enrolled")}
 if _,err=s.Enroll(r.ID,n,SignEnrollment(private,r.ID,n));!errors.Is(err,ErrDenied){t.Fatal("consumed challenge replay accepted")}
 n,err=s.Challenge(r.ID);if err!=nil{t.Fatal(err)}
 enrolled,err:=s.Enroll(r.ID,n,SignEnrollment(private,r.ID,n));if err!=nil{t.Fatal(err)}
 if enrolled.State!=Enrolled||enrolled.AgentID==""{t.Fatalf("missing identity: %+v",enrolled)}
 if _,err=s.Enroll(r.ID,n,SignEnrollment(private,r.ID,n));!errors.Is(err,ErrDenied){t.Fatal("double enrolled")}
 if err=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(path,clock);if err!=nil{t.Fatal(err)}
 restored,ok:=s.Get("tenant",r.ID);if !ok||restored.AgentID!=enrolled.AgentID||restored.State!=Enrolled{t.Fatalf("agent identity lost: %+v",restored)}
 if err=s.Revoke("tenant",r.ID,false);!errors.Is(err,ErrDenied){t.Fatal("unauthorized revocation")}
 if err=s.Revoke("tenant",r.ID,true);err!=nil{t.Fatal(err)}
 if err=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(path,clock);if err!=nil{t.Fatal(err)}
 defer s.Close()
 revoked,ok:=s.Get("tenant",r.ID);if !ok||revoked.State!=Revoked||revoked.AgentID!=enrolled.AgentID{t.Fatalf("revocation not durable: %+v",revoked)}
}
func TestExpiredApprovalAndChallengeOnRestart(t *testing.T){
 clockTime:=time.Now()
 clock:=func()time.Time{return clockTime}
 path:=filepath.Join(t.TempDir(),"pairing.log")
 s,err:=Open(path,clock);if err!=nil{t.Fatal(err)}
 pub,priv:=newKey(t)
 r,err:=s.Propose("t","s",pub);if err!=nil{t.Fatal(err)}
 if _,err=s.Decide("t",r.ID,true,true);err!=nil{t.Fatal(err)}
 n,err:=s.Challenge(r.ID);if err!=nil{t.Fatal(err)}
 if err=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(path,clock);if err!=nil{t.Fatal(err)}
 if _,err=s.Enroll(r.ID,n,SignEnrollment(priv,r.ID,n));!errors.Is(err,ErrDenied){t.Fatal("crash resurrected challenge")}
 clockTime=clockTime.Add(2*time.Minute)
 status,ok:=s.Get("t",r.ID);if !ok||status.State!=Expired{t.Fatalf("expired approval status: %+v",status)}
 if _,err=s.Challenge(r.ID);!errors.Is(err,ErrDenied){t.Fatal("expired approval issued challenge")}
 if err=s.Close();err!=nil{t.Fatal(err)}
 // Expired proposal cannot be approved after reopening.
 s,err=Open(path,clock);if err!=nil{t.Fatal(err)}
 defer s.Close()
 otherPub,_:=newKey(t)
 clockTime=clockTime.Add(time.Second)
 other,err:=s.Propose("t","s2",otherPub);if err!=nil{t.Fatal(err)}
 clockTime=clockTime.Add(6*time.Minute)
 if _,err=s.Decide("t",other.ID,true,true);!errors.Is(err,ErrDenied){t.Fatal("expired proposal approved")}
}
func TestCorruptionAndSingleWriterFailClosed(t *testing.T){
 for _,mode:=range []string{"tamper","partial"}{t.Run(mode,func(t *testing.T){
  path:=filepath.Join(t.TempDir(),"pairing.log")
  s,err:=Open(path,nil);if err!=nil{t.Fatal(err)}
  pub,_:=newKey(t)
  if _,err=s.Propose("tenant","site",pub);err!=nil{t.Fatal(err)}
  if second,err:=Open(path,nil);!errors.Is(err,ownership.ErrInUse){if err==nil{second.Close()};t.Fatalf("second writer: %v",err)}
  if err=s.Close();err!=nil{t.Fatal(err)}
  raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
  if mode=="tamper"{raw[10]='X'}else{raw=append(raw,[]byte("{\"op\":")...)}
  if err=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
  if second,err:=Open(path,nil);!errors.Is(err,ErrCorrupt){if err==nil{second.Close()};t.Fatalf("corrupt tail accepted: %v",err)}
 })}
}
func TestConcurrentSameKeyOnlyOneProposal(t *testing.T){
 path:=filepath.Join(t.TempDir(),"pairing.log")
 s,err:=Open(path,nil);if err!=nil{t.Fatal(err)}
 defer s.Close()
 pub,_:=newKey(t)
 var wg sync.WaitGroup
 var accepted atomic.Int64
 for i:=0;i<12;i++{
  wg.Add(1)
  go func(){defer wg.Done();if _,err:=s.Propose("t","s",pub);err==nil{accepted.Add(1)}}()
 }
 wg.Wait()
 if accepted.Load()!=1{t.Fatalf("same key proposed %d times",accepted.Load())}
}
