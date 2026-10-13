package session

import (
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "sync"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/identity"
)
func fixture(t *testing.T,now *time.Time)(*identity.Registry,*Manager,string,ed25519.PrivateKey){
 t.Helper()
 clock:=func()time.Time{return *now}
 r:=identity.NewRegistry(clock)
 inv,e:=r.Issue("tenant-one","site-one",time.Minute);if e!=nil{t.Fatal(e)}
 pub,priv,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 agent,e:=r.Enroll(inv.Token,pub,identity.SignEnrollment(priv,inv.Token));if e!=nil{t.Fatal(e)}
 return r,New(r,clock),agent.ID,priv
}
func TestHandshakeAndRevocation(t *testing.T){
 now:=time.Now()
 r,m,id,priv:=fixture(t,&now)
 nonce,e:=m.Begin(id);if e!=nil{t.Fatal(e)}
 token,e:=m.Complete(id,nonce,Sign(priv,nonce));if e!=nil{t.Fatal(e)}
 if e=m.Authorize(id,token);e!=nil{t.Fatal(e)}
 if _,e=m.Complete(id,nonce,Sign(priv,nonce));!errors.Is(e,ErrDenied){t.Fatalf("replay accepted: %v",e)}
 if e=m.Authorize("other",token);!errors.Is(e,ErrDenied){t.Fatal("cross-agent authorization succeeded")}
 if e=r.Revoke(id);e!=nil{t.Fatal(e)}
 if e=m.Authorize(id,token);!errors.Is(e,ErrDenied){t.Fatal("revoked session still valid")}
}
func TestInvalidProofConsumesChallenge(t *testing.T){
 now:=time.Now()
 _,m,id,priv:=fixture(t,&now)
 nonce,e:=m.Begin(id);if e!=nil{t.Fatal(e)}
 if _,e=m.Complete(id,nonce,make([]byte,64));!errors.Is(e,ErrDenied){t.Fatal("invalid signature accepted")}
 if _,e=m.Complete(id,nonce,Sign(priv,nonce));!errors.Is(e,ErrDenied){t.Fatal("consumed nonce reused")}
}
func TestExpiry(t *testing.T){
 now:=time.Now()
 _,m,id,priv:=fixture(t,&now)
 nonce,e:=m.Begin(id);if e!=nil{t.Fatal(e)}
 now=now.Add(31*time.Second)
 if _,e=m.Complete(id,nonce,Sign(priv,nonce));!errors.Is(e,ErrDenied){t.Fatal("expired nonce accepted")}
 nonce,e=m.Begin(id);if e!=nil{t.Fatal(e)}
 token,e:=m.Complete(id,nonce,Sign(priv,nonce));if e!=nil{t.Fatal(e)}
 now=now.Add(6*time.Minute)
 if e=m.Authorize(id,token);!errors.Is(e,ErrDenied){t.Fatal("expired session accepted")}
 m.Sweep()
}
func TestConcurrentReplayOnlyOneWinner(t *testing.T){
 now:=time.Now()
 _,m,id,priv:=fixture(t,&now)
 nonce,e:=m.Begin(id);if e!=nil{t.Fatal(e)}
 signature:=Sign(priv,nonce)
 var wg sync.WaitGroup
 results:=make(chan error,16)
 for i:=0;i<16;i++{wg.Add(1);go func(){defer wg.Done();_,e:=m.Complete(id,nonce,signature);results<-e}()}
 wg.Wait();close(results)
 passed:=0
 for e:=range results{if e==nil{passed++}else if !errors.Is(e,ErrDenied){t.Fatalf("unexpected error: %v",e)}}
 if passed!=1{t.Fatalf("expected one valid handshake, got %d",passed)}
}
