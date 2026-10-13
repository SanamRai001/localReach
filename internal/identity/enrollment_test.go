package identity

import (
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "sync"
 "testing"
 "time"
)

func key(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 return pub,priv
}
func TestEnrollmentAndRevocation(t *testing.T){
 now:=time.Date(2026,10,13,0,0,0,0,time.UTC)
 registry:=NewRegistry(func()time.Time{return now})
 invitation,err:=registry.Issue("tenant-1","site-a",time.Minute);if err!=nil{t.Fatal(err)}
 pub,priv:=key(t)
 if _,err=registry.Enroll(invitation.Token,pub,make([]byte,64));!errors.Is(err,ErrInvalidProof){t.Fatalf("expected proof rejection, got %v",err)}
 agent,err:=registry.Enroll(invitation.Token,pub,SignEnrollment(priv,invitation.Token));if err!=nil{t.Fatal(err)}
 if agent.TenantID!="tenant-1"||agent.SiteID!="site-a"||agent.Revoked{t.Fatalf("wrong scope %+v",agent)}
 if _,err=registry.Enroll(invitation.Token,pub,SignEnrollment(priv,invitation.Token));!errors.Is(err,ErrInvalidInvitation){t.Fatalf("invitation must be single-use: %v",err)}
 challenge:=make([]byte,32);if _,err=rand.Read(challenge);err!=nil{t.Fatal(err)}
 signature:=ed25519.Sign(priv,append([]byte("localreach/session/v1:"),challenge...))
 if err=registry.VerifyChallenge(agent.ID,challenge,signature);err!=nil{t.Fatal(err)}
 if err=registry.Revoke(agent.ID);err!=nil{t.Fatal(err)}
 if err=registry.VerifyChallenge(agent.ID,challenge,signature);!errors.Is(err,ErrRevoked){t.Fatalf("revocation failed: %v",err)}
}
func TestExpiryAndWrongKey(t *testing.T){
 now:=time.Now()
 registry:=NewRegistry(func()time.Time{return now})
 if _,err:=registry.Issue("t","s",0);err==nil{t.Fatal("zero TTL accepted")}
 inv,err:=registry.Issue("t","s",time.Second);if err!=nil{t.Fatal(err)}
 pub,priv:=key(t)
 _,wrongPrivate:=key(t)
 if _,err=registry.Enroll(inv.Token,pub,SignEnrollment(wrongPrivate,inv.Token));!errors.Is(err,ErrInvalidProof){t.Fatalf("wrong proof: %v",err)}
 now=now.Add(time.Second)
 if _,err=registry.Enroll(inv.Token,pub,SignEnrollment(priv,inv.Token));!errors.Is(err,ErrInvalidInvitation){t.Fatalf("expired invitation: %v",err)}
}
func TestConcurrentRedemptionSingleWinner(t *testing.T){
 registry:=NewRegistry(nil)
 inv,err:=registry.Issue("tenant","site",time.Minute);if err!=nil{t.Fatal(err)}
 pub,priv:=key(t);sig:=SignEnrollment(priv,inv.Token)
 var wg sync.WaitGroup
 results:=make(chan error,20)
 for i:=0;i<20;i++{wg.Add(1);go func(){defer wg.Done();_,e:=registry.Enroll(inv.Token,pub,sig);results<-e}()}
 wg.Wait();close(results)
 wins:=0
 for err:=range results{if err==nil{wins++}else if !errors.Is(err,ErrInvalidInvitation){t.Fatalf("unexpected outcome %v",err)}}
 if wins!=1{t.Fatalf("expected exactly one redemption, got %d",wins)}
}
func TestReturnedKeysCannotMutateRegistry(t *testing.T){
 registry:=NewRegistry(nil)
 inv,err:=registry.Issue("a","b",time.Minute);if err!=nil{t.Fatal(err)}
 pub,priv:=key(t)
 agent,err:=registry.Enroll(inv.Token,pub,SignEnrollment(priv,inv.Token));if err!=nil{t.Fatal(err)}
 agent.PublicKey[0]^=0xff
 stored,ok:=registry.Lookup(agent.ID);if !ok||stored.PublicKey[0]!=pub[0]{t.Fatal("key alias leaked")}
}
