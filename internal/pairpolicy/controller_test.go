package pairpolicy

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/admintrust"
 "github.com/SanamRai001/localReach/internal/pairledger"
 "github.com/SanamRai001/localReach/internal/pairtransport"
)
func TestSignedAdministratorApprovalPersistsAndCannotReplay(t *testing.T){
 now:=time.Now()
 clock:=func()time.Time{return now}
 dir:=t.TempDir()
 adminFile:=filepath.Join(dir,"admins.log")
 pairFile:=filepath.Join(dir,"pairings.log")
 trust,err:=admintrust.Open(adminFile,clock);if err!=nil{t.Fatal(err)}
 pub,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if err=trust.Provision("tenant","owner-1",pub);err!=nil{t.Fatal(err)}
 pairs,err:=pairledger.Open(pairFile,clock);if err!=nil{t.Fatal(err)}
 agentPublic,agentPrivate,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 pending,err:=pairs.Propose("tenant","site",agentPublic);if err!=nil{t.Fatal(err)}
 controller:=Controller{Trust:trust,Pairings:pairs,Now:clock}
 n:=make([]byte,32)
 if _,err=rand.Read(n);err!=nil{t.Fatal(err)}
 nonce:=func()string{return base64Nonce(n)}()
 decision:=pairtransport.Decision{ID:pending.ID,Tenant:"tenant",KeyID:"owner-1",Nonce:nonce,Approve:true,IssuedAt:now.Unix(),ExpiresAt:now.Add(time.Minute).Unix()}
 if _,err=controller.Decide(decision,make([]byte,64));err==nil{t.Fatal("unauthorized decision accepted")}
 approved,err:=controller.Decide(decision,pairtransport.SignDecision(private,decision))
 if err!=nil||approved.State!=pairledger.Approved{t.Fatalf("approval: %v %+v",err,approved)}
 if err=trust.Close();err!=nil{t.Fatal(err)}
 if err=pairs.Close();err!=nil{t.Fatal(err)}
 trust,err=admintrust.Open(adminFile,clock);if err!=nil{t.Fatal(err)}
 defer trust.Close()
 pairs,err=pairledger.Open(pairFile,clock);if err!=nil{t.Fatal(err)}
 defer pairs.Close()
 controller=Controller{Trust:trust,Pairings:pairs,Now:clock}
 if _,err=controller.Decide(decision,pairtransport.SignDecision(private,decision));err==nil{t.Fatal("replay after restart accepted")}
 challenge,err:=pairs.Challenge(pending.ID);if err!=nil{t.Fatal(err)}
 enrolled,err:=pairs.Enroll(pending.ID,challenge,pairledger.SignEnrollment(agentPrivate,pending.ID,challenge));if err!=nil||enrolled.State!=pairledger.Enrolled{t.Fatalf("durable enroll: %v %+v",err,enrolled)}
 if err=trust.Revoke("tenant","owner-1");err!=nil{t.Fatal(err)}
 anotherPublic,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 another,err:=pairs.Propose("tenant","site",anotherPublic);if err!=nil{t.Fatal(err)}
 _,wrongKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 second:=pairtransport.Decision{ID:another.ID,Tenant:"tenant",KeyID:"owner-1",Nonce:base64Nonce(randomBytes(t)),Approve:true,IssuedAt:now.Unix(),ExpiresAt:now.Add(time.Minute).Unix()}
 if _,err=controller.Decide(second,pairtransport.SignDecision(wrongKey,second));err==nil{t.Fatal("wrong key approved")}
 if _,err=controller.Decide(second,pairtransport.SignDecision(private,second));err==nil{t.Fatal("revoked admin approved")}
}
func base64Nonce(b []byte)string{return base64.RawURLEncoding.EncodeToString(b)}
func randomBytes(t *testing.T)[]byte{
 t.Helper()
 raw:=make([]byte,32)
 if _,err:=rand.Read(raw);err!=nil{t.Fatal(err)}
 return raw
}
