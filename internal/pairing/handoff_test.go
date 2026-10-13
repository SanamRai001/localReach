package pairing

import (
 "crypto/ed25519"
 "crypto/rand"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/identity"
)
func TestApprovedHandoffAndEnrollment(t *testing.T){
 clock:=time.Now()
 now:=func()time.Time{return clock}
 registry:=identity.NewRegistry(now)
 manager:=New(registry,now)
 public,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 request,err:=manager.Propose("tenant","site",public);if err!=nil{t.Fatal(err)}
 if _,err=manager.InvitationForAgent(request.ID,SignHandoff(private,request.ID));err==nil{t.Fatal("unapproved invitation leaked")}
 if _,err=manager.Decide(request.ID,"tenant",true,true);err!=nil{t.Fatal(err)}
 _,attacker,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if _,err=manager.InvitationForAgent(request.ID,SignHandoff(attacker,request.ID));err==nil{t.Fatal("wrong key retrieved invitation")}
 invitation,err:=manager.InvitationForAgent(request.ID,SignHandoff(private,request.ID));if err!=nil{t.Fatal(err)}
 if _,err=manager.Redeem(request.ID,identity.SignEnrollment(attacker,invitation));err==nil{t.Fatal("wrong key enrolled")}
 agent,err:=manager.Redeem(request.ID,identity.SignEnrollment(private,invitation));if err!=nil{t.Fatal(err)}
 if agent.TenantID!="tenant"||agent.SiteID!="site"{t.Fatal("incorrect enrollment scope")}
 if _,err=manager.InvitationForAgent(request.ID,SignHandoff(private,request.ID));err==nil{t.Fatal("enrolled invitation leaked")}
 if _,err=manager.Redeem(request.ID,identity.SignEnrollment(private,invitation));err==nil{t.Fatal("replayed enrollment")}
}
func TestHandoffApprovalExpires(t *testing.T){
 clock:=time.Now()
 now:=func()time.Time{return clock}
 registry:=identity.NewRegistry(now)
 manager:=New(registry,now)
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 request,err:=manager.Propose("tenant","site",pub);if err!=nil{t.Fatal(err)}
 if _,err=manager.Decide(request.ID,"tenant",true,true);err!=nil{t.Fatal(err)}
 clock=clock.Add(6*time.Minute)
 if _,err=manager.InvitationForAgent(request.ID,SignHandoff(priv,request.ID));err==nil{t.Fatal("expired request yielded invitation")}
}
