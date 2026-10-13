package pairing
import(
 "crypto/ed25519"
 "crypto/rand"
 "testing"
 "time"
 "github.com/SanamRai001/localReach/internal/identity"
)
func TestApprovalCannotBeBypassed(t *testing.T){
 now:=time.Now()
 reg:=identity.NewRegistry(func()time.Time{return now})
 mgr:=New(reg,func()time.Time{return now})
 pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 req,err:=mgr.Propose("org","site",pub);if err!=nil{t.Fatal(err)}
 if _,err=mgr.Decide(req.ID,"other",true,true);err==nil{t.Fatal("cross tenant approval")}
 if _,err=mgr.Decide(req.ID,"org",false,true);err==nil{t.Fatal("unauthorized approval")}
 if _,err=mgr.Redeem(req.ID,make([]byte,64));err==nil{t.Fatal("redeemed unapproved")}
 if _,err=mgr.Decide(req.ID,"org",true,false);err!=nil{t.Fatal(err)}
 if _,err=mgr.Decide(req.ID,"org",true,true);err==nil{t.Fatal("rejected pairing was approved")}
 if _,err=mgr.Redeem(req.ID,make([]byte,64));err==nil{t.Fatal("rejected enrollment")}
}
func TestExpiredRequestCannotBeApproved(t *testing.T){
 now:=time.Now();mgr:=New(identity.NewRegistry(nil),func()time.Time{return now})
 pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 req,err:=mgr.Propose("org","site",pub);if err!=nil{t.Fatal(err)}
 now=now.Add(6*time.Minute)
 if _,err=mgr.Decide(req.ID,"org",true,true);err==nil{t.Fatal("expired approval")}
}
