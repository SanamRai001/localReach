package pgpairing

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "database/sql"
 "errors"
 "sync"
 "sync/atomic"
 "testing"
)

func TestInvitationIsOneUseAndOnlyCreatesPendingPairing(t *testing.T){
 db:=integrationDB(t)
 adminPub,_:=keys(t)
 setupOrg(t,db,"org","site","owner","OWNER",adminPub)
 s:=New(db);ctx:=context.Background()
 invite,err:=s.IssueInvitation(ctx,"org","site","owner")
 if err!=nil||invite.Token==""{t.Fatalf("invite failed: %v",err)}
 public,_:=keys(t)
 if _,err=s.RedeemInvitation(ctx,"other",invite.Token,public);!errors.Is(err,ErrDenied){t.Fatal("cross-tenant invite accepted")}
 other,_:=keys(t)
 if _,err=s.RedeemInvitation(ctx,"org","bad-code",other);!errors.Is(err,ErrDenied){t.Fatal("bad invitation accepted")}
 record,err:=s.RedeemInvitation(ctx,"org",invite.Token,public)
 if err!=nil||record.State!="PENDING"||record.Site!="site"{t.Fatalf("redeem status: %v %+v",err,record)}
 if _,err=s.RedeemInvitation(ctx,"org",invite.Token,other);!errors.Is(err,ErrDenied){t.Fatal("replayed invitation accepted")}
 got,err:=s.Get(ctx,"org",record.RequestID)
 if err!=nil||got.State!="PENDING"{t.Fatal("redeemed invitation self-approved")}
 var events int
 if err=db.QueryRowContext(ctx,`SELECT COUNT(*) FROM lr_pairing_invitation_audit WHERE organization_id='org'`).Scan(&events);err!=nil{t.Fatal(err)}
 if events!=2{t.Fatalf("issued and redeemed events = %d",events)}
}
func TestInvitationRejectsRevocationExpiryAndViewer(t *testing.T){
 db:=integrationDB(t)
 ownerPub,_:=keys(t)
 setupOrg(t,db,"org","site","owner","OWNER",ownerPub)
 viewerPub,_:=keys(t)
 if _,err:=db.Exec(`INSERT INTO lr_admin_keys(organization_id,admin_id,public_key,role)
 VALUES('org','viewer',$1,'VIEWER')`,[]byte(viewerPub));err!=nil{t.Fatal(err)}
 s:=New(db);ctx:=context.Background()
 if _,err:=s.IssueInvitation(ctx,"org","site","viewer");!errors.Is(err,ErrDenied){t.Fatal("viewer invited")}
 invite,err:=s.IssueInvitation(ctx,"org","site","owner")
 if err!=nil{t.Fatal(err)}
 if _,err=db.Exec(`UPDATE lr_admin_keys SET status='REVOKED' WHERE organization_id='org' AND admin_id='owner'`);err!=nil{t.Fatal(err)}
 pub,_:=keys(t)
 if _,err=s.RedeemInvitation(ctx,"org",invite.Token,pub);!errors.Is(err,ErrDenied){t.Fatal("revoked owner invitation accepted")}
 if _,err=db.Exec(`UPDATE lr_admin_keys SET status='ACTIVE' WHERE organization_id='org' AND admin_id='owner'`);err!=nil{t.Fatal(err)}
 if _,err=db.Exec(`UPDATE lr_pairing_invitations SET expires_at=NOW()-INTERVAL '1 second'`);err!=nil{t.Fatal(err)}
 if _,err=s.RedeemInvitation(ctx,"org",invite.Token,pub);!errors.Is(err,ErrDenied){t.Fatal("expired invitation accepted")}
 if _,err=db.Exec(`UPDATE lr_organizations SET status='BLOCKED' WHERE organization_id='org'`);err!=nil{t.Fatal(err)}
 if _,err=s.IssueInvitation(ctx,"org","site","owner");!errors.Is(err,ErrDenied){t.Fatal("blocked org issued invitation")}
}
func TestConcurrentInvitationRedeemersOneWins(t *testing.T){
 db:=integrationDB(t)
 adminPub,_:=keys(t);setupOrg(t,db,"org","site","owner","ADMIN",adminPub)
 s:=New(db);ctx:=context.Background()
 invite,err:=s.IssueInvitation(ctx,"org","site","owner");if err!=nil{t.Fatal(err)}
 var wg sync.WaitGroup
 var winners atomic.Int32
 for i:=0;i<10;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   public,_,err:=ed25519.GenerateKey(rand.Reader)
   if err!=nil{t.Errorf("keygen: %v",err);return}
   if r,err:=s.RedeemInvitation(ctx,"org",invite.Token,public);err==nil{
    if r.State!="PENDING"{t.Errorf("redeemer not pending: %+v",r)}
    winners.Add(1)
   }
  }()
 }
 wg.Wait()
 if winners.Load()!=1{t.Fatalf("single-use invitation accepted %d times",winners.Load())}
 var pairCount int
 if err=db.QueryRow(`SELECT COUNT(*) FROM lr_pairings WHERE organization_id='org'`).Scan(&pairCount);err!=nil{t.Fatal(err)}
 if pairCount!=1{t.Fatalf("unexpected %d pairing proposals",pairCount)}
 // A committed redemption cannot be undone by a client replay.
 var consumed sql.NullTime
 if err=db.QueryRow(`SELECT consumed_at FROM lr_pairing_invitations WHERE invite_id=$1`,invite.InviteID).Scan(&consumed);err!=nil||!consumed.Valid{t.Fatalf("invitation not consumed: %v",err)}
}
