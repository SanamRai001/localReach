package pgpairing

import(
 "context"
 "crypto/ed25519"
 "database/sql"
 "errors"
 "os"
 "testing"
)

func TestPostgresSignedAgentResumeAndRevocation(t *testing.T){
 db:=integrationDB(t)
 adminPub,adminPriv:=keys(t)
 setupOrg(t,db,"org","site","owner","OWNER",adminPub)
 public,private:=keys(t)
 ctx:=context.Background()
 store:=New(db)
 req,err:=store.Propose(ctx,"org","site",public);if err!=nil{t.Fatal(err)}
 decision:=makeDecision(t,"org",req.RequestID,"owner",Approve)
 if _,err=store.Decide(ctx,decision,SignDecision(adminPriv,decision));err!=nil{t.Fatal(err)}
 challenge,err:=store.Challenge(ctx,"org",req.RequestID);if err!=nil{t.Fatal(err)}
 enrolled,err:=store.Enroll(ctx,"org",req.RequestID,challenge,SignEnrollment(private,"org",req.RequestID,challenge))
 if err!=nil||!enrolled.AgentID.Valid{t.Fatalf("enroll: %v %+v",err,enrolled)}
 agentID:=enrolled.AgentID.String
 if _,err=store.ResolveIdentity(ctx,"wrong",public);!errors.Is(err,ErrDenied){t.Fatal("cross-org key lookup")}
 otherPub,otherPriv:=keys(t)
 if _,err=store.ResolveIdentity(ctx,"org",otherPub);!errors.Is(err,ErrDenied){t.Fatal("unregistered key resolved")}
 id,err:=store.ResolveIdentity(ctx,"org",public)
 if err!=nil||id!=agentID{t.Fatalf("resolution: %s %v",id,err)}
 first,err:=store.BeginResume(ctx,"org",id);if err!=nil{t.Fatal(err)}
 if _,err=store.BeginResume(ctx,"org",id);!errors.Is(err,ErrDenied){t.Fatal("concurrent resume challenge allowed")}
 if err=store.VerifyResume(ctx,"org",id,first,SignResume(otherPriv,"org",id,first));!errors.Is(err,ErrDenied){t.Fatal("wrong private key verified")}
 // Invalid proof does not consume the challenge because the transaction rolls back.
 if err=store.VerifyResume(ctx,"org",id,first,SignResume(private,"other",id,first));!errors.Is(err,ErrDenied){t.Fatal("wrong organization proof accepted")}
 if err=store.VerifyResume(ctx,"org",id,first,SignResume(private,"org",id,first));err!=nil{t.Fatal(err)}
 if err=store.VerifyResume(ctx,"org",id,first,SignResume(private,"org",id,first));!errors.Is(err,ErrDenied){t.Fatal("replayed resume proof")}
 // Another backend instance recovers the same agent after process restart.
 secondDB,err:=sql.Open("postgres",os.Getenv("LOCALREACH_TEST_POSTGRES_DSN"));if err!=nil{t.Fatal(err)}
 defer secondDB.Close()
 again:=New(secondDB)
 id,err=again.ResolveIdentity(ctx,"org",public)
 if err!=nil||id!=agentID{t.Fatal("agent ID changed after reopening db")}
 second,err:=again.BeginResume(ctx,"org",id);if err!=nil{t.Fatal(err)}
 if err=again.VerifyResume(ctx,"org",id,second,SignResume(private,"org",id,second));err!=nil{t.Fatal(err)}
 var audited int
 if err=db.QueryRowContext(ctx,`SELECT COUNT(*) FROM lr_agent_identity_audit WHERE organization_id='org' AND agent_id=$1`,agentID).Scan(&audited);err!=nil{t.Fatal(err)}
 if audited!=2{t.Fatalf("expected 2 verified resumes, got %d",audited)}
 revoke:=makeDecision(t,"org",req.RequestID,"owner",Revoke)
 if _,err=again.Decide(ctx,revoke,SignDecision(adminPriv,revoke));err!=nil{t.Fatal(err)}
 if _,err=again.ResolveIdentity(ctx,"org",public);!errors.Is(err,ErrDenied){t.Fatal("revoked key resolved")}
 if _,err=again.BeginResume(ctx,"org",agentID);!errors.Is(err,ErrDenied){t.Fatal("revoked agent challenge")}
 if err=again.VerifyResume(ctx,"org",agentID,second,SignResume(private,"org",agentID,second));!errors.Is(err,ErrDenied){t.Fatal("revoked key resumed")}
}
func TestPostgresAgentResumeExpiryAndBlockedOrganization(t *testing.T){
 db:=integrationDB(t)
 adminPub,adminPriv:=keys(t)
 setupOrg(t,db,"org","site","owner","OWNER",adminPub)
 pub,priv:=keys(t)
 ctx:=context.Background();s:=New(db)
 req,err:=s.Propose(ctx,"org","site",pub);if err!=nil{t.Fatal(err)}
 d:=makeDecision(t,"org",req.RequestID,"owner",Approve)
 if _,err=s.Decide(ctx,d,SignDecision(adminPriv,d));err!=nil{t.Fatal(err)}
 n,err:=s.Challenge(ctx,"org",req.RequestID);if err!=nil{t.Fatal(err)}
 enrolled,err:=s.Enroll(ctx,"org",req.RequestID,n,SignEnrollment(priv,"org",req.RequestID,n));if err!=nil{t.Fatal(err)}
 agent:=enrolled.AgentID.String
 n,err=s.BeginResume(ctx,"org",agent);if err!=nil{t.Fatal(err)}
 if _,err=db.ExecContext(ctx,`UPDATE lr_agent_resume_challenges SET expires_at=NOW()-INTERVAL '1 second' WHERE organization_id='org'`);err!=nil{t.Fatal(err)}
 if err=s.VerifyResume(ctx,"org",agent,n,SignResume(priv,"org",agent,n));!errors.Is(err,ErrDenied){t.Fatal("expired resume verified")}
 n,err=s.BeginResume(ctx,"org",agent);if err!=nil{t.Fatal(err)}
 if _,err=db.ExecContext(ctx,`UPDATE lr_organizations SET status='BLOCKED' WHERE organization_id='org'`);err!=nil{t.Fatal(err)}
 if _,err=s.ResolveIdentity(ctx,"org",pub);!errors.Is(err,ErrDenied){t.Fatal("blocked org resolved")}
 if err=s.VerifyResume(ctx,"org",agent,n,SignResume(priv,"org",agent,n));!errors.Is(err,ErrDenied){t.Fatal("blocked org resumed")}
 if _,err=s.BeginResume(ctx,"org",agent);!errors.Is(err,ErrDenied){t.Fatal("blocked org challenge")}
}
