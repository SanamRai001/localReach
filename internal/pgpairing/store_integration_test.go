package pgpairing

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "database/sql"
 "encoding/base64"
 "errors"
 "net/url"
 "os"
 "path/filepath"
 "sync"
 "sync/atomic"
 "testing"
 "time"

 _ "github.com/lib/pq"
)

func integrationDB(t *testing.T)*sql.DB{
 t.Helper()
 dsn:=os.Getenv("LOCALREACH_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("PostgreSQL integration DSN not configured")}
 parsed,err:=url.Parse(dsn)
 if err!=nil||parsed.Scheme!="postgres"||parsed.Path!="/localreach_test"{t.Fatal("refusing to modify database other than localreach_test")}
 db,err:=sql.Open("postgres",dsn)
 if err!=nil{t.Fatal(err)}
 db.SetMaxOpenConns(8)
 t.Cleanup(func(){db.Close()})
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 if err=db.PingContext(ctx);err!=nil{t.Fatal(err)}
 for _,migrationName:=range []string{"060_pairing_postgres.sql","062_agent_resume.sql","063_pairing_invitations.sql"}{
  migration,readErr:=os.ReadFile(filepath.Join("..","..","migrations",migrationName))
  if readErr!=nil{t.Fatal(readErr)}
  if _,err=db.ExecContext(ctx,string(migration));err!=nil{t.Fatal(err)}
 }
 if _,err=db.ExecContext(ctx,`TRUNCATE lr_pairing_invitation_audit,lr_pairing_invitations,lr_agent_identity_audit,lr_agent_resume_challenges,lr_pairing_audit,lr_agents,lr_pairing_challenges,lr_decision_nonces,lr_pairings,lr_admin_keys,lr_sites,lr_organizations CASCADE`);err!=nil{t.Fatal(err)}
 return db
}
func keys(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper()
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 return pub,priv
}
func randomNonce(t *testing.T)string{
 t.Helper()
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{t.Fatal(err)}
 return base64.RawURLEncoding.EncodeToString(b)
}
func setupOrg(t *testing.T,db *sql.DB,org,site,admin,role string,pub ed25519.PublicKey){
 t.Helper()
 ctx:=context.Background()
 if _,err:=db.ExecContext(ctx,`INSERT INTO lr_organizations(organization_id) VALUES ($1)`,org);err!=nil{t.Fatal(err)}
 if _,err:=db.ExecContext(ctx,`INSERT INTO lr_sites(organization_id,site_id) VALUES($1,$2)`,org,site);err!=nil{t.Fatal(err)}
 if _,err:=db.ExecContext(ctx,`INSERT INTO lr_admin_keys(organization_id,admin_id,public_key,role) VALUES($1,$2,$3,$4)`,org,admin,[]byte(pub),role);err!=nil{t.Fatal(err)}
}
func makeDecision(t *testing.T,org,id,admin string,action Action)AdminDecision{
 t.Helper()
 now:=time.Now().UTC()
 return AdminDecision{Organization:org,RequestID:id,AdminID:admin,Action:action,Nonce:randomNonce(t),IssuedAt:now.Unix(),ExpiresAt:now.Add(time.Minute).Unix()}
}
func TestPostgresPairingApprovalEnrollmentRevocation(t *testing.T){
 db:=integrationDB(t)
 adminPub,adminPriv:=keys(t)
 setupOrg(t,db,"org-a","site-a","admin-1","ADMIN",adminPub)
 store:=New(db);ctx:=context.Background()
 agentPub,agentPriv:=keys(t)
 proposed,err:=store.Propose(ctx,"org-a","site-a",agentPub);if err!=nil{t.Fatal(err)}
 if _,err=store.Propose(ctx,"org-a","site-a",agentPub);err==nil{t.Fatal("duplicate public key admitted")}
 if _,err=store.Get(ctx,"org-b",proposed.RequestID);!errors.Is(err,ErrDenied){t.Fatal("cross-tenant pairing disclosed")}
 decision:=makeDecision(t,"org-a",proposed.RequestID,"admin-1",Approve)
 _,attacker:=keys(t)
 if _,err=store.Decide(ctx,decision,SignDecision(attacker,decision));!errors.Is(err,ErrDenied){t.Fatal("unauthorized approval")}
 approved,err:=store.Decide(ctx,decision,SignDecision(adminPriv,decision))
 if err!=nil||approved.State!="APPROVED"{t.Fatalf("approval: %v %+v",err,approved)}
 if _,err=store.Decide(ctx,decision,SignDecision(adminPriv,decision));!errors.Is(err,ErrDenied){t.Fatal("signed decision replay")}
 // Recreate connection to prove state lives in PostgreSQL, not process RAM.
 second,err:=sql.Open("postgres",os.Getenv("LOCALREACH_TEST_POSTGRES_DSN"));if err!=nil{t.Fatal(err)}
 defer second.Close()
 restarted:=New(second)
 status,err:=restarted.Get(ctx,"org-a",proposed.RequestID)
 if err!=nil||status.State!="APPROVED"{t.Fatalf("approval lost: %v %+v",err,status)}
 challenge,err:=restarted.Challenge(ctx,"org-a",proposed.RequestID);if err!=nil{t.Fatal(err)}
 if _,err=restarted.Challenge(ctx,"org-a",proposed.RequestID);!errors.Is(err,ErrDenied){t.Fatal("multiple overlapping challenge issued")}
 if _,err=restarted.Enroll(ctx,"org-a",proposed.RequestID,challenge,SignEnrollment(attacker,"org-a",proposed.RequestID,challenge));!errors.Is(err,ErrDenied){t.Fatal("wrong agent enrolled")}
 enrolled,err:=restarted.Enroll(ctx,"org-a",proposed.RequestID,challenge,SignEnrollment(agentPriv,"org-a",proposed.RequestID,challenge))
 if err!=nil||enrolled.State!="ENROLLED"||!enrolled.AgentID.Valid{t.Fatalf("enrollment: %v %+v",err,enrolled)}
 active,err:=restarted.AgentActive(ctx,"org-a",enrolled.AgentID.String);if err!=nil||!active{t.Fatalf("expected active paired agent: %v %v",active,err)}
 if _,err=restarted.Enroll(ctx,"org-a",proposed.RequestID,challenge,SignEnrollment(agentPriv,"org-a",proposed.RequestID,challenge));!errors.Is(err,ErrDenied){t.Fatal("enrollment replay accepted")}
 revocation:=makeDecision(t,"org-a",proposed.RequestID,"admin-1",Revoke)
 after,err:=restarted.Decide(ctx,revocation,SignDecision(adminPriv,revocation))
 if err!=nil||after.State!="REVOKED"{t.Fatalf("revoke: %v %+v",err,after)}
 active,err=restarted.AgentActive(ctx,"org-a",enrolled.AgentID.String);if err!=nil||active{t.Fatalf("revoked agent remains active: %v %v",active,err)}
 var eventCount int
 if err=db.QueryRowContext(ctx,`SELECT COUNT(*) FROM lr_pairing_audit WHERE organization_id='org-a' AND request_id=$1`,proposed.RequestID).Scan(&eventCount);err!=nil{t.Fatal(err)}
 if eventCount!=4{t.Fatalf("expected all 4 events, got %d",eventCount)}
}
func TestPostgresDecisionRollbackOnAuditFailure(t *testing.T){
 db:=integrationDB(t)
 adminPub,adminPriv:=keys(t);setupOrg(t,db,"org","site","admin","OWNER",adminPub)
 ctx:=context.Background();store:=New(db)
 agentPub,_:=keys(t)
 req,err:=store.Propose(ctx,"org","site",agentPub);if err!=nil{t.Fatal(err)}
 _,err=db.ExecContext(ctx,`CREATE FUNCTION lr_test_deny_audit() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'test audit failure'; END $$`)
 if err!=nil{t.Fatal(err)}
 _,err=db.ExecContext(ctx,`CREATE TRIGGER lr_test_audit_denied BEFORE INSERT ON lr_pairing_audit FOR EACH ROW EXECUTE FUNCTION lr_test_deny_audit()`)
 if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){
  _,_=db.Exec(`DROP TRIGGER IF EXISTS lr_test_audit_denied ON lr_pairing_audit`)
  _,_=db.Exec(`DROP FUNCTION IF EXISTS lr_test_deny_audit()`)
 })
 d:=makeDecision(t,"org",req.RequestID,"admin",Approve)
 if _,err=store.Decide(ctx,d,SignDecision(adminPriv,d));err==nil{t.Fatal("audit failure did not abort approval")}
 rec,err:=store.Get(ctx,"org",req.RequestID)
 if err!=nil||rec.State!="PENDING"{t.Fatalf("approval committed despite audit failure: %v %+v",err,rec)}
 var consumed int
 if err=db.QueryRowContext(ctx,`SELECT COUNT(*) FROM lr_decision_nonces`).Scan(&consumed);err!=nil{t.Fatal(err)}
 if consumed!=0{t.Fatal("approval nonce leaked outside rolled-back transaction")}
 if _,err=db.ExecContext(ctx,`DROP TRIGGER lr_test_audit_denied ON lr_pairing_audit`);err!=nil{t.Fatal(err)}
 if _,err=store.Decide(ctx,d,SignDecision(adminPriv,d));err!=nil{t.Fatalf("valid retry after rollback denied: %v",err)}
}
func TestPostgresCrossTenantRoleAndConcurrency(t *testing.T){
 db:=integrationDB(t)
 adminPub,adminPriv:=keys(t);setupOrg(t,db,"org-a","site","admin","VIEWER",adminPub)
 otherPub,otherPriv:=keys(t);setupOrg(t,db,"org-b","site","admin","OWNER",otherPub)
 ctx:=context.Background();s:=New(db)
 agentPub,_:=keys(t)
 req,err:=s.Propose(ctx,"org-a","site",agentPub);if err!=nil{t.Fatal(err)}
 viewer:=makeDecision(t,"org-a",req.RequestID,"admin",Approve)
 if _,err=s.Decide(ctx,viewer,SignDecision(adminPriv,viewer));!errors.Is(err,ErrDenied){t.Fatal("viewer approved")}
 cross:=makeDecision(t,"org-b",req.RequestID,"admin",Approve)
 if _,err=s.Decide(ctx,cross,SignDecision(otherPriv,cross));!errors.Is(err,ErrDenied){t.Fatal("cross-tenant admin approved")}
 if _,err=db.ExecContext(ctx,`UPDATE lr_admin_keys SET role='ADMIN' WHERE organization_id='org-a'`);err!=nil{t.Fatal(err)}
 d:=makeDecision(t,"org-a",req.RequestID,"admin",Approve)
 var successful atomic.Int64
 var wg sync.WaitGroup
 for i:=0;i<12;i++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   if _,err:=s.Decide(ctx,d,SignDecision(adminPriv,d));err==nil{successful.Add(1)}
  }()
 }
 wg.Wait()
 if successful.Load()!=1{t.Fatalf("concurrent approvals succeeded %d times",successful.Load())}
 var count int
 if err=db.QueryRowContext(ctx,`SELECT COUNT(*) FROM lr_decision_nonces`).Scan(&count);err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("replay ledger expected one, got %d",count)}
}
