package agentlifecycle

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "database/sql"
 "encoding/base64"
 "errors"
 "net/url"
 "os"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/pgpairing"
 _ "github.com/lib/pq"
)

func lifecycleDatabase(t *testing.T)*sql.DB{
 t.Helper()
 dsn:=os.Getenv("LOCALREACH_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("PostgreSQL test DSN not configured")}
 u,err:=url.Parse(dsn)
 if err!=nil||u.Scheme!="postgres"||u.Path!="/localreach_test"{t.Fatal("only disposable localreach_test accepted")}
 db,err:=sql.Open("postgres",dsn);if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){db.Close()})
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
 for _,name:=range []string{"060_pairing_postgres.sql","062_agent_resume.sql"}{
  data,err:=os.ReadFile(filepath.Join("..","..","migrations",name))
  if err!=nil{t.Fatal(err)}
  if _,err=db.ExecContext(ctx,string(data));err!=nil{t.Fatal(err)}
 }
 if _,err=db.ExecContext(ctx,`TRUNCATE lr_agent_identity_audit,lr_agent_resume_challenges,
 lr_pairing_audit,lr_agents,lr_pairing_challenges,lr_decision_nonces,lr_pairings,
 lr_admin_keys,lr_sites,lr_organizations CASCADE`);err!=nil{t.Fatal(err)}
 return db
}

func TestCoordinatorPostgreSQLApprovedIdentityAndRestart(t *testing.T){
 db:=lifecycleDatabase(t)
 ctx:=context.Background()
 adminPub,adminPriv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 for _,statement:=range []struct{sql string;args []any}{
  {`INSERT INTO lr_organizations(organization_id) VALUES($1)`,[]any{"org"}},
  {`INSERT INTO lr_sites(organization_id,site_id) VALUES($1,$2)`,[]any{"org","site"}},
  {`INSERT INTO lr_admin_keys(organization_id,admin_id,public_key,role) VALUES($1,$2,$3,'OWNER')`,[]any{"org","owner",[]byte(adminPub)}},
 }{
  if _,err=db.ExecContext(ctx,statement.sql,statement.args...);err!=nil{t.Fatal(err)}
 }
 signer:=newSigner(t)
 backend:=pgpairing.New(db)
 native:=Coordinator{Backend:backend}
 proposal,err:=native.RequestPairing(ctx,"org","site",signer);if err!=nil{t.Fatal(err)}
 if _,err=native.FinishPairing(ctx,"org",proposal.RequestID,signer);!errors.Is(err,ErrDenied){t.Fatal("unapproved key was enrolled")}
 decision:=pgpairing.AdminDecision{
  Organization:"org",RequestID:proposal.RequestID,AdminID:"owner",
  Action:pgpairing.Approve,Nonce:randomLocalNonce(t),
  IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
 if _,err=backend.Decide(ctx,decision,pgpairing.SignDecision(adminPriv,decision));err!=nil{t.Fatal(err)}
 wrong:=newSigner(t)
 if _,err=native.FinishPairing(ctx,"org",proposal.RequestID,wrong);!errors.Is(err,ErrDenied){t.Fatal("wrong key enrolled")}
 enrolled,err:=native.FinishPairing(ctx,"org",proposal.RequestID,signer)
 if err!=nil||enrolled.State!="ENROLLED"||!enrolled.AgentID.Valid{t.Fatalf("enrollment failed: %v %+v",err,enrolled)}
 reopened,err:=sql.Open("postgres",os.Getenv("LOCALREACH_TEST_POSTGRES_DSN"));if err!=nil{t.Fatal(err)}
 defer reopened.Close()
 afterRestart:=Coordinator{Backend:pgpairing.New(reopened)}
 if _,err=afterRestart.VerifySavedIdentity(ctx,"org",wrong);!errors.Is(err,ErrDenied){t.Fatal("wrong key restored")}
 agentID,err:=afterRestart.VerifySavedIdentity(ctx,"org",signer)
 if err!=nil||agentID!=enrolled.AgentID.String{t.Fatalf("approved native identity did not recover: %v %q",err,agentID)}
 revoke:=pgpairing.AdminDecision{
  Organization:"org",RequestID:proposal.RequestID,AdminID:"owner",Action:pgpairing.Revoke,
  Nonce:randomLocalNonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
 if _,err=backend.Decide(ctx,revoke,pgpairing.SignDecision(adminPriv,revoke));err!=nil{t.Fatal(err)}
 if _,err=afterRestart.VerifySavedIdentity(ctx,"org",signer);!errors.Is(err,ErrDenied){t.Fatal("revoked identity recovered")}
 nextSigner:=newSigner(t)
 next,err:=afterRestart.RequestPairing(ctx,"org","site",nextSigner)
 if err!=nil||next.State!="PENDING"||next.RequestID==proposal.RequestID{t.Fatal("fresh unapproved rotation proposal failed")}
 if _,err=afterRestart.VerifySavedIdentity(ctx,"org",nextSigner);!errors.Is(err,ErrDenied){t.Fatal("new key inherited permissions")}
}
func randomLocalNonce(t *testing.T)string{
 t.Helper()
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{t.Fatal(err)}
 return base64.RawURLEncoding.EncodeToString(b)
}
