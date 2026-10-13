package pgauth

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "database/sql"
 "errors"
 "net/url"
 "os"
 "path/filepath"
 "testing"

 _ "github.com/lib/pq"
)
func dbForTest(t *testing.T)*sql.DB{
 t.Helper()
 dsn:=os.Getenv("LOCALREACH_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("PostgreSQL test DSN missing")}
 u,err:=url.Parse(dsn);if err!=nil||u.Scheme!="postgres"||u.Path!="/localreach_test"{t.Fatal("refusing to modify non-test database")}
 db,err:=sql.Open("postgres",dsn);if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){db.Close()})
 ctx:=context.Background()
 if err=db.PingContext(ctx);err!=nil{t.Fatal(err)}
 for _,path:=range []string{"060_pairing_postgres.sql","061_admin_sessions_postgres.sql"}{
  raw,err:=os.ReadFile(filepath.Join("..","..","migrations",path));if err!=nil{t.Fatal(err)}
  if _,err=db.ExecContext(ctx,string(raw));err!=nil{t.Fatal(err)}
 }
 if _,err=db.ExecContext(ctx,`TRUNCATE lr_admin_login_audit,lr_admin_sessions,lr_admin_login_challenges,
 lr_pairing_audit,lr_agents,lr_pairing_challenges,lr_decision_nonces,lr_pairings,lr_admin_keys,lr_sites,lr_organizations CASCADE`);err!=nil{t.Fatal(err)}
 return db
}
func setup(t *testing.T,db *sql.DB,org,admin,role string,pub ed25519.PublicKey){
 t.Helper()
 if _,err:=db.Exec(`INSERT INTO lr_organizations(organization_id) VALUES($1)`,org);err!=nil{t.Fatal(err)}
 if _,err:=db.Exec(`INSERT INTO lr_admin_keys(organization_id,admin_id,public_key,role) VALUES($1,$2,$3,$4)`,org,admin,[]byte(pub),role);err!=nil{t.Fatal(err)}
}
func TestSignedLoginSessionAndRevocation(t *testing.T){
 db:=dbForTest(t)
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 setup(t,db,"org","owner","OWNER",pub)
 s:=New(db);ctx:=context.Background()
 nonce,err:=s.Challenge(ctx,"org","owner");if err!=nil{t.Fatal(err)}
 if _,err=s.Challenge(ctx,"org","owner");!errors.Is(err,ErrDenied){t.Fatal("second active challenge accepted")}
 _,attacker,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if _,err=s.Authenticate(ctx,"org","owner",nonce,SignChallenge(attacker,"org","owner",nonce));!errors.Is(err,ErrDenied){t.Fatal("wrong key logged in")}
 token,err:=s.Authenticate(ctx,"org","owner",nonce,SignChallenge(priv,"org","owner",nonce));if err!=nil{t.Fatal(err)}
 if _,err=s.Authenticate(ctx,"org","owner",nonce,SignChallenge(priv,"org","owner",nonce));!errors.Is(err,ErrDenied){t.Fatal("challenge replay issued session")}
 if _,err=s.Authorize(ctx,"another",token,"OWNER");!errors.Is(err,ErrDenied){t.Fatal("cross-tenant session accepted")}
 actor,err:=s.Authorize(ctx,"org",token,"OWNER","ADMIN")
 if err!=nil||actor.AdminID!="owner"||actor.Role!="OWNER"{t.Fatalf("auth: %v %+v",err,actor)}
 if _,err=s.Authorize(ctx,"org",token,"VIEWER");!errors.Is(err,ErrDenied){t.Fatal("unauthorized role admitted")}
 // Simulate a new process opening the same database.
 reopened,err:=sql.Open("postgres",os.Getenv("LOCALREACH_TEST_POSTGRES_DSN"));if err!=nil{t.Fatal(err)}
 defer reopened.Close()
 again:=New(reopened)
 if _,err=again.Authorize(ctx,"org",token,"OWNER");err!=nil{t.Fatalf("session not durable: %v",err)}
 if _,err=db.Exec(`UPDATE lr_admin_keys SET role='VIEWER' WHERE organization_id='org' AND admin_id='owner'`);err!=nil{t.Fatal(err)}
 if _,err=again.Authorize(ctx,"org",token,"OWNER");!errors.Is(err,ErrDenied){t.Fatal("stale owner role authorized")}
 if _,err=db.Exec(`UPDATE lr_admin_keys SET role='OWNER',status='REVOKED' WHERE organization_id='org' AND admin_id='owner'`);err!=nil{t.Fatal(err)}
 if _,err=again.Authorize(ctx,"org",token,"OWNER");!errors.Is(err,ErrDenied){t.Fatal("revoked signing key session authorized")}
}
func TestLogoutAndExpiredSession(t *testing.T){
 db:=dbForTest(t)
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 setup(t,db,"org","admin","ADMIN",pub)
 s:=New(db);ctx:=context.Background()
 nonce,err:=s.Challenge(ctx,"org","admin");if err!=nil{t.Fatal(err)}
 token,err:=s.Authenticate(ctx,"org","admin",nonce,SignChallenge(priv,"org","admin",nonce));if err!=nil{t.Fatal(err)}
 if err=s.Logout(ctx,"org",token);err!=nil{t.Fatal(err)}
 if _,err=s.Authorize(ctx,"org",token,"ADMIN");!errors.Is(err,ErrDenied){t.Fatal("logged-out session accepted")}
 if err=s.Logout(ctx,"org",token);!errors.Is(err,ErrDenied){t.Fatal("second logout accepted")}
 nonce,err=s.Challenge(ctx,"org","admin");if err!=nil{t.Fatal(err)}
 next,err:=s.Authenticate(ctx,"org","admin",nonce,SignChallenge(priv,"org","admin",nonce));if err!=nil{t.Fatal(err)}
 if _,err=db.Exec(`UPDATE lr_admin_sessions SET expires_at=NOW()-INTERVAL '1 second' WHERE organization_id='org'`);err!=nil{t.Fatal(err)}
 if _,err=s.Authorize(ctx,"org",next,"ADMIN");!errors.Is(err,ErrDenied){t.Fatal("expired token accepted")}
 if _,err=db.Exec(`UPDATE lr_admin_sessions SET expires_at=NOW()+INTERVAL '1 minute' WHERE organization_id='org' AND revoked_at IS NULL`);err!=nil{t.Fatal(err)}
 if _,err=db.Exec(`UPDATE lr_organizations SET status='BLOCKED' WHERE organization_id='org'`);err!=nil{t.Fatal(err)}
 if _,err=s.Authorize(ctx,"org",next,"ADMIN");!errors.Is(err,ErrDenied){t.Fatal("blocked org allowed session")}
 var audited int
 if err=db.QueryRow(`SELECT COUNT(*) FROM lr_admin_login_audit WHERE organization_id='org'`).Scan(&audited);err!=nil{t.Fatal(err)}
 if audited!=5{t.Fatalf("expected challenge/login/logout/challenge/login audit =5, got %d",audited)}
}
