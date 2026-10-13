package pgcapability

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "database/sql"
 "encoding/base64"
 "encoding/hex"
 "errors"
 "os"
 "net/url"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/pgpairing"
 _ "github.com/lib/pq"
)
func disposable(t *testing.T)*sql.DB{
 t.Helper()
 dsn:=os.Getenv("LOCALREACH_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("disposable PostgreSQL not configured")}
 u,err:=url.Parse(dsn)
 if err!=nil||u.Scheme!="postgres"||u.Path!="/localreach_test"||
 u.Hostname()!="127.0.0.1"||u.Query().Get("sslmode")!="disable"{
  t.Fatal("never touch anything other than disposable loopback localreach_test")
 }
 db,err:=sql.Open("postgres",dsn);if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){db.Close()})
 for _,name:=range []string{"060_pairing_postgres.sql","066_device_read_grants.sql"}{
  contents,err:=os.ReadFile(filepath.Join("..","..","migrations",name))
  if err!=nil{t.Fatal(err)}
  if _,err=db.Exec(string(contents));err!=nil{t.Fatal(err)}
 }
 if _,err=db.Exec(`TRUNCATE lr_device_read_audit,lr_device_read_decision_nonces,
 lr_device_read_grants,lr_pairing_audit,lr_agents,lr_pairing_challenges,
 lr_decision_nonces,lr_pairings,lr_admin_keys,lr_sites,lr_organizations CASCADE`);err!=nil{t.Fatal(err)}
 return db
}
func pair(t *testing.T)(ed25519.PublicKey,ed25519.PrivateKey){
 t.Helper();p,k,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)};return p,k
}
func newNonce(t *testing.T)string{
 t.Helper();b:=make([]byte,32);if _,e:=rand.Read(b);e!=nil{t.Fatal(e)}
 return base64.RawURLEncoding.EncodeToString(b)
}
func seed(t *testing.T,db *sql.DB,org,site,admin string)(string,ed25519.PrivateKey){
 t.Helper();ctx:=context.Background()
 adminPub,adminPriv:=pair(t)
 for _,row:=range []struct{sql string;args []any}{
  {`INSERT INTO lr_organizations(organization_id) VALUES($1)`,[]any{org}},
  {`INSERT INTO lr_sites(organization_id,site_id) VALUES($1,$2)`,[]any{org,site}},
  {`INSERT INTO lr_admin_keys(organization_id,admin_id,public_key,role)
 VALUES($1,$2,$3,'OWNER')`,[]any{org,admin,[]byte(adminPub)}},
 }{if _,e:=db.Exec(row.sql,row.args...);e!=nil{t.Fatal(e)}}
 agentPub,agentPriv:=pair(t);s:=pgpairing.New(db)
 r,e:=s.Propose(ctx,org,site,agentPub);if e!=nil{t.Fatal(e)}
 d:=pgpairing.AdminDecision{
 Organization:org,RequestID:r.RequestID,AdminID:admin,Action:pgpairing.Approve,
 Nonce:newNonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix()}
 if _,e=s.Decide(ctx,d,pgpairing.SignDecision(adminPriv,d));e!=nil{t.Fatal(e)}
 challenge,e:=s.Challenge(ctx,org,r.RequestID);if e!=nil{t.Fatal(e)}
 enrolled,e:=s.Enroll(ctx,org,r.RequestID,challenge,
 pgpairing.SignEnrollment(agentPriv,org,r.RequestID,challenge))
 if e!=nil||!enrolled.AgentID.Valid{t.Fatalf("enrollment failed: %v",e)}
 return enrolled.AgentID.String,adminPriv
}
func decision(t *testing.T,org,site,agent,admin,cap,action string)Decision{
 t.Helper()
 return Decision{
 Organization:org,Site:site,AgentID:agent,AdminID:admin,Capability:cap,
 DeviceFingerprint:hex.EncodeToString(make([]byte,32)),Action:action,
 Nonce:newNonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
}
func TestReadGrantRequiresDistinctSignedApprovalAndScopes(t *testing.T){
 db:=disposable(t);ctx:=context.Background()
 id,priv:=seed(t,db,"org","kitchen","owner")
 s:=New(db)
 d:=decision(t,"org","kitchen",id,"owner",PrinterDiscovery,Grant)
 yes,err:=s.Allowed(ctx,"org","kitchen",id,d.DeviceFingerprint,PrinterDiscovery)
 if err!=nil||yes{t.Fatal("implicit device access before separate permission")}
 wrongPub,wrongPriv:=pair(t);_ =wrongPub
 if err=s.Decide(ctx,d,Sign(wrongPriv,d));!errors.Is(err,ErrDenied){t.Fatal("wrong signing key grant")}
 if err=s.Decide(ctx,d,Sign(priv,d));err!=nil{t.Fatal(err)}
 if err=s.Decide(ctx,d,Sign(priv,d));!errors.Is(err,ErrDenied){t.Fatal("replayed grant accepted")}
 yes,err=s.Allowed(ctx,"org","kitchen",id,d.DeviceFingerprint,PrinterDiscovery)
 if err!=nil||!yes{t.Fatalf("legitimate discovery read not allowed: %v",err)}
 for _,scope:=range []struct{org,site,agent,fingerprint,capability string}{
  {"another","kitchen",id,d.DeviceFingerprint,PrinterDiscovery},
  {"org","other-site",id,d.DeviceFingerprint,PrinterDiscovery},
  {"org","kitchen","another-agent",d.DeviceFingerprint,PrinterDiscovery},
  {"org","kitchen",id,hex.EncodeToString([]byte("another device fingerprint-----")),PrinterDiscovery},
  {"org","kitchen",id,d.DeviceFingerprint,AttendanceDiscovery},
 }{
  granted,e:=s.Allowed(ctx,scope.org,scope.site,scope.agent,scope.fingerprint,scope.capability)
  if e==nil&&granted{t.Fatalf("grant leaked to %+v",scope)}
 }
 revoke:=decision(t,"org","kitchen",id,"owner",PrinterDiscovery,Revoke)
 if err=s.Decide(ctx,revoke,Sign(priv,revoke));err!=nil{t.Fatal(err)}
 yes,err=s.Allowed(ctx,"org","kitchen",id,d.DeviceFingerprint,PrinterDiscovery)
 if err!=nil||yes{t.Fatal("revoked device permission remains active")}
 if err=s.Decide(ctx,revoke,Sign(priv,revoke));!errors.Is(err,ErrDenied){t.Fatal("revocation replay")}
 var count int
 if err=db.QueryRow(`SELECT COUNT(*) FROM lr_device_read_audit WHERE organization_id='org'`).Scan(&count);err!=nil||count!=2{
  t.Fatalf("grant+revoke audit must be atomic, got %d: %v",count,err)
 }
}
func TestDiscoveryGrantFailsClosedOnExpiryAdminAndAgentRevocation(t *testing.T){
 db:=disposable(t);ctx:=context.Background()
 id,priv:=seed(t,db,"org","site","owner")
 s:=New(db)
 d:=decision(t,"org","site",id,"owner",AttendanceDiscovery,Grant)
 if err:=s.Decide(ctx,d,Sign(priv,d));err!=nil{t.Fatal(err)}
 if _,err:=db.Exec(`UPDATE lr_device_read_grants SET expires_at=NOW()-INTERVAL '1 second'`);err!=nil{t.Fatal(err)}
 ok,err:=s.Allowed(ctx,"org","site",id,d.DeviceFingerprint,AttendanceDiscovery)
 if err!=nil||ok{t.Fatal("expired permission allowed")}
 d.Nonce=newNonce(t)
 if err=s.Decide(ctx,d,Sign(priv,d));err!=nil{t.Fatal(err)}
 if _,err=db.Exec(`UPDATE lr_admin_keys SET status='REVOKED' WHERE organization_id='org'`);err!=nil{t.Fatal(err)}
 ok,err=s.Allowed(ctx,"org","site",id,d.DeviceFingerprint,AttendanceDiscovery)
 if err!=nil||ok{t.Fatal("revoked grant issuer still authorizes")}
 d.Nonce=newNonce(t)
 if err=s.Decide(ctx,d,Sign(priv,d));!errors.Is(err,ErrDenied){t.Fatal("revoked admin signed new grant")}
 if _,err=db.Exec(`UPDATE lr_admin_keys SET status='ACTIVE';UPDATE lr_agents SET revoked_at=NOW()`);err!=nil{t.Fatal(err)}
 ok,err=s.Allowed(ctx,"org","site",id,d.DeviceFingerprint,AttendanceDiscovery)
 if err!=nil||ok{t.Fatal("revoked agent still has grant")}
}
func TestSignatureIsBoundToEveryGrantDimension(t *testing.T){
 d:=Decision{Organization:"o",Site:"s",AgentID:"a",AdminID:"admin",
 DeviceFingerprint:hex.EncodeToString(make([]byte,32)),Capability:PrinterDiscovery,
 Action:Grant,Nonce:"nonce",IssuedAt:100,ExpiresAt:110}
 pub,priv:=pair(t)
 signed:=Sign(priv,d)
 if !ed25519.Verify(pub,Message(d),signed){t.Fatal("valid signature failed")}
 changes:=[]func(*Decision){
  func(x *Decision){x.Organization="other"},
  func(x *Decision){x.Site="other"},
  func(x *Decision){x.AgentID="other"},
  func(x *Decision){x.DeviceFingerprint=hex.EncodeToString([]byte("different fingerprint bytes------"))},
  func(x *Decision){x.Capability=AttendanceDiscovery},
  func(x *Decision){x.Action=Revoke},
 }
 for _,change:=range changes{
  altered:=d;change(&altered)
  if ed25519.Verify(pub,Message(altered),signed){t.Fatal("signature did not bind dimension")}
 }
}
