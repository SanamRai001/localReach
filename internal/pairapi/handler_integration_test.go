package pairapi

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "database/sql"
 "encoding/base64"
 "encoding/json"
 "io"
 "net/http"
 "net/http/httptest"
 "net/url"
 "os"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/pgauth"
 "github.com/SanamRai001/localReach/internal/pgpairing"
 _ "github.com/lib/pq"
)
type nativeSigner struct{public ed25519.PublicKey;private ed25519.PrivateKey}
func newSigner(t *testing.T)*nativeSigner{
 t.Helper()
 public,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 return &nativeSigner{public:public,private:private}
}
func(s *nativeSigner)PublicKey()ed25519.PublicKey{return append(ed25519.PublicKey(nil),s.public...)}
func(s *nativeSigner)SignMessage(data []byte)([]byte,error){return ed25519.Sign(s.private,data),nil}
func nonce(t *testing.T)string{
 t.Helper()
 data:=make([]byte,32)
 if _,err:=rand.Read(data);err!=nil{t.Fatal(err)}
 return base64.RawURLEncoding.EncodeToString(data)
}
func testDB(t *testing.T)*sql.DB{
 t.Helper()
 dsn:=os.Getenv("LOCALREACH_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("no disposable PostgreSQL DSN")}
 u,err:=url.Parse(dsn)
 if err!=nil||u.Scheme!="postgres"||u.Path!="/localreach_test"{t.Fatal("refusing non-test PostgreSQL DB")}
 db,err:=sql.Open("postgres",dsn)
 if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){db.Close()})
 db.SetMaxOpenConns(8)
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 for _,name:=range []string{"060_pairing_postgres.sql","061_admin_sessions_postgres.sql","062_agent_resume.sql"}{
  content,err:=os.ReadFile(filepath.Join("..","..","migrations",name))
  if err!=nil{t.Fatal(err)}
  if _,err=db.ExecContext(ctx,string(content));err!=nil{t.Fatal(err)}
 }
 if _,err=db.ExecContext(ctx,`TRUNCATE lr_agent_identity_audit,lr_agent_resume_challenges,
 lr_admin_login_audit,lr_admin_sessions,lr_admin_login_challenges,
 lr_pairing_audit,lr_agents,lr_pairing_challenges,lr_decision_nonces,
 lr_pairings,lr_admin_keys,lr_sites,lr_organizations CASCADE`);err!=nil{t.Fatal(err)}
 return db
}
func prepare(t *testing.T,db *sql.DB)(*nativeSigner,string){
 t.Helper()
 admin:=newSigner(t)
 for _,insert:=range []struct{query string;args []any}{
  {`INSERT INTO lr_organizations(organization_id) VALUES($1)`,[]any{"org"}},
  {`INSERT INTO lr_sites(organization_id,site_id) VALUES($1,$2)`,[]any{"org","site"}},
  {`INSERT INTO lr_admin_keys(organization_id,admin_id,public_key,role) VALUES($1,$2,$3,'OWNER')`,[]any{"org","owner",[]byte(admin.public)}},
 }{if _,err:=db.Exec(insert.query,insert.args...);err!=nil{t.Fatal(err)}}
 auth:=pgauth.New(db)
 challenge,err:=auth.Challenge(context.Background(),"org","owner")
 if err!=nil{t.Fatal(err)}
 token,err:=auth.Authenticate(context.Background(),"org","owner",challenge,pgauth.SignChallenge(admin.private,"org","owner",challenge))
 if err!=nil{t.Fatal(err)}
 return admin,token
}
func post(t *testing.T,c *http.Client,base,path,token string,input any)(int,map[string]string){
 t.Helper()
 data,err:=json.Marshal(input);if err!=nil{t.Fatal(err)}
 req,err:=http.NewRequest(http.MethodPost,base+path,bytes.NewReader(data))
 if err!=nil{t.Fatal(err)}
 req.Header.Set("Content-Type","application/json")
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 response,err:=c.Do(req);if err!=nil{t.Fatal(err)}
 defer response.Body.Close()
 result:=map[string]string{}
 if response.StatusCode==200{
  raw,err:=io.ReadAll(response.Body);if err!=nil{t.Fatal(err)}
  if err=json.Unmarshal(raw,&result);err!=nil{t.Fatalf("bad response: %s %v",raw,err)}
 }
 return response.StatusCode,result
}
func TestAdminApprovedNativeTLSFlowAndRevocation(t *testing.T){
 db:=testDB(t)
 admin,token:=prepare(t,db)
 server:=httptest.NewTLSServer(Handler{Auth:pgauth.New(db),Pairing:pgpairing.New(db)})
 defer server.Close()
 ctx:=context.Background()
 agent:=newSigner(t)
 if status,_:=post(t,server.Client(),server.URL,"/v1/control/propose","",proposal{
  Organization:"org",Site:"site",PublicKey:base64.RawURLEncoding.EncodeToString(agent.PublicKey()),
 });status!=403{t.Fatalf("unauthenticated proposal accepted: %d",status)}
 status,resp:=post(t,server.Client(),server.URL,"/v1/control/propose",token,proposal{
  Organization:"org",Site:"site",PublicKey:base64.RawURLEncoding.EncodeToString(agent.PublicKey()),
 })
 if status!=200||resp["state"]!="PENDING"{t.Fatalf("proposal: %d %+v",status,resp)}
 id:=resp["requestId"]
 native,err:=agentremote.New(server.URL,server.Client());if err!=nil{t.Fatal(err)}
 if _,err=native.FinishEnrollment(ctx,"org",id,agent);err==nil{t.Fatal("enrolled without approval")}
 d:=pgpairing.AdminDecision{Organization:"org",RequestID:id,AdminID:"owner",Action:pgpairing.Approve,
  Nonce:nonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix()}
 body:=signedDecision{Organization:d.Organization,RequestID:d.RequestID,AdminID:d.AdminID,Action:d.Action,
  Nonce:d.Nonce,IssuedAt:d.IssuedAt,ExpiresAt:d.ExpiresAt,Signature:base64.RawURLEncoding.EncodeToString(pgpairing.SignDecision(admin.private,d))}
 if status,_=post(t,server.Client(),server.URL,"/v1/control/decide","bogus",body);status!=403{t.Fatal("wrong bearer token approved")}
 if status,_=post(t,server.Client(),server.URL,"/v1/control/decide",token,body);status!=200{t.Fatalf("signed admin decision: %d",status)}
 wrong:=newSigner(t)
 if _,err=native.FinishEnrollment(ctx,"org",id,wrong);err==nil{t.Fatal("wrong agent key enrolled")}
 // Wrong-key challenge remains valid but a new challenge cannot be issued
 // until it expires, so use a second approved request for the success case.
 next:=newSigner(t)
 status,resp=post(t,server.Client(),server.URL,"/v1/control/propose",token,proposal{
  Organization:"org",Site:"site",PublicKey:base64.RawURLEncoding.EncodeToString(next.PublicKey()),
 })
 if status!=200{t.Fatal("second proposal failed")}
 secondID:=resp["requestId"]
 d.RequestID=secondID;d.Nonce=nonce(t);d.IssuedAt=time.Now().Unix();d.ExpiresAt=time.Now().Add(time.Minute).Unix()
 body.RequestID=d.RequestID;body.Nonce=d.Nonce;body.IssuedAt=d.IssuedAt;body.ExpiresAt=d.ExpiresAt
 body.Signature=base64.RawURLEncoding.EncodeToString(pgpairing.SignDecision(admin.private,d))
 if status,_=post(t,server.Client(),server.URL,"/v1/control/decide",token,body);status!=200{t.Fatal("approval failed")}
 agentID,err:=native.FinishEnrollment(ctx,"org",secondID,next)
 if err!=nil||agentID==""{t.Fatalf("enroll: %v",err)}
 restored,err:=native.VerifyIdentity(ctx,"org",next)
 if err!=nil||restored!=agentID{t.Fatalf("resume proof failed: %v %s",err,restored)}
 if _,err=native.VerifyIdentity(ctx,"org",wrong);err==nil{t.Fatal("unpaired key resumed")}
 // Simulate gateway handler and database connection recreation.
 fresh,err:=sql.Open("postgres",os.Getenv("LOCALREACH_TEST_POSTGRES_DSN"));if err!=nil{t.Fatal(err)}
 defer fresh.Close()
 newServer:=httptest.NewTLSServer(Handler{Auth:pgauth.New(fresh),Pairing:pgpairing.New(fresh)})
 defer newServer.Close()
 reconnected,err:=agentremote.New(newServer.URL,newServer.Client());if err!=nil{t.Fatal(err)}
 again,err:=reconnected.VerifyIdentity(ctx,"org",next)
 if err!=nil||again!=agentID{t.Fatalf("identity restart: %v %s",err,again)}
 d.Action=pgpairing.Revoke;d.Nonce=nonce(t);d.IssuedAt=time.Now().Unix();d.ExpiresAt=time.Now().Add(time.Minute).Unix()
 body.Action=d.Action;body.Nonce=d.Nonce;body.IssuedAt=d.IssuedAt;body.ExpiresAt=d.ExpiresAt
 body.Signature=base64.RawURLEncoding.EncodeToString(pgpairing.SignDecision(admin.private,d))
 if status,_=post(t,newServer.Client(),newServer.URL,"/v1/control/decide",token,body);status!=200{t.Fatalf("revoke: %d",status)}
 if _,err=reconnected.VerifyIdentity(ctx,"org",next);err==nil{t.Fatal("revoked native identity resumed")}
}
func TestHTTPSOriginMethodBodyAndPlaintextDeny(t *testing.T){
 h:=Handler{}
 plain:=httptest.NewServer(h);defer plain.Close()
 if status,_:=post(t,plain.Client(),plain.URL,"/v1/agent/enrollment-challenge","",agentRequest{Organization:"org"});status!=426{t.Fatal("plaintext allowed")}
 secure:=httptest.NewTLSServer(h);defer secure.Close()
 req,err:=http.NewRequest("POST",secure.URL+"/v1/agent/enroll",bytes.NewBufferString("{}"))
 if err!=nil{t.Fatal(err)}
 req.Header.Set("Content-Type","application/json")
 req.Header.Set("Origin","https://attacker.example")
 response,err:=secure.Client().Do(req);if err!=nil{t.Fatal(err)}
 response.Body.Close()
 if response.StatusCode!=403{t.Fatalf("browser request: %d",response.StatusCode)}
 req,err=http.NewRequest("GET",secure.URL+"/v1/agent/enroll",nil)
 if err!=nil{t.Fatal(err)}
 response,err=secure.Client().Do(req);if err!=nil{t.Fatal(err)}
 response.Body.Close()
 if response.StatusCode!=405{t.Fatalf("method: %d",response.StatusCode)}
}
