package pilotacceptance

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "database/sql"
 "encoding/pem"
 "encoding/base64"
 "errors"
 "math/big"
 "net"
 "net/http"
 "net/url"
 "os"
 "os/exec"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/pgpairing"
 _ "github.com/lib/pq"
)
const controlAddress="127.0.0.1:19443"

// The real control-plane executable runs in a separate OS process with its
// own PostgreSQL connections and server-side private TLS key. The client has
// ONLY a test Ed25519 signer and a trusted certificate; no database password.
type testSigner struct{pub ed25519.PublicKey;private ed25519.PrivateKey}
func(s testSigner)PublicKey()ed25519.PublicKey{return append(ed25519.PublicKey(nil),s.pub...)}
func(s testSigner)SignMessage(m []byte)([]byte,error){return ed25519.Sign(s.private,m),nil}
func key(t *testing.T)testSigner{
 t.Helper()
 p,k,e:=ed25519.GenerateKey(rand.Reader)
 if e!=nil{t.Fatal(e)}
 return testSigner{pub:p,private:k}
}
func fixtureDB(t *testing.T)*sql.DB{
 t.Helper()
 dsn:=os.Getenv("LOCALREACH_TEST_POSTGRES_DSN")
 parsed,err:=url.Parse(dsn)
 if err!=nil||parsed.Scheme!="postgres"||parsed.Path!="/localreach_test"||
 parsed.Hostname()!="127.0.0.1"||parsed.Query().Get("sslmode")!="disable"{
  t.Fatal("separate-process fixture refuses anything except disposable loopback localreach_test")
 }
 db,err:=sql.Open("postgres",dsn)
 if err!=nil{t.Fatal(err)}
 t.Cleanup(func(){db.Close()})
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
 defer cancel()
 for _,migration:=range []string{
  "060_pairing_postgres.sql","061_admin_sessions_postgres.sql",
  "062_agent_resume.sql","063_pairing_invitations.sql",
  "064_shared_admission.sql","065_agent_connections.sql",
 }{
  raw,err:=os.ReadFile(filepath.Join("..","..","migrations",migration))
  if err!=nil{t.Fatal(err)}
  if _,err=db.ExecContext(ctx,string(raw));err!=nil{t.Fatal(err)}
 }
 _,err=db.ExecContext(ctx,"TRUNCATE "+
  "lr_agent_connection_audit,lr_agent_connections,lr_admission_windows,"+
  "lr_pairing_invitation_audit,lr_pairing_invitations,lr_agent_identity_audit,"+
  "lr_agent_resume_challenges,lr_admin_login_audit,lr_admin_sessions,"+
  "lr_admin_login_challenges,lr_pairing_audit,lr_agents,lr_pairing_challenges,"+
  "lr_decision_nonces,lr_pairings,lr_admin_keys,lr_sites,lr_organizations CASCADE")
 if err!=nil{t.Fatal(err)}
 return db
}
func certs(t *testing.T)(string,string,*x509.CertPool){
 t.Helper()
 pub,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 now:=time.Now()
 cert:=&x509.Certificate{
  SerialNumber:big.NewInt(539),
  Subject:pkix.Name{CommonName:"LocalReach disposable loopback CI fixture"},
  IPAddresses:[]net.IP{net.ParseIP("127.0.0.1")},
  NotBefore:now.Add(-time.Minute),NotAfter:now.Add(time.Hour),
  KeyUsage:x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
  BasicConstraintsValid:true,
 }
 der,err:=x509.CreateCertificate(rand.Reader,cert,cert,pub,private)
 if err!=nil{t.Fatal(err)}
 bytes,err:=x509.MarshalPKCS8PrivateKey(private)
 if err!=nil{t.Fatal(err)}
 dir:=t.TempDir()
 certificate:=filepath.Join(dir,"pilot-test-cert.pem")
 secret:=filepath.Join(dir,"pilot-test-key.pem")
 certPEM:=pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der})
 if err=os.WriteFile(certificate,certPEM,0600);err!=nil{t.Fatal(err)}
 if err=os.WriteFile(secret,pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:bytes}),0600);err!=nil{t.Fatal(err)}
 roots:=x509.NewCertPool()
 if !roots.AppendCertsFromPEM(certPEM){t.Fatal("cannot build test trust root")}
 return certificate,secret,roots
}
type controlProcess struct{command *exec.Cmd; logs *os.File}
func startControl(t *testing.T,bin,cert,secret,dsn string)*controlProcess{
 t.Helper()
 logs,err:=os.CreateTemp(t.TempDir(),"control-*.log")
 if err!=nil{t.Fatal(err)}
 c:=exec.Command(bin,"-tls-cert",cert,"-tls-key",secret,"-allow-disposable-loopback-db")
 c.Env=append(os.Environ(),"LOCALREACH_CONTROL_DSN="+dsn)
 c.Stdout=logs;c.Stderr=logs
 if err=c.Start();err!=nil{t.Fatal(err)}
 p:=&controlProcess{command:c,logs:logs}
 t.Cleanup(func(){p.kill()})
 deadline:=time.Now().Add(7*time.Second)
 for time.Now().Before(deadline){
  conn,err:=net.DialTimeout("tcp",controlAddress,200*time.Millisecond)
  if err==nil{_ =conn.Close();return p}
  time.Sleep(60*time.Millisecond)
 }
 _=p.kill()
 t.Fatalf("loopback TLS control plane failed to start; see %s",logs.Name())
 return nil
}
func(p *controlProcess)kill()error{
 if p==nil||p.command==nil||p.command.Process==nil{return nil}
 _=p.command.Process.Kill()
 err:=p.command.Wait()
 if p.logs!=nil{_ =p.logs.Close();p.logs=nil}
 return err
}
func trustClient(roots *x509.CertPool)*http.Client{
 return &http.Client{Timeout:10*time.Second,Transport:&http.Transport{
  TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12,RootCAs:roots},
  Proxy:nil,
  TLSHandshakeTimeout:4*time.Second,
 }}
}
func enrolledAgent(t *testing.T,db *sql.DB)(testSigner,testSigner,string,string){
 t.Helper()
 ctx:=context.Background()
 admin,agent:=key(t),key(t)
 for _,query:=range []struct{sql string;args []any}{
  {"INSERT INTO lr_organizations(organization_id) VALUES($1)",[]any{"pilot"}},
  {"INSERT INTO lr_sites(organization_id,site_id) VALUES($1,$2)",[]any{"pilot","site"}},
  {"INSERT INTO lr_admin_keys(organization_id,admin_id,public_key,role) VALUES($1,$2,$3,'OWNER')",
   []any{"pilot","owner",[]byte(admin.pub)}},
 }{
  if _,err:=db.ExecContext(ctx,query.sql,query.args...);err!=nil{t.Fatal(err)}
 }
 s:=pgpairing.New(db)
 req,err:=s.Propose(ctx,"pilot","site",agent.pub)
 if err!=nil{t.Fatal(err)}
 d:=pgpairing.AdminDecision{
  Organization:"pilot",RequestID:req.RequestID,AdminID:"owner",Action:pgpairing.Approve,
  Nonce:nonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
 if _,err=s.Decide(ctx,d,pgpairing.SignDecision(admin.private,d));err!=nil{t.Fatal(err)}
 challenge,err:=s.Challenge(ctx,"pilot",req.RequestID)
 if err!=nil{t.Fatal(err)}
 record,err:=s.Enroll(ctx,"pilot",req.RequestID,challenge,
  pgpairing.SignEnrollment(agent.private,"pilot",req.RequestID,challenge))
 if err!=nil||!record.AgentID.Valid{t.Fatalf("enrollment: %v %+v",err,record)}
 return admin,agent,req.RequestID,record.AgentID.String
}
func nonce(t *testing.T)string{
 t.Helper()
 raw:=make([]byte,32)
 if _,err:=rand.Read(raw);err!=nil{t.Fatal(err)}
 return base64.RawURLEncoding.EncodeToString(raw)
}
func awaitFrame(t *testing.T,events <-chan bool,timeout time.Duration){
 t.Helper()
 select{
 case ok:=<-events:
  if !ok{t.Fatal("stream became offline before expected heartbeat")}
 case <-time.After(timeout):t.Fatal("authenticated stream heartbeat timed out")
 }
}
func TestSeparateProcessTLSCrashReclaimRevocation(t *testing.T){
 binary:=os.Getenv("LOCALREACH_CONTROL_BINARY")
 if binary==""{t.Skip("requires explicit compiled control-plane binary and disposable Postgres")}
 if _,err:=os.Stat(binary);err!=nil{t.Fatal(err)}
 db:=fixtureDB(t)
 admin,agent,requestID,agentID:=enrolledAgent(t,db)
 cert,private,roots:=certs(t)
 dsn:=os.Getenv("LOCALREACH_TEST_POSTGRES_DSN")
 parent:=startControl(t,binary,cert,private,dsn)
 remote,err:=agentremote.New("https://"+controlAddress,trustClient(roots))
 if err!=nil{t.Fatal(err)}
 // Wrong TLS trust must not authenticate or consume a usable session.
 notTrusted,err:=agentremote.New("https://"+controlAddress,trustClient(x509.NewCertPool()))
 if err!=nil{t.Fatal(err)}
 if _,err=notTrusted.VerifyIdentity(context.Background(),"pilot",agent);err==nil{
  t.Fatal("untrusted certificate accepted")
 }
 ctx,cancel:=context.WithTimeout(context.Background(),75*time.Second)
 defer cancel()
 events:=make(chan bool,32)
 finished:=make(chan error,1)
 go func(){finished<-remote.StreamSession(ctx,"pilot",agent,func(ok bool){
  select{case events<-ok:default:}
 })}()
 awaitFrame(t,events,5*time.Second)
 // This interval deliberately exceeds the previous HTTP WriteTimeout=10s.
 for i:=0;i<3;i++{awaitFrame(t,events,6*time.Second)}
 select{case err:=<-finished:t.Fatalf("stream died before 12+ seconds: %v",err);default:}
 active,err:=pgpairing.New(db).ConnectionOnline(ctx,"pilot",agentID)
 if err!=nil||!active{t.Fatal("healthy separate-process stream not ONLINE")}
 // Kill actual control-plane process, not just an in-memory handler.
 _=parent.kill()
 select{case <-finished:case <-time.After(5*time.Second):t.Fatal("crashed gateway stream did not terminate")}
 // Lease is allowed to remain active until its bounded 15s expiry.
 expiry:=time.Now().Add(20*time.Second)
 for time.Now().Before(expiry){
  active,err=pgpairing.New(db).ConnectionOnline(ctx,"pilot",agentID)
  if err!=nil{t.Fatal(err)}
  if !active{break}
  time.Sleep(200*time.Millisecond)
 }
 if active{t.Fatal("crashed gateway lease did not expire")}
 restarted:=startControl(t,binary,cert,private,dsn)
 recovery:=make(chan bool,16)
 recoveredDone:=make(chan error,1)
 go func(){recoveredDone<-remote.StreamSession(ctx,"pilot",agent,func(ok bool){
  select{case recovery<-ok:default:}
 })}()
 awaitFrame(t,recovery,5*time.Second)
 active,err=pgpairing.New(db).ConnectionOnline(ctx,"pilot",agentID)
 if err!=nil||!active{t.Fatal("reconnected stream not ONLINE")}
 revoked:=pgpairing.AdminDecision{
  Organization:"pilot",RequestID:requestID,AdminID:"owner",Action:pgpairing.Revoke,
  Nonce:nonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
 if _,err=pgpairing.New(db).Decide(ctx,revoked,pgpairing.SignDecision(admin.private,revoked));err!=nil{t.Fatal(err)}
 select{
 case err:=<-recoveredDone:
  if !errors.Is(err,agentremote.ErrSessionClosed){t.Fatalf("unexpected revocation: %v",err)}
 case <-time.After(7*time.Second):t.Fatal("revoked stream did not close")
 }
 active,err=pgpairing.New(db).ConnectionOnline(ctx,"pilot",agentID)
 if err!=nil||active{t.Fatal("revoked agent remained ONLINE")}
 if _,err=remote.VerifyIdentity(ctx,"pilot",agent);err==nil{t.Fatal("revoked key resumed")}
 _=restarted.kill()
 t.Logf("pass: separate OS process, 12+ second TLS stream, crash lease expiry, restart and revocation (device capabilities NONE)")
}
