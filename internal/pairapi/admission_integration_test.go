package pairapi

import (
 "context"
 "database/sql"
 "strings"
 "crypto/sha256"
 "encoding/hex"
 "net/http"
 "net/http/httptest"
 "os"
 "testing"

 "github.com/SanamRai001/localReach/internal/adminremote"
 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/pgauth"
 "github.com/SanamRai001/localReach/internal/pgpairing"
)
func TestNativeAdminReviewAndSeparatelySignedApproval(t *testing.T){
 db:=testDB(t)
 _,_=prepare(t,db)
 admin:=newSigner(t)
 // Register the real test admin key, distinct from the agent key.
 if _,err:=db.Exec(`UPDATE lr_admin_keys SET public_key=$1 WHERE organization_id='org' AND admin_id='owner'`,[]byte(admin.public));err!=nil{t.Fatal(err)}
 handler:=Handler{Auth:pgauth.New(db),Pairing:pgpairing.New(db),Admission:NewSQLAdmission(db)}
 server:=httptest.NewTLSServer(handler);defer server.Close()
 client,err:=adminremote.New(server.URL,server.Client());if err!=nil{t.Fatal(err)}
 ctx:=context.Background()
 session,err:=client.Login(ctx,"org","owner",admin)
 if err!=nil||session==""{t.Fatalf("admin signed login denied: %v",err)}
 invite,err:=client.Invite(ctx,"org","site",session)
 if err!=nil||invite.Token==""{t.Fatalf("invitation: %v",err)}
 agent:=newSigner(t)
 native,err:=agentremote.New(server.URL,server.Client());if err!=nil{t.Fatal(err)}
 requestID,err:=native.RequestInvitation(ctx,"org",invite.Token,agent)
 if err!=nil||requestID==""{t.Fatalf("redemption: %v",err)}
 review,err:=client.Review(ctx,"org",requestID,session)
 if err!=nil||review.State!="PENDING"{t.Fatalf("review: %v %+v",err,review)}
 expected:=sha256.Sum256(agent.PublicKey())
 if review.Fingerprint!=hex.EncodeToString(expected[:]){t.Fatal("fingerprint differs from native key")}
 if err:=client.ApproveReviewed(ctx,"org","owner",requestID,session,hex.EncodeToString(make([]byte,32)),admin);err==nil{t.Fatal("wrong fingerprint approved")}
 if record,err:=pgpairing.New(db).Get(ctx,"org",requestID);err!=nil||record.State!="PENDING"{t.Fatal("wrong fingerprint altered pairing")}
 if err:=client.ApproveReviewed(ctx,"org","owner",requestID,session,review.Fingerprint,admin);err!=nil{t.Fatalf("signed approval denied: %v",err)}
 if _,err:=native.FinishEnrollment(ctx,"org",requestID,agent);err!=nil{t.Fatalf("native enrollment denied: %v",err)}
 if err:=client.ApproveReviewed(ctx,"org","owner",requestID,session,review.Fingerprint,admin);err==nil{t.Fatal("replayed approval accepted")}
}
func TestSharedAdmissionAcrossProcessesAndRoutes(t *testing.T){
 db:=testDB(t)
 ctx:=context.Background()
 first:=NewSQLAdmission(db)
 // A second connection simulates a separate gateway process.
 secondDB,err:=sql.Open("postgres",os.Getenv("LOCALREACH_TEST_POSTGRES_DSN"));if err!=nil{t.Fatal(err)}
 defer secondDB.Close()
 second:=NewSQLAdmission(secondDB)
 for i:=0;i<5;i++{
  gate:=first
  if i%2==1{gate=second}
  if !gate.Allow(ctx,"192.0.2.24:9888","/v1/control/login"){t.Fatalf("attempt %d denied early",i)}
 }
 if second.Allow(ctx,"192.0.2.24:9888","/v1/control/login"){t.Fatal("sixth request bypassed DB-wide limit")}
 if first.Allow(ctx,"192.0.2.24:9888","/v1/control/login"){t.Fatal("first process reset another process's counter")}
 if !first.Allow(ctx,"192.0.2.24:9888","/v1/control/review"){t.Fatal("isolated route budget denied")}
 if !first.Allow(ctx,"192.0.2.25:9888","/v1/control/login"){t.Fatal("separate peer denied")}
 if _,err:=db.Exec(`UPDATE lr_admission_windows SET window_start=NOW()-INTERVAL '2 minutes'
 WHERE action='/v1/control/login'`);err!=nil{t.Fatal(err)}
 if !second.Allow(ctx,"192.0.2.24:9888","/v1/control/login"){t.Fatal("window failed to expire")}
 if first.Allow(ctx,"bad-remote","/v1/control/login"){t.Fatal("invalid peer admitted")}
 if first.Allow(ctx,"192.0.2.24:9888","/not-control"){t.Fatal("unknown route admitted")}
}
func TestSharedAdmissionPreventsBypassOfHandler(t *testing.T){
 db:=testDB(t)
 s:=httptest.NewTLSServer(Handler{Auth:pgauth.New(db),Pairing:pgpairing.New(db),Admission:NewSQLAdmission(db)})
 defer s.Close()
 // A transport-level response guard must reject repeated invalid logins
 // even if the request body is malformed.
 for i:=0;i<6;i++{
  req,err:=http.NewRequest("POST",s.URL+"/v1/control/login",strings.NewReader("{}"));if err!=nil{t.Fatal(err)}
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("X-Forwarded-For","203.0.113.9")
  r,err:=s.Client().Do(req);if err!=nil{t.Fatal(err)}
  r.Body.Close()
  if i==5&&r.StatusCode!=429{t.Fatalf("rate limit bypassed: %d",r.StatusCode)}
 }
}
