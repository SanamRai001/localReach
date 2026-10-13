package pairapi

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "encoding/base64"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/pgauth"
 "github.com/SanamRai001/localReach/internal/pgpairing"
)
func TestInvitationOverTLSRequiresAdminAndRemainsPending(t *testing.T){
 db:=testDB(t)
 admin,adminToken:=prepare(t,db)
 handler:=Handler{Auth:pgauth.New(db),Pairing:pgpairing.New(db),Guard:NewGuard(nil)}
 server:=httptest.NewTLSServer(handler);defer server.Close()
 client:=server.Client()
 // A fresh challenge authenticates the preprovisioned administrator key.
 status,challenge:=post(t,client,server.URL,"/v1/control/login-challenge","",loginRequest{
  Organization:"org",AdminID:"owner",
 })
 if status!=200||challenge["nonce"]==""{t.Fatalf("admin login challenge %d %+v",status,challenge)}
 status,login:=post(t,client,server.URL,"/v1/control/login","",loginRequest{
  Organization:"org",AdminID:"owner",Nonce:challenge["nonce"],
  Signature:base64.RawURLEncoding.EncodeToString(pgauth.SignChallenge(admin.private,"org","owner",challenge["nonce"])),
 })
 if status!=200||login["token"]==""{t.Fatalf("signed login: %d %+v",status,login)}
 agent:=newSigner(t)
 status,inv:=post(t,client,server.URL,"/v1/control/invite",login["token"],invitationRequest{
  Organization:"org",Site:"site",
 })
 if status!=200||inv["token"]==""||inv["scope"]!="PENDING_REQUEST_ONLY"{t.Fatalf("admin invitation: %d %+v",status,inv)}
 native,err:=agentremote.New(server.URL,client);if err!=nil{t.Fatal(err)}
 pending,err:=native.RequestInvitation(context.Background(),"org",inv["token"],agent)
 if err!=nil||pending==""{t.Fatalf("redeem pending invitation: %v",err)}
 record,err:=pgpairing.New(db).Get(context.Background(),"org",pending)
 if err!=nil||record.State!="PENDING"{t.Fatalf("unexpected autoapproval: %v %+v",err,record)}
 if status,_=post(t,client,server.URL,"/v1/control/review","",reviewRequest{
  Organization:"org",RequestID:pending,
 });status!=403{t.Fatalf("unauthenticated fingerprint review succeeded: %d",status)}
 status,review:=post(t,client,server.URL,"/v1/control/review",login["token"],reviewRequest{
  Organization:"org",RequestID:pending,
 })
 expected:=sha256.Sum256(agent.PublicKey())
 if status!=200||review["fingerprint"]!=hex.EncodeToString(expected[:])||review["state"]!="PENDING"{
  t.Fatalf("admin review mismatch: %d %+v",status,review)
 }
 if _,err=native.FinishEnrollment(context.Background(),"org",pending,agent);err==nil{t.Fatal("invitation directly enrolled")}
 // The same admin must explicitly sign a new, request-scoped decision.
 decision:=pgpairing.AdminDecision{Organization:"org",RequestID:pending,AdminID:"owner",Action:pgpairing.Approve,
  Nonce:nonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix()}
 approval:=signedDecision{Organization:decision.Organization,RequestID:pending,AdminID:"owner",Action:decision.Action,
  Nonce:decision.Nonce,IssuedAt:decision.IssuedAt,ExpiresAt:decision.ExpiresAt,
  Signature:base64.RawURLEncoding.EncodeToString(pgpairing.SignDecision(admin.private,decision))}
 status,_=post(t,client,server.URL,"/v1/control/decide",adminToken,approval)
 if status!=200{t.Fatalf("admin approval rejected: %d",status)}
 agentID,err:=native.FinishEnrollment(context.Background(),"org",pending,agent)
 if err!=nil||agentID==""{t.Fatalf("approved agent could not enroll: %v",err)}
 // No device access was granted even after successful pairing.
 if valid,err:=native.VerifyIdentity(context.Background(),"org",agent);err!=nil||valid!=agentID{t.Fatalf("resume proof failed: %v",err)}
}
func TestInvitationRateGuardAndNoTrustedProxyHeaders(t *testing.T){
 now:=time.Now()
 limiter:=NewGuard(func()time.Time{return now})
 for i:=0;i<5;i++{
  r:=httptest.NewRequest("POST","https://example.test/v1/agent/request-invite",nil)
  r.RemoteAddr="192.0.2.2:3000"
  r.Header.Set("X-Forwarded-For","198.51.100."+string(rune('0'+i)))
  if !limiter.Allow(r){t.Fatalf("attempt %d unexpectedly blocked",i)}
 }
 r:=httptest.NewRequest("POST","https://example.test/v1/agent/request-invite",nil)
 r.RemoteAddr="192.0.2.2:3000"
 r.Header.Set("X-Forwarded-For","203.0.113.9")
 if limiter.Allow(r){t.Fatal("spoofed proxy header bypassed limiter")}
 now=now.Add(time.Minute)
 if !limiter.Allow(r){t.Fatal("expired test window not reset")}
 r.RemoteAddr="not-a-socket"
 if limiter.Allow(r){t.Fatal("invalid remote peer accepted")}
 // No guard is a deliberate fail-closed setting.
 h:=Handler{}
 w:=httptest.NewRecorder()
 h.limited(w,httptest.NewRequest(http.MethodPost,"https://test",nil))
 if w.Code!=429{t.Fatalf("missing guard should deny, got %d",w.Code)}
}
