package pairapi

import(
 "context"
 "encoding/base64"
 "encoding/hex"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/pgcapability"
 "github.com/SanamRai001/localReach/internal/pgpairing"
 "github.com/SanamRai001/localReach/internal/pgauth"
)
func TestSeparateSignedDeviceReadGrantOverHTTPS(t *testing.T){
 db:=testDB(t);ctx:=context.Background()
 admin,token:=prepare(t,db)
 pairing:=pgpairing.New(db)
 agent:=newSigner(t)
 request,err:=pairing.Propose(ctx,"org","site",agent.PublicKey());if err!=nil{t.Fatal(err)}
 approve:=pgpairing.AdminDecision{
  Organization:"org",RequestID:request.RequestID,AdminID:"owner",Action:pgpairing.Approve,
  Nonce:nonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
 if _,err=pairing.Decide(ctx,approve,pgpairing.SignDecision(admin.private,approve));err!=nil{t.Fatal(err)}
 challenge,err:=pairing.Challenge(ctx,"org",request.RequestID);if err!=nil{t.Fatal(err)}
 enrolled,err:=pairing.Enroll(ctx,"org",request.RequestID,challenge,
  pgpairing.SignEnrollment(agent.private,"org",request.RequestID,challenge));if err!=nil{t.Fatal(err)}
 agentID:=enrolled.AgentID.String
 policy:=pgcapability.New(db)
 fingerprint:=hex.EncodeToString(make([]byte,32))
 allowed,err:=policy.Allowed(ctx,"org","site",agentID,fingerprint,pgcapability.PrinterDiscovery)
 if err!=nil||allowed{t.Fatal("pairing accidentally gave discovery permission")}
 server:=httptest.NewTLSServer(Handler{Auth:pgauth.New(db),Pairing:pairing,ReadPolicy:policy})
 defer server.Close()
 d:=pgcapability.Decision{
  Organization:"org",Site:"site",AgentID:agentID,DeviceFingerprint:fingerprint,
  Capability:pgcapability.PrinterDiscovery,AdminID:"owner",Action:pgcapability.Grant,
  Nonce:nonce(t),IssuedAt:time.Now().Unix(),ExpiresAt:time.Now().Add(time.Minute).Unix(),
 }
 body:=signedDeviceReadDecision{
  Organization:d.Organization,Site:d.Site,AgentID:d.AgentID,DeviceFingerprint:d.DeviceFingerprint,
  Capability:d.Capability,AdminID:d.AdminID,Action:d.Action,Nonce:d.Nonce,
  IssuedAt:d.IssuedAt,ExpiresAt:d.ExpiresAt,
  Signature:base64.RawURLEncoding.EncodeToString(pgcapability.Sign(admin.private,d)),
 }
 url:="/v1/control/device-read-decision"
 if status,_:=post(t,server.Client(),server.URL,url,"",body);status!=403{t.Fatal("unauthenticated device grant")}
 if status,_:=post(t,server.Client(),server.URL,url,"not-a-session",body);status!=403{t.Fatal("wrong session device grant")}
 bad:=body;bad.AgentID="unpaired-agent"
 if status,_:=post(t,server.Client(),server.URL,url,token,bad);status!=403{t.Fatal("tampered agent ID in decision")}
 status,response:=post(t,server.Client(),server.URL,url,token,body)
 if status!=200||response["state"]!="ACTIVE"||response["deviceOperations"]!="DISABLED"{
  t.Fatalf("read policy decision: %d %+v",status,response)
 }
 allowed,err=policy.Allowed(ctx,"org","site",agentID,fingerprint,pgcapability.PrinterDiscovery)
 if err!=nil||!allowed{t.Fatalf("separate grant unavailable: %v",err)}
 if status,_=post(t,server.Client(),server.URL,url,token,body);status!=403{t.Fatal("replayed grant accepted")}
 d.Action=pgcapability.Revoke;d.Nonce=nonce(t);d.IssuedAt=time.Now().Unix();d.ExpiresAt=time.Now().Add(time.Minute).Unix()
 body.Action=d.Action;body.Nonce=d.Nonce;body.IssuedAt=d.IssuedAt;body.ExpiresAt=d.ExpiresAt
 body.Signature=base64.RawURLEncoding.EncodeToString(pgcapability.Sign(admin.private,d))
 status,response=post(t,server.Client(),server.URL,url,token,body)
 if status!=200||response["state"]!="REVOKED"{t.Fatalf("revoke failed: %d %+v",status,response)}
 allowed,err=policy.Allowed(ctx,"org","site",agentID,fingerprint,pgcapability.PrinterDiscovery)
 if err!=nil||allowed{t.Fatal("revoked discovery permission still active")}
}
