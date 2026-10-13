package pairtransport

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/pairing"
)
func request(t *testing.T,c *http.Client,base,path string,input any)(int,map[string]string){
 t.Helper()
 data,err:=json.Marshal(input);if err!=nil{t.Fatal(err)}
 req,err:=http.NewRequest("POST",base+path,bytes.NewReader(data));if err!=nil{t.Fatal(err)}
 req.Header.Set("Content-Type","application/json")
 res,err:=c.Do(req);if err!=nil{t.Fatal(err)}
 defer res.Body.Close()
 result:=map[string]string{}
 if res.StatusCode==200{
  if err=json.NewDecoder(res.Body).Decode(&result);err!=nil{t.Fatal(err)}
 }
 return res.StatusCode,result
}
func randomTestNonce(t *testing.T)string{
 t.Helper()
 b:=make([]byte,32)
 if _,err:=rand.Read(b);err!=nil{t.Fatal(err)}
 return base64.RawURLEncoding.EncodeToString(b)
}
func decisionPayload(d Decision,priv ed25519.PrivateKey)any{
 return struct{
  Decision
  Signature string `json:"signature"`
 }{d,base64.RawURLEncoding.EncodeToString(SignDecision(priv,d))}
}
func TestTLSApprovedAgentEnrollment(t *testing.T){
 registry:=identity.NewRegistry(nil)
 manager:=pairing.New(registry,nil)
 agentPub,agentKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 req,err:=manager.Propose("tenant-a","site-a",agentPub);if err!=nil{t.Fatal(err)}
 adminPub,adminKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 _,wrongAdmin,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 _,wrongAgent,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 server:=httptest.NewTLSServer(New(manager,map[string]ed25519.PublicKey{"tenant-a":adminPub},nil))
 defer server.Close()
 client:=server.Client()
 d:=Decision{ID:req.ID,Tenant:"tenant-a",Approve:true,Nonce:randomTestNonce(t)}
 if status,_:=request(t,client,server.URL,"/v1/pair/admin/decide",decisionPayload(d,wrongAdmin));status!=403{t.Fatalf("unauthorized approval %d",status)}
 before,ok:=manager.Get(req.ID,"tenant-a")
 if !ok||before.State!=pairing.Pending{t.Fatalf("request changed after bad signature: %+v",before)}
 status,out:=request(t,client,server.URL,"/v1/pair/admin/decide",decisionPayload(d,adminKey))
 if status!=200||out["state"]!=string(pairing.Approved){t.Fatalf("admin decision: %d %+v",status,out)}
 if status,_:=request(t,client,server.URL,"/v1/pair/admin/decide",decisionPayload(d,adminKey));status!=403{t.Fatalf("decision replay accepted %d",status)}
 status,out=request(t,client,server.URL,"/v1/pair/agent/challenge",map[string]string{"id":req.ID})
 if status!=200||out["nonce"]==""{t.Fatalf("challenge: %d %+v",status,out)}
 nonce:=out["nonce"]
 bad:=base64.RawURLEncoding.EncodeToString(pairing.SignChallengeHandoff(wrongAgent,req.ID,nonce))
 if status,_:=request(t,client,server.URL,"/v1/pair/agent/handoff",map[string]string{"id":req.ID,"nonce":nonce,"signature":bad});status!=403{t.Fatalf("wrong key handoff accepted %d",status)}
 good:=base64.RawURLEncoding.EncodeToString(pairing.SignChallengeHandoff(agentKey,req.ID,nonce))
 if status,_:=request(t,client,server.URL,"/v1/pair/agent/handoff",map[string]string{"id":req.ID,"nonce":nonce,"signature":good});status!=403{t.Fatalf("consumed challenge replay accepted %d",status)}
 status,out=request(t,client,server.URL,"/v1/pair/agent/challenge",map[string]string{"id":req.ID})
 if status!=200{t.Fatal(status)}
 nonce=out["nonce"]
 signature:=base64.RawURLEncoding.EncodeToString(pairing.SignChallengeHandoff(agentKey,req.ID,nonce))
 status,out=request(t,client,server.URL,"/v1/pair/agent/handoff",map[string]string{"id":req.ID,"nonce":nonce,"signature":signature})
 if status!=200||out["invitation"]==""{t.Fatalf("approved handoff %d %+v",status,out)}
 invitation:=out["invitation"]
 badProof:=base64.RawURLEncoding.EncodeToString(AgentProof(wrongAgent,invitation))
 if status,_:=request(t,client,server.URL,"/v1/pair/agent/enroll",map[string]string{"id":req.ID,"proof":badProof});status!=403{t.Fatalf("wrong enrollment proof accepted %d",status)}
 proof:=base64.RawURLEncoding.EncodeToString(AgentProof(agentKey,invitation))
 status,out=request(t,client,server.URL,"/v1/pair/agent/enroll",map[string]string{"id":req.ID,"proof":proof})
 if status!=200||out["agentId"]==""||out["tenantId"]!="tenant-a"||out["siteId"]!="site-a"{t.Fatalf("enrollment: %d %+v",status,out)}
 if status,_:=request(t,client,server.URL,"/v1/pair/agent/enroll",map[string]string{"id":req.ID,"proof":proof});status!=403{t.Fatalf("enrollment replay accepted %d",status)}
}
func TestTLSOnlyAndCrossTenantAdminDenied(t *testing.T){
 registry:=identity.NewRegistry(nil)
 mgr:=pairing.New(registry,nil)
 pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 req,err:=mgr.Propose("tenant-a","site-a",pub);if err!=nil{t.Fatal(err)}
 otherPub,otherKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 handler:=New(mgr,map[string]ed25519.PublicKey{"tenant-b":otherPub},nil)
 plain:=httptest.NewServer(handler);defer plain.Close()
 if status,_:=request(t,plain.Client(),plain.URL,"/v1/pair/agent/challenge",map[string]string{"id":req.ID});status!=426{t.Fatalf("plaintext accepted: %d",status)}
 tls:=httptest.NewTLSServer(handler);defer tls.Close()
 d:=Decision{ID:req.ID,Tenant:"tenant-b",Approve:true,Nonce:randomTestNonce(t)}
 if status,_:=request(t,tls.Client(),tls.URL,"/v1/pair/admin/decide",decisionPayload(d,otherKey));status!=403{t.Fatalf("cross tenant decision accepted %d",status)}
 // Browser-origin requests are not permitted to this protocol.
 data:=[]byte(`{"id":"sample"}`)
 httpReq,err:=http.NewRequest("POST",tls.URL+"/v1/pair/agent/challenge",bytes.NewReader(data));if err!=nil{t.Fatal(err)}
 httpReq.Header.Set("Content-Type","application/json")
 httpReq.Header.Set("Origin","https://evil.example")
 response,err:=tls.Client().Do(httpReq);if err!=nil{t.Fatal(err)}
 defer response.Body.Close()
 if response.StatusCode!=403{t.Fatalf("browser request accepted %d",response.StatusCode)}
}
func TestExpiredChallengeDenied(t *testing.T){
 now:=time.Now()
 clock:=func()time.Time{return now}
 reg:=identity.NewRegistry(clock)
 mgr:=pairing.New(reg,clock)
 pub,agentKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 req,err:=mgr.Propose("t","s",pub);if err!=nil{t.Fatal(err)}
 adminPub,adminKey,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 s:=httptest.NewTLSServer(New(mgr,map[string]ed25519.PublicKey{"t":adminPub},clock));defer s.Close()
 d:=Decision{ID:req.ID,Tenant:"t",Approve:true,Nonce:randomTestNonce(t)}
 if status,_:=request(t,s.Client(),s.URL,"/v1/pair/admin/decide",decisionPayload(d,adminKey));status!=200{t.Fatal(status)}
 status,out:=request(t,s.Client(),s.URL,"/v1/pair/agent/challenge",map[string]string{"id":req.ID})
 if status!=200{t.Fatal(status)}
 nonce:=out["nonce"]
 now=now.Add(31*time.Second)
 proof:=base64.RawURLEncoding.EncodeToString(pairing.SignChallengeHandoff(agentKey,req.ID,nonce))
 if status,_:=request(t,s.Client(),s.URL,"/v1/pair/agent/handoff",map[string]string{"id":req.ID,"nonce":nonce,"signature":proof});status!=403{t.Fatalf("expired challenge accepted %d",status)}
}
