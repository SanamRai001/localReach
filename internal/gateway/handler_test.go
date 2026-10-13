package gateway

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
 "github.com/SanamRai001/localReach/internal/session"
)
func TestTLSHandshakeAndHeartbeat(t *testing.T){
 registry:=identity.NewRegistry(nil)
 invite,e:=registry.Issue("tenant-a","office-a",time.Minute);if e!=nil{t.Fatal(e)}
 pub,private,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 agent,e:=registry.Enroll(invite.Token,pub,identity.SignEnrollment(private,invite.Token));if e!=nil{t.Fatal(e)}
 h:=New(session.New(registry,nil))
 plaintext:=httptest.NewServer(h)
 defer plaintext.Close()
 request:=func(client *http.Client,url,path string,payload any,token string)*http.Response{
  t.Helper()
  b,e:=json.Marshal(payload);if e!=nil{t.Fatal(e)}
  req,e:=http.NewRequest("POST",url+path,bytes.NewReader(b));if e!=nil{t.Fatal(e)}
  req.Header.Set("Content-Type","application/json")
  req.Header.Set("X-LocalReach-Agent-ID",agent.ID)
  if token!=""{req.Header.Set("Authorization","Bearer "+token)}
  resp,e:=client.Do(req);if e!=nil{t.Fatal(e)}
  return resp
 }
 resp:=request(plaintext.Client(),plaintext.URL,"/v1/agent/challenge",map[string]string{"agentId":agent.ID},"")
 if resp.StatusCode!=426{t.Fatalf("plaintext should be blocked: %d",resp.StatusCode)};resp.Body.Close()
 secured:=httptest.NewTLSServer(h)
 defer secured.Close()
 c:=secured.Client() // trusts ONLY the test server's certificate
 resp=request(c,secured.URL,"/v1/agent/challenge",map[string]string{"agentId":agent.ID},"")
 if resp.StatusCode!=200{t.Fatalf("challenge status: %d",resp.StatusCode)}
 var challenge struct{ Challenge string `json:"challenge"`}
 if e=json.NewDecoder(resp.Body).Decode(&challenge);e!=nil{t.Fatal(e)};resp.Body.Close()
 signature:=base64.RawURLEncoding.EncodeToString(session.Sign(private,challenge.Challenge))
 payload:=map[string]string{"agentId":agent.ID,"challenge":challenge.Challenge,"signature":signature}
 resp=request(c,secured.URL,"/v1/agent/session",payload,"")
 if resp.StatusCode!=200{t.Fatalf("session status: %d",resp.StatusCode)}
 var sess struct{ SessionToken string `json:"sessionToken"`}
 if e=json.NewDecoder(resp.Body).Decode(&sess);e!=nil{t.Fatal(e)};resp.Body.Close()
 resp=request(c,secured.URL,"/v1/agent/heartbeat",map[string]string{},sess.SessionToken)
 if resp.StatusCode!=200{t.Fatalf("heartbeat status: %d",resp.StatusCode)};resp.Body.Close()
 resp=request(c,secured.URL,"/v1/agent/session",payload,"")
 if resp.StatusCode!=403{t.Fatalf("replay status: %d",resp.StatusCode)};resp.Body.Close()
 if e=registry.Revoke(agent.ID);e!=nil{t.Fatal(e)}
 resp=request(c,secured.URL,"/v1/agent/heartbeat",map[string]string{},sess.SessionToken)
 if resp.StatusCode!=403{t.Fatalf("revoked status: %d",resp.StatusCode)};resp.Body.Close()
}
