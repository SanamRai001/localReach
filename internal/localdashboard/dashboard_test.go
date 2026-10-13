package localdashboard

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "net/http"
 "net/http/httptest"
 "strings"
 "testing"
 "testing/fstest"
 "time"

 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/landiscovery"
 "github.com/SanamRai001/localReach/internal/localsetup"
)
type mockSigner struct{pub ed25519.PublicKey;private ed25519.PrivateKey}
func signer(t *testing.T)*mockSigner{
 t.Helper();pub,priv,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 return &mockSigner{pub:pub,private:priv}
}
func (s *mockSigner)PublicKey()ed25519.PublicKey{return s.pub}
func (s *mockSigner)SignMessage(v []byte)([]byte,error){return ed25519.Sign(s.private,v),nil}
func (s *mockSigner)Fingerprint()string{d:=sha256.Sum256(s.pub);return hex.EncodeToString(d[:])}
type mockRemote struct{
 requests int
 enrolls int
 resumes int
}
func(r *mockRemote)RequestInvitation(_ context.Context,org,token string,s agentremote.Signer)(string,error){
 if org!="org"||token==""||len(s.PublicKey())!=32{return "",errors.New("denied")}
 r.requests++;return "pending-request-1",nil
}
func(r *mockRemote)FinishEnrollment(_ context.Context,org,id string,s agentremote.Signer)(string,error){
 if org!="org"||id!="pending-request-1"{return "",errors.New("denied")}
 r.enrolls++;return "enrolled-agent-1",nil
}
func(r *mockRemote)VerifyIdentity(_ context.Context,org string,s agentremote.Signer)(string,error){
 if org!="org"{return "",errors.New("denied")}
 r.resumes++;return "enrolled-agent-1",nil
}
func(r *mockRemote)StreamSession(ctx context.Context,org string,s agentremote.Signer,cb func(bool))error{
 cb(true)
 <-ctx.Done()
 cb(false)
 return ctx.Err()
}
func mounted(t *testing.T,s *Service)(http.Handler,string){
 t.Helper()
 files:=fstest.MapFS{
  "index.html":&fstest.MapFile{Data:[]byte("Real dashboard")},
  "style.css":&fstest.MapFile{Data:[]byte("body{}")},
  "setup.js":&fstest.MapFile{Data:[]byte("fetch('/v1/local/status')")},
 }
 h,err:=NewHandler(files,s)
 if err!=nil{t.Fatal(err)}
 d,ok:=h.(*Dashboard)
 if !ok{t.Fatal("handler type")}
 return h,d.token
}
func req(t *testing.T,h http.Handler,method,path,origin,token string,body string)(int,map[string]any){
 t.Helper()
 r:=httptest.NewRequest(method,localsetup.Origin+path,strings.NewReader(body))
 r.RemoteAddr="127.0.0.1:32100"
 if origin!=""{r.Header.Set("Origin",origin)}
 if token!=""{r.Header.Set("X-LocalReach-Token",token)}
 if method=="POST"{r.Header.Set("Content-Type","application/json")}
 w:=httptest.NewRecorder()
 h.ServeHTTP(w,r)
 data:=map[string]any{}
 if strings.HasPrefix(w.Header().Get("Content-Type"),"application/json"){
  if err:=json.Unmarshal(w.Body.Bytes(),&data);err!=nil{t.Fatalf("bad JSON: %v %q",err,w.Body.String())}
 }
 return w.Code,data
}
func TestOnlyTrustedLocalPageMayMutateState(t *testing.T){
 s:=New(nil,nil,"")
 var calls int
 s.Discover=func(_ context.Context,_ time.Duration)([]landiscovery.Candidate,error){
  calls++
  return []landiscovery.Candidate{{Name:"printer._ipp._tcp.local",Type:"PRINTER",Verified:false,Source:"UNTRUSTED_MDNS"}},nil
 }
 h,token:=mounted(t,s)
 for _,tc:=range []struct{origin,token,remote string;want int}{
  {"",token,"127.0.0.1:1000",403},
  {"https://other.site",token,"127.0.0.1:1000",403},
  {localsetup.Origin,"bad","127.0.0.1:1000",403},
  {localsetup.Origin,token,"203.0.113.12:1000",403},
  {localsetup.Origin,token,"127.0.0.1:1000",200},
 }{
  r:=httptest.NewRequest("POST",localsetup.Origin+"/v1/local/discover",strings.NewReader(`{"seconds":1}`))
  r.RemoteAddr=tc.remote;r.Header.Set("Content-Type","application/json")
  if tc.origin!=""{r.Header.Set("Origin",tc.origin)}
  r.Header.Set("X-LocalReach-Token",tc.token)
  w:=httptest.NewRecorder();h.ServeHTTP(w,r)
  if w.Code!=tc.want{t.Fatalf("unexpected status %d for %+v",w.Code,tc)}
 }
 if calls!=1{t.Fatalf("discovery called %d times; expected exactly one authorized request",calls)}
 status,data:=req(t,h,"GET","/v1/local/bootstrap","","","")
 if status!=200||data["csrfToken"]!=token{t.Fatalf("bootstrap missing ephemeral CSRF: %d %+v",status,data)}
 status,_=req(t,h,"POST","/v1/local/initialize",localsetup.Origin,token,`{}`)
 if status==200{t.Fatal("without native store, initialize unexpectedly created an identity")}
}
func TestBrowserDiscoveryOnlyShowsUnverifiedLocalResults(t *testing.T){
 s:=New(nil,nil,"")
 s.Discover=func(_ context.Context,d time.Duration)([]landiscovery.Candidate,error){
  if d!=8*time.Second{t.Errorf("wrong bounded duration: %v",d)}
  return []landiscovery.Candidate{{Name:"office._ipps._tcp.local",
   Type:"PRINTER",Fingerprint:"test-unverified",Source:"UNTRUSTED_MDNS",Verified:false}},nil
 }
 h,token:=mounted(t,s)
 status,data:=req(t,h,"POST","/v1/local/discover",localsetup.Origin,token,`{"seconds":8}`)
 if status!=200{t.Fatalf("discovery failed: %d %+v",status,data)}
 candidates,ok:=data["candidates"].([]any)
 if !ok||len(candidates)!=1{t.Fatalf("missing real discovery response: %+v",data)}
 item:=candidates[0].(map[string]any)
 if item["verified"]!=false||item["source"]!="UNTRUSTED_MDNS"{t.Fatalf("fake trust: %+v",item)}
 status,data=req(t,h,"GET","/v1/local/dashboard","","","")
 if status!=200||data["discovery"]!="COMPLETE"||data["deviceCount"]!=float64(1){
  t.Fatalf("dashboard not showing discovery result: %+v",data)
 }
 status,_=req(t,h,"POST","/v1/local/discover",localsetup.Origin,token,`{"seconds":45}`)
 if status!=400{t.Fatal("unbounded discovery accepted")}
}
func TestPairingRequiresRealConfiguredGatewayAndExistingIdentity(t *testing.T){
 s:=New(nil,nil,"")
 h,token:=mounted(t,s)
 dummy:=base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{3},32))
 body,_:=json.Marshal(map[string]string{"invitation":dummy})
 status,data:=req(t,h,"POST","/v1/local/request",localsetup.Origin,token,string(body))
 if status!=409||data["code"]!="GATEWAY_NOT_CONFIGURED"{t.Fatalf("pretended gateway exists: %d %+v",status,data)}
 status,data=req(t,h,"GET","/v1/local/dashboard","","","")
 if status!=200||data["connection"]!="OFFLINE"||data["pairing"]!="NOT_PAIRED"{t.Fatalf("fake pairing: %+v",data)}
}
func TestPendingToEnrollmentToLiveStreamIsRealState(t *testing.T){
 remote:=&mockRemote{}
 s:=New(nil,remote,"org")
 identity:=signer(t)
 s.mu.Lock();s.signer=identity;s.fingerprint=identity.Fingerprint();s.identityError="";s.mu.Unlock()
 defer s.Close()
 h,token:=mounted(t,s)
 invite:=base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{7},32))
 body,_:=json.Marshal(map[string]string{"invitation":invite})
 status,data:=req(t,h,"POST","/v1/local/request",localsetup.Origin,token,string(body))
 if status!=200||data["state"]!="PENDING_APPROVAL"{t.Fatalf("request: %d %+v",status,data)}
 if state:=s.Status();state.Connection!="OFFLINE"||state.Pairing!="PENDING_APPROVAL"{t.Fatal("pending was treated as online")}
 status,_=req(t,h,"POST","/v1/local/request",localsetup.Origin,token,string(body))
 if status!=409||remote.requests!=1{t.Fatal("duplicate pending request accepted")}
 status,_=req(t,h,"POST","/v1/local/finish",localsetup.Origin,token,`{}`)
 if status!=200||remote.enrolls!=1{t.Fatal("approved enrollment was not used")}
 deadline:=time.Now().Add(time.Second)
 for time.Now().Before(deadline)&&s.Status().Connection!="ONLINE"{time.Sleep(5*time.Millisecond)}
 if state:=s.Status();state.Connection!="ONLINE"||state.Pairing!="PAIRED"{
  t.Fatalf("no real stream => unexpected state %+v",state)
 }
 s.Close()
 deadline=time.Now().Add(time.Second)
 for time.Now().Before(deadline)&&s.Status().Connection=="ONLINE"{time.Sleep(5*time.Millisecond)}
 if s.Status().Connection!="OFFLINE"{t.Fatal("closed stream still online")}
}
