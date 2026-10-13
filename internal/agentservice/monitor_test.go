package agentservice

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "sync"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/localsetup"
 "net/http/httptest"
 "testing/fstest"
 "encoding/json"
)
type signer struct{public ed25519.PublicKey;private ed25519.PrivateKey}
func(s signer)PublicKey()ed25519.PublicKey{return s.public}
func(s signer)SignMessage(b []byte)([]byte,error){return ed25519.Sign(s.private,b),nil}
type verifier struct{
 mu sync.Mutex
 fail bool
 calls int
}
func(v *verifier)VerifyIdentity(ctx context.Context,org string,s Signer)(string,error){
 v.mu.Lock();defer v.mu.Unlock()
 v.calls++
 if v.fail||org!="organization"||len(s.PublicKey())!=ed25519.PublicKeySize{return "",errors.New("verify refused")}
 return "agent-1",nil
}
func TestTruthfulVerifiedThenFailedAndStale(t *testing.T){
 public,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 now:=time.Date(2026,10,13,12,0,0,0,time.UTC)
 v:=&verifier{}
 monitor:=New("organization",signer{public,private},v)
 monitor.Now=func()time.Time{return now}
 initial:=monitor.Snapshot()
 if initial.Pairing!="NOT_PAIRED"||initial.Connection!="OFFLINE"||initial.Verification!="NOT_CHECKED"{t.Fatalf("wrong initial state: %+v",initial)}
 monitor.Tick(context.Background())
 state:=monitor.Snapshot()
 if state.Pairing!="PAIRED"||state.Verification!="VERIFIED_RECENTLY"||state.Connection!="OFFLINE"||state.Devices!="NOT_DISCOVERED"||state.LastVerifiedAt==""{t.Fatalf("wrong verified state: %+v",state)}
 now=now.Add(91*time.Second)
 state=monitor.Snapshot()
 if state.Pairing!="UNVERIFIED"||state.Verification!="STALE"||state.LastVerifiedAt!=""{t.Fatalf("stale proof accepted: %+v",state)}
 v.mu.Lock();v.fail=true;v.mu.Unlock()
 monitor.Tick(context.Background())
 state=monitor.Snapshot()
 if state.Pairing!="UNVERIFIED"||state.Verification!="FAILED"||state.Connection!="OFFLINE"{t.Fatalf("failure reported as connected: %+v",state)}
}
func TestLocalStatusUsesRealMonitorButNoMutation(t *testing.T){
 public,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 m:=New("organization",signer{public,private},&verifier{})
 m.Tick(context.Background())
 site:=fstest.MapFS{"index.html":&fstest.MapFile{Data:[]byte("LocalReach")}}
 handler:=localsetup.Handler(site,m.Snapshot)
 request:=httptest.NewRequest("GET",localsetup.Origin+"/v1/local/status",nil)
 request.RemoteAddr="127.0.0.1:34567"
 response:=httptest.NewRecorder()
 handler.ServeHTTP(response,request)
 if response.Code!=200{t.Fatal(response.Code)}
 var state map[string]string
 if err:=json.Unmarshal(response.Body.Bytes(),&state);err!=nil{t.Fatal(err)}
 if state["verification"]!="VERIFIED_RECENTLY"||state["connection"]!="OFFLINE"||state["devices"]!="NOT_DISCOVERED"{t.Fatalf("false status: %+v",state)}
 request=httptest.NewRequest("POST",localsetup.Origin+"/v1/local/status",nil)
 request.RemoteAddr="127.0.0.1:34567"
 response=httptest.NewRecorder()
 handler.ServeHTTP(response,request)
 if response.Code!=405{t.Fatalf("status became mutable: %d",response.Code)}
}
func TestRunCancellationFailsClosed(t *testing.T){
 public,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 m:=New("organization",signer{public,private},&verifier{})
 ctx,cancel:=context.WithCancel(context.Background())
 done:=make(chan struct{})
 go func(){m.Run(ctx);close(done)}()
 cancel()
 select{case <-done:case <-time.After(3*time.Second):t.Fatal("monitor did not stop")}
 s:=m.Snapshot()
 if s.Agent!="STOPPED"||s.Pairing!="UNVERIFIED"||s.Verification!="STOPPED"{t.Fatalf("active after cancellation: %+v",s)}
}
