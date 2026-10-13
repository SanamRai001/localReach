package transport

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/broker"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/integration"
 "github.com/SanamRai001/localReach/internal/journal"
 "github.com/SanamRai001/localReach/internal/session"
)
func setup(t *testing.T)(Server,*broker.Broker,identity.Agent,ed25519.PrivateKey){
 t.Helper()
 reg:=identity.NewRegistry(nil)
 inv,e:=reg.Issue("tenant-a","site-a",time.Minute);if e!=nil{t.Fatal(e)}
 pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 agent,e:=reg.Enroll(inv.Token,pub,identity.SignEnrollment(key,inv.Token));if e!=nil{t.Fatal(e)}
 b,e:=broker.Open(filepath.Join(t.TempDir(),"broker.log"),1<<20,nil);if e!=nil{t.Fatal(e)}
 t.Cleanup(func(){b.Close()})
 return Server{Registry:reg,Sessions:session.New(reg,nil),Broker:b},b,agent,key
}
func TestOutboundTLSDelivery(t *testing.T){
 server,b,agent,key:=setup(t)
 if e:=b.Submit("first","tenant-a",agent.ID);e!=nil{t.Fatal(e)}
 if e:=b.Submit("foreign","tenant-b",agent.ID);e!=nil{t.Fatal(e)}
 tls:=httptest.NewTLSServer(New(server));defer tls.Close()
 j,e:=journal.Open(filepath.Join(t.TempDir(),"edge.log"),1<<20);if e!=nil{t.Fatal(e)};defer j.Close()
 worker:=Agent{Identity:integration.Client{HTTP:tls.Client(),BaseURL:tls.URL,AgentID:agent.ID,PrivateKey:key},Journal:j}
 ok,e:=worker.PollOnce(context.Background());if e!=nil||!ok{t.Fatalf("mock delivery: %v %v",ok,e)}
 bResult,_:=b.Get("first","tenant-a");edge,_:=j.Get("first")
 if bResult.State!=broker.Succeeded||edge.State!=journal.Succeeded{t.Fatalf("inconsistent states: %+v %+v",bResult,edge)}
 ok,e=worker.PollOnce(context.Background());if e!=nil||ok{t.Fatalf("foreign tenant received or unexpected work: %v %v",ok,e)}
 if e=server.Registry.Revoke(agent.ID);e!=nil{t.Fatal(e)}
 if e=b.Submit("next","tenant-a",agent.ID);e!=nil{t.Fatal(e)}
 ok,e=worker.PollOnce(context.Background());if e==nil||ok{t.Fatalf("revoked agent fetched: %v %v",ok,e)}
}
func TestRejectPlaintextAndPreventDuplicateExecution(t *testing.T){
 server,b,agent,key:=setup(t)
 plain:=httptest.NewServer(New(server));defer plain.Close()
 resp,e:=http.Post(plain.URL+"/v1/agent/claim","application/json",nil);if e!=nil{t.Fatal(e)}
 if resp.StatusCode!=426{t.Fatalf("plaintext accepted: %d",resp.StatusCode)};resp.Body.Close()
 tls:=httptest.NewTLSServer(New(server));defer tls.Close()
 j,e:=journal.Open(filepath.Join(t.TempDir(),"edge.log"),1<<20);if e!=nil{t.Fatal(e)};defer j.Close()
 if e=b.Submit("repeat","tenant-a",agent.ID);e!=nil{t.Fatal(e)}
 if e=j.Submit("repeat","mock.ping");e!=nil{t.Fatal(e)}
 if e=j.Begin("repeat");e!=nil{t.Fatal(e)}
 if e=j.Finish("repeat",journal.Succeeded,"pong");e!=nil{t.Fatal(e)}
 worker:=Agent{Identity:integration.Client{HTTP:tls.Client(),BaseURL:tls.URL,AgentID:agent.ID,PrivateKey:key},Journal:j}
 claimed,e:=worker.PollOnce(context.Background())
 if !claimed||e!=nil{t.Fatalf("durable result reconciliation failed: %v %v",claimed,e)}
 cloud,_:=b.Get("repeat","tenant-a");if cloud.State!=broker.Succeeded{t.Fatal(cloud)}
 edge,_:=j.Get("repeat");if edge.State!=journal.Succeeded{t.Fatal(edge)}
}

func TestPreexistingEdgeIntentQuarantined(t *testing.T){
 server,b,agent,key:=setup(t)
 tls:=httptest.NewTLSServer(New(server));defer tls.Close()
 j,e:=journal.Open(filepath.Join(t.TempDir(),"edge.log"),1<<20);if e!=nil{t.Fatal(e)};defer j.Close()
 if e=b.Submit("uncertain","tenant-a",agent.ID);e!=nil{t.Fatal(e)}
 if e=j.Submit("uncertain","mock.ping");e!=nil{t.Fatal(e)}
 worker:=Agent{Identity:integration.Client{HTTP:tls.Client(),BaseURL:tls.URL,AgentID:agent.ID,PrivateKey:key},Journal:j}
 handled,e:=worker.PollOnce(context.Background())
 if e!=nil||!handled{t.Fatalf("quarantine: handled %v, err %v",handled,e)}
 cloud,_:=b.Get("uncertain","tenant-a")
 if cloud.State!=broker.Indeterminate{t.Fatalf("uncertain work was not quarantined: %+v",cloud)}
 edge,_:=j.Get("uncertain")
 if edge.State!=journal.Queued{t.Fatalf("existing edge record mutated: %+v",edge)}
}
