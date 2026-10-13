package integration

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "net/http/httptest"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/broker"
 "github.com/SanamRai001/localReach/internal/gateway"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/journal"
 "github.com/SanamRai001/localReach/internal/session"
)
func TestBrokerToAgentMockDelivery(t *testing.T){
 reg:=identity.NewRegistry(nil)
 inv,e:=reg.Issue("org-one","site-one",time.Minute);if e!=nil{t.Fatal(e)}
 pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 agent,e:=reg.Enroll(inv.Token,pub,identity.SignEnrollment(key,inv.Token));if e!=nil{t.Fatal(e)}
 srv:=httptest.NewTLSServer(gateway.New(session.New(reg,nil)));defer srv.Close()
 b,e:=broker.Open(filepath.Join(t.TempDir(),"broker.log"),1<<20,nil);if e!=nil{t.Fatal(e)};defer b.Close()
 j,e:=journal.Open(filepath.Join(t.TempDir(),"edge.log"),1<<20);if e!=nil{t.Fatal(e)};defer j.Close()
 d:=Delivery{Client:Client{HTTP:srv.Client(),BaseURL:srv.URL,AgentID:agent.ID,PrivateKey:key},Registry:reg,Broker:b,Edge:j}
 if e=b.Submit("order-1","org-one",agent.ID);e!=nil{t.Fatal(e)}
 if e=b.Submit("different-tenant","org-two",agent.ID);e!=nil{t.Fatal(e)}
 handled,e:=d.RunOnce(context.Background());if e!=nil||!handled{t.Fatalf("delivery: handled=%v err=%v",handled,e)}
 cloud,_:=b.Get("order-1","org-one");edge,_:=j.Get("order-1")
 if cloud.State!=broker.Succeeded||edge.State!=journal.Succeeded||edge.Result!="pong"{t.Fatalf("unexpected states: %+v %+v",cloud,edge)}
 handled,e=d.RunOnce(context.Background());if e!=nil||handled{t.Fatalf("cross-tenant or empty job handled: %v %v",handled,e)}
 if _,ok:=j.Get("different-tenant");ok{t.Fatal("cross-tenant command reached edge")}
 if e=reg.Revoke(agent.ID);e!=nil{t.Fatal(e)}
 if e=b.Submit("order-2","org-one",agent.ID);e!=nil{t.Fatal(e)}
 handled,e=d.RunOnce(context.Background());if e==nil||handled{t.Fatalf("revoked agent claimed job: %v %v",handled,e)}
 state,_:=b.Get("order-2","org-one");if state.State!=broker.Queued{t.Fatal(state)}
}
func TestEdgeDuplicateIsNeverExecutedAgain(t *testing.T){
 reg:=identity.NewRegistry(nil)
 inv,e:=reg.Issue("tenant","site",time.Minute);if e!=nil{t.Fatal(e)}
 pub,key,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)}
 a,e:=reg.Enroll(inv.Token,pub,identity.SignEnrollment(key,inv.Token));if e!=nil{t.Fatal(e)}
 srv:=httptest.NewTLSServer(gateway.New(session.New(reg,nil)));defer srv.Close()
 b,e:=broker.Open(filepath.Join(t.TempDir(),"broker.log"),1<<20,nil);if e!=nil{t.Fatal(e)};defer b.Close()
 j,e:=journal.Open(filepath.Join(t.TempDir(),"edge.log"),1<<20);if e!=nil{t.Fatal(e)};defer j.Close()
 if e=b.Submit("duplicate","tenant",a.ID);e!=nil{t.Fatal(e)}
 if e=j.Submit("duplicate","mock.ping");e!=nil{t.Fatal(e)}
 if e=j.Begin("duplicate");e!=nil{t.Fatal(e)}
 if e=j.Finish("duplicate",journal.Succeeded,"pong");e!=nil{t.Fatal(e)}
 d:=Delivery{Client:Client{HTTP:srv.Client(),BaseURL:srv.URL,AgentID:a.ID,PrivateKey:key},Registry:reg,Broker:b,Edge:j}
 claimed,e:=d.RunOnce(context.Background())
 if !claimed||!errors.Is(e,journal.ErrConflict){t.Fatalf("expected reconciliation blocker got %v %v",claimed,e)}
 edge,_:=j.Get("duplicate");if edge.State!=journal.Succeeded{t.Fatal(edge)}
 cloud,_:=b.Get("duplicate","tenant");if cloud.State!=broker.Leased{t.Fatal(cloud)}
}
