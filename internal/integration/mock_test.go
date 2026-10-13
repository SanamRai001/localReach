package integration

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "net/http/httptest"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/gateway"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/journal"
 "github.com/SanamRai001/localReach/internal/session"
)
func TestEncryptedIdentityAndJournalMock(t *testing.T){
 registry:=identity.NewRegistry(nil)
 invitation,err:=registry.Issue("workspace-1","site-1",time.Minute);if err!=nil{t.Fatal(err)}
 pub,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 agent,err:=registry.Enroll(invitation.Token,pub,identity.SignEnrollment(private,invitation.Token));if err!=nil{t.Fatal(err)}
 server:=httptest.NewTLSServer(gateway.New(session.New(registry,nil)));defer server.Close()
 client:=Client{HTTP:server.Client(),BaseURL:server.URL,AgentID:agent.ID,PrivateKey:private}
 path:=filepath.Join(t.TempDir(),"agent.journal")
 j,err:=journal.Open(path,1024*1024);if err!=nil{t.Fatal(err)}
 if err:=client.ExecuteMock(context.Background(),j,"op-1");err!=nil{t.Fatal(err)}
 got,ok:=j.Get("op-1");if !ok||got.State!=journal.Succeeded||got.Result!="pong"{t.Fatalf("unexpected state %+v",got)}
 if err:=client.ExecuteMock(context.Background(),j,"op-1");!errors.Is(err,journal.ErrConflict){t.Fatalf("duplicate execution accepted: %v",err)}
 if err:=j.Submit("unsafe","mock.ping");err!=nil{t.Fatal(err)}
 if err:=j.Begin("unsafe");err!=nil{t.Fatal(err)}
 if err:=j.Close();err!=nil{t.Fatal(err)}
 reopened,err:=journal.Open(path,1024*1024);if err!=nil{t.Fatal(err)}
 defer reopened.Close()
 got,_=reopened.Get("unsafe")
 if got.State!=journal.Indeterminate{t.Fatalf("interrupted operation not protected: %+v",got)}
 if err:=reopened.Begin("unsafe");!errors.Is(err,journal.ErrConflict){t.Fatalf("unsafe replay: %v",err)}
 if err:=registry.Revoke(agent.ID);err!=nil{t.Fatal(err)}
 if err:=client.ExecuteMock(context.Background(),reopened,"op-2");err==nil{t.Fatal("revoked agent executed command")}
 if _,exists:=reopened.Get("op-2");exists{t.Fatal("unauthorized operation journaled")}
}
func TestPlaintextAndWrongAgentIdentityFailClosed(t *testing.T){
 reg:=identity.NewRegistry(nil)
 inv,err:=reg.Issue("t","s",time.Minute);if err!=nil{t.Fatal(err)}
 pub,private,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 a,err:=reg.Enroll(inv.Token,pub,identity.SignEnrollment(private,inv.Token));if err!=nil{t.Fatal(err)}
 plain:=httptest.NewServer(gateway.New(session.New(reg,nil)));defer plain.Close()
 c:=Client{HTTP:plain.Client(),BaseURL:plain.URL,AgentID:a.ID,PrivateKey:private}
 if _,err:=c.Handshake(context.Background());err==nil{t.Fatal("plaintext accepted")}
 secured:=httptest.NewTLSServer(gateway.New(session.New(reg,nil)));defer secured.Close()
 _,other,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 c=Client{HTTP:secured.Client(),BaseURL:secured.URL,AgentID:a.ID,PrivateKey:other}
 if _,err:=c.Handshake(context.Background());err==nil{t.Fatal("incorrect private key accepted")}
}
