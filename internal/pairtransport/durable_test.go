package pairtransport

import (
 "crypto/ed25519"
 "crypto/rand"
 "net/http/httptest"
 "path/filepath"
 "testing"
 "time"

 "github.com/SanamRai001/localReach/internal/admintrust"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/pairing"
)
func TestDurableAdminDecisionAcrossTransportRestart(t *testing.T){
 clock:=time.Now()
 now:=func()time.Time{return clock}
 path:=filepath.Join(t.TempDir(),"trust.log")
 store,err:=admintrust.Open(path,now);if err!=nil{t.Fatal(err)}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 if err=store.Provision("org","owner-1",pub);err!=nil{t.Fatal(err)}
 registry:=identity.NewRegistry(now)
 mgr:=pairing.New(registry,now)
 agentPub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 pending,err:=mgr.Propose("org","site",agentPub);if err!=nil{t.Fatal(err)}
 d:=Decision{ID:pending.ID,Tenant:"org",Approve:true,Nonce:randomTestNonce(t),KeyID:"owner-1",IssuedAt:clock.Unix(),ExpiresAt:clock.Add(time.Minute).Unix()}
 server:=httptest.NewTLSServer(NewWithTrust(mgr,store,now))
 status,out:=request(t,server.Client(),server.URL,"/v1/pair/admin/decide",decisionPayload(d,priv))
 if status!=200||out["state"]!=string(pairing.Approved){t.Fatalf("trusted decision: %d %+v",status,out)}
 server.Close()
 if err=store.Close();err!=nil{t.Fatal(err)}
 store,err=admintrust.Open(path,now);if err!=nil{t.Fatal(err)}
 defer store.Close()
 server=httptest.NewTLSServer(NewWithTrust(mgr,store,now))
 defer server.Close()
 if status,_=request(t,server.Client(),server.URL,"/v1/pair/admin/decide",decisionPayload(d,priv));status!=403{t.Fatalf("replayed decision after restart: %d",status)}
 second,err:=mgr.Propose("org","site-2",func()ed25519.PublicKey{p,_,e:=ed25519.GenerateKey(rand.Reader);if e!=nil{t.Fatal(e)};return p}());if err!=nil{t.Fatal(err)}
 oldIssued:=Decision{ID:second.ID,Tenant:"org",Approve:true,Nonce:randomTestNonce(t),KeyID:"owner-1",IssuedAt:clock.Add(-5*time.Minute).Unix(),ExpiresAt:clock.Add(time.Minute).Unix()}
 if status,_=request(t,server.Client(),server.URL,"/v1/pair/admin/decide",decisionPayload(oldIssued,priv));status!=403{t.Fatalf("stale signature accepted: %d",status)}
 if err=store.Revoke("org","owner-1");err!=nil{t.Fatal(err)}
 afterRevocation:=Decision{ID:second.ID,Tenant:"org",Approve:true,Nonce:randomTestNonce(t),KeyID:"owner-1",IssuedAt:clock.Unix(),ExpiresAt:clock.Add(time.Minute).Unix()}
 if status,_=request(t,server.Client(),server.URL,"/v1/pair/admin/decide",decisionPayload(afterRevocation,priv));status!=403{t.Fatalf("revoked key authorized: %d",status)}
}
