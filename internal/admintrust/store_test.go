package admintrust

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "sync/atomic"
 "testing"

 "github.com/SanamRai001/localReach/internal/ownership"
)
func nonce(t *testing.T)string{
 t.Helper()
 var b [32]byte
 if _,err:=rand.Read(b[:]);err!=nil{t.Fatal(err)}
 return base64.RawURLEncoding.EncodeToString(b[:])
}
func TestPersistentReplayAndRevocation(t *testing.T){
 path:=filepath.Join(t.TempDir(),"admin.log")
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 s,err:=Open(path,nil);if err!=nil{t.Fatal(err)}
 if err=s.Provision("org","admin-1",pub);err!=nil{t.Fatal(err)}
 if err=s.Provision("org","admin-1",pub);!errors.Is(err,ErrDenied){t.Fatal("duplicate provisioning allowed")}
 if second,err:=Open(path,nil);!errors.Is(err,ownership.ErrInUse){if err==nil{second.Close()};t.Fatalf("second ledger writer: %v",err)}
 msg:=[]byte("approved decision")
 signed:=ed25519.Sign(priv,msg)
 n:=nonce(t)
 if err=s.VerifyAndConsume("other","admin-1",n,msg,signed);!errors.Is(err,ErrDenied){t.Fatal("cross tenant replay accepted")}
 if err=s.VerifyAndConsume("org","admin-1",n,msg,signed);err!=nil{t.Fatal(err)}
 if err=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(path,nil);if err!=nil{t.Fatal(err)}
 if err=s.VerifyAndConsume("org","admin-1",n,msg,signed);!errors.Is(err,ErrDenied){t.Fatal("nonce replay accepted after restart")}
 n2:=nonce(t)
 if err=s.VerifyAndConsume("org","admin-1",n2,[]byte("tampered"),signed);!errors.Is(err,ErrDenied){t.Fatal("bad signature accepted")}
 if err=s.VerifyAndConsume("org","admin-1",n2,msg,signed);err!=nil{t.Fatal(err)}
 if err=s.Revoke("org","admin-1");err!=nil{t.Fatal(err)}
 if err=s.Close();err!=nil{t.Fatal(err)}
 s,err=Open(path,nil);if err!=nil{t.Fatal(err)}
 defer s.Close()
 if err=s.VerifyAndConsume("org","admin-1",nonce(t),msg,signed);!errors.Is(err,ErrDenied){t.Fatal("revoked key authorized")}
}
func TestTamperingOrTruncatedTailFailsClosed(t *testing.T){
 for _,variant:=range []string{"tamper","partial"}{
  t.Run(variant,func(t *testing.T){
   path:=filepath.Join(t.TempDir(),"audit.log")
   pub,_,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
   s,err:=Open(path,nil);if err!=nil{t.Fatal(err)}
   if err=s.Provision("org","admin",pub);err!=nil{t.Fatal(err)}
   if err=s.Close();err!=nil{t.Fatal(err)}
   raw,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
   if variant=="tamper"{raw[10]='X'}else{raw=append(raw,[]byte("{\"op\":\"CONSUME\"")...)}
   if err=os.WriteFile(path,raw,0600);err!=nil{t.Fatal(err)}
   _,err=Open(path,nil)
   if !errors.Is(err,ErrCorrupt){t.Fatalf("failed to deny corrupt audit: %v",err)}
  })
 }
}
func TestConcurrentNonceOnlyOneWinner(t *testing.T){
 path:=filepath.Join(t.TempDir(),"admin.log")
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 s,err:=Open(path,nil);if err!=nil{t.Fatal(err)}
 defer s.Close()
 if err=s.Provision("org","admin",pub);err!=nil{t.Fatal(err)}
 message:=[]byte("admin decision")
 sig:=ed25519.Sign(priv,message)
 n:=nonce(t)
 var wg sync.WaitGroup
 var accepted atomic.Int64
 for i:=0;i<20;i++{wg.Add(1);go func(){defer wg.Done();if s.VerifyAndConsume("org","admin",n,message,sig)==nil{accepted.Add(1)}}()}
 wg.Wait()
 if accepted.Load()!=1{t.Fatalf("accepted %d competing same-nonce decisions",accepted.Load())}
}
