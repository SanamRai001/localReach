//go:build windows

package agentkeys

import (
 "bytes"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)

func TestWindowsDPAPIRestartIdentityAndSignature(t *testing.T){
 s:=Store{Dir:t.TempDir()}
 if _,err:=s.Load();!errors.Is(err,ErrMissing){t.Fatalf("new identity unexpectedly exists: %v",err)}
 created,err:=s.Create();if err!=nil{t.Fatal(err)}
 if created.CreatedAt().IsZero()||created.CreatedAt().After(time.Now().Add(time.Minute)){t.Fatal("bad creation time")}
 if created.Fingerprint()==""{t.Fatal("missing public fingerprint")}
 file,err:=os.ReadFile(filepath.Join(s.Dir,filename));if err!=nil{t.Fatal(err)}
 // Serialized private-key text must never be present in the file.
 if bytes.Contains(file,[]byte("private")){t.Fatal("plaintext marker found in DPAPI file")}
 restored,err:=s.Load();if err!=nil{t.Fatal(err)}
 if !bytes.Equal(created.PublicKey(),restored.PublicKey())||created.Fingerprint()!=restored.Fingerprint(){t.Fatal("identity changed across load")}
 if !created.CreatedAt().Equal(restored.CreatedAt()){t.Fatal("creation timestamp changed on restore")}
 message:=[]byte("localreach/session/v1:test-challenge-"+string(bytes.Repeat([]byte("A"),32)))
 signature,err:=restored.SignMessage(message);if err!=nil{t.Fatal(err)}
 if !ed25519.Verify(restored.PublicKey(),message,signature){t.Fatal("invalid restored signature")}
 if _,err=s.Create();!errors.Is(err,ErrExists){t.Fatalf("existing identity was overwritten: %v",err)}
}
func TestWindowsDPAPIRejectsCorruptionWithoutKeyRegeneration(t *testing.T){
 s:=Store{Dir:t.TempDir()}
 first,err:=s.Create();if err!=nil{t.Fatal(err)}
 path:=filepath.Join(s.Dir,filename)
 original,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 invalid:=append([]byte(nil),original...)
 invalid[len(invalid)/2]='!'
 if err=os.WriteFile(path,invalid,0600);err!=nil{t.Fatal(err)}
 if _,err=s.Load();!errors.Is(err,ErrCorrupt){t.Fatalf("corrupt identity accepted: %v",err)}
 if _,err=s.Create();!errors.Is(err,ErrExists){t.Fatalf("key regenerated over damage: %v",err)}
 if err=os.WriteFile(path,original,0600);err!=nil{t.Fatal(err)}
 recovered,err:=s.Load();if err!=nil{t.Fatal(err)}
 if !bytes.Equal(first.PublicKey(),recovered.PublicKey()){t.Fatal("cannot recover saved identity")}
}
func TestWindowsDPAPISingleCreatorAcrossRaces(t *testing.T){
 s:=Store{Dir:t.TempDir()}
 var success atomic.Int64
 var wg sync.WaitGroup
 for n:=0;n<8;n++{
  wg.Add(1)
  go func(){
   defer wg.Done()
   _,err:=s.Create()
   if err==nil{success.Add(1)}else if !errors.Is(err,ErrExists){t.Errorf("create failed unexpectedly: %v",err)}
  }()
 }
 wg.Wait()
 if success.Load()!=1{t.Fatalf("unexpected %d writers",success.Load())}
 if _,err:=s.Load();err!=nil{t.Fatal(err)}
}
func TestDPAPICiphertextIsUserBoundAndAuthenticated(t *testing.T){
 raw:=[]byte("temporary private test material")
 encrypted,err:=protect(raw);if err!=nil{t.Fatal(err)}
 if bytes.Equal(encrypted,raw){t.Fatal("DPAPI returned cleartext")}
 original,err:=unprotect(encrypted);if err!=nil{t.Fatal(err)}
 if !bytes.Equal(original,raw){t.Fatal("DPAPI roundtrip wrong")}
 encrypted[len(encrypted)/2]^=0x7f
 if _,err=unprotect(encrypted);err==nil{t.Fatal("tampered ciphertext decrypted successfully")}
}
