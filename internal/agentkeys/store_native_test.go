//go:build linux || darwin

package agentkeys

import(
 "bytes"
 "crypto/ed25519"
 "errors"
 "os"
 "path/filepath"
 "sync"
 "sync/atomic"
 "testing"
)
type mockVault struct{
 mu sync.Mutex
 values map[string][]byte
 disabled bool
}
func(m *mockVault)Ready()error{if m.disabled{return ErrUnsupported};return nil}
func(m *mockVault)Put(k string,v []byte)error{
 m.mu.Lock();defer m.mu.Unlock()
 if m.values==nil{m.values=make(map[string][]byte)}
 if _,found:=m.values[k];found{return ErrExists}
 m.values[k]=append([]byte(nil),v...)
 return nil
}
func(m *mockVault)Get(k string)([]byte,error){
 m.mu.Lock();defer m.mu.Unlock()
 v,ok:=m.values[k];if !ok{return nil,ErrCorrupt}
 return append([]byte(nil),v...),nil
}
func TestNativeIdentityReloadAndPrivateKeyNotOnDisk(t *testing.T){
 v:=&mockVault{}
 s:=Store{Dir:t.TempDir(),vault:v}
 if _,err:=s.Load();!errors.Is(err,ErrMissing){t.Fatalf("uninitialized identity: %v",err)}
 i,err:=s.Create();if err!=nil{t.Fatal(err)}
 marker,err:=os.ReadFile(filepath.Join(s.Dir,nativeMarker));if err!=nil{t.Fatal(err)}
 if bytes.Contains(marker,[]byte("\"key\""))||bytes.Contains(marker,[]byte("\"private\"")){t.Fatal("secret field present on disk")}
 if len(marker)>2048{t.Fatal("unbounded identity reference")}
 restored,err:=s.Load();if err!=nil{t.Fatal(err)}
 if !bytes.Equal(restored.PublicKey(),i.PublicKey())||restored.Fingerprint()!=i.Fingerprint(){t.Fatal("restored identity changed")}
 if !restored.CreatedAt().Equal(i.CreatedAt()){t.Fatal("creation time changed")}
 msg:=[]byte("localreach/native-proof/v1:opaque-sample")
 sig,err:=restored.SignMessage(msg);if err!=nil{t.Fatal(err)}
 if !ed25519.Verify(restored.PublicKey(),msg,sig){t.Fatal("restored identity failed signature proof")}
 if _,err=s.Create();!errors.Is(err,ErrExists){t.Fatalf("existing key replaced: %v",err)}
}
func TestNativeMissingVaultSecretFailsClosed(t *testing.T){
 v:=&mockVault{}
 s:=Store{Dir:t.TempDir(),vault:v}
 if _,err:=s.Create();err!=nil{t.Fatal(err)}
 v.mu.Lock();v.values=map[string][]byte{};v.mu.Unlock()
 if _,err:=s.Load();!errors.Is(err,ErrCorrupt){t.Fatalf("missing vault secret accepted: %v",err)}
 if _,err:=s.Create();!errors.Is(err,ErrExists){t.Fatalf("identity regenerated after secret loss: %v",err)}
}
func TestNativeMarkerTamperingAndSymlinkFailClosed(t *testing.T){
 v:=&mockVault{}
 s:=Store{Dir:t.TempDir(),vault:v}
 if _,err:=s.Create();err!=nil{t.Fatal(err)}
 path:=filepath.Join(s.Dir,nativeMarker)
 orig,err:=os.ReadFile(path);if err!=nil{t.Fatal(err)}
 tampered:=append([]byte(nil),orig...)
 tampered[len(tampered)/2]='!'
 if err=os.WriteFile(path,tampered,0600);err!=nil{t.Fatal(err)}
 if _,err:=s.Load();!errors.Is(err,ErrCorrupt){t.Fatalf("tampered marker accepted: %v",err)}
 if err=os.WriteFile(path,orig,0600);err!=nil{t.Fatal(err)}
 if _,err:=s.Load();err!=nil{t.Fatal(err)}
 if err=os.Remove(path);err!=nil{t.Fatal(err)}
 if err=os.Symlink(filepath.Join(s.Dir,"not-a-marker"),path);err!=nil{t.Skipf("symlink support unavailable: %v",err)}
 if _,err:=s.Load();!errors.Is(err,ErrCorrupt){t.Fatalf("symlink marker accepted: %v",err)}
}
func TestNativeNoProviderCreatesNoMarker(t *testing.T){
 s:=Store{Dir:t.TempDir(),vault:&mockVault{disabled:true}}
 if _,err:=s.Create();!errors.Is(err,ErrUnsupported){t.Fatalf("disabled backend: %v",err)}
 if _,err:=os.Lstat(filepath.Join(s.Dir,nativeMarker));!errors.Is(err,os.ErrNotExist){t.Fatalf("unavailable backend left marker: %v",err)}
}
func TestNativeConcurrentFirstCreate(t *testing.T){
 v:=&mockVault{}
 s:=Store{Dir:t.TempDir(),vault:v}
 var wg sync.WaitGroup
 var winners atomic.Int64
 for i:=0;i<12;i++{
  wg.Add(1)
  go func(){defer wg.Done();_,err:=s.Create();if err==nil{winners.Add(1)}else if !errors.Is(err,ErrExists){t.Errorf("unexpected create: %v",err)}}()
 }
 wg.Wait()
 if winners.Load()!=1{t.Fatalf("concurrent identities created %d",winners.Load())}
 if _,err:=s.Load();err!=nil{t.Fatal(err)}
}
func TestOptionalNativeCredentialManagerIntegration(t *testing.T){
 if os.Getenv("LOCALREACH_TEST_NATIVE_VAULT")!="1"{t.Skip("requires an unlocked user-native credential store")}
 s:=Store{Dir:t.TempDir()}
 created,err:=s.Create();if err!=nil{t.Fatal(err)}
 loaded,err:=s.Load();if err!=nil{t.Fatal(err)}
 if !bytes.Equal(created.PublicKey(),loaded.PublicKey()){t.Fatal("native keychain identity changed")}
}
