//go:build windows

package agentkeys

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "time"
)
func DefaultDir()(string,error){
 local:=os.Getenv("LOCALAPPDATA")
 if local==""{return "",ErrUnsupported}
 return filepath.Join(local,"LocalReach","Agent"),nil
}
// Create is explicitly called on FIRST enrollment and never overwrites an
// existing identity. A crash during its write fails closed on next Load.
// No automatic key rotation or regeneration is allowed.
func(s Store)Create()(*Identity,error){
 if err:=s.directory();err!=nil{return nil,err}
 createdAt:=time.Now().UTC().Truncate(time.Second)
 public,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{return nil,err}
 raw,err:=json.Marshal(payload{Key:base64.RawURLEncoding.EncodeToString(private),CreatedAt:createdAt.Unix()})
 if err!=nil{return nil,err}
 protected,err:=protect(raw)
 for n:=range raw{raw[n]=0}
 if err!=nil{return nil,err}
 serialized,err:=json.Marshal(envelope{Version:formatVersion,Protected:base64.RawURLEncoding.EncodeToString(protected)})
 if err!=nil{return nil,err}
 if len(serialized)>maxFileBytes{return nil,ErrCorrupt}
 file,err:=os.OpenFile(s.path(),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if errors.Is(err,os.ErrExist){return nil,ErrExists}
 if err!=nil{return nil,err}
 // On a failed write, preserve the incomplete file as a fail-closed signal.
 _,writeErr:=file.Write(serialized)
 if writeErr==nil{writeErr=file.Sync()}
 closeErr:=file.Close()
 if writeErr!=nil{return nil,writeErr}
 if closeErr!=nil{return nil,closeErr}
 if !bytes.Equal(public,private.Public().(ed25519.PublicKey)){return nil,ErrCorrupt}
 return &Identity{private:private,createdAt:createdAt},nil
}
// Load never creates a replacement identity when bytes are missing, damaged
// or OS DPAPI refuses decryption. An explicit recovery flow is required.
func(s Store)Load()(*Identity,error){
 if s.Dir==""{return nil,ErrUnsupported}
 info,err:=os.Lstat(s.Dir)
 if errors.Is(err,os.ErrNotExist){return nil,ErrMissing}
 if err!=nil{return nil,err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return nil,ErrCorrupt}
 fileInfo,err:=os.Lstat(s.path())
 if errors.Is(err,os.ErrNotExist){return nil,ErrMissing}
 if err!=nil{return nil,err}
 if !fileInfo.Mode().IsRegular()||fileInfo.Size()==0||fileInfo.Size()>maxFileBytes{return nil,ErrCorrupt}
 data,err:=os.ReadFile(s.path())
 if err!=nil{return nil,err}
 var e envelope
 decoder:=json.NewDecoder(bytes.NewReader(data))
 decoder.DisallowUnknownFields()
 if decoder.Decode(&e)!=nil||decoder.Decode(new(any))!=io.EOF||e.Version!=formatVersion||e.Protected==""{return nil,ErrCorrupt}
 encrypted,err:=base64.RawURLEncoding.DecodeString(e.Protected)
 if err!=nil||len(encrypted)==0||len(encrypted)>maxFileBytes{return nil,ErrCorrupt}
 plaintext,err:=unprotect(encrypted)
 if err!=nil{return nil,fmt.Errorf("%w: DPAPI unprotect failed",ErrCorrupt)}
 defer func(){for n:=range plaintext{plaintext[n]=0}}()
 var p payload
 inner:=json.NewDecoder(bytes.NewReader(plaintext))
 inner.DisallowUnknownFields()
 if inner.Decode(&p)!=nil||inner.Decode(new(any))!=io.EOF||p.CreatedAt<=0{return nil,ErrCorrupt}
 private,err:=base64.RawURLEncoding.DecodeString(p.Key)
 if err!=nil||len(private)!=ed25519.PrivateKeySize{return nil,ErrCorrupt}
 public:=ed25519.PrivateKey(private).Public().(ed25519.PublicKey)
 if len(public)!=ed25519.PublicKeySize{return nil,ErrCorrupt}
 return &Identity{private:ed25519.PrivateKey(private),createdAt:time.Unix(p.CreatedAt,0).UTC()},nil
}
