// Package agentkeys stores an agent signing identity using the platform
// credential protection mechanism. Never return private key bytes to a UI.
package agentkeys

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "time"
)

var (
 ErrUnsupported=errors.New("secure native key storage is unavailable")
 ErrExists=errors.New("agent signing identity already exists")
 ErrMissing=errors.New("agent signing identity does not exist")
 ErrCorrupt=errors.New("agent signing identity is invalid or cannot be decrypted")
)
const (
 filename="identity.dpapi"
 formatVersion=1
 maxFileBytes=16384
)
type envelope struct {
 Version int `json:"version"`
 Protected string `json:"protected"`
}
type payload struct{
 Key string `json:"key"`
 CreatedAt int64 `json:"createdAt"`
}
// Identity keeps sensitive bytes exclusively in the backend Go process.
// Go garbage collection and copies mean complete in-memory erasure cannot
// be guaranteed; never log, serialize or expose Identity to browser code.
type Identity struct {
 private ed25519.PrivateKey
 createdAt time.Time
}
func(i *Identity)PublicKey()ed25519.PublicKey{
 if i==nil||len(i.private)!=ed25519.PrivateKeySize{return nil}
 public:=i.private.Public().(ed25519.PublicKey)
 return append(ed25519.PublicKey(nil),public...)
}
func(i *Identity)Fingerprint()string{
 public:=i.PublicKey()
 if len(public)!=ed25519.PublicKeySize{return ""}
 digest:=sha256.Sum256(public)
 return hex.EncodeToString(digest[:])
}
func(i *Identity)CreatedAt()time.Time{
 if i==nil{return time.Time{}}
 return i.createdAt
}
// SignMessage is available ONLY inside the trusted native agent process.
// Callers must domain-separate protocol messages and never offer this method
// over an untrusted generic RPC endpoint.
func(i *Identity)SignMessage(message []byte)([]byte,error){
 if i==nil||len(i.private)!=ed25519.PrivateKeySize||len(message)==0||len(message)>8192{return nil,ErrCorrupt}
 return ed25519.Sign(i.private,message),nil
}
type Store struct{Dir string}
// DefaultDir is scoped to the interactive Windows user's local profile,
// rather than a machine-wide directory or remotely roaming application data.
func DefaultDir()(string,error){
 local:=os.Getenv("LOCALAPPDATA")
 if local==""{return "",ErrUnsupported}
 return filepath.Join(local,"LocalReach","Agent"),nil
}
func(s Store)directory()error{
 if s.Dir==""{return ErrUnsupported}
 if err:=os.MkdirAll(s.Dir,0700);err!=nil{return err}
 info,err:=os.Lstat(s.Dir)
 if err!=nil{return err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return ErrCorrupt}
 return nil
}
func(s Store)path()string{return filepath.Join(s.Dir,filename)}
// Create is explicitly called on FIRST enrollment and never overwrites an
// existing identity. A crash during its write fails closed on next Load.
// No automatic key rotation or regeneration is allowed.
func(s Store)Create()(*Identity,error){
 if err:=s.directory();err!=nil{return nil,err}
 public,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{return nil,err}
 raw,err:=json.Marshal(payload{Key:base64.RawURLEncoding.EncodeToString(private),CreatedAt:time.Now().UTC().Unix()})
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
 return &Identity{private:private,createdAt:time.Now().UTC()},nil
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
