// Package agentkeys manages persistent agent signing keys using native
// OS secret storage. Never expose private key bytes to a browser.
package agentkeys

import (
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/hex"
 "errors"
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
 filename="identity.dpapi" // Windows marker; Unix stores use identity.ref
 formatVersion=1
 maxFileBytes=16384
)
type envelope struct{
 Version int `json:"version"`
 Protected string `json:"protected"`
}
type payload struct{
 Key string `json:"key"`
 CreatedAt int64 `json:"createdAt"`
}
type Identity struct{
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
// SignMessage is backend-only; the caller must domain-separate signatures.
func(i *Identity)SignMessage(message []byte)([]byte,error){
 if i==nil||len(i.private)!=ed25519.PrivateKeySize||len(message)==0||len(message)>8192{return nil,ErrCorrupt}
 return ed25519.Sign(i.private,message),nil
}
// vaultBackend is deliberately unexported: UI/application code cannot pass
// arbitrary external providers. Tests inject an isolated in-memory vault.
type vaultBackend interface{Ready()error;Put(string,[]byte)error;Get(string)([]byte,error)}
type Store struct{Dir string;vault vaultBackend}
func(s Store)directory()error{
 if s.Dir==""{return ErrUnsupported}
 if err:=os.MkdirAll(s.Dir,0700);err!=nil{return err}
 info,err:=os.Lstat(s.Dir)
 if err!=nil{return err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return ErrCorrupt}
 return nil
}
func(s Store)path()string{return filepath.Join(s.Dir,filename)}
