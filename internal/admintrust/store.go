// Package admintrust owns a single-writer, append-only local administrative
// trust ledger. No HTTP endpoints and no private keys are stored here.
package admintrust

import (
 "bufio"
 "bytes"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "os"
 "sync"
 "time"

 "github.com/SanamRai001/localReach/internal/ownership"
)

var (
 ErrDenied=errors.New("administrator authorization denied")
 ErrCorrupt=errors.New("administrator ledger invalid or incomplete")
 ErrFull=errors.New("administrator ledger capacity exhausted")
)
const maxBytes int64=64<<20
const domain="localreach/admintrust/ledger/v1:"
type event struct{
 Op string `json:"op"`
 Tenant string `json:"tenant"`
 KeyID string `json:"keyId"`
 PublicKey string `json:"publicKey,omitempty"`
 NonceHash string `json:"nonceHash,omitempty"`
 At int64 `json:"at"`
 Previous string `json:"previous,omitempty"`
 Digest string `json:"digest"`
}
type adminKey struct{pub ed25519.PublicKey;revoked bool}
type Store struct{
 mu sync.Mutex
 file *os.File
 owner *ownership.Lock
 now func()time.Time
 keys map[string]adminKey
 used map[string]bool
 lastHash string
 poisoned bool
}
func key(tenant,id string)string{return tenant+"\x00"+id}
func digest(e event)string{
 e.Digest=""
 data,_:=json.Marshal(e)
 b:=sha256.Sum256(append([]byte(domain),data...))
 return base64.RawURLEncoding.EncodeToString(b[:])
}
func validID(s string)bool{return len(s)>0&&len(s)<=128}
func (s *Store)apply(e event)error{
 if !validID(e.Tenant)||!validID(e.KeyID)||e.At<=0{return ErrCorrupt}
 k:=key(e.Tenant,e.KeyID)
 old,has:=s.keys[k]
 switch e.Op{
 case "PROVISION":
  decoded,err:=base64.RawURLEncoding.DecodeString(e.PublicKey)
  if has||err!=nil||len(decoded)!=ed25519.PublicKeySize||e.NonceHash!=""{return ErrCorrupt}
  s.keys[k]=adminKey{pub:append(ed25519.PublicKey(nil),decoded...)}
 case "REVOKE":
  if !has||old.revoked||e.PublicKey!=""||e.NonceHash!=""{return ErrCorrupt}
  old.revoked=true;s.keys[k]=old
 case "CONSUME":
  decoded,err:=base64.RawURLEncoding.DecodeString(e.NonceHash)
  if !has||old.revoked||e.PublicKey!=""||err!=nil||len(decoded)!=sha256.Size{return ErrCorrupt}
  nonceKey:=key(e.Tenant,e.NonceHash)
  if s.used[nonceKey]{return ErrCorrupt}
  s.used[nonceKey]=true
 default:return ErrCorrupt
 }
 s.lastHash=e.Digest
 return nil
}
func Open(path string,now func()time.Time)(*Store,error){
 if now==nil{now=time.Now}
 owner,err:=ownership.Acquire(path);if err!=nil{return nil,err}
 file,err:=os.OpenFile(path,os.O_RDWR|os.O_CREATE,0600)
 if err!=nil{_ =owner.Release();return nil,err}
 s:=&Store{file:file,owner:owner,now:now,keys:map[string]adminKey{},used:map[string]bool{}}
 bad:=func()( *Store,error){_ =file.Close();_ =owner.Release();return nil,ErrCorrupt}
 stat,err:=file.Stat();if err!=nil||stat.Size()>maxBytes{return bad()}
 reader:=bufio.NewReader(file)
 for{
  line,readErr:=reader.ReadBytes('\n')
  if readErr==io.EOF{
   if len(line)!=0{return bad()}
   break
  }
  if readErr!=nil||len(line)==0||len(line)>8192{return bad()}
  var e event
  decoder:=json.NewDecoder(bytes.NewReader(line))
  decoder.DisallowUnknownFields()
  if decoder.Decode(&e)!=nil||decoder.Decode(new(any))!=io.EOF||e.Previous!=s.lastHash||e.Digest==""||digest(e)!=e.Digest{return bad()}
  if err=s.apply(e);err!=nil{return bad()}
 }
 if _,err=file.Seek(0,io.SeekEnd);err!=nil{return bad()}
 return s,nil
}
func(s *Store)append(e event)error{
 if s.file==nil||s.poisoned{return ErrDenied}
 e.Previous=s.lastHash;e.At=s.now().Unix();e.Digest=digest(e)
 line,err:=json.Marshal(e);if err!=nil{return err}
 line=append(line,'\n')
 pos,err:=s.file.Seek(0,io.SeekEnd);if err!=nil{s.poisoned=true;return err}
 if pos+int64(len(line))>maxBytes{return ErrFull}
 if _,err=s.file.Write(line);err!=nil{s.poisoned=true;return err}
 if err=s.file.Sync();err!=nil{s.poisoned=true;return err}
 return s.apply(e)
}
// Provision is trusted local/bootstrap code ONLY; never expose as an HTTP
// endpoint or let a caller self-register a key.
func(s *Store)Provision(tenant,id string,pub ed25519.PublicKey)error{
 s.mu.Lock();defer s.mu.Unlock()
 if !validID(tenant)||!validID(id)||len(pub)!=ed25519.PublicKeySize||s.file==nil{return ErrDenied}
 if _,ok:=s.keys[key(tenant,id)];ok{return ErrDenied}
 return s.append(event{Op:"PROVISION",Tenant:tenant,KeyID:id,PublicKey:base64.RawURLEncoding.EncodeToString(pub)})
}
func(s *Store)Revoke(tenant,id string)error{
 s.mu.Lock();defer s.mu.Unlock()
 existing,ok:=s.keys[key(tenant,id)]
 if !ok||existing.revoked||s.file==nil{return ErrDenied}
 return s.append(event{Op:"REVOKE",Tenant:tenant,KeyID:id})
}
// VerifyAndConsume atomically checks tenant/key/signature and persists a
// tenant-scoped hash of a single-use nonce BEFORE granting a decision.
func(s *Store)VerifyAndConsume(tenant,id,nonce string,message,signature []byte)error{
 s.mu.Lock();defer s.mu.Unlock()
 decoded,err:=base64.RawURLEncoding.DecodeString(nonce)
 if err!=nil||len(decoded)!=32||len(signature)!=ed25519.SignatureSize||s.file==nil{return ErrDenied}
 existing,ok:=s.keys[key(tenant,id)]
 if !ok||existing.revoked||!ed25519.Verify(existing.pub,message,signature){return ErrDenied}
 hash:=sha256.Sum256([]byte(nonce))
 hashText:=base64.RawURLEncoding.EncodeToString(hash[:])
 if s.used[key(tenant,hashText)]{return ErrDenied}
 return s.append(event{Op:"CONSUME",Tenant:tenant,KeyID:id,NonceHash:hashText})
}
func(s *Store)Close()error{
 s.mu.Lock();defer s.mu.Unlock()
 if s.file==nil{return nil}
 err:=s.file.Close()
 s.file=nil
 releaseErr:=s.owner.Release()
 if err!=nil{return err}
 return releaseErr
}
