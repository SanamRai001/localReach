// Package pairledger provides an isolated, restart-safe pairing lifecycle.
// It does not start a listener, authenticate administrators or grant devices.
package pairledger

import (
 "bufio"
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "os"
 "strings"
 "sync"
 "time"

 "github.com/SanamRai001/localReach/internal/ownership"
)

var (
 ErrDenied=errors.New("pairing lifecycle denied")
 ErrCorrupt=errors.New("pairing journal corrupt or incomplete")
 ErrFull=errors.New("pairing journal full")
)
const (
 maxBytes int64=64<<20
 maxRecords=4096
 domain="localreach/pairledger/v1:"
 proofDomain="localreach/pairledger/enroll/v1:"
)
type State string
const (
 Pending State="PENDING_APPROVAL"
 Approved State="APPROVED"
 Rejected State="REJECTED"
 Enrolled State="ENROLLED"
 Revoked State="REVOKED"
 Expired State="EXPIRED"
)
type Record struct {
 ID string
 Tenant string
 Site string
 PublicKey ed25519.PublicKey
 State State
 ExpiresAt time.Time
 ApprovalUntil time.Time
 AgentID string
}
type event struct{
 Op string `json:"op"`
 ID string `json:"id"`
 Tenant string `json:"tenant"`
 Site string `json:"site,omitempty"`
 Key string `json:"key,omitempty"`
 Expires int64 `json:"expires,omitempty"`
 ApprovalUntil int64 `json:"approvalUntil,omitempty"`
 AgentID string `json:"agentId,omitempty"`
 At int64 `json:"at"`
 Previous string `json:"previous,omitempty"`
 Digest string `json:"digest"`
}
type challenge struct{requestID string; expires time.Time}
type Store struct{
 mu sync.Mutex
 file *os.File
 owner *ownership.Lock
 now func()time.Time
 records map[string]Record
 keys map[[32]byte]string
 agents map[string]string
 challenges map[string]challenge
 lastHash string
 poisoned bool
}
func valid(s string)bool{return len(s)>0&&len(s)<=128&&strings.IndexFunc(s,func(r rune)bool{return r<32||r==127})==-1}
func randomID(size int)(string,error){
 b:=make([]byte,size)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(b),nil
}
func digest(e event)string{
 e.Digest=""
 raw,_:=json.Marshal(e)
 sum:=sha256.Sum256(append([]byte(domain),raw...))
 return base64.RawURLEncoding.EncodeToString(sum[:])
}
func copyRecord(r Record)Record{r.PublicKey=append(ed25519.PublicKey(nil),r.PublicKey...);return r}
func emptyExtras(e event)bool{return e.Site==""&&e.Key==""&&e.Expires==0&&e.ApprovalUntil==0&&e.AgentID==""}
func (s *Store) apply(e event)error{
 if !valid(e.ID)||!valid(e.Tenant)||e.At<=0{return ErrCorrupt}
 record,found:=s.records[e.ID]
 switch e.Op{
 case "PROPOSE":
  pub,err:=base64.RawURLEncoding.DecodeString(e.Key)
  hash:=sha256.Sum256(pub)
  if found||len(s.records)>=maxRecords||!valid(e.Site)||err!=nil||len(pub)!=ed25519.PublicKeySize||e.Expires<=e.At||e.Expires>e.At+int64(5*time.Minute)||e.ApprovalUntil!=0||e.AgentID!=""{return ErrCorrupt}
  if _,used:=s.keys[hash];used{return ErrCorrupt}
  record=Record{ID:e.ID,Tenant:e.Tenant,Site:e.Site,PublicKey:append(ed25519.PublicKey(nil),pub...),State:Pending,ExpiresAt:time.Unix(0,e.Expires)}
  s.keys[hash]=e.ID
 case "APPROVE":
  if !found||record.Tenant!=e.Tenant||record.State!=Pending||!emptyExtras(event{Site:e.Site,Key:e.Key,Expires:e.Expires,AgentID:e.AgentID})||e.ApprovalUntil<=e.At||e.ApprovalUntil>e.At+int64(time.Minute)||e.ApprovalUntil>record.ExpiresAt.UnixNano()||e.At>=record.ExpiresAt.UnixNano(){return ErrCorrupt}
  record.State=Approved
  record.ApprovalUntil=time.Unix(0,e.ApprovalUntil)
 case "REJECT":
  if !found||record.Tenant!=e.Tenant||record.State!=Pending||!emptyExtras(e)||e.At>=record.ExpiresAt.UnixNano(){return ErrCorrupt}
  record.State=Rejected
 case "ENROLL":
  if !found||record.Tenant!=e.Tenant||record.State!=Approved||!valid(e.AgentID)||e.Site!=""||e.Key!=""||e.Expires!=0||e.ApprovalUntil!=0||e.At>=record.ApprovalUntil.UnixNano()||e.At>=record.ExpiresAt.UnixNano(){return ErrCorrupt}
  if _,exists:=s.agents[e.AgentID];exists{return ErrCorrupt}
  record.State=Enrolled;record.AgentID=e.AgentID
  s.agents[e.AgentID]=e.ID
 case "REVOKE":
  if !found||record.Tenant!=e.Tenant||record.State!=Enrolled||!emptyExtras(e){return ErrCorrupt}
  record.State=Revoked
 default:return ErrCorrupt
 }
 s.records[e.ID]=record
 s.lastHash=e.Digest
 return nil
}
func Open(path string,now func()time.Time)(*Store,error){
 if now==nil{now=time.Now}
 owner,err:=ownership.Acquire(path);if err!=nil{return nil,err}
 file,err:=os.OpenFile(path,os.O_RDWR|os.O_CREATE,0600)
 if err!=nil{_ =owner.Release();return nil,err}
 s:=&Store{file:file,owner:owner,now:now,records:map[string]Record{},keys:map[[32]byte]string{},agents:map[string]string{},challenges:map[string]challenge{}}
 fail:=func()(*Store,error){_ =file.Close();_ =owner.Release();return nil,ErrCorrupt}
 st,err:=file.Stat()
 if err!=nil||st.Size()>maxBytes{return fail()}
 reader:=bufio.NewReader(file)
 for{
  line,e:=reader.ReadBytes('\n')
  if e==io.EOF{if len(line)!=0{return fail()};break}
  if e!=nil||len(line)==0||len(line)>8192{return fail()}
  var item event
  decoder:=json.NewDecoder(bytes.NewReader(line))
  decoder.DisallowUnknownFields()
  if decoder.Decode(&item)!=nil||decoder.Decode(new(any))!=io.EOF||item.Previous!=s.lastHash||item.Digest==""||item.Digest!=digest(item){return fail()}
  if s.apply(item)!=nil{return fail()}
 }
 if _,err=file.Seek(0,io.SeekEnd);err!=nil{return fail()}
 return s,nil
}
func(s *Store) append(e event)error{
 if s.file==nil||s.poisoned{return ErrDenied}
 e.At=s.now().UnixNano();e.Previous=s.lastHash;e.Digest=digest(e)
 data,err:=json.Marshal(e);if err!=nil{return err}
 data=append(data,'\n')
 pos,err:=s.file.Seek(0,io.SeekEnd)
 if err!=nil{s.poisoned=true;return err}
 if pos+int64(len(data))>maxBytes{return ErrFull}
 if _,err=s.file.Write(data);err!=nil{s.poisoned=true;return err}
 if err=s.file.Sync();err!=nil{s.poisoned=true;return err}
 if err=s.apply(e);err!=nil{s.poisoned=true;return err}
 return nil
}
// Propose saves the agent public key and scope. It does not approve anything.
func(s *Store)Propose(tenant,site string,pub ed25519.PublicKey)(Record,error){
 s.mu.Lock();defer s.mu.Unlock()
 if !valid(tenant)||!valid(site)||len(pub)!=ed25519.PublicKeySize||len(s.records)>=maxRecords{return Record{},ErrDenied}
 h:=sha256.Sum256(pub)
 if _,exists:=s.keys[h];exists{return Record{},ErrDenied}
 id,err:=randomID(24);if err!=nil{return Record{},err}
 e:=event{Op:"PROPOSE",ID:id,Tenant:tenant,Site:site,Key:base64.RawURLEncoding.EncodeToString(pub),Expires:s.now().Add(5*time.Minute).UnixNano()}
 if err=s.append(e);err!=nil{return Record{},err}
 return copyRecord(s.records[id]),nil
}
// Decide requires independently established administrator authorization.
// Passing authorized=true from an HTTP body would be a security vulnerability.
func(s *Store)Decide(tenant,id string,authorized,approve bool)(Record,error){
 s.mu.Lock();defer s.mu.Unlock()
 r,ok:=s.records[id]
 if !authorized||!ok||r.Tenant!=tenant||r.State!=Pending||!s.now().Before(r.ExpiresAt){return Record{},ErrDenied}
 e:=event{ID:id,Tenant:tenant}
 if approve{
  e.Op="APPROVE"
  until:=s.now().Add(time.Minute)
  if until.After(r.ExpiresAt){until=r.ExpiresAt}
  e.ApprovalUntil=until.UnixNano()
 }else{e.Op="REJECT"}
 if err:=s.append(e);err!=nil{return Record{},err}
 return copyRecord(s.records[id]),nil
}
// Challenge is ephemeral: restarting the process invalidates all challenges.
func(s *Store)Challenge(id string)(string,error){
 s.mu.Lock();defer s.mu.Unlock()
 r,ok:=s.records[id]
 if !ok||r.State!=Approved||!s.now().Before(r.ApprovalUntil){return "",ErrDenied}
 for k,c:=range s.challenges{if !s.now().Before(c.expires){delete(s.challenges,k)}}
 if len(s.challenges)>=1024{return "",ErrFull}
 n,err:=randomID(32);if err!=nil{return "",err}
 s.challenges[n]=challenge{requestID:id,expires:s.now().Add(30*time.Second)}
 return n,nil
}
// SignEnrollment proves possession of the proposed key for a fresh nonce.
func SignEnrollment(priv ed25519.PrivateKey,id,nonce string)[]byte{
 return ed25519.Sign(priv,[]byte(proofDomain+id+":"+nonce))
}
// Enroll consumes the fresh challenge even after a wrong signature, then
// durably records the bound agent ID. No device capabilities are granted.
func(s *Store)Enroll(id,nonce string,proof []byte)(Record,error){
 s.mu.Lock();defer s.mu.Unlock()
 ch,ok:=s.challenges[nonce]
 if ok{delete(s.challenges,nonce)}
 r,exists:=s.records[id]
 if !ok||ch.requestID!=id||!s.now().Before(ch.expires)||!exists||r.State!=Approved||!s.now().Before(r.ApprovalUntil)||len(proof)!=ed25519.SignatureSize||!ed25519.Verify(r.PublicKey,[]byte(proofDomain+id+":"+nonce),proof){return Record{},ErrDenied}
 agentID,err:=randomID(18);if err!=nil{return Record{},err}
 if err=s.append(event{Op:"ENROLL",ID:id,Tenant:r.Tenant,AgentID:agentID});err!=nil{return Record{},err}
 return copyRecord(s.records[id]),nil
}
// Revoke is an operator-only call and does not yet broadcast session kills.
func(s *Store)Revoke(tenant,id string,authorized bool)error{
 s.mu.Lock();defer s.mu.Unlock()
 r,ok:=s.records[id]
 if !ok||!authorized||r.Tenant!=tenant||r.State!=Enrolled{return ErrDenied}
 return s.append(event{Op:"REVOKE",ID:id,Tenant:tenant})
}
func(s *Store)Get(tenant,id string)(Record,bool){
 s.mu.Lock();defer s.mu.Unlock()
 r,ok:=s.records[id]
 if !ok||r.Tenant!=tenant{return Record{},false}
 if (r.State==Pending||r.State==Approved)&&!s.now().Before(r.ExpiresAt){r.State=Expired}
 if r.State==Approved&&!s.now().Before(r.ApprovalUntil){r.State=Expired}
 return copyRecord(r),true
}
func(s *Store)Close()error{
 s.mu.Lock();defer s.mu.Unlock()
 if s.file==nil{return nil}
 err:=s.file.Close();s.file=nil
 releaseErr:=s.owner.Release()
 if err!=nil{return err}
 return releaseErr
}
