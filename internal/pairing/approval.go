// Package pairing models an explicit admin-approved pairing state machine.
// This is an isolated in-memory policy primitive, NOT an authenticated API.
package pairing

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "errors"
 "sync"
 "time"

 "github.com/SanamRai001/localReach/internal/identity"
)
var ErrDenied=errors.New("pairing denied")
const handoffDomain="localreach/pairing/handoff/v1:"
type State string
const (Pending State="PENDING_APPROVAL";Approved State="APPROVED";Rejected State="REJECTED";Expired State="EXPIRED";Enrolled State="ENROLLED")
type Request struct{
 ID string
 TenantID string
 SiteID string
 PublicKey ed25519.PublicKey
 State State
 ExpiresAt time.Time
}
type record struct{request Request;invitation string}
type Manager struct{
 mu sync.Mutex
 registry *identity.Registry
 now func()time.Time
 requests map[string]record
 keys map[[32]byte]string
}
func New(registry *identity.Registry,now func()time.Time)*Manager{
 if now==nil{now=time.Now}
 return &Manager{registry:registry,now:now,requests:map[string]record{},keys:map[[32]byte]string{}}
}
func newID()(string,error){b:=make([]byte,24);if _,err:=rand.Read(b);err!=nil{return "",err};return base64.RawURLEncoding.EncodeToString(b),nil}
func copyRequest(r Request)Request{r.PublicKey=append(ed25519.PublicKey(nil),r.PublicKey...);return r}
// Propose records a request for admin review; it DOES NOT enroll the key.
func(m *Manager)Propose(tenant,site string,pub ed25519.PublicKey)(Request,error){
 if m.registry==nil||tenant==""||site==""||len(pub)!=ed25519.PublicKeySize{return Request{},ErrDenied}
 m.mu.Lock();defer m.mu.Unlock()
 if len(m.requests)>=1024{return Request{},ErrDenied}
 hash:=sha256.Sum256(pub);if _,exists:=m.keys[hash];exists{return Request{},ErrDenied}
 id,err:=newID();if err!=nil{return Request{},err}
 req:=Request{ID:id,TenantID:tenant,SiteID:site,PublicKey:append(ed25519.PublicKey(nil),pub...),State:Pending,ExpiresAt:m.now().Add(5*time.Minute)}
 m.requests[id]=record{request:req};m.keys[hash]=id
 return copyRequest(req),nil
}
// Decide expects a previously independently authenticated tenant administrator.
// The caller must prove tenant admin role; this function checks the scope
// binding but cannot itself authenticate its arguments.
func(m *Manager)Decide(id,tenant string,authorized bool,approve bool)(Request,error){
 m.mu.Lock();defer m.mu.Unlock()
 rec,ok:=m.requests[id]
 if !ok||!authorized||rec.request.TenantID!=tenant||rec.request.State!=Pending{return Request{},ErrDenied}
 if !m.now().Before(rec.request.ExpiresAt){rec.request.State=Expired;m.requests[id]=rec;return Request{},ErrDenied}
 if approve{
  inv,err:=m.registry.Issue(rec.request.TenantID,rec.request.SiteID,time.Minute)
  if err!=nil{return Request{},err}
  rec.invitation=inv.Token;rec.request.State=Approved
 }else{rec.request.State=Rejected}
 m.requests[id]=rec
 return copyRequest(rec.request),nil
}
// InvitationForAgent releases a short-lived approved invitation only to the
// holder of the originally proposed Ed25519 key. The random request ID is
// signed with domain separation. Caller MUST use confidential authenticated
// transport; no HTTP endpoint is exposed in this phase.
func(m *Manager)InvitationForAgent(id string,signature []byte)(string,error){
 m.mu.Lock();defer m.mu.Unlock()
 rec,ok:=m.requests[id]
 if !ok||rec.request.State!=Approved||!m.now().Before(rec.request.ExpiresAt)||len(signature)!=ed25519.SignatureSize||rec.invitation==""{return "",ErrDenied}
 if !ed25519.Verify(rec.request.PublicKey,[]byte(handoffDomain+id),signature){return "",ErrDenied}
 return rec.invitation,nil
}
// SignHandoff proves key possession to the internal pairing manager.
func SignHandoff(private ed25519.PrivateKey,id string)[]byte{
 return ed25519.Sign(private,[]byte(handoffDomain+id))
}
// Redeem requires the local agent to prove private-key possession. Approved
// invitations are kept private in memory and never exposed by Get.
func(m *Manager)Redeem(id string,proof []byte)(identity.Agent,error){
 m.mu.Lock();defer m.mu.Unlock()
 rec,ok:=m.requests[id]
 if !ok||rec.request.State!=Approved||!m.now().Before(rec.request.ExpiresAt){return identity.Agent{},ErrDenied}
 enrolled,err:=m.registry.Enroll(rec.invitation,rec.request.PublicKey,proof)
 if err!=nil{return identity.Agent{},ErrDenied}
 rec.request.State=Enrolled;rec.invitation="";m.requests[id]=rec
 return enrolled,nil
}
func(m *Manager)Get(id,tenant string)(Request,bool){
 m.mu.Lock();defer m.mu.Unlock()
 rec,ok:=m.requests[id];if !ok||rec.request.TenantID!=tenant{return Request{},false}
 req:=rec.request
 if m.now().After(req.ExpiresAt)&&req.State==Pending{req.State=Expired}
 return copyRequest(req),true
}
// ApprovedProof is intentionally NOT exported: agents must receive a secured
// invitation after approval through a future authenticated pairing channel.
