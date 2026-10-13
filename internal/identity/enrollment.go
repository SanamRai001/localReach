// Package identity models one-time, scope-bound enrollment of an edge identity.
// This is an isolated prototype, not an externally reachable enrollment service.
package identity

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "errors"
 "fmt"
 "sync"
 "time"
)

var (
 ErrInvalidInvitation = errors.New("invalid or expired invitation")
 ErrInvalidProof = errors.New("invalid agent proof")
 ErrAlreadyEnrolled = errors.New("agent public key is already enrolled")
 ErrRevoked = errors.New("agent revoked")
)

const proofDomain = "localreach/enrollment/v1:"
type Invitation struct {
 Token string
 ExpiresAt time.Time
}
type Agent struct {
 ID string
 TenantID string
 SiteID string
 PublicKey ed25519.PublicKey
 EnrolledAt time.Time
 Revoked bool
}
type invitationRecord struct {
 tenant, site string
 expires time.Time
}
type Registry struct {
 mu sync.Mutex
 now func()time.Time
 invitations map[[32]byte]invitationRecord
 agents map[string]Agent
 keys map[[32]byte]string
}
func NewRegistry(now func()time.Time)*Registry{
 if now==nil{now=time.Now}
 return &Registry{now:now,invitations:make(map[[32]byte]invitationRecord),agents:make(map[string]Agent),keys:make(map[[32]byte]string)}
}
func randomToken(n int)(string,error){
 b:=make([]byte,n)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(b),nil
}
// Issue must only be called after independent workspace-admin authorization.
func (r *Registry) Issue(tenantID,siteID string,ttl time.Duration)(Invitation,error){
 if tenantID==""||siteID==""||ttl<=0||ttl>10*time.Minute{return Invitation{},errors.New("invalid invitation scope or TTL")}
 token,err:=randomToken(32);if err!=nil{return Invitation{},err}
 r.mu.Lock();defer r.mu.Unlock()
 expires:=r.now().Add(ttl)
 r.invitations[sha256.Sum256([]byte(token))]=invitationRecord{tenant:tenantID,site:siteID,expires:expires}
 return Invitation{Token:token,ExpiresAt:expires},nil
}
func SignEnrollment(private ed25519.PrivateKey, invitationToken string)[]byte{
 return ed25519.Sign(private,[]byte(proofDomain+invitationToken))
}
// Enroll requires proof that the enrolling process controls the submitted public key.
// The invitation is consumed only when the proof is correct.
func (r *Registry) Enroll(token string,pub ed25519.PublicKey,signature []byte)(Agent,error){
 if len(pub)!=ed25519.PublicKeySize||len(signature)!=ed25519.SignatureSize||token==""{return Agent{},ErrInvalidProof}
 hash:=sha256.Sum256([]byte(token))
 if !ed25519.Verify(pub,[]byte(proofDomain+token),signature){return Agent{},ErrInvalidProof}
 keyHash:=sha256.Sum256(pub)
 r.mu.Lock();defer r.mu.Unlock()
 inv,ok:=r.invitations[hash]
 if !ok||!r.now().Before(inv.expires){return Agent{},ErrInvalidInvitation}
 if _,exists:=r.keys[keyHash];exists{return Agent{},ErrAlreadyEnrolled}
 id,err:=randomToken(18);if err!=nil{return Agent{},fmt.Errorf("create identity: %w",err)}
 agent:=Agent{ID:id,TenantID:inv.tenant,SiteID:inv.site,PublicKey:append(ed25519.PublicKey(nil),pub...),EnrolledAt:r.now()}
 r.agents[id]=agent;r.keys[keyHash]=id
 delete(r.invitations,hash)
 return copyAgent(agent),nil
}
func copyAgent(a Agent)Agent{
 a.PublicKey=append(ed25519.PublicKey(nil),a.PublicKey...)
 return a
}
func (r *Registry) Lookup(id string)(Agent,bool){
 r.mu.Lock();defer r.mu.Unlock()
 a,ok:=r.agents[id];return copyAgent(a),ok
}
func (r *Registry) Revoke(id string)error{
 r.mu.Lock();defer r.mu.Unlock()
 a,ok:=r.agents[id];if !ok{return errors.New("unknown agent")}
 a.Revoked=true;r.agents[id]=a
 return nil
}
// VerifyChallenge validates possession of the enrolled private key for a fresh challenge.
// Caller must generate unpredictable, single-use challenges and enforce replay/expiry.
func (r *Registry) VerifyChallenge(id string,challenge,signature []byte)error{
 if len(challenge)<32||len(signature)!=ed25519.SignatureSize{return ErrInvalidProof}
 a,ok:=r.Lookup(id);if !ok{return ErrInvalidProof}
 if a.Revoked{return ErrRevoked}
 if !ed25519.Verify(a.PublicKey,append([]byte("localreach/session/v1:"),challenge...),signature){return ErrInvalidProof}
 return nil
}
