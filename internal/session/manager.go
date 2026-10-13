// Package session implements a bounded, one-time challenge handshake.
// This prototype is in-memory and MUST run behind authenticated TLS in production.
package session

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
var ErrDenied=errors.New("authentication denied")
const domain="localreach/session/v1:"
type challenge struct{ agent string; expires time.Time }
type active struct{ agent string; expires time.Time }
type Manager struct {
 mu sync.Mutex
 now func()time.Time
 registry *identity.Registry
 pending map[[32]byte]challenge
 sessions map[[32]byte]active
}
func New(reg *identity.Registry,now func()time.Time)*Manager{
 if now==nil{now=time.Now}
 return &Manager{registry:reg,now:now,pending:map[[32]byte]challenge{},sessions:map[[32]byte]active{}}
}
func fresh()(string,error){
 b:=make([]byte,32)
 if _,e:=rand.Read(b);e!=nil{return "",e}
 return base64.RawURLEncoding.EncodeToString(b),nil
}
// Begin generates a single-use challenge for an enrolled, nonrevoked agent.
// Caller must apply rate limits and establish transport confidentiality.
func (m *Manager) Begin(agentID string)(string,error){
 a,ok:=m.registry.Lookup(agentID);if !ok||a.Revoked{return "",ErrDenied}
 m.mu.Lock();defer m.mu.Unlock()
 if len(m.pending)>=4096{return "",ErrDenied}
 nonce,e:=fresh();if e!=nil{return "",e}
 m.pending[sha256.Sum256([]byte(nonce))]=challenge{agent:agentID,expires:m.now().Add(30*time.Second)}
 return nonce,nil
}
// Complete consumes challenge before checking proof, stopping concurrent replay.
// Invalid signatures also consume the challenge to fail closed.
func (m *Manager) Complete(agentID,nonce string,signature []byte)(string,error){
 h:=sha256.Sum256([]byte(nonce))
 m.mu.Lock()
 c,ok:=m.pending[h]
 if ok{delete(m.pending,h)}
 valid:=ok&&c.agent==agentID&&m.now().Before(c.expires)
 m.mu.Unlock()
 if !valid||len(signature)!=ed25519.SignatureSize{return "",ErrDenied}
 if e:=m.registry.VerifyChallenge(agentID,[]byte(nonce),signature);e!=nil{return "",ErrDenied}
 token,e:=fresh();if e!=nil{return "",e}
 m.mu.Lock();defer m.mu.Unlock()
 // Recheck revocation at issuance to narrow revoke/auth race.
 a,ok:=m.registry.Lookup(agentID);if !ok||a.Revoked{return "",ErrDenied}
 if len(m.sessions)>=4096{return "",ErrDenied}
 m.sessions[sha256.Sum256([]byte(token))]=active{agent:agentID,expires:m.now().Add(5*time.Minute)}
 return token,nil
}
// Authorize validates session expiry, current revocation, and exact agent scope.
// Sessions are short-lived; authorization must be checked on EVERY operation.
func (m *Manager) Authorize(agentID,token string)error{
 if token==""{return ErrDenied}
 h:=sha256.Sum256([]byte(token))
 m.mu.Lock()
 s,ok:=m.sessions[h]
 if ok&&(!m.now().Before(s.expires)){delete(m.sessions,h);ok=false}
 m.mu.Unlock()
 if !ok||s.agent!=agentID{return ErrDenied}
 a,found:=m.registry.Lookup(agentID)
 if !found||a.Revoked{return ErrDenied}
 return nil
}
// Sweep removes expired material. Call periodically for long-lived processes.
func (m *Manager) Sweep(){
 m.mu.Lock();defer m.mu.Unlock()
 for k,c:=range m.pending{if !m.now().Before(c.expires){delete(m.pending,k)}}
 for k,s:=range m.sessions{if !m.now().Before(s.expires){delete(m.sessions,k)}}
}
func Sign(private ed25519.PrivateKey,nonce string)[]byte{
 return ed25519.Sign(private,[]byte(domain+nonce))
}
