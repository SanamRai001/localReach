// Package pairtransport is a TLS-only in-memory pairing transport experiment.
// It has no listener. Trusted admin public keys are explicitly provisioned
// by the caller and must NOT be supplied by an HTTP client.
package pairtransport

import (
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/json"
 "io"
 "net/http"
 "strconv"
 "sync"
 "time"

 "github.com/SanamRai001/localReach/internal/admintrust"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/pairing"
)

const decisionDomain="localreach/pairing/admin-decision/v1:"
type Decision struct {
 ID string `json:"id"`
 Tenant string `json:"tenant"`
 Approve bool `json:"approve"`
 Nonce string `json:"nonce"`
 KeyID string `json:"keyId,omitempty"`
 IssuedAt int64 `json:"issuedAt,omitempty"`
 ExpiresAt int64 `json:"expiresAt,omitempty"`
}
func field(s string)string{return strconv.Itoa(len(s))+":"+s}
func decisionMessage(d Decision)[]byte{
 return []byte(decisionDomain+field(d.ID)+field(d.Tenant)+strconv.FormatBool(d.Approve)+field(d.Nonce)+field(d.KeyID)+strconv.FormatInt(d.IssuedAt,10)+":"+strconv.FormatInt(d.ExpiresAt,10))
}
// DecisionMessage is the canonical signed byte representation of an approval.\nfunc DecisionMessage(d Decision)[]byte{return decisionMessage(d)}\nfunc SignDecision(private ed25519.PrivateKey,d Decision)[]byte{
 return ed25519.Sign(private,decisionMessage(d))
}
type challenge struct{ id string; expires time.Time }
type Handler struct{
 Manager *pairing.Manager
 Admins map[string]ed25519.PublicKey // legacy prototype: tenant -> trusted admin key
 Trust *admintrust.Store
 mu sync.Mutex
 challenges map[string]challenge
 decisions map[string]bool
 now func()time.Time
}
func New(manager *pairing.Manager,admins map[string]ed25519.PublicKey,now func()time.Time)http.Handler{
 return newHandler(manager,admins,nil,now)
}
// NewWithTrust uses persisted, revocable tenant-scoped administrator keys.
// Provisioning remains a trusted operator-only action, not an HTTP route.
func NewWithTrust(manager *pairing.Manager,store *admintrust.Store,now func()time.Time)http.Handler{
 return newHandler(manager,nil,store,now)
}
func newHandler(manager *pairing.Manager,admins map[string]ed25519.PublicKey,store *admintrust.Store,now func()time.Time)http.Handler{
 if now==nil{now=time.Now}
 keys:=map[string]ed25519.PublicKey{}
 for k,v:=range admins{keys[k]=append(ed25519.PublicKey(nil),v...)}
 h:=&Handler{Manager:manager,Admins:keys,Trust:store,now:now,challenges:map[string]challenge{},decisions:map[string]bool{}}
 mux:=http.NewServeMux()
 mux.HandleFunc("/v1/pair/admin/decide",h.decide)
 mux.HandleFunc("/v1/pair/agent/challenge",h.challenge)
 mux.HandleFunc("/v1/pair/agent/handoff",h.handoff)
 mux.HandleFunc("/v1/pair/agent/enroll",h.enroll)
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("X-Content-Type-Options","nosniff")
  if r.TLS==nil{http.Error(w,"TLS required",http.StatusUpgradeRequired);return}
  // This protocol is for native clients, not browser-origin requests.
  if r.Header.Get("Origin")!=""{http.Error(w,"browser origin not allowed",http.StatusForbidden);return}
  if h.Manager==nil{http.Error(w,"unavailable",http.StatusServiceUnavailable);return}
  mux.ServeHTTP(w,r)
 })
}
func parse(w http.ResponseWriter,r *http.Request,out any)bool{
 if r.Method!=http.MethodPost{http.Error(w,"method not allowed",405);return false}
 if r.Header.Get("Content-Type")!="application/json"{http.Error(w,"JSON required",415);return false}
 d:=json.NewDecoder(http.MaxBytesReader(w,r.Body,2048))
 d.DisallowUnknownFields()
 if d.Decode(out)!=nil{http.Error(w,"invalid body",400);return false}
 var extra any
 if d.Decode(&extra)!=io.EOF{http.Error(w,"trailing body",400);return false}
 return true
}
func answer(w http.ResponseWriter,value any){
 w.Header().Set("Content-Type","application/json")
 _=json.NewEncoder(w).Encode(value)
}
func denied(w http.ResponseWriter){http.Error(w,"denied",http.StatusForbidden)}
func nonce()(string,error){
 var buf [32]byte
 if _,err:=rand.Read(buf[:]);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(buf[:]),nil
}
func validNonce(n string)bool{
 b,e:=base64.RawURLEncoding.DecodeString(n)
 return e==nil&&len(b)==32
}
func(h *Handler)decide(w http.ResponseWriter,r *http.Request){
 var request struct{
  Decision
  Signature string `json:"signature"`
 }
 if !parse(w,r,&request){return}
 d:=request.Decision
 signature,e:=base64.RawURLEncoding.DecodeString(request.Signature)
 if e!=nil||len(signature)!=ed25519.SignatureSize||!validNonce(d.Nonce)||len(d.ID)>128||d.ID==""{denied(w);return}
 if h.Trust!=nil{
  // Freshness is signed; prevent indefinitely valid offline approvals.
  now:=h.now().Unix()
  if d.KeyID==""||d.IssuedAt>now+30||d.IssuedAt<now-120||d.ExpiresAt<=now||d.ExpiresAt>d.IssuedAt+120{denied(w);return}
  if err:=h.Trust.VerifyAndConsume(d.Tenant,d.KeyID,d.Nonce,decisionMessage(d),signature);err!=nil{denied(w);return}
 }else{
  // Legacy in-memory test configuration. Never deploy or expose publicly.
  pub,ok:=h.Admins[d.Tenant]
  if !ok||len(pub)!=ed25519.PublicKeySize||!ed25519.Verify(pub,decisionMessage(d),signature){denied(w);return}
  h.mu.Lock()
  if len(h.decisions)>=4096||h.decisions[d.Tenant+":"+d.Nonce]{h.mu.Unlock();denied(w);return}
  h.decisions[d.Tenant+":"+d.Nonce]=true
  h.mu.Unlock()
 }
 req,e:=h.Manager.Decide(d.ID,d.Tenant,true,d.Approve)
 if e!=nil{denied(w);return}
 answer(w,map[string]string{"state":string(req.State)})
}
func(h *Handler)challenge(w http.ResponseWriter,r *http.Request){
 var p struct{ID string `json:"id"`}
 if !parse(w,r,&p){return}
 if len(p.ID)==0||len(p.ID)>128{denied(w);return}
 n,e:=nonce();if e!=nil{http.Error(w,"unavailable",503);return}
 h.mu.Lock()
 if len(h.challenges)>=1024{h.mu.Unlock();http.Error(w,"unavailable",503);return}
 h.challenges[n]=challenge{id:p.ID,expires:h.now().Add(30*time.Second)}
 h.mu.Unlock()
 answer(w,map[string]string{"nonce":n})
}
func(h *Handler)handoff(w http.ResponseWriter,r *http.Request){
 var p struct{ID string `json:"id"`;Nonce string `json:"nonce"`;Signature string `json:"signature"`}
 if !parse(w,r,&p){return}
 sig,e:=base64.RawURLEncoding.DecodeString(p.Signature)
 if e!=nil||len(sig)!=ed25519.SignatureSize||!validNonce(p.Nonce){denied(w);return}
 h.mu.Lock()
 challenge,ok:=h.challenges[p.Nonce]
 if ok{delete(h.challenges,p.Nonce)}
 valid:=ok&&challenge.id==p.ID&&h.now().Before(challenge.expires)
 h.mu.Unlock()
 if !valid{denied(w);return}
 inv,e:=h.Manager.InvitationWithChallenge(p.ID,p.Nonce,sig)
 if e!=nil{denied(w);return}
 answer(w,map[string]string{"invitation":inv})
}
func(h *Handler)enroll(w http.ResponseWriter,r *http.Request){
 var p struct{ID string `json:"id"`;Proof string `json:"proof"`}
 if !parse(w,r,&p){return}
 sig,e:=base64.RawURLEncoding.DecodeString(p.Proof)
 if e!=nil||len(sig)!=ed25519.SignatureSize||len(p.ID)==0||len(p.ID)>128{denied(w);return}
 agent,e:=h.Manager.Redeem(p.ID,sig)
 if e!=nil{denied(w);return}
 answer(w,map[string]string{"agentId":agent.ID,"tenantId":agent.TenantID,"siteId":agent.SiteID})
}
// AgentProof ties the second enrollment step to the original invitation.
// The invitation must never be logged or exposed to a web page.
func AgentProof(private ed25519.PrivateKey,invitation string)[]byte{
 return identity.SignEnrollment(private,invitation)
}
