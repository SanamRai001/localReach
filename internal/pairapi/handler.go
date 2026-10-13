// Package pairapi is an HTTPS-only pairing *handler* for controlled tests.
// It does not bind a listener, issue device permissions, or authenticate users
// via a browser. Operators must supply real TLS termination and abuse controls
// before considering any deployment.
package pairapi

import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/pgauth"
 "github.com/SanamRai001/localReach/internal/pgpairing"
)
const bodyLimit=4096
type Auth interface{Authorize(context.Context,string,string,...string)(pgauth.Actor,error)}
type Pairing interface{
 Propose(context.Context,string,string,ed25519.PublicKey)(pgpairing.Record,error)
 Decide(context.Context,pgpairing.AdminDecision,[]byte)(pgpairing.Record,error)
 Challenge(context.Context,string,string)(string,error)
 Enroll(context.Context,string,string,string,[]byte)(pgpairing.Record,error)
 ResolveIdentity(context.Context,string,ed25519.PublicKey)(string,error)
 BeginResume(context.Context,string,string)(string,error)
 VerifyResume(context.Context,string,string,string,[]byte)error
 IssueInvitation(context.Context,string,string,string)(pgpairing.Invitation,error)
 RedeemInvitation(context.Context,string,string,ed25519.PublicKey)(pgpairing.Record,error)
 ReviewRequest(context.Context,string,string)(pgpairing.Review,error)
}
type Handler struct{Auth Auth;Pairing Pairing;Guard *Guard;Admission Admission;Sessions Sessions;ReadPolicy ReadGrantPolicy;SessionInterval time.Duration}
type proposal struct {
 Organization string `json:"organization"`
 Site string `json:"site"`
 PublicKey string `json:"publicKey"`
}
type signedDecision struct {
 Organization string `json:"organization"`
 RequestID string `json:"requestId"`
 AdminID string `json:"adminId"`
 Action pgpairing.Action `json:"action"`
 Nonce string `json:"nonce"`
 IssuedAt int64 `json:"issuedAt"`
 ExpiresAt int64 `json:"expiresAt"`
 Signature string `json:"signature"`
}
type invitationRequest struct{
 Organization string `json:"organization"`
 Site string `json:"site"`
 Token string `json:"token"`
 PublicKey string `json:"publicKey"`
}
type reviewRequest struct{
 Organization string `json:"organization"`
 RequestID string `json:"requestId"`
}
type loginRequest struct{
 Organization string `json:"organization"`
 AdminID string `json:"adminId"`
 Nonce string `json:"nonce"`
 Signature string `json:"signature"`
}
type loginAuth interface{
 Challenge(context.Context,string,string)(string,error)
 Authenticate(context.Context,string,string,string,[]byte)(string,error)
}
type agentRequest struct{
 Organization string `json:"organization"`
 RequestID string `json:"requestId"`
 AgentID string `json:"agentId"`
 Nonce string `json:"nonce"`
 PublicKey string `json:"publicKey"`
 Signature string `json:"signature"`
}
func decode(w http.ResponseWriter,r *http.Request,v any)bool{
 if r.Method!=http.MethodPost{http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return false}
 if r.Header.Get("Content-Type")!="application/json"{http.Error(w,"JSON required",http.StatusUnsupportedMediaType);return false}
 dec:=json.NewDecoder(http.MaxBytesReader(w,r.Body,bodyLimit))
 dec.DisallowUnknownFields()
 if err:=dec.Decode(v);err!=nil{http.Error(w,"invalid body",http.StatusBadRequest);return false}
 var extra any
 if dec.Decode(&extra)!=io.EOF{http.Error(w,"trailing body",http.StatusBadRequest);return false}
 return true
}
func denied(w http.ResponseWriter){http.Error(w,"denied",http.StatusForbidden)}
func respond(w http.ResponseWriter,v any){
 w.Header().Set("Content-Type","application/json")
 _=json.NewEncoder(w).Encode(v)
}
func decoded(raw string,length int)([]byte,error){
 b,err:=base64.RawURLEncoding.DecodeString(raw)
 if err!=nil||len(b)!=length{return nil,errors.New("invalid proof")}
 return b,nil
}
func validToken(header string)string{
 const prefix="Bearer "
 if !strings.HasPrefix(header,prefix)||strings.ContainsAny(header,"\r\n") {return ""}
 return strings.TrimPrefix(header,prefix)
}
func(h Handler)admin(w http.ResponseWriter,r *http.Request,org string)(pgauth.Actor,bool){
 if h.Auth==nil||org==""{denied(w);return pgauth.Actor{},false}
 token:=validToken(r.Header.Get("Authorization"))
 if token==""{denied(w);return pgauth.Actor{},false}
 actor,err:=h.Auth.Authorize(r.Context(),org,token,"OWNER","ADMIN")
 if err!=nil{denied(w);return pgauth.Actor{},false}
 return actor,true
}
func(h Handler)ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("X-Content-Type-Options","nosniff")
 w.Header().Set("Referrer-Policy","no-referrer")
 w.Header().Set("Content-Security-Policy","default-src 'none'; frame-ancestors 'none'")
 // No public listener is provided. A reverse proxy forwarding plaintext is
 // deliberately NOT accepted; use direct TLS during controlled verification.
 if r.TLS==nil{http.Error(w,"TLS required",http.StatusUpgradeRequired);return}
 // Native clients only. Never accept browser ambient credentials/CORS.
 if r.Header.Get("Origin")!=""||r.Header.Get("Cookie")!=""{denied(w);return}
 if r.Method!=http.MethodPost{http.Error(w,"method not allowed",http.StatusMethodNotAllowed);return}
 if h.Pairing==nil{http.Error(w,"unavailable",http.StatusServiceUnavailable);return}
 if h.Admission!=nil&&!h.Admission.Allow(r.Context(),r.RemoteAddr,r.URL.Path){http.Error(w,"request limit",http.StatusTooManyRequests);return}
 switch r.URL.Path{
 case "/v1/control/login-challenge":h.loginChallenge(w,r)
 case "/v1/control/login":h.login(w,r)
 case "/v1/control/invite":h.invite(w,r)
 case "/v1/control/review":h.review(w,r)
 case "/v1/agent/request-invite":h.redeemInvite(w,r)
 case "/v1/control/propose": h.propose(w,r)
 case "/v1/control/decide":h.decide(w,r)
 case "/v1/agent/enrollment-challenge":h.challenge(w,r)
 case "/v1/agent/enroll":h.enroll(w,r)
 case "/v1/agent/resume-challenge":h.resumeChallenge(w,r)
 case "/v1/agent/resume-verify":h.resumeVerify(w,r)
 case "/v1/agent/session":h.streamSession(w,r)
 default:http.NotFound(w,r)
 }
}
func(h Handler)propose(w http.ResponseWriter,r *http.Request){
 var p proposal
 if !decode(w,r,&p){return}
 if _,ok:=h.admin(w,r,p.Organization);!ok{return}
 public,err:=decoded(p.PublicKey,ed25519.PublicKeySize)
 if err!=nil{denied(w);return}
 record,err:=h.Pairing.Propose(r.Context(),p.Organization,p.Site,ed25519.PublicKey(public))
 if err!=nil{denied(w);return}
 respond(w,map[string]any{"requestId":record.RequestID,"state":record.State})
}
func(h Handler)decide(w http.ResponseWriter,r *http.Request){
 var d signedDecision
 if !decode(w,r,&d){return}
 actor,ok:=h.admin(w,r,d.Organization)
 if !ok{return}
 // An authenticated token must belong to the *signing administrator*.
 if actor.AdminID!=d.AdminID{denied(w);return}
 signature,err:=decoded(d.Signature,ed25519.SignatureSize)
 if err!=nil{denied(w);return}
 record,err:=h.Pairing.Decide(r.Context(),pgpairing.AdminDecision{
  Organization:d.Organization,RequestID:d.RequestID,AdminID:d.AdminID,Action:d.Action,
  Nonce:d.Nonce,IssuedAt:d.IssuedAt,ExpiresAt:d.ExpiresAt,
 },signature)
 if err!=nil{denied(w);return}
 respond(w,map[string]string{"state":record.State})
}
func(h Handler)challenge(w http.ResponseWriter,r *http.Request){
 var p agentRequest
 if !decode(w,r,&p){return}
 nonce,err:=h.Pairing.Challenge(r.Context(),p.Organization,p.RequestID)
 if err!=nil{denied(w);return}
 respond(w,map[string]string{"nonce":nonce})
}
func(h Handler)enroll(w http.ResponseWriter,r *http.Request){
 var p agentRequest
 if !decode(w,r,&p){return}
 signature,err:=decoded(p.Signature,ed25519.SignatureSize)
 if err!=nil{denied(w);return}
 record,err:=h.Pairing.Enroll(r.Context(),p.Organization,p.RequestID,p.Nonce,signature)
 if err!=nil||!record.AgentID.Valid{denied(w);return}
 respond(w,map[string]string{"agentId":record.AgentID.String,"state":record.State})
}
func(h Handler)resumeChallenge(w http.ResponseWriter,r *http.Request){
 var p agentRequest
 if !decode(w,r,&p){return}
 public,err:=decoded(p.PublicKey,ed25519.PublicKeySize)
 if err!=nil{denied(w);return}
 agentID,err:=h.Pairing.ResolveIdentity(r.Context(),p.Organization,ed25519.PublicKey(public))
 if err!=nil{denied(w);return}
 nonce,err:=h.Pairing.BeginResume(r.Context(),p.Organization,agentID)
 if err!=nil{denied(w);return}
 respond(w,map[string]string{"agentId":agentID,"nonce":nonce})
}
func(h Handler)resumeVerify(w http.ResponseWriter,r *http.Request){
 var p agentRequest
 if !decode(w,r,&p){return}
 signature,err:=decoded(p.Signature,ed25519.SignatureSize)
 if err!=nil{denied(w);return}
 if err:=h.Pairing.VerifyResume(r.Context(),p.Organization,p.AgentID,p.Nonce,signature);err!=nil{denied(w);return}
 respond(w,map[string]string{"result":"IDENTITY_VERIFIED","connection":"OFFLINE","capabilities":"NONE"})
}
// ServerConfig documents strict direct TLS expectations for a future
// operator-managed process; Handler never uses ListenAndServe itself.
type ServerConfig struct{ReadHeaderTimeout,ReadTimeout,WriteTimeout time.Duration}
func RecommendedTimeouts()ServerConfig{return ServerConfig{
 ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,WriteTimeout:10*time.Second,
}}

func(h Handler)limited(w http.ResponseWriter,r *http.Request)bool{
 if h.Admission!=nil{return true} // Already admitted before dispatch.
 if h.Guard==nil||!h.Guard.Allow(r){http.Error(w,"request limit",http.StatusTooManyRequests);return false}
 return true
}
// These login routes are for native clients with a PREPROVISIONED admin key,
// not browser password login or self-registration. Admission is fail closed.
func(h Handler)loginChallenge(w http.ResponseWriter,r *http.Request){
 if !h.limited(w,r){return}
 var p loginRequest
 if !decode(w,r,&p){return}
 auth,ok:=h.Auth.(loginAuth)
 if !ok{denied(w);return}
 nonce,err:=auth.Challenge(r.Context(),p.Organization,p.AdminID)
 if err!=nil{denied(w);return}
 respond(w,map[string]string{"nonce":nonce})
}
func(h Handler)login(w http.ResponseWriter,r *http.Request){
 if !h.limited(w,r){return}
 var p loginRequest
 if !decode(w,r,&p){return}
 auth,ok:=h.Auth.(loginAuth)
 if !ok{denied(w);return}
 signature,err:=decoded(p.Signature,ed25519.SignatureSize)
 if err!=nil{denied(w);return}
 token,err:=auth.Authenticate(r.Context(),p.Organization,p.AdminID,p.Nonce,signature)
 if err!=nil{denied(w);return}
 respond(w,map[string]string{"token":token,"expiresInSeconds":"300"})
}
func(h Handler)invite(w http.ResponseWriter,r *http.Request){
 if !h.limited(w,r){return}
 var p invitationRequest
 if !decode(w,r,&p){return}
 admin,ok:=h.admin(w,r,p.Organization)
 if !ok{return}
 invitation,err:=h.Pairing.IssueInvitation(r.Context(),p.Organization,p.Site,admin.AdminID)
 if err!=nil{denied(w);return}
 respond(w,map[string]string{
  "token":invitation.Token,"site":invitation.Site,
  "expiresAt":invitation.ExpiresAt.UTC().Format(time.RFC3339),
  "scope":"PENDING_REQUEST_ONLY",
 })
}
func(h Handler)redeemInvite(w http.ResponseWriter,r *http.Request){
 if !h.limited(w,r){return}
 var p invitationRequest
 if !decode(w,r,&p){return}
 public,err:=decoded(p.PublicKey,ed25519.PublicKeySize)
 if err!=nil{denied(w);return}
 record,err:=h.Pairing.RedeemInvitation(r.Context(),p.Organization,p.Token,ed25519.PublicKey(public))
 if err!=nil{denied(w);return}
 respond(w,map[string]string{"requestId":record.RequestID,"state":record.State})
}

func(h Handler)review(w http.ResponseWriter,r *http.Request){
 var p reviewRequest
 if !decode(w,r,&p){return}
 if _,ok:=h.admin(w,r,p.Organization);!ok{return}
 value,err:=h.Pairing.ReviewRequest(r.Context(),p.Organization,p.RequestID)
 if err!=nil{denied(w);return}
 respond(w,map[string]any{
  "requestId":value.RequestID,"site":value.Site,
  "state":value.State,"fingerprint":value.Fingerprint,
  "expiresAt":value.ExpiresAt.UTC().Format(time.RFC3339),
 })
}
