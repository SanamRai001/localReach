// Package adminremote provides a native-only administrator client.
// Its signer holds a separately provisioned OS-protected administrator key.
// No private key, bearer session, or invitation secret is persisted by this package.
package adminremote

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "net/url"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/pgauth"
 "github.com/SanamRai001/localReach/internal/pgpairing"
)
var ErrDenied=errors.New("administrator operation denied")
type Signer interface{
 PublicKey()ed25519.PublicKey
 SignMessage([]byte)([]byte,error)
}
type Client struct{BaseURL string; HTTP *http.Client}
func New(base string,client *http.Client)(Client,error){
 u,err:=url.Parse(base)
 if err!=nil||u.Scheme!="https"||u.Host==""||u.User!=nil||
 u.Path!=""||u.RawQuery!=""||u.Fragment!=""||strings.HasSuffix(base,"/")||client==nil{return Client{},ErrDenied}
 return Client{BaseURL:base,HTTP:client},nil
}
func(c Client)post(ctx context.Context,path,token string,payload any,out any)error{
 if c.HTTP==nil||c.BaseURL==""{return ErrDenied}
 input,err:=json.Marshal(payload)
 if err!=nil||len(input)>4096{return ErrDenied}
 req,err:=http.NewRequestWithContext(ctx,"POST",c.BaseURL+path,bytes.NewReader(input))
 if err!=nil{return ErrDenied}
 req.Header.Set("Content-Type","application/json")
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 client:=*c.HTTP
 client.CheckRedirect=func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}
 if client.Timeout==0||client.Timeout>10*time.Second{client.Timeout=10*time.Second}
 resp,err:=client.Do(req)
 if err!=nil{return ErrDenied}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK{return ErrDenied}
 decoder:=json.NewDecoder(io.LimitReader(resp.Body,4096))
 decoder.DisallowUnknownFields()
 if err=decoder.Decode(out);err!=nil{return ErrDenied}
 var unexpected any
 if decoder.Decode(&unexpected)!=io.EOF{return ErrDenied}
 return nil
}
func validSigner(s Signer)bool{return s!=nil&&len(s.PublicKey())==ed25519.PublicKeySize}
func validScope(org,admin string)bool{return org!=""&&admin!=""&&len(org)<=128&&len(admin)<=128}
func(c Client)Login(ctx context.Context,org,admin string,s Signer)(string,error){
 if !validScope(org,admin)||!validSigner(s){return "",ErrDenied}
 var challenge struct{Nonce string `json:"nonce"`}
 if err:=c.post(ctx,"/v1/control/login-challenge","",map[string]string{
  "organization":org,"adminId":admin,
 },&challenge);err!=nil{return "",ErrDenied}
 decoded,err:=base64.RawURLEncoding.DecodeString(challenge.Nonce)
 if err!=nil||len(decoded)!=32{return "",ErrDenied}
 proof,err:=s.SignMessage(pgauth.ChallengeMessage(org,admin,challenge.Nonce))
 if err!=nil||len(proof)!=ed25519.SignatureSize{return "",ErrDenied}
 var response struct{Token string `json:"token"`;ExpiresInSeconds string `json:"expiresInSeconds"`}
 if err=c.post(ctx,"/v1/control/login","",map[string]string{
  "organization":org,"adminId":admin,"nonce":challenge.Nonce,
  "signature":base64.RawURLEncoding.EncodeToString(proof),
 },&response);err!=nil{return "",ErrDenied}
 raw,err:=base64.RawURLEncoding.DecodeString(response.Token)
 if err!=nil||len(raw)!=32||response.ExpiresInSeconds!="300"{return "",ErrDenied}
 return response.Token,nil
}
type Invitation struct{Token string `json:"token"`; Site string `json:"site"`; ExpiresAt string `json:"expiresAt"`; Scope string `json:"scope"`}
func(c Client)Invite(ctx context.Context,org,site,session string)(Invitation,error){
 if org==""||site==""||session==""{return Invitation{},ErrDenied}
 var response Invitation
 if err:=c.post(ctx,"/v1/control/invite",session,map[string]string{
  "organization":org,"site":site,
 },&response);err!=nil{return Invitation{},ErrDenied}
 raw,err:=base64.RawURLEncoding.DecodeString(response.Token)
 if err!=nil||len(raw)!=32||response.Scope!="PENDING_REQUEST_ONLY"||response.Site!=site{return Invitation{},ErrDenied}
 return response,nil
}
type Review struct{
 RequestID string `json:"requestId"`
 Site string `json:"site"`
 State string `json:"state"`
 Fingerprint string `json:"fingerprint"`
 ExpiresAt time.Time `json:"expiresAt"`
}
func(c Client)Review(ctx context.Context,org,requestID,session string)(Review,error){
 if org==""||requestID==""||session==""{return Review{},ErrDenied}
 var response Review
 if err:=c.post(ctx,"/v1/control/review",session,map[string]string{
  "organization":org,"requestId":requestID,
 },&response);err!=nil{return Review{},ErrDenied}
 decoded,err:=hex.DecodeString(response.Fingerprint)
 if err!=nil||len(decoded)!=32||response.RequestID!=requestID{return Review{},ErrDenied}
 return response,nil
}
// ApproveReviewed requires the *operator-provided* full SHA-256 public-key
// fingerprint. It re-reads server state just before constructing the signed
// admin decision. Caller must first compare the fingerprint out of band.
func(c Client)ApproveReviewed(ctx context.Context,org,admin,requestID,session,confirmedFingerprint string,s Signer)error{
 if !validScope(org,admin)||!validSigner(s)||session==""||
 len(confirmedFingerprint)!=64{return ErrDenied}
 review,err:=c.Review(ctx,org,requestID,session)
 if err!=nil||review.Fingerprint!=confirmedFingerprint||
 review.State!="PENDING"||!time.Now().Before(review.ExpiresAt){return ErrDenied}
 raw:=make([]byte,32)
 if _,err=rand.Read(raw);err!=nil{return ErrDenied}
 now:=time.Now().Unix()
 decision:=pgpairing.AdminDecision{
  Organization:org,RequestID:requestID,AdminID:admin,
  Action:pgpairing.Approve,Nonce:base64.RawURLEncoding.EncodeToString(raw),
  IssuedAt:now,ExpiresAt:now+60,
 }
 proof,err:=s.SignMessage(pgpairing.DecisionMessage(decision))
 if err!=nil||len(proof)!=ed25519.SignatureSize{return ErrDenied}
 var response struct{State string `json:"state"`}
 if err=c.post(ctx,"/v1/control/decide",session,map[string]any{
  "organization":decision.Organization,"requestId":decision.RequestID,
  "adminId":decision.AdminID,"action":decision.Action,
  "nonce":decision.Nonce,"issuedAt":decision.IssuedAt,
  "expiresAt":decision.ExpiresAt,
  "signature":base64.RawURLEncoding.EncodeToString(proof),
 },&response);err!=nil||response.State!="APPROVED"{return ErrDenied}
 return nil
}
