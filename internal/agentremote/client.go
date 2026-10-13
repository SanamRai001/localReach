// Package agentremote is a native-client HTTPS pairing adapter. It never
// holds database credentials or exposes the OS-protected private signing key.
package agentremote

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "net/url"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/pgpairing"
)
var ErrDenied=errors.New("remote pairing denied")
type Signer interface{
 PublicKey()ed25519.PublicKey
 SignMessage([]byte)([]byte,error)
}
type Client struct{
 BaseURL string
 HTTP *http.Client
}
// New requires HTTPS and a caller-supplied TLS-validating client. Certificates
// must be authenticated by the client's TLS trust store, NEVER insecurely
// skipped. This is not a discovery mechanism for arbitrary URLs.
func New(base string,httpClient *http.Client)(Client,error){
 parsed,err:=url.Parse(base)
 if err!=nil||parsed.Scheme!="https"||parsed.Host==""||parsed.User!=nil||parsed.RawQuery!=""||parsed.Fragment!=""||parsed.Path!=""||strings.HasSuffix(base,"/"){return Client{},ErrDenied}
 if httpClient==nil{return Client{},ErrDenied}
 return Client{BaseURL:base,HTTP:httpClient},nil
}
func(c Client)post(ctx context.Context,path string,input any,result any)error{
 if c.BaseURL==""||c.HTTP==nil{return ErrDenied}
 data,err:=json.Marshal(input)
 if err!=nil||len(data)>4096{return ErrDenied}
 req,err:=http.NewRequestWithContext(ctx,"POST",c.BaseURL+path,bytes.NewReader(data))
 if err!=nil{return ErrDenied}
 req.Header.Set("Content-Type","application/json")
 // A redirect must not forward pairing material or switch to plain HTTP.
 client:=*c.HTTP
 client.CheckRedirect=func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}
 if client.Timeout==0||client.Timeout>10*time.Second{client.Timeout=10*time.Second}
 response,err:=client.Do(req)
 if err!=nil{return ErrDenied}
 defer response.Body.Close()
 if response.StatusCode!=http.StatusOK{return ErrDenied}
 decoder:=json.NewDecoder(io.LimitReader(response.Body,4096))
 decoder.DisallowUnknownFields()
 if err=decoder.Decode(result);err!=nil{return ErrDenied}
 var extra any
 if decoder.Decode(&extra)!=io.EOF{return ErrDenied}
 return nil
}
func validSigner(s Signer)bool{return s!=nil&&len(s.PublicKey())==ed25519.PublicKeySize}
// FinishEnrollment requires a separately admin-approved pairing request and
// a previously created native signing identity. No new key is generated.
func(c Client)FinishEnrollment(ctx context.Context,org,requestID string,s Signer)(string,error){
 if !validSigner(s)||org==""||requestID==""{return "",ErrDenied}
 var challenge struct{Nonce string `json:"nonce"`}
 if err:=c.post(ctx,"/v1/agent/enrollment-challenge",map[string]string{"organization":org,"requestId":requestID},&challenge);err!=nil{return "",ErrDenied}
 proof,err:=s.SignMessage(pgpairing.EnrollmentMessage(org,requestID,challenge.Nonce))
 if err!=nil{return "",ErrDenied}
 var response struct{AgentID string `json:"agentId"`;State string `json:"state"`}
 if err=c.post(ctx,"/v1/agent/enroll",map[string]string{
  "organization":org,"requestId":requestID,"nonce":challenge.Nonce,
  "signature":base64.RawURLEncoding.EncodeToString(proof),
 },&response);err!=nil||response.State!="ENROLLED"||response.AgentID==""{return "",ErrDenied}
 return response.AgentID,nil
}
// VerifyIdentity proves native possession after restart but NEVER claims
// online connectivity or device permission.
func(c Client)VerifyIdentity(ctx context.Context,org string,s Signer)(string,error){
 if !validSigner(s)||org==""{return "",ErrDenied}
 var challenge struct{AgentID string `json:"agentId"`;Nonce string `json:"nonce"`}
 if err:=c.post(ctx,"/v1/agent/resume-challenge",map[string]string{
  "organization":org,"publicKey":base64.RawURLEncoding.EncodeToString(s.PublicKey()),
 },&challenge);err!=nil||challenge.AgentID==""{return "",ErrDenied}
 proof,err:=s.SignMessage(pgpairing.ResumeMessage(org,challenge.AgentID,challenge.Nonce))
 if err!=nil{return "",ErrDenied}
 var state struct{Result string `json:"result"`;Connection string `json:"connection"`;Capabilities string `json:"capabilities"`}
 if err=c.post(ctx,"/v1/agent/resume-verify",map[string]string{
  "organization":org,"agentId":challenge.AgentID,"nonce":challenge.Nonce,
  "signature":base64.RawURLEncoding.EncodeToString(proof),
 },&state);err!=nil||state.Result!="IDENTITY_VERIFIED"||state.Connection!="OFFLINE"||state.Capabilities!="NONE"{return "",ErrDenied}
 return challenge.AgentID,nil
}

// RequestInvitation submits an existing native *public key* with a short-lived
// admin-issued secret. The token only authorizes a PENDING proposal. It never
// approves the pairing, authenticates as an admin, or grants device access.
// The token must be supplied from a protected UI/stdin, not a CLI argument.
func(c Client)RequestInvitation(ctx context.Context,org,token string,s Signer)(string,error){
 if !validSigner(s)||org==""||token==""{return "",ErrDenied}
 var response struct{
  RequestID string `json:"requestId"`
  State string `json:"state"`
 }
 if err:=c.post(ctx,"/v1/agent/request-invite",map[string]string{
  "organization":org,"token":token,
  "publicKey":base64.RawURLEncoding.EncodeToString(s.PublicKey()),
 },&response);err!=nil||response.RequestID==""||response.State!="PENDING"{return "",ErrDenied}
 return response.RequestID,nil
}
