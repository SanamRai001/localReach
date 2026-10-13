package agentremote

import (
 "bufio"
 "bytes"
 "context"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "time"

 "github.com/SanamRai001/localReach/internal/pgpairing"
)
var ErrSessionClosed=errors.New("authenticated agent stream ended")
type streamFrame struct{
 Type string `json:"type"`
 AgentID string `json:"agentId"`
 Capabilities string `json:"capabilities"`
}
// StreamSession uses the OS-native signer for one-use Ed25519 proof, then
// keeps an outbound-only TLS response stream open. onHeartbeat(true) means
// an authenticated frame was just received (NOT device authorization).
// A dead/stalled stream always triggers onHeartbeat(false) before return.
func(c Client)StreamSession(ctx context.Context,org string,s Signer,onHeartbeat func(bool))error{
 if onHeartbeat==nil||!validSigner(s)||org==""{return ErrDenied}
 defer onHeartbeat(false)
 var challenge struct{AgentID string `json:"agentId"`;Nonce string `json:"nonce"`}
 if err:=c.post(ctx,"/v1/agent/resume-challenge",map[string]string{
  "organization":org,"publicKey":base64.RawURLEncoding.EncodeToString(s.PublicKey()),
 },&challenge);err!=nil||challenge.AgentID==""{return ErrDenied}
 proof,err:=s.SignMessage(pgpairing.ResumeMessage(org,challenge.AgentID,challenge.Nonce))
 if err!=nil||len(proof)!=64{return ErrDenied}
 body,err:=json.Marshal(map[string]string{
  "organization":org,"agentId":challenge.AgentID,"nonce":challenge.Nonce,
  "signature":base64.RawURLEncoding.EncodeToString(proof),
 })
 if err!=nil||len(body)>4096{return ErrDenied}
 streamCtx,cancel:=context.WithCancel(ctx)
 defer cancel()
 // No request-level 10-second timeout: the stream must survive beyond it.
 // A resettable watchdog cancels stalls even when no further bytes arrive.
 watchdog:=time.AfterFunc(12*time.Second,cancel)
 defer watchdog.Stop()
 reset:=func(){watchdog.Reset(12*time.Second)}
 req,err:=http.NewRequestWithContext(streamCtx,http.MethodPost,c.BaseURL+"/v1/agent/session",bytes.NewReader(body))
 if err!=nil{return ErrDenied}
 req.Header.Set("Content-Type","application/json")
 client:=*c.HTTP
 client.Timeout=0
 client.CheckRedirect=func(*http.Request,[]*http.Request)error{return http.ErrUseLastResponse}
 resp,err:=client.Do(req)
 if err!=nil{return ErrDenied}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK||resp.Header.Get("Content-Type")!="application/x-ndjson"{return ErrDenied}
 scanner:=bufio.NewScanner(io.LimitReader(resp.Body,1<<20))
 scanner.Buffer(make([]byte,0,256),2048)
 first:=true
 for scanner.Scan(){
  reset()
  var event streamFrame
  if err=json.Unmarshal(scanner.Bytes(),&event);err!=nil{return ErrDenied}
  if event.AgentID!=challenge.AgentID||event.Capabilities!="NONE"{return ErrDenied}
  switch event.Type{
  case "connected":
   if !first{return ErrDenied}
   first=false
   onHeartbeat(true)
  case "heartbeat":
   if first{return ErrDenied}
   onHeartbeat(true)
  case "closed":
   return ErrSessionClosed
  default:return ErrDenied
  }
 }
 // Unexpected EOF is never success; only a live, healthy response is ONLINE.
 if first{return ErrDenied}
 return ErrSessionClosed
}
