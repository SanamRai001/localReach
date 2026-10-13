// Package integration exercises an authenticated TLS control handshake together
// with an agent-owned crash-aware mock operation journal. No remote device API
// or WAN listener is provided.
package integration

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "net/http"
 "strings"

 "github.com/SanamRai001/localReach/internal/journal"
 "github.com/SanamRai001/localReach/internal/session"
)

type Client struct {
 HTTP *http.Client
 BaseURL string
 AgentID string
 PrivateKey ed25519.PrivateKey
}
func (c Client) post(ctx context.Context,path string,payload any,token string,out any)error{
 if len(c.PrivateKey)!=ed25519.PrivateKeySize{return errors.New("invalid agent identity")}
 if !strings.HasPrefix(c.BaseURL,"https://"){return errors.New("TLS required")}
 data,err:=json.Marshal(payload);if err!=nil{return err}
 req,err:=http.NewRequestWithContext(ctx,http.MethodPost,c.BaseURL+path,bytes.NewReader(data));if err!=nil{return err}
 req.Header.Set("Content-Type","application/json")
 req.Header.Set("X-LocalReach-Agent-ID",c.AgentID)
 if token!=""{req.Header.Set("Authorization","Bearer "+token)}
 client:=c.HTTP
 if client==nil{client=http.DefaultClient}
 resp,err:=client.Do(req);if err!=nil{return err}
 defer resp.Body.Close()
 if resp.StatusCode!=http.StatusOK{return fmt.Errorf("gateway rejected request: %d",resp.StatusCode)}
 if out==nil{return nil}
 dec:=json.NewDecoder(io.LimitReader(resp.Body,4096))
 return dec.Decode(out)
}
// Handshake proves possession of the agent key and returns a short-lived session.
// Session binding to TLS client identity remains a production release blocker.
func (c Client) Handshake(ctx context.Context)(string,error){
 var challenge struct{Challenge string `json:"challenge"`}
 if err:=c.post(ctx,"/v1/agent/challenge",map[string]string{"agentId":c.AgentID},"",&challenge);err!=nil{return "",err}
 signature:=base64.RawURLEncoding.EncodeToString(session.Sign(c.PrivateKey,challenge.Challenge))
 var result struct{SessionToken string `json:"sessionToken"`}
 err:=c.post(ctx,"/v1/agent/session",map[string]string{"agentId":c.AgentID,"challenge":challenge.Challenge,"signature":signature},"",&result)
 if err!=nil{return "",err}
 if result.SessionToken==""{return "",errors.New("missing session")}
 return result.SessionToken,nil
}
// ExecuteMock is local execution, NOT a cloud-delivered command. The journal
// is written before any effect and duplicate IDs cannot trigger a second run.
func (c Client) ExecuteMock(ctx context.Context,j *journal.Journal,id string)error{
 token,err:=c.Handshake(ctx);if err!=nil{return err}
 if err:=c.post(ctx,"/v1/agent/heartbeat",map[string]string{},token,nil);err!=nil{return err}
 if err=j.Submit(id,"mock.ping");err!=nil{return err}
 if err=j.Begin(id);err!=nil{return err}
 // The only adapter behavior in this experimental slice: a pure mock result.
 return j.Finish(id,journal.Succeeded,"pong")
}
