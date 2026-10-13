// Package localdashboard powers the real loopback-only LocalReach setup UI.
// An OS-protected agent identity stays in Go; never exposed to browser code.
package localdashboard

import (
 "context"
 "crypto/ed25519"
 "encoding/base64"
 "errors"
 "sync"
 "sync/atomic"
 "time"

 "github.com/SanamRai001/localReach/internal/agentkeys"
 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/agentservice"
 "github.com/SanamRai001/localReach/internal/landiscovery"
 "github.com/SanamRai001/localReach/internal/localstatus"
)

var (
 ErrUnavailable=errors.New("a trusted HTTPS gateway and organization must be configured when starting LocalReach")
 ErrNoIdentity=errors.New("no existing OS-protected agent identity; initialize this computer first")
 ErrPending=errors.New("a pairing request is already pending; ask an administrator to review it")
 ErrNoRequest=errors.New("request a pairing invitation and await approval first")
 ErrBusy=errors.New("another local operation is in progress")
 ErrInvalid=errors.New("invalid one-time invitation")
)
type Signer interface{
 PublicKey()ed25519.PublicKey
 Fingerprint()string
 SignMessage([]byte)([]byte,error)
}
type Remote interface {
 RequestInvitation(context.Context,string,string,agentremote.Signer)(string,error)
 FinishEnrollment(context.Context,string,string,agentremote.Signer)(string,error)
 VerifyIdentity(context.Context,string,agentremote.Signer)(string,error)
 StreamSession(context.Context,string,agentremote.Signer,func(bool))error
}
type IdentityStore interface{
 Load()(*agentkeys.Identity,error)
 Create()(*agentkeys.Identity,error)
}
type Discovery func(context.Context,time.Duration)([]landiscovery.Candidate,error)
type Status struct {
 Agent string `json:"agent"`
 Identity string `json:"identity"`
 Fingerprint string `json:"fingerprint,omitempty"`
 Organization string `json:"organization,omitempty"`
 CloudConfigured bool `json:"cloudConfigured"`
 Pairing string `json:"pairing"`
 Connection string `json:"connection"`
 Verification string `json:"verification"`
 RequestID string `json:"requestId,omitempty"`
 DeviceCount int `json:"deviceCount"`
 Discovery string `json:"discovery"`
 LastError string `json:"lastError,omitempty"`
}
type Service struct {
 Store IdentityStore
 Remote Remote
 Organization string
 Discover Discovery
 mu sync.RWMutex
 signer agentremote.Signer
 fingerprint string
 identityError string
 requestID string
 enrolled bool
 monitor *agentservice.LiveMonitor
 cancel context.CancelFunc
 devices []landiscovery.Candidate
 discovery string
 lastError string
 operation atomic.Bool
}
func New(store IdentityStore,remote Remote,organization string)*Service{
 s:=&Service{Store:store,Remote:remote,Organization:organization,Discover:landiscovery.Listen,discovery:"NOT_STARTED"}
 if store==nil {s.identityError="Secure identity store is unavailable";return s}
 id,err:=store.Load()
 if err==nil{s.signer=id;s.fingerprint=id.Fingerprint()}
 if err!=nil&& !errors.Is(err,agentkeys.ErrMissing){
  s.identityError="Secure identity cannot be loaded. Check your OS account or key store; no replacement key was created."
 }
 return s
}
func(s *Service)begin()error{
 if !s.operation.CompareAndSwap(false,true){return ErrBusy}
 return nil
}
func(s *Service)Initialize()(string,error){
 if err:=s.begin();err!=nil{return "",err}
 defer s.operation.Store(false)
 s.mu.RLock();already:=s.signer!=nil;s.mu.RUnlock()
 if already{return "",agentkeys.ErrExists}
 if s.Store==nil{return "",ErrNoIdentity}
 id,err:=s.Store.Create()
 if err!=nil{return "",err}
 s.mu.Lock()
 s.signer=id;s.fingerprint=id.Fingerprint();s.identityError="";s.lastError=""
 s.mu.Unlock()
 return id.Fingerprint(),nil
}
func(s *Service)getSigner()(agentremote.Signer,error){
 s.mu.RLock();defer s.mu.RUnlock()
 if s.signer==nil{return nil,ErrNoIdentity}
 return s.signer,nil
}
func(s *Service)checkRemote()error{
 if s.Remote==nil||s.Organization==""{return ErrUnavailable}
 return nil
}
func(s *Service)Request(ctx context.Context,token string)(string,error){
 if err:=s.begin();err!=nil{return "",err}
 defer s.operation.Store(false)
 if err:=s.checkRemote();err!=nil{return "",err}
 b,err:=base64.RawURLEncoding.DecodeString(token)
 if err!=nil||len(b)!=32||len(token)!=43{return "",ErrInvalid}
 signer,err:=s.getSigner();if err!=nil{return "",err}
 s.mu.RLock();pending:=s.requestID;s.mu.RUnlock()
 if pending!=""{return "",ErrPending}
 id,err:=s.Remote.RequestInvitation(ctx,s.Organization,token,signer)
 if err!=nil{return "",errors.New("invitation was denied or has expired; verify your gateway and ask the administrator for a new code")}
 if id==""||len(id)>128{return "",errors.New("invalid gateway pairing response")}
 s.mu.Lock()
 s.requestID=id;s.enrolled=false;s.lastError=""
 s.mu.Unlock()
 return id,nil
}
func(s *Service)Finish(ctx context.Context)error{
 if err:=s.begin();err!=nil{return err}
 defer s.operation.Store(false)
 if err:=s.checkRemote();err!=nil{return err}
 signer,err:=s.getSigner();if err!=nil{return err}
 s.mu.RLock();requestID:=s.requestID;s.mu.RUnlock()
 if requestID==""{return ErrNoRequest}
 agentID,err:=s.Remote.FinishEnrollment(ctx,s.Organization,requestID,signer)
 if err!=nil{return errors.New("not approved yet, approval expired, or cloud unreachable; no connection was established")}
 if agentID==""{return errors.New("gateway did not confirm enrollment")}
 s.mu.Lock();s.enrolled=true;s.requestID="";s.lastError="";s.mu.Unlock()
 s.startMonitor()
 return nil
}
func(s *Service)Reconnect(ctx context.Context)error{
 if err:=s.begin();err!=nil{return err}
 defer s.operation.Store(false)
 if err:=s.checkRemote();err!=nil{return err}
 signer,err:=s.getSigner();if err!=nil{return err}
 if _,err:=s.Remote.VerifyIdentity(ctx,s.Organization,signer);err!=nil{
  return errors.New("existing identity is not enrolled, has been revoked, or the cloud is unavailable")
 }
 s.mu.Lock();s.enrolled=true;s.requestID="";s.lastError="";s.mu.Unlock()
 s.startMonitor()
 return nil
}
func(s *Service)startMonitor(){
 s.mu.Lock();defer s.mu.Unlock()
 if s.cancel!=nil{s.cancel()}
 ctx,cancel:=context.WithCancel(context.Background())
 s.cancel=cancel
 monitor:=agentservice.NewLive(s.Organization,s.signer,s.Remote)
 s.monitor=monitor
 go monitor.Run(ctx)
}
func(s *Service)DiscoverLocal(ctx context.Context,duration time.Duration)([]landiscovery.Candidate,error){
 if duration<time.Second||duration>15*time.Second{return nil,landiscovery.ErrInvalid}
 if err:=s.begin();err!=nil{return nil,err}
 defer s.operation.Store(false)
 s.mu.Lock();s.discovery="SCANNING";s.lastError="";s.mu.Unlock()
 discover:=s.Discover
 if discover==nil{discover=landiscovery.Listen}
 results,err:=discover(ctx,duration)
 s.mu.Lock();defer s.mu.Unlock()
 if err!=nil{
  s.discovery="UNAVAILABLE"
  s.lastError="Passive local discovery is unavailable. Check multicast/network settings or another mDNS listener."
  return nil,err
 }
 s.devices=append([]landiscovery.Candidate(nil),results...)
 s.discovery="COMPLETE"
 return append([]landiscovery.Candidate(nil),results...),nil
}
func(s *Service)Status()Status{
 s.mu.RLock()
 st:=Status{Agent:"RUNNING",Identity:"NOT_INITIALIZED",Fingerprint:s.fingerprint,
  Organization:s.Organization,CloudConfigured:s.Remote!=nil&&s.Organization!="",
  Pairing:"NOT_PAIRED",Connection:"OFFLINE",Verification:"NOT_CHECKED",
  RequestID:s.requestID,DeviceCount:len(s.devices),Discovery:s.discovery,LastError:s.lastError}
 if s.signer!=nil{st.Identity="READY"}
 if s.identityError!=""{st.Identity="UNAVAILABLE";st.LastError=s.identityError}
 if s.requestID!=""{st.Pairing="PENDING_APPROVAL"}
 if s.enrolled{st.Pairing="PAIRED";st.Verification="CONNECTING"}
 monitor:=s.monitor
 s.mu.RUnlock()
 if monitor!=nil{
  live:=monitor.Snapshot()
  st.Connection=live.Connection
  st.Verification=live.Verification
  if live.Connection=="ONLINE"{st.Pairing="PAIRED"}
  if live.Verification=="FAILED"||live.Verification=="STALE"{st.Pairing="UNVERIFIED"}
 }
 return st
}
func(s *Service)Snapshot()localstatus.Snapshot{
 state:=s.Status()
 return localstatus.Snapshot{Agent:state.Agent,Pairing:state.Pairing,
  Connection:state.Connection,Devices:"NOT_DISCOVERED",Verification:state.Verification}
}
func(s *Service)Close(){
 s.mu.Lock()
 if s.cancel!=nil{s.cancel();s.cancel=nil}
 s.mu.Unlock()
}
