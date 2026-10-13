package agentservice

import (
 "context"
 "crypto/ed25519"
 "sync"
 "time"

 "github.com/SanamRai001/localReach/internal/localstatus"
)
type Streamer interface{
 StreamSession(context.Context,string,Signer,func(bool))error
}
// LiveMonitor publishes ONLINE only while authenticated session frames arrive
// on an active outbound TLS stream. A crash or network drop turns it OFFLINE.
// No device command handlers or permission grants are attached.
type LiveMonitor struct{
 Organization string
 Identity Signer
 Remote Streamer
 mu sync.RWMutex
 snapshot localstatus.Snapshot
 lastFrame time.Time
 // Retry backoff is bounded: clients never tight-loop during failures.
 Retry time.Duration
}
func NewLive(org string,s Signer,remote Streamer)*LiveMonitor{
 return &LiveMonitor{Organization:org,Identity:s,Remote:remote,
  snapshot:localstatus.Default(),Retry:2*time.Second}
}
func(m *LiveMonitor)Snapshot()localstatus.Snapshot{
 m.mu.RLock()
 defer m.mu.RUnlock()
 state:=m.snapshot
 if state.Connection=="ONLINE"&&
  (m.lastFrame.IsZero()||time.Since(m.lastFrame)>12*time.Second){
  state.Connection="OFFLINE"
  state.Pairing="UNVERIFIED"
  state.Verification="STALE"
  state.LastVerifiedAt=""
 }
 state.Devices="NOT_DISCOVERED"
 return state
}
func(m *LiveMonitor)setLive(ok bool){
 m.mu.Lock();defer m.mu.Unlock()
 if ok{
  m.lastFrame=time.Now()
  m.snapshot.Pairing="PAIRED"
  m.snapshot.Verification="VERIFIED_RECENTLY"
  m.snapshot.LastVerifiedAt=m.lastFrame.UTC().Format(time.RFC3339)
  m.snapshot.Connection="ONLINE"
 }else{
  m.lastFrame=time.Time{}
  m.snapshot.Pairing="UNVERIFIED"
  m.snapshot.Verification="FAILED"
  m.snapshot.LastVerifiedAt=""
  m.snapshot.Connection="OFFLINE"
 }
 m.snapshot.Devices="NOT_DISCOVERED"
}
func(m *LiveMonitor)Run(ctx context.Context){
 defer func(){
  m.setLive(false)
  m.mu.Lock()
  m.snapshot.Agent="STOPPED"
  m.snapshot.Verification="STOPPED"
  m.mu.Unlock()
 }()
 retry:=m.Retry
 if retry<time.Second{retry=time.Second}
 for ctx.Err()==nil{
  if m.Remote!=nil&&m.Identity!=nil&&m.Organization!=""&&len(m.Identity.PublicKey())==ed25519.PublicKeySize{
   // Server verifies identity and active lease; false on stream loss.
   _=m.Remote.StreamSession(ctx,m.Organization,m.Identity,m.setLive)
  }
  m.setLive(false)
  if ctx.Err()!=nil{return}
  timer:=time.NewTimer(retry)
  select{
  case <-ctx.Done():
   if !timer.Stop(){select{case <-timer.C:default:}}
   return
  case <-timer.C:
  }
  if retry<30*time.Second{
   retry*=2
   if retry>30*time.Second{retry=30*time.Second}
  }
 }
}
