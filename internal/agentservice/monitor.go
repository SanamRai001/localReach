// Package agentservice maintains an intentionally conservative local view
// of periodic HTTPS identity verification. It does not create a cloud session.
package agentservice

import (
 "context"
 "crypto/ed25519"
 "sync"
 "time"

 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/localstatus"
)
type Signer = agentremote.Signer
type Verifier interface{
 VerifyIdentity(context.Context,string,Signer)(string,error)
}
// Monitor only verifies an existing agent identity; it cannot enroll,
// mutate local hardware or grant network/device capabilities.
type Monitor struct{
 Organization string
 Identity Signer
 Remote Verifier
 Now func()time.Time
 Interval time.Duration
 mu sync.RWMutex
 tickMu sync.Mutex
 snapshot localstatus.Snapshot
 verifiedAt time.Time
}
func New(organization string,signer Signer,remote Verifier)*Monitor{
 return &Monitor{
  Organization:organization,Identity:signer,Remote:remote,
  Interval:60*time.Second,snapshot:localstatus.Default(),
 }
}
func(m *Monitor)clock()time.Time{
 if m.Now!=nil{return m.Now().UTC()}
 return time.Now().UTC()
}
// Snapshot never returns PAIRED once the last proof is stale. A verified
// identity is NOT an active cloud transport or a device authorization.
func(m *Monitor)Snapshot()localstatus.Snapshot{
 m.mu.RLock()
 defer m.mu.RUnlock()
 result:=m.snapshot
 if result.Verification=="VERIFIED_RECENTLY"&&
  (m.verifiedAt.IsZero()||m.clock().Sub(m.verifiedAt)>90*time.Second||
  m.clock().Before(m.verifiedAt)){
  result.Pairing="UNVERIFIED"
  result.Verification="STALE"
  result.LastVerifiedAt=""
 }
 result.Connection="OFFLINE"
 result.Devices="NOT_DISCOVERED"
 return result
}
func(m *Monitor)Tick(ctx context.Context){
 m.tickMu.Lock()
 defer m.tickMu.Unlock()
 ok:=false
 if m.Remote!=nil&&m.Identity!=nil&&m.Organization!=""&&len(m.Identity.PublicKey())==ed25519.PublicKeySize{
  agentID,err:=m.Remote.VerifyIdentity(ctx,m.Organization,m.Identity)
  ok=err==nil&&agentID!=""&&ctx.Err()==nil
 }
 m.mu.Lock()
 defer m.mu.Unlock()
 m.snapshot.Connection="OFFLINE"
 m.snapshot.Devices="NOT_DISCOVERED"
 if ok{
  m.verifiedAt=m.clock()
  m.snapshot.Pairing="PAIRED"
  m.snapshot.Verification="VERIFIED_RECENTLY"
  m.snapshot.LastVerifiedAt=m.verifiedAt.Format(time.RFC3339)
 }else{
  m.verifiedAt=time.Time{}
  m.snapshot.Pairing="UNVERIFIED"
  m.snapshot.Verification="FAILED"
  m.snapshot.LastVerifiedAt=""
 }
}
// Run verifies immediately, then at the configured cadence. It never
// claims continuous connectivity and exits on cancellation.
func(m *Monitor)Run(ctx context.Context){
 interval:=m.Interval
 if interval<10*time.Second{interval=10*time.Second}
 m.Tick(ctx)
 ticker:=time.NewTicker(interval)
 defer ticker.Stop()
 for {
  select {
  case <-ctx.Done():
   m.mu.Lock()
   m.snapshot.Agent="STOPPED"
   m.snapshot.Pairing="UNVERIFIED"
   m.snapshot.Verification="STOPPED"
   m.snapshot.LastVerifiedAt=""
   m.mu.Unlock()
   return
  case <-ticker.C:m.Tick(ctx)
  }
 }
}
