package integration

import (
 "context"
 "errors"
 "fmt"
 "time"

 "github.com/SanamRai001/localReach/internal/broker"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/journal"
)

// Delivery is an in-process mock delivery integration. Broker methods are
// not public endpoints; authenticated TLS proof is required before claiming.
// The device effect is ONLY mock.ping. It does not open any LAN sockets.
type Delivery struct {
 Client Client
 Registry *identity.Registry
 Broker *broker.Broker
 Edge *journal.Journal
}
// RunOnce simulates one authenticated agent receiving a broker command.
// Fail closed on any uncertainty: a duplicate edge ID is not re-executed.
// The caller must not treat a network failure as proof the operation did not run.
func (d Delivery) RunOnce(ctx context.Context)(bool,error){
 if d.Registry==nil||d.Broker==nil||d.Edge==nil{return false,errors.New("delivery dependencies missing")}
 // Authenticated gateway proof is required for each simulated claim.
 token,err:=d.Client.Handshake(ctx)
 if err!=nil{return false,err}
 if err=d.Client.post(ctx,"/v1/agent/heartbeat",map[string]string{},token,nil);err!=nil{return false,err}
 agent,ok:=d.Registry.Lookup(d.Client.AgentID)
 if !ok||agent.Revoked{return false,errors.New("agent revoked or missing")}
 // Tenant and agent scope come from the verified registry, not user input.
 cmd,claimed,err:=d.Broker.Claim(agent.TenantID,agent.ID,20*time.Second)
 if err!=nil||!claimed{return false,err}
 if cmd.Operation!="mock.ping"{return false,errors.New("operation not allowlisted")}
 // Edge must persist command identity before acknowledging device receipt.
 if err=d.Edge.Submit(cmd.ID,cmd.Operation);err!=nil{
  // Even if already present, do not run it again. The broker lease remains
  // unacknowledged for later reconciliation, not safe for physical effects.
  return true,fmt.Errorf("edge rejects command; requires reconciliation: %w",err)
 }
 if err=d.Broker.Receive(cmd.ID,agent.TenantID,agent.ID,cmd.Lease);err!=nil{return true,err}
 // Persist EXECUTING before any effect. A crash here will be INDETERMINATE.
 if err=d.Edge.Begin(cmd.ID);err!=nil{return true,err}
 if err=d.Edge.Finish(cmd.ID,journal.Succeeded,"pong");err!=nil{return true,err}
 if err=d.Broker.Complete(cmd.ID,agent.TenantID,agent.ID,cmd.Lease,broker.Succeeded,"pong");err!=nil{
  // Edge may be completed while broker is stale; never re-run hardware.
  return true,fmt.Errorf("edge completed but broker report failed: %w",err)
 }
 return true,nil
}
