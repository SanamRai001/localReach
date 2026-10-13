package pgpairing

import (
 "context"
 "errors"
 "time"
)

var ErrSessionUnavailable=errors.New("agent session unavailable")
const sessionLease=15*time.Second

// OpenConnection reserves the ONE live gateway session for an enrolled agent.
// If the existing session is still leased, a second connection cannot replace
// it. An expired lease may be reclaimed; session IDs are random and scoped.
func(s *Store)OpenConnection(ctx context.Context,org,agent string)(string,error){
 if !valid(org)||!valid(agent){return "",ErrSessionUnavailable}
 session,err:=randomID(24);if err!=nil{return "",err}
 tx,err:=s.begin(ctx);if err!=nil{return "",err};defer tx.Rollback()
 var active bool
 err=tx.QueryRowContext(ctx,`SELECT EXISTS(
 SELECT 1 FROM lr_agents a
 JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 JOIN lr_organizations o ON o.organization_id=a.organization_id
 WHERE a.organization_id=$1 AND a.agent_id=$2 AND a.revoked_at IS NULL
 AND p.status='ENROLLED' AND o.status='ACTIVE')`,org,agent).Scan(&active)
 if err!=nil||!active{return "",ErrSessionUnavailable}
 result,err:=tx.ExecContext(ctx,`INSERT INTO lr_agent_connections
 (organization_id,agent_id,session_id,expires_at)
 VALUES($1,$2,$3,NOW()+INTERVAL '15 seconds')
 ON CONFLICT (organization_id,agent_id) DO UPDATE SET
 session_id=EXCLUDED.session_id,started_at=NOW(),heartbeat_at=NOW(),expires_at=EXCLUDED.expires_at
 WHERE lr_agent_connections.expires_at<=NOW()`,org,agent,session)
 if err!=nil{return "",err}
 changed,err:=result.RowsAffected()
 if err!=nil||changed!=1{return "",ErrSessionUnavailable}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_agent_connection_audit
 (organization_id,agent_id,action) VALUES($1,$2,'OPEN')`,org,agent);err!=nil{return "",err}
 if err=tx.Commit();err!=nil{return "",err}
 return session,nil
}
// RenewConnection requires that the same process still owns this session,
// the lease has not already expired, and tenant/pairing/agent remain active.
// Revocation is enforced on EVERY heartbeat with a transactional row check.
func(s *Store)RenewConnection(ctx context.Context,org,agent,session string)error{
 if !valid(org)||!valid(agent)||!valid(session){return ErrSessionUnavailable}
 tx,err:=s.begin(ctx);if err!=nil{return err};defer tx.Rollback()
 result,err:=tx.ExecContext(ctx,`UPDATE lr_agent_connections c
 SET heartbeat_at=NOW(),expires_at=NOW()+INTERVAL '15 seconds'
 FROM lr_agents a, lr_pairings p, lr_organizations o
 WHERE c.organization_id=$1 AND c.agent_id=$2 AND c.session_id=$3
 AND c.expires_at>NOW()
 AND a.organization_id=c.organization_id AND a.agent_id=c.agent_id
 AND p.organization_id=a.organization_id AND p.request_id=a.request_id
 AND o.organization_id=a.organization_id
 AND a.revoked_at IS NULL AND p.status='ENROLLED' AND o.status='ACTIVE'`,
 org,agent,session)
 if err!=nil{return err}
 count,err:=result.RowsAffected()
 if err!=nil||count!=1{return ErrSessionUnavailable}
 return tx.Commit()
}
func(s *Store)CloseConnection(ctx context.Context,org,agent,session string)error{
 if !valid(org)||!valid(agent)||!valid(session){return ErrSessionUnavailable}
 tx,err:=s.begin(ctx);if err!=nil{return err};defer tx.Rollback()
 result,err:=tx.ExecContext(ctx,`DELETE FROM lr_agent_connections
 WHERE organization_id=$1 AND agent_id=$2 AND session_id=$3`,org,agent,session)
 if err!=nil{return err}
 count,err:=result.RowsAffected();if err!=nil{return err}
 if count==1{
  if _,err=tx.ExecContext(ctx,`INSERT INTO lr_agent_connection_audit
 (organization_id,agent_id,action) VALUES($1,$2,'CLOSE')`,org,agent);err!=nil{return err}
 }
 return tx.Commit()
}
// ConnectionOnline must be used as a liveness hint ONLY, not authorization.
// Leases expire on crash, but no command/capability grant exists here.
func(s *Store)ConnectionOnline(ctx context.Context,org,agent string)(bool,error){
 if !valid(org)||!valid(agent)||s==nil||s.DB==nil{return false,ErrSessionUnavailable}
 var live bool
 err:=s.DB.QueryRowContext(ctx,`SELECT EXISTS(
 SELECT 1 FROM lr_agent_connections c
 JOIN lr_agents a ON a.organization_id=c.organization_id AND a.agent_id=c.agent_id
 JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 JOIN lr_organizations o ON o.organization_id=a.organization_id
 WHERE c.organization_id=$1 AND c.agent_id=$2
 AND c.expires_at>NOW() AND a.revoked_at IS NULL
 AND p.status='ENROLLED' AND o.status='ACTIVE')`,org,agent).Scan(&live)
 return live,err
}
// SessionTTL exists only to synchronize heartbeat and lease bounds.
func SessionTTL()time.Duration{return sessionLease}
// Ensure CloseConnection can safely run with a bounded, detached context.
func SessionCloseContext()(context.Context,context.CancelFunc){
 return context.WithTimeout(context.Background(),3*time.Second)
}
