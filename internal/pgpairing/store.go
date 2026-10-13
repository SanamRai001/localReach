// Package pgpairing provides transactional PostgreSQL pairing primitives.
// There is no HTTP listener, admin login UI, or device capability grant here.
package pgpairing

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "database/sql"
 "encoding/base64"
 "errors"
 "strconv"
 "strings"
 "time"
)

var ErrDenied=errors.New("pairing request denied")
const adminDomain="localreach/pgpairing/admin/v1:"
const enrollDomain="localreach/pgpairing/enroll/v1:"
type Action string
const (
 Approve Action="APPROVE"
 Reject Action="REJECT"
 Revoke Action="REVOKE"
)
type AdminDecision struct{
 Organization string
 RequestID string
 AdminID string
 Action Action
 Nonce string
 IssuedAt int64
 ExpiresAt int64
}
func part(s string)string{return strconv.Itoa(len(s))+":"+s}
func message(d AdminDecision)[]byte{
 return []byte(adminDomain+part(d.Organization)+part(d.RequestID)+part(d.AdminID)+part(string(d.Action))+part(d.Nonce)+strconv.FormatInt(d.IssuedAt,10)+":"+strconv.FormatInt(d.ExpiresAt,10))
}
// DecisionMessage is the canonical tenant/key/request-scoped admin decision.
func DecisionMessage(d AdminDecision)[]byte{return message(d)}
func SignDecision(priv ed25519.PrivateKey,d AdminDecision)[]byte{return ed25519.Sign(priv,DecisionMessage(d))}
// EnrollmentMessage is the exact domain-separated server-verifiable proof.
// Native signers should sign these bytes, never an arbitrary remote message.
func EnrollmentMessage(org,id,nonce string)[]byte{
 return []byte(enrollDomain+part(org)+part(id)+part(nonce))
}
func SignEnrollment(priv ed25519.PrivateKey,org,id,nonce string)[]byte{
 return ed25519.Sign(priv,EnrollmentMessage(org,id,nonce))
}
type Record struct{
 Organization string
 RequestID string
 Site string
 State string
 ExpiresAt time.Time
 ApprovalExpiresAt sql.NullTime
 AgentID sql.NullString
}
type Store struct{DB *sql.DB;Now func()time.Time}
func New(db *sql.DB)*Store{return &Store{DB:db}}
func(s *Store)now()time.Time{if s.Now!=nil{return s.Now().UTC()};return time.Now().UTC()}
func valid(s string)bool{return len(s)>0&&len(s)<=128&&strings.IndexFunc(s,func(r rune)bool{return r<32||r==127})==-1}
func randomID(size int)(string,error){
 b:=make([]byte,size)
 if _,err:=rand.Read(b);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(b),nil
}
func (s *Store)begin(ctx context.Context)(*sql.Tx,error){
 if s==nil||s.DB==nil{return nil,ErrDenied}
 return s.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable})
}
// Propose is for an already trusted/limited intake service ONLY. Never
// expose this method as an unauthenticated public API.
func(s *Store)Propose(ctx context.Context,org,site string,pub ed25519.PublicKey)(Record,error){
 if !valid(org)||!valid(site)||len(pub)!=ed25519.PublicKeySize{return Record{},ErrDenied}
 id,err:=randomID(24);if err!=nil{return Record{},err}
 tx,err:=s.begin(ctx);if err!=nil{return Record{},err};defer tx.Rollback()
 var active string
 if err=tx.QueryRowContext(ctx,`SELECT o.status FROM lr_organizations o
 JOIN lr_sites x ON x.organization_id=o.organization_id
 WHERE o.organization_id=$1 AND x.site_id=$2 FOR SHARE OF o,x`,org,site).Scan(&active);err!=nil{return Record{},ErrDenied}
 if active!="ACTIVE"{return Record{},ErrDenied}
 var r Record
 err=tx.QueryRowContext(ctx,`INSERT INTO lr_pairings
 (organization_id,request_id,site_id,public_key,expires_at)
 VALUES($1,$2,$3,$4,NOW()+INTERVAL '5 minutes')
 RETURNING organization_id,request_id,site_id,status,expires_at,approval_expires_at,agent_id`,
 org,id,site,[]byte(pub)).Scan(&r.Organization,&r.RequestID,&r.Site,&r.State,&r.ExpiresAt,&r.ApprovalExpiresAt,&r.AgentID)
 if err!=nil{return Record{},err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_pairing_audit
 (organization_id,request_id,actor_type,actor_id,event_type)
 VALUES($1,$2,'SYSTEM','trusted-intake','PROPOSE')`,org,id);err!=nil{return Record{},err}
 if err=tx.Commit();err!=nil{return Record{},err}
 return r,nil
}
func validDecision(d AdminDecision,now time.Time,signature []byte)bool{
 if !valid(d.Organization)||!valid(d.RequestID)||!valid(d.AdminID)||len(signature)!=ed25519.SignatureSize{return false}
 if d.Action!=Approve&&d.Action!=Reject&&d.Action!=Revoke{return false}
 raw,err:=base64.RawURLEncoding.DecodeString(d.Nonce)
 if err!=nil||len(raw)!=32{return false}
 current:=now.Unix()
 return d.IssuedAt>=current-120&&d.IssuedAt<=current+30&&d.ExpiresAt>current&&d.ExpiresAt<=d.IssuedAt+120
}
// Decide validates the trusted admin role, signed decision, nonce replay,
// pairing update, and audit INSERT in ONE PostgreSQL transaction.
func(s *Store)Decide(ctx context.Context,d AdminDecision,signature []byte)(Record,error){
 if !validDecision(d,s.now(),signature){return Record{},ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return Record{},err};defer tx.Rollback()
 var key []byte
 err=tx.QueryRowContext(ctx,`SELECT a.public_key FROM lr_admin_keys a
 JOIN lr_organizations o ON o.organization_id=a.organization_id
 WHERE a.organization_id=$1 AND a.admin_id=$2 AND a.status='ACTIVE'
 AND a.role IN ('OWNER','ADMIN') AND o.status='ACTIVE'
 FOR SHARE OF a,o`,d.Organization,d.AdminID).Scan(&key)
 if err!=nil||len(key)!=ed25519.PublicKeySize||!ed25519.Verify(ed25519.PublicKey(key),message(d),signature){return Record{},ErrDenied}
 var current string
 var expiry time.Time
 err=tx.QueryRowContext(ctx,`SELECT status,expires_at FROM lr_pairings
 WHERE organization_id=$1 AND request_id=$2 FOR UPDATE`,d.Organization,d.RequestID).Scan(&current,&expiry)
 if err!=nil{return Record{},ErrDenied}
 if d.Action==Revoke{
  if current!="ENROLLED"{return Record{},ErrDenied}
 }else{
  if current!="PENDING"||!s.now().Before(expiry){return Record{},ErrDenied}
 }
 hash:=sha256.Sum256([]byte(d.Nonce))
 result,err:=tx.ExecContext(ctx,`INSERT INTO lr_decision_nonces
 (organization_id,nonce_hash,request_id,admin_id)
 VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`,d.Organization,hash[:],d.RequestID,d.AdminID)
 if err!=nil{return Record{},err}
 affected,err:=result.RowsAffected();if err!=nil{return Record{},err}
 if affected!=1{return Record{},ErrDenied}
 switch d.Action{
 case Approve:
  _,err=tx.ExecContext(ctx,`UPDATE lr_pairings
 SET status='APPROVED',approval_expires_at=LEAST(expires_at,NOW()+INTERVAL '1 minute')
 WHERE organization_id=$1 AND request_id=$2`,d.Organization,d.RequestID)
 case Reject:
  _,err=tx.ExecContext(ctx,`UPDATE lr_pairings SET status='REJECTED'
 WHERE organization_id=$1 AND request_id=$2`,d.Organization,d.RequestID)
 case Revoke:
  _,err=tx.ExecContext(ctx,`UPDATE lr_pairings SET status='REVOKED',revoked_at=NOW()
 WHERE organization_id=$1 AND request_id=$2`,d.Organization,d.RequestID)
  if err==nil{
   _,err=tx.ExecContext(ctx,`UPDATE lr_agents SET revoked_at=NOW()
 WHERE organization_id=$1 AND request_id=$2 AND revoked_at IS NULL`,d.Organization,d.RequestID)
  }
 }
 if err!=nil{return Record{},err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_pairing_audit
 (organization_id,request_id,actor_type,actor_id,event_type)
 VALUES($1,$2,'ADMIN',$3,$4)`,d.Organization,d.RequestID,d.AdminID,string(d.Action));err!=nil{return Record{},err}
 var r Record
 err=tx.QueryRowContext(ctx,`SELECT organization_id,request_id,site_id,status,expires_at,approval_expires_at,agent_id
 FROM lr_pairings WHERE organization_id=$1 AND request_id=$2`,d.Organization,d.RequestID).
 Scan(&r.Organization,&r.RequestID,&r.Site,&r.State,&r.ExpiresAt,&r.ApprovalExpiresAt,&r.AgentID)
 if err!=nil{return Record{},err}
 if err=tx.Commit();err!=nil{return Record{},err}
 return r,nil
}
func(s *Store)Get(ctx context.Context,org,id string)(Record,error){
 if !valid(org)||!valid(id)||s==nil||s.DB==nil{return Record{},ErrDenied}
 var r Record
 err:=s.DB.QueryRowContext(ctx,`SELECT organization_id,request_id,site_id,status,expires_at,approval_expires_at,agent_id
 FROM lr_pairings WHERE organization_id=$1 AND request_id=$2`,org,id).
 Scan(&r.Organization,&r.RequestID,&r.Site,&r.State,&r.ExpiresAt,&r.ApprovalExpiresAt,&r.AgentID)
 if errors.Is(err,sql.ErrNoRows){return Record{},ErrDenied}
 if err!=nil{return Record{},err}
 return r,nil
}
// AgentActive must be consulted by command-session authorization; being paired
// is still NOT permission to perform any device operation.
func(s *Store)AgentActive(ctx context.Context,org,agent string)(bool,error){
 if !valid(org)||!valid(agent)||s==nil||s.DB==nil{return false,ErrDenied}
 var active bool
 err:=s.DB.QueryRowContext(ctx,`SELECT EXISTS(
 SELECT 1 FROM lr_agents a JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 JOIN lr_organizations o ON o.organization_id=a.organization_id
 WHERE a.organization_id=$1 AND a.agent_id=$2 AND a.revoked_at IS NULL
 AND p.status='ENROLLED' AND o.status='ACTIVE')`,org,agent).Scan(&active)
 return active,err
}
