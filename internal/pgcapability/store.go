// Package pgcapability holds ONLY discovery-read policy. No hardware
// commands, printer jobs, attendance records or arbitrary network endpoints.
package pgcapability

import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "database/sql"
 "encoding/base64"
 "encoding/hex"
 "errors"
 "strconv"
 "strings"
 "time"
)

var ErrDenied=errors.New("device discovery permission denied")
const domain="localreach/device-read-decision/v1:"
const (
 PrinterDiscovery="PRINTER_DISCOVERY_READ"
 AttendanceDiscovery="ATTENDANCE_DISCOVERY_READ"
 Grant="GRANT"
 Revoke="REVOKE"
)
type Decision struct{
 Organization string
 Site string
 AgentID string
 DeviceFingerprint string
 Capability string
 AdminID string
 Action string
 Nonce string
 IssuedAt int64
 ExpiresAt int64
}
type Store struct{DB *sql.DB;Now func()time.Time}
func New(db *sql.DB)*Store{return &Store{DB:db}}
func(s *Store)now()time.Time{if s.Now!=nil{return s.Now().UTC()};return time.Now().UTC()}
func part(v string)string{return strconv.Itoa(len(v))+":"+v}
func Message(d Decision)[]byte{
 return []byte(domain+part(d.Organization)+part(d.Site)+part(d.AgentID)+part(d.DeviceFingerprint)+
 part(d.Capability)+part(d.AdminID)+part(d.Action)+part(d.Nonce)+
 strconv.FormatInt(d.IssuedAt,10)+":"+strconv.FormatInt(d.ExpiresAt,10))
}
func Sign(private ed25519.PrivateKey,d Decision)[]byte{return ed25519.Sign(private,Message(d))}
func valid(v string)bool{
 return len(v)>0&&len(v)<=128&&strings.IndexFunc(v,func(r rune)bool{return r<32||r==127})==-1
}
func allowedCapability(v string)bool{return v==PrinterDiscovery||v==AttendanceDiscovery}
func fingerprintOK(v string)bool{
 if len(v)!=64{return false}
 _,err:=hex.DecodeString(v)
 return err==nil&&strings.ToLower(v)==v
}
func validDecision(d Decision,signature []byte,now time.Time)bool{
 if !valid(d.Organization)||!valid(d.Site)||!valid(d.AgentID)||!valid(d.AdminID)||
 !fingerprintOK(d.DeviceFingerprint)||!allowedCapability(d.Capability)||
 (d.Action!=Grant&&d.Action!=Revoke)||len(signature)!=ed25519.SignatureSize{return false}
 b,err:=base64.RawURLEncoding.DecodeString(d.Nonce)
 if err!=nil||len(b)!=32{return false}
 nowUnix:=now.Unix()
 if d.IssuedAt<nowUnix-120||d.IssuedAt>nowUnix+30||
 d.ExpiresAt<=nowUnix||d.ExpiresAt>d.IssuedAt+120{return false}
 return true
}
func (s *Store)Decide(ctx context.Context,d Decision,signature []byte)error{
 if s==nil||s.DB==nil||!validDecision(d,signature,s.now()){return ErrDenied}
 tx,err:=s.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable})
 if err!=nil{return err}
 defer tx.Rollback()
 var key []byte
 err=tx.QueryRowContext(ctx,`SELECT k.public_key FROM lr_admin_keys k
 JOIN lr_organizations o ON o.organization_id=k.organization_id
 JOIN lr_sites x ON x.organization_id=o.organization_id
 WHERE k.organization_id=$1 AND k.admin_id=$2 AND x.site_id=$3
 AND k.status='ACTIVE' AND k.role IN ('OWNER','ADMIN') AND o.status='ACTIVE'
 FOR SHARE OF k,o,x`,d.Organization,d.AdminID,d.Site).Scan(&key)
 if err!=nil||len(key)!=ed25519.PublicKeySize||
 !ed25519.Verify(ed25519.PublicKey(key),Message(d),signature){return ErrDenied}
 var site string
 err=tx.QueryRowContext(ctx,`SELECT p.site_id FROM lr_agents a
 JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 WHERE a.organization_id=$1 AND a.agent_id=$2 AND a.revoked_at IS NULL
 AND p.status='ENROLLED' FOR SHARE OF a,p`,d.Organization,d.AgentID).Scan(&site)
 if err!=nil||site!=d.Site{return ErrDenied}
 nonceHash:=sha256.Sum256([]byte(d.Nonce))
 result,err:=tx.ExecContext(ctx,`INSERT INTO lr_device_read_decision_nonces
 (organization_id,nonce_hash) VALUES($1,$2) ON CONFLICT DO NOTHING`,d.Organization,nonceHash[:])
 if err!=nil{return err}
 rows,err:=result.RowsAffected()
 if err!=nil||rows!=1{return ErrDenied}
 if d.Action==Grant {
  // A re-grant requires an entirely new, signed decision and produces an
  // audit row; its duration is capped at one hour (not indefinite).
  _,err=tx.ExecContext(ctx,`INSERT INTO lr_device_read_grants
 (organization_id,agent_id,site_id,device_fingerprint,capability,status,approved_by,expires_at)
 VALUES($1,$2,$3,$4,$5,'ACTIVE',$6,NOW()+INTERVAL '1 hour')
 ON CONFLICT(organization_id,agent_id,device_fingerprint,capability)
 DO UPDATE SET status='ACTIVE',approved_by=EXCLUDED.approved_by,
 site_id=EXCLUDED.site_id,approved_at=NOW(),expires_at=NOW()+INTERVAL '1 hour',
 revoked_at=NULL`,d.Organization,d.AgentID,d.Site,d.DeviceFingerprint,d.Capability,d.AdminID)
 }else{
  result,err=tx.ExecContext(ctx,`UPDATE lr_device_read_grants
 SET status='REVOKED',revoked_at=NOW()
 WHERE organization_id=$1 AND agent_id=$2 AND site_id=$3
 AND device_fingerprint=$4 AND capability=$5 AND status='ACTIVE'`,
 d.Organization,d.AgentID,d.Site,d.DeviceFingerprint,d.Capability)
  if err==nil{
   rows,err=result.RowsAffected()
   if err!=nil||rows!=1{return ErrDenied}
  }
 }
 if err!=nil{return err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_device_read_audit
 (organization_id,agent_id,device_fingerprint,capability,admin_id,action)
 VALUES($1,$2,$3,$4,$5,$6)`,
 d.Organization,d.AgentID,d.DeviceFingerprint,d.Capability,d.AdminID,d.Action);err!=nil{return err}
 return tx.Commit()
}
// Allowed checks an actual current grant, active issuer, pairing and
// organization. It is a policy query, not a device-operation authorization
// endpoint. No command channel consumes this value in R2K.1.
func(s *Store)Allowed(ctx context.Context,org,site,agent,fingerprint,capability string)(bool,error){
 if s==nil||s.DB==nil||!valid(org)||!valid(site)||!valid(agent)||
 !fingerprintOK(fingerprint)||!allowedCapability(capability){return false,ErrDenied}
 var active bool
 err:=s.DB.QueryRowContext(ctx,`SELECT EXISTS(
 SELECT 1 FROM lr_device_read_grants g
 JOIN lr_agents a ON a.organization_id=g.organization_id AND a.agent_id=g.agent_id
 JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 JOIN lr_organizations o ON o.organization_id=g.organization_id
 JOIN lr_admin_keys k ON k.organization_id=g.organization_id AND k.admin_id=g.approved_by
 WHERE g.organization_id=$1 AND g.site_id=$2 AND g.agent_id=$3
 AND g.device_fingerprint=$4 AND g.capability=$5
 AND g.status='ACTIVE' AND g.expires_at>NOW()
 AND a.revoked_at IS NULL AND p.status='ENROLLED' AND p.site_id=g.site_id
 AND o.status='ACTIVE' AND k.status='ACTIVE' AND k.role IN ('OWNER','ADMIN'))`,
 org,site,agent,fingerprint,capability).Scan(&active)
 return active,err
}
