package pgpairing

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "errors"
 "time"
)

// Challenge issues one currently usable proof-of-possession challenge per
// approved request. Only the hashed nonce is saved in PostgreSQL.
func(s *Store)Challenge(ctx context.Context,org,id string)(string,error){
 if !valid(org)||!valid(id){return "",ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return "",err};defer tx.Rollback()
 var state string
 var deadline,expires time.Time
 err=tx.QueryRowContext(ctx,`SELECT p.status,p.approval_expires_at,p.expires_at
 FROM lr_pairings p JOIN lr_organizations o ON o.organization_id=p.organization_id
 WHERE p.organization_id=$1 AND p.request_id=$2 AND o.status='ACTIVE'
 FOR UPDATE OF p`,org,id).Scan(&state,&deadline,&expires)
 if err!=nil||state!="APPROVED"||!s.now().Before(deadline)||!s.now().Before(expires){return "",ErrDenied}
 nonce,err:=randomID(32);if err!=nil{return "",err}
 sum:=sha256.Sum256([]byte(nonce))
 result,err:=tx.ExecContext(ctx,`INSERT INTO lr_pairing_challenges
 (organization_id,request_id,nonce_hash,expires_at)
 VALUES($1,$2,$3,NOW()+INTERVAL '30 seconds')
 ON CONFLICT(organization_id,request_id) DO UPDATE
 SET nonce_hash=EXCLUDED.nonce_hash,expires_at=EXCLUDED.expires_at,used_at=NULL
 WHERE lr_pairing_challenges.expires_at < NOW() OR lr_pairing_challenges.used_at IS NOT NULL`,
 org,id,sum[:])
 if err!=nil{return "",err}
 n,err:=result.RowsAffected();if err!=nil{return "",err}
 if n!=1{return "",ErrDenied}
 if err=tx.Commit();err!=nil{return "",err}
 return nonce,nil
}
// Enroll atomically consumes the hashed challenge, writes an enrolled pairing,
// registers the agent and writes its audit event, with no capability grants.
func(s *Store)Enroll(ctx context.Context,org,id,nonce string,proof []byte)(Record,error){
 if !valid(org)||!valid(id)||len(proof)!=ed25519.SignatureSize{return Record{},ErrDenied}
 raw,err:=base64.RawURLEncoding.DecodeString(nonce)
 if err!=nil||len(raw)!=32{return Record{},ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return Record{},err};defer tx.Rollback()
 var pub []byte
 var status string
 var expires,approved time.Time
 err=tx.QueryRowContext(ctx,`SELECT p.public_key,p.status,p.expires_at,p.approval_expires_at
 FROM lr_pairings p JOIN lr_organizations o ON o.organization_id=p.organization_id
 WHERE p.organization_id=$1 AND p.request_id=$2 AND o.status='ACTIVE'
 FOR UPDATE OF p`,org,id).Scan(&pub,&status,&expires,&approved)
 if err!=nil||status!="APPROVED"||len(pub)!=ed25519.PublicKeySize||!s.now().Before(expires)||!s.now().Before(approved){return Record{},ErrDenied}
 var stored []byte
 var deadline time.Time
 var used sqlNullTime
 err=tx.QueryRowContext(ctx,`SELECT nonce_hash,expires_at,used_at FROM lr_pairing_challenges
 WHERE organization_id=$1 AND request_id=$2 FOR UPDATE`,org,id).Scan(&stored,&deadline,&used)
 if err!=nil||used.Valid||!s.now().Before(deadline){return Record{},ErrDenied}
 digest:=sha256.Sum256([]byte(nonce))
 if !bytes.Equal(stored,digest[:])||!ed25519.Verify(ed25519.PublicKey(pub),[]byte(enrollDomain+part(org)+part(id)+part(nonce)),proof){return Record{},ErrDenied}
 agentID,err:=randomID(18);if err!=nil{return Record{},err}
 if _,err=tx.ExecContext(ctx,`UPDATE lr_pairing_challenges SET used_at=NOW()
 WHERE organization_id=$1 AND request_id=$2 AND used_at IS NULL`,org,id);err!=nil{return Record{},err}
 if _,err=tx.ExecContext(ctx,`UPDATE lr_pairings SET status='ENROLLED',agent_id=$3,enrolled_at=NOW()
 WHERE organization_id=$1 AND request_id=$2`,org,id,agentID);err!=nil{return Record{},err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_agents
 (organization_id,agent_id,request_id,public_key) VALUES($1,$2,$3,$4)`,
 org,agentID,id,pub);err!=nil{return Record{},err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_pairing_audit
 (organization_id,request_id,actor_type,actor_id,event_type)
 VALUES($1,$2,'AGENT',$3,'ENROLL')`,org,id,agentID);err!=nil{return Record{},err}
 var r Record
 err=tx.QueryRowContext(ctx,`SELECT organization_id,request_id,site_id,status,expires_at,approval_expires_at,agent_id
 FROM lr_pairings WHERE organization_id=$1 AND request_id=$2`,org,id).
 Scan(&r.Organization,&r.RequestID,&r.Site,&r.State,&r.ExpiresAt,&r.ApprovalExpiresAt,&r.AgentID)
 if err!=nil{return Record{},err}
 if err=tx.Commit();err!=nil{return Record{},err}
 return r,nil
}
type sqlNullTime struct{Time time.Time;Valid bool}
func(n *sqlNullTime)Scan(value any)error{
 if value==nil{n.Valid=false;return nil}
 t,ok:=value.(time.Time);if !ok{return errors.New("invalid used timestamp")}
 n.Time=t;n.Valid=true;return nil
}
