package pgpairing

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "database/sql"
 "encoding/base64"
 "time"
)

const resumeDomain="localreach/pgpairing/resume/v1:"

// ResumeMessage binds a fresh server challenge to organization and agent ID.
// It is not an authorization to execute printer or attendance operations.
func ResumeMessage(org,agentID,nonce string)[]byte{
 return []byte(resumeDomain+part(org)+part(agentID)+part(nonce))
}
func SignResume(priv ed25519.PrivateKey,org,agentID,nonce string)[]byte{
 return ed25519.Sign(priv,ResumeMessage(org,agentID,nonce))
}

// ResolveIdentity performs an internal lookup by the *public* key held in
// native OS-protected storage. It is not a login or a public discovery API;
// callers must subsequently complete VerifyResume to prove key possession.
func(s *Store)ResolveIdentity(ctx context.Context,org string,pub ed25519.PublicKey)(string,error){
 if !valid(org)||len(pub)!=ed25519.PublicKeySize||s==nil||s.DB==nil{return "",ErrDenied}
 var id string
 err:=s.DB.QueryRowContext(ctx,`SELECT a.agent_id FROM lr_agents a
 JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 JOIN lr_organizations o ON o.organization_id=a.organization_id
 WHERE a.organization_id=$1 AND a.public_key=$2 AND a.revoked_at IS NULL
 AND p.status='ENROLLED' AND o.status='ACTIVE'`,org,[]byte(pub)).Scan(&id)
 if err!=nil{return "",ErrDenied}
 return id,nil
}

// BeginResume creates a 30-second single-use challenge only for an
// enrolled, non-revoked agent of an active organization.
func(s *Store)BeginResume(ctx context.Context,org,agent string)(string,error){
 if !valid(org)||!valid(agent){return "",ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return "",err};defer tx.Rollback()
 var pub []byte
 err=tx.QueryRowContext(ctx,`SELECT a.public_key FROM lr_agents a
 JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 JOIN lr_organizations o ON o.organization_id=a.organization_id
 WHERE a.organization_id=$1 AND a.agent_id=$2 AND a.revoked_at IS NULL
 AND p.status='ENROLLED' AND o.status='ACTIVE'
 FOR SHARE OF a,p,o`,org,agent).Scan(&pub)
 if err!=nil||len(pub)!=ed25519.PublicKeySize{return "",ErrDenied}
 nonce,err:=randomID(32);if err!=nil{return "",err}
 digest:=sha256.Sum256([]byte(nonce))
 result,err:=tx.ExecContext(ctx,`INSERT INTO lr_agent_resume_challenges
 (organization_id,agent_id,nonce_hash,expires_at)
 VALUES($1,$2,$3,NOW()+INTERVAL '30 seconds')
 ON CONFLICT(organization_id,agent_id) DO UPDATE
 SET nonce_hash=EXCLUDED.nonce_hash,expires_at=EXCLUDED.expires_at,consumed_at=NULL
 WHERE lr_agent_resume_challenges.expires_at < NOW()
 OR lr_agent_resume_challenges.consumed_at IS NOT NULL`,org,agent,digest[:])
 if err!=nil{return "",err}
 affected,err:=result.RowsAffected()
 if err!=nil||affected!=1{return "",ErrDenied}
 if err=tx.Commit();err!=nil{return "",err}
 return nonce,nil
}

// VerifyResume atomically consumes a fresh challenge after verifying the
// persisted, non-revoked signing key and writes a scoped identity audit.
// It does NOT create a session, grant device permissions, or mark the agent
// as online. Public transport needs authenticated TLS and abuse controls.
func(s *Store)VerifyResume(ctx context.Context,org,agent,nonce string,signature []byte)error{
 if !valid(org)||!valid(agent)||len(signature)!=ed25519.SignatureSize{return ErrDenied}
 decoded,err:=base64.RawURLEncoding.DecodeString(nonce)
 if err!=nil||len(decoded)!=32{return ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return err};defer tx.Rollback()
 var public []byte
 err=tx.QueryRowContext(ctx,`SELECT a.public_key FROM lr_agents a
 JOIN lr_pairings p ON p.organization_id=a.organization_id AND p.request_id=a.request_id
 JOIN lr_organizations o ON o.organization_id=a.organization_id
 WHERE a.organization_id=$1 AND a.agent_id=$2 AND a.revoked_at IS NULL
 AND p.status='ENROLLED' AND o.status='ACTIVE'
 FOR SHARE OF a,p,o`,org,agent).Scan(&public)
 if err!=nil||len(public)!=ed25519.PublicKeySize{return ErrDenied}
 var stored []byte
 var expiration time.Time
 var used sql.NullTime
 err=tx.QueryRowContext(ctx,`SELECT nonce_hash,expires_at,consumed_at
 FROM lr_agent_resume_challenges WHERE organization_id=$1 AND agent_id=$2
 FOR UPDATE`,org,agent).Scan(&stored,&expiration,&used)
 digest:=sha256.Sum256([]byte(nonce))
 if err!=nil||used.Valid||!s.now().Before(expiration)||!bytes.Equal(stored,digest[:])||
 !ed25519.Verify(ed25519.PublicKey(public),ResumeMessage(org,agent,nonce),signature){return ErrDenied}
 result,err:=tx.ExecContext(ctx,`UPDATE lr_agent_resume_challenges
 SET consumed_at=NOW() WHERE organization_id=$1 AND agent_id=$2 AND consumed_at IS NULL`,org,agent)
 if err!=nil{return err}
 affected,err:=result.RowsAffected()
 if err!=nil||affected!=1{return ErrDenied}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_agent_identity_audit
 (organization_id,agent_id,event_type) VALUES($1,$2,'RESUME_VERIFIED')`,org,agent);err!=nil{return err}
 return tx.Commit()
}
