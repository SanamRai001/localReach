package pgpairing

import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "encoding/base64"
 "time"
)

// Invitation is a one-time, ten-minute credential authorizing ONLY a
// *pending* pairing proposal, never approval, enrollment or device access.
type Invitation struct{
 Organization string
 Site string
 InviteID string
 Token string
 ExpiresAt time.Time
}

// IssueInvitation requires an independently authenticated OWNER/ADMIN.
// Authorization is checked again against the live organization/admin rows
// inside the transaction. This method is NOT a public self-service signup.
func(s *Store)IssueInvitation(ctx context.Context,org,site,admin string)(Invitation,error){
 if !valid(org)||!valid(site)||!valid(admin){return Invitation{},ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return Invitation{},err}
 defer tx.Rollback()
 var status string
 err=tx.QueryRowContext(ctx,`SELECT o.status FROM lr_organizations o
 JOIN lr_sites x ON x.organization_id=o.organization_id
 JOIN lr_admin_keys k ON k.organization_id=o.organization_id
 WHERE o.organization_id=$1 AND x.site_id=$2 AND k.admin_id=$3
 AND k.status='ACTIVE' AND k.role IN ('OWNER','ADMIN')
 FOR SHARE OF o,x,k`,org,site,admin).Scan(&status)
 if err!=nil||status!="ACTIVE"{return Invitation{},ErrDenied}
 id,err:=randomID(18);if err!=nil{return Invitation{},err}
 secret,err:=randomID(32);if err!=nil{return Invitation{},err}
 digest:=sha256.Sum256([]byte(secret))
 var expiration time.Time
 err=tx.QueryRowContext(ctx,`INSERT INTO lr_pairing_invitations
 (organization_id,invite_id,site_id,admin_id,secret_hash,expires_at)
 VALUES($1,$2,$3,$4,$5,NOW()+INTERVAL '10 minutes')
 RETURNING expires_at`,org,id,site,admin,digest[:]).Scan(&expiration)
 if err!=nil{return Invitation{},err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_pairing_invitation_audit
 (organization_id,invite_id,action) VALUES($1,$2,'ISSUED')`,org,id);err!=nil{return Invitation{},err}
 if err=tx.Commit();err!=nil{return Invitation{},err}
 return Invitation{Organization:org,Site:site,InviteID:id,Token:secret,ExpiresAt:expiration},nil
}

// RedeemInvitation consumes a random one-use bearer secret and atomically
// creates a PENDING proposal tied to the original organization and site.
// It does not approve the request. A public transport MUST enforce per-source
// throttling, request size limits, TLS trust and abuse monitoring.
func(s *Store)RedeemInvitation(ctx context.Context,org,token string,pub ed25519.PublicKey)(Record,error){
 if !valid(org)||len(pub)!=ed25519.PublicKeySize{return Record{},ErrDenied}
 decoded,err:=base64.RawURLEncoding.DecodeString(token)
 if err!=nil||len(decoded)!=32{return Record{},ErrDenied}
 digest:=sha256.Sum256([]byte(token))
 tx,err:=s.begin(ctx);if err!=nil{return Record{},err}
 defer tx.Rollback()
 var inviteID,site,admin string
 err=tx.QueryRowContext(ctx,`SELECT i.invite_id,i.site_id,i.admin_id
 FROM lr_pairing_invitations i
 JOIN lr_organizations o ON o.organization_id=i.organization_id
 JOIN lr_admin_keys k ON k.organization_id=i.organization_id AND k.admin_id=i.admin_id
 WHERE i.organization_id=$1 AND i.secret_hash=$2
 AND i.consumed_at IS NULL AND i.expires_at>NOW()
 AND o.status='ACTIVE' AND k.status='ACTIVE' AND k.role IN ('OWNER','ADMIN')
 FOR UPDATE OF i`,org,digest[:]).Scan(&inviteID,&site,&admin)
 if err!=nil{return Record{},ErrDenied}
 requestID,err:=randomID(24);if err!=nil{return Record{},err}
 var result Record
 err=tx.QueryRowContext(ctx,`INSERT INTO lr_pairings
 (organization_id,request_id,site_id,public_key,expires_at)
 VALUES($1,$2,$3,$4,NOW()+INTERVAL '5 minutes')
 RETURNING organization_id,request_id,site_id,status,expires_at,approval_expires_at,agent_id`,
 org,requestID,site,[]byte(pub)).
 Scan(&result.Organization,&result.RequestID,&result.Site,&result.State,&result.ExpiresAt,&result.ApprovalExpiresAt,&result.AgentID)
 if err!=nil{return Record{},ErrDenied}
 updated,err:=tx.ExecContext(ctx,`UPDATE lr_pairing_invitations
 SET consumed_at=NOW(),request_id=$3
 WHERE organization_id=$1 AND invite_id=$2 AND consumed_at IS NULL`,org,inviteID,requestID)
 if err!=nil{return Record{},err}
 count,err:=updated.RowsAffected()
 if err!=nil||count!=1{return Record{},ErrDenied}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_pairing_invitation_audit
 (organization_id,invite_id,action) VALUES($1,$2,'REDEEMED')`,org,inviteID);err!=nil{return Record{},err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_pairing_audit
 (organization_id,request_id,actor_type,actor_id,event_type)
 VALUES($1,$2,'SYSTEM','invitation-intake','PROPOSE')`,org,requestID);err!=nil{return Record{},err}
 if err=tx.Commit();err!=nil{return Record{},err}
 return result,nil
}
