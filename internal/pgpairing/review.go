package pgpairing

import (
 "context"
 "crypto/sha256"
 "database/sql"
 "encoding/hex"
 "time"
)

// Review is deliberately non-secret and intended for an authenticated
// administrator to compare with the fingerprint on the physical agent.
// Viewing is NOT a device grant or an approval.
type Review struct {
 Organization string
 RequestID string
 Site string
 State string
 Fingerprint string
 CreatedAt time.Time
 ExpiresAt time.Time
}
// ReviewRequest never returns the private key, admin keys, invitation code,
// enrollment challenge, or bearer token.
func(s *Store)ReviewRequest(ctx context.Context,org,id string)(Review,error){
 if !valid(org)||!valid(id)||s==nil||s.DB==nil{return Review{},ErrDenied}
 var value Review
 var public []byte
 err:=s.DB.QueryRowContext(ctx,`SELECT p.organization_id,p.request_id,p.site_id,p.status,
 p.public_key,p.created_at,p.expires_at
 FROM lr_pairings p JOIN lr_organizations o ON o.organization_id=p.organization_id
 WHERE p.organization_id=$1 AND p.request_id=$2 AND o.status='ACTIVE'`,
 org,id).Scan(&value.Organization,&value.RequestID,&value.Site,
 &value.State,&public,&value.CreatedAt,&value.ExpiresAt)
 if err==sql.ErrNoRows||err!=nil||len(public)!=32{return Review{},ErrDenied}
 hash:=sha256.Sum256(public)
 value.Fingerprint=hex.EncodeToString(hash[:])
 return value,nil
}
