// Package pairpolicy composes independently provisioned, durable admin trust
// with durable pairing state. It has no HTTP routes or public listener.
package pairpolicy

import (
 "crypto/ed25519"
 "encoding/base64"
 "errors"
 "time"

 "github.com/SanamRai001/localReach/internal/admintrust"
 "github.com/SanamRai001/localReach/internal/pairledger"
 "github.com/SanamRai001/localReach/internal/pairtransport"
)
var ErrDenied=errors.New("pairing authorization denied")
type Controller struct{
 Trust *admintrust.Store
 Pairings *pairledger.Store
 Now func()time.Time
}
// Decide consumes the signed administrator decision nonce durably BEFORE
// recording the approval/rejection. A crash between stores denies retry;
// atomicity across both journals requires a future transactional database.
func(c Controller)Decide(d pairtransport.Decision,signature []byte)(pairledger.Record,error){
 if c.Trust==nil||c.Pairings==nil||d.ID==""||d.Tenant==""||d.KeyID==""||len(signature)!=ed25519.SignatureSize{return pairledger.Record{},ErrDenied}
 now:=time.Now
 if c.Now!=nil{now=c.Now}
 current:=now().Unix()
 if d.IssuedAt>current+30||d.IssuedAt<current-120||d.ExpiresAt<=current||d.ExpiresAt>d.IssuedAt+120{return pairledger.Record{},ErrDenied}
 decoded,err:=base64.RawURLEncoding.DecodeString(d.Nonce)
 if err!=nil||len(decoded)!=32{return pairledger.Record{},ErrDenied}
 if err=c.Trust.VerifyAndConsume(d.Tenant,d.KeyID,d.Nonce,pairtransport.DecisionMessage(d),signature);err!=nil{return pairledger.Record{},ErrDenied}
 request,err:=c.Pairings.Decide(d.Tenant,d.ID,true,d.Approve)
 if err!=nil{return pairledger.Record{},ErrDenied}
 return request,nil
}
