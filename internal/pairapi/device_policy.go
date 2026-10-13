package pairapi

import(
 "context"
 "crypto/ed25519"
 "net/http"

 "github.com/SanamRai001/localReach/internal/pgcapability"
)
type ReadGrantPolicy interface{
 Decide(context.Context,pgcapability.Decision,[]byte)error
}
type signedDeviceReadDecision struct{
 Organization string `json:"organization"`
 Site string `json:"site"`
 AgentID string `json:"agentId"`
 DeviceFingerprint string `json:"deviceFingerprint"`
 Capability string `json:"capability"`
 AdminID string `json:"adminId"`
 Action string `json:"action"`
 Nonce string `json:"nonce"`
 IssuedAt int64 `json:"issuedAt"`
 ExpiresAt int64 `json:"expiresAt"`
 Signature string `json:"signature"`
}
// Grants are admin operations, not agent calls. A device permission may
// ONLY be approved separately from pairing, through a live admin session
// and a second domain-separated Ed25519 signature.
func(h Handler)decideDeviceRead(w http.ResponseWriter,r *http.Request){
 if h.ReadPolicy==nil{http.Error(w,"unavailable",http.StatusServiceUnavailable);return}
 var input signedDeviceReadDecision
 if !decode(w,r,&input){return}
 admin,ok:=h.admin(w,r,input.Organization)
 if !ok||admin.AdminID!=input.AdminID{denied(w);return}
 proof,err:=decoded(input.Signature,ed25519.SignatureSize)
 if err!=nil{denied(w);return}
 d:=pgcapability.Decision{
  Organization:input.Organization,Site:input.Site,AgentID:input.AgentID,
  DeviceFingerprint:input.DeviceFingerprint,Capability:input.Capability,
  AdminID:input.AdminID,Action:input.Action,Nonce:input.Nonce,
  IssuedAt:input.IssuedAt,ExpiresAt:input.ExpiresAt,
 }
 if err=h.ReadPolicy.Decide(r.Context(),d,proof);err!=nil{denied(w);return}
 result:="ACTIVE"
 if input.Action==pgcapability.Revoke{result="REVOKED"}
 respond(w,map[string]string{"state":result,"scope":"DISCOVERY_READ_ONLY","deviceOperations":"DISABLED"})
}
