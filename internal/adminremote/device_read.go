package adminremote

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "encoding/hex"
 "time"

 "github.com/SanamRai001/localReach/internal/pgcapability"
)
// DecideDiscoveryRead signs a completely separate, narrowly scoped
// permission decision. It does NOT enable a physical read or write command:
// R2K.1 only stores auditable discovery policy for future guarded APIs.
func(c Client)DecideDiscoveryRead(ctx context.Context,session string,d pgcapability.Decision,s Signer)error{
 if session==""||!validSigner(s)||!validScope(d.Organization,d.AdminID)||
 d.Site==""||d.AgentID==""||len(d.DeviceFingerprint)!=64||
 (d.Capability!=pgcapability.PrinterDiscovery&&d.Capability!=pgcapability.AttendanceDiscovery)||
 (d.Action!=pgcapability.Grant&&d.Action!=pgcapability.Revoke){return ErrDenied}
 raw,err:=hex.DecodeString(d.DeviceFingerprint)
 if err!=nil||len(raw)!=32||hex.EncodeToString(raw)!=d.DeviceFingerprint{return ErrDenied}
 nonce:=make([]byte,32)
 if _,err=rand.Read(nonce);err!=nil{return ErrDenied}
 d.Nonce=base64.RawURLEncoding.EncodeToString(nonce)
 d.IssuedAt=time.Now().Unix()
 d.ExpiresAt=d.IssuedAt+60
 proof,err:=s.SignMessage(pgcapability.Message(d))
 if err!=nil||len(proof)!=ed25519.SignatureSize{return ErrDenied}
 var result struct{
  State string `json:"state"`
  Scope string `json:"scope"`
  DeviceOperations string `json:"deviceOperations"`
 }
 if err=c.post(ctx,"/v1/control/device-read-decision",session,map[string]any{
  "organization":d.Organization,"site":d.Site,"agentId":d.AgentID,
  "deviceFingerprint":d.DeviceFingerprint,"capability":d.Capability,
  "adminId":d.AdminID,"action":d.Action,"nonce":d.Nonce,
  "issuedAt":d.IssuedAt,"expiresAt":d.ExpiresAt,
  "signature":base64.RawURLEncoding.EncodeToString(proof),
 },&result);err!=nil{return ErrDenied}
 state:="ACTIVE"
 if d.Action==pgcapability.Revoke{state="REVOKED"}
 if result.State!=state||result.Scope!="DISCOVERY_READ_ONLY"||
 result.DeviceOperations!="DISABLED"{return ErrDenied}
 return nil
}
