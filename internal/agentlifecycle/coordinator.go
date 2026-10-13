// Package agentlifecycle binds a native OS-protected agent signing identity
// to the transactional pairing backend. It does not expose a public API.
package agentlifecycle

import (
 "context"
 "crypto/ed25519"
 "errors"

 "github.com/SanamRai001/localReach/internal/pgpairing"
)

var ErrDenied=errors.New("native agent enrollment or identity verification denied")

// Signer is implemented by *agentkeys.Identity. The native agent must never
// expose this interface or arbitrary signing operations over HTTP or IPC.
type Signer interface {
 PublicKey()ed25519.PublicKey
 SignMessage([]byte)([]byte,error)
}

// Backend is a server-side contract. Database credentials MUST remain at
// the server and never be embedded in native agent distributions.
type Backend interface{
 Propose(context.Context,string,string,ed25519.PublicKey)(pgpairing.Record,error)
 Challenge(context.Context,string,string)(string,error)
 Enroll(context.Context,string,string,string,[]byte)(pgpairing.Record,error)
 ResolveIdentity(context.Context,string,ed25519.PublicKey)(string,error)
 BeginResume(context.Context,string,string)(string,error)
 VerifyResume(context.Context,string,string,string,[]byte)error
}

type Coordinator struct{Backend Backend}
func validSigner(i Signer)bool{return i!=nil&&len(i.PublicKey())==ed25519.PublicKeySize}

// RequestPairing records an agent's public key for a separately authenticated,
// rate-limited proposal intake. It does NOT approve the pairing. Native
// identity creation is an explicit independent user action, not automatic.
func(c Coordinator)RequestPairing(ctx context.Context,org,site string,i Signer)(pgpairing.Record,error){
 if c.Backend==nil||!validSigner(i){return pgpairing.Record{},ErrDenied}
 req,err:=c.Backend.Propose(ctx,org,site,i.PublicKey())
 if err!=nil{return pgpairing.Record{},ErrDenied}
 return req,nil
}

// FinishPairing is usable only AFTER independent tenant administrator
// approval. A fresh one-use server challenge and native Ed25519 signature
// bind enrollment to the originally proposed key.
func(c Coordinator)FinishPairing(ctx context.Context,org,requestID string,i Signer)(pgpairing.Record,error){
 if c.Backend==nil||!validSigner(i){return pgpairing.Record{},ErrDenied}
 nonce,err:=c.Backend.Challenge(ctx,org,requestID)
 if err!=nil{return pgpairing.Record{},ErrDenied}
 proof,err:=i.SignMessage(pgpairing.EnrollmentMessage(org,requestID,nonce))
 if err!=nil{return pgpairing.Record{},ErrDenied}
 record,err:=c.Backend.Enroll(ctx,org,requestID,nonce,proof)
 if err!=nil||record.State!="ENROLLED"||!record.AgentID.Valid{return pgpairing.Record{},ErrDenied}
 return record,nil
}

// VerifySavedIdentity is invoked after an explicit Load of the existing
// OS-protected native key. It resolves the enrolled agent, proves possession
// with a short-lived one-use challenge, and returns only its scoped agent ID.
// It does NOT create a command session or grant any capability.
func(c Coordinator)VerifySavedIdentity(ctx context.Context,org string,i Signer)(string,error){
 if c.Backend==nil||!validSigner(i){return "",ErrDenied}
 agentID,err:=c.Backend.ResolveIdentity(ctx,org,i.PublicKey())
 if err!=nil||agentID==""{return "",ErrDenied}
 nonce,err:=c.Backend.BeginResume(ctx,org,agentID)
 if err!=nil{return "",ErrDenied}
 proof,err:=i.SignMessage(pgpairing.ResumeMessage(org,agentID,nonce))
 if err!=nil{return "",ErrDenied}
 if err:=c.Backend.VerifyResume(ctx,org,agentID,nonce,proof);err!=nil{return "",ErrDenied}
 return agentID,nil
}
