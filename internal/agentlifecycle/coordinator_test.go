package agentlifecycle

import(
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "encoding/base64"
 "database/sql"
 "bytes"
 "errors"
 "testing"

 "github.com/SanamRai001/localReach/internal/pgpairing"
)
type testSigner struct{public ed25519.PublicKey;private ed25519.PrivateKey;deny bool}
func newSigner(t *testing.T)*testSigner{
 t.Helper();pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{t.Fatal(err)}
 return &testSigner{public:pub,private:priv}
}
func(s *testSigner)PublicKey()ed25519.PublicKey{return append(ed25519.PublicKey(nil),s.public...)}
func(s *testSigner)SignMessage(m []byte)([]byte,error){
 if s.deny{return nil,errors.New("native store inaccessible")}
 return ed25519.Sign(s.private,m),nil
}
type fakeBackend struct{
 expected ed25519.PublicKey
 approved bool
 enrolled bool
 revoked bool
 nonce string
 calls int
}
func(b *fakeBackend)Propose(_ context.Context,org,site string,pub ed25519.PublicKey)(pgpairing.Record,error){
 if org!="org"||site!="site"||b.expected!=nil{return pgpairing.Record{},ErrDenied}
 b.expected=append(ed25519.PublicKey(nil),pub...)
 return pgpairing.Record{Organization:org,RequestID:"req",Site:site,State:"PENDING"},nil
}
func(b *fakeBackend)Challenge(_ context.Context,org,id string)(string,error){
 if org!="org"||id!="req"||!b.approved{return "",ErrDenied}
 b.calls++
 return b.nonce,nil
}
func(b *fakeBackend)Enroll(_ context.Context,org,id,nonce string,sig []byte)(pgpairing.Record,error){
 if org!="org"||id!="req"||nonce!=b.nonce||!ed25519.Verify(b.expected,pgpairing.EnrollmentMessage(org,id,nonce),sig){return pgpairing.Record{},ErrDenied}
 b.enrolled=true
 return pgpairing.Record{Organization:org,RequestID:id,State:"ENROLLED",AgentID:sqlNullString("agent")},nil
}
func(b *fakeBackend)ResolveIdentity(_ context.Context,org string,pub ed25519.PublicKey)(string,error){
 if org!="org"||!b.enrolled||b.revoked||!bytes.Equal(b.expected,pub){return "",ErrDenied}
 return "agent",nil
}
func(b *fakeBackend)BeginResume(_ context.Context,org,id string)(string,error){
 if org!="org"||id!="agent"||b.revoked{return "",ErrDenied}
 return b.nonce,nil
}
func(b *fakeBackend)VerifyResume(_ context.Context,org,id,nonce string,sig []byte)error{
 if org!="org"||id!="agent"||nonce!=b.nonce||b.revoked||
 !ed25519.Verify(b.expected,pgpairing.ResumeMessage(org,id,nonce),sig){return ErrDenied}
 return nil
}
func sqlNullString(s string)sql.NullString{return sql.NullString{String:s,Valid:true}}
func TestNativeSignerRequiresAdminApprovalAndChecksRecovery(t *testing.T){
 signer:=newSigner(t)
 nonce:=base64.RawURLEncoding.EncodeToString(make([]byte,32))
 backend:=&fakeBackend{nonce:nonce}
 c:=Coordinator{Backend:backend}
 if _,err:=c.FinishPairing(context.Background(),"org","req",signer);!errors.Is(err,ErrDenied){t.Fatal("enrollment without approval")}
 req,err:=c.RequestPairing(context.Background(),"org","site",signer)
 if err!=nil||req.State!="PENDING"{t.Fatal("proposal failed")}
 if _,err=c.FinishPairing(context.Background(),"org","req",signer);!errors.Is(err,ErrDenied){t.Fatal("enrollment without approval")}
 backend.approved=true
 wrong:=newSigner(t)
 if _,err=c.FinishPairing(context.Background(),"org","req",wrong);!errors.Is(err,ErrDenied){t.Fatal("wrong-key enrollment accepted")}
 record,err:=c.FinishPairing(context.Background(),"org","req",signer)
 if err!=nil||record.AgentID.String!="agent"{t.Fatalf("enrollment failed: %v",err)}
 if _,err=c.VerifySavedIdentity(context.Background(),"other",signer);!errors.Is(err,ErrDenied){t.Fatal("cross-org recovery")}
 if _,err=c.VerifySavedIdentity(context.Background(),"org",wrong);!errors.Is(err,ErrDenied){t.Fatal("wrong-key recovery")}
 restored,err:=c.VerifySavedIdentity(context.Background(),"org",signer)
 if err!=nil||restored!="agent"{t.Fatalf("existing key not verified: %v",err)}
 backend.revoked=true
 if _,err=c.VerifySavedIdentity(context.Background(),"org",signer);!errors.Is(err,ErrDenied){t.Fatal("revoked key recovered")}
}
func TestSignerUnavailableNeverCausesNewIdentity(t *testing.T){
 signer:=newSigner(t)
 backend:=&fakeBackend{nonce:base64.RawURLEncoding.EncodeToString(make([]byte,32))}
 c:=Coordinator{Backend:backend}
 _,err:=c.RequestPairing(context.Background(),"org","site",signer);if err!=nil{t.Fatal(err)}
 backend.approved=true;signer.deny=true
 if _,err=c.FinishPairing(context.Background(),"org","req",signer);!errors.Is(err,ErrDenied){t.Fatal("native signer failure allowed enrollment")}
 if backend.enrolled{t.Fatal("unexpected enrolled identity")}
}
