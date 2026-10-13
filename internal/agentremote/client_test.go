package agentremote

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "errors"
 "net/http"
 "net/http/httptest"
 "testing"
)
type fixedSigner struct{pub ed25519.PublicKey;private ed25519.PrivateKey}
func(s *fixedSigner)PublicKey()ed25519.PublicKey{return s.pub}
func(s *fixedSigner)SignMessage(b []byte)([]byte,error){return ed25519.Sign(s.private,b),nil}
func TestRejectPlaintextAndMissingTLSClient(t *testing.T){
 if _,err:=New("http://example.com",http.DefaultClient);!errors.Is(err,ErrDenied){t.Fatal("plaintext URL accepted")}
 if _,err:=New("https://example.com",nil);!errors.Is(err,ErrDenied){t.Fatal("missing configured trust client accepted")}
 if _,err:=New("https://user:pass@example.com",http.DefaultClient);!errors.Is(err,ErrDenied){t.Fatal("URL embedded credentials")}
 if _,err:=New("https://example.com/path",http.DefaultClient);!errors.Is(err,ErrDenied){t.Fatal("base path injection")}
 if _,err:=New("https://example.com/?token=secret",http.DefaultClient);!errors.Is(err,ErrDenied){t.Fatal("query embedded credential")}
}
func TestRedirectNeverLeaksOrDowngradesEnrollment(t *testing.T){
 redirect:=httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  http.Redirect(w,r,"http://127.0.0.1:18888/stolen",http.StatusTemporaryRedirect)
 }))
 defer redirect.Close()
 c,err:=New(redirect.URL,redirect.Client())
 if err!=nil{t.Fatal(err)}
 pub,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 if _,err=c.FinishEnrollment(context.Background(),"org","request",&fixedSigner{pub,private});!errors.Is(err,ErrDenied){t.Fatal("redirect accepted")}
}
