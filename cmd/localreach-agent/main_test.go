package main

import(
 "context"
 "errors"
 "crypto/tls"
 "net/http"
 "os"
 "path/filepath"
 "testing"

 "github.com/SanamRai001/localReach/internal/agentkeys"
)
func TestCommandsRequireExplicitParametersAndDoNotGenerateKeys(t *testing.T){
 ctx:=context.Background()
 dir:=t.TempDir()
 cases:=[][]string{
  {},
  {"bad-command"},
  {"serve"},
  {"enroll"},
  {"init","-gateway","https://example.com","-identity-dir",dir},
  {"init","-request","abc","-identity-dir",dir},
  {"serve","-organization","org","-gateway","https://example.com","-identity-dir",dir},
  {"enroll","-organization","org","-gateway","https://example.com","-identity-dir",dir},
 }
 for _,args:=range cases{
  err:=run(ctx,args)
  if err==nil{t.Fatalf("accepted missing identity or unsafe args: %v",args)}
  if errors.Is(err,agentkeys.ErrExists){t.Fatalf("unexpected auto-create: %v",args)}
 }
 // Missing identity remains missing; no command implicitly creates one.
 items,err:=os.ReadDir(dir)
 if err!=nil{t.Fatal(err)}
 if len(items)!=0{t.Fatalf("unexpected key files were created: %v",items)}
}
func TestMalformedArgumentsFailWithoutTouchingDisk(t *testing.T){
 dir:=filepath.Join(t.TempDir(),"missing-identity")
 for _,args:=range [][]string{
  {"serve","-unknown"},
  {"enroll","-identity-dir",dir,"extra"},
  {"init","-identity-dir",dir,"-organization","abc"},
 }{
  if err:=run(context.Background(),args);err==nil{t.Fatalf("invalid args accepted: %v",args)}
 }
 if _,err:=os.Stat(dir);!errors.Is(err,os.ErrNotExist){t.Fatalf("invalid args touched identity path: %v",err)}
}
func TestTrustedClientNeverDisablesTLSValidation(t *testing.T){
 client:=trustedClient()
 if client.Timeout==0{t.Fatal("client timeout missing")}
 tr,ok:=client.Transport.(interface{Clone()*http.Transport})
 if !ok{t.Fatal("unexpected HTTP transport")}
 transport:=tr.Clone()
 if transport.TLSClientConfig==nil||transport.TLSClientConfig.InsecureSkipVerify||transport.TLSClientConfig.MinVersion<tls.VersionTLS12{
  t.Fatal("TLS validation or minimum protocol disabled")
 }
}
