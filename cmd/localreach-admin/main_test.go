package main

import (
 "bytes"
 "context"
 "crypto/tls"
 "errors"
 "net/http"
 "os"
 "path/filepath"
 "testing"
 "github.com/SanamRai001/localReach/internal/agentkeys"
)
func TestAdministratorCLIRefusesImplicitOrMixedIdentity(t *testing.T){
 ctx:=context.Background()
 out:=new(bytes.Buffer)
 for _,args:=range [][]string{
  {},
  {"unknown"},
  {"invite"},
  {"approve"},
  {"init"},
  {"init","-identity-dir",filepath.Join(t.TempDir(),"new"),"-organization","org"},
  {"approve","-identity-dir",t.TempDir(),"-organization","org","-gateway","http://unsafe","-admin","owner","-request","x"},
 }{
  if err:=run(ctx,args,bytes.NewBuffer(nil),out);err==nil{t.Fatalf("accepted unsafe args: %q",args)}
 }
 if def,err:=agentkeys.DefaultDir();err==nil{
  if err=run(ctx,[]string{"init","-identity-dir",def},bytes.NewBuffer(nil),out);err==nil{
   t.Fatal("agent identity directory reused as admin key")
  }
 }
 dir:=filepath.Join(t.TempDir(),"uninitialized")
 if err:=run(ctx,[]string{"review","-identity-dir",dir,"-gateway","https://example.org","-organization","org","-admin","owner","-request","r"},
 bytes.NewBuffer(nil),out);err==nil{t.Fatal("review automatically generated missing signing key")}
 if _,err:=os.Stat(dir);!errors.Is(err,os.ErrNotExist){t.Fatal("unexpected native identity creation")}
}
func TestAdminTLSNeverDisablesServerVerification(t *testing.T){
 tr,ok:=trustedClient().Transport.(*http.Transport)
 if !ok||tr.TLSClientConfig==nil||tr.TLSClientConfig.InsecureSkipVerify||
 tr.TLSClientConfig.MinVersion<tls.VersionTLS12{t.Fatal("TLS certificate verification disabled")}
}
