package main

import (
 "context"
 "strings"
 "testing"
)
func TestControlPlaneRequiresSecureExplicitConfiguration(t *testing.T){
 tests:=[]struct{dsn string;allow bool;want bool}{
  {"",false,false},
  {"http://user:pass@example.org/db",false,false},
  {"postgres://user:pass@database.internal:5432/localreach?sslmode=disable",true,false},
  {"postgres://user:pass@database.internal:5432/localreach?sslmode=require",false,false},
  {"postgres://user:pass@database.internal:5432/localreach?sslmode=verify-full",false,true},
  {"postgres://user:pass@127.0.0.1/localreach_test?sslmode=disable",false,false},
  {"postgres://user:pass@127.0.0.1/localreach_test?sslmode=disable",true,true},
  {"postgres://user:pass@127.0.0.1/production?sslmode=disable",true,false},
 }
 for _,tc:=range tests{
  got:=validateDSN(tc.dsn,tc.allow)==nil
  if got!=tc.want{t.Errorf("config allow=%v accepted=%v want=%v",tc.allow,got,tc.want)}
 }
 if listenAddress!="127.0.0.1:19443"{t.Fatal("control plane must bind only loopback")}
}
func TestControlPlaneNeverStartsWithoutTLSKeys(t *testing.T){
 if err:=run(context.Background(),[]string{});err==nil{t.Fatal("missing operator certificate accepted")}
 if err:=run(context.Background(),[]string{"-tls-cert","missing.pem"});err==nil{t.Fatal("missing key accepted")}
 if err:=run(context.Background(),[]string{"-unknown"});err==nil{t.Fatal("unknown flag accepted")}
 if err:=run(context.Background(),[]string{"extra"});err==nil{t.Fatal("unexpected positional argument accepted")}
 if err:=validateDSN("postgres://user:pass@public.example.org/prod?sslmode=disable",true);err==nil||!strings.Contains(err.Error(),"TLS"){t.Fatal("remote plaintext PostgreSQL accepted")}
}

func TestStagingRequiresExplicitFlagRestrictedCIDRAndTLS(t *testing.T){
 ctx:=context.Background()
 cases:=[]struct{args []string;contains string}{
  {[]string{"-staging-listen","0.0.0.0:19443","-staging-dns","pilot.example.test","-staging-peer-cidrs","203.0.113.4/32"},"require"},
  {[]string{"-enable-restricted-staging"},""},
  {[]string{"-enable-restricted-staging","-allow-disposable-loopback-db","-staging-listen","0.0.0.0:19443",
    "-staging-dns","pilot.example.test","-staging-peer-cidrs","203.0.113.4/32"},"forbids"},
  {[]string{"-enable-restricted-staging","-staging-listen","0.0.0.0:19443",
    "-staging-dns","pilot.example.test","-staging-peer-cidrs","0.0.0.0/0"},""},
  {[]string{"-enable-restricted-staging","-staging-listen","0.0.0.0:19443",
    "-staging-dns","pilot.example.test","-staging-peer-cidrs","203.0.113.4/32"},"TLS"},
 }
 for _,tc:=range cases{
  err:=run(ctx,tc.args)
  if err==nil{t.Fatalf("unsafe staging startup admitted: %q",tc.args)}
  if tc.contains!=""&&!strings.Contains(err.Error(),tc.contains){
   t.Fatalf("wrong rejection (%v): %v",tc.args,err)
  }
 }
}
