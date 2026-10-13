package staginggate

import (
 "crypto/tls"
 "net"
 "time"
 "net/http"
 "net/http/httptest"
 "testing"
)
func gate(t *testing.T)*Gate{
 t.Helper()
 g,err:=New("0.0.0.0:19443","pilot.example.test","127.0.0.1/32,203.0.113.4/32")
 if err!=nil{t.Fatal(err)}
 return g
}
func TestExplicitStagingSettingsRejectUnsafeConfiguration(t *testing.T){
 for _,tc:=range []struct{address,host,cidrs string}{
  {"0.0.0.0:19443","pilot.example.test",""},
  {"0.0.0.0:19443","pilot.example.test","0.0.0.0/0"},
  {"0.0.0.0:19443","pilot.example.test","203.0.0.0/16"},
  {"0.0.0.0:19443","pilot.example.test","::/0"},
  {"0.0.0.0:19443","pilot.example.test","127.0.0.1/32,"},
  {"0.0.0.0:19443","UPPER.example.test","127.0.0.1/32"},
  {"0.0.0.0:19443","pilot.example.test:19443","127.0.0.1/32"},
  {"0.0.0.0:19443","pilot..example.test","127.0.0.1/32"},
  {"0.0.0.0:80","pilot.example.test","127.0.0.1/32"},
  {"example.test:19443","pilot.example.test","127.0.0.1/32"},
  {"0.0.0.0:19443","pilot.example.test","not-an-IP"},
 }{
  if _,err:=New(tc.address,tc.host,tc.cidrs);err==nil{
   t.Fatalf("unsafe staging config accepted: %+v",tc)
  }
 }
}
func request() *http.Request{
 r:=httptest.NewRequest("POST","https://pilot.example.test:19443/v1/agent/resume-verify",nil)
 r.Host="pilot.example.test:19443"
 r.RemoteAddr="127.0.0.1:55555"
 r.TLS=&tls.ConnectionState{Version:tls.VersionTLS13,ServerName:"pilot.example.test"}
 return r
}
func TestGateUsesDirectPeerTLSAndExactHost(t *testing.T){
 g:=gate(t)
 count:=0
 h:=g.Wrap(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){count++;w.WriteHeader(204)}))
 check:=func(r *http.Request,want int){
  t.Helper()
  response:=httptest.NewRecorder()
  h.ServeHTTP(response,r)
  if response.Code!=want{t.Fatalf("status %d expected %d",response.Code,want)}
 }
 check(request(),204)
 r:=request();r.RemoteAddr="203.0.113.9:3333"
 r.Header.Set("X-Forwarded-For","127.0.0.1")
 check(r,403)
 r=request();r.RemoteAddr="203.0.113.4:3333";check(r,204)
 r=request();r.TLS.ServerName="attacker.example.test";check(r,421)
 r=request();r.Host="other.example.test:19443";check(r,421)
 r=request();r.TLS=nil;check(r,426)
 r=request();r.TLS.Version=tls.VersionTLS12;check(r,426)
 r=request();r.RemoteAddr="unknown";check(r,403)
 if count!=2{t.Fatalf("unexpected %d admitted requests",count)}
}
func TestStagingFailsClosedUnderConcurrencyPressure(t *testing.T){
 g:=gate(t)
 h:=g.Wrap(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.WriteHeader(204)}))
 for i:=0;i<cap(g.slots);i++{g.slots<-struct{}{}}
 result:=httptest.NewRecorder()
 h.ServeHTTP(result,request())
 if result.Code!=503{t.Fatalf("full concurrency limit accepted: %d",result.Code)}
 for i:=0;i<cap(g.slots);i++{<-g.slots}
}
func TestFilteredListenerAllowsExplicitPeer(t *testing.T){
 g:=gate(t)
 listener,err:=net.Listen("tcp","127.0.0.1:0")
 if err!=nil{t.Fatal(err)}
 filtered:=g.FilterListener(listener)
 defer filtered.Close()
 done:=make(chan error,1)
 go func(){
  c,err:=filtered.Accept()
  if err==nil{_ = c.Close()}
  done<-err
 }()
 c,err:=net.Dial("tcp",listener.Addr().String())
 if err!=nil{t.Fatal(err)}
 _=c.Close()
 select{
 case err=<-done:if err!=nil{t.Fatal(err)}
 case <-time.After(2*time.Second):t.Fatal("allowlisted peer not accepted")
 }
}
