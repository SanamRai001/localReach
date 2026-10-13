package localstatus
import("net/http/httptest";"strings";"testing")
func TestStatusIsLocalOnlyAndReadOnly(t *testing.T){
 h:=Handler(nil)
 cases:=[]struct{method,path,remote,origin string;want int}{
  {"GET","/v1/local/status","127.0.0.1:3456","",200},
  {"GET","/v1/local/status","203.0.113.4:90","",403},
  {"POST","/v1/local/status","127.0.0.1:3456","",405},
  {"GET","/v1/local/status","127.0.0.1:3456","https://evil.example",403},
  {"GET","/v1/local/status","127.0.0.1:3456","http://127.0.0.1:18788",200},
 }
 for _,tc:=range cases{
  r:=httptest.NewRequest(tc.method,"http://127.0.0.1:18788"+tc.path,strings.NewReader(""))
  r.RemoteAddr=tc.remote;r.Header.Set("Origin",tc.origin)
  w:=httptest.NewRecorder();h.ServeHTTP(w,r)
  if w.Code!=tc.want{t.Fatalf("%+v returned %d",tc,w.Code)}
 }
}
