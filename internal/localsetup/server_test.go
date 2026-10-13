package localsetup
import(
 "net/http/httptest"
 "strings"
 "testing"
 "testing/fstest"
)
func TestStrictHostPeerAndReadOnly(t *testing.T){
 site:=fstest.MapFS{"index.html":&fstest.MapFile{Data:[]byte("<p>LocalReach</p>")}}
 h:=Handler(site,nil)
 cases:=[]struct{host,remote,origin,method,path string;want int}{
  {Address,"127.0.0.1:4567","","GET","/v1/local/status",200},
  {"evil.example","127.0.0.1:4567","","GET","/v1/local/status",403},
  {Address,"203.0.113.4:80","","GET","/v1/local/status",403},
  {Address,"127.0.0.1:4567","http://evil.example","GET","/v1/local/status",403},
  {Address,"127.0.0.1:4567","","POST","/v1/local/status",405},
  {Address,"127.0.0.1:4567","","GET","/index.html",200},
  {Address,"127.0.0.1:4567","","GET","/private.txt",404},
 }
 for _,tc:=range cases{
  req:=httptest.NewRequest(tc.method,Origin+tc.path,strings.NewReader(""))
  req.Host=tc.host;req.RemoteAddr=tc.remote;req.Header.Set("Origin",tc.origin)
  w:=httptest.NewRecorder();h.ServeHTTP(w,req)
  if w.Code!=tc.want{t.Fatalf("%+v: got %d want %d",tc,w.Code,tc.want)}
 }
}
