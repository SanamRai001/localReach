package localdashboard

import (
 "net/http/httptest"
 "os"
 "strings"
 "testing"

 "github.com/SanamRai001/localReach/internal/localsetup"
)
func TestActualDashboardFilesAreServedAndTourIsGone(t *testing.T){
 assets:=os.DirFS("../../web/setup")
 h,err:=NewHandler(assets,New(nil,nil,""))
 if err!=nil{t.Fatal(err)}
 for _,item:=range []struct{path,want string}{
  {"/","Find your devices"},
  {"/style.css",".workspace-card"},
  {"/setup.js","/v1/local/discover"},
 }{
  r:=httptest.NewRequest("GET",localsetup.Origin+item.path,nil)
  r.RemoteAddr="127.0.0.1:42211"
  w:=httptest.NewRecorder()
  h.ServeHTTP(w,r)
  if w.Code!=200||!strings.Contains(w.Body.String(),item.want){
   t.Fatalf("real asset %s unavailable: code=%d",item.path,w.Code)
  }
  if item.path=="/"&&(strings.Contains(w.Body.String(),"id=\"next\"")||strings.Contains(w.Body.String(),"mock only")){
   t.Fatal("old looping preview is still deployed")
  }
 }
}
