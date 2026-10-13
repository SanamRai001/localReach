// Package localsetup serves the static preview and non-secret status on a
// strict loopback origin. There are NO pairing or device mutation endpoints.
package localsetup

import (
 "io/fs"
 "net"
 "net/http"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/localstatus"
)
const Address="127.0.0.1:18788"
const Origin="http://"+Address
func Handler(site fs.FS, status func()localstatus.Snapshot)http.Handler{
 files:=http.FileServer(http.FS(site))
 state:=localstatus.Handler(status)
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("X-Content-Type-Options","nosniff")
  w.Header().Set("Referrer-Policy","no-referrer")
  w.Header().Set("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
  w.Header().Set("Cache-Control","no-store")
  if r.Host!=Address{http.Error(w,"invalid host",403);return}
  host,_,err:=net.SplitHostPort(r.RemoteAddr)
  if err!=nil||net.ParseIP(host)==nil||!net.ParseIP(host).IsLoopback(){http.Error(w,"local only",403);return}
  if origin:=r.Header.Get("Origin");origin!=""&&!strings.EqualFold(origin,Origin){http.Error(w,"invalid origin",403);return}
  if r.Method!="GET"&&r.Method!="HEAD"{http.Error(w,"read only",405);return}
  if r.URL.Path=="/v1/local/status"{
   if r.Method!="GET"{http.Error(w,"read only",405);return}
   state.ServeHTTP(w,r);return
  }
  if r.URL.Path=="/"{http.Redirect(w,r,"/index.html",http.StatusTemporaryRedirect);return}
  if r.URL.Path!="/index.html"&&r.URL.Path!="/style.css"&&r.URL.Path!="/setup.js"{http.NotFound(w,r);return}
  files.ServeHTTP(w,r)
 })
}
func Serve(site fs.FS,status func()localstatus.Snapshot)error{
 listener,err:=net.Listen("tcp",Address)
 if err!=nil{return err}
 defer listener.Close()
 server:=&http.Server{Handler:Handler(site,status),ReadHeaderTimeout:5*time.Second,IdleTimeout:30*time.Second,MaxHeaderBytes:8192}
 return server.Serve(listener)
}
