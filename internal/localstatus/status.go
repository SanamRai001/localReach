// Package localstatus exposes only non-secret local setup state.
// This handler has no pairing, enrollment, admin or device-control mutation.
package localstatus

import (
 "encoding/json"
 "net"
 "net/http"
 "strings"
)
type Snapshot struct {
 Agent string `json:"agent"`
 Pairing string `json:"pairing"`
 Connection string `json:"connection"`
 Devices string `json:"devices"`
 Verification string `json:"verification,omitempty"`
 LastVerifiedAt string `json:"lastVerifiedAt,omitempty"`
}
func Default() Snapshot{return Snapshot{Agent:"RUNNING",Pairing:"NOT_PAIRED",Connection:"OFFLINE",Devices:"NOT_DISCOVERED",Verification:"NOT_CHECKED"}}
func Handler(snapshot func()Snapshot)http.Handler{
 if snapshot==nil{snapshot=Default}
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("X-Content-Type-Options","nosniff")
  // Require a directly connected loopback client. Reverse proxies do not
  // count as permission to expose the local status API remotely.
  host,_,err:=net.SplitHostPort(r.RemoteAddr)
  if err!=nil||net.ParseIP(host)==nil||!net.ParseIP(host).IsLoopback(){http.Error(w,"local only",403);return}
  if r.URL.Path!="/v1/local/status"{http.NotFound(w,r);return}
  if r.Method!="GET"{http.Error(w,"method not allowed",405);return}
  origin:=r.Header.Get("Origin")
  if origin!=""&&!allowedOrigin(origin){http.Error(w,"origin denied",403);return}
  w.Header().Set("Content-Type","application/json")
  _=json.NewEncoder(w).Encode(snapshot())
 })
}
func allowedOrigin(origin string)bool{
 // Only the dedicated local setup origin is allowed; no wildcard CORS.
 return strings.EqualFold(origin,"http://127.0.0.1:18788")
}
