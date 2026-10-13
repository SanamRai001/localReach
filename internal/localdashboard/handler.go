package localdashboard

import (
 "context"
 "crypto/rand"
 "crypto/subtle"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "io/fs"
 "mime"
 "net"
 "net/http"
 "time"

 "github.com/SanamRai001/localReach/internal/localsetup"
)

type Dashboard struct{service *Service;token string;site http.Handler}
func NewHandler(site fs.FS,svc *Service)(http.Handler,error){
 if svc==nil{return nil,errors.New("dashboard service is required")}
 secret:=make([]byte,32)
 if _,err:=rand.Read(secret);err!=nil{return nil,err}
 return &Dashboard{service:svc,token:base64.RawURLEncoding.EncodeToString(secret),
 site:localsetup.Handler(site,svc.Snapshot)},nil
}
func localPeer(r *http.Request)bool{
 if r.Host!=localsetup.Address{return false}
 host,_,err:=net.SplitHostPort(r.RemoteAddr)
 if err!=nil{return false}
 ip:=net.ParseIP(host)
 return ip!=nil&&ip.IsLoopback()
}
func reply(w http.ResponseWriter,status int,data any){
 w.Header().Set("Content-Type","application/json; charset=utf-8")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(data)
}
func problem(w http.ResponseWriter,status int,code,message string){
 reply(w,status,map[string]string{"code":code,"error":message})
}
func sameOrigin(r *http.Request)bool{
 return r.Header.Get("Origin")==localsetup.Origin &&
 r.Header.Get("Cookie")=="" &&
 (r.Header.Get("Sec-Fetch-Site")==""||r.Header.Get("Sec-Fetch-Site")=="same-origin")
}
func validToken(provided,expected string)bool{
 if len(provided)!=len(expected){return false}
 return subtle.ConstantTimeCompare([]byte(provided),[]byte(expected))==1
}
func decode(w http.ResponseWriter,r *http.Request,target any)bool{
 contentType,_,err:=mime.ParseMediaType(r.Header.Get("Content-Type"))
 if err!=nil||contentType!="application/json"{
  problem(w,415,"JSON_REQUIRED","Send a JSON request from the LocalReach dashboard.")
  return false
 }
 r.Body=http.MaxBytesReader(w,r.Body,1024)
 decoder:=json.NewDecoder(r.Body)
 decoder.DisallowUnknownFields()
 if err=decoder.Decode(target);err!=nil{
  problem(w,400,"INVALID_BODY","Request body is missing or invalid.")
  return false
 }
 var extra any
 if decoder.Decode(&extra)!=io.EOF{
  problem(w,400,"INVALID_BODY","Unexpected additional request body.")
  return false
 }
 return true
}
func(s *Dashboard)ServeHTTP(w http.ResponseWriter,r *http.Request){
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("X-Content-Type-Options","nosniff")
 w.Header().Set("Referrer-Policy","no-referrer")
 w.Header().Set("Content-Security-Policy","default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
 if !localPeer(r){http.Error(w,"local only",403);return}
 switch r.URL.Path{
 case "/v1/local/dashboard":
  if r.Method!="GET"{http.Error(w,"method not allowed",405);return}
  if o:=r.Header.Get("Origin");o!=""&&o!=localsetup.Origin{http.Error(w,"wrong origin",403);return}
  reply(w,200,s.service.Status())
  return
 case "/v1/local/bootstrap":
  if r.Method!="GET"{http.Error(w,"method not allowed",405);return}
  if o:=r.Header.Get("Origin");o!=""&&o!=localsetup.Origin{http.Error(w,"wrong origin",403);return}
  reply(w,200,map[string]any{"csrfToken":s.token,"status":s.service.Status()})
  return
 case "/v1/local/initialize","/v1/local/discover","/v1/local/request","/v1/local/finish","/v1/local/reconnect":
  if r.Method!="POST"{http.Error(w,"method not allowed",405);return}
  if !sameOrigin(r)||!validToken(r.Header.Get("X-LocalReach-Token"),s.token){
   problem(w,403,"LOCAL_APPROVAL_REQUIRED","This action requires the trusted LocalReach page.")
   return
  }
  s.action(w,r)
  return
 default:
  s.site.ServeHTTP(w,r)
 }
}
func(s *Dashboard)action(w http.ResponseWriter,r *http.Request){
 ctx,cancel:=context.WithTimeout(r.Context(),18*time.Second)
 defer cancel()
 switch r.URL.Path{
 case "/v1/local/initialize":
  var input struct{}
  if !decode(w,r,&input){return}
  fingerprint,err:=s.service.Initialize()
  if err!=nil{s.failure(w,err);return}
  reply(w,200,map[string]any{"fingerprint":fingerprint,"status":s.service.Status()})
 case "/v1/local/discover":
  var input struct{Seconds int `json:"seconds"`}
  if !decode(w,r,&input){return}
  if input.Seconds<1||input.Seconds>15{
   problem(w,400,"INVALID_DURATION","Choose between 1 and 15 seconds.")
   return
  }
  entries,err:=s.service.DiscoverLocal(ctx,time.Duration(input.Seconds)*time.Second)
  if err!=nil{s.failure(w,err);return}
  reply(w,200,map[string]any{"candidates":entries,"status":s.service.Status()})
 case "/v1/local/request":
  var input struct{Invitation string `json:"invitation"`}
  if !decode(w,r,&input){return}
  id,err:=s.service.Request(ctx,input.Invitation)
  if err!=nil{s.failure(w,err);return}
  reply(w,200,map[string]any{"requestId":id,"state":"PENDING_APPROVAL","status":s.service.Status()})
 case "/v1/local/finish":
  var input struct{}
  if !decode(w,r,&input){return}
  if err:=s.service.Finish(ctx);err!=nil{s.failure(w,err);return}
  reply(w,200,map[string]any{"message":"Enrollment confirmed; connecting stream.","status":s.service.Status()})
 case "/v1/local/reconnect":
  var input struct{}
  if !decode(w,r,&input){return}
  if err:=s.service.Reconnect(ctx);err!=nil{s.failure(w,err);return}
  reply(w,200,map[string]any{"message":"Identity verified. Connecting stream.","status":s.service.Status()})
 }
}
func(s *Dashboard)failure(w http.ResponseWriter,err error){
 switch {
 case errors.Is(err,ErrBusy):problem(w,409,"BUSY","Another operation is in progress.")
 case errors.Is(err,ErrUnavailable):problem(w,409,"GATEWAY_NOT_CONFIGURED","No trusted cloud gateway is configured. Restart setup with -gateway and -organization when you have an approved server.")
 case errors.Is(err,ErrNoIdentity):problem(w,409,"NO_IDENTITY",err.Error())
 case errors.Is(err,ErrNoRequest),errors.Is(err,ErrPending):problem(w,409,"PAIRING_STATE",err.Error())
 case errors.Is(err,ErrInvalid):problem(w,400,"INVALID_INVITATION","The invitation code is invalid.")
 default:problem(w,502,"OPERATION_FAILED","The operation could not complete. Check your secure key store, network and administrator approval.")
 }
}
func ServeContext(ctx context.Context,site fs.FS,svc *Service)error{
 handler,err:=NewHandler(site,svc)
 if err!=nil{return err}
 listener,err:=net.Listen("tcp",localsetup.Address)
 if err!=nil{return err}
 defer listener.Close()
 server:=&http.Server{
  Handler:handler,ReadHeaderTimeout:5*time.Second,
  ReadTimeout:25*time.Second,WriteTimeout:25*time.Second,
  IdleTimeout:30*time.Second,MaxHeaderBytes:8192,
 }
 finished:=make(chan struct{})
 go func(){
  select{
  case <-ctx.Done():
   closeCtx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
   defer cancel()
   _=server.Shutdown(closeCtx)
  case <-finished:
  }
 }()
 err=server.Serve(listener)
 close(finished)
 if errors.Is(err,http.ErrServerClosed){return nil}
 return err
}
