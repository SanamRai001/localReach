// LocalReach native agent prototype. Start manually; NOT an installed service.
// Passive local discovery only; no printer/attendance commands or public listener.
package main

import(
 "context"
 "crypto/tls"
 "encoding/base64"
 "bufio"
 "io"
 "strings"
 "errors"
 "flag"
 "fmt"
 "log"
 "net"
 "net/http"
 "os"
 "os/signal"
 "time"

 "github.com/SanamRai001/localReach/internal/agentkeys"
 "github.com/SanamRai001/localReach/internal/agentremote"
 "github.com/SanamRai001/localReach/internal/agentservice"
 "github.com/SanamRai001/localReach/internal/localsetup"
 "github.com/SanamRai001/localReach/internal/landiscovery"
)
func trustedClient()*http.Client{
 return &http.Client{
  Timeout:10*time.Second,
  Transport:&http.Transport{
   Proxy:http.ProxyFromEnvironment,
   TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
   DialContext:(&net.Dialer{Timeout:5*time.Second,KeepAlive:30*time.Second}).DialContext,
   TLSHandshakeTimeout:5*time.Second,
   MaxIdleConnsPerHost:2,
   IdleConnTimeout:15*time.Second,
  },
 }
}
func run(ctx context.Context,args []string)error{
 if len(args)==0{return errors.New("required command: init, discover, request, enroll or serve")}
 command:=args[0]
 if command!="init"&&command!="discover"&&command!="request"&&command!="enroll"&&command!="serve"{return errors.New("unknown command (expected init, discover, request, enroll or serve)")}
 flags:=flag.NewFlagSet(command,flag.ContinueOnError)
 dir:=flags.String("identity-dir","","identity directory (defaults to user local profile)")
 gateway:=flags.String("gateway","","trusted HTTPS control-plane URL")
 org:=flags.String("organization","","organization ID")
 requestID:=flags.String("request","","administrator-approved pairing request ID")
 webDir:=flags.String("web","web/setup","static setup assets (repo-relative)")
 retry:=flags.Duration("retry",2*time.Second,"minimum reconnect delay (bounded exponential backoff)")
 discoveryDuration:=flags.Duration("duration",5*time.Second,"passive local DNS-SD listen duration (1s to 30s)")
 if err:=flags.Parse(args[1:]);err!=nil{return err}
 if flags.NArg()!=0{return errors.New("unexpected positional argument")}
 if command=="discover"{
  if *gateway!=""||*org!=""||*requestID!=""||*dir!=""{return errors.New("passive discovery accepts no credentials, organization or server")}
  if *discoveryDuration<time.Second||*discoveryDuration>30*time.Second{return errors.New("discovery duration must be 1 to 30 seconds")}
  fmt.Println("Listening passively for local printer mDNS announcements (no packets sent).")
  items,err:=landiscovery.Listen(ctx,*discoveryDuration)
  if err!=nil{return fmt.Errorf("passive discovery unavailable: %w",err)}
  if len(items)==0{fmt.Println("No announcements observed; this does not mean no printers exist.");return nil}
  for _,d:=range items{
   fmt.Printf("%s | %s | fingerprint %s | UNVERIFIED mDNS hint\n",d.Type,d.Name,d.Fingerprint)
  }
  fmt.Println("No candidates were contacted, authorized or shared with the cloud.")
  return nil
 }
 directory:=*dir
 if directory==""{
  def,err:=agentkeys.DefaultDir()
  if err!=nil{return fmt.Errorf("native key storage unavailable: %w",err)}
  directory=def
 }
 store:=agentkeys.Store{Dir:directory}
 switch command{
 case "init":
  if *gateway!=""||*org!=""||*requestID!=""{return errors.New("init accepts no gateway, organization or pairing request")}
  id,err:=store.Create()
  if err!=nil{return fmt.Errorf("cannot initialize native identity: %w",err)}
  fmt.Println("Agent identity created in the OS-protected credential store.")
  fmt.Println("Public key (safe to share with an authorized organization admin):",base64.RawURLEncoding.EncodeToString(id.PublicKey()))
  fmt.Println("Fingerprint:",id.Fingerprint())
  fmt.Println("NOT_PAIRED: an administrator must separately approve enrollment.")
  return nil
 case "request","enroll","serve":
  if *gateway==""||*org==""{return errors.New("organization and trusted HTTPS gateway are required")}
  id,err:=store.Load()
  if err!=nil{return fmt.Errorf("existing native identity required (never regenerated): %w",err)}
  remote,err:=agentremote.New(*gateway,trustedClient())
  if err!=nil{return fmt.Errorf("invalid HTTPS gateway: %w",err)}
  if command=="request"{
   if *requestID!=""{return errors.New("request does not accept an approved request ID")}
   fmt.Fprintln(os.Stderr,"Paste the short-lived administrator invitation token, then press Enter:")
   input:=bufio.NewReader(io.LimitReader(os.Stdin,256))
   secret,readErr:=input.ReadString('\n')
   if readErr!=nil&&readErr!=io.EOF{return errors.New("could not read invitation")}
   secret=strings.TrimSpace(secret)
   decoded,decodeErr:=base64.RawURLEncoding.DecodeString(secret)
   if decodeErr!=nil||len(decoded)!=32{return errors.New("invalid invitation format")}
   pending,err:=remote.RequestInvitation(ctx,*org,secret,id)
   if err!=nil{return errors.New("invitation denied or already consumed")}
   fmt.Println("PENDING_APPROVAL: request",pending)
   fmt.Println("An authorized administrator must compare the public-key fingerprint and approve separately.")
   return nil
  }
  if command=="enroll"{
   if *requestID==""{return errors.New("enroll requires an independently approved -request")}
   agentID,err:=remote.FinishEnrollment(ctx,*org,*requestID,id)
   if err!=nil{return errors.New("enrollment was not authorized or did not complete")}
   fmt.Println("ENROLLED: identity registered as agent",agentID)
   fmt.Println("No device permissions or online command session exist.")
   return nil
  }
  if *requestID!=""{return errors.New("serve does not accept an enrollment request")}
  monitor:=agentservice.NewLive(*org,id,remote)
  monitor.Retry=*retry
  ctx,cancel:=context.WithCancel(ctx)
  defer cancel()
  done:=make(chan struct{})
  go func(){monitor.Run(ctx);close(done)}()
  log.Printf("LocalReach diagnostic agent: http://%s (loopback only; NO device access)",localsetup.Address)
  err=localsetup.ServeContext(ctx,os.DirFS(*webDir),monitor.Snapshot)
  cancel()
  <-done
  return err
 }
 return errors.New("invalid command")
}
func main(){
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt)
 defer stop()
 if err:=run(ctx,os.Args[1:]);err!=nil{
  log.Print(err)
  os.Exit(1)
 }
}
