// LocalReach real localhost setup dashboard. No device commands or public listener.
package main

import (
 "context"
 "crypto/tls"
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
 "github.com/SanamRai001/localReach/internal/localdashboard"
 "github.com/SanamRai001/localReach/internal/localsetup"
)
func client()*http.Client{
 return &http.Client{
  Timeout:10*time.Second,
  Transport:&http.Transport{
   Proxy:http.ProxyFromEnvironment,
   TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
   TLSHandshakeTimeout:5*time.Second,
   DialContext:(&net.Dialer{Timeout:5*time.Second,KeepAlive:30*time.Second}).DialContext,
  },
 }
}
func run(ctx context.Context,args []string)error{
 flags:=flag.NewFlagSet("localreach-setup",flag.ContinueOnError)
 root:=flags.String("web","web/setup","directory containing the local setup dashboard")
 gateway:=flags.String("gateway","","optional operator-managed trusted HTTPS gateway")
 org:=flags.String("organization","","organization ID for that trusted gateway")
 if err:=flags.Parse(args);err!=nil{return err}
 if flags.NArg()!=0{return fmt.Errorf("unexpected positional arguments")}
 if (*gateway=="")!=(*org==""){return fmt.Errorf("gateway and organization must be provided together")}
 var remote localdashboard.Remote
 if *gateway!=""{
  r,err:=agentremote.New(*gateway,client())
  if err!=nil{return fmt.Errorf("trusted HTTPS gateway required: %w",err)}
  remote=r
 }
 dir,err:=agentkeys.DefaultDir()
 if err!=nil{return fmt.Errorf("native key storage unavailable: %w",err)}
 service:=localdashboard.New(agentkeys.Store{Dir:dir},remote,*org)
 defer service.Close()
 log.Printf("LocalReach local dashboard: http://%s",localsetup.Address)
 if remote==nil{log.Print("No cloud configured. Local identity and passive printer discovery are available; pairing needs an operator-managed HTTPS gateway.")}
 return localdashboard.ServeContext(ctx,os.DirFS(*root),service)
}
func main(){
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt)
 defer stop()
 if err:=run(ctx,os.Args[1:]);err!=nil{log.Fatal(err)}
}
