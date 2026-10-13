// localreach-lab starts a loopback-only HTTPS gateway and a separate agent
// process for MOCK.PING verification. Never deploy this lab server publicly.
package main

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "encoding/base64"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "log"
 "net"
 "net/http"
 "net/url"
 "os"
 "path/filepath"
 "time"

 "github.com/SanamRai001/localReach/internal/broker"
 "github.com/SanamRai001/localReach/internal/identity"
 "github.com/SanamRai001/localReach/internal/integration"
 "github.com/SanamRai001/localReach/internal/journal"
 "github.com/SanamRai001/localReach/internal/session"
 "github.com/SanamRai001/localReach/internal/transport"
)
type config struct {
 AgentID string `json:"agentId"`
 Private string `json:"privateKey"`
 URL string `json:"url"`
 CACert string `json:"caCert"`
}
func main(){
 mode:=flag.String("mode","","gateway or agent")
 dir:=flag.String("data",".localreach-lab","lab data directory")
 certFile:=flag.String("cert","","path to user-created loopback TLS certificate")
 keyFile:=flag.String("key","","path to corresponding TLS key")
 flag.Parse()
 if err:=run(*mode,*dir,*certFile,*keyFile);err!=nil{log.Fatal(err)}
}
func run(mode,dir,certFile,keyFile string)error{
 if mode!="gateway"&&mode!="agent"{return errors.New("mode must be gateway or agent")}
 if mode=="agent"{return runAgent(dir)}
 if certFile==""||keyFile==""{return errors.New("gateway requires explicit -cert and -key: see docs/R1K2_LAB.md")}
 if err:=os.MkdirAll(dir,0700);err!=nil{return err}
 // Exact fixed loopback endpoint; no public bind or exposed admin API.
 addr:="127.0.0.1:18787"
 cert,err:=tls.LoadX509KeyPair(certFile,keyFile);if err!=nil{return err}
 rawCert,err:=os.ReadFile(certFile);if err!=nil{return err}
 reg:=identity.NewRegistry(nil)
 inv,err:=reg.Issue("lab-tenant","lab-site",time.Minute);if err!=nil{return err}
 pub,priv,err:=ed25519.GenerateKey(rand.Reader);if err!=nil{return err}
 enrolled,err:=reg.Enroll(inv.Token,pub,identity.SignEnrollment(priv,inv.Token));if err!=nil{return err}
 conf:=config{AgentID:enrolled.ID,Private:base64.RawURLEncoding.EncodeToString(priv),URL:"https://"+addr,CACert:string(rawCert)}
 b,err:=broker.Open(filepath.Join(dir,"broker.log"),1<<20,nil);if err!=nil{return err}
 defer b.Close()
 if err=b.Submit("lab-mock-001","lab-tenant",enrolled.ID);err!=nil{return err}
 data,err:=json.MarshalIndent(conf,"","  ");if err!=nil{return err}
 if err=os.WriteFile(filepath.Join(dir,"agent.json"),data,0600);err!=nil{return err}
 // Agent configuration contains a TEST private key and must remain local.
 l,err:=net.Listen("tcp",addr);if err!=nil{return err}
 defer l.Close()
 srv:=&http.Server{Handler:transport.New(transport.Server{Registry:reg,Sessions:session.New(reg,nil),Broker:b}),ReadHeaderTimeout:5*time.Second}
 log.Printf("lab gateway: %s (loopback only), agent config: %s",conf.URL,filepath.Join(dir,"agent.json"))
 return srv.Serve(tls.NewListener(l,&tls.Config{Certificates:[]tls.Certificate{cert},MinVersion:tls.VersionTLS12}))
}
func runAgent(dir string)error{
 data,err:=os.ReadFile(filepath.Join(dir,"agent.json"));if err!=nil{return err}
 var c config
 if err=json.Unmarshal(data,&c);err!=nil{return err}
 target,err:=url.Parse(c.URL);if err!=nil||target.Scheme!="https"||target.Host!="127.0.0.1:18787"||target.Path!=""||target.User!=nil||target.RawQuery!=""||target.Fragment!=""{return errors.New("lab agent refuses non-loopback target")}
 raw,err:=base64.RawURLEncoding.DecodeString(c.Private);if err!=nil{return err}
 if len(raw)!=ed25519.PrivateKeySize{return errors.New("invalid lab private key")}
 roots:=x509.NewCertPool()
 if !roots.AppendCertsFromPEM([]byte(c.CACert)){return errors.New("invalid lab trust certificate")}
 httpClient:=&http.Client{Timeout:10*time.Second,Transport:&http.Transport{TLSClientConfig:&tls.Config{RootCAs:roots,MinVersion:tls.VersionTLS12}}}
 j,err:=journal.Open(filepath.Join(dir,"edge.log"),1<<20);if err!=nil{return err}
 defer j.Close()
 agent:=transport.Agent{Identity:integration.Client{HTTP:httpClient,BaseURL:c.URL,AgentID:c.AgentID,PrivateKey:ed25519.PrivateKey(raw)},Journal:j}
 ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second);defer cancel()
 handled,err:=agent.PollOnce(ctx)
 if err!=nil{return err}
 fmt.Printf("mock command handled: %v\n",handled)
 return nil
}
