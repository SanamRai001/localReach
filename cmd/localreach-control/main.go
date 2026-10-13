// localreach-control is an operator-only LOOPBACK pairing control-plane
// prototype. It deliberately cannot bind an Internet-facing address.
// Do not expose it with a proxy; production auth/throttling is incomplete.
package main

import(
 "context"
 "crypto/tls"
 "database/sql"
 "errors"
 "flag"
 "fmt"
 "log"
 "net"
 "net/http"
 "net/url"
 "os"
 "os/signal"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/pairapi"
 "github.com/SanamRai001/localReach/internal/pgauth"
 "github.com/SanamRai001/localReach/internal/pgpairing"
 _ "github.com/lib/pq"
)
const listenAddress="127.0.0.1:19443"
func validateDSN(raw string,allowLoopbackTestDB bool)error{
 if raw==""{return errors.New("LOCALREACH_CONTROL_DSN is required")}
 u,err:=url.Parse(raw)
 if err!=nil||u.Scheme!="postgres"||u.Hostname()==""||u.User==nil||u.Path==""{return errors.New("invalid PostgreSQL connection configuration")}
 mode:=u.Query().Get("sslmode")
 if mode=="verify-full"{return nil}
 if mode=="disable"&&allowLoopbackTestDB&&
  (u.Hostname()=="localhost"||u.Hostname()=="127.0.0.1"||u.Hostname()=="::1")&&
  (u.EscapedPath()=="/localreach_test"){return nil}
 return errors.New("PostgreSQL TLS requires sslmode=verify-full (unless explicitly using a disposable loopback test DB)")
}
func serve(ctx context.Context,certFile,keyFile,dsn string,allowLocalTestDB bool)error{
 if certFile==""||keyFile==""{return errors.New("TLS certificate and private key paths must be explicitly provided")}
 if err:=validateDSN(dsn,allowLocalTestDB);err!=nil{return err}
 pair,err:=tls.LoadX509KeyPair(certFile,keyFile)
 if err!=nil{return fmt.Errorf("TLS certificate loading failed: %w",err)}
 db,err:=sql.Open("postgres",dsn);if err!=nil{return errors.New("failed to open PostgreSQL")}
 defer db.Close()
 db.SetMaxOpenConns(8);db.SetMaxIdleConns(4);db.SetConnMaxLifetime(30*time.Minute)
 pingCtx,cancel:=context.WithTimeout(ctx,5*time.Second)
 err=db.PingContext(pingCtx);cancel()
 if err!=nil{return errors.New("PostgreSQL unavailable or TLS identity untrusted")}
 listener,err:=net.Listen("tcp",listenAddress)
 if err!=nil{return err}
 defer listener.Close()
 tlsListener:=tls.NewListener(listener,&tls.Config{
  Certificates:[]tls.Certificate{pair},
  MinVersion:tls.VersionTLS12,
 })
 handler:=pairapi.Handler{Auth:pgauth.New(db),Pairing:pgpairing.New(db),
  Guard:pairapi.NewGuard(nil),Admission:pairapi.NewSQLAdmission(db)}
 server:=&http.Server{
  Handler:handler,
  ReadHeaderTimeout:5*time.Second,ReadTimeout:10*time.Second,
  WriteTimeout:10*time.Second,IdleTimeout:20*time.Second,
  MaxHeaderBytes:8192,
 }
 done:=make(chan struct{})
 go func(){
  select{
  case <-ctx.Done():
   shutdownCtx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
   defer cancel()
   _=server.Shutdown(shutdownCtx)
  case <-done:
  }
 }()
 log.Printf("LocalReach experimental control plane listening on loopback TLS %s (NO device grants)",listenAddress)
 err=server.Serve(tlsListener)
 close(done)
 if errors.Is(err,http.ErrServerClosed){return nil}
 return err
}
func run(ctx context.Context,args []string)error{
 flags:=flag.NewFlagSet("localreach-control",flag.ContinueOnError)
 cert:=flags.String("tls-cert","","trusted server certificate PEM path")
 key:=flags.String("tls-key","","server private key PEM path")
 localTest:=flags.Bool("allow-disposable-loopback-db",false,"permit plaintext PostgreSQL only for localreach_test on loopback")
 if err:=flags.Parse(args);err!=nil{return err}
 if flags.NArg()!=0{return errors.New("unexpected positional arguments")}
 // Only operator-supplied environment holds DB credentials; never log them.
 dsn:=strings.TrimSpace(os.Getenv("LOCALREACH_CONTROL_DSN"))
 return serve(ctx,*cert,*key,dsn,*localTest)
}
func main(){
 ctx,stop:=signal.NotifyContext(context.Background(),os.Interrupt)
 defer stop()
 if err:=run(ctx,os.Args[1:]);err!=nil{
  log.Print(err)
  os.Exit(1)
 }
}
