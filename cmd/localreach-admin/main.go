// localreach-admin is an operator-only native CLI. Admin signing keys are
// separately provisioned; browser JavaScript never receives private keys.
package main

import (
 "bufio"
 "context"
 "crypto/tls"
 "encoding/base64"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "path/filepath"
 "strings"
 "time"

 "github.com/SanamRai001/localReach/internal/adminremote"
 "github.com/SanamRai001/localReach/internal/agentkeys"
 "github.com/SanamRai001/localReach/internal/pgcapability"
)
func trustedClient()*http.Client{
 return &http.Client{
  Timeout:10*time.Second,
  Transport:&http.Transport{
   Proxy:http.ProxyFromEnvironment,
   TLSClientConfig:&tls.Config{MinVersion:tls.VersionTLS12},
   DialContext:(&net.Dialer{Timeout:5*time.Second}).DialContext,
   TLSHandshakeTimeout:5*time.Second,
  },
 }
}
func run(ctx context.Context,args []string,input io.Reader,out io.Writer)error{
 if len(args)==0{return errors.New("required command: init, invite, review, approve, grant-read or revoke-read")}
 command:=args[0]
 switch command{case "init","invite","review","approve","grant-read","revoke-read":default:return errors.New("invalid administrator command")}
 fs:=flag.NewFlagSet(command,flag.ContinueOnError)
 dir:=fs.String("identity-dir","","separate native administrator key directory (required)")
 gateway:=fs.String("gateway","","trusted HTTPS control plane URL")
 org:=fs.String("organization","","organization ID")
 admin:=fs.String("admin","","preprovisioned administrator key ID")
 site:=fs.String("site","","approved organization site")
 request:=fs.String("request","","pairing request ID to review/approve")
 agentID:=fs.String("agent","","enrolled agent ID for discovery policy")
 device:=fs.String("device-fingerprint","","unverified discovery fingerprint")
 capability:=fs.String("capability","","PRINTER_DISCOVERY_READ or ATTENDANCE_DISCOVERY_READ")
 if err:=fs.Parse(args[1:]);err!=nil{return err}
 if fs.NArg()!=0{return errors.New("unexpected positional arguments")}
 if *dir==""{return errors.New("an independent -identity-dir is required; do not use the agent identity")}
 defaultDir,err:=agentkeys.DefaultDir()
 if err==nil&&filepath.Clean(*dir)==filepath.Clean(defaultDir){return errors.New("administrator identity must be separate from agent identity")}
 if command=="init"{
  if *gateway!=""||*org!=""||*admin!=""||*site!=""||*request!=""||*agentID!=""||*device!=""||*capability!=""{return errors.New("init accepts identity-dir only")}
  identity,err:= (agentkeys.Store{Dir:*dir}).Create()
  if err!=nil{return fmt.Errorf("native administrator key initialization denied: %w",err)}
  fmt.Fprintln(out,"Administrator PUBLIC key (must be provisioned by an existing trusted operator):",base64.RawURLEncoding.EncodeToString(identity.PublicKey()))
  fmt.Fprintln(out,"Fingerprint:",identity.Fingerprint())
  fmt.Fprintln(out,"No organization access is granted by generating a key.")
  return nil
 }
 if *gateway==""||*org==""||*admin==""{return errors.New("HTTPS gateway, organization and provisioned administrator ID required")}
 if command=="invite"&&(*site==""||*request!=""||*agentID!=""||*device!=""||*capability!=""){return errors.New("invite requires only site")}
 if (command=="review"||command=="approve")&&(*request==""||*site!=""||*agentID!=""||*device!=""||*capability!=""){return errors.New("review and approve require only request")}
 if (command=="grant-read"||command=="revoke-read")&&(*request!=""||*site==""||*agentID==""||len(*device)!=64||(*capability!=pgcapability.PrinterDiscovery&&*capability!=pgcapability.AttendanceDiscovery)){
  return errors.New("read-policy decisions require site, agent, 64-character fingerprint and supported discovery capability")
 }
 id,err:=(agentkeys.Store{Dir:*dir}).Load()
 if err!=nil{return fmt.Errorf("existing native administrator key required: %w",err)}
 remote,err:=adminremote.New(*gateway,trustedClient())
 if err!=nil{return err}
 token,err:=remote.Login(ctx,*org,*admin,id)
 if err!=nil{return errors.New("administrator identity is not provisioned or signed login denied")}
 switch command{
 case "grant-read","revoke-read":
  fmt.Fprintln(out,"WARNING: discovery fingerprints are UNVERIFIED hints, NOT cryptographic hardware identities.")
  fmt.Fprintln(out,"This decision DOES NOT enable any device commands.")
  fmt.Fprintln(out,"Type the exact 64-character fingerprint to confirm this separate read-policy decision:")
  reader:=bufio.NewReader(io.LimitReader(input,256))
  line,readErr:=reader.ReadString('\n')
  if readErr!=nil&&readErr!=io.EOF{return errors.New("could not read fingerprint")}
  if strings.TrimSpace(line)!=*device{return errors.New("fingerprint mismatch: no grant applied")}
  action:=pgcapability.Grant
  if command=="revoke-read"{action=pgcapability.Revoke}
  decision:=pgcapability.Decision{
   Organization:*org,Site:*site,AgentID:*agentID,AdminID:*admin,
   DeviceFingerprint:*device,Capability:*capability,Action:action,
  }
  if err=remote.DecideDiscoveryRead(ctx,token,decision,id);err!=nil{return errors.New("separate signed discovery policy denied")}
  fmt.Fprintln(out,"DISCOVERY READ POLICY:",action,"(device operations remain DISABLED)")
 case "invite":
  invitation,err:=remote.Invite(ctx,*org,*site,token)
  if err!=nil{return errors.New("invitation rejected")}
  fmt.Fprintln(out,"ONE-TIME INVITATION: transfer privately to the intended agent owner; never put this in shell history or a URL.")
  fmt.Fprintln(out,invitation.Token)
  fmt.Fprintln(out,"Expires:",invitation.ExpiresAt)
  fmt.Fprintln(out,"Creates a PENDING request only; it does not grant device access.")
 case "review","approve":
  review,err:=remote.Review(ctx,*org,*request,token)
  if err!=nil{return errors.New("request review denied")}
  fmt.Fprintln(out,"Organization:",*org,"Site:",review.Site,"State:",review.State)
  fmt.Fprintln(out,"Agent public-key SHA256 fingerprint:",review.Fingerprint)
  fmt.Fprintln(out,"Expires:",review.ExpiresAt.UTC().Format(time.RFC3339))
  if command=="approve"{
   if review.State!="PENDING"||!time.Now().Before(review.ExpiresAt){return errors.New("cannot approve a nonpending or expired request")}
   fmt.Fprintln(out,"Compare this full fingerprint with the intended agent OUT OF BAND.")
   fmt.Fprintln(out,"To approve, type the exact 64-character fingerprint and press Enter:")
   reader:=bufio.NewReader(io.LimitReader(input,256))
   line,readErr:=reader.ReadString('\n')
   if readErr!=nil&&readErr!=io.EOF{return errors.New("could not read confirmation")}
   entered:=strings.TrimSpace(line)
   if entered!=review.Fingerprint{return errors.New("fingerprint was not confirmed; request remains pending")}
   if err=remote.ApproveReviewed(ctx,*org,*admin,*request,token,entered,id);err!=nil{
    return errors.New("signed decision denied; state not confirmed approved")
   }
   fmt.Fprintln(out,"APPROVED: native agent must still prove key possession to enroll. No device permissions granted.")
  }
 }
 return nil
}
func main(){
 if err:=run(context.Background(),os.Args[1:],os.Stdin,os.Stdout);err!=nil{
  fmt.Fprintln(os.Stderr,err)
  os.Exit(1)
 }
}
