// Package staginggate is a narrow, explicitly configured edge gate for
// direct-TLS pairing acceptance in a controlled cross-network staging pilot.
// It must not be mistaken for a production public Internet gateway.
package staginggate

import (
 "crypto/tls"
 "crypto/x509"
 "errors"
 "net"
 "net/http"
 "net/netip"
 "strconv"
 "strings"
 "time"
)
var ErrConfiguration=errors.New("restricted staging configuration invalid")
type Gate struct {
 Address string
 ServerName string
 hostHeader string
 allowed []netip.Prefix
 slots chan struct{}
}
// New requires a DNS identity, explicit IP:port bind and tightly scoped
// source CIDRs. No wildcard source prefix is permitted.
func New(address,serverName,sourceCIDRs string)(*Gate,error){
 if strings.TrimSpace(address)!=address||strings.TrimSpace(serverName)!=serverName||
 serverName!=strings.ToLower(serverName)||len(serverName)<4||len(serverName)>253||
 !strings.Contains(serverName,".")||strings.HasSuffix(serverName,".")||
 strings.ContainsAny(serverName," /:@\\"){return nil,ErrConfiguration}
 for _,label:=range strings.Split(serverName,"."){
  if len(label)<1||len(label)>63||label[0]=='-'||label[len(label)-1]=='-'{return nil,ErrConfiguration}
  for _,ch:=range label {
   if !(ch>='a'&&ch<='z'||ch>='0'&&ch<='9'||ch=='-'){return nil,ErrConfiguration}
  }
 }
 ipString,portString,err:=net.SplitHostPort(address)
 if err!=nil{return nil,ErrConfiguration}
 ip,err:=netip.ParseAddr(ipString)
 if err!=nil||ip.Zone()!=""{return nil,ErrConfiguration}
 p,err:=strconv.Atoi(portString)
 if err!=nil||p<1024||p>65535{return nil,ErrConfiguration}
 if sourceCIDRs==""||strings.TrimSpace(sourceCIDRs)!=sourceCIDRs{return nil,ErrConfiguration}
 raw:=strings.Split(sourceCIDRs,",")
 if len(raw)>16{return nil,ErrConfiguration}
 allowed:=make([]netip.Prefix,0,len(raw))
 for _,entry:=range raw{
  if entry==""||strings.TrimSpace(entry)!=entry{return nil,ErrConfiguration}
  prefix,err:=netip.ParsePrefix(entry)
  if err!=nil||!prefix.IsValid()||prefix.Addr().Zone()!=""{
   return nil,ErrConfiguration
  }
  prefix=prefix.Masked()
  // /24 and /64 are maximum networks; a /0 public Internet
  // allowlist must never be accepted via operator error.
  if prefix.Addr().Is4()&&prefix.Bits()<24{return nil,ErrConfiguration}
  if prefix.Addr().Is6()&&prefix.Bits()<64{return nil,ErrConfiguration}
  allowed=append(allowed,prefix)
 }
 return &Gate{
  Address:address,ServerName:serverName,
  hostHeader:net.JoinHostPort(serverName,portString),
  allowed:allowed,slots:make(chan struct{},16),
 },nil
}
func(g *Gate)Allowed(remote string)bool{
 if g==nil{return false}
 host,_,err:=net.SplitHostPort(remote)
 if err!=nil{return false}
 addr,err:=netip.ParseAddr(host)
 if err!=nil||addr.Zone()!=""{return false}
 addr=addr.Unmap()
 for _,prefix:=range g.allowed{
  if prefix.Contains(addr){return true}
 }
 return false
}
// Wrap trusts only the direct TCP peer, the actual TLS connection's SNI,
// and the HTTP Host field. X-Forwarded-* headers are intentionally ignored.
func(g *Gate)Wrap(next http.Handler)http.Handler{
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  w.Header().Set("X-Content-Type-Options","nosniff")
  if g==nil||next==nil||!g.Allowed(r.RemoteAddr){
   http.Error(w,"not allowed",http.StatusForbidden);return
  }
  if r.TLS==nil||r.TLS.Version<tls.VersionTLS13{
   http.Error(w,"TLS 1.3 required",http.StatusUpgradeRequired);return
  }
  if r.TLS.ServerName!=g.ServerName||r.Host!=g.hostHeader{
   http.Error(w,"wrong TLS host",http.StatusMisdirectedRequest);return
  }
  select {
  case g.slots<-struct{}{}:
   defer func(){<-g.slots}()
   next.ServeHTTP(w,r)
  default:
   http.Error(w,"gateway busy",http.StatusServiceUnavailable)
  }
 })
}
// ValidateCertificate binds the operator's PEM to the required SNI/DNS name.
// This is deliberately checked BEFORE opening a socket.
func ValidateCertificate(cert tls.Certificate,serverName string)error{
 if len(cert.Certificate)==0{return ErrConfiguration}
 leaf,err:=x509.ParseCertificate(cert.Certificate[0])
 if err!=nil||leaf.VerifyHostname(serverName)!=nil{return ErrConfiguration}
 now:=time.Now()
 if now.Before(leaf.NotBefore)||!now.Before(leaf.NotAfter){return ErrConfiguration}
 if leaf.KeyUsage!=0&&leaf.KeyUsage&x509.KeyUsageDigitalSignature==0{return ErrConfiguration}
 for _,use:=range leaf.ExtKeyUsage{
  if use==x509.ExtKeyUsageServerAuth||use==x509.ExtKeyUsageAny{return nil}
 }
 if len(leaf.ExtKeyUsage)>0{return ErrConfiguration}
 return nil
}
