// Package landiscovery observes existing mDNS announcements. It never
// sends discovery probes, connects to devices or uploads local inventory.
package landiscovery

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "errors"
 "net"
 "sort"
 "strings"
 "time"
)
var ErrInvalid=errors.New("untrusted LAN discovery advertisement")
type Candidate struct{
 Name string `json:"name"`
 Type string `json:"type"`
 Fingerprint string `json:"fingerprint"`
 Source string `json:"source"`
 Verified bool `json:"verified"`
}
type record struct{name string;kind uint16;data []byte;offset int}
func nameAt(packet []byte,start int)(string,int,error){
 if start>=len(packet)||start<0{return "",0,ErrInvalid}
 pos:=start;end:=-1
 labels:=make([]string,0,8)
 for jumps:=0;jumps<32;jumps++{
  if pos>=len(packet){return "",0,ErrInvalid}
  size:=int(packet[pos])
  if size==0{
   pos++
   if end<0{end=pos}
   if len(labels)==0{return "",end,ErrInvalid}
   return strings.Join(labels,"."),end,nil
  }
  if size&0xc0==0xc0{
   if pos+1>=len(packet){return "",0,ErrInvalid}
   target:=((size&0x3f)<<8)|int(packet[pos+1])
   if target>=len(packet)||target>=pos{return "",0,ErrInvalid}
   if end<0{end=pos+2}
   pos=target
   continue
  }
  if size&0xc0!=0||size>63||pos+1+size>len(packet){return "",0,ErrInvalid}
  label:=string(packet[pos+1:pos+1+size])
  for _,ch:=range label{
   if ch<33||ch>126||ch=='/'||ch=='\\'{return "",0,ErrInvalid}
  }
  labels=append(labels,strings.ToLower(label))
  if len(labels)>32{return "",0,ErrInvalid}
  pos+=1+size
 }
 return "",0,ErrInvalid
}
func u16(b []byte,pos int)int{return int(b[pos])<<8|int(b[pos+1])}
func typeOf(name string)string{
 for _,suffix:=range []string{"._ipp._tcp.local","._ipps._tcp.local","._printer._tcp.local","._pdl-datastream._tcp.local"}{
  if strings.HasSuffix(name,suffix)&&len(name)>len(suffix){return "PRINTER"}
 }
 // Attendance readers currently have no interoperable standard mDNS
 // identity to trust. They require explicit vendor-specific future support.
 return ""
}
// Parse observes SRV records from existing DNS-SD announcements, rather
// than interpreting arbitrary IP/hostnames as trusted reachable devices.
// Source data is ALWAYS untrusted and fingerprints are spoofable hints.
func Parse(packet []byte)[]Candidate{
 if len(packet)<12||packet[2]&0x80==0{return nil} // response only
 questions:=u16(packet,4)
 count:=u16(packet,6)+u16(packet,8)+u16(packet,10)
 if questions>32||count>128{return nil}
 cursor:=12
 for i:=0;i<questions;i++{
  _,end,err:=nameAt(packet,cursor)
  if err!=nil||end+4>len(packet){return nil}
  cursor=end+4
 }
 result:=make(map[string]Candidate)
 for i:=0;i<count;i++{
  name,end,err:=nameAt(packet,cursor)
  if err!=nil||end+10>len(packet){return nil}
  kind:=u16(packet,end)
  class:=u16(packet,end+2)&0x7fff
  rdlen:=u16(packet,end+8)
  dataStart:=end+10
  if rdlen<0||dataStart+rdlen>len(packet){return nil}
  cursor=dataStart+rdlen
  if kind!=33||class!=1||rdlen<7{continue} // SRV only
  t:=typeOf(name)
  if t==""{continue}
  port:=u16(packet,dataStart+4)
  target,_,err:=nameAt(packet,dataStart+6)
  if err!=nil||port<1||!strings.HasSuffix(target,".local"){continue}
  // Do not return/resolve IP addresses or contact the target host.
  // A SHA-256 of mDNS strings is NOT a cryptographic device identity.
  hash:=sha256.Sum256([]byte(name+"|"+target+"|"+string(rune(port>>8))+":"+string(rune(port&255))))
  finger:=hex.EncodeToString(hash[:])
  result[finger]=Candidate{Name:name,Type:t,Fingerprint:finger,Source:"UNTRUSTED_MDNS",Verified:false}
 }
 entries:=make([]Candidate,0,len(result))
 for _,v:=range result{entries=append(entries,v)}
 sort.Slice(entries,func(i,j int)bool{return entries[i].Fingerprint<entries[j].Fingerprint})
 return entries
}
// Listen passively for up to duration, max 20 candidates. It may see zero
// candidates due to network silence, firewalls or another OS mDNS listener.
// No packet is written, no device address is connected to or uploaded.
func Listen(ctx context.Context,duration time.Duration)([]Candidate,error){
 if duration<time.Second||duration>30*time.Second{return nil,ErrInvalid}
 socket,err:=net.ListenMulticastUDP("udp4",nil,&net.UDPAddr{
  IP:net.IPv4(224,0,0,251),Port:5353,
 })
 if err!=nil{return nil,err}
 defer socket.Close()
 _=socket.SetReadBuffer(64*1024)
 stop:=time.Now().Add(duration)
 found:=make(map[string]Candidate)
 packet:=make([]byte,1500)
 for ctx.Err()==nil&&time.Now().Before(stop){
  until:=time.Now().Add(250*time.Millisecond)
  if until.After(stop){until=stop}
  if err=socket.SetReadDeadline(until);err!=nil{return nil,err}
  size,_,err:=socket.ReadFromUDP(packet)
  if err!=nil{
   if e,ok:=err.(net.Error);ok&&e.Timeout(){continue}
   return nil,err
  }
  for _,candidate:=range Parse(packet[:size]){
   if len(found)>=20{break}
   found[candidate.Fingerprint]=candidate
  }
  if len(found)>=20{break}
 }
 if ctx.Err()!=nil{return nil,ctx.Err()}
 entries:=make([]Candidate,0,len(found))
 for _,v:=range found{entries=append(entries,v)}
 sort.Slice(entries,func(i,j int)bool{return entries[i].Fingerprint<entries[j].Fingerprint})
 return entries,nil
}
