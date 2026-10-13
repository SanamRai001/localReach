package landiscovery

import(
 "bytes"
 "encoding/binary"
 "testing"
 "time"
 "context"
 "strings"
)
func labels(v string)[]byte{
 out:=[]byte{}
 for _,s:=range strings.Split(v,"."){
  out=append(out,byte(len(s)))
  out=append(out,[]byte(s)...)
 }
 return append(out,0)
}
func srvPacket(instance,target string,port uint16)[]byte{
 head:=[]byte{0,0,0x84,0,0,0,0,1,0,0,0,0}
 name:=labels(instance)
 data:=[]byte{0,0,0,0,byte(port>>8),byte(port)}
 data=append(data,labels(target)...)
 record:=bytes.NewBuffer(nil)
 record.Write(name)
 _=binary.Write(record,binary.BigEndian,uint16(33))
 _=binary.Write(record,binary.BigEndian,uint16(1))
 _=binary.Write(record,binary.BigEndian,uint32(120))
 _=binary.Write(record,binary.BigEndian,uint16(len(data)))
 record.Write(data)
 return append(head,record.Bytes()...)
}
func TestPassiveDNSServiceCandidatesAreUntrustedAndDeterministic(t *testing.T){
 data:=srvPacket("Kitchen._ipp._tcp.local","printer.local",631)
 found:=Parse(data)
 if len(found)!=1{t.Fatalf("expected one printer, got %+v",found)}
 item:=found[0]
 if item.Name!="kitchen._ipp._tcp.local"||item.Type!="PRINTER"||item.Source!="UNTRUSTED_MDNS"||
 item.Verified||len(item.Fingerprint)!=64{t.Fatalf("unsafe candidate %+v",item)}
 again:=Parse(data)
 if len(again)!=1||again[0].Fingerprint!=item.Fingerprint{t.Fatal("non-deterministic hint")}
 bad:=srvPacket("Unknown._ssh._tcp.local","machine.local",22)
 if len(Parse(bad))!=0{t.Fatal("unapproved service included")}
 // Attendance devices are vendor-specific; generic network hosts are not
 // silently categorized as trusted attendance readers.
 attendance:=srvPacket("Reader._device-info._tcp.local","reader.local",8080)
 if len(Parse(attendance))!=0{t.Fatal("unverified attendance reader classified")}
}
func TestRejectUntrustedDNSPacketsAndCompressionLoops(t *testing.T){
 p:=srvPacket("Printer._printer._tcp.local","printer.local",9100)
 copies:=[][]byte{
  nil,make([]byte,3),
  append([]byte(nil),p[:len(p)-2]...),
  append([]byte(nil),p...),
  append([]byte(nil),p...),
 }
 copies[3][2]=0 // question, not an answer
 copies[4][12]=0xc0;copies[4][13]=12 // invalid forward/self compression
 for i,v:=range copies{
  if len(Parse(v))!=0{t.Fatalf("malformed packet %d returned candidates",i)}
 }
 badHost:=srvPacket("Printer._ipp._tcp.local","external.example",631)
 if len(Parse(badHost))!=0{t.Fatal("nonlocal target accepted")}
 zeroPort:=srvPacket("Printer._ipp._tcp.local","printer.local",0)
 if len(Parse(zeroPort))!=0{t.Fatal("zero port accepted")}
}
func TestDiscoveryRequiresExplicitSafeTimeout(t *testing.T){
 if _,err:=Listen(context.Background(),100*time.Millisecond);err==nil{t.Fatal("short duration accepted")}
 if _,err:=Listen(context.Background(),time.Minute);err==nil{t.Fatal("unbounded duration accepted")}
}
