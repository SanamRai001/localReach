package staginggate

import "net"

// FilterListener rejects unallowlisted peers BEFORE the TLS handshake.
// This reduces unnecessary certificate/handshake CPU work but is NOT a
// network firewall or a replacement for DDoS protection.
func(g *Gate)FilterListener(inner net.Listener)net.Listener{
 return &filteredListener{Listener:inner,gate:g}
}
type filteredListener struct {
 net.Listener
 gate *Gate
}
func(l *filteredListener)Accept()(net.Conn,error){
 for {
  conn,err:=l.Listener.Accept()
  if err!=nil{return nil,err}
  if l.gate!=nil&&l.gate.Allowed(conn.RemoteAddr().String()){
   return conn,nil
  }
  _=conn.Close()
 }
}
