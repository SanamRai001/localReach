package pairapi

import (
 "net"
 "net/http"
 "sync"
 "time"
)

// Guard is a bounded, per-direct-peer experimental admission limiter.
// It deliberately ignores X-Forwarded-For, which clients can spoof.
// Production requires a gateway-wide, trusted-proxy-aware distributed limiter.
type Guard struct{
 mu sync.Mutex
 entries map[string]bucket
 now func()time.Time
}
type bucket struct{window time.Time;count int}
func NewGuard(now func()time.Time)*Guard{
 if now==nil{now=time.Now}
 return &Guard{entries:make(map[string]bucket),now:now}
}
func(g *Guard)Allow(r *http.Request)bool{
 if g==nil{return false}
 host,_,err:=net.SplitHostPort(r.RemoteAddr)
 if err!=nil||net.ParseIP(host)==nil{return false}
 g.mu.Lock()
 defer g.mu.Unlock()
 now:=g.now()
 if len(g.entries)>4096{
  for k,b:=range g.entries{if now.Sub(b.window)>=time.Minute||now.Before(b.window){delete(g.entries,k)}}
  if len(g.entries)>4096{return false}
 }
 b,exists:=g.entries[host]
 if !exists||now.Sub(b.window)>=time.Minute||now.Before(b.window){b=bucket{window:now}}
 if b.count>=5{return false}
 b.count++
 g.entries[host]=b
 return true
}
