package transport

import (
 "context"
 "math/rand"
 "time"
)

// Runner supervises outbound mock polling with cancellable bounded backoff.
// It never retries a device operation itself; PollOnce performs journal checks.
type Runner struct {
 Agent Agent
 IdleInterval time.Duration
 MinBackoff time.Duration
 MaxBackoff time.Duration
}
// Run returns when the context is cancelled. Errors trigger backoff rather
// than a busy loop; intermittent connectivity does not delete local records.
func(r Runner)Run(ctx context.Context){
 idle:=r.IdleInterval;if idle<=0{idle=time.Second}
 min:=r.MinBackoff;if min<=0{min=time.Second}
 max:=r.MaxBackoff;if max<min{max=30*time.Second;if max<min{max=min}}
 backoff:=min
 for ctx.Err()==nil{
  handled,err:=r.Agent.PollOnce(ctx)
  delay:=idle
  if err!=nil{
   // Add bounded jitter to avoid mass reconnect storms.
   jitter:=time.Duration(rand.Int63n(int64(backoff/2+1)))
   delay=backoff+jitter
   if delay>max{delay=max}
   if backoff<max/2{backoff*=2}else{backoff=max}
  }else{
   backoff=min
   if handled{delay=0}
  }
  if delay==0{continue}
  timer:=time.NewTimer(delay)
  select{
  case <-ctx.Done():
   if !timer.Stop(){select{case <-timer.C:default:}}
   return
  case <-timer.C:
  }
 }
}
