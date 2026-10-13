package transport

import(
 "context"
 "testing"
 "time"
)
// An invalid unconfigured agent exercises the error/backoff path. Cancellation
// must stop it without blocking on a long reconnect delay.
func TestRunnerStopsOnCancellation(t *testing.T){
 ctx,cancel:=context.WithCancel(context.Background())
 finished:=make(chan struct{})
 go func(){Runner{MinBackoff:time.Hour,MaxBackoff:time.Hour}.Run(ctx);close(finished)}()
 cancel()
 select{
 case <-finished:
 case <-time.After(2*time.Second):t.Fatal("runner failed to stop")
 }
}
