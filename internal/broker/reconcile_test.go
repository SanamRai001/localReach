package broker

import (
 "errors"
 "path/filepath"
 "testing"
 "time"
)
func TestLateObservationRequiresOriginalLeaseAndScope(t *testing.T){
 now:=time.Now()
 b,e:=Open(filepath.Join(t.TempDir(),"broker.log"),1<<20,func()time.Time{return now})
 if e!=nil{t.Fatal(e)}
 defer b.Close()
 if e=b.Submit("job","tenant","agent");e!=nil{t.Fatal(e)}
 c,ok,e:=b.Claim("tenant","agent",time.Second);if e!=nil||!ok{t.Fatal(e)}
 if e=b.Receive(c.ID,c.Tenant,c.Agent,c.Lease);e!=nil{t.Fatal(e)}
 now=now.Add(2*time.Second)
 if e=b.Reconcile();e!=nil{t.Fatal(e)}
 for _,v:=range []struct{tenant,agent,lease string}{
  {"other","agent",c.Lease},{"tenant","other",c.Lease},{"tenant","agent","wrong"},
 }{
  if e=b.ReconcileObservedResult(c.ID,v.tenant,v.agent,v.lease,Succeeded,"pong");!errors.Is(e,ErrConflict){t.Fatalf("accepted invalid scope: %+v",v)}
 }
 if e=b.ReconcileObservedResult(c.ID,"tenant","agent",c.Lease,Succeeded,"pong");e!=nil{t.Fatal(e)}
 result,_:=b.Get("job","tenant")
 if result.State!=Succeeded||result.Result!="pong"{t.Fatal(result)}
 if e=b.ReconcileObservedResult(c.ID,"tenant","agent",c.Lease,Failed,"changed");!errors.Is(e,ErrConflict){t.Fatal("late result rewritten")}
}
func TestLateObservationCannotChangeUnreceivedJob(t *testing.T){
 b,e:=Open(filepath.Join(t.TempDir(),"broker.log"),1<<20,nil);if e!=nil{t.Fatal(e)}
 defer b.Close()
 if e=b.Submit("job","tenant","agent");e!=nil{t.Fatal(e)}
 c,ok,e:=b.Claim("tenant","agent",time.Second);if e!=nil||!ok{t.Fatal(e)}
 if e=b.ReconcileObservedResult("job","tenant","agent",c.Lease,Succeeded,"pong");!errors.Is(e,ErrConflict){t.Fatal("job completed without receipt")}
}
