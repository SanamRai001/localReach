package broker

import(
 "errors"
 "path/filepath"
 "testing"
 "time"
)
func TestLeaseAcknowledgementAndRecovery(t *testing.T){
 now:=time.Now()
 path:=filepath.Join(t.TempDir(),"broker.log")
 open:=func()*Broker{b,e:=Open(path,1<<20,func()time.Time{return now});if e!=nil{t.Fatal(e)};return b}
 b:=open()
 if e:=b.Submit("one","tenant-a","agent-a");e!=nil{t.Fatal(e)}
 if e:=b.Submit("one","tenant-a","agent-a");!errors.Is(e,ErrConflict){t.Fatal("duplicate allowed")}
 if _,ok,e:=b.Claim("tenant-b","agent-a",time.Second);e!=nil||ok{t.Fatal("cross tenant claim")}
 lease,ok,e:=b.Claim("tenant-a","agent-a",time.Second);if e!=nil||!ok{t.Fatal(e)}
 if e:=b.Receive("one","tenant-a","agent-b",lease.Lease);!errors.Is(e,ErrConflict){t.Fatal("wrong agent")}
 if e:=b.Receive("one","tenant-a","agent-a",lease.Lease);e!=nil{t.Fatal(e)}
 now=now.Add(2*time.Second)
 if _,ok,e:=b.Claim("tenant-a","agent-a",time.Second);e!=nil||ok{t.Fatal("received job reissued")}
 if e:=b.Close();e!=nil{t.Fatal(e)}
 b=open();defer b.Close()
 if e:=b.Reconcile();e!=nil{t.Fatal(e)}
 c,ok:=b.Get("one","tenant-a");if !ok||c.State!=Indeterminate{t.Fatal(c)}
 if _,ok:=b.Get("one","tenant-b");ok{t.Fatal("tenant data leaked")}
}
func TestUnacknowledgedLeaseCanExpireAndReassign(t *testing.T){
 now:=time.Now()
 b,e:=Open(filepath.Join(t.TempDir(),"b"),1<<20,func()time.Time{return now});if e!=nil{t.Fatal(e)};defer b.Close()
 if e=b.Submit("x","t","a");e!=nil{t.Fatal(e)}
 old,ok,e:=b.Claim("t","a",time.Second);if !ok||e!=nil{t.Fatal(e)}
 now=now.Add(2*time.Second)
 latest,ok,e:=b.Claim("t","a",time.Second);if !ok||e!=nil{t.Fatal(e)}
 if latest.Lease==old.Lease{t.Fatal("lease unchanged")}
 if e=b.Receive("x","t","a",old.Lease);!errors.Is(e,ErrConflict){t.Fatal("stale lease accepted")}
 if e=b.Receive("x","t","a",latest.Lease);e!=nil{t.Fatal(e)}
 if e=b.Complete("x","t","a",latest.Lease,Succeeded,"pong");e!=nil{t.Fatal(e)}
 if e=b.Complete("x","t","a",latest.Lease,Succeeded,"pong");!errors.Is(e,ErrConflict){t.Fatal("duplicate completion")}
}
