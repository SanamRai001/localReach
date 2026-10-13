package ownership_test

import (
 "errors"
 "path/filepath"
 "testing"

 "github.com/SanamRai001/localReach/internal/broker"
 "github.com/SanamRai001/localReach/internal/journal"
 "github.com/SanamRai001/localReach/internal/ownership"
)
func TestBrokerBlocksSecondWriter(t *testing.T){
 path:=filepath.Join(t.TempDir(),"broker.log")
 first,err:=broker.Open(path,1<<20,nil);if err!=nil{t.Fatal(err)}
 if second,err:=broker.Open(path,1<<20,nil);!errors.Is(err,ownership.ErrInUse){if err==nil{second.Close()};t.Fatalf("second writer accepted: %v",err)}
 if err:=first.Close();err!=nil{t.Fatal(err)}
 again,err:=broker.Open(path,1<<20,nil);if err!=nil{t.Fatal(err)};defer again.Close()
}
func TestEdgeBlocksSecondWriter(t *testing.T){
 path:=filepath.Join(t.TempDir(),"edge.log")
 first,err:=journal.Open(path,1<<20);if err!=nil{t.Fatal(err)}
 if second,err:=journal.Open(path,1<<20);!errors.Is(err,ownership.ErrInUse){if err==nil{second.Close()};t.Fatalf("second writer accepted: %v",err)}
 if err:=first.Close();err!=nil{t.Fatal(err)}
 again,err:=journal.Open(path,1<<20);if err!=nil{t.Fatal(err)};defer again.Close()
}
