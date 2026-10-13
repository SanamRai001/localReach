package journal

import (
 "errors"
 "os"
 "path/filepath"
 "strings"
 "testing"
)
func TestRecoveryProtectsUncertainEffects(t *testing.T){
 path:=filepath.Join(t.TempDir(),"edge.journal")
 j,e:=Open(path,1024*1024);if e!=nil{t.Fatal(e)}
 if e=j.Submit("a","mock.ping");e!=nil{t.Fatal(e)}
 if e=j.Submit("b","printer.print");e!=nil{t.Fatal(e)}
 if e=j.Begin("b");e!=nil{t.Fatal(e)}
 if e=j.Close();e!=nil{t.Fatal(e)}
 restarted,e:=Open(path,1024*1024);if e!=nil{t.Fatal(e)}
 defer restarted.Close()
 a,_:=restarted.Get("a");b,_:=restarted.Get("b")
 if a.State!=Queued||b.State!=Indeterminate{t.Fatalf("recovery: %+v %+v",a,b)}
 if e=restarted.Begin("b");!errors.Is(e,ErrConflict){t.Fatalf("unsafe retry allowed: %v",e)}
 if e=restarted.Begin("a");e!=nil{t.Fatal(e)}
 if e=restarted.Finish("a",Succeeded,"pong");e!=nil{t.Fatal(e)}
 if e=restarted.Finish("a",Succeeded,"pong");!errors.Is(e,ErrConflict){t.Fatal("duplicate completion allowed")}
 if e=restarted.Submit("a","mock.ping");!errors.Is(e,ErrConflict){t.Fatal("duplicate ID allowed")}
}
func TestCorruptedJournalFailsClosed(t *testing.T){
 path:=filepath.Join(t.TempDir(),"events")
 if e:=os.WriteFile(path,[]byte("{bad"),0600);e!=nil{t.Fatal(e)}
 if j,e:=Open(path,1024*1024);e==nil{j.Close();t.Fatal("corruption accepted")}
}
func TestBoundedAndInvalidOperation(t *testing.T){
 path:=filepath.Join(t.TempDir(),"events")
 j,e:=Open(path,1024);if e!=nil{t.Fatal(e)}
 defer j.Close()
 if e=j.Submit("bad","");e==nil{t.Fatal("empty operation accepted")}
 for i:=0;i<50;i++{
  e=j.Submit(strings.Repeat("x",i+1),strings.Repeat("y",100))
  if errors.Is(e,ErrCapacity){return}
  if e!=nil{t.Fatal(e)}
 }
 t.Fatal("capacity not enforced")
}
