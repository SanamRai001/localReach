package ownership
import (
 "errors"
 "path/filepath"
 "testing"
)
func TestExclusiveWriterAndStaleSentinel(t *testing.T){
 path:=filepath.Join(t.TempDir(),"journal")
 l,err:=Acquire(path);if err!=nil{t.Fatal(err)}
 if _,err=Acquire(path);!errors.Is(err,ErrInUse){t.Fatalf("concurrent writer admitted: %v",err)}
 if err=l.Release();err!=nil{t.Fatal(err)}
 again,err:=Acquire(path);if err!=nil{t.Fatal(err)}
 defer again.Release()
}
