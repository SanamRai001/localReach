// Package ownership provides a fail-closed single-process writer sentinel.
// An interrupted process may leave a stale lock: operators must verify no
// writer is alive before removing it. This is NOT an OS advisory file lock.
package ownership

import (
 "errors"
 "os"
)
var ErrInUse=errors.New("journal already owned or stale ownership sentinel exists")
type Lock struct{path string; file *os.File}
func Acquire(path string)(*Lock,error){
 f,err:=os.OpenFile(path+".owner",os.O_WRONLY|os.O_CREATE|os.O_EXCL,0600)
 if os.IsExist(err){return nil,ErrInUse}
 if err!=nil{return nil,err}
 if _,err=f.WriteString("LocalReach exclusive writer sentinel; inspect before manual stale recovery\n");err!=nil{f.Close();return nil,err}
 if err=f.Sync();err!=nil{f.Close();return nil,err}
 return &Lock{path:path+".owner",file:f},nil
}
func(l *Lock)Release()error{
 if l==nil||l.file==nil{return nil}
 if err:=l.file.Close();err!=nil{return err}
 l.file=nil
 return os.Remove(l.path)
}
