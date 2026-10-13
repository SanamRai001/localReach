// Package journal is a single-process, append-only command state experiment.
// Durable records are fsynced before state is exposed. Never share one file
// between processes; production requires storage locking and compaction.
package journal

import (
 "bufio"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "path/filepath"
 "sync"
 "github.com/SanamRai001/localReach/internal/ownership"
)
type State string
const (
 Queued State = "QUEUED"
 Executing State = "EXECUTING"
 Succeeded State = "SUCCEEDED"
 Failed State = "FAILED"
 Indeterminate State = "INDETERMINATE"
)
var (
 ErrConflict=errors.New("command conflict")
 ErrCapacity=errors.New("journal capacity exceeded")
)
type Command struct {
 ID string `json:"id"`
 Operation string `json:"operation"`
 State State `json:"state"`
 Result string `json:"result,omitempty"`
}
type Journal struct {
 mu sync.Mutex
 file *os.File
 owner *ownership.Lock
 path string
 entries map[string]Command
 maxBytes int64
}
// Open recovers all valid events and refuses malformed or truncated files.
// The caller is responsible for exclusive ownership of the path.
func Open(path string,maxBytes int64)(*Journal,error){
 if maxBytes<1024{return nil,errors.New("invalid journal capacity")}
 if err:=os.MkdirAll(filepath.Dir(path),0700);err!=nil{return nil,err}
 owner,err:=ownership.Acquire(path);if err!=nil{return nil,err}
 f,err:=os.OpenFile(path,os.O_RDWR|os.O_CREATE,0600);if err!=nil{owner.Release();return nil,err}
 j:=&Journal{file:f,owner:owner,path:path,entries:make(map[string]Command),maxBytes:maxBytes}
 reader:=bufio.NewReader(f)
 for {
  line,err:=reader.ReadBytes('\n')
  if err==io.EOF&&len(line)==0{break}
  if err!=nil{f.Close();owner.Release();return nil,fmt.Errorf("journal truncated or unreadable: %w",err)}
  var event Command
  if e:=json.Unmarshal(line,&event);e!=nil||event.ID==""||event.Operation==""{f.Close();owner.Release();return nil,errors.New("invalid journal event")}
  previous,exists:=j.entries[event.ID]
  if !validTransition(previous,exists,event){f.Close();owner.Release();return nil,fmt.Errorf("invalid journal transition for %s",event.ID)}
  j.entries[event.ID]=event
 }
 if _,err=f.Seek(0,io.SeekEnd);err!=nil{f.Close();owner.Release();return nil,err}
 // An interrupted EXECUTING command might have affected real hardware.
 // Never silently requeue it on restart.
 for _,c:=range j.entries{
  if c.State==Executing {
   c.State=Indeterminate
   if err=j.append(c);err!=nil{f.Close();owner.Release();return nil,err}
  }
 }
 return j,nil
}
func validTransition(old Command,exists bool,next Command)bool{
 if !exists{return next.State==Queued && next.Result==""}
 if next.Operation!=old.Operation{return false}
 switch old.State {
 case Queued:return next.State==Executing && next.Result==""
 case Executing:return next.State==Succeeded||next.State==Failed||next.State==Indeterminate
 default:return false
 }
}
func (j *Journal) append(c Command)error{
 b,err:=json.Marshal(c);if err!=nil{return err}
 b=append(b,'\n')
 info,err:=j.file.Stat();if err!=nil{return err}
 if info.Size()+int64(len(b))>j.maxBytes{return ErrCapacity}
 if _,err=j.file.Write(b);err!=nil{return err}
 if err=j.file.Sync();err!=nil{return err}
 j.entries[c.ID]=c
 return nil
}
func (j *Journal) Submit(id,operation string)error{
 j.mu.Lock();defer j.mu.Unlock()
 if id==""||operation==""||len(id)>128||len(operation)>128{return errors.New("invalid command")}
 if _,ok:=j.entries[id];ok{return ErrConflict}
 return j.append(Command{ID:id,Operation:operation,State:Queued})
}
func (j *Journal) Begin(id string)error{return j.transition(id,Executing,"")}
func (j *Journal) Finish(id string,state State,result string)error{
 if state!=Succeeded&&state!=Failed&&state!=Indeterminate{return ErrConflict}
 if len(result)>1024{return errors.New("result too long")}
 return j.transition(id,state,result)
}
func (j *Journal) transition(id string,state State,result string)error{
 j.mu.Lock();defer j.mu.Unlock()
 c,ok:=j.entries[id]
 if !ok{return os.ErrNotExist}
 next:=Command{ID:id,Operation:c.Operation,State:state,Result:result}
 if !validTransition(c,true,next){return ErrConflict}
 return j.append(next)
}
func (j *Journal) Get(id string)(Command,bool){
 j.mu.Lock();defer j.mu.Unlock()
 c,ok:=j.entries[id];return c,ok
}
func (j *Journal) Close()error{j.mu.Lock();defer j.mu.Unlock();if err:=j.file.Close();err!=nil{return err};return j.owner.Release()}
