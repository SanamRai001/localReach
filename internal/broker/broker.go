// Package broker is a single-process, fsynced mock command dispatcher.
// It is NOT a multi-node or internet-facing control plane.
package broker

import (
 "bufio"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "sync"
 "time"
)
type State string
const(
 Queued State="QUEUED"
 Leased State="LEASED"
 Received State="RECEIVED"
 Succeeded State="SUCCEEDED"
 Failed State="FAILED"
 Indeterminate State="INDETERMINATE"
)
var ErrConflict=errors.New("invalid transition or duplicate command")
var ErrCapacity=errors.New("broker journal capacity reached")
type Command struct{
 ID string `json:"id"`
 Tenant string `json:"tenant"`
 Agent string `json:"agent"`
 Operation string `json:"operation"`
 State State `json:"state"`
 Lease string `json:"lease,omitempty"`
 Until time.Time `json:"until,omitempty"`
 Result string `json:"result,omitempty"`
}
type Broker struct{
 mu sync.Mutex
 file *os.File
 jobs map[string]Command
 now func()time.Time
 limit int64
}
func Open(path string,limit int64,now func()time.Time)(*Broker,error){
 if limit<1024{return nil,errors.New("capacity too small")}
 if now==nil{now=time.Now}
 if e:=os.MkdirAll(filepath.Dir(path),0700);e!=nil{return nil,e}
 f,e:=os.OpenFile(path,os.O_RDWR|os.O_CREATE,0600);if e!=nil{return nil,e}
 b:=&Broker{file:f,jobs:map[string]Command{},now:now,limit:limit}
 reader:=bufio.NewReader(f)
 for{
  line,err:=reader.ReadBytes('\n')
  if err==io.EOF&&len(line)==0{break}
  if err!=nil{f.Close();return nil,errors.New("incomplete broker journal")}
  var c Command
  if json.Unmarshal(line,&c)!=nil||c.ID==""||c.Tenant==""||c.Agent==""||c.Operation!="mock.ping"{f.Close();return nil,errors.New("invalid broker journal")}
  if prev,ok:=b.jobs[c.ID];ok&&(prev.Tenant!=c.Tenant||prev.Agent!=c.Agent||prev.Operation!=c.Operation){f.Close();return nil,errors.New("mutated journal scope")}
  b.jobs[c.ID]=c
 }
 if _,e=f.Seek(0,io.SeekEnd);e!=nil{f.Close();return nil,e}
 return b,nil
}
func(b *Broker)persist(c Command)error{
 bytes,e:=json.Marshal(c);if e!=nil{return e}
 bytes=append(bytes,'\n')
 s,e:=b.file.Stat();if e!=nil{return e}
 if s.Size()+int64(len(bytes))>b.limit{return ErrCapacity}
 n,e:=b.file.Write(bytes);if e!=nil{return e}
 if n!=len(bytes){return io.ErrShortWrite}
 if e=b.file.Sync();e!=nil{return e}
 b.jobs[c.ID]=c
 return nil
}
func(b *Broker)Submit(id,tenant,agent string)error{
 b.mu.Lock();defer b.mu.Unlock()
 if len(id)==0||len(id)>128||len(tenant)==0||len(tenant)>128||len(agent)==0||len(agent)>128{return ErrConflict}
 if _,ok:=b.jobs[id];ok{return ErrConflict}
 return b.persist(Command{ID:id,Tenant:tenant,Agent:agent,Operation:"mock.ping",State:Queued})
}
func newLease()(string,error){
 var buf [24]byte
 if _,e:=rand.Read(buf[:]);e!=nil{return "",e}
 return hex.EncodeToString(buf[:]),nil
}
// Claim leases only QUEUED work or work whose lease expired BEFORE RECEIVED.
// Caller must already authenticate and authorize both tenant and agent.
func(b *Broker)Claim(tenant,agent string,ttl time.Duration)(Command,bool,error){
 b.mu.Lock();defer b.mu.Unlock()
 if tenant==""||agent==""||ttl<=0||ttl>time.Minute{return Command{},false,ErrConflict}
 for _,c:=range b.jobs{
  if c.Tenant!=tenant||c.Agent!=agent{continue}
  if c.State!=Queued && !(c.State==Leased && !b.now().Before(c.Until)){continue}
  lease,e:=newLease();if e!=nil{return Command{},false,e}
  c.State=Leased;c.Lease=lease;c.Until=b.now().Add(ttl)
  if e=b.persist(c);e!=nil{return Command{},false,e}
  return c,true,nil
 }
 return Command{},false,nil
}
// Receive explicitly acknowledges possible onset of device-side execution.
// Lost/expired received work is NOT eligible for automatic leasing again.
func(b *Broker)Receive(id,tenant,agent,lease string)error{
 b.mu.Lock();defer b.mu.Unlock()
 c,ok:=b.jobs[id]
 if !ok||c.Tenant!=tenant||c.Agent!=agent||c.State!=Leased||c.Lease!=lease||!b.now().Before(c.Until){return ErrConflict}
 c.State=Received
 return b.persist(c)
}
func(b *Broker)Complete(id,tenant,agent,lease string,state State,result string)error{
 b.mu.Lock();defer b.mu.Unlock()
 c,ok:=b.jobs[id]
 if !ok||c.Tenant!=tenant||c.Agent!=agent||c.State!=Received||c.Lease!=lease||len(result)>1024{return ErrConflict}
 if state!=Succeeded&&state!=Failed&&state!=Indeterminate{return ErrConflict}
 c.State=state;c.Result=result
 return b.persist(c)
}
// Reconcile transitions RECEIVED to INDETERMINATE after its deadline. This
// avoids wrongly claiming a physical effect has not happened.
func(b *Broker)Reconcile()error{
 b.mu.Lock();defer b.mu.Unlock()
 for _,c:=range b.jobs{
  if c.State==Received&&!b.now().Before(c.Until){
   c.State=Indeterminate;c.Result="execution outcome unknown"
   if e:=b.persist(c);e!=nil{return e}
  }
 }
 return nil
}
func(b *Broker)Get(id,tenant string)(Command,bool){
 b.mu.Lock();defer b.mu.Unlock()
 c,ok:=b.jobs[id]
 if !ok||c.Tenant!=tenant{return Command{},false}
 return c,true
}
func(b *Broker)Close()error{b.mu.Lock();defer b.mu.Unlock();return b.file.Close()}
