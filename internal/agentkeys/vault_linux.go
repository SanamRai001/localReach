//go:build linux

package agentkeys

import (
 "bytes"
 "context"
 "errors"
 "io"
 "os"
 "os/exec"
 "time"
)

// Linux uses the existing desktop session Secret Service via libsecret's
// /usr/bin/secret-tool. No secret bytes are passed in argv/environment/files.
// A headless machine without an unlocked Secret Service is unsupported.
type linuxVault struct{}
func nativeVault()vaultBackend{return linuxVault{}}
func(linuxVault)Ready()error{
 if os.Getenv("DBUS_SESSION_BUS_ADDRESS")==""{return ErrUnsupported}
 info,err:=os.Stat("/usr/bin/secret-tool")
 if err!=nil||info.IsDir()||info.Mode()&0111==0{return ErrUnsupported}
 return nil
}
func linuxTool(input []byte,args ...string)([]byte,error){
 ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second)
 defer cancel()
 cmd:=exec.CommandContext(ctx,"/usr/bin/secret-tool",args...)
 cmd.Stdin=bytes.NewReader(input)
 var output bytes.Buffer
 // Secret output is bounded independently of the command's input.
 cmd.Stdout=&limitedBuffer{buf:&output,limit:maxFileBytes}
 // Do not forward stderr: it may contain names of user collections or paths.
 cmd.Stderr=io.Discard
 if err:=cmd.Run();err!=nil{return nil,ErrUnsupported}
 return append([]byte(nil),output.Bytes()...),nil
}
type limitedBuffer struct{buf *bytes.Buffer;limit int}
func(b *limitedBuffer)Write(p []byte)(int,error){
 if b.buf.Len()+len(p)>b.limit{return 0,errors.New("secret output too large")}
 return b.buf.Write(p)
}
func(linuxVault)Put(ref string,value []byte)error{
 if len(value)==0||len(value)>maxFileBytes{return ErrCorrupt}
 // secret-tool reads standard input when it is not a tty.
 _,err:=linuxTool(value,"store","--label=LocalReach Agent Identity",
  "application","localreach-agent","identity",ref)
 return err
}
func(linuxVault)Get(ref string)([]byte,error){
 out,err:=linuxTool(nil,"lookup","application","localreach-agent","identity",ref)
 if err!=nil{return nil,ErrCorrupt}
 if len(out)==0{return nil,ErrCorrupt}
 return out,nil
}
