//go:build windows

package agentkeys

import (
 "errors"
 "runtime"
 "syscall"
 "unsafe"
)

const uiForbidden=0x1
type dataBlob struct {
 size uint32
 data *byte
}
var (
 crypt32=syscall.NewLazyDLL("crypt32.dll")
 kernel32=syscall.NewLazyDLL("kernel32.dll")
 procProtect=crypt32.NewProc("CryptProtectData")
 procUnprotect=crypt32.NewProc("CryptUnprotectData")
 procLocalFree=kernel32.NewProc("LocalFree")
)
func dpapi(input []byte,encrypt bool)([]byte,error){
 if len(input)==0||len(input)>maxFileBytes{return nil,ErrCorrupt}
 in:=dataBlob{size:uint32(len(input)),data:&input[0]}
 var out dataBlob
 var result uintptr
 var callErr error
 if encrypt{
  result,_,callErr=procProtect.Call(
   uintptr(unsafe.Pointer(&in)),0,0,0,0,
   uintptr(uiForbidden),uintptr(unsafe.Pointer(&out)))
 }else{
  result,_,callErr=procUnprotect.Call(
   uintptr(unsafe.Pointer(&in)),0,0,0,0,
   uintptr(uiForbidden),uintptr(unsafe.Pointer(&out)))
 }
 runtime.KeepAlive(input)
 if result==0{
  if callErr!=nil&&!errors.Is(callErr,syscall.Errno(0)){return nil,callErr}
  return nil,ErrCorrupt
 }
 if out.data==nil||out.size==0||out.size>maxFileBytes{
  if out.data!=nil{procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))}
  return nil,ErrCorrupt
 }
 allocated:=unsafe.Slice(out.data,int(out.size))
 copied:=append([]byte(nil),allocated...)
 // Release the DPAPI-owned buffer. The private key remains in the backend
 // process while the Identity is in use; Go cannot guarantee full zeroization.
 for i:=range allocated{allocated[i]=0}
 procLocalFree.Call(uintptr(unsafe.Pointer(out.data)))
 return copied,nil
}
func protect(b []byte)([]byte,error){return dpapi(b,true)}
func unprotect(b []byte)([]byte,error){return dpapi(b,false)}
