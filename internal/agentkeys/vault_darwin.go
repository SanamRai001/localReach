//go:build darwin && cgo

package agentkeys

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <string.h>
#include <stdlib.h>

static OSStatus lr_put(const char* account, const unsigned char* data, int length) {
 CFStringRef acct=CFStringCreateWithCString(kCFAllocatorDefault,account,kCFStringEncodingUTF8);
 if (!acct) return errSecParam;
 CFDataRef secret=CFDataCreate(kCFAllocatorDefault,data,length);
 if (!secret) {CFRelease(acct);return errSecParam;}
 CFMutableDictionaryRef attrs=CFDictionaryCreateMutable(kCFAllocatorDefault,0,
   &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 if (!attrs) {CFRelease(acct);CFRelease(secret);return errSecParam;}
 CFDictionarySetValue(attrs,kSecClass,kSecClassGenericPassword);
 CFDictionarySetValue(attrs,kSecAttrService,CFSTR("com.localreach.agent.identity"));
 CFDictionarySetValue(attrs,kSecAttrAccount,acct);
 CFDictionarySetValue(attrs,kSecValueData,secret);
 OSStatus rc=SecItemAdd(attrs,NULL); // Duplicate items are denied, not overwritten
 CFRelease(attrs);CFRelease(secret);CFRelease(acct);
 return rc;
}
static OSStatus lr_get(const char* account,unsigned char* out,int max,int* actual) {
 CFStringRef acct=CFStringCreateWithCString(kCFAllocatorDefault,account,kCFStringEncodingUTF8);
 if (!acct)return errSecParam;
 CFMutableDictionaryRef query=CFDictionaryCreateMutable(kCFAllocatorDefault,0,
   &kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
 if (!query){CFRelease(acct);return errSecParam;}
 CFDictionarySetValue(query,kSecClass,kSecClassGenericPassword);
 CFDictionarySetValue(query,kSecAttrService,CFSTR("com.localreach.agent.identity"));
 CFDictionarySetValue(query,kSecAttrAccount,acct);
 CFDictionarySetValue(query,kSecMatchLimit,kSecMatchLimitOne);
 CFDictionarySetValue(query,kSecReturnData,kCFBooleanTrue);
 CFTypeRef item=NULL;
 OSStatus rc=SecItemCopyMatching(query,&item);
 CFRelease(query);CFRelease(acct);
 if(rc!=errSecSuccess)return rc;
 if(!item||CFGetTypeID(item)!=CFDataGetTypeID()){if(item)CFRelease(item);return errSecParam;}
 CFDataRef data=(CFDataRef)item;
 CFIndex size=CFDataGetLength(data);
 if(size<=0||size>max){CFRelease(item);return errSecParam;}
 memcpy(out,CFDataGetBytePtr(data),size);
 *actual=(int)size;
 CFRelease(item);
 return errSecSuccess;
}
*/
import "C"
import (
 "unsafe"
)

type keychainVault struct{}
func nativeVault()vaultBackend{return keychainVault{}}
func(keychainVault)Ready()error{return nil}
func(keychainVault)Put(ref string,value []byte)error{
 if len(value)==0||len(value)>maxFileBytes{return ErrCorrupt}
 account:=C.CString(ref)
 defer C.free(unsafe.Pointer(account))
 rc:=C.lr_put(account,(*C.uchar)(unsafe.Pointer(&value[0])),C.int(len(value)))
 if rc!=C.errSecSuccess{return ErrUnsupported}
 return nil
}
func(keychainVault)Get(ref string)([]byte,error){
 account:=C.CString(ref)
 defer C.free(unsafe.Pointer(account))
 out:=make([]byte,maxFileBytes)
 var n C.int
 rc:=C.lr_get(account,(*C.uchar)(unsafe.Pointer(&out[0])),C.int(len(out)),&n)
 if rc!=C.errSecSuccess{return nil,ErrCorrupt}
 if n<=0||int(n)>len(out){return nil,ErrCorrupt}
 copied:=append([]byte(nil),out[:int(n)]...)
 for i:=range out{out[i]=0}
 return copied,nil
}
