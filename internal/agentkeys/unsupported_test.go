//go:build !windows && !linux && !darwin

package agentkeys

import (
 "errors"
 "testing"
)

func TestUnsupportedPlatformFailsClosed(t *testing.T){
 s:=Store{Dir:t.TempDir()}
 if _,err:=s.Create();!errors.Is(err,ErrUnsupported){t.Fatalf("unsupported native store allowed creation: %v",err)}
 if _,err:=protect([]byte("secret"));!errors.Is(err,ErrUnsupported){t.Fatalf("plaintext fallback found: %v",err)}
}
