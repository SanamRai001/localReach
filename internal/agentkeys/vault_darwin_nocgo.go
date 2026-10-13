//go:build darwin && !cgo

package agentkeys

// No silent fallback when Security.framework cannot be linked.
type disabledKeychain struct{}
func nativeVault()vaultBackend{return disabledKeychain{}}
func(disabledKeychain)Ready()error{return ErrUnsupported}
func(disabledKeychain)Put(string,[]byte)error{return ErrUnsupported}
func(disabledKeychain)Get(string)([]byte,error){return nil,ErrUnsupported}
