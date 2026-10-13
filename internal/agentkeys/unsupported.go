//go:build !windows

package agentkeys

// Fail closed until native Keychain/Secret Service backends exist. Never
// silently save agent private keys to disk without OS-backed protection.
func protect([]byte)([]byte,error){return nil,ErrUnsupported}
func unprotect([]byte)([]byte,error){return nil,ErrUnsupported}
