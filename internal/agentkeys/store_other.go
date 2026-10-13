//go:build !windows && !linux && !darwin

package agentkeys

func DefaultDir()(string,error){return "",ErrUnsupported}
func(Store)Create()(*Identity,error){return nil,ErrUnsupported}
func(Store)Load()(*Identity,error){return nil,ErrUnsupported}
