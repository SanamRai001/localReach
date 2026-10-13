//go:build linux || darwin

package agentkeys

import (
 "bytes"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "os"
 "path/filepath"
 "time"
)

const nativeMarker="identity.ref"
type reference struct{
 Version int `json:"version"`
 ID string `json:"id"`
 Fingerprint string `json:"fingerprint"`
 CreatedAt int64 `json:"createdAt"`
}
// DefaultDir contains only a non-secret marker. Private bytes live in the
// OS credential manager (macOS Keychain or Linux Secret Service).
func DefaultDir()(string,error){
 base,err:=os.UserConfigDir()
 if err!=nil||base==""{return "",ErrUnsupported}
 return filepath.Join(base,"LocalReach","Agent"),nil
}
func(s Store)provider()vaultBackend{
 if s.vault!=nil{return s.vault}
 return nativeVault()
}
func(s Store)markerPath()string{return filepath.Join(s.Dir,nativeMarker)}
func(s Store)Create()(*Identity,error){
 if err:=s.directory();err!=nil{return nil,err}
 provider:=s.provider()
 if err:=provider.Ready();err!=nil{return nil,err}
 pub,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{return nil,err}
 stamp:=time.Now().UTC().Truncate(time.Second)
 idBytes:=make([]byte,32)
 if _,err=rand.Read(idBytes);err!=nil{return nil,err}
 ref:=base64.RawURLEncoding.EncodeToString(idBytes)
 digest:=sha256.Sum256(pub)
 marker:=reference{Version:formatVersion,ID:ref,Fingerprint:base64.RawURLEncoding.EncodeToString(digest[:]),CreatedAt:stamp.Unix()}
 data,err:=json.Marshal(marker);if err!=nil{return nil,err}
 // Claim before writing any secret so competing first-runs cannot create
 // distinct identities. Interrupted provisioning leaves a fail-closed marker.
 file,err:=os.OpenFile(s.markerPath(),os.O_CREATE|os.O_EXCL|os.O_WRONLY,0600)
 if errors.Is(err,os.ErrExist){return nil,ErrExists}
 if err!=nil{return nil,err}
 _,err=file.Write(data)
 if err==nil{err=file.Sync()}
 closeErr:=file.Close()
 if err!=nil{return nil,err}
 if closeErr!=nil{return nil,closeErr}
 raw,err:=json.Marshal(payload{Key:base64.RawURLEncoding.EncodeToString(private),CreatedAt:stamp.Unix()})
 if err!=nil{return nil,err}
 putErr:=provider.Put(ref,raw)
 for k:=range raw{raw[k]=0}
 if putErr!=nil{return nil,putErr}
 return &Identity{private:private,createdAt:stamp},nil
}
func(s Store)Load()(*Identity,error){
 if s.Dir==""{return nil,ErrUnsupported}
 info,err:=os.Lstat(s.Dir)
 if errors.Is(err,os.ErrNotExist){return nil,ErrMissing}
 if err!=nil{return nil,err}
 if !info.IsDir()||info.Mode()&os.ModeSymlink!=0{return nil,ErrCorrupt}
 info,err=os.Lstat(s.markerPath())
 if errors.Is(err,os.ErrNotExist){return nil,ErrMissing}
 if err!=nil{return nil,err}
 if !info.Mode().IsRegular()||info.Size()<2||info.Size()>2048{return nil,ErrCorrupt}
 data,err:=os.ReadFile(s.markerPath());if err!=nil{return nil,err}
 var marker reference
 decoder:=json.NewDecoder(bytes.NewReader(data))
 decoder.DisallowUnknownFields()
 if decoder.Decode(&marker)!=nil||decoder.Decode(new(any))!=io.EOF||marker.Version!=formatVersion||marker.CreatedAt<=0{return nil,ErrCorrupt}
 id,err:=base64.RawURLEncoding.DecodeString(marker.ID)
 if err!=nil||len(id)!=32{return nil,ErrCorrupt}
 want,err:=base64.RawURLEncoding.DecodeString(marker.Fingerprint)
 if err!=nil||len(want)!=sha256.Size{return nil,ErrCorrupt}
 provider:=s.provider()
 if err:=provider.Ready();err!=nil{return nil,err}
 secret,err:=provider.Get(marker.ID)
 if err!=nil{return nil,err}
 defer func(){for n:=range secret{secret[n]=0}}()
 if len(secret)==0||len(secret)>maxFileBytes{return nil,ErrCorrupt}
 var pl payload
 inner:=json.NewDecoder(bytes.NewReader(secret))
 inner.DisallowUnknownFields()
 if inner.Decode(&pl)!=nil||inner.Decode(new(any))!=io.EOF||pl.CreatedAt!=marker.CreatedAt{return nil,ErrCorrupt}
 private,err:=base64.RawURLEncoding.DecodeString(pl.Key)
 if err!=nil||len(private)!=ed25519.PrivateKeySize{return nil,ErrCorrupt}
 derived:=ed25519.NewKeyFromSeed(private[:ed25519.SeedSize])
 if !bytes.Equal(derived,private){return nil,ErrCorrupt}
 digest:=sha256.Sum256(private[32:])
 if !bytes.Equal(digest[:],want){return nil,ErrCorrupt}
 return &Identity{private:ed25519.PrivateKey(private),createdAt:time.Unix(pl.CreatedAt,0).UTC()},nil
}
