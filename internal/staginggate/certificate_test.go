package staginggate

import (
 "crypto/ed25519"
 "crypto/rand"
 "crypto/tls"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "math/big"
 "testing"
 "time"
)
func certificate(t *testing.T,dns string,begin,end time.Time)tls.Certificate{
 t.Helper()
 pub,private,err:=ed25519.GenerateKey(rand.Reader)
 if err!=nil{t.Fatal(err)}
 der,err:=x509.CreateCertificate(rand.Reader,&x509.Certificate{
  SerialNumber:big.NewInt(1),
  Subject:pkix.Name{CommonName:dns},
  DNSNames:[]string{dns},
  NotBefore:begin,NotAfter:end,
  KeyUsage:x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
 },&x509.Certificate{
  SerialNumber:big.NewInt(1),
  Subject:pkix.Name{CommonName:dns},
  DNSNames:[]string{dns},
  NotBefore:begin,NotAfter:end,
  KeyUsage:x509.KeyUsageDigitalSignature,
  ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
 },pub,private)
 if err!=nil{t.Fatal(err)}
 encoded,err:=x509.MarshalPKCS8PrivateKey(private)
 if err!=nil{t.Fatal(err)}
 pair,err:=tls.X509KeyPair(
  pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}),
  pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:encoded}),
 )
 if err!=nil{t.Fatal(err)}
 return pair
}
func TestStagingCertificateIdentityAndExpiration(t *testing.T){
 now:=time.Now()
 valid:=certificate(t,"pilot.example.test",now.Add(-time.Hour),now.Add(time.Hour))
 if err:=ValidateCertificate(valid,"pilot.example.test");err!=nil{t.Fatal(err)}
 if err:=ValidateCertificate(valid,"wrong.example.test");err==nil{t.Fatal("mismatched certificate accepted")}
 expired:=certificate(t,"pilot.example.test",now.Add(-3*time.Hour),now.Add(-time.Hour))
 if err:=ValidateCertificate(expired,"pilot.example.test");err==nil{t.Fatal("expired certificate accepted")}
 future:=certificate(t,"pilot.example.test",now.Add(time.Hour),now.Add(3*time.Hour))
 if err:=ValidateCertificate(future,"pilot.example.test");err==nil{t.Fatal("not-yet-valid certificate accepted")}
}
