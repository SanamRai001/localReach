// Package pgauth offers a PostgreSQL-backed challenge/response session for
// preprovisioned administrator Ed25519 keys. No HTTP listener or login UI.
package pgauth

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "crypto/sha256"
 "database/sql"
 "encoding/base64"
 "errors"
 "strconv"
 "strings"
 "time"
)

var ErrDenied=errors.New("administrator authentication denied")
const challengeDomain="localreach/pgauth/login/v1:"
type Actor struct{Organization string;AdminID string;Role string}
type Store struct{DB *sql.DB}
func New(db *sql.DB)*Store{return &Store{DB:db}}
func part(s string)string{return strconv.Itoa(len(s))+":"+s}
// ChallengeMessage is the domain-separated byte message used by native key signers.
func ChallengeMessage(org,admin,nonce string)[]byte{return []byte(challengeDomain+part(org)+part(admin)+part(nonce))}
func SignChallenge(priv ed25519.PrivateKey,org,admin,nonce string)[]byte{
 return ed25519.Sign(priv,ChallengeMessage(org,admin,nonce))
}
func valid(s string)bool{return len(s)>0&&len(s)<=128&&strings.IndexFunc(s,func(r rune)bool{return r<32||r==127})==-1}
func random(n int)(string,error){
 raw:=make([]byte,n)
 if _,err:=rand.Read(raw);err!=nil{return "",err}
 return base64.RawURLEncoding.EncodeToString(raw),nil
}
func(s *Store)begin(ctx context.Context)(*sql.Tx,error){
 if s==nil||s.DB==nil{return nil,ErrDenied}
 return s.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable})
}
// Challenge is for trusted, rate-limited login intake. It does not disclose
// key material, session state, or arbitrary tenant membership.
func(s *Store)Challenge(ctx context.Context,org,admin string)(string,error){
 if !valid(org)||!valid(admin){return "",ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return "",err};defer tx.Rollback()
 var status string
 err=tx.QueryRowContext(ctx,`SELECT k.status FROM lr_admin_keys k
 JOIN lr_organizations o ON o.organization_id=k.organization_id
 WHERE k.organization_id=$1 AND k.admin_id=$2 AND o.status='ACTIVE'
 FOR SHARE OF k,o`,org,admin).Scan(&status)
 if err!=nil||status!="ACTIVE"{return "",ErrDenied}
 nonce,err:=random(32);if err!=nil{return "",err}
 hash:=sha256.Sum256([]byte(nonce))
 res,err:=tx.ExecContext(ctx,`INSERT INTO lr_admin_login_challenges
 (organization_id,admin_id,nonce_hash,expires_at)
 VALUES($1,$2,$3,NOW()+INTERVAL '30 seconds')
 ON CONFLICT(organization_id,admin_id) DO UPDATE
 SET nonce_hash=EXCLUDED.nonce_hash,expires_at=EXCLUDED.expires_at,consumed_at=NULL
 WHERE lr_admin_login_challenges.expires_at < NOW() OR lr_admin_login_challenges.consumed_at IS NOT NULL`,
 org,admin,hash[:])
 if err!=nil{return "",err}
 affected,err:=res.RowsAffected();if err!=nil{return "",err}
 if affected!=1{return "",ErrDenied}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_admin_login_audit(organization_id,admin_id,action)
 VALUES($1,$2,'CHALLENGE')`,org,admin);err!=nil{return "",err}
 if err=tx.Commit();err!=nil{return "",err}
 return nonce,nil
}
// Authenticate atomically consumes a nonce and issues an opaque, short-lived
// bearer token. Only its SHA-256 hash is stored in PostgreSQL.
func(s *Store)Authenticate(ctx context.Context,org,admin,nonce string,proof []byte)(string,error){
 raw,err:=base64.RawURLEncoding.DecodeString(nonce)
 if !valid(org)||!valid(admin)||err!=nil||len(raw)!=32||len(proof)!=ed25519.SignatureSize{return "",ErrDenied}
 tx,err:=s.begin(ctx);if err!=nil{return "",err};defer tx.Rollback()
 var pub []byte
 err=tx.QueryRowContext(ctx,`SELECT k.public_key FROM lr_admin_keys k
 JOIN lr_organizations o ON o.organization_id=k.organization_id
 WHERE k.organization_id=$1 AND k.admin_id=$2 AND k.status='ACTIVE' AND o.status='ACTIVE'
 FOR SHARE OF k,o`,org,admin).Scan(&pub)
 if err!=nil||len(pub)!=ed25519.PublicKeySize{return "",ErrDenied}
 var stored []byte
 var expiry time.Time
 var used sql.NullTime
 err=tx.QueryRowContext(ctx,`SELECT nonce_hash,expires_at,consumed_at
 FROM lr_admin_login_challenges WHERE organization_id=$1 AND admin_id=$2 FOR UPDATE`,org,admin).
 Scan(&stored,&expiry,&used)
 hash:=sha256.Sum256([]byte(nonce))
 if err!=nil||used.Valid||!time.Now().Before(expiry)||!bytes.Equal(stored,hash[:])||
 !ed25519.Verify(ed25519.PublicKey(pub),[]byte(challengeDomain+part(org)+part(admin)+part(nonce)),proof){return "",ErrDenied}
 token,err:=random(32);if err!=nil{return "",err}
 tokenHash:=sha256.Sum256([]byte(token))
 if _,err=tx.ExecContext(ctx,`UPDATE lr_admin_login_challenges SET consumed_at=NOW()
 WHERE organization_id=$1 AND admin_id=$2`,org,admin);err!=nil{return "",err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_admin_sessions
 (organization_id,admin_id,session_hash,expires_at)
 VALUES($1,$2,$3,NOW()+INTERVAL '5 minutes')`,org,admin,tokenHash[:]);err!=nil{return "",err}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_admin_login_audit(organization_id,admin_id,action)
 VALUES($1,$2,'LOGIN')`,org,admin);err!=nil{return "",err}
 if err=tx.Commit();err!=nil{return "",err}
 return token,nil
}
// Authorize checks role and revocation against the LIVE admin/member record,
// not against role claims embedded in a bearer token.
func(s *Store)Authorize(ctx context.Context,org,token string,allowedRoles ...string)(Actor,error){
 if !valid(org)||s==nil||s.DB==nil{return Actor{},ErrDenied}
 raw,err:=base64.RawURLEncoding.DecodeString(token)
 if err!=nil||len(raw)!=32{return Actor{},ErrDenied}
 hash:=sha256.Sum256([]byte(token))
 var actor Actor
 err=s.DB.QueryRowContext(ctx,`SELECT sess.admin_id,k.role
 FROM lr_admin_sessions sess
 JOIN lr_admin_keys k ON k.organization_id=sess.organization_id AND k.admin_id=sess.admin_id
 JOIN lr_organizations o ON o.organization_id=sess.organization_id
 WHERE sess.organization_id=$1 AND sess.session_hash=$2
 AND sess.revoked_at IS NULL AND sess.expires_at>NOW()
 AND k.status='ACTIVE' AND o.status='ACTIVE'`,org,hash[:]).Scan(&actor.AdminID,&actor.Role)
 if err!=nil{return Actor{},ErrDenied}
 accepted:=false
 for _,role:=range allowedRoles{if actor.Role==role{accepted=true;break}}
 if !accepted{return Actor{},ErrDenied}
 actor.Organization=org
 return actor,nil
}
func(s *Store)Logout(ctx context.Context,org,token string)error{
 if !valid(org){return ErrDenied}
 raw,err:=base64.RawURLEncoding.DecodeString(token)
 if err!=nil||len(raw)!=32{return ErrDenied}
 hash:=sha256.Sum256([]byte(token))
 tx,err:=s.begin(ctx);if err!=nil{return err};defer tx.Rollback()
 var admin string
 err=tx.QueryRowContext(ctx,`UPDATE lr_admin_sessions SET revoked_at=NOW()
 WHERE organization_id=$1 AND session_hash=$2 AND revoked_at IS NULL
 RETURNING admin_id`,org,hash[:]).Scan(&admin)
 if err!=nil{return ErrDenied}
 if _,err=tx.ExecContext(ctx,`INSERT INTO lr_admin_login_audit(organization_id,admin_id,action)
 VALUES($1,$2,'LOGOUT')`,org,admin);err!=nil{return err}
 return tx.Commit()
}
