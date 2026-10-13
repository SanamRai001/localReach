package pairapi

import (
 "context"
 "crypto/sha256"
 "database/sql"
 "net"
 "strings"
)

// Admission gates native API requests before parsing their JSON bodies.
// It fails closed on database errors. Admission is shared by all gateways
// using the same PostgreSQL DB, unlike a process-local token bucket.
type Admission interface { Allow(context.Context,string,string) bool }
type SQLAdmission struct{ DB *sql.DB }
func NewSQLAdmission(db *sql.DB)*SQLAdmission{return &SQLAdmission{DB:db}}
func(a *SQLAdmission)Allow(ctx context.Context,remoteAddr,route string)bool{
 if a==nil||a.DB==nil||len(route)==0||len(route)>100||
 !strings.HasPrefix(route,"/v1/"){return false}
 host,_,err:=net.SplitHostPort(remoteAddr)
 if err!=nil{return false}
 ip:=net.ParseIP(host)
 if ip==nil{return false}
 // A private or local proxy is treated as the *single* source. Never trust
 // unverified forwarding headers when assigning per-client buckets.
 hash:=sha256.Sum256([]byte(ip.String()))
 var attempts int
 err=a.DB.QueryRowContext(ctx,`INSERT INTO lr_admission_windows
 (action,peer_hash,window_start,attempts)
 VALUES($1,$2,NOW(),1)
 ON CONFLICT (action,peer_hash) DO UPDATE SET
 window_start=CASE WHEN lr_admission_windows.window_start<=NOW()-INTERVAL '1 minute'
 THEN NOW() ELSE lr_admission_windows.window_start END,
 attempts=CASE WHEN lr_admission_windows.window_start<=NOW()-INTERVAL '1 minute'
 THEN 1 ELSE lr_admission_windows.attempts+1 END
 WHERE lr_admission_windows.attempts<5 OR
 lr_admission_windows.window_start<=NOW()-INTERVAL '1 minute'
 RETURNING attempts`,route,hash[:]).Scan(&attempts)
 return err==nil&&attempts>=1&&attempts<=5
}
