package pgpairing

import (
 "context"
 "database/sql"
 "errors"
 "os"
 "testing"
)
func TestConnectionLeaseLiveRenewDuplicateCrashAndRevocation(t *testing.T){
 db:=integrationDB(t)
 adminPub,adminPriv:=keys(t)
 setupOrg(t,db,"org","site","owner","OWNER",adminPub)
 pub,priv:=keys(t)
 ctx:=context.Background();s:=New(db)
 request,err:=s.Propose(ctx,"org","site",pub);if err!=nil{t.Fatal(err)}
 d:=makeDecision(t,"org",request.RequestID,"owner",Approve)
 if _,err=s.Decide(ctx,d,SignDecision(adminPriv,d));err!=nil{t.Fatal(err)}
 proof,err:=s.Challenge(ctx,"org",request.RequestID);if err!=nil{t.Fatal(err)}
 record,err:=s.Enroll(ctx,"org",request.RequestID,proof,SignEnrollment(priv,"org",request.RequestID,proof));if err!=nil{t.Fatal(err)}
 id:=record.AgentID.String
 first,err:=s.OpenConnection(ctx,"org",id);if err!=nil{t.Fatal(err)}
 if _,err=s.OpenConnection(ctx,"org",id);!errors.Is(err,ErrSessionUnavailable){t.Fatal("duplicate session")}
 other,err:=sql.Open("postgres",os.Getenv("LOCALREACH_TEST_POSTGRES_DSN"));if err!=nil{t.Fatal(err)}
 defer other.Close()
 s2:=New(other)
 if _,err=s2.OpenConnection(ctx,"org",id);!errors.Is(err,ErrSessionUnavailable){t.Fatal("second gateway claimed active lease")}
 if err=s2.RenewConnection(ctx,"org",id,"attacker");!errors.Is(err,ErrSessionUnavailable){t.Fatal("wrong session renewed")}
 if err=s2.RenewConnection(ctx,"org",id,first);err!=nil{t.Fatal(err)}
 online,err:=s2.ConnectionOnline(ctx,"org",id);if err!=nil||!online{t.Fatal("lease not online")}
 if _,err=db.ExecContext(ctx,`UPDATE lr_agent_connections SET expires_at=NOW()-INTERVAL '1 second'
 WHERE organization_id='org' AND agent_id=$1`,id);err!=nil{t.Fatal(err)}
 if err=s.RenewConnection(ctx,"org",id,first);!errors.Is(err,ErrSessionUnavailable){t.Fatal("expired lease renewed")}
 online,err=s.ConnectionOnline(ctx,"org",id);if err!=nil||online{t.Fatal("crashed stream still online")}
 second,err:=s2.OpenConnection(ctx,"org",id);if err!=nil{t.Fatal(err)}
 if second==first{t.Fatal("reclaimed session reused identifier")}
 if err=s.CloseConnection(ctx,"org",id,first);err!=nil{t.Fatal(err)}
 online,err=s2.ConnectionOnline(ctx,"org",id);if err!=nil||!online{t.Fatal("stale owner closed new session")}
 revoke:=makeDecision(t,"org",request.RequestID,"owner",Revoke)
 if _,err=s.Decide(ctx,revoke,SignDecision(adminPriv,revoke));err!=nil{t.Fatal(err)}
 if err=s2.RenewConnection(ctx,"org",id,second);!errors.Is(err,ErrSessionUnavailable){t.Fatal("revoked identity continued online")}
 online,err=s.ConnectionOnline(ctx,"org",id);if err!=nil||online{t.Fatal("revoked agent remained online")}
 if err=s.CloseConnection(ctx,"org",id,second);err!=nil{t.Fatal(err)}
 if _,err=s.OpenConnection(ctx,"org",id);!errors.Is(err,ErrSessionUnavailable){t.Fatal("revoked agent reconnected")}
}
