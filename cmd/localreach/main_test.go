package main

import (
 "bytes"
 "context"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
)
func TestMockCommandLifecycle(t *testing.T){
 token:="test-token-unique-and-long-enough"
 s:=httptest.NewServer(handler(newRelay(),token));defer s.Close()
 c:=s.Client()
 send:=func(method,path,body,tok string)*http.Response{
  t.Helper()
  req,err:=http.NewRequest(method,s.URL+path,bytes.NewBufferString(body));if err!=nil{t.Fatal(err)}
  req.Header.Set("Authorization","Bearer "+tok)
  resp,err:=c.Do(req);if err!=nil{t.Fatal(err)}
  return resp
 }
 unauthorized:=send("POST","/v1/mock/jobs",`{"operation":"mock.ping"}`,"wrong")
 if unauthorized.StatusCode!=401{t.Fatalf("expected 401, got %d",unauthorized.StatusCode)};unauthorized.Body.Close()
 denied:=send("POST","/v1/mock/jobs",`{"operation":"printer.raw"}`,token)
 if denied.StatusCode!=400{t.Fatalf("unexpected operation must be rejected, got %d",denied.StatusCode)};denied.Body.Close()
 created:=send("POST","/v1/mock/jobs",`{"operation":"mock.ping"}`,token)
 if created.StatusCode!=202{t.Fatalf("expected 202 got %d",created.StatusCode)}
 var j Job
 if err:=json.NewDecoder(created.Body).Decode(&j);err!=nil{t.Fatal(err)};created.Body.Close()
 if j.State!="QUEUED"{t.Fatal(j)}
 if err:=agentStep(context.Background(),c,s.URL,token);err!=nil{t.Fatal(err)}
 status:=send("GET","/v1/mock/jobs/"+j.ID,"",token)
 var got Job
 if err:=json.NewDecoder(status.Body).Decode(&got);err!=nil{t.Fatal(err)};status.Body.Close()
 if got.State!="SUCCEEDED"||got.Result!="pong"{t.Fatalf("unexpected result %+v",got)}
 duplicate:=send("POST","/v1/agent/complete",`{"id":"`+j.ID+`","result":"pong"}`,token)
 if duplicate.StatusCode!=409{t.Fatalf("duplicate completion should conflict; got %d",duplicate.StatusCode)};duplicate.Body.Close()
}
