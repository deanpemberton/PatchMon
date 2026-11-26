// Agent-update-only maintenance client for a local single-tenant server.
// Invoke through a trusted administrative path, never as an HTTP endpoint.
package main

import (
 "context"
 "encoding/json"
 "errors"
 "fmt"
 "io"
 "os"
 "regexp"
 "time"

 "github.com/hibiken/asynq"
 "github.com/PatchMon/PatchMon/server-source-code/internal/queue"
)

type Request struct {
 HostID string `json:"host_id"`
 APIID string `json:"api_id"`
 Batch string `json:"batch"`
}

var hostID=regexp.MustCompile("^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$")
var batchID=regexp.MustCompile("^[a-f0-9]{24}$")
var apiID=regexp.MustCompile("^[A-Za-z0-9_.:@-]{1,200}$")

func valid(rows []Request) bool {
 if len(rows)<1 || len(rows)>5 {return false}
 seen:=map[string]bool{}
 seenAPI:=map[string]bool{}
 for _,r:=range rows {
  if !hostID.MatchString(r.HostID)||!batchID.MatchString(r.Batch)||!apiID.MatchString(r.APIID)||seen[r.HostID]||seenAPI[r.APIID]||r.Batch!=rows[0].Batch{return false}
  seen[r.HostID]=true
  seenAPI[r.APIID]=true
 }
 return true
}

func main() {
 if len(os.Args)!=1 {fmt.Fprintln(os.Stderr,"no command-line options supported");os.Exit(2)}
 data,err:=io.ReadAll(io.LimitReader(os.Stdin,16385))
 if err!=nil||len(data)>16384 {fmt.Fprintln(os.Stderr,"invalid request");os.Exit(2)}
 var rows []Request
 if json.Unmarshal(data,&rows)!=nil||!valid(rows){fmt.Fprintln(os.Stderr,"invalid bounded batch");os.Exit(2)}
 // The caller is the local administrator and checks exact enrollment, batch
 // membership, execution switches, and bundle provenance. The native worker
 // independently enforces both agent update gates and active-patch exclusion.
 qc:=queue.NewClient(asynq.RedisClientOpt{Addr:"127.0.0.1:6379",DB:0})
 defer qc.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
 defer cancel()
 for _,r:=range rows {
  task,err:=queue.NewUpdateAgentTask(r.APIID,"",false)
  if err!=nil{fmt.Fprintln(os.Stderr,"native task creation failed");os.Exit(1)}
  id:="agent-rollout-"+r.Batch+"-"+r.HostID
  _,err=qc.EnqueueContext(ctx,task,asynq.TaskID(id),asynq.MaxRetry(0),asynq.Timeout(30*time.Second),asynq.Deadline(time.Now().Add(time.Minute)),asynq.Retention(30*time.Minute))
  if err!=nil&&!errors.Is(err,asynq.ErrTaskIDConflict){fmt.Fprintln(os.Stderr,"native queue enqueue failed");os.Exit(1)}
  fmt.Printf("AGENT_UPDATE_REQUEST %s %s\n",r.HostID,id)
 }
}
