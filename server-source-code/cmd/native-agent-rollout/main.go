// A local administrator's one-shot, agent-only rollout utility.
// Uses the same Asynq task type and payload as HostsHandler.ForceAgentUpdate.
// It cannot enqueue package installation, reboots, or arbitrary jobs.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"

	"github.com/hibiken/asynq"
)

const taskType = "update_agent"
const queue = "agent-commands"

type target struct {
	ID string `json:"id"`
	APIID string `json:"api_id"`
}
type payload struct {
	APIID string `json:"api_id"`
	BypassSettings bool `json:"bypass_settings"`
}
var uuidPattern = regexp.MustCompile("^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$")
var apiPattern = regexp.MustCompile("^patchmon_[0-9a-f]{16}$")

func validatedTargets(r io.Reader) ([]target, error) {
	var targets []target
	d := json.NewDecoder(io.LimitReader(r, 32768))
	d.DisallowUnknownFields()
	if err := d.Decode(&targets); err != nil { return nil, err }
	var trailing any
	if d.Decode(&trailing) != io.EOF { return nil, fmt.Errorf("trailing input") }
	if len(targets) < 1 || len(targets) > 50 { return nil, fmt.Errorf("target count out of bounds") }
	ids := map[string]bool{}
	apiIDs := map[string]bool{}
	for _, t := range targets {
		if !uuidPattern.MatchString(t.ID) || !apiPattern.MatchString(t.APIID) || ids[t.ID] || apiIDs[t.APIID] { return nil, fmt.Errorf("invalid or duplicate target") }
		ids[t.ID], apiIDs[t.APIID] = true, true
	}
	return targets, nil
}
func main() {
	if os.Geteuid() != 0 || len(os.Args) != 1 { fmt.Fprintln(os.Stderr,"local root administrator only; JSON targets on stdin"); os.Exit(1) }
	targets, err := validatedTargets(os.Stdin)
	if err != nil { fmt.Fprintln(os.Stderr,"invalid target manifest"); os.Exit(1) }
	client := asynq.NewClient(asynq.RedisClientOpt{Addr:"127.0.0.1:6379",DB:0})
	defer client.Close()
	n := 0
	for i,t := range targets {
		raw,_ := json.Marshal(payload{APIID:t.APIID,BypassSettings:true})
		task := asynq.NewTask(taskType,raw,asynq.Queue(queue),asynq.MaxRetry(1),asynq.Timeout(20*time.Second))
		// Native worker rechecks the active patch gate immediately before
		// transmission. Unique prevents duplicate pending commands.
		_,err := client.Enqueue(task,asynq.Unique(10*time.Minute),asynq.ProcessIn(time.Duration(i/5)*20*time.Second))
		if err == asynq.ErrDuplicateTask { fmt.Printf("ALREADY_QUEUED %s\n",t.ID);continue }
		if err != nil { fmt.Fprintf(os.Stderr,"QUEUE_ERROR %s\n",t.ID);os.Exit(1) }
		fmt.Printf("AGENT_UPDATE_QUEUED %s\n",t.ID);n++
	}
	fmt.Printf("AGENT_UPDATE_QUEUED_COUNT %d\n",n)
}
