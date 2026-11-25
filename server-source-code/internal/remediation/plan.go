package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/database"
	"github.com/PatchMon/PatchMon/server-source-code/internal/db"
	"github.com/jackc/pgx/v5"
)

const VerifiedPatchType = "patch_package_verified"
const ValidationMarker = "PATCHMON_VERIFIED_PLAN "
const validationMaxAge = 30*time.Minute

// Snapshot is stored in native PatchMon run history, linking the validated
// package/version set and policy revision to the eventual execution.
type Snapshot struct {
	Managed bool `json:"severity_remediation"`
	PolicyID string `json:"policy_id"`
	PolicyName string `json:"name"`
	Revision int64 `json:"remediation_revision"`
	HostID string `json:"remediation_host_id"`
	Identity string `json:"identity_fingerprint"`
	Packages []VerifiedPackage `json:"verified_packages"`
	Digest string `json:"plan_digest"`
	RolloutDigest string `json:"rollout_digest"`
	Decisions []Decision `json:"remediation_decisions"`
	Routine bool `json:"routine"`
}

func PackageDigest(pkgs []VerifiedPackage) string {
	p:=slices.Clone(pkgs)
	sort.Slice(p,func(i,j int)bool{return p[i].Name<p[j].Name})
	raw,_:=json.Marshal(p)
	sum:=sha256.Sum256(raw);return hex.EncodeToString(sum[:])
}

func MakeSnapshot(c Configuration,h HostEvidence,decisions []Decision)(Snapshot,error) {
	pkgs:=map[string]VerifiedPackage{}
	chosen:=[]Decision{}
	routine:=false
	for _,d:=range decisions {
		if !d.Eligible{continue}
		p:=VerifiedPackage{Name:d.Target.Package,Installed:d.Target.Installed,Candidate:d.Target.Candidate}
		if prior,ok:=pkgs[p.Name];ok&&prior!=p{return Snapshot{},errors.New("conflicting candidates")}
		if len(pkgs)>=64 {if _,ok:=pkgs[p.Name];!ok{continue}}
		pkgs[p.Name]=p
		chosen=append(chosen,d)
		if d.Severity==SeverityRoutine||d.Severity==SeverityMedium||d.Severity==SeverityLow{routine=true}
	}
	list:=make([]VerifiedPackage,0,len(pkgs))
	for _,p:=range pkgs{list=append(list,p)}
	sort.Slice(list,func(i,j int)bool{return list[i].Name<list[j].Name})
	s:=Snapshot{Managed:true,PolicyID:c.PolicyID,PolicyName:c.Name,Revision:c.Revision,HostID:h.HostID,Identity:h.IdentityFingerprint,Packages:list,Decisions:chosen,Routine:routine}
	s.RolloutDigest=PackageDigest(list)
	raw,_:=json.Marshal([]any{s.PolicyID,s.Revision,s.HostID,s.Identity,s.RolloutDigest})
	sum:=sha256.Sum256(raw);s.Digest=hex.EncodeToString(sum[:])
	if err:=s.Validate();err!=nil{return Snapshot{},err}
	return s,nil
}
func (s Snapshot) Validate() error {
	if !s.Managed||s.PolicyID==""||s.HostID==""||s.Identity==""||s.Revision<1||len(s.Packages)==0||len(s.Packages)>64{return errors.New("invalid remediation snapshot")}
	seen:=map[string]bool{}
	for _,p:=range s.Packages{if !p.Valid()||seen[p.Name]{return errors.New("invalid or duplicate remediation package")};seen[p.Name]=true}
	if s.RolloutDigest!=PackageDigest(s.Packages){return errors.New("invalid rollout digest")}
	raw,_:=json.Marshal([]any{s.PolicyID,s.Revision,s.HostID,s.Identity,s.RolloutDigest})
	sum:=sha256.Sum256(raw)
	if s.Digest!=hex.EncodeToString(sum[:]){return errors.New("invalid plan digest")}
	return nil
}

// ParseSnapshot distinguishes ordinary/manual runs from managed remediation.
// A malformed managed snapshot must never be dispatched as an ordinary patch.
func ParseSnapshot(raw []byte)(Snapshot,bool,error) {
	var marker struct{Managed bool `json:"severity_remediation"`}
	if len(raw)==0{return Snapshot{},false,nil}
	if err:=json.Unmarshal(raw,&marker);err!=nil{return Snapshot{},false,err}
	if !marker.Managed{return Snapshot{},false,nil}
	var s Snapshot
	if err:=json.Unmarshal(raw,&s);err!=nil{return s,true,err}
	return s,true,s.Validate()
}

func (s Snapshot) Names() []string {
	names:=make([]string,len(s.Packages))
	for i,p:=range s.Packages{names[i]=p.Name}
	return names
}

func FindHost(e Evidence,id string)(HostEvidence,bool) {
	for _,h:=range e.Hosts {if h.HostID==id{return h,true}}
	return HostEvidence{},false
}

func (s Snapshot) MatchesEvidence(h HostEvidence) bool {
	if h.HostID!=s.HostID||h.IdentityFingerprint!=s.Identity{return false}
	for _,pkg:=range s.Packages {
		found:=false
		for _,t:=range h.Targets {
			if t.Package==pkg.Name&&t.Installed==pkg.Installed&&t.Candidate==pkg.Candidate&&t.FixedCandidateVerified&&(!t.Security||t.VendorApplicable&&Severity(t)!=SeverityUnknown) {found=true;break}
		}
		if !found{return false}
	}
	return true
}

func ValidateDryRun(run *db.GetPatchRunByIDRow,s Snapshot,now time.Time) error {
	if run==nil||!run.DryRun||run.Status!="validated"||run.HostID!=s.HostID||run.PatchType!="patch_package"||
		!run.CompletedAt.Valid||!Fresh(run.CompletedAt.Time,now,validationMaxAge)||run.ErrorMessage!=nil&&*run.ErrorMessage!=""{
		return errors.New("fresh successful validation required")
	}
	old,managed,err:=ParseSnapshot(run.PolicySnapshot)
	if err!=nil||!managed||old.Digest!=s.Digest{return errors.New("validation plan mismatch")}
	proof:=ValidationMarker+s.RolloutDigest
	for _,line:=range strings.Split(run.ShellOutput,"\n"){if strings.TrimSpace(line)==proof{return nil}}
	return errors.New("agent did not attest the exact safe transaction")
}

func LastRoutine(ctx context.Context,d *database.DB,policy,host string)(time.Time,error) {
	tx,err:=d.Begin(ctx);if err!=nil{return time.Time{},err}
	defer func(){_=tx.Rollback(context.WithoutCancel(ctx))}()
	var t *time.Time
	err=tx.QueryRow(ctx,`SELECT max(completed_at) FROM patch_runs WHERE host_id=$1 AND status='completed' AND NOT dry_run
	AND (patch_type='patch_all' OR (policy_id=$2 AND policy_snapshot->>'severity_remediation'='true' AND policy_snapshot->>'routine'='true'))`,host,policy).Scan(&t)
	if err!=nil||t==nil{return time.Time{},err};return *t,nil
}

func LatestAttempt(ctx context.Context,d *database.DB,s Snapshot)(string,error) {
	tx,err:=d.Begin(ctx);if err!=nil{return "",err}
	defer func(){_=tx.Rollback(context.WithoutCancel(ctx))}()
	var id string
	err=tx.QueryRow(ctx,`SELECT id FROM patch_runs WHERE host_id=$1 AND policy_id=$2 AND policy_snapshot->>'plan_digest'=$3 ORDER BY created_at DESC,id DESC LIMIT 1`,s.HostID,s.PolicyID,s.Digest).Scan(&id)
	if errors.Is(err,pgx.ErrNoRows){return "",nil};return id,err
}

func ActiveCount(ctx context.Context,d *database.DB,policy string)(int,error) {
	tx,err:=d.Begin(ctx);if err!=nil{return 0,err}
	defer func(){_=tx.Rollback(context.WithoutCancel(ctx))}()
	var count int
	err=tx.QueryRow(ctx,`SELECT count(*)::int FROM patch_runs WHERE ($1='' OR policy_id=$1) AND status IN ('scheduled','queued','running','agent_disconnected','pending_validation','pending_approval','validated')`,policy).Scan(&count)
	return count,err
}

// CanaryPassed requires the exact same package/version cohort, successful
// execution, subsequent inventory, and fresh independent health evidence.
func CanaryPassed(ctx context.Context,d *database.DB,c Configuration,e Evidence,s Snapshot,now time.Time)(bool,error) {
	if slices.Contains(c.Policy.CanaryHostIDs,s.HostID){return true,nil}
	if len(c.Policy.CanaryHostIDs)==0{return false,nil}
	tx,err:=d.Begin(ctx);if err!=nil{return false,err}
	defer func(){_=tx.Rollback(context.WithoutCancel(ctx))}()
	rows,err:=tx.Query(ctx,`SELECT host_id,completed_at FROM patch_runs WHERE policy_id=$1 AND host_id=ANY($2::text[]) AND status='completed' AND NOT dry_run AND policy_snapshot->>'rollout_digest'=$3 AND policy_snapshot->>'remediation_revision'=$4 ORDER BY completed_at DESC LIMIT 20`,c.PolicyID,c.Policy.CanaryHostIDs,s.RolloutDigest,jsonNumber(c.Revision))
	if err!=nil{return false,err}
	type result struct{id string;at time.Time};results:=[]result{}
	for rows.Next(){var r result;if err=rows.Scan(&r.id,&r.at);err!=nil{rows.Close();return false,err};results=append(results,r)}
	err=rows.Err();rows.Close();if err!=nil{return false,err}
	for _,r:=range results {
		h,ok:=FindHost(e,r.id);if !ok||!h.Safe(now,c.Policy)||h.ObservedAt.Before(r.at)||!Fresh(r.at,now,7*24*time.Hour){continue}
		var confirmed bool
		err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM hosts WHERE id=$1 AND status='active' AND identity_fingerprint=$2 AND packages_hash=$3 AND last_full_report_at >= $4 AND awaiting_post_patch_report_run_id IS NULL AND identity_conflict_at IS NULL AND NOT COALESCE(needs_reboot,false))`,r.id,h.IdentityFingerprint,h.PackagesHash,r.at).Scan(&confirmed)
		if err!=nil{return false,err};if !confirmed{continue}
		ok=true
		for _,p:=range s.Packages{
			var match bool
			err=tx.QueryRow(ctx,`SELECT EXISTS(SELECT 1 FROM host_packages hp JOIN packages p ON p.id=hp.package_id WHERE hp.host_id=$1 AND p.name=$2 AND hp.current_version=$3 AND hp.last_checked >= $4)`,r.id,p.Name,p.Candidate,r.at).Scan(&match)
			if err!=nil{return false,err};if !match{ok=false;break}
		}
		if ok{return true,nil}
	}
	return false,nil
}
func jsonNumber(i int64)string{raw,_:=json.Marshal(i);return string(raw)}

// Recheck validates the current scope and evidence immediately before native
// dispatch. It is also called on offline-agent retries, preventing stale plans.
func Recheck(ctx context.Context,d *database.DB,s Snapshot,now time.Time,real bool)(Configuration,error) {
	c,err:=ReadConfiguration(ctx,d,s.PolicyID);if err!=nil{return c,err}
	if c.Revision!=s.Revision||c.Policy.Mode==ModeDisabled||c.Policy.Mode==ModeShadow||real&&!ExecutionEnabled(){return c,errors.New("remediation paused or changed")}
	id,err:=ResolvePolicy(ctx,d,s.HostID);if err!=nil{return c,err};if id!=s.PolicyID{return c,errors.New("host no longer in effective scope")}
	e,err:=Read(now);if err!=nil{return c,err}
	h,ok:=FindHost(e,s.HostID);if !ok||!s.MatchesEvidence(h){return c,errors.New("current evidence no longer matches plan")}
	if err=CheckHost(ctx,d,h,s.Packages,now,c.Policy);err!=nil{return c,err}
	if c.Policy.Mode==ModeAutomatic {
		ok,err=CanaryPassed(ctx,d,c,e,s,now);if err!=nil{return c,err};if !ok{return c,errors.New("verified canary rollout required")}
	}
	return c,nil
}
