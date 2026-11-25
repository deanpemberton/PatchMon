package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/database"
	"github.com/jackc/pgx/v5"
)

type Configuration struct {
	PolicyID  string          `json:"policy_id"`
	Name      string          `json:"name"`
	DelayType string          `json:"delay_type"`
	Revision  int64           `json:"revision"`
	Policy    Policy          `json:"policy"`
	Report    json.RawMessage `json:"report,omitempty"`
}

func ReadConfiguration(ctx context.Context, d *database.DB, id string) (Configuration, error) {
	c := Configuration{PolicyID: id, Policy: DefaultPolicy()}
	tx, err := d.Begin(ctx)
	if err != nil {
		return c, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var raw []byte
	err = tx.QueryRow(ctx, `SELECT p.name,p.patch_delay_type,r.settings,COALESCE(r.revision,0),r.report FROM patch_policies p LEFT JOIN patch_remediation_policies r ON r.policy_id=p.id WHERE p.id=$1`, id).Scan(&c.Name, &c.DelayType, &raw, &c.Revision, &c.Report)
	if err != nil {
		return c, err
	}
	if len(raw) > 0 {
		if err = json.Unmarshal(raw, &c.Policy); err != nil {
			return c, err
		}
	}
	return c, c.Policy.Validate()
}

func WriteConfiguration(ctx context.Context, d *database.DB, id, actor string, expected int64, p Policy) error {
	if actor == "" {
		return errors.New("authenticated policy editor required")
	}
	if err := p.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// Lock the native policy to serialize creation and edits, including legacy
	// schedule changes. A severity policy must never fall through to patch_all.
	var delay string
	if err = tx.QueryRow(ctx, "SELECT patch_delay_type FROM patch_policies WHERE id=$1 FOR UPDATE", id).Scan(&delay); err != nil {
		return err
	}
	if p.Mode != ModeDisabled && delay != "immediate" {
		return ErrImmediateRequired
	}
	if p.RecoveryWaiverUntil != nil {
		if !p.recoveryWaiverActive(p.CanaryHostIDs[0], time.Now().UTC()) {
			return ErrRecoveryWaiverScope
		}
		var single bool
		if err = tx.QueryRow(ctx, "SELECT count(*)=1 AND count(*) FILTER (WHERE target_type='host' AND target_id=$2)=1 FROM patch_policy_assignments WHERE patch_policy_id=$1", id, p.CanaryHostIDs[0]).Scan(&single); err != nil {
			return err
		}
		if !single {
			return ErrRecoveryWaiverScope
		}
	}
	var revision int64
	err = tx.QueryRow(ctx, "SELECT revision FROM patch_remediation_policies WHERE policy_id=$1", id).Scan(&revision)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if revision != expected {
		return ErrRevision
	}
	if p.Mode != ModeDisabled {
		if _, err = tx.Exec(ctx, "UPDATE patch_policies SET auto_patch_enabled=false,auto_reboot=false,updated_at=NOW() WHERE id=$1", id); err != nil {
			return err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO patch_remediation_policies(policy_id,settings,revision,updated_by) VALUES($1,$2::jsonb,1,$3)
	ON CONFLICT(policy_id) DO UPDATE SET settings=EXCLUDED.settings,revision=patch_remediation_policies.revision+1,updated_by=EXCLUDED.updated_by,updated_at=NOW(),report=NULL`, id, raw, actor)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var ErrImmediateRequired = errors.New("severity remediation requires an immediate native policy")
var ErrRevision = errors.New("policy changed; reload before saving")
var ErrRecoveryWaiverScope = errors.New("recovery waiver requires exactly one directly assigned canary and a current one-hour window")

func ListConfigurations(ctx context.Context, d *database.DB) ([]Configuration, error) {
	tx, err := d.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	rows, err := tx.Query(ctx, `SELECT p.id,p.name,p.patch_delay_type,r.settings,r.revision FROM patch_remediation_policies r JOIN patch_policies p ON p.id=r.policy_id ORDER BY p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Configuration{}
	for rows.Next() {
		var c Configuration
		var raw []byte
		if err = rows.Scan(&c.PolicyID, &c.Name, &c.DelayType, &raw, &c.Revision); err != nil {
			return nil, err
		}
		if err = json.Unmarshal(raw, &c.Policy); err != nil {
			return nil, err
		}
		if err = c.Policy.Validate(); err != nil {
			return nil, err
		}
		if c.Policy.Mode != ModeDisabled {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

type Report struct {
	EvaluatedAt        time.Time    `json:"evaluated_at"`
	Mode               string       `json:"mode"`
	EvidenceAvailable  bool         `json:"evidence_available"`
	ExecutionEnabled   bool         `json:"execution_enabled"`
	Reason             string       `json:"reason,omitempty"`
	Hosts              []HostReport `json:"hosts"`
	OpenFindings       int          `json:"open_findings"`
	OverdueFindings    int          `json:"overdue_findings"`
	UnobservedFindings int          `json:"unobserved_findings"`
}
type HostReport struct {
	HostID                      string     `json:"host_id"`
	Decisions                   []Decision `json:"decisions"`
	Blocker                     string     `json:"blocker,omitempty"`
	RunID                       string     `json:"run_id,omitempty"`
	UnclassifiedSecurityUpdates []string   `json:"unclassified_security_updates,omitempty"`
}

func SaveReport(ctx context.Context, d *database.DB, c Configuration, r Report) error {
	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err = tx.QueryRow(ctx, `SELECT count(*)::int,count(*) FILTER(WHERE deadline <= $2)::int,count(*) FILTER(WHERE last_seen < $2 - interval '30 minutes')::int FROM patch_remediation_findings WHERE policy_id=$1 AND resolved_at IS NULL`, c.PolicyID, r.EvaluatedAt).Scan(&r.OpenFindings, &r.OverdueFindings, &r.UnobservedFindings); err != nil {
		return err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if len(raw) > MaxEvidenceBytes {
		return errors.New("report too large")
	}
	_, err = tx.Exec(ctx, "UPDATE patch_remediation_policies SET report=$1::jsonb WHERE policy_id=$2 AND revision=$3", raw, c.PolicyID, c.Revision)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// Observe persists the first discovery and earliest outstanding SLA deadline.
// An absent scanner observation never closes a finding. A previously verified
// resolution starts a new observation only if the same finding reappears.
func Observe(ctx context.Context, d *database.DB, c Configuration, h HostEvidence, now, lastRoutine time.Time) ([]Decision, error) {
	tx, err := d.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	out := make([]Decision, 0, len(h.Targets))
	for _, t := range h.Targets {
		if t.FirstSeen.After(now) {
			return nil, errors.New("future finding")
		}
		key := t.CVE
		if key == "" {
			key = "routine:" + t.Installed + ":" + t.Candidate
		}
		var first time.Time
		var priorDeadline *time.Time
		err = tx.QueryRow(ctx, `SELECT first_seen,deadline FROM patch_remediation_findings WHERE policy_id=$1 AND host_id=$2 AND package_name=$3 AND finding_key=$4 AND resolved_at IS NULL FOR UPDATE`, c.PolicyID, h.HostID, t.Package, key).Scan(&first, &priorDeadline)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if !first.IsZero() && first.Before(t.FirstSeen) {
			t.FirstSeen = first
		}
		x := Evaluate(c.Policy, t, now, lastRoutine)
		if priorDeadline != nil && (x.Deadline == nil || priorDeadline.Before(*x.Deadline)) {
			x.Deadline = priorDeadline
			x.Overdue = !now.Before(*priorDeadline)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO patch_remediation_findings(policy_id,host_id,package_name,finding_key,first_seen,last_seen,deadline)
		VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(policy_id,host_id,package_name,finding_key) DO UPDATE SET
		first_seen=EXCLUDED.first_seen,last_seen=EXCLUDED.last_seen,deadline=EXCLUDED.deadline,resolved_at=NULL`, c.PolicyID, h.HostID, t.Package, key, t.FirstSeen, now, x.Deadline); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	// A trusted scanner must explicitly attest a fixed finding, and live inventory
	// must confirm the reported installed version. Absence alone is not evidence.
	for _, f := range h.ResolvedFindings {
		var installed string
		err = tx.QueryRow(ctx, `SELECT hp.current_version FROM host_packages hp JOIN packages p ON p.id=hp.package_id WHERE hp.host_id=$1 AND p.name=$2`, h.HostID, f.Package).Scan(&installed)
		if errors.Is(err, pgx.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if installed != f.Installed {
			continue
		}
		_, err = tx.Exec(ctx, `UPDATE patch_remediation_findings SET resolved_at=$1 WHERE policy_id=$2 AND host_id=$3 AND package_name=$4 AND finding_key=$5 AND resolved_at IS NULL AND last_seen <= $6`, now, c.PolicyID, h.HostID, f.Package, f.Key, h.ObservedAt)
		if err != nil {
			return nil, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, err
	}
	Ordered(out)
	return out, nil
}

// ResolvePolicy uses the same native assignment ordering but propagates all
// lookup failures. Explicit remediation exclusions also apply to direct
// assignments; this is intentionally more conservative than manual patching.
func ResolvePolicy(ctx context.Context, d *database.DB, hostID string) (string, error) {
	tx, err := d.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var id string
	err = tx.QueryRow(ctx, `SELECT a.patch_policy_id FROM patch_policy_assignments a WHERE (a.target_type='host' AND a.target_id=$1) OR
	(a.target_type='host_group' AND EXISTS(SELECT 1 FROM host_group_memberships m WHERE m.host_id=$1 AND m.host_group_id=a.target_id))
	ORDER BY CASE WHEN a.target_type='host' THEN 0 ELSE 1 END,a.created_at,a.id LIMIT 1`, hostID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var excluded bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM patch_policy_exclusions WHERE host_id=$1 AND patch_policy_id=$2)", hostID, id).Scan(&excluded); err != nil {
		return "", err
	}
	if excluded {
		return "", nil
	}
	return id, nil
}

// CheckHost binds evidence to live enrollment identity, package snapshot and
// exact package candidates. It performs no network or package operation.
func CheckDispatchIdentity(ctx context.Context, d *database.DB, hostID, apiID string) error {
	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var match bool
	if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM hosts WHERE id=$1 AND api_id=$2 AND identity_conflict_at IS NULL)", hostID, apiID).Scan(&match); err != nil {
		return err
	}
	if !match {
		return errors.New("dispatch enrollment identity changed")
	}
	return nil
}

func CheckHost(ctx context.Context, d *database.DB, h HostEvidence, pkgs []VerifiedPackage, now time.Time, p Policy) error {
	if !h.Safe(now, p) {
		return errors.New("backup, recovery, health or evidence freshness gate")
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var status, manager, osType, osVersion, fingerprint, hash string
	var lastUpdate, lastReport *time.Time
	var conflict, reboot, waiting bool
	err = tx.QueryRow(ctx, `SELECT status,COALESCE(package_manager,''),os_type,os_version,COALESCE(identity_fingerprint,''),COALESCE(packages_hash,''),last_update,last_full_report_at,identity_conflict_at IS NOT NULL,COALESCE(needs_reboot,false),awaiting_post_patch_report_run_id IS NOT NULL FROM hosts WHERE id=$1`, h.HostID).Scan(&status, &manager, &osType, &osVersion, &fingerprint, &hash, &lastUpdate, &lastReport, &conflict, &reboot, &waiting)
	if err != nil {
		return err
	}
	if status != "active" || manager != "apt" || osType != h.OS || osVersion != h.OSVersion || fingerprint != h.IdentityFingerprint || hash != h.PackagesHash || conflict || reboot || waiting || lastUpdate == nil || lastReport == nil || !Fresh(*lastUpdate, now, 90*time.Minute) || !Fresh(*lastReport, now, 24*time.Hour) {
		return errors.New("host identity, package snapshot or health gate")
	}
	for _, pkg := range pkgs {
		if !pkg.Valid() {
			return errors.New("invalid package")
		}
		var installed, candidate string
		var checked time.Time
		var pending bool
		err = tx.QueryRow(ctx, `SELECT hp.current_version,COALESCE(hp.available_version,''),hp.last_checked,hp.needs_update FROM host_packages hp JOIN packages p ON p.id=hp.package_id WHERE hp.host_id=$1 AND p.name=$2`, h.HostID, pkg.Name).Scan(&installed, &candidate, &checked, &pending)
		if err != nil {
			return err
		}
		if !pending || installed != pkg.Installed || candidate != pkg.Candidate || !Fresh(checked, now, 24*time.Hour) {
			return fmt.Errorf("package snapshot changed: %s", pkg.Name)
		}
	}
	return nil
}

func CheckEvidenceIdentity(ctx context.Context, d *database.DB, h HostEvidence, now time.Time) error {
	if !Fresh(h.ObservedAt, now, MaxEvidenceAge) || h.IdentityFingerprint == "" || h.PackagesHash == "" {
		return errors.New("invalid host evidence identity")
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var matches bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM hosts WHERE id=$1 AND identity_fingerprint=$2 AND packages_hash=$3 AND os_type=$4 AND os_version=$5 AND status='active' AND identity_conflict_at IS NULL AND last_update >= $6 AND last_full_report_at >= $7)`, h.HostID, h.IdentityFingerprint, h.PackagesHash, h.OS, h.OSVersion, now.Add(-90*time.Minute), now.Add(-24*time.Hour)).Scan(&matches); err != nil {
		return err
	}
	if !matches {
		return errors.New("host evidence does not match current inventory")
	}
	return nil
}
