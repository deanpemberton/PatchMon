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
const validationMaxAge = 30 * time.Minute

// Snapshot is stored in native PatchMon run history, linking the validated
// package/version set and policy revision to the eventual execution.
type Snapshot struct {
	Managed       bool              `json:"severity_remediation"`
	PolicyID      string            `json:"policy_id"`
	PolicyName    string            `json:"name"`
	Revision      int64             `json:"remediation_revision"`
	HostID        string            `json:"remediation_host_id"`
	Identity      string            `json:"identity_fingerprint"`
	Packages      []VerifiedPackage `json:"verified_packages"`
	Digest        string            `json:"plan_digest"`
	RolloutDigest string            `json:"rollout_digest"`
	Decisions     []Decision        `json:"remediation_decisions"`
	Routine       bool              `json:"routine"`
}

func PackageDigest(pkgs []VerifiedPackage) string {
	p := slices.Clone(pkgs)
	sort.Slice(p, func(i, j int) bool { return p[i].Name < p[j].Name })
	raw, _ := json.Marshal(p)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func MakeSnapshot(c Configuration, h HostEvidence, decisions []Decision) (Snapshot, error) {
	pkgs := map[string]VerifiedPackage{}
	chosen := []Decision{}
	routine := false
	for _, d := range decisions {
		if !d.Eligible || slices.Contains(h.UnclassifiedSecurityUpdates, d.Target.Package) {
			continue
		}
		if !d.Target.Security {
			blocked := false
			for _, other := range decisions {
				if other.Target.Package == d.Target.Package && other.Target.Security {
					blocked = true
					break
				}
			}
			if blocked {
				continue
			}
		}
		p := VerifiedPackage{Name: d.Target.Package, Installed: d.Target.Installed, Candidate: d.Target.Candidate}
		if prior, ok := pkgs[p.Name]; ok && prior != p {
			return Snapshot{}, errors.New("conflicting candidates")
		}
		if len(pkgs) >= 64 {
			if _, ok := pkgs[p.Name]; !ok {
				continue
			}
		}
		pkgs[p.Name] = p
		chosen = append(chosen, d)
		if d.Severity == SeverityRoutine || d.Severity == SeverityMedium || d.Severity == SeverityLow {
			routine = true
		}
	}
	list := make([]VerifiedPackage, 0, len(pkgs))
	for _, p := range pkgs {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	s := Snapshot{Managed: true, PolicyID: c.PolicyID, PolicyName: c.Name, Revision: c.Revision, HostID: h.HostID, Identity: h.IdentityFingerprint, Packages: list, Decisions: chosen, Routine: routine}
	s.RolloutDigest = PackageDigest(list)
	raw, _ := json.Marshal([]any{s.PolicyID, s.Revision, s.HostID, s.Identity, s.RolloutDigest})
	sum := sha256.Sum256(raw)
	s.Digest = hex.EncodeToString(sum[:])
	if err := s.Validate(); err != nil {
		return Snapshot{}, err
	}
	return s, nil
}
func (s Snapshot) Validate() error {
	if !s.Managed || s.PolicyID == "" || s.HostID == "" || s.Identity == "" || s.Revision < 1 || len(s.Packages) == 0 || len(s.Packages) > 64 {
		return errors.New("invalid remediation snapshot")
	}
	seen := map[string]bool{}
	for _, p := range s.Packages {
		if !p.Valid() || seen[p.Name] {
			return errors.New("invalid or duplicate remediation package")
		}
		seen[p.Name] = true
	}
	if s.RolloutDigest != PackageDigest(s.Packages) {
		return errors.New("invalid rollout digest")
	}
	raw, _ := json.Marshal([]any{s.PolicyID, s.Revision, s.HostID, s.Identity, s.RolloutDigest})
	sum := sha256.Sum256(raw)
	if s.Digest != hex.EncodeToString(sum[:]) {
		return errors.New("invalid plan digest")
	}
	return nil
}

// ParseSnapshot distinguishes ordinary/manual runs from managed remediation.
// A malformed managed snapshot must never be dispatched as an ordinary patch.
func ParseSnapshot(raw []byte) (Snapshot, bool, error) {
	var marker struct {
		Managed bool `json:"severity_remediation"`
	}
	if len(raw) == 0 {
		return Snapshot{}, false, nil
	}
	if err := json.Unmarshal(raw, &marker); err != nil {
		return Snapshot{}, false, err
	}
	if !marker.Managed {
		return Snapshot{}, false, nil
	}
	var s Snapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return s, true, err
	}
	return s, true, s.Validate()
}

func (s Snapshot) Names() []string {
	names := make([]string, len(s.Packages))
	for i, p := range s.Packages {
		names[i] = p.Name
	}
	return names
}

func FindHost(e Evidence, id string) (HostEvidence, bool) {
	for _, h := range e.Hosts {
		if h.HostID == id {
			return h, true
		}
	}
	return HostEvidence{}, false
}

func (s Snapshot) MatchesEvidence(h HostEvidence) bool {
	if h.HostID != s.HostID || h.IdentityFingerprint != s.Identity {
		return false
	}
	for _, pkg := range s.Packages {
		if slices.Contains(h.UnclassifiedSecurityUpdates, pkg.Name) {
			return false
		}
		found := false
		security := false
		for _, t := range h.Targets {
			if t.Package == pkg.Name && t.Security {
				security = true
				break
			}
		}
		for _, t := range h.Targets {
			if t.Package == pkg.Name && t.Installed == pkg.Installed && t.Candidate == pkg.Candidate && t.FixedCandidateVerified && ((!t.Security && !security) || (t.Security && t.VendorApplicable && Severity(t) != SeverityUnknown && Severity(t) != SeverityNone)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func ValidateDryRun(run *db.GetPatchRunByIDRow, s Snapshot, now time.Time) error {
	if run == nil || !run.DryRun || run.Status != "validated" || run.HostID != s.HostID || run.PatchType != "patch_package" ||
		!run.CompletedAt.Valid || !Fresh(run.CompletedAt.Time, now, validationMaxAge) || run.ErrorMessage != nil && *run.ErrorMessage != "" {
		return errors.New("fresh successful validation required")
	}
	old, managed, err := ParseSnapshot(run.PolicySnapshot)
	if err != nil || !managed || old.Digest != s.Digest {
		return errors.New("validation plan mismatch")
	}
	proof := ValidationMarker + s.RolloutDigest
	for _, line := range strings.Split(run.ShellOutput, "\n") {
		if strings.TrimSpace(line) == proof {
			return nil
		}
	}
	return errors.New("agent did not attest the exact safe transaction")
}

func LastRoutine(ctx context.Context, d *database.DB, policy, host string) (time.Time, error) {
	tx, err := d.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var t *time.Time
	err = tx.QueryRow(ctx, `SELECT max(completed_at) FROM patch_runs WHERE host_id=$1 AND status='completed' AND NOT dry_run
	AND (patch_type='patch_all' OR (policy_id=$2 AND policy_snapshot->>'severity_remediation'='true' AND policy_snapshot->>'routine'='true'))`, host, policy).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return *t, nil
}

func LatestAttempt(ctx context.Context, d *database.DB, s Snapshot) (string, error) {
	tx, err := d.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var id string
	err = tx.QueryRow(ctx, `SELECT id FROM patch_runs WHERE host_id=$1 AND policy_id=$2 AND policy_snapshot->>'plan_digest'=$3 ORDER BY created_at DESC,id DESC LIMIT 1`, s.HostID, s.PolicyID, s.Digest).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func ActiveCount(ctx context.Context, d *database.DB, policy string) (int, error) {
	tx, err := d.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var count int
	err = tx.QueryRow(ctx, `SELECT count(*)::int FROM patch_runs WHERE ($1='' OR policy_id=$1) AND status IN ('scheduled','queued','running','agent_disconnected','pending_validation','pending_approval','validated')`, policy).Scan(&count)
	return count, err
}

// CanaryPassed admits a first eligible host for each exact package/version
// cohort under the current authenticated policy revision. Native run history
// elects that host durably, including a failed validation or execution. Other
// hosts must wait for successful installation, fresh inventory and health.
// The scheduler's transaction advisory lock serializes initial run creation;
// dispatch retries use the same persisted election. A time-limited single-host
// recovery waiver retains its original fixed scope.
func CanaryPassed(ctx context.Context, d *database.DB, c Configuration, e Evidence, s Snapshot, now time.Time) (bool, error) {
	if c.Policy.RecoveryWaiverUntil != nil {
		return c.Policy.recoveryWaiverActive(s.HostID, now), nil
	}
	current, ok := FindHost(e, s.HostID)
	if !ok || !current.Safe(now, c.Policy) || current.OS == "" || current.OSVersion == "" {
		return false, nil
	}
	tx, err := d.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var elected, identity string
	err = tx.QueryRow(ctx, `SELECT r.host_id, coalesce(r.policy_snapshot->>'identity_fingerprint','')
	FROM patch_runs r JOIN hosts h ON h.id=r.host_id
	WHERE r.policy_id=$1 AND r.policy_snapshot->>'severity_remediation'='true'
	AND r.policy_snapshot->>'rollout_digest'=$2 AND r.policy_snapshot->>'remediation_revision'=$3
	AND h.os_type=$4 AND h.os_version=$5
	ORDER BY r.created_at ASC,r.id ASC LIMIT 1`, c.PolicyID, s.RolloutDigest, jsonNumber(c.Revision), current.OS, current.OSVersion).Scan(&elected, &identity)
	if errors.Is(err, pgx.ErrNoRows) {
		// No cohort attempt exists. The first safe candidate can begin its
		// native dry run; the scheduler holds the election lock until queued.
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if identity == "" {
		return false, nil
	}
	if elected == s.HostID {
		// Only that exact enrolled host may continue its own validation/run.
		// LatestAttempt and ValidateDryRun prevent a retry of failed plans.
		return identity == s.Identity, nil
	}
	h, ok := FindHost(e, elected)
	if !ok || h.IdentityFingerprint != identity || !h.Safe(now, c.Policy) {
		return false, nil
	}
	// The latest elected-host attempt must be an actual completed run.
	// In particular, a failed attempt cannot release another host.
	var at *time.Time
	var status string
	var dryRun bool
	err = tx.QueryRow(ctx, `SELECT completed_at,status,dry_run FROM patch_runs
	WHERE policy_id=$1 AND host_id=$2 AND policy_snapshot->>'severity_remediation'='true'
	AND policy_snapshot->>'identity_fingerprint'=$3 AND policy_snapshot->>'rollout_digest'=$4
	AND policy_snapshot->>'remediation_revision'=$5 ORDER BY created_at DESC,id DESC LIMIT 1`,
		c.PolicyID, elected, identity, s.RolloutDigest, jsonNumber(c.Revision)).Scan(&at, &status, &dryRun)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if status != "completed" || dryRun || at == nil || !Fresh(*at, now, 7*24*time.Hour) || h.ObservedAt.Before(*at) {
		return false, nil
	}
	var confirmed bool
	err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM hosts WHERE id=$1 AND status='active' AND identity_fingerprint=$2 AND packages_hash=$3 AND last_full_report_at >= $4 AND awaiting_post_patch_report_run_id IS NULL AND identity_conflict_at IS NULL AND NOT COALESCE(needs_reboot,false))`, elected, identity, h.PackagesHash, *at).Scan(&confirmed)
	if err != nil || !confirmed {
		return false, err
	}
	for _, p := range s.Packages {
		var match bool
		err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM host_packages hp JOIN packages p ON p.id=hp.package_id WHERE hp.host_id=$1 AND p.name=$2 AND hp.current_version=$3 AND hp.last_checked >= $4)`, elected, p.Name, p.Candidate, *at).Scan(&match)
		if err != nil || !match {
			return false, err
		}
	}
	return true, nil
}

func jsonNumber(i int64) string { raw, _ := json.Marshal(i); return string(raw) }

// Recheck validates the current scope and evidence immediately before native
// dispatch. It is also called on offline-agent retries, preventing stale plans.
func Recheck(ctx context.Context, d *database.DB, s Snapshot, now time.Time, real bool) (Configuration, error) {
	c, err := ReadConfiguration(ctx, d, s.PolicyID)
	if err != nil {
		return c, err
	}
	if c.DelayType != "immediate" || c.Revision != s.Revision || c.Policy.Mode == ModeDisabled || c.Policy.Mode == ModeShadow || real && !ExecutionEnabled() {
		return c, errors.New("remediation paused or changed")
	}
	id, err := ResolvePolicy(ctx, d, s.HostID)
	if err != nil {
		return c, err
	}
	if id != s.PolicyID {
		return c, errors.New("host no longer in effective scope")
	}
	e, err := Read(now)
	if err != nil {
		return c, err
	}
	h, ok := FindHost(e, s.HostID)
	if !ok || !s.MatchesEvidence(h) {
		return c, errors.New("current evidence no longer matches plan")
	}
	if err = CheckHost(ctx, d, h, s.Packages, now, c.Policy); err != nil {
		return c, err
	}
	if c.Policy.Mode == ModeAutomatic {
		ok, err = CanaryPassed(ctx, d, c, e, s, now)
		if err != nil {
			return c, err
		}
		if !ok {
			return c, errors.New("verified canary rollout required")
		}
	}
	return c, nil
}
