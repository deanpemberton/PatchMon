package remediation

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/database"
	"github.com/jackc/pgx/v5"
)

var (
	dependencyInst    = regexp.MustCompile(`^Inst ([^ ]+) \[([^]]+)\] \(([^ )]+)(?: |\))`)
	dependencySummary = regexp.MustCompile(`^([0-9]+) upgraded, ([0-9]+) newly installed, ([0-9]+) to remove and [0-9]+ not upgraded\.?$`)
)

// An unsuccessful simulation is a proposal, never a validation receipt. Only
// already-installed upgrades with exact current signed candidates may be added.
// The resulting full transaction still needs a fresh successful agent dry run,
// normal database rechecks and the unchanged pre-install archive guard.
func dependencyProposal(seed Snapshot, output string, h HostEvidence, decisions []Decision) ([]Decision, bool) {
	if !seed.PriorityOnly || len(output) == 0 || len(output) > 1024*1024 {
		return nil, false
	}
	observed := make(map[string]VerifiedPackage)
	count := -1
	for _, raw := range strings.Split(output, "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "Remv ") || strings.HasPrefix(line, "Purg ") {
			return nil, false
		}
		if strings.HasPrefix(line, "Inst ") {
			m := dependencyInst.FindStringSubmatch(line)
			if len(m) != 4 {
				return nil, false
			}
			p := VerifiedPackage{Name: m[1], Installed: m[2], Candidate: m[3]}
			if !p.Valid() || len(observed) >= expandedTargetLimit {
				return nil, false
			}
			if _, exists := observed[p.Name]; exists {
				return nil, false
			}
			observed[p.Name] = p
		}
		if m := dependencySummary.FindStringSubmatch(line); len(m) == 4 {
			n, err := strconv.Atoi(m[1])
			if count != -1 || err != nil || m[2] != "0" || m[3] != "0" || n > expandedTargetLimit {
				return nil, false
			}
			count = n
		}
	}
	if count != len(observed) || len(observed) <= len(seed.Packages) {
		return nil, false
	}
	original := make(map[string]bool)
	for _, p := range seed.Packages {
		if observed[p.Name] != p {
			return nil, false
		}
		original[p.Name] = true
	}
	// Match all proposed additions to signed targets AND current policy
	// decisions. A deferred routine upgrade may accompany an urgent dependency
	// but an invalid/unknown target or an unobserved package cannot be invented.
	signed := make(map[string]VerifiedPackage)
	for _, t := range h.Targets {
		p := VerifiedPackage{Name: t.Package, Installed: t.Installed, Candidate: t.Candidate}
		if !p.Valid() {
			continue
		}
		if prior, exists := signed[p.Name]; exists && prior != p {
			return nil, false
		}
		signed[p.Name] = p
	}
	expanded := append([]Decision(nil), seed.Decisions...)
	added := make(map[string]bool)
	for _, d := range decisions {
		p := VerifiedPackage{Name: d.Target.Package, Installed: d.Target.Installed, Candidate: d.Target.Candidate}
		if original[p.Name] || added[p.Name] || !p.Valid() || observed[p.Name] != p || signed[p.Name] != p {
			continue
		}
		if !d.Eligible && d.Reason != "routine_not_due" {
			continue
		}
		d.Eligible = true
		d.Reason = "required_apt_dependency"
		expanded = append(expanded, d)
		added[p.Name] = true
	}
	if len(original)+len(added) != len(observed) {
		return nil, false
	}
	return expanded, true
}

// ExpandPriorityDependencies uses only the latest failed, exact managed seed
// simulation. It never changes historical runs or fabricates a success marker.
// Rebuilding the same expanded digest on each dispatch lets native approval
// and retry logic operate unchanged. At most three expanding passes are tried.
func ExpandPriorityDependencies(ctx context.Context, db *database.DB, c Configuration, h HostEvidence, seed Snapshot, decisions []Decision, agentVersion string, now time.Time) (Snapshot, error) {
	if !c.Policy.PriorityOnly {
		return seed, nil
	}
	result := seed
	for range 3 {
		tx, err := db.Begin(ctx)
		if err != nil {
			return result, err
		}
		var status, failure, output string
		var dry bool
		var completed *time.Time
		var raw []byte
		err = tx.QueryRow(ctx, `SELECT status,dry_run,coalesce(error_message,''),coalesce(shell_output,''),completed_at,policy_snapshot FROM patch_runs WHERE host_id=$1 AND policy_id=$2 AND policy_snapshot->>'plan_digest'=$3 ORDER BY created_at DESC,id DESC LIMIT 1`, result.HostID, result.PolicyID, result.Digest).Scan(&status, &dry, &failure, &output, &completed, &raw)
		_ = tx.Rollback(context.WithoutCancel(ctx))
		if errors.Is(err, pgx.ErrNoRows) {
			return result, nil
		}
		if err != nil {
			return result, err
		}
		if !dry || status != "failed" || completed == nil || !Fresh(*completed, now, 24*time.Hour) ||
			(failure != "unexpected apt transaction summary" && failure != "unexpected package or version in simulation") {
			return result, nil
		}
		old, managed, err := ParseSnapshot(raw)
		if err != nil || !managed || old.Digest != result.Digest || !old.MatchesEvidence(h) {
			return result, nil
		}
		expanded, ok := dependencyProposal(result, output, h, decisions)
		if !ok {
			return result, nil
		}
		next, err := MakeSnapshotForAgent(c, h, expanded, agentVersion)
		if err != nil || len(next.Packages) <= len(result.Packages) {
			return result, nil
		}
		// MakeSnapshot enforces the transport/agent limits and may truncate.
		// Reject partial closure instead of sending another unsafe subset.
		expected := make(map[string]bool)
		for _, d := range expanded {
			expected[d.Target.Package] = true
		}
		if len(next.Packages) != len(expected) || !next.MatchesEvidence(h) {
			return result, nil
		}
		next.Routine = seed.Routine
		result = next
	}
	return result, nil
}
