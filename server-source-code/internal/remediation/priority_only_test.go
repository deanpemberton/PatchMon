package remediation

import (
	"fmt"
	"testing"
	"time"
)

func TestPriorityOnlyIsScopedAndDoesNotClaimFix(t *testing.T) {
	now := time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)
	p := DefaultPolicy()
	p.Mode = ModeAutomatic
	p.BackupOnlyHostIDs = []string{"host"}
	p.CanaryHostIDs = []string{"host"}
	t.Setenv("PATCHMON_PRIORITY_ONLY_POLICY_ID", "policy")
	c := Configuration{PolicyID: "policy", Revision: 2, Policy: p}
	applyPriorityOnly(&c)
	if !c.Policy.PriorityOnly || !c.PriorityOnly {
		t.Fatal("explicit scope not activated")
	}
	other := Configuration{PolicyID: "other", Policy: p}
	applyPriorityOnly(&other)
	if other.PriorityOnly {
		t.Fatal("scope leaked")
	}
	score := 9.1
	target := Target{Package: "example", Installed: "1", Candidate: "2", FirstSeen: now.Add(-time.Hour), Security: true, CVE: "CVE-2099-12345", Score: &score, ScoreSource: "fixture", ScoreVersion: "3.1"}
	for _, tc := range []struct {
		severity string
		hours    int
		score    *float64
		kev      bool
	}{{SeverityCritical, 4, &score, false}, {SeverityExploited, 4, nil, true}, {SeverityUnclassifiedSecurity, 4, nil, false}} {
		target.Score = tc.score
		target.KnownExploited = tc.kev
		d := Evaluate(c.Policy, target, now, time.Time{})
		if !d.Eligible || d.Severity != tc.severity || d.Deadline == nil || !d.Deadline.Equal(target.FirstSeen.Add(time.Duration(tc.hours)*time.Hour)) || d.Target.FixedCandidateVerified {
			t.Fatalf("unexpected priority decision %+v", d)
		}
	}
	high := 8.0
	target.Score = &high
	d := Evaluate(c.Policy, target, now, time.Time{})
	if !d.Eligible || d.Deadline == nil || !d.Deadline.Equal(target.FirstSeen.Add(48*time.Hour)) {
		t.Fatal("high deadline")
	}
	h := HostEvidence{HostID: "host", IdentityFingerprint: "identity", PackagesHash: "hash", ObservedAt: now, BackupAt: now.Add(-time.Hour), BackupComplete: true, Targets: []Target{target}, UnclassifiedSecurityUpdates: []string{"example"}}
	if !h.Safe(now, c.Policy) || h.ApplicationHealthy || h.RecoveryVerified {
		t.Fatal("incorrect priority-only backup gate")
	}
	s, err := MakeSnapshot(c, h, []Decision{d})
	if err != nil || !s.PriorityOnly || !s.MatchesEvidence(h) {
		t.Fatalf("available package rejected: %v", err)
	}
	s.PriorityOnly = false
	if s.Validate() == nil {
		t.Fatal("snapshot mode tampering accepted")
	}
	h.BackupComplete = false
	if h.Safe(now, c.Policy) {
		t.Fatal("missing backup accepted")
	}
	target.Candidate = ""
	if Evaluate(c.Policy, target, now, time.Time{}).Eligible {
		t.Fatal("unavailable update accepted")
	}
	if Evaluate(p, h.Targets[0], now, time.Time{}).Eligible {
		t.Fatal("strict policy relaxed")
	}
}

func TestExpandedPriorityBatchCompatibleAgent(t *testing.T) {
	p := DefaultPolicy()
	p.Mode = ModeAutomatic
	p.PriorityOnly = true
	p.BackupOnlyHostIDs = []string{"host"}
	c := Configuration{PolicyID: "policy", Revision: 2, Policy: p}
	h := HostEvidence{HostID: "host", IdentityFingerprint: "identity"}
	now := time.Now().UTC()
	var ds []Decision
	for i := 0; i < 113; i++ {
		d := Evaluate(p, Target{Package: fmt.Sprintf("example-%03d", i), Installed: "1", Candidate: "2", FirstSeen: now}, now, time.Time{})
		ds = append(ds, d)
	}
	for _, tc := range []struct {
		agent string
		limit int
	}{{"2.1.9-rc.remediation.3", 64}, {expandedPriorityAgent, 113}, {"", 64}} {
		s, err := MakeSnapshotForAgent(c, h, ds, tc.agent)
		if err != nil || len(s.Packages) != tc.limit {
			t.Fatalf("agent %q: want %d packages, got %d (%v)", tc.agent, tc.limit, len(s.Packages), err)
		}
	}
}

func TestPriorityBackupEvidenceHostOverrides(t *testing.T) {
	now := time.Date(2026, 11, 26, 3, 0, 0, 0, time.UTC)
	t.Setenv("PATCHMON_PRIORITY_ONLY_POLICY_ID", "policy")
	t.Setenv("PATCHMON_PRIORITY_BACKUP_DEFAULT", BackupIgnore)
	p := DefaultPolicy()
	p.Mode = ModeAutomatic
	p.BackupOnlyHostIDs = []string{"ordinary", "protected"}
	p.BackupEvidenceOverrides = map[string]string{"protected": BackupRequire}
	p = PolicyForConfiguration("policy", p)
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	h := HostEvidence{HostID: "ordinary", IdentityFingerprint: "identity", PackagesHash: "hash", ObservedAt: now}
	if !h.Safe(now, p) || h.BackupComplete || h.RecoveryVerified {
		t.Fatal("explicit default ignore must not fabricate recovery evidence")
	}
	h.HostID = "protected"
	if h.Safe(now, p) {
		t.Fatal("host-specific requirement bypassed")
	}
	h.BackupComplete = true
	h.BackupAt = now.Add(-time.Hour)
	if !h.Safe(now, p) {
		t.Fatal("fresh backup for protected host rejected")
	}
	h.BackupAt = now.Add(-100 * time.Hour)
	if h.Safe(now, p) {
		t.Fatal("stale backup accepted for protected host")
	}
	h.HostID = "ordinary"
	h.ObservedAt = now.Add(-time.Hour)
	if h.Safe(now, p) {
		t.Fatal("stale package evidence bypassed")
	}
	h.ObservedAt = now
	h.PackagesHash = ""
	if h.Safe(now, p) {
		t.Fatal("missing package identity bypassed")
	}
	h.PackagesHash = "hash"
	h.HostID = "unconfirmed"
	h.BackupComplete = false
	if h.Safe(now, p) {
		t.Fatal("unconfirmed host inherited exception")
	}
	p.BackupEvidenceDefault = BackupRequire
	p.BackupEvidenceOverrides = map[string]string{"ordinary": BackupIgnore}
	h.HostID = "ordinary"
	if !h.Safe(now, p) {
		t.Fatal("host-specific ignore override rejected")
	}
	h.HostID = "protected"
	if h.Safe(now, p) {
		t.Fatal("default requirement bypassed")
	}
	p.BackupEvidenceOverrides["unconfirmed"] = BackupIgnore
	if p.Validate() == nil {
		t.Fatal("out-of-scope override accepted")
	}
	delete(p.BackupEvidenceOverrides, "unconfirmed")
	p.BackupEvidenceOverrides["ordinary"] = "unknown"
	if p.Validate() == nil {
		t.Fatal("invalid override mode accepted")
	}
	p.BackupEvidenceOverrides = nil
	p.BackupEvidenceDefault = BackupIgnore
	if PolicyForConfiguration("other", p).Validate() == nil {
		t.Fatal("non-opted-in policy accepted ignore setting")
	}
	p.BackupEvidenceDefault = ""
	p = PolicyForConfiguration("policy", p)
	p.BackupEvidenceDefault = BackupRequire
	if PolicyForConfiguration("policy", p).BackupEvidenceDefault != BackupRequire {
		t.Fatal("saved required default overridden by deployment")
	}
}
