package remediation

import (
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
	}{{SeverityCritical, 4, &score, false}, {SeverityExploited, 4, nil, true}, {SeverityUnknown, 24, nil, false}} {
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
