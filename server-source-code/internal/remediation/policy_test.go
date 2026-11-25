package remediation

import (
	"testing"
	"time"
)

func TestSeverityBoundariesAndKEV(t *testing.T) {
	for _, tc := range []struct {
		score float64
		want  string
	}{{0, SeverityNone}, {3.9, SeverityLow}, {4, SeverityMedium}, {6.9, SeverityMedium}, {7, SeverityHigh}, {8.9, SeverityHigh}, {9, SeverityCritical}, {10, SeverityCritical}, {11, SeverityUnknown}} {
		x := Target{Security: true, Score: &tc.score}
		if got := Severity(x); got != tc.want {
			t.Fatalf("score %v: got %s, want %s", tc.score, got, tc.want)
		}
	}
	if got := Severity(Target{Security: true}); got != SeverityUnknown {
		t.Fatal(got)
	}
	if got := Severity(Target{Security: true, KnownExploited: true}); got != SeverityExploited {
		t.Fatal(got)
	}
}

func TestEvaluateDeadlineAndGates(t *testing.T) {
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	p := DefaultPolicy()
	p.Mode = ModeShadow
	score := 9.5
	x := Target{Package: "example-package", Installed: "1.0-1", Candidate: "1.0-2", CVE: "CVE-2099-12345", SourcePackage: "example-package", InstalledSourceVersion: "1.0-1", CandidateSourceVersion: "1.0-2", FixedSourceVersion: "1.0-2", AdvisorySource: "fixture", Score: &score, ScoreSource: "fixture", ScoreVersion: "3.1", Security: true, VendorApplicable: true, FixedCandidateVerified: true, FirstSeen: now.Add(-time.Hour)}
	d := Evaluate(p, x, now, time.Time{})
	if !d.Eligible || d.Overdue || d.Deadline == nil || !d.Deadline.Equal(now.Add(3*time.Hour)) {
		t.Fatalf("unexpected decision %+v", d)
	}
	x.FirstSeen = now.Add(-5 * time.Hour)
	if d = Evaluate(p, x, now, time.Time{}); !d.Overdue {
		t.Fatal("missed deadline")
	}
	score = 8
	if d = Evaluate(p, x, now, time.Time{}); !d.Deadline.Equal(x.FirstSeen.Add(48 * time.Hour)) {
		t.Fatal("high deadline")
	}
	x.FixedCandidateVerified = false
	if Evaluate(p, x, now, time.Time{}).Eligible {
		t.Fatal("unverified fix accepted")
	}
	x.FixedCandidateVerified = true
	x.Score = nil
	if Evaluate(p, x, now, time.Time{}).Eligible {
		t.Fatal("unknown score accepted")
	}
	x.KnownExploited = true
	if !Evaluate(p, x, now, time.Time{}).Eligible {
		t.Fatal("known exploitation not prioritized")
	}
	p.Mode = ModeAutomatic
	if p.Validate() == nil {
		t.Fatal("automatic mode without canary accepted")
	}
	p.CanaryHostIDs = []string{"example-canary"}
	if p.Validate() != nil {
		t.Fatal("valid policy rejected")
	}
}

func TestRejectUnsafeTargets(t *testing.T) {
	for _, name := range []string{"-o", "pkg;id", "pkg=1", "pkg/../../etc/passwd", "pkg\n"} {
		if (VerifiedPackage{Name: name, Installed: "1", Candidate: "2"}).Valid() {
			t.Fatalf("unsafe name accepted: %q", name)
		}
	}
	if (VerifiedPackage{Name: "pkg", Installed: "1", Candidate: "2 -o"}).Valid() {
		t.Fatal("unsafe version accepted")
	}
}
