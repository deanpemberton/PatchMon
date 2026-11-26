package remediation

import (
	"strings"
	"testing"
	"time"
)

func TestPriorityDependencyProposal(t *testing.T) {
	now := time.Now().UTC()
	p := DefaultPolicy()
	p.Mode = ModeAutomatic
	p.PriorityOnly = true
	p.BackupOnlyHostIDs = []string{"host"}
	c := Configuration{PolicyID: "policy", Revision: 1, Policy: p}
	score := 7.8
	h := HostEvidence{HostID: "host", IdentityFingerprint: "identity"}
	var decisions []Decision
	for _, name := range []string{"libpam-modules-bin", "libpam-runtime", "libpam-modules", "libpam0g", "unrelated"} {
		target := Target{Package: name, Installed: "1.5.2-6+deb12u2", Candidate: "1.5.2-6+deb12u3", FirstSeen: now}
		if name == "libpam-modules-bin" || name == "libpam-runtime" {
			target.Security = true
			target.CVE = "CVE-2026-12345"
			target.Score = &score
			target.ScoreSource = "fixture"
			target.ScoreVersion = "3.1"
		}
		h.Targets = append(h.Targets, target)
		decisions = append(decisions, Evaluate(p, target, now, now.Add(-time.Hour)))
	}
	seed, err := MakeSnapshotForAgent(c, h, decisions, expandedPriorityAgent)
	if err != nil || len(seed.Packages) != 2 {
		t.Fatalf("expected two due targets: %+v %v", seed.Packages, err)
	}
	simulation := "4 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n" +
		"Inst libpam0g [1.5.2-6+deb12u2] (1.5.2-6+deb12u3 Debian-Security [amd64])\n" +
		"Inst libpam-modules-bin [1.5.2-6+deb12u2] (1.5.2-6+deb12u3 Debian-Security [amd64])\n" +
		"Inst libpam-modules [1.5.2-6+deb12u2] (1.5.2-6+deb12u3 Debian-Security [amd64])\n" +
		"Inst libpam-runtime [1.5.2-6+deb12u2] (1.5.2-6+deb12u3 Debian-Security [all])\n"
	expanded, ok := dependencyProposal(seed, simulation, h, decisions)
	if !ok || len(expanded) != 4 {
		t.Fatalf("failed to include complete dependency cohort: %v %+v", ok, expanded)
	}
	s, err := MakeSnapshotForAgent(c, h, expanded, expandedPriorityAgent)
	if err != nil || len(s.Packages) != 4 || s.Digest == seed.Digest || !s.MatchesEvidence(h) {
		t.Fatalf("expanded snapshot was not separately pinned: %+v %v", s.Packages, err)
	}
	for _, d := range expanded {
		if d.Target.Package == "unrelated" {
			t.Fatal("unrelated routine upgrade was included")
		}
		if d.Reason == "required_apt_dependency" && (d.Severity != SeverityRoutine || d.Target.Security || d.Target.Score != nil) {
			t.Fatal("dependency incorrectly reclassified as a CVE")
		}
	}
	for _, output := range []string{
		strings.Replace(simulation, "0 newly installed", "1 newly installed", 1),
		strings.Replace(simulation, "0 to remove", "1 to remove", 1),
		simulation + "Remv other [1]\n",
		strings.Replace(simulation, "4 upgraded", "3 upgraded", 1),
		strings.Replace(simulation, "Inst libpam0g", "Inst unobserved", 1),
		strings.Replace(simulation, "Inst libpam0g [1.5.2-6+deb12u2]", "Inst libpam0g [1.5.2-6+deb12u1]", 1),
		strings.Replace(simulation, "Inst libpam0g [1.5.2-6+deb12u2] (1.5.2-6+deb12u3", "Inst libpam0g [1.5.2-6+deb12u2] (1.5.2-6+deb12u4", 1),
		strings.Replace(simulation, "Inst libpam0g", "Inst libpam-runtime", 1),
		strings.Replace(simulation, "Inst libpam-runtime", "Inst unrelated", 1),
	} {
		if _, ok := dependencyProposal(seed, output, h, decisions); ok {
			t.Fatalf("accepted invalid dependency proposal: %s", output)
		}
	}
	seed.PriorityOnly = false
	if _, ok := dependencyProposal(seed, simulation, h, decisions); ok {
		t.Fatal("strict policy was relaxed")
	}
}
