package remediation

import "sort"

// PriorityTargets reduces available upgrades to one authoritative decision
// per exact installed/candidate pair. Keep non-actionable observations for
// vulnerability reporting; do not confuse them with a pending installation.
func PriorityTargets(h HostEvidence) []Target {
	type key struct {
		Package, Installed, Candidate string
	}
	best := map[key]Target{}
	other := make([]Target, 0)
	for _, t := range h.Targets {
		if !(VerifiedPackage{Name: t.Package, Installed: t.Installed, Candidate: t.Candidate}).Valid() {
			other = append(other, t)
			continue
		}
		k := key{t.Package, t.Installed, t.Candidate}
		old, ok := best[k]
		if !ok {
			best[k] = t
			continue
		}
		first := old.FirstSeen
		if t.FirstSeen.Before(first) {
			first = t.FirstSeen
		}
		a, b := Priority(UpdateSeverity(t, h.UnclassifiedSecurityUpdates)), Priority(UpdateSeverity(old, h.UnclassifiedSecurityUpdates))
		score := func(x Target) float64 {
			if x.Score == nil {
				return -1
			}
			return *x.Score
		}
		if a < b || (a == b && (score(t) > score(old) || (score(t) == score(old) && t.CVE < old.CVE))) {
			old = t
		}
		old.FirstSeen = first
		best[k] = old
	}
	for _, t := range best {
		other = append(other, t)
	}
	sort.SliceStable(other, func(i, j int) bool {
		a, b := other[i], other[j]
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		if a.Installed != b.Installed {
			return a.Installed < b.Installed
		}
		if a.Candidate != b.Candidate {
			return a.Candidate < b.Candidate
		}
		return a.CVE < b.CVE
	})
	return other
}
