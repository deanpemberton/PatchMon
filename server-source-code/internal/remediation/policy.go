// Package remediation evaluates vulnerability-driven patch policies. Evidence is
// supplied by a trusted inventory/advisory adapter, not inferred from package names.
package remediation

import (
	"errors"
	"math"
	"regexp"
	"sort"
	"time"
)

const (
	ModeDisabled      = "disabled"
	ModeShadow        = "shadow"
	ModeApproval      = "approval"
	ModeAutomatic     = "automatic"
	SeverityUnknown   = "unknown"
	SeverityNone      = "none"
	SeverityRoutine   = "routine"
	SeverityLow       = "low"
	SeverityMedium    = "medium"
	SeverityHigh      = "high"
	SeverityCritical  = "critical"
	SeverityExploited = "exploited"
)

var (
	cvePattern     = regexp.MustCompile("^CVE-[0-9]{4}-[0-9]{4,}$")
	packagePattern = regexp.MustCompile("^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9][a-z0-9-]{0,31})?$")
	versionPattern = regexp.MustCompile(`^[0-9][A-Za-z0-9.+:~-]{0,255}$`)
)

type Policy struct {
	// Runtime-only, explicitly scoped administrative opt-in; not a client field.
	PriorityOnly bool `json:"-"`

	Mode                string     `json:"mode"`
	CriticalHours       int        `json:"critical_hours"`
	HighHours           int        `json:"high_hours"`
	RoutineHours        int        `json:"routine_hours"`
	MaxConcurrent       int        `json:"max_concurrent"`
	BackupMaxAgeHours   int        `json:"backup_max_age_hours"`
	CanaryHostIDs       []string   `json:"canary_host_ids"`
	RecoveryWaiverUntil *time.Time `json:"recovery_waiver_until,omitempty"`
	BackupOnlyHostIDs   []string   `json:"backup_only_host_ids,omitempty"`
}

func DefaultPolicy() Policy {
	return Policy{Mode: ModeDisabled, CriticalHours: 4, HighHours: 48, RoutineHours: 24, MaxConcurrent: 5, BackupMaxAgeHours: 36}
}

func (p Policy) Validate() error {
	switch p.Mode {
	case ModeDisabled, ModeShadow, ModeApproval, ModeAutomatic:
	default:
		return errors.New("invalid remediation mode")
	}
	if p.CriticalHours < 1 || p.CriticalHours > 168 || p.HighHours < p.CriticalHours || p.HighHours > 720 ||
		p.RoutineHours < 1 || p.RoutineHours > 720 || p.MaxConcurrent < 1 || p.MaxConcurrent > 5 ||
		p.BackupMaxAgeHours < 1 || p.BackupMaxAgeHours > 72 || len(p.CanaryHostIDs) > 20 {
		return errors.New("invalid remediation policy limits")
	}
	seen := map[string]bool{}
	for _, id := range p.CanaryHostIDs {
		if id == "" || len(id) > 128 || seen[id] {
			return errors.New("invalid canary host ID")
		}
		seen[id] = true
	}
	if p.Mode == ModeAutomatic && !p.PriorityOnly && len(p.CanaryHostIDs) == 0 {
		return errors.New("automatic remediation requires at least one canary host")
	}
	if p.PriorityOnly && (p.Mode != ModeAutomatic || p.RecoveryWaiverUntil != nil || len(p.BackupOnlyHostIDs) == 0) {
		return errors.New("priority-only patching requires automatic mode and explicitly accepted backup scope")
	}
	if p.RecoveryWaiverUntil != nil && (p.Mode != ModeAutomatic || p.MaxConcurrent != 1 || len(p.CanaryHostIDs) != 1 || p.RecoveryWaiverUntil.IsZero()) {
		return errors.New("a recovery waiver requires a single automatic canary with concurrency one")
	}
	if len(p.BackupOnlyHostIDs) > 0 {
		if p.Mode != ModeAutomatic || p.RecoveryWaiverUntil != nil || len(p.BackupOnlyHostIDs) > 512 {
			return errors.New("backup-only risk acceptance requires automatic mode and a bounded authorized host scope")
		}
		seen := map[string]bool{}
		for _, id := range p.BackupOnlyHostIDs {
			if id == "" || len(id) > 128 || seen[id] {
				return errors.New("invalid backup-only authorized host ID")
			}
			seen[id] = true
		}
	}
	return nil
}

// A waived recovery rehearsal is an explicit, short-lived policy risk decision.
// It never represents a successful restore, and cannot authorize any other host.
const RecoveryWaiverDuration = time.Hour

func (p Policy) recoveryWaiverActive(hostID string, now time.Time) bool {
	return p.RecoveryWaiverUntil != nil && p.Validate() == nil &&
		p.CanaryHostIDs[0] == hostID && now.Before(*p.RecoveryWaiverUntil) &&
		p.RecoveryWaiverUntil.Sub(now) <= RecoveryWaiverDuration
}

// Target binds a vendor-verified fixed candidate to the exact installed binary.
// FirstSeen is the persistent observation time, not the feed publication time.
type Target struct {
	Package                string    `json:"package"`
	Installed              string    `json:"installed"`
	Candidate              string    `json:"candidate"`
	SourcePackage          string    `json:"source_package,omitempty"`
	InstalledSourceVersion string    `json:"installed_source_version,omitempty"`
	CandidateSourceVersion string    `json:"candidate_source_version,omitempty"`
	FixedSourceVersion     string    `json:"fixed_source_version,omitempty"`
	AdvisorySource         string    `json:"advisory_source,omitempty"`
	CVE                    string    `json:"cve,omitempty"`
	Score                  *float64  `json:"score,omitempty"`
	ScoreSource            string    `json:"score_source,omitempty"`
	ScoreVersion           string    `json:"score_version,omitempty"`
	KnownExploited         bool      `json:"known_exploited,omitempty"`
	Security               bool      `json:"security"`
	VendorApplicable       bool      `json:"vendor_applicable"`
	FixedCandidateVerified bool      `json:"fixed_candidate_verified"`
	FirstSeen              time.Time `json:"first_seen"`
}

func (t Target) Validate() error {
	if !packagePattern.MatchString(t.Package) || !versionPattern.MatchString(t.Installed) || t.FirstSeen.IsZero() || (t.Candidate != "" && (!versionPattern.MatchString(t.Candidate) || t.Installed == t.Candidate)) || (t.Candidate == "" && (!t.Security || t.FixedCandidateVerified)) {
		return errors.New("invalid target")
	}
	if t.Security {
		if !cvePattern.MatchString(t.CVE) {
			return errors.New("invalid security finding identifier")
		}
		if t.FixedCandidateVerified && (!packagePattern.MatchString(t.SourcePackage) || !versionPattern.MatchString(t.InstalledSourceVersion) || !versionPattern.MatchString(t.CandidateSourceVersion) || !versionPattern.MatchString(t.FixedSourceVersion) || t.AdvisorySource == "") {
			return errors.New("missing source-package provenance")
		}
	} else if t.CVE != "" || t.Score != nil || t.KnownExploited {
		return errors.New("routine target carries security metadata")
	}
	if t.Score != nil && (math.IsNaN(*t.Score) || math.IsInf(*t.Score, 0) || *t.Score < 0 || *t.Score > 10 || t.ScoreSource == "" || t.ScoreVersion == "") {
		return errors.New("invalid score or score provenance")
	}
	return nil
}

func Severity(t Target) string {
	if !t.Security {
		return SeverityRoutine
	}
	if t.KnownExploited {
		return SeverityExploited
	}
	if t.Score == nil || math.IsNaN(*t.Score) || math.IsInf(*t.Score, 0) || *t.Score < 0 || *t.Score > 10 {
		return SeverityUnknown
	}
	switch {
	case *t.Score == 0:
		return SeverityNone
	case *t.Score >= 9:
		return SeverityCritical
	case *t.Score >= 7:
		return SeverityHigh
	case *t.Score >= 4:
		return SeverityMedium
	default:
		return SeverityLow
	}
}

type Decision struct {
	Target   Target     `json:"target"`
	Severity string     `json:"severity"`
	Deadline *time.Time `json:"deadline,omitempty"`
	Overdue  bool       `json:"overdue"`
	Eligible bool       `json:"eligible"`
	Reason   string     `json:"reason"`
}

// Evaluate computes urgency and eligibility separately. Critical/high fixes are
// eligible immediately; their deadlines are SLA targets, not execution delays.
func Evaluate(p Policy, t Target, now time.Time, lastRoutine time.Time) Decision {
	d := Decision{Target: t, Severity: Severity(t)}
	if p.Validate() != nil || t.Validate() != nil || t.FirstSeen.After(now) {
		d.Reason = "invalid_policy_or_target"
		return d
	}
	hours := p.RoutineHours
	switch d.Severity {
	case SeverityExploited, SeverityCritical:
		hours = p.CriticalHours
	case SeverityHigh:
		hours = p.HighHours
	case SeverityUnknown:
		if !p.PriorityOnly {
			d.Reason = "unknown_severity"
			return d
		}
	case SeverityNone:
		if !p.PriorityOnly {
			d.Reason = "no_cvss_impact"
			return d
		}
	}
	first := t.FirstSeen
	if !p.PriorityOnly && d.Severity == SeverityRoutine && !lastRoutine.IsZero() && lastRoutine.After(first) {
		first = lastRoutine
	}
	deadline := first.Add(time.Duration(hours) * time.Hour)
	d.Deadline = &deadline
	d.Overdue = !now.Before(deadline)
	if p.Mode == ModeDisabled {
		d.Reason = "policy_disabled"
		return d
	}
	// In the explicitly authorized priority-only policy, a CVE grades
	// urgency, not the available candidate's verified vulnerability fix.
	// The native agent still pins and validates the APT transaction.
	if p.PriorityOnly {
		if !(VerifiedPackage{Name: t.Package, Installed: t.Installed, Candidate: t.Candidate}).Valid() {
			d.Reason = "no_available_candidate"
			return d
		}
		if Priority(d.Severity) > Priority(SeverityHigh) && !lastRoutine.IsZero() &&
			now.Before(deadline) && now.Before(lastRoutine.Add(time.Duration(p.RoutineHours)*time.Hour)) {
			d.Reason = "routine_not_due"
			return d
		}
		d.Eligible = true
		d.Reason = "available_candidate_priority_only"
		return d
	}
	if t.Security && (!t.VendorApplicable || !t.FixedCandidateVerified) {
		d.Reason = "vendor_fix_unverified"
		return d
	}
	if !t.FixedCandidateVerified {
		d.Reason = "candidate_unverified"
		return d
	}
	if (d.Severity == SeverityRoutine || d.Severity == SeverityLow || d.Severity == SeverityMedium) && now.Before(deadline) && !lastRoutine.IsZero() {
		d.Reason = "routine_not_due"
		return d
	}
	d.Eligible = true
	d.Reason = "eligible"
	return d
}

func Priority(s string) int {
	switch s {
	case SeverityExploited:
		return 0
	case SeverityCritical:
		return 1
	case SeverityHigh:
		return 2
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 4
	case SeverityRoutine:
		return 5
	default:
		return 6
	}
}

// Ordered sorts by risk, then oldest deadline, then package name. It never
// treats missing or invalid scores as low severity.
func Ordered(ds []Decision) {
	sort.SliceStable(ds, func(i, j int) bool {
		a, b := ds[i], ds[j]
		if Priority(a.Severity) != Priority(b.Severity) {
			return Priority(a.Severity) < Priority(b.Severity)
		}
		if a.Deadline != nil && b.Deadline != nil && !a.Deadline.Equal(*b.Deadline) {
			return a.Deadline.Before(*b.Deadline)
		}
		return a.Target.Package < b.Target.Package
	})
}

type VerifiedPackage struct {
	Name      string `json:"name"`
	Installed string `json:"installed"`
	Candidate string `json:"candidate"`
}

func (p VerifiedPackage) Valid() bool {
	return packagePattern.MatchString(p.Name) && versionPattern.MatchString(p.Installed) && versionPattern.MatchString(p.Candidate) && p.Installed != p.Candidate
}
