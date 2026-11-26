package store

import (
	"encoding/json"
	"os"
	"strconv"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/remediation"
)

// PackageAdvisorySummary reports the highest known CVSS and priority for
// matching current installations. Missing data is never a score of zero.
type PackageAdvisorySummary struct {
	CVSSScore         *float64 `json:"cvssScore"`
	Severity          string   `json:"severity"`
	AdvisoryHostCount int32    `json:"advisoryHostCount"`
	AdvisoryCVECount  int32    `json:"advisoryCveCount"`
	CVSSVersion       *string  `json:"cvssVersion"`
	CVSSSource        *string  `json:"cvssSource"`
	UpdatePriorityPending bool `json:"updatePriorityPending"`
	PriorityDeadline *time.Time `json:"priorityDeadline"`
	PriorityFirstSeen *time.Time `json:"priorityFirstSeen"`
	PriorityStatus string `json:"priorityStatus"`
}

type packageAdvisoryRow struct {
	HostID      string   `json:"host_id"`
	Fingerprint string   `json:"fingerprint"`
	Hash        string   `json:"package_hash"`
	OS          string   `json:"os"`
	OSVersion   string   `json:"os_version"`
	Package     string   `json:"package"`
	Installed   string   `json:"installed"`
	Candidate string `json:"candidate"`
	CVE         string   `json:"cve"`
	CVSS        *float64 `json:"cvss"`
	Version     string   `json:"score_version"`
	Source      string   `json:"score_source"`
	Rank        *int32   `json:"rank"`
}

func advisoryRank(severity string) *int32 {
	ranks := map[string]int32{
		remediation.SeverityExploited: 7,
		remediation.SeverityCritical:  6,
		remediation.SeverityUnclassifiedSecurity: 5,
		remediation.SeverityHigh:      4,
		remediation.SeverityMedium:    3,
		remediation.SeverityLow:       2,
		remediation.SeverityNone:      1,
		remediation.SeverityRoutine: 0,
	}
	if rank, ok := ranks[severity]; ok {
		return &rank
	}
	return nil
}

func advisorySeverity(rank *int32) string {
	if rank == nil {
		return remediation.SeverityUnknown
	}
	switch *rank {
	case 7:
		return remediation.SeverityExploited
	case 6:
		return remediation.SeverityCritical
	case 5:
		return remediation.SeverityUnclassifiedSecurity
	case 4:
		return remediation.SeverityHigh
	case 3:
		return remediation.SeverityMedium
	case 2:
		return remediation.SeverityLow
	case 1:
		return remediation.SeverityNone
	case 0:
		return remediation.SeverityRoutine
	default:
		return remediation.SeverityUnknown
	}
}

func packageAdvisoryRows(e remediation.Evidence, now time.Time) []packageAdvisoryRow {
	rows := []packageAdvisoryRow{}
	if !remediation.Fresh(e.GeneratedAt, now, remediation.MaxEvidenceAge) {
		return rows
	}
	for _, h := range e.Hosts {
		if h.IdentityFingerprint == "" || h.PackagesHash == "" ||
			!remediation.Fresh(h.ObservedAt, now, remediation.MaxEvidenceAge) {
			continue
		}
		for _, t := range remediation.PriorityTargets(h) {
			if t.Validate() != nil || (t.Candidate == "" && (!t.Security || !t.VendorApplicable)) {
				continue
			}
			rows = append(rows, packageAdvisoryRow{
				HostID: h.HostID, Fingerprint: h.IdentityFingerprint, Hash: h.PackagesHash,
				OS: h.OS, OSVersion: h.OSVersion, Package: t.Package, Installed: t.Installed,
				Candidate: t.Candidate, CVE: t.CVE, CVSS: t.Score, Version: t.ScoreVersion, Source: t.ScoreSource,
				Rank: advisoryRank(remediation.UpdateSeverity(t, h.UnclassifiedSecurityUpdates)),
			})
		}
	}
	return rows
}

func currentPackageAdvisories(now time.Time) string {
	e, err := remediation.Read(now)
	if err != nil {
		return ""
	}
	rows := packageAdvisoryRows(e, now)
	if len(rows) == 0 {
		return ""
	}
	data, err := json.Marshal(rows)
	if err != nil || len(data) > remediation.MaxEvidenceBytes {
		return ""
	}
	return string(data)
}

// Aggregate before sorting/pagination. Every advisory must match a current
// installation, identity and inventory hash; never join by package name alone.
func packageAdvisorySQL(filters packagesListFilters, args []any) (cte, columns, join string, out []any) {
	// Always evaluate the live pending inventory, even if signed evidence
	// is unavailable. Never borrow a score from a non-pending installation.
	raw := filters.AdvisoryJSON
	if raw == "" {
		raw = "[]"
	}
	args = append(args, raw)
	param := "$" + strconv.Itoa(len(args))
	where := ""
	if hostScoped(filters) {
		args = append(args, *filters.HostID)
		where += " AND hp.host_id = $" + strconv.Itoa(len(args))
	}
	if filters.RepositoryID != nil && *filters.RepositoryID != "" {
		args = append(args, *filters.RepositoryID)
		where += " AND hp.source_repository_id = $" + strconv.Itoa(len(args))
	}
	policy := os.Getenv("PATCHMON_PRIORITY_ONLY_POLICY_ID")
	args = append(args, policy)
	policyParam := "$" + strconv.Itoa(len(args))
	cte = `WITH pending_scope AS (
 SELECT hp.package_id,count(*)::int AS pending_count,
        count(*) FILTER (WHERE hp.is_security_update)::int AS security_count
 FROM host_packages hp
 WHERE hp.needs_update AND hp.available_version IS DISTINCT FROM hp.current_version` + where + `
 GROUP BY hp.package_id
), live_decisions AS (
 SELECT x->>'host_id' AS host_id, d->'target'->>'package' AS package,
        d->'target'->>'installed' AS installed,d->'target'->>'candidate' AS candidate,
        d->>'severity' AS severity,
        (d->>'deadline')::timestamptz AS deadline,
        (d->'target'->>'first_seen')::timestamptz AS first_seen,
        CASE WHEN coalesce(x->>'run_id','')<>'' THEN
          coalesce(nullif(x->>'blocker',''),'dispatched')
        WHEN coalesce(x->>'blocker','')<>'' AND x->>'blocker'<>'no_unambiguous_eligible_packages' THEN x->>'blocker'
        WHEN d->>'eligible'='true' THEN 'eligible'
        ELSE coalesce(d->>'reason','awaiting_evaluation') END AS state
 FROM patch_remediation_policies rp
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(rp.report->'hosts')='array' THEN rp.report->'hosts' ELSE '[]'::jsonb END) x
 CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(x->'decisions')='array' THEN x->'decisions' ELSE '[]'::jsonb END) d
 WHERE rp.policy_id=` + policyParam + ` AND rp.settings->>'mode'='automatic'
 AND rp.report->>'execution_enabled'='true' AND rp.report->>'evidence_available'='true'
 AND (rp.report->>'evaluated_at')::timestamptz >= now()-interval '3 minutes'
 AND coalesce(d->'target'->>'candidate','')<>''
), matched AS (
 SELECT p.id AS package_id,v.*,hp.needs_update AS pending,
        ld.deadline,ld.first_seen,ld.state
 FROM jsonb_to_recordset(` + param + `::jsonb) AS v(
      host_id text, fingerprint text, package_hash text, os text, os_version text,
      package text, installed text, candidate text,cve text, cvss double precision,
      score_version text, score_source text, rank int)
 JOIN hosts h ON h.id=v.host_id AND h.identity_fingerprint=v.fingerprint
      AND h.packages_hash=v.package_hash AND h.os_type=v.os AND h.os_version=v.os_version
      AND h.status='active' AND h.identity_conflict_at IS NULL
      AND h.last_update >= (now() AT TIME ZONE 'UTC') - interval '90 minutes'
      AND h.last_full_report_at >= (now() AT TIME ZONE 'UTC') - interval '24 hours'
 JOIN packages p ON p.name=v.package
 JOIN host_packages hp ON hp.host_id=h.id AND hp.package_id=p.id AND hp.current_version=v.installed
 LEFT JOIN pending_scope ps ON ps.package_id=p.id
 LEFT JOIN live_decisions ld ON ld.host_id=v.host_id AND ld.package=v.package AND ld.installed=v.installed AND ld.candidate=v.candidate
 AND ld.severity=CASE v.rank WHEN 7 THEN 'exploited' WHEN 6 THEN 'critical' WHEN 5 THEN 'unclassified_security' WHEN 4 THEN 'high' WHEN 3 THEN 'medium' WHEN 2 THEN 'low' WHEN 1 THEN 'none' WHEN 0 THEN 'routine' ELSE 'unknown' END
 WHERE hp.last_checked >= (now() AT TIME ZONE 'UTC') - interval '24 hours'
 AND ((hp.needs_update AND v.candidate=hp.available_version AND v.candidate<>'')
 OR (NOT hp.needs_update AND v.candidate='' AND ps.package_id IS NULL))` + where + `
), matched_advisories AS (
 SELECT package_id,
        (array_agg(cvss ORDER BY rank DESC NULLS LAST,cvss DESC NULLS LAST,cve))[1] AS cvss_score,
        max(rank) AS severity_rank,
        count(DISTINCT host_id)::int AS host_count,
        count(DISTINCT NULLIF(cve,''))::int AS cve_count,
        (array_agg(NULLIF(score_version,'') ORDER BY rank DESC NULLS LAST,cvss DESC NULLS LAST,cve))[1] AS cvss_version,
        (array_agg(NULLIF(score_source,'') ORDER BY rank DESC NULLS LAST,cvss DESC NULLS LAST,cve))[1] AS cvss_source,
        min(deadline) AS deadline,min(first_seen) AS first_seen,
        bool_or(pending AND state IS NULL) AS awaiting_evaluation,
        string_agg(DISTINCT state,', ' ORDER BY state) FILTER(WHERE pending) AS state
 FROM matched GROUP BY package_id
)
`
	// If only some pending installations have evidence, say so; never
	// present a non-pending advisory as the pending update's priority.
	columns = "a.cvss_score, a.severity_rank, COALESCE(a.host_count,0), COALESCE(a.cve_count,0), a.cvss_version, a.cvss_source, COALESCE(ps.pending_count,0)>0, a.deadline, a.first_seen, CASE WHEN ps.pending_count IS NULL THEN 'no_update_available' WHEN COALESCE(a.host_count,0)<ps.pending_count THEN 'awaiting_evidence_or_outside_scope' WHEN a.awaiting_evaluation THEN 'awaiting_evaluation' ELSE COALESCE(a.state,'awaiting_evaluation') END"
	join = "\nLEFT JOIN matched_advisories a ON a.package_id = p.id\nLEFT JOIN pending_scope ps ON ps.package_id=p.id\n"
	return cte, columns, join, args
}
