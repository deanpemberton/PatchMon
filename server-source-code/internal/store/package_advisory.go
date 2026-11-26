package store

import (
	"encoding/json"
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
}

type packageAdvisoryRow struct {
	HostID      string   `json:"host_id"`
	Fingerprint string   `json:"fingerprint"`
	Hash        string   `json:"package_hash"`
	OS          string   `json:"os"`
	OSVersion   string   `json:"os_version"`
	Package     string   `json:"package"`
	Installed   string   `json:"installed"`
	CVE         string   `json:"cve"`
	CVSS        *float64 `json:"cvss"`
	Version     string   `json:"score_version"`
	Source      string   `json:"score_source"`
	Rank        *int32   `json:"rank"`
}

func advisoryRank(severity string) *int32 {
	ranks := map[string]int32{
		remediation.SeverityExploited: 6,
		remediation.SeverityCritical:  5,
		remediation.SeverityHigh:      4,
		remediation.SeverityMedium:    3,
		remediation.SeverityLow:       2,
		remediation.SeverityNone:      1,
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
	case 6:
		return remediation.SeverityExploited
	case 5:
		return remediation.SeverityCritical
	case 4:
		return remediation.SeverityHigh
	case 3:
		return remediation.SeverityMedium
	case 2:
		return remediation.SeverityLow
	case 1:
		return remediation.SeverityNone
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
		for _, t := range h.Targets {
			if !t.Security || !t.VendorApplicable || t.Validate() != nil {
				continue
			}
			rows = append(rows, packageAdvisoryRow{
				HostID: h.HostID, Fingerprint: h.IdentityFingerprint, Hash: h.PackagesHash,
				OS: h.OS, OSVersion: h.OSVersion, Package: t.Package, Installed: t.Installed,
				CVE: t.CVE, CVSS: t.Score, Version: t.ScoreVersion, Source: t.ScoreSource,
				Rank: advisoryRank(remediation.Severity(t)),
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
	if filters.AdvisoryJSON == "" {
		return "", "NULL::double precision AS cvss_score, NULL::int AS severity_rank, 0::int, 0::int, NULL::text, NULL::text", "", args
	}
	args = append(args, filters.AdvisoryJSON)
	param := "$" + strconv.Itoa(len(args))
	where := ""
	if hostScoped(filters) {
		args = append(args, *filters.HostID)
		where += " AND h.id = $" + strconv.Itoa(len(args))
	}
	if filters.RepositoryID != nil && *filters.RepositoryID != "" {
		args = append(args, *filters.RepositoryID)
		where += " AND hp.source_repository_id = $" + strconv.Itoa(len(args))
	}
	cte = `WITH matched_advisories AS (
 SELECT p.id AS package_id, max(v.cvss) AS cvss_score, max(v.rank) AS severity_rank,
        count(DISTINCT h.id)::int AS host_count, count(DISTINCT v.cve)::int AS cve_count,
        (array_agg(v.score_version ORDER BY v.cvss DESC NULLS LAST, v.cve, v.host_id)
          FILTER (WHERE v.cvss IS NOT NULL))[1] AS cvss_version,
        (array_agg(v.score_source ORDER BY v.cvss DESC NULLS LAST, v.cve, v.host_id)
          FILTER (WHERE v.cvss IS NOT NULL))[1] AS cvss_source
 FROM jsonb_to_recordset(` + param + `::jsonb) AS v(
      host_id text, fingerprint text, package_hash text, os text, os_version text,
      package text, installed text, cve text, cvss double precision,
      score_version text, score_source text, rank int)
 JOIN hosts h ON h.id=v.host_id AND h.identity_fingerprint=v.fingerprint
      AND h.packages_hash=v.package_hash AND h.os_type=v.os AND h.os_version=v.os_version
      AND h.status='active' AND h.identity_conflict_at IS NULL
      AND h.last_update >= now() - interval '90 minutes'
      AND h.last_full_report_at >= now() - interval '24 hours'
 JOIN packages p ON p.name=v.package
 JOIN host_packages hp ON hp.host_id=h.id AND hp.package_id=p.id AND hp.current_version=v.installed
 WHERE hp.last_checked >= now() - interval '24 hours'` + where + `
 GROUP BY p.id
)
`
	columns = "a.cvss_score, a.severity_rank, COALESCE(a.host_count,0), COALESCE(a.cve_count,0), a.cvss_version, a.cvss_source"
	join = "\nLEFT JOIN matched_advisories a ON a.package_id = p.id\n"
	return cte, columns, join, args
}
