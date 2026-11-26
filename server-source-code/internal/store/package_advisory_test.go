package store

import (
	"strings"
	"testing"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/remediation"
)

func TestPackageAdvisoryRowsRequireCurrentApplicableEvidence(t *testing.T) {
	now := time.Now().UTC()
	score := 8.2
	base := remediation.Target{Package: "example-bin", Installed: "1.0-1", CVE: "CVE-2099-12345", Security: true, VendorApplicable: true, Score: &score, ScoreSource: "fixture", ScoreVersion: "3.1", FirstSeen: now}
	known := base
	known.CVE = "CVE-2099-12346"
	known.KnownExploited = true
	known.Score = nil
	known.ScoreSource = ""
	known.ScoreVersion = ""
	uncertain := base
	uncertain.CVE = "CVE-2099-12347"
	uncertain.VendorApplicable = false
	host := remediation.HostEvidence{HostID: "fixture-host", IdentityFingerprint: "fixture", PackagesHash: "fixture", ObservedAt: now, Targets: []remediation.Target{base, known, uncertain}}
	e := remediation.Evidence{Schema: 1, GeneratedAt: now, Hosts: []remediation.HostEvidence{host}}
	rows := packageAdvisoryRows(e, now)
	if len(rows) != 2 || rows[0].CVSS == nil || *rows[0].CVSS != 8.2 || advisorySeverity(rows[0].Rank) != remediation.SeverityHigh ||
		rows[1].CVSS != nil || advisorySeverity(rows[1].Rank) != remediation.SeverityExploited {
		t.Fatalf("unexpected matched rows: %+v", rows)
	}
	e.Hosts[0].ObservedAt = now.Add(-time.Hour)
	if len(packageAdvisoryRows(e, now)) != 0 {
		t.Fatal("stale host evidence shown")
	}
	e.Hosts[0].ObservedAt = now
	e.GeneratedAt = now.Add(-time.Hour)
	if len(packageAdvisoryRows(e, now)) != 0 {
		t.Fatal("stale signed snapshot shown")
	}
	if advisorySeverity(nil) != remediation.SeverityUnknown {
		t.Fatal("missing severity treated as known")
	}
}

func TestPackageAdvisorySQLScopeAndSort(t *testing.T) {
	host := "fixture-host"
	filters := packagesListFilters{HostID: &host, AdvisoryJSON: "[]"}
	query, args := listPackagesSQL(filters, "cvssScore", "desc", 25, 50)
	for _, required := range []string{"jsonb_to_recordset($3::jsonb)", "h.id = $4", "hph.host_id = $5", "hp.current_version=v.installed", "h.packages_hash=v.package_hash", "h.identity_fingerprint=v.fingerprint", "(now() AT TIME ZONE 'UTC') - interval '90 minutes'", "(now() AT TIME ZONE 'UTC') - interval '24 hours'", "ORDER BY cvss_score DESC NULLS LAST, name ASC, id ASC LIMIT $1 OFFSET $2"} {
		if !strings.Contains(query, required) {
			t.Fatalf("missing %q: %s", required, query)
		}
	}
	if len(args) != 5 || args[3] != host || args[4] != host {
		t.Fatalf("wrong bound parameters: %#v", args)
	}
	if sort := resolvePackagesListSort("severity", "desc"); sort != "severity_rank DESC NULLS LAST, name ASC, id ASC" {
		t.Fatalf("wrong severity sort: %s", sort)
	}
	query, args = listPackagesSQL(packagesListFilters{}, "cvssScore", "desc", 25, 0)
	if !strings.Contains(query, "NULL::double precision AS cvss_score") || len(args) != 2 {
		t.Fatal("missing evidence changed the ordinary package browsing path")
	}
}
