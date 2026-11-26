package store

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
)

var aptEvidenceName = regexp.MustCompile("^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9][a-z0-9-]{0,31})?$")
var aptEvidenceVersion = regexp.MustCompile("^[0-9][A-Za-z0-9.+:~-]{0,255}$")
var aptEvidenceRelease = regexp.MustCompile("^[a-z0-9-]{1,32}$")

type aptProvenanceRow struct {
	Binary          string `json:"binary"`
	Installed       string `json:"installed"`
	Candidate       string `json:"candidate"`
	Source          string `json:"source"`
	InstalledSource string `json:"installed_source"`
	CandidateSource string `json:"candidate_source"`
}

type aptProvenanceReport struct {
	Schema     int                `json:"schema"`
	Distro     string             `json:"distro"`
	Release    string             `json:"release"`
	Candidates []aptProvenanceRow `json:"candidates"`
}

func verifiedAPTObservation(payload *ReportPayload, hash string) []byte {
	decodedHash, err := hex.DecodeString(hash)
	if err != nil || len(decodedHash) != 32 || payload.PackageManager != "apt" || len(payload.APTProvenance) == 0 || len(payload.APTProvenance) > 524288 {
		return nil
	}
	var report aptProvenanceReport
	decoder := json.NewDecoder(bytes.NewReader(payload.APTProvenance))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&report) != nil || decoder.Decode(new(any)) != io.EOF || report.Schema != 1 ||
		(report.Distro != "debian" && report.Distro != "ubuntu") || !aptEvidenceRelease.MatchString(report.Release) ||
		!strings.Contains(strings.ToLower(payload.OSType), report.Distro) || report.Candidates == nil || len(report.Candidates) > 2000 {
		return nil
	}
	// Preserve exact binary names when available. A base-name match is
	// accepted only for a unique inventory row and a unique observation.
	packages := make(map[string][]ReportPackage)
	for _, p := range payload.Packages {
		base, _, _ := strings.Cut(p.Name, ":")
		packages[base] = append(packages[base], p)
	}
	rows := make([]aptProvenanceRow, 0, len(report.Candidates))
	bases := make(map[string]int)
	for _, row := range report.Candidates {
		base, _, _ := strings.Cut(row.Binary, ":")
		bases[base]++
	}
	seen := make(map[string]bool)
	for _, row := range report.Candidates {
		if !aptEvidenceName.MatchString(row.Binary) || !aptEvidenceName.MatchString(row.Source) ||
			!aptEvidenceVersion.MatchString(row.Installed) || !aptEvidenceVersion.MatchString(row.Candidate) ||
			!aptEvidenceVersion.MatchString(row.InstalledSource) || !aptEvidenceVersion.MatchString(row.CandidateSource) ||
			row.Installed == row.Candidate || seen[row.Binary] {
			return nil
		}
		seen[row.Binary] = true
		base, _, _ := strings.Cut(row.Binary, ":")
		matches := 0
		for _, p := range packages[base] {
			if p.Name != row.Binary && (p.Name != base || len(packages[base]) != 1 || bases[base] != 1) {
				continue
			}
			if p.NeedsUpdate && p.CurrentVersion == row.Installed && p.AvailableVersion != nil && *p.AvailableVersion == row.Candidate {
				matches++
			}
		}
		if matches == 1 {
			rows = append(rows, row)
		}
	}
	report.Candidates = rows
	data, err := json.Marshal(report)
	if err != nil {
		return nil
	}
	return data
}

// Store observations in the inventory transaction; never carry a prior receipt
// across a changed/missing package report. No agent-provided host ID or clock.
func storeAPTProvenance(ctx context.Context, tx pgx.Tx, hostID string, payload *ReportPayload, hash string) error {
	data := verifiedAPTObservation(payload, hash)
	if data == nil {
		_, err := tx.Exec(ctx, "DELETE FROM patch_remediation_apt_provenance WHERE host_id=$1", hostID)
		return err
	}
	if _, err := tx.Exec(ctx, "DELETE FROM patch_remediation_apt_provenance WHERE host_id=$1", hostID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO patch_remediation_apt_provenance(host_id,identity_fingerprint,packages_hash,received_at,evidence)
	SELECT id,identity_fingerprint,packages_hash,now(),$3::jsonb FROM hosts
	WHERE id=$1 AND packages_hash=$2 AND identity_fingerprint IS NOT NULL AND identity_fingerprint<>'' AND identity_conflict_at IS NULL`, hostID, hash, data)
	return err
}
