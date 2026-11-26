package store

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAPTObservationExactPackageAndOriginReceipt(t *testing.T) {
	candidate := "1.0-2"
	p := &ReportPayload{OSType: "Debian GNU/Linux", PackageManager: "apt", Packages: []ReportPackage{{Name: "example", CurrentVersion: "1.0-1", AvailableVersion: &candidate, NeedsUpdate: true}}}
	p.APTProvenance = json.RawMessage(`{"schema":1,"distro":"debian","release":"trixie","candidates":[{"binary":"example:amd64","installed":"1.0-1","candidate":"1.0-2","source":"example-src","installed_source":"1.0-1","candidate_source":"1.0-2"}]}`)
	hash := strings.Repeat("a", 64)
	data := verifiedAPTObservation(p, hash)
	if data == nil || !strings.Contains(string(data), "example:amd64") {
		t.Fatal("valid exact package observation rejected")
	}
	p.Packages[0].CurrentVersion = "1.0-0"
	data = verifiedAPTObservation(p, hash)
	if data == nil || strings.Contains(string(data), "example:amd64") {
		t.Fatal("mismatched version was retained")
	}
	if verifiedAPTObservation(p, "") != nil {
		t.Fatal("missing package hash accepted")
	}
	p.APTProvenance = json.RawMessage(`{"schema":1,"distro":"ubuntu","release":"noble","candidates":[]}`)
	if verifiedAPTObservation(p, hash) != nil {
		t.Fatal("mismatched distribution accepted")
	}
}
