package remediation

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/PatchMon/PatchMon/server-source-code/internal/migrate"
	"github.com/PatchMon/PatchMon/server-source-code/internal/pgtest"
)

func TestMain(m *testing.M) {
	os.Exit(pgtest.Main(m))
}

// Exercise the real migrations and SQL on a disposable database. All
// enrollment identities and package data are fabricated test fixtures.
func TestMigrationAndRemediationRepository(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	u := pgtest.URL(t)
	m, err := migrate.Open(u)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = m.Close() }()
	if err = m.Migrate(63); err != nil {
		t.Fatalf("prepare legacy schema: %v", err)
	}
	d := pgtest.Open(t)
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := d.Exec(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC().Truncate(time.Second)
	exec("INSERT INTO users(id,username,email,role,updated_at) VALUES('fixture-owner','fixture-owner','fixture-owner' || chr(64) || 'example.invalid','admin',NOW())")
	exec("INSERT INTO hosts(id,friendly_name,os_type,os_version,updated_at,api_id,api_key,package_manager,last_update,last_full_report_at,identity_fingerprint,packages_hash) VALUES('fixture-host','Example host','Debian','13',NOW(),'fixture-enrollment','fixture-not-a-secret','apt',$1,$1,'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')", now)
	exec("INSERT INTO packages(id,name,updated_at) VALUES('fixture-package','example-bin',NOW())")
	exec("INSERT INTO host_packages(id,host_id,package_id,current_version,available_version,needs_update,is_security_update,last_checked) VALUES('fixture-host-package','fixture-host','fixture-package','1.0-1','1.0-2',true,true,$1)", now)
	exec("INSERT INTO patch_policies(id,name,patch_delay_type,updated_at) VALUES('fixture-policy','Example policy','immediate',NOW())")
	exec("INSERT INTO host_groups(id,name,updated_at) VALUES('fixture-group','Example group',NOW())")
	exec("INSERT INTO host_group_memberships(id,host_id,host_group_id) VALUES('fixture-membership','fixture-host','fixture-group')")
	exec("INSERT INTO patch_policy_assignments(id,patch_policy_id,target_type,target_id,updated_at) VALUES('fixture-assignment','fixture-policy','host_group','fixture-group',NOW())")
	exec("INSERT INTO patch_runs(id,host_id,job_id,patch_type,status,dry_run,updated_at,completed_at) VALUES('fixture-history','fixture-host','fixture-job','patch_all','completed',false,NOW(),$1)", now.Add(-48*time.Hour))
	if err = m.Up(); err != nil {
		t.Fatalf("upgrade legacy schema: %v", err)
	}
	version, dirty, err := m.Version()
	if err != nil || version != 67 || dirty {
		t.Fatalf("unexpected migrated schema: version=%d dirty=%t error=%v", version, dirty, err)
	}
	var retained int
	if err = d.RawQueryRow(ctx, "SELECT count(*) FROM patch_runs WHERE id='fixture-history' AND status='completed'").Scan(&retained); err != nil || retained != 1 {
		t.Fatalf("native history not retained: %v", err)
	}
	c, err := ReadConfiguration(ctx, d, "fixture-policy")
	if err != nil || c.Policy.Mode != ModeDisabled || c.Revision != 0 {
		t.Fatalf("new policy not disabled: %v %+v", err, c)
	}
	p := DefaultPolicy()
	p.Mode = ModeShadow
	if err = WriteConfiguration(ctx, d, "fixture-policy", "fixture-owner", 0, p); err != nil {
		t.Fatal(err)
	}
	c, err = ReadConfiguration(ctx, d, "fixture-policy")
	if err != nil || c.Revision != 1 || c.Policy.Mode != ModeShadow {
		t.Fatalf("configuration readback: %v %+v", err, c)
	}
	if err = WriteConfiguration(ctx, d, "fixture-policy", "fixture-owner", 0, p); !errors.Is(err, ErrRevision) {
		t.Fatalf("stale revision accepted: %v", err)
	}
	if id, e := ResolvePolicy(ctx, d, "fixture-host"); e != nil || id != "fixture-policy" {
		t.Fatalf("group resolution: %s %v", id, e)
	}
	score := 9.8
	h := HostEvidence{
		HostID: "fixture-host", IdentityFingerprint: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		OS: "Debian", OSVersion: "13", PackagesHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: now,
		BackupAt: now.Add(-time.Hour), BackupComplete: true, RecoveryVerified: true, ApplicationHealthy: true,
		Targets: []Target{{
			Package: "example-bin", Installed: "1.0-1", Candidate: "1.0-2",
			CVE: "CVE-2099-12345", Score: &score, ScoreSource: "fixture", ScoreVersion: "3.1",
			SourcePackage: "example-source", InstalledSourceVersion: "1.0-1",
			CandidateSourceVersion: "1.0-2", FixedSourceVersion: "1.0-2", AdvisorySource: "fixture",
			Security: true, VendorApplicable: true, FixedCandidateVerified: true, FirstSeen: now.Add(-time.Hour),
		}},
	}
	if err = CheckEvidenceIdentity(ctx, d, h, now); err != nil {
		t.Fatal(err)
	}
	last, err := LastRoutine(ctx, d, c.PolicyID, h.HostID)
	if err != nil || !last.Equal(now.Add(-48*time.Hour)) {
		t.Fatalf("routine history not retained: %v %v", last, err)
	}
	ds, err := Observe(ctx, d, c, h, now, last)
	if err != nil || len(ds) != 1 || ds[0].Deadline == nil || !ds[0].Deadline.Equal(now.Add(3*time.Hour)) {
		t.Fatalf("observe: %v %+v", err, ds)
	}
	s, err := MakeSnapshot(c, h, ds)
	if err != nil {
		t.Fatal(err)
	}
	if err = CheckHost(ctx, d, h, s.Packages, now, c.Policy); err != nil {
		t.Fatal(err)
	}
	h.Targets[0].FirstSeen = now
	ds2, err := Observe(ctx, d, c, h, now.Add(time.Minute), last)
	if err != nil || len(ds2) != 1 || ds2[0].Deadline == nil || !ds2[0].Deadline.Equal(*ds[0].Deadline) {
		t.Fatalf("first observation reset: %v %+v", err, ds2)
	}
	if err = SaveReport(ctx, d, c, Report{EvaluatedAt: now, Mode: ModeShadow, Hosts: []HostReport{{HostID: h.HostID, Decisions: ds}}}); err != nil {
		t.Fatal(err)
	}
	exec("UPDATE host_packages SET available_version='1.0-3' WHERE id='fixture-host-package'")
	if err = CheckHost(ctx, d, h, s.Packages, now, c.Policy); err == nil {
		t.Fatal("changed candidate passed safety gate")
	}
	backupOnly := DefaultPolicy()
	backupOnly.Mode = ModeAutomatic
	backupOnly.CanaryHostIDs = []string{"fixture-host"}
	backupOnly.BackupOnlyHostIDs, err = BackupOnlyScope(ctx, d, c.PolicyID)
	if err != nil || len(backupOnly.BackupOnlyHostIDs) != 1 || backupOnly.BackupOnlyHostIDs[0] != h.HostID {
		t.Fatalf("unexpected backup-only scope: %v %+v", err, backupOnly.BackupOnlyHostIDs)
	}
	backupOnly.BackupOnlyHostIDs = append(backupOnly.BackupOnlyHostIDs, "unauthorized-host")
	if err = WriteConfiguration(ctx, d, c.PolicyID, "fixture-owner", c.Revision, backupOnly); !errors.Is(err, ErrBackupOnlyScope) {
		t.Fatalf("scope mismatch accepted: %v", err)
	}
	backupOnly.BackupOnlyHostIDs = backupOnly.BackupOnlyHostIDs[:1]
	if err = WriteConfiguration(ctx, d, c.PolicyID, "fixture-owner", c.Revision, backupOnly); err != nil {
		t.Fatalf("exact scope acceptance rejected: %v", err)
	}
	c, err = ReadConfiguration(ctx, d, c.PolicyID)
	if err != nil || len(c.Policy.BackupOnlyHostIDs) != 1 {
		t.Fatalf("backup-only policy not persisted: %v", err)
	}
	waiver := DefaultPolicy()
	waiver.Mode = ModeAutomatic
	waiver.MaxConcurrent = 1
	waiver.CanaryHostIDs = []string{"fixture-host"}
	until := time.Now().UTC().Add(30 * time.Minute)
	waiver.RecoveryWaiverUntil = &until
	if err = WriteConfiguration(ctx, d, c.PolicyID, "fixture-owner", c.Revision, waiver); !errors.Is(err, ErrRecoveryWaiverScope) {
		t.Fatalf("group-scoped recovery waiver accepted: %v", err)
	}
	exec("UPDATE patch_policy_assignments SET target_type='host',target_id='fixture-host' WHERE id='fixture-assignment'")
	if err = WriteConfiguration(ctx, d, c.PolicyID, "fixture-owner", c.Revision, waiver); err != nil {
		t.Fatalf("single-host recovery waiver rejected: %v", err)
	}
	exec("INSERT INTO patch_policy_exclusions(id,patch_policy_id,host_id,updated_at) VALUES('fixture-exclusion','fixture-policy','fixture-host',NOW())")
	if id, e := ResolvePolicy(ctx, d, h.HostID); e != nil || id != "" {
		t.Fatalf("exclusion ignored: %s %v", id, e)
	}
}
