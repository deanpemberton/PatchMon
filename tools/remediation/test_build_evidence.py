import datetime as dt
import json
import pathlib
import tempfile
import unittest

from build_evidence import build, iso, make_host, nvd_score, ubuntu_index

NOW = dt.datetime(2025, 1, 1, 12, tzinfo=dt.timezone.utc)
IDENT = "CVE-2099-12345"


def host():
    return {
        "host_id": "example-host", "identity_fingerprint": "fixture-identity",
        "packages_hash": "fixture-inventory", "os": "Debian", "os_version": "13",
        "distribution": "debian", "release": "trixie",
        "observed_at": iso(NOW), "backup_at": iso(NOW - dt.timedelta(hours=1)),
        "backup_complete": True, "recovery_verified": True, "application_healthy": True,
        "packages": [{
            "name": "example-bin", "installed": "1.0-1", "candidate": "1.0-2",
            "source_package": "example-source", "installed_source_version": "1.0-1",
            "candidate_source_package": "example-source", "candidate_source_version": "1.0-2",
            "source_provenance_verified": True, "security_candidate": True,
        }],
    }


def feed(status="resolved", fixed="1.0-2"):
    return {"example-source": {IDENT: {"releases": {
        "trixie": {"status": status, "fixed_version": fixed}}}}}


class EvidenceTests(unittest.TestCase):
    def test_source_and_binary_mapping(self):
        h = make_host(host(), feed(), {}, {IDENT}, NOW)
        t = h["targets"][0]
        self.assertTrue(t["known_exploited"])
        self.assertTrue(t["fixed_candidate_verified"])
        self.assertEqual(t["source_package"], "example-source")
        self.assertEqual(t["package"], "example-bin")

    def test_backport_and_wrong_source(self):
        h = host()
        h["packages"][0]["candidate_source_version"] = "1.0-1"
        self.assertFalse(make_host(h, feed(), {}, set(), NOW)["targets"][0]["fixed_candidate_verified"])
        h["packages"][0]["candidate_source_version"] = "1.0-2"
        h["packages"][0]["candidate_source_package"] = "other-source"
        self.assertFalse(make_host(h, feed(), {}, set(), NOW)["targets"][0]["fixed_candidate_verified"])

    def test_unfixed_and_unclassified(self):
        h = make_host(host(), feed("open", ""), {}, set(), NOW)
        self.assertTrue(h["targets"][0]["vendor_applicable"])
        self.assertFalse(h["targets"][0]["fixed_candidate_verified"])
        h = make_host(host(), {"different-source": {}}, {}, set(), NOW)
        self.assertEqual(h["targets"], [])
        self.assertEqual(h["unclassified_security_updates"], ["example-bin"])

    def test_missing_candidate_is_visible(self):
        h = host()
        h["packages"][0]["candidate"] = ""
        t = make_host(h, feed("open", ""), {}, set(), NOW)["targets"][0]
        self.assertEqual(t["candidate"], "")
        self.assertFalse(t["fixed_candidate_verified"])

    def test_ubuntu_exact_ecosystem(self):
        rows = ubuntu_index([{"id": "UBUNTU-" + IDENT, "affected": [{
            "package": {"name": "example-source", "ecosystem": "Ubuntu:24.04:LTS"},
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0-2"}]}],
        }]}])
        h = host()
        h["distribution"], h["release"] = "ubuntu", "Ubuntu:24.04:LTS"
        self.assertTrue(make_host(h, {}, rows, set(), NOW)["targets"][0]["fixed_candidate_verified"])
        h["release"] = "Ubuntu:22.04:LTS"
        self.assertEqual(make_host(h, {}, rows, set(), NOW)["unclassified_security_updates"], ["example-bin"])

    def test_positive_resolution_only_for_tracked_findings(self):
        h = host()
        h["packages"][0]["installed_source_version"] = "1.0-2"
        self.assertEqual(make_host(h, feed(), {}, set(), NOW)["resolved_findings"], [])
        h["tracked_findings"] = [{"package": "example-bin", "key": IDENT}]
        self.assertEqual(len(make_host(h, feed(), {}, set(), NOW)["resolved_findings"]), 1)

    def test_cvss_preference_and_cache(self):
        data = {"metrics": {
            "cvssMetricV31": [{"source": "fixture", "cvssData": {"version": "3.1", "baseScore": 9.8}}],
            "cvssMetricV40": [{"source": "fixture", "cvssData": {"version": "4.0", "baseScore": 8.9}}],
        }}
        self.assertEqual(nvd_score(data)["score"], 8.9)
        self.assertEqual(nvd_score({"metrics": {"cvssMetricV2": [{"cvssData": {"baseScore": 10}}]}}), {})
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "cache.json"
            path.write_text(json.dumps({IDENT: {"fetched_at": iso(NOW), **nvd_score(data)}}))
            inv = {"schema": 1, "generated_at": iso(NOW), "hosts": [host()]}
            evidence = build(inv, feed(), {}, set(), path, NOW, True)
            self.assertEqual(evidence["hosts"][0]["targets"][0]["score"], 8.9)
            path.write_text(json.dumps({IDENT: {"fetched_at": iso(NOW - dt.timedelta(days=2)), **nvd_score(data)}}))
            evidence = build(inv, feed(), {}, set(), path, NOW, True)
            self.assertNotIn("score", evidence["hosts"][0]["targets"][0])

    def test_stale_inventory(self):
        h = host()
        h["observed_at"] = iso(NOW - dt.timedelta(hours=1))
        with self.assertRaises(ValueError):
            make_host(h, feed(), {}, set(), NOW)


if __name__ == "__main__":
    unittest.main()
