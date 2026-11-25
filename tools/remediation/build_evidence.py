#!/usr/bin/env python3
"""Build signed PatchMon remediation evidence from trusted local inventories.

Only CVE identifiers are sent to the NVD. Never upload inventories, backups,
agent credentials, or signing keys. This tool cannot execute patches.
"""
import argparse
import base64
import datetime as dt
import json
import math
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PACKAGE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,127}(:[a-z0-9][a-z0-9-]{0,31})?$")
VERSION = re.compile(r"^[0-9][A-Za-z0-9.+:~\-]{0,255}$")
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_FEED_AGE = 24 * 3600
MAX_INPUT = 512 * 1024 * 1024
MAX_ENVELOPE = 8 * 1024 * 1024
HOST_KEYS = (
    "host_id", "identity_fingerprint", "os", "os_version", "packages_hash",
    "observed_at", "backup_at", "backup_complete", "recovery_verified",
    "application_healthy",
)


def utc():
    return dt.datetime.now(dt.timezone.utc)


def timestamp(value):
    result = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return result.astimezone(dt.timezone.utc)


def iso(value):
    return value.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def recent(value, now, seconds):
    age = (now - timestamp(value)).total_seconds()
    return 0 <= age <= seconds


def read_json(path, max_age=None, now=None):
    path = pathlib.Path(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT:
        raise ValueError("invalid input file")
    if max_age is not None:
        age = (now.timestamp() - info.st_mtime)
        if not 0 <= age <= max_age:
            raise ValueError("stale advisory feed")
    with path.open("rb") as f:
        return json.load(f)


def atomic_json(path, value):
    path = pathlib.Path(path)
    with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".evidence-", delete=False) as f:
        name = f.name
        try:
            os.fchmod(f.fileno(), 0o600)
            f.write(json.dumps(value, separators=(",", ":"), allow_nan=False).encode())
            f.flush()
            os.fsync(f.fileno())
            os.replace(name, path)
        finally:
            if os.path.exists(name):
                os.unlink(name)


def version_cmp(a, op, b):
    if not VERSION.fullmatch(a or "") or not VERSION.fullmatch(b or ""):
        raise ValueError("invalid distribution version")
    result = subprocess.run(["dpkg", "--compare-versions", a, op, b],
                            check=False, capture_output=True, timeout=5)
    if result.returncode not in (0, 1):
        raise ValueError("version comparison failed")
    return result.returncode == 0


def debian_findings(feed, source, release):
    for cve, advisory in feed.get(source, {}).items():
        if not CVE.fullmatch(cve):
            continue
        row = advisory.get("releases", {}).get(release)
        if not isinstance(row, dict):
            continue
        status = row.get("status")
        fixed = row.get("fixed_version", "")
        if status == "resolved" and fixed == "0":
            # Debian's explicit not-affected sentinel is not a fixed version.
            yield cve, "not_affected", "", "debian-security-tracker"
        elif status == "resolved" and VERSION.fullmatch(fixed or ""):
            yield cve, "fixed", fixed, "debian-security-tracker"
        elif status == "open":
            yield cve, "open", "", "debian-security-tracker"
        else:
            yield cve, "uncertain", "", "debian-security-tracker"


def ubuntu_index(records):
    """Index Ubuntu CVE OSV records by exact source package and ecosystem."""
    if isinstance(records, dict):
        records = records.get("vulns", [])
    result = {}
    for record in records:
        if record.get("withdrawn"):
            continue
        identifiers = set(record.get("upstream", [])) | set(record.get("aliases", []))
        ident = record.get("id", "")
        if ident.startswith("UBUNTU-CVE-"):
            identifiers.add(ident.removeprefix("UBUNTU-"))
        cves = sorted(c for c in identifiers if CVE.fullmatch(c))
        # Ubuntu CVE records describe one vulnerability. Do not infer a mapping
        # from an advisory that aggregates several independent CVEs.
        if len(cves) != 1:
            continue
        for affected in record.get("affected", []):
            package = affected.get("package", {})
            ecosystem, name = package.get("ecosystem", ""), package.get("name", "")
            if not ecosystem.startswith("Ubuntu:") or not PACKAGE.fullmatch(name):
                continue
            ranges = affected.get("ranges", [])
            if len(ranges) != 1 or ranges[0].get("type") != "ECOSYSTEM":
                row = (cves[0], "uncertain", "", "ubuntu-osv")
            else:
                events = ranges[0].get("events", [])
                # Accept only the simple distro-wide affected interval. More
                # complicated ranges are reported but cannot authorize a patch.
                if events == [{"introduced": "0"}]:
                    row = (cves[0], "open", "", "ubuntu-osv")
                elif (len(events) == 2 and events[0] == {"introduced": "0"}
                      and set(events[1]) == {"fixed"}
                      and VERSION.fullmatch(events[1]["fixed"] or "")):
                    row = (cves[0], "fixed", events[1]["fixed"], "ubuntu-osv")
                else:
                    row = (cves[0], "uncertain", "", "ubuntu-osv")
            result.setdefault((ecosystem, name), []).append(row)
    return result


def nvd_score(cve):
    if cve.get("vulnStatus", "").lower() == "rejected":
        return {}
    for key, version in (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"),
                         ("cvssMetricV30", "3.0")):
        valid = []
        for item in cve.get("metrics", {}).get(key, []):
            data = item.get("cvssData", {})
            score = data.get("baseScore")
            if (data.get("version") == version and isinstance(score, (int, float))
                    and not isinstance(score, bool) and math.isfinite(score)
                    and 0 <= score <= 10):
                valid.append((score, str(item.get("source") or "NVD")))
        if valid:
            score, source = max(valid)
            return {"score": score, "score_source": "NVD:" + source,
                    "score_version": version}
    return {}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def enrich_nvd(ids, cache_path, now, offline=False):
    """Cache successful/unknown results; never downgrade a failed request to safe."""
    path = pathlib.Path(cache_path)
    cache = read_json(path) if path.exists() else {}
    cache = {k: v for k, v in cache.items() if CVE.fullmatch(k) and isinstance(v, dict)}
    pending = []
    for cve in sorted(set(ids)):
        if not CVE.fullmatch(cve):
            raise ValueError("invalid CVE")
        row = cache.get(cve, {})
        ttl = MAX_FEED_AGE if "score" in row else 3600
        if not row.get("fetched_at") or not recent(row["fetched_at"], now, ttl):
            pending.append(cve)
    if not offline:
        api_key = os.getenv("NVD_API_KEY", "")
        opener = urllib.request.build_opener(NoRedirect())
        headers = {"Accept": "application/json", "User-Agent": "PatchMon-remediation/1"}
        if api_key:
            headers["apiKey"] = api_key
        for start in range(0, len(pending), 100):
            batch = pending[start:start + 100]
            url = NVD + "?" + urllib.parse.urlencode({"cveIds": ",".join(batch)})
            try:
                with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as f:
                    data = f.read(32 * 1024 * 1024 + 1)
                    if len(data) > 32 * 1024 * 1024:
                        raise ValueError("NVD response too large")
                    response = json.loads(data)
                received = {}
                for item in response.get("vulnerabilities", []):
                    cve = item.get("cve", {})
                    ident = cve.get("id")
                    if ident in batch:
                        received[ident] = nvd_score(cve)
                for ident in batch:
                    cache[ident] = {"fetched_at": iso(now), **received.get(ident, {})}
            except (OSError, ValueError):
                # Keep existing observations for audit, but expired scores will
                # be omitted below. Retry on the next scheduled evaluation.
                break
            atomic_json(path, cache)
            if start + 100 < len(pending):
                time.sleep(0.7 if api_key else 6.1)
    result = {}
    for ident in ids:
        row = cache.get(ident, {})
        if row.get("fetched_at") and recent(row["fetched_at"], now, MAX_FEED_AGE):
            result[ident] = {k: row[k] for k in ("score", "score_source", "score_version") if k in row}
    return result


def make_host(host, debian, ubuntu, kev, now):
    """Map exact vendor source versions to installed binaries and candidates."""
    if not recent(host["observed_at"], now, 30 * 60):
        raise ValueError("stale host inventory")
    result = {k: host[k] for k in HOST_KEYS}
    for key in ("backup_complete", "recovery_verified", "application_healthy"):
        if type(result[key]) is not bool:
            raise ValueError("health attestation must be boolean")
    result.update(targets=[], resolved_findings=[], unclassified_security_updates=[])
    distribution, release = host["distribution"], host["release"]
    if distribution not in ("debian", "ubuntu"):
        raise ValueError("unsupported vendor")
    if (distribution == "debian" and not debian) or (distribution == "ubuntu" and not ubuntu):
        raise ValueError("required vendor feed unavailable")
    tracked = {(r["package"], r["key"]) for r in host.get("tracked_findings", [])}
    seen = set()
    for pkg in host["packages"]:
        name, installed = pkg["name"], pkg["installed"]
        candidate = pkg.get("candidate", "")
        if (not PACKAGE.fullmatch(name) or not VERSION.fullmatch(installed)
                or (candidate and not VERSION.fullmatch(candidate)) or name in seen):
            raise ValueError("invalid or duplicate package inventory")
        seen.add(name)
        if candidate == installed:
            candidate = ""
        security = pkg.get("security_candidate")
        if type(security) is not bool:
            raise ValueError("security classification must be boolean")
        source, source_version = pkg.get("source_package", ""), pkg.get("installed_source_version", "")
        source_valid = PACKAGE.fullmatch(source) and VERSION.fullmatch(source_version)
        provenance = (source_valid and pkg.get("source_provenance_verified") is True
                      and pkg.get("candidate_source_package") == source
                      and VERSION.fullmatch(pkg.get("candidate_source_version", ""))
                      and candidate and version_cmp(candidate, "gt", installed))
        findings = []
        if source_valid:
            findings = (list(debian_findings(debian, source, release))
                        if distribution == "debian" else ubuntu.get((release, source), []))
        # Conflicting vendor records are not a reason to choose the most
        # convenient fix. Retain one uncertain finding instead.
        merged = {}
        for row in findings:
            if row[0] in merged and merged[row[0]] != row:
                merged[row[0]] = (row[0], "uncertain", "", row[3])
            else:
                merged[row[0]] = row
        affected = False
        for cve, status, fixed, vendor in merged.values():
            if status == "not_affected" or (status == "fixed" and version_cmp(source_version, "ge", fixed)):
                if (name, cve) in tracked:
                    result["resolved_findings"].append({"package": name, "key": cve, "installed": installed})
                continue
            affected = True
            verified = bool(status == "fixed" and provenance
                            and version_cmp(pkg["candidate_source_version"], "ge", fixed))
            target = {
                "package": name, "installed": installed, "candidate": candidate,
                "source_package": source, "installed_source_version": source_version,
                "candidate_source_version": pkg.get("candidate_source_version", ""),
                "fixed_source_version": fixed, "advisory_source": vendor, "cve": cve,
                "known_exploited": cve in kev, "security": True,
                "vendor_applicable": status in ("open", "fixed"),
                "fixed_candidate_verified": verified, "first_seen": iso(now),
            }
            result["targets"].append(target)
        if candidate and security and not affected:
            result["unclassified_security_updates"].append(name)
        # A known affected or unclassified security package must not slip
        # through the routine policy merely because its score is missing.
        elif candidate and not security and not affected:
            result["targets"].append({
                "package": name, "installed": installed, "candidate": candidate,
                "security": False, "vendor_applicable": False,
                "fixed_candidate_verified": bool(provenance), "first_seen": iso(now),
            })
        # Positive resolution of a previous routine observation requires a
        # trusted collector's explicit receipt; absence is not resolution.
    for receipt in host.get("resolved_routine_findings", []):
        if not receipt["key"].startswith("routine:"):
            raise ValueError("invalid routine receipt")
        result["resolved_findings"].append({k: receipt[k] for k in ("package", "key", "installed")})
    return result


def build(inventory, debian, ubuntu, kev, cache, now, offline):
    if inventory.get("schema") != 1 or not recent(inventory["generated_at"], now, 30 * 60):
        raise ValueError("invalid or stale inventory")
    hosts = [make_host(h, debian, ubuntu, kev, now) for h in inventory["hosts"]]
    ids = {t["cve"] for h in hosts for t in h["targets"] if t.get("cve")}
    scores = enrich_nvd(ids, cache, now, offline)
    for host in hosts:
        for target in host["targets"]:
            target.update(scores.get(target.get("cve"), {}))
    return {"schema": 1, "generated_at": iso(now), "hosts": hosts}


def sign(payload, key):
    key = pathlib.Path(key)
    info = key.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("private signing key must be a regular owner-only file")
    raw = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
    with tempfile.TemporaryDirectory() as directory:
        path = pathlib.Path(directory) / "payload"
        path.write_bytes(raw)
        sig = subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey",
                              str(key), "-in", str(path)], check=True,
                             capture_output=True, timeout=15).stdout
    if len(sig) != 64:
        raise ValueError("signing key must be Ed25519")
    result = {"payload": base64.b64encode(raw).decode(),
              "signature": base64.b64encode(sig).decode()}
    if len(json.dumps(result).encode()) > MAX_ENVELOPE:
        raise ValueError("evidence envelope too large")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--debian-tracker")
    parser.add_argument("--ubuntu-osv")
    parser.add_argument("--kev", required=True)
    parser.add_argument("--nvd-cache", required=True)
    parser.add_argument("--signing-key", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    now = utc()
    inventory = read_json(args.inventory)
    debian = read_json(args.debian_tracker, MAX_FEED_AGE, now) if args.debian_tracker else {}
    ubuntu = ubuntu_index(read_json(args.ubuntu_osv, MAX_FEED_AGE, now)) if args.ubuntu_osv else {}
    kev = {x["cveID"] for x in read_json(args.kev, MAX_FEED_AGE, now)["vulnerabilities"]
           if CVE.fullmatch(x["cveID"])}
    evidence = build(inventory, debian, ubuntu, kev, args.nvd_cache, now, args.offline)
    atomic_json(args.output, sign(evidence, args.signing_key))


if __name__ == "__main__":
    main()
