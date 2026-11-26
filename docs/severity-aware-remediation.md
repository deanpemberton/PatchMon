# Severity-aware remediation (experimental)

This feature extends the native patch scheduler. It never delegates a package
transaction to an external automation system. Advisory and recovery providers
supply signed evidence; PatchMon owns policy authorization, validation,
execution, history, and reconciliation.

## Policy and safety model

Assign an immediate patch policy to hosts or groups using the normal PatchMon
policy editor. Expand the assignment panel and choose severity-based remediation.

| Priority | Default target |
| --- | --- |
| CISA known exploited or CVSS 9.0–10.0 | 4 hours |
| CVSS 7.0–8.9 | 48 hours |
| CVSS 0.1–6.9 and routine upgrades | 24 hours |
| Unknown, uncertain applicability or no verified fix | Review; no automatic upgrade |

The times are targets from first observation, not delays for critical/high
findings. The ledger retains the earliest outstanding deadline across scans and
policy edits. An absent finding, stale feed, completed run, or a successful
download is not proof of resolution. A positive reassessment plus current
installed inventory is required.

Modes:

- **Disabled** (default): no remediation dispatch.
- **Shadow**: evaluate and record findings without creating patch runs.
- **Approval**: create exact-version validation runs; existing authenticated
  patch approvals authorize execution.
- **Automatic**: require explicit browser confirmation, server opt-in, and
  verified canaries before unattended upgrades.

The server opt-in is `PATCHMON_REMEDIATION_EXECUTION=true`. It is off by default
and is separate from signature verification. Legacy recurring full upgrades
introduced by the scheduler use a separate explicit switch
(`PATCHMON_LEGACY_AUTO_PATCH_EXECUTION=true`) and cannot run under a policy
with severity remediation enabled.

Initial support is single-tenant, Debian/Ubuntu APT only. Other package managers
and unsupported agents must not execute verified requests. No removals, new
dependencies, downgrades, unapproved packages, or automatic reboots are allowed
in severity-managed transactions. An incompatible update remains blocked for
manual review. A policy can be paused or revised in the browser; this invalidates
queued plans at dispatch. Already-running transactions are not rolled back by
changing a policy.

A separate **backup-only risk acceptance** option permits an authenticated
administrator to accept the absence of a tested restore for the currently
effective, non-excluded hosts when explicitly authorizing Automatic mode.
The server captures that host list and stores it with the policy revision and
editor identity; caller-supplied host lists are ignored. A newly assigned host
must have a verified restore or be included in a new explicit confirmation.
This option never changes `recovery_verified` evidence, and it does not
relax current completed-backup, health, signed fix, identity, exact validation,
concurrency, scope, or canary gates. It cannot be combined with a timed waiver.

Automatic rollout requires a completed canary on the exact package/version
cohort under the same policy revision, verified post-patch inventory and fresh
independent application-health evidence. A different cohort requires its own
canary. The default concurrency ceiling is five. Failures are not retried by
silently reverting to a full upgrade.

## Advisory evidence provider

`tools/remediation/build_evidence.py` consumes a locally collected,
timestamped inventory and fresh vendor advisory mirrors. It uses Debian Security
Tracker source-package records or Ubuntu OSV exact ecosystem records to assess
applicability, and uses the distribution package manager's version ordering.
NVD CVSS v4.0, v3.1 and v3.0 scores are cached; the selected score's source and
version are retained. CISA KEV overrides numeric severity. No CVSS v2 score
is silently interpreted as v3/v4. Only CVE identifiers, not inventory data, are
sent to NVD. Missing/expired scores remain unknown.

The external inventory collector is deployment-specific. It must verify package
source provenance from authenticated distribution package metadata; it must not
equate binary and source versions or assert recovery and health merely because
a backup file exists. Use a complete, current package snapshot associated with
the live enrolled host and its package hash. Signing evidence does not grant
permission to patch.

The inventory input is JSON, schema 1, with `generated_at` and `hosts`.
Each host requires:

| Field | Meaning |
| --- | --- |
| host_id, identity_fingerprint, os, os_version, packages_hash | Exact current enrollment and inventory identifiers |
| observed_at, backup_at | UTC RFC3339 timestamps |
| backup_complete, recovery_verified, application_healthy | Independent positive boolean attestations |
| distribution | debian or ubuntu |
| release | Debian codename, or exact Ubuntu OSV ecosystem |
| packages | Full installed binary inventory with candidate and provenance |
| tracked_findings (optional) | Prior unresolved package/key pairs for positive vendor reassessment |
| resolved_routine_findings (optional) | Explicit verified package/key/installed receipts |

Each package supplies `name`, `installed`, `candidate` (empty when absent),
`source_package`, `installed_source_version`, `candidate_source_package`,
`candidate_source_version`, `source_provenance_verified`, and the boolean
`security_candidate`. Values in the included unit tests are synthetic, not
real deployment records.

Provide a local Debian tracker JSON mirror, Ubuntu OSV CVE record array (or
object with a vulns array), CISA KEV JSON, and writable NVD cache. The files must
be refreshed by a trusted process; mirror age is checked. Complex or conflicting
Ubuntu ranges are not automatically authorized. An unknown mapping must be
reviewed. The adapter accepts `NVD_API_KEY` through the process environment
if needed; no key is required for offline tests.

Create an Ed25519 signing key in a private directory outside the checkout:

```sh
umask 077
openssl genpkey -algorithm ED25519 -out evidence-signing.pem
openssl pkey -in evidence-signing.pem -pubout -outform DER | tail -c 32 | base64 -w0
```

Configure the resulting raw public key (base64) in
`PATCHMON_REMEDIATION_PUBLIC_KEY` and set
`PATCHMON_REMEDIATION_EVIDENCE_FILE` to the signed envelope path. Keep the
private key only with the evidence producer. Protect the directory and envelope
from modification by untrusted users. The signature is Ed25519 over the exact
decoded payload, not over a reserialized JSON object.

```sh
python3 tools/remediation/build_evidence.py \
  --inventory /path/to/inventory.json \
  --debian-tracker /path/to/debian-tracker.json \
  --ubuntu-osv /path/to/ubuntu-osv.json \
  --kev /path/to/kev.json \
  --nvd-cache /path/to/nvd-cache.json \
  --signing-key /path/to/evidence-signing.pem \
  --output /path/to/evidence.json
```

No inventory, key, credential, internal URL, or backup data belongs in the
source repository. Do not use actual deployment records in public CI.

## Validation and deployment

The feature-validation workflow builds native server and Linux agent test
binaries, records the commit and checksums, and runs synthetic advisory tests.
Its artifacts are test candidates, not production releases.

Before production promotion:

1. Pass upstream test, build, formatting, lint and vulnerability checks,
   including database migrations against a disposable database.
2. Validate a synthetic inventory and a disposable Debian/Ubuntu host with the
   matching agent; exercise invalid evidence, stale backup, revoked permission,
   failed validation, extra dependencies, canary failure, and successful
   exact-version reconciliation.
3. Back up and rehearse restoration of the database and application
   configuration; record the pre-upgrade binary and schema. Do not roll back
   only the executable after irreversible schema changes.
4. Install a reviewed immutable server artifact, with all execution switches
   off. Verify the existing authentication and native agent paths.
5. Configure the trusted local producer and observe shadow reports before
   upgrading a small canary cohort of agents. Old agents are not expected to
   understand the verified wire request.
6. Verify recovery and application health gates, then authorize the selected
   scope. Keep the legacy full-upgrade switch off unless explicitly required.

A server/agent build alone does not prove a live migration, vendor mapping,
backup restoration, or patch execution is safe.

## Package list advisory visibility

The Packages table exposes sortable CVSS and Severity columns. CVSS is the
highest numeric score among current, applicable signed advisory matches for
the selected host scope. Known exploited findings take precedence in severity
without manufacturing a numeric CVSS value. Exact host enrollment fingerprint,
package snapshot hash, OS/release and installed binary version must still
match the current inventory. Missing, expired, unmatched or unscored evidence
is displayed as Unknown (not zero or safe); partial evidence is not proof of
complete vulnerability coverage. Sorting is performed before pagination and
unknowns remain last. This read-only presentation is independent of execution
mode, fixed-candidate verification and patch authorization.

Render individual CVE identifiers in the UI using the shared `CveLink`
component. Links open the canonical NIST NVD description in a new tab;
never use an advisory-supplied URL or turn a missing identifier into a link.

## Dynamic rollout election

Automatic remediation elects the first eligible host in each exact OS/release and installed/candidate package cohort under the saved policy revision. Named canary hosts retain ordering preference, but no longer block unrelated cohorts. Native run history persists the election. A failed or unverified first attempt blocks the same cohort; followers require an actual completed installation, current matching enrollment, fresh subsequent inventory and positive application/backup evidence. Single-host temporary recovery waivers remain restricted to their original host. No per-patch approval is introduced, and the existing native concurrency and revalidation gates remain in force.

## Native APT provenance reports

On Debian and Ubuntu, the agent uses the distribution's read-only python3-apt cache (if installed) to collect exact installed/candidate binary and source versions and positively attributed trusted distribution origins. The authenticated full package report carries this optional observation. The server validates and records it against the current enrolled identity and canonical package hash in the same transaction as the inventory; absent, malformed, ambiguous or unmatched observations clear old provenance. This is not a vendor advisory, backup or application-health attestation. The evidence producer must correlate these separately. No new remote execution endpoint is introduced. APT hosts send a full package report on each normal check-in to keep provenance current; unsupported or missing python3-apt fails closed without stopping ordinary inventory.
