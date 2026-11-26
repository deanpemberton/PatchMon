-- Opt-in remediation settings are separate from ordinary scheduled patching.
CREATE TABLE IF NOT EXISTS patch_remediation_policies (
    policy_id TEXT PRIMARY KEY REFERENCES patch_policies(id) ON DELETE CASCADE,
    settings JSONB NOT NULL,
    revision BIGINT NOT NULL DEFAULT 1,
    updated_by TEXT REFERENCES users(id) ON DELETE SET NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    report JSONB
);
CREATE TABLE IF NOT EXISTS patch_remediation_findings (
    policy_id TEXT NOT NULL REFERENCES patch_policies(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    package_name TEXT NOT NULL,
    finding_key TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    deadline TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    PRIMARY KEY (policy_id,host_id,package_name,finding_key)
);
CREATE INDEX IF NOT EXISTS patch_remediation_open_deadline ON patch_remediation_findings(policy_id,deadline) WHERE resolved_at IS NULL;
