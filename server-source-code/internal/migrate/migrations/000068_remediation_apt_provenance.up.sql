-- Authenticated local observations only; never a patch authorization.
CREATE TABLE IF NOT EXISTS patch_remediation_apt_provenance (
    host_id TEXT PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    identity_fingerprint TEXT NOT NULL,
    packages_hash TEXT NOT NULL,
    received_at TIMESTAMPTZ NOT NULL,
    evidence JSONB NOT NULL
);
