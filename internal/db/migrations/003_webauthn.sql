-- WebAuthn challenges (ephemeral, short TTL)
CREATE TABLE IF NOT EXISTS webauthn_challenges (
    id           TEXT PRIMARY KEY,
    user_id      TEXT,  -- NULL for discoverable-credential login
    challenge    BLOB NOT NULL,
    type         TEXT NOT NULL CHECK(type IN ('registration', 'authentication')),
    session_data TEXT NOT NULL,  -- JSON: go-webauthn SessionData blob
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
    ON webauthn_challenges(expires_at);

-- Stored passkey credentials (one user can have many)
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id               TEXT PRIMARY KEY,
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    BLOB NOT NULL UNIQUE,
    public_key       BLOB NOT NULL,
    attestation_type TEXT NOT NULL DEFAULT 'none',
    aaguid           BLOB,
    sign_count       INTEGER NOT NULL DEFAULT 0,
    transports       TEXT,   -- JSON array: ["internal","hybrid"]
    backup_eligible  INTEGER NOT NULL DEFAULT 0 CHECK(backup_eligible IN (0, 1)),
    backup_state     INTEGER NOT NULL DEFAULT 0 CHECK(backup_state IN (0, 1)),
    user_present     INTEGER NOT NULL DEFAULT 1 CHECK(user_present IN (0, 1)),
    user_verified    INTEGER NOT NULL DEFAULT 0 CHECK(user_verified IN (0, 1)),
    name             TEXT NOT NULL DEFAULT '',
    created_at       TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at     TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user_id
    ON webauthn_credentials(user_id);
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_credential_id
    ON webauthn_credentials(credential_id);
