-- Registered OAuth clients (managed via admin UI)
CREATE TABLE IF NOT EXISTS oauth_clients (
    id            TEXT PRIMARY KEY,
    name          TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,  -- JSON array: ["https://...","myapp://..."]
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);

-- Short-lived authorization codes (60s TTL, single-use)
CREATE TABLE IF NOT EXISTS oauth_auth_codes (
    id             TEXT PRIMARY KEY,
    code_hash      TEXT NOT NULL UNIQUE,
    client_id      TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id        TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    redirect_uri   TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    issued_at      TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    used_at        TEXT   -- NULL = unused; non-null = consumed
);

-- Immutable audit log of all auth events
CREATE TABLE IF NOT EXISTS auth_events (
    id          TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    user_id     TEXT,           -- NULL for failed logins where user doesn't exist
    username    TEXT NOT NULL,  -- always captured, even for failures
    client_id   TEXT,           -- NULL for direct API logins
    device_hint TEXT,
    ip_address  TEXT,
    detail      TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_code_hash  ON oauth_auth_codes(code_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_expires_at ON oauth_auth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_events_occurred_at     ON auth_events(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_auth_events_user_id         ON auth_events(user_id);
