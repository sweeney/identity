//go:build integration

package db_test

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
)

// TestOpen_WebAuthnTablesExist verifies the WebAuthn tables are created.
func TestOpen_WebAuthnTablesExist(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	defer database.Close()

	tables := []string{"webauthn_credentials", "webauthn_challenges"}
	for _, table := range tables {
		var name string
		err := database.DB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		require.NoError(t, err, "table %q should exist", table)
	}
}

// TestOpen_WebAuthnCredentialsColumnsComplete verifies every expected column exists
// in webauthn_credentials. This would have caught the user_present/user_verified
// missing-column bug on existing databases.
func TestOpen_WebAuthnCredentialsColumnsComplete(t *testing.T) {
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	defer database.Close()

	expectedColumns := []string{
		"id", "user_id", "credential_id", "public_key", "attestation_type",
		"aaguid", "sign_count", "transports", "backup_eligible", "backup_state",
		"user_present", "user_verified", "name", "created_at", "last_used_at",
	}

	rows, err := database.DB().Query("PRAGMA table_info(webauthn_credentials)")
	require.NoError(t, err)
	defer rows.Close()

	actualColumns := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, pk int
		var dflt sql.NullString
		require.NoError(t, rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk))
		actualColumns[name] = true
	}

	for _, col := range expectedColumns {
		assert.True(t, actualColumns[col], "column %q should exist in webauthn_credentials", col)
	}
}

// TestOpen_SchemaUpgrade_AddColumnsToExistingTable simulates the scenario that
// caused the production outage: a database created with migration 003 (without
// user_present/user_verified columns) being opened by new code that expects them.
//
// This test creates a database with the OLD schema (003 without the flag columns),
// then opens it with the current code and verifies the columns exist and the
// credential store works.
func TestOpen_SchemaUpgrade_AddColumnsToExistingTable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upgrade.db")

	// Step 1: Create a database with the old schema (no user_present/user_verified)
	rawDB, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	rawDB.SetMaxOpenConns(1)

	_, err = rawDB.Exec("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON")
	require.NoError(t, err)

	// Simulate migrations 001-003 with the OLD 003 schema (missing flag columns)
	_, err = rawDB.Exec(`
		CREATE TABLE users (
			id TEXT PRIMARY KEY,
			username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			display_name TEXT NOT NULL DEFAULT '',
			password_hash TEXT NOT NULL,
			role TEXT NOT NULL DEFAULT 'user',
			is_active INTEGER NOT NULL DEFAULT 1,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
			updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		);
		CREATE TABLE refresh_tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			token_hash TEXT NOT NULL UNIQUE,
			family_id TEXT NOT NULL,
			parent_token_id TEXT,
			device_hint TEXT NOT NULL DEFAULT '',
			issued_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
			last_used_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
			expires_at TEXT NOT NULL,
			is_revoked INTEGER NOT NULL DEFAULT 0
		);
		CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
		CREATE TABLE oauth_clients (
			id TEXT PRIMARY KEY, name TEXT NOT NULL,
			redirect_uris TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
		);
		CREATE TABLE oauth_auth_codes (
			id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE,
			client_id TEXT NOT NULL, user_id TEXT NOT NULL,
			redirect_uri TEXT NOT NULL, code_challenge TEXT NOT NULL,
			issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, used_at TEXT
		);
		CREATE TABLE auth_events (
			id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
			user_id TEXT, username TEXT NOT NULL,
			client_id TEXT, device_hint TEXT,
			ip_address TEXT, detail TEXT NOT NULL DEFAULT '',
			occurred_at TEXT NOT NULL
		);
		CREATE TABLE webauthn_challenges (
			id TEXT PRIMARY KEY, user_id TEXT,
			challenge BLOB NOT NULL,
			type TEXT NOT NULL CHECK(type IN ('registration', 'authentication')),
			session_data TEXT NOT NULL,
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
			expires_at TEXT NOT NULL
		);
		-- OLD schema: no user_present, user_verified, backup_eligible, backup_state
		CREATE TABLE webauthn_credentials (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			credential_id BLOB NOT NULL UNIQUE,
			public_key BLOB NOT NULL,
			attestation_type TEXT NOT NULL DEFAULT 'none',
			aaguid BLOB,
			sign_count INTEGER NOT NULL DEFAULT 0,
			transports TEXT,
			name TEXT NOT NULL DEFAULT '',
			created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
			last_used_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
		);
	`)
	require.NoError(t, err)

	// Insert a test user and credential with the old schema
	_, err = rawDB.Exec(`INSERT INTO users (id, username, password_hash, created_at, updated_at)
		VALUES ('u1', 'testuser', '$2a$04$x', datetime('now'), datetime('now'))`)
	require.NoError(t, err)

	_, err = rawDB.Exec(`INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, created_at, last_used_at)
		VALUES ('c1', 'u1', x'AABB', x'CCDD', datetime('now'), datetime('now'))`)
	require.NoError(t, err)

	rawDB.Close()

	// Step 2: Open with current code — migrations should add the missing columns
	database, err := db.Open(path)
	require.NoError(t, err)
	defer database.Close()

	// Step 3: Verify the new columns exist
	var userPresent, userVerified int
	err = database.DB().QueryRow(
		"SELECT user_present, user_verified FROM webauthn_credentials WHERE id = 'c1'",
	).Scan(&userPresent, &userVerified)
	require.NoError(t, err, "new columns should exist and be queryable")
	assert.Equal(t, 1, userPresent, "user_present default should be 1")
	assert.Equal(t, 0, userVerified, "user_verified default should be 0")

	// Step 4: Verify backup flags also exist (added in 003 but may be missing on very old DBs)
	var backupEligible, backupState int
	err = database.DB().QueryRow(
		"SELECT backup_eligible, backup_state FROM webauthn_credentials WHERE id = 'c1'",
	).Scan(&backupEligible, &backupState)
	require.NoError(t, err, "backup flag columns should exist")

	// Step 5: Verify a full SELECT works (same columns the store uses)
	var id, userID, attestationType, name, createdAt, lastUsedAt string
	var credentialID, publicKey []byte
	var aaguid []byte
	var signCount int
	var transports sql.NullString
	err = database.DB().QueryRow(`
		SELECT id, user_id, credential_id, public_key, attestation_type, aaguid,
			sign_count, transports, backup_eligible, backup_state,
			user_present, user_verified, name, created_at, last_used_at
		FROM webauthn_credentials WHERE id = 'c1'
	`).Scan(&id, &userID, &credentialID, &publicKey, &attestationType, &aaguid,
		&signCount, &transports, &backupEligible, &backupState,
		&userPresent, &userVerified, &name, &createdAt, &lastUsedAt)
	require.NoError(t, err, "full SELECT with all columns should work on upgraded DB")
	assert.Equal(t, "c1", id)
}

// TestOpen_SchemaUpgrade_Idempotent verifies that opening an already-upgraded
// database a second time doesn't fail (ALTER TABLE ADD COLUMN on existing columns).
func TestOpen_SchemaUpgrade_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")

	// Open twice — should not fail
	for i := range 3 {
		database, err := db.Open(path)
		require.NoError(t, err, "open attempt %d should succeed", i+1)
		database.Close()
	}
}
