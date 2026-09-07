//go:build integration

package db_test

// migration_idempotence_test.go guards a property that is easy to lose and
// expensive to notice: migrations are re-applied on every startup, so any
// statement after a failing ALTER runs again on each restart.
//
// Migration 011 originally backfilled `audiences` from the legacy `audience`
// column with an unguarded UPDATE. The ALTER was skipped on re-run as intended,
// but the UPDATE was not — so every restart reverted whatever an operator had
// since configured, and wiped the column outright for clients created after the
// migration, whose legacy column is empty.

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
)

// TestMigrations_SurviveRepeatedApplication asserts that data written after
// migration survives further startups.
func TestMigrations_SurviveRepeatedApplication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idempotence.db")

	database, err := db.Open(path)
	require.NoError(t, err)

	_, err = database.DB().Exec(`
		INSERT INTO oauth_clients (id, name, redirect_uris, grant_types, scopes,
		                           token_endpoint_auth_method, audiences, created_at, updated_at)
		VALUES ('app', 'App', '[]', '["authorization_code"]', '[]', 'none',
		        '["statehouse","config"]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, database.Close())

	// Restart twice: migrations run again each time.
	for i := 0; i < 2; i++ {
		database, err = db.Open(path)
		require.NoError(t, err, "restart %d", i+1)

		var audiences string
		require.NoError(t, database.DB().
			QueryRow(`SELECT audiences FROM oauth_clients WHERE id = 'app'`).Scan(&audiences))
		assert.Equal(t, `["statehouse","config"]`, audiences,
			"restart %d must not rewrite configured audiences", i+1)
		require.NoError(t, database.Close())
	}
}

// A row carrying only the legacy single-value column is still backfilled, and
// then left alone.
func TestMigrations_BackfillsLegacyAudienceOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backfill.db")

	database, err := db.Open(path)
	require.NoError(t, err)
	// Put a row into the pre-migration shape by writing the legacy column back.
	_, err = database.DB().Exec(`
		INSERT INTO oauth_clients (id, name, redirect_uris, grant_types, scopes,
		                           token_endpoint_auth_method, audience, audiences,
		                           created_at, updated_at)
		VALUES ('legacy', 'Legacy', '[]', '["authorization_code"]', '[]', 'none',
		        'id.swee.net', '[]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, database.Close())

	database, err = db.Open(path)
	require.NoError(t, err)
	var audiences, legacy string
	require.NoError(t, database.DB().
		QueryRow(`SELECT audiences, audience FROM oauth_clients WHERE id = 'legacy'`).
		Scan(&audiences, &legacy))
	assert.Equal(t, `["id.swee.net"]`, audiences, "the legacy value must be carried over")
	assert.Empty(t, legacy, "and the legacy column cleared, so the backfill cannot repeat")
	require.NoError(t, database.Close())
}
