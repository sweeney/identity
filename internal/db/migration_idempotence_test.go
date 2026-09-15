//go:build integration

package db_test

// migration_idempotence_test.go guards the migration runner against replaying
// work it has already done.
//
// Before #44 the runner kept no ledger, so every file was re-executed on every
// startup and each migration had to defend itself. Migration 011 originally
// backfilled `audiences` from the legacy `audience` column with an unguarded
// UPDATE: the ALTER above it was skipped on re-run as intended, but the UPDATE
// was not — so every restart reverted whatever an operator had since
// configured, and wiped the column outright for clients created after the
// migration, whose legacy column is empty.
//
// The ledger makes that structural rather than a property each migration has to
// remember. These tests hold both ends of it: nothing is replayed on restart,
// and a database that predates the ledger is still brought fully up to date.

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"

	_ "modernc.org/sqlite"
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

	// Restart twice. Each boot must be a no-op, and must not fail: an
	// ADD COLUMN migration re-run is what #44 turned into a startup outage.
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

// TestMigrations_LedgerRecordsEveryMigration checks the wiring: every migration
// file is recorded on the first boot, and the second boot adds nothing.
func TestMigrations_LedgerRecordsEveryMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")

	files, err := os.ReadDir("migrations")
	require.NoError(t, err)
	var want []string
	for _, f := range files {
		want = append(want, f.Name())
	}
	require.NotEmpty(t, want)

	database, err := db.Open(path)
	require.NoError(t, err)
	assert.Equal(t, want, appliedMigrations(t, database.DB()))
	require.NoError(t, database.Close())

	database, err = db.Open(path)
	require.NoError(t, err)
	defer database.Close()
	assert.Equal(t, want, appliedMigrations(t, database.DB()),
		"a second boot must neither re-run nor re-record anything")
}

// TestMigrations_AdoptDatabaseFromBeforeTheLedger walks the upgrade path a real
// deployment takes: a database migrated by the pre-#44 runner, which left no
// record of what it applied, and which is still missing the migrations added
// since. Adoption must complete the outstanding ones — including migration
// 011's backfill of the legacy single-value `audience` column — without
// tripping over the ones already applied.
func TestMigrations_AdoptDatabaseFromBeforeTheLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build the database as the old runner would have, stopping short of 011 so
	// the backfill it performs is genuinely outstanding.
	legacy, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	files, err := os.ReadDir("migrations")
	require.NoError(t, err)
	for _, f := range files {
		if f.Name() >= "011" {
			break
		}
		body, err := os.ReadFile(filepath.Join("migrations", f.Name()))
		require.NoError(t, err)
		if _, err := legacy.Exec(string(body)); err != nil {
			// 004 backfills columns that later revisions of 003 create
			// outright, so on a database seeded from today's files it is a
			// no-op that reports itself as one. The old runner skipped it for
			// the same reason. Any other failure is a broken fixture.
			require.Contains(t, err.Error(), "duplicate column name", "seeding %s", f.Name())
		}
	}
	_, err = legacy.Exec(`
		INSERT INTO oauth_clients (id, name, redirect_uris, grant_types, scopes,
		                           token_endpoint_auth_method, audience,
		                           created_at, updated_at)
		VALUES ('legacy', 'Legacy', '[]', '["authorization_code"]', '[]', 'none',
		        'id.swee.net', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, legacy.Close())

	database, err := db.Open(path)
	require.NoError(t, err, "adopting a pre-ledger database must not fail")

	var audiences, legacyAudience string
	require.NoError(t, database.DB().
		QueryRow(`SELECT audiences, audience FROM oauth_clients WHERE id = 'legacy'`).
		Scan(&audiences, &legacyAudience))
	assert.Equal(t, `["id.swee.net"]`, audiences, "the legacy value must be carried over")
	assert.Empty(t, legacyAudience, "and the legacy column cleared")

	// Every migration is now recorded, so none of them runs again.
	var want []string
	for _, f := range files {
		want = append(want, f.Name())
	}
	assert.Equal(t, want, appliedMigrations(t, database.DB()))
	require.NoError(t, database.Close())

	database, err = db.Open(path)
	require.NoError(t, err)
	defer database.Close()
	require.NoError(t, database.DB().
		QueryRow(`SELECT audiences FROM oauth_clients WHERE id = 'legacy'`).Scan(&audiences))
	assert.Equal(t, `["id.swee.net"]`, audiences, "the restart after adoption changes nothing")
}

func appliedMigrations(t *testing.T, sqlDB *sql.DB) []string {
	t.Helper()

	rows, err := sqlDB.Query("SELECT name FROM schema_migrations ORDER BY name")
	require.NoError(t, err)
	defer rows.Close()

	var names []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		names = append(names, name)
	}
	require.NoError(t, rows.Err())
	return names
}
