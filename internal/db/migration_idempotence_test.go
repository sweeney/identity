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
	want := migrationNames(t)

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

// migrationNames lists the migration files in the order the runner applies
// them.
func migrationNames(t *testing.T) []string {
	t.Helper()

	files, err := os.ReadDir("migrations")
	require.NoError(t, err)
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	require.NotEmpty(t, names)
	return names
}

// seedPreLedgerDatabase builds a database at path the way the pre-#44 runner
// would have: migration bodies executed whole, straight onto a bare file, with
// no schema_migrations table. Files from stopBefore onwards are left out, so a
// caller can choose how far behind the deployed database is; an empty
// stopBefore applies all of them.
func seedPreLedgerDatabase(t *testing.T, path, stopBefore string) {
	t.Helper()

	legacy, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer legacy.Close()

	for _, name := range migrationNames(t) {
		if stopBefore != "" && name >= stopBefore {
			break
		}
		body, err := os.ReadFile(filepath.Join("migrations", name))
		require.NoError(t, err)
		if _, err := legacy.Exec(string(body)); err != nil {
			// 004 backfills columns that later revisions of 003 create
			// outright, so on a database seeded from today's files it is a
			// no-op that reports itself as one. The old runner skipped it for
			// the same reason. Any other failure is a broken fixture.
			require.Contains(t, err.Error(), "duplicate column name", "seeding %s", name)
		}
	}
}

// TestMigrations_AdoptDatabaseBehindTheLedger walks the upgrade path of a
// deployment that is a few migrations behind: no record of what it applied, and
// still missing the migrations added since. Adoption must complete the
// outstanding ones — including migration 011's backfill of the legacy
// single-value `audience` column — without tripping over the ones already
// applied.
func TestMigrations_AdoptDatabaseBehindTheLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "behind.db")

	// Stop short of 011 so the backfill it performs is genuinely outstanding.
	seedPreLedgerDatabase(t, path, "011")

	legacy, err := sql.Open("sqlite", path)
	require.NoError(t, err)
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
	assert.Equal(t, migrationNames(t), appliedMigrations(t, database.DB()))
	require.NoError(t, database.Close())

	database, err = db.Open(path)
	require.NoError(t, err)
	defer database.Close()
	require.NoError(t, database.DB().
		QueryRow(`SELECT audiences FROM oauth_clients WHERE id = 'legacy'`).Scan(&audiences))
	assert.Equal(t, `["id.swee.net"]`, audiences, "the restart after adoption changes nothing")
}

// TestMigrations_AdoptFullyMigratedDatabase is the state a deployed host is
// actually in on the day this ships: every migration already applied, none of
// them recorded. That makes the adoption boot the mirror image of the test
// above — thirteen files offered, thirteen already done, nothing allowed to
// change — and it is the only test that exercises the re-run of migration 011,
// whose backfill modifies data, against a database where it has already run.
func TestMigrations_AdoptFullyMigratedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "current.db")

	seedPreLedgerDatabase(t, path, "")

	// A client configured the way an operator would have left it after 011:
	// backfilled `audiences`, legacy `audience` already cleared.
	legacy, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = legacy.Exec(`
		INSERT INTO oauth_clients (id, name, redirect_uris, grant_types, scopes,
		                           token_endpoint_auth_method, audiences,
		                           created_at, updated_at)
		VALUES ('app', 'App', '[]', '["authorization_code"]', '[]', 'none',
		        '["statehouse","config"]', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, legacy.Close())

	before := schemaOf(t, path)

	database, err := db.Open(path)
	require.NoError(t, err, "adopting a fully-migrated database must not fail")

	var audiences string
	require.NoError(t, database.DB().
		QueryRow(`SELECT audiences FROM oauth_clients WHERE id = 'app'`).Scan(&audiences))
	assert.Equal(t, `["statehouse","config"]`, audiences,
		"adoption must not re-run 011's backfill over configured audiences")

	assert.Equal(t, migrationNames(t), appliedMigrations(t, database.DB()),
		"every migration is recorded, so none is offered again")
	require.NoError(t, database.Close())

	assert.Equal(t, before, schemaOf(t, path),
		"adoption must leave the schema exactly as it found it")

	// And the boot after adoption is an ordinary no-op.
	database, err = db.Open(path)
	require.NoError(t, err)
	defer database.Close()
	require.NoError(t, database.DB().
		QueryRow(`SELECT audiences FROM oauth_clients WHERE id = 'app'`).Scan(&audiences))
	assert.Equal(t, `["statehouse","config"]`, audiences)
}

// schemaOf returns every object definition in the database except the ledger,
// so that "adoption changed nothing" can be asserted rather than sampled.
func schemaOf(t *testing.T, path string) []string {
	t.Helper()

	sqlDB, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer sqlDB.Close()

	rows, err := sqlDB.Query(`SELECT type, name, COALESCE(sql, '') FROM sqlite_master
	                           WHERE name NOT LIKE 'sqlite_%' AND name <> 'schema_migrations'
	                           ORDER BY type, name`)
	require.NoError(t, err)
	defer rows.Close()

	var objects []string
	for rows.Next() {
		var kind, name, ddl string
		require.NoError(t, rows.Scan(&kind, &name, &ddl))
		objects = append(objects, kind+" "+name+": "+ddl)
	}
	require.NoError(t, rows.Err())
	require.NotEmpty(t, objects)
	return objects
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
