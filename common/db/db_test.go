package db_test

// db_test.go covers #44: the migration runner kept no record of what it had
// already applied, so every file was re-executed on every startup.
//
// `CREATE TABLE IF NOT EXISTS` made that harmless; `ALTER TABLE ... ADD COLUMN`
// could not, so those migrations failed with "duplicate column name" on the
// second boot and fell into a retry that split the file on every `;` — comments
// and trigger bodies included. The fragments no longer parsed, and the service
// refused to start.
//
// The failure only ever showed up on the *second* boot of a database, which is
// why a suite that opens a fresh database each time never saw it. Every test
// here therefore opens the same path twice.

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commondb "github.com/sweeney/identity/common/db"

	_ "modernc.org/sqlite"
)

//go:embed testdata/*/*.sql
var testMigrations embed.FS

// openTwice opens path with the given migration directory, closes it, and opens
// it again — the restart that #44 broke. It returns the second handle.
func openTwice(t *testing.T, path, dir string) *commondb.Database {
	t.Helper()

	first, err := commondb.OpenWithMigrations(path, testMigrations, dir)
	require.NoError(t, err, "first boot should apply the migrations cleanly")
	require.NoError(t, first.Close())

	second, err := commondb.OpenWithMigrations(path, testMigrations, dir)
	require.NoError(t, err, "second boot should be a no-op, not a startup failure")
	t.Cleanup(func() { second.Close() })
	return second
}

func columns(t *testing.T, database *commondb.Database, table string) map[string]bool {
	t.Helper()

	rows, err := database.DB().Query("SELECT name FROM pragma_table_info(?)", table)
	require.NoError(t, err)
	defer rows.Close()

	found := map[string]bool{}
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		found[name] = true
	}
	require.NoError(t, rows.Err())
	return found
}

func appliedMigrations(t *testing.T, database *commondb.Database) []string {
	t.Helper()

	rows, err := database.DB().Query("SELECT name FROM schema_migrations ORDER BY name")
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

// TestMigrate_SemicolonInsideComment is the reproduction from #44: a migration
// whose only sin is a semicolon in its prose.
func TestMigrate_SemicolonInsideComment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "semicolon.db")

	database := openTwice(t, path, "testdata/semicolon_comment")

	assert.True(t, columns(t, database, "widgets")["label"],
		"the ADD COLUMN migration should still have been applied")
}

// TestMigrate_TriggerBodySurvivesRestart covers the same splitter against a
// compound statement. A trigger body is delimited by BEGIN ... END and contains
// its own semicolons, so splitting on `;` cuts it in half.
func TestMigrate_TriggerBodySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trigger.db")

	database := openTwice(t, path, "testdata/trigger")

	assert.True(t, columns(t, database, "gadgets")["note"])

	// The trigger must exist and fire — a half-applied CREATE TRIGGER would
	// leave the column in place but the behaviour missing.
	_, err := database.DB().Exec("INSERT INTO gadgets (id) VALUES ('g1')")
	require.NoError(t, err)
	_, err = database.DB().Exec("UPDATE gadgets SET note = 'hello' WHERE id = 'g1'")
	require.NoError(t, err)

	var touched int
	require.NoError(t, database.DB().
		QueryRow("SELECT touched FROM gadgets WHERE id = 'g1'").Scan(&touched))
	assert.Equal(t, 1, touched, "the trigger should have fired exactly once")
}

// TestMigrate_AppliesEachMigrationOnce is the ledger's own guarantee, and the
// reason the splitter is no longer reachable on a restart: a migration that has
// already run is not run again. It also makes non-idempotent migrations
// writable, which they were not before.
func TestMigrate_AppliesEachMigrationOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")

	database := openTwice(t, path, "testdata/ledger")

	var seeds int
	require.NoError(t, database.DB().QueryRow("SELECT count(*) FROM seeds").Scan(&seeds))
	assert.Equal(t, 1, seeds, "a one-shot INSERT migration should not be replayed on restart")

	assert.Equal(t, []string{"001_seeds.sql", "002_seed_row.sql"}, appliedMigrations(t, database),
		"the ledger should record every applied migration by filename")
}

// TestMigrate_AdoptsPreExistingDatabase covers the deploy itself: a database
// created by the old ledger-less runner already has every column, but no record
// of it. Adopting it must neither fail nor re-run the data migrations.
func TestMigrate_AdoptsPreExistingDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")

	// Build the database the way the pre-#44 runner would have: the migration
	// bodies applied straight to a bare file, with no ledger table.
	legacy, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	for _, name := range []string{"001_people.sql", "002_person_nickname.sql", "003_person_email.sql"} {
		body, err := testMigrations.ReadFile("testdata/legacy/" + name)
		require.NoError(t, err)
		_, err = legacy.Exec(string(body))
		require.NoError(t, err)
	}
	_, err = legacy.Exec("INSERT INTO people (id, name, nickname) VALUES ('p1', 'Ada', 'Addie')")
	require.NoError(t, err)
	require.NoError(t, legacy.Close())

	database, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/legacy")
	require.NoError(t, err, "adopting a pre-existing database must not fail")
	defer database.Close()

	assert.Equal(t,
		[]string{"001_people.sql", "002_person_nickname.sql", "003_person_email.sql"},
		appliedMigrations(t, database),
		"every migration should be recorded as applied, not left to re-run forever")

	var nickname string
	require.NoError(t, database.DB().
		QueryRow("SELECT nickname FROM people WHERE id = 'p1'").Scan(&nickname))
	assert.Equal(t, "Addie", nickname, "adoption must not disturb existing rows")

	// And the adopted database is now an ordinary one: the next boot skips
	// everything rather than leaning on duplicate-column tolerance again.
	require.NoError(t, database.Close())
	again, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/legacy")
	require.NoError(t, err)
	defer again.Close()
	assert.Len(t, appliedMigrations(t, again), 3)
}

// TestMigrate_BackfillColumnSkipsWhatIsAlreadyThere pins the one pattern that
// depends on "duplicate column name" being survivable. SQLite has no
// ADD COLUMN IF NOT EXISTS, so a migration that exists to reach databases
// created before an earlier migration grew a column has to add it
// unconditionally — and on a database that already has it, the statements after
// it must still run. Identity's own migration 004 is exactly this shape.
func TestMigrate_BackfillColumnSkipsWhatIsAlreadyThere(t *testing.T) {
	path := filepath.Join(t.TempDir(), "backfill.db")

	database := openTwice(t, path, "testdata/backfill")

	found := columns(t, database, "notes")
	assert.True(t, found["pinned"])
	assert.True(t, found["archived"],
		"a skipped duplicate column must not abandon the rest of the migration")
	assert.Equal(t, []string{"001_notes.sql", "002_note_flags.sql"}, appliedMigrations(t, database))
}

// TestMigrate_FailedMigrationIsNotRecorded covers the other direction: an error
// that is not a duplicate column fails the boot, names the file it came from,
// and leaves no ledger row — so the migration is offered again once it is
// fixed, rather than being recorded as done.
func TestMigrate_FailedMigrationIsNotRecorded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.db")

	_, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/broken")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "002_broken.sql", "the error should name the failing migration")

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer raw.Close()

	var recorded int
	require.NoError(t, raw.QueryRow(
		"SELECT count(*) FROM schema_migrations WHERE name = '002_broken.sql'").Scan(&recorded))
	assert.Zero(t, recorded, "a migration that failed must not be recorded as applied")

	// Its first statement must have been rolled back with it: a half-applied
	// migration that is offered again has to start from a clean slate.
	var sides int
	require.NoError(t, raw.QueryRow(
		"SELECT count(*) FROM pragma_table_info('shapes') WHERE name = 'sides'").Scan(&sides))
	assert.Zero(t, sides, "the whole migration should roll back, not just the failing statement")
}

// TestMigrate_DuplicateColumnFromCreateTableIsAnError scopes the one tolerated
// error to the statement it exists for. `duplicate column name` also comes from
// a CREATE TABLE whose column list repeats a name — an ordinary copy-paste slip
// — and swallowing that one is worse than it was before the ledger: the boot
// succeeds, the table is missing, and the migration is recorded as applied, so
// it is never retried even once the typo is fixed.
func TestMigrate_DuplicateColumnFromCreateTableIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "typo.db")

	_, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/duplicate_column_typo")
	require.Error(t, err, "a repeated column name in CREATE TABLE is a typo, not a no-op")
	assert.Contains(t, err.Error(), "001_typo.sql")
	assert.Contains(t, err.Error(), "duplicate column name")

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer raw.Close()

	var recorded int
	require.NoError(t, raw.QueryRow(
		"SELECT count(*) FROM schema_migrations WHERE name = '001_typo.sql'").Scan(&recorded))
	assert.Zero(t, recorded, "the migration must stay unrecorded so the fix is picked up")
}

// TestMigrate_RecordsChecksum covers the ledger's checksum column, which exists
// so that editing a migration that has already shipped is visible on the next
// boot rather than months later as an unexplained difference between a fresh
// database and an old one. It is recorded, not enforced: a deployed database
// will not re-run the file whatever the checksum says, and failing the boot
// would turn a corrected typo in a comment into an outage.
func TestMigrate_RecordsChecksum(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checksum.db")

	database, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/checksum")
	require.NoError(t, err)
	defer database.Close()

	body, err := testMigrations.ReadFile("testdata/checksum/001_stable.sql")
	require.NoError(t, err)
	want := sha256.Sum256(body)

	var got string
	require.NoError(t, database.DB().QueryRow(
		"SELECT checksum FROM schema_migrations WHERE name = '001_stable.sql'").Scan(&got))
	assert.Equal(t, hex.EncodeToString(want[:]), got)
}

// TestMigrate_UpgradesALedgerMissingTheChecksumColumn covers the ledger's own
// schema change. CREATE TABLE IF NOT EXISTS does nothing to a table that
// already exists, so a database carrying the two-column ledger written by the
// first build that had one would never gain the checksum column, and the next
// SELECT of it fails the boot with "no such column". The column has to be added
// separately, and the migrations already recorded must survive it — a ledger
// silently emptied here would replay every migration.
//
// This is the runner's own version of the thing it exists to do, so the next
// column added to schema_migrations reaches deployed databases too.
func TestMigrate_UpgradesALedgerMissingTheChecksumColumn(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old-ledger.db")

	// Exactly the shape the first build created, with a migration recorded
	// against it and the table that migration made.
	old, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	_, err = old.Exec(`CREATE TABLE schema_migrations (
		name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)`)
	require.NoError(t, err)
	_, err = old.Exec(`CREATE TABLE stable (id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = old.Exec(`INSERT INTO stable VALUES ('s1')`)
	require.NoError(t, err)
	_, err = old.Exec(`INSERT INTO schema_migrations (name, applied_at)
		VALUES ('001_stable.sql', '2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	require.NoError(t, old.Close())

	database, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/checksum")
	require.NoError(t, err, "a ledger predating the checksum column must be upgraded, not fatal")
	defer database.Close()

	assert.Equal(t, []string{"001_stable.sql"}, appliedMigrations(t, database),
		"the recorded migrations survive the upgrade, so none of them is replayed")

	var stored string
	require.NoError(t, database.DB().QueryRow(
		"SELECT checksum FROM schema_migrations WHERE name = '001_stable.sql'").Scan(&stored))
	assert.Empty(t, stored,
		"a row written before the column existed reads as unknown, not as a mismatch")

	var rows int
	require.NoError(t, database.DB().QueryRow("SELECT count(*) FROM stable").Scan(&rows))
	assert.Equal(t, 1, rows, "and the data the recorded migration produced is untouched")
}

// TestMigrate_ChecksumDivergenceDoesNotFailTheBoot pins that decision: a row
// whose checksum no longer matches the file warns and carries on. A row written
// before the column existed carries an empty checksum and must not warn at all.
func TestMigrate_ChecksumDivergenceDoesNotFailTheBoot(t *testing.T) {
	for _, tc := range []struct{ name, stored string }{
		{"edited since it was applied", "0000000000000000000000000000000000000000000000000000000000000000"},
		{"recorded before checksums existed", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "checksum.db")

			database, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/checksum")
			require.NoError(t, err)
			_, err = database.DB().Exec(
				"UPDATE schema_migrations SET checksum = ? WHERE name = '001_stable.sql'", tc.stored)
			require.NoError(t, err)
			require.NoError(t, database.Close())

			again, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/checksum")
			require.NoError(t, err, "a checksum mismatch must not block a boot")
			defer again.Close()

			var stored string
			require.NoError(t, again.DB().QueryRow(
				"SELECT checksum FROM schema_migrations WHERE name = '001_stable.sql'").Scan(&stored))
			assert.Equal(t, tc.stored, stored, "and must not rewrite the recorded checksum")
		})
	}
}

// TestMigrate_DuplicateColumnFromRenameIsAnError is the other half of scoping
// the tolerance. `ALTER TABLE ... RENAME COLUMN x TO y` where the table already
// has a `y` reports "duplicate column name" too, so a check for `ALTER TABLE`
// alone would swallow a rename that never happened and record it as done.
func TestMigrate_DuplicateColumnFromRenameIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rename.db")

	_, err := commondb.OpenWithMigrations(path, testMigrations, "testdata/rename_collision")
	require.Error(t, err, "a rename onto a name the table already has is a mistake, not a no-op")
	assert.Contains(t, err.Error(), "002_rename_onto_taken_name.sql")

	raw, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	defer raw.Close()

	var recorded int
	require.NoError(t, raw.QueryRow(
		"SELECT count(*) FROM schema_migrations WHERE name = '002_rename_onto_taken_name.sql'").
		Scan(&recorded))
	assert.Zero(t, recorded)
}

// TestMigrate_AddColumnIsRecognisedInEveryForm guards the other direction: the
// COLUMN keyword is optional in SQLite and the table name may be qualified, so
// narrowing the tolerance to ADD COLUMN must not narrow it out of the forms
// people actually write.
func TestMigrate_AddColumnIsRecognisedInEveryForm(t *testing.T) {
	path := filepath.Join(t.TempDir(), "addforms.db")

	database := openTwice(t, path, "testdata/add_without_column_keyword")

	found := columns(t, database, "crates")
	assert.True(t, found["label"], "the already-present column should have been skipped")
	assert.True(t, found["weight"], "and the statement after it should still have run")
}
