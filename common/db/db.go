package db

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	_ "modernc.org/sqlite"
)

// Database wraps a *sql.DB with migration management.
type Database struct {
	db *sql.DB
}

// OpenWithMigrations opens the given path and applies the migrations from
// migFS at migDir. Sets restrictive file permissions and the standard
// per-connection PRAGMAs.
func OpenWithMigrations(path string, migFS embed.FS, migDir string) (*Database, error) {
	if path != ":memory:" {
		oldMask := syscall.Umask(0077)
		defer syscall.Umask(oldMask)
	}

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	sqlDB.SetMaxOpenConns(1)

	database := &Database{db: sqlDB}

	if err := database.configure(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	if err := database.migrate(migFS, migDir); err != nil {
		sqlDB.Close()
		return nil, err
	}

	if path != ":memory:" {
		os.Chmod(path, 0600)        //nolint:errcheck
		os.Chmod(path+"-wal", 0600) //nolint:errcheck
		os.Chmod(path+"-shm", 0600) //nolint:errcheck
	}

	return database, nil
}

// DB returns the underlying *sql.DB for use by stores.
func (d *Database) DB() *sql.DB {
	return d.db
}

// Close closes the underlying database connection.
func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) configure() error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA busy_timeout=5000",
	}
	for _, p := range pragmas {
		if _, err := d.db.Exec(p); err != nil {
			return fmt.Errorf("pragma %q: %w", p, err)
		}
	}
	return nil
}

// migrationsTable is the ledger of migrations that have already been applied.
// Its existence is what makes the runner safe to restart: a file named here is
// never executed again.
const migrationsTable = "schema_migrations"

// migrate applies every migration in migFS at dir that the ledger does not
// already record, in filename order, each in a transaction of its own.
//
// Before #44 there was no ledger. Every file was re-executed on every startup,
// which `CREATE TABLE IF NOT EXISTS` tolerated and `ALTER TABLE ... ADD COLUMN`
// could not: the second boot failed with "duplicate column name" and fell into
// a retry that split the file on every ";" it could find, comments included.
// That made a semicolon in a migration's prose a delayed startup outage, and it
// made a non-idempotent migration unwriteable. Recording what has run removes
// both problems at the source.
func (d *Database) migrate(migFS embed.FS, dir string) error {
	entries, err := migFS.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %q: %w", dir, err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Strings(names)

	if _, err := d.db.Exec(`CREATE TABLE IF NOT EXISTS ` + migrationsTable + ` (
		name       TEXT PRIMARY KEY,
		applied_at TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create %s: %w", migrationsTable, err)
	}

	applied, err := d.appliedMigrations()
	if err != nil {
		return err
	}

	for _, name := range names {
		if applied[name] {
			continue
		}

		body, err := migFS.ReadFile(dir + "/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}

		if err := d.applyMigration(name, string(body)); err != nil {
			return err
		}
	}

	return nil
}

// appliedMigrations reads the ledger.
func (d *Database) appliedMigrations() (map[string]bool, error) {
	rows, err := d.db.Query(`SELECT name FROM ` + migrationsTable)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", migrationsTable, err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read %s: %w", migrationsTable, err)
		}
		applied[name] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", migrationsTable, err)
	}
	return applied, nil
}

// applyMigration runs one migration and records it, atomically: the ledger row
// and the schema change commit together, so a migration that fails part way
// leaves neither behind and is offered again on the next boot.
//
// A migration file therefore must not manage transactions itself, and must not
// contain a statement SQLite refuses to run inside one (VACUUM, or a
// foreign_keys pragma).
//
// "duplicate column name" is not treated as a failure. SQLite has no
// `ADD COLUMN IF NOT EXISTS`, so a migration that backfills a column only into
// the databases missing it — because a later revision of an earlier migration
// creates it outright — can be written no other way. Skipping is per statement,
// so the rest of the file still runs. It is also what lets a database migrated
// by a pre-ledger build be adopted: its columns are already there, the re-run
// is a no-op, and the ledger row written here means it is never offered again.
func (d *Database) applyMigration(name, body string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	for _, stmt := range splitStatements(body) {
		if _, err := tx.Exec(stmt); err != nil {
			if strings.Contains(err.Error(), "duplicate column name") {
				continue
			}
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO `+migrationsTable+` (name, applied_at) VALUES (?, ?)`,
		name, time.Now().UTC().Format(time.RFC3339Nano),
	); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}

	return nil
}
