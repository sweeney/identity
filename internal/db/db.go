package db

import (
	"database/sql"
	"embed"
	"fmt"
	"os"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Database wraps a *sql.DB with migration management.
type Database struct {
	db *sql.DB
}

// Open opens (or creates) a SQLite database at path, enables WAL mode and
// foreign keys, and runs all pending migrations.
func Open(path string) (*Database, error) {
	// Set restrictive umask before creating the database file so it is
	// never world-readable, even momentarily.
	if path != ":memory:" {
		oldMask := syscall.Umask(0077)
		defer syscall.Umask(oldMask)
	}

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	// SQLite is not safe for concurrent writers with the default pool size.
	// We serialize writes via a single connection for writes; reads can fan out.
	sqlDB.SetMaxOpenConns(1)

	database := &Database{db: sqlDB}

	if err := database.configure(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	if err := database.migrate(); err != nil {
		sqlDB.Close()
		return nil, err
	}

	// Restrict file permissions to owner-only (0600).
	if path != ":memory:" {
		os.Chmod(path, 0600)       //nolint:errcheck
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

// configure sets per-connection PRAGMAs.
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

// migrate runs all SQL files in migrations/ in lexicographic order.
// Uses CREATE TABLE IF NOT EXISTS / CREATE INDEX IF NOT EXISTS, so it is
// safe to call on an already-migrated database.
func (d *Database) migrate() error {
	entries, err := migrationFiles.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		sql, err := migrationFiles.ReadFile("migrations/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		// Run the migration. If it contains multiple statements and one fails
		// with "duplicate column name" (from ALTER TABLE ADD COLUMN on a column
		// that already exists), run each statement individually so the rest
		// can still execute.
		if _, err := d.db.Exec(string(sql)); err != nil {
			if !strings.Contains(err.Error(), "duplicate column name") {
				return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
			}
			// Fall back to per-statement execution, ignoring duplicate column errors.
			for _, stmt := range strings.Split(string(sql), ";") {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" {
					continue
				}
				if _, err := d.db.Exec(stmt); err != nil {
					if strings.Contains(err.Error(), "duplicate column name") {
						continue
					}
					return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
				}
			}
		}
	}

	return nil
}
