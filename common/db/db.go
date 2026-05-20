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

func (d *Database) migrate(migFS embed.FS, dir string) error {
	entries, err := migFS.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %q: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		sqlBytes, err := migFS.ReadFile(dir + "/" + entry.Name())
		if err != nil {
			return fmt.Errorf("read migration %s: %w", entry.Name(), err)
		}

		if _, err := d.db.Exec(string(sqlBytes)); err != nil {
			if !strings.Contains(err.Error(), "duplicate column name") {
				return fmt.Errorf("apply migration %s: %w", entry.Name(), err)
			}
			for _, stmt := range strings.Split(string(sqlBytes), ";") {
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
