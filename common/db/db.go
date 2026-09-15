package db

import (
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"fmt"
	"log"
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
		applied_at TEXT NOT NULL,
		checksum   TEXT NOT NULL DEFAULT ''
	)`); err != nil {
		return fmt.Errorf("create %s: %w", migrationsTable, err)
	}

	applied, err := d.appliedMigrations()
	if err != nil {
		return err
	}

	var ran int
	for _, name := range names {
		body, err := migFS.ReadFile(dir + "/" + name)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", name, err)
		}
		sum := checksum(body)

		if recorded, ok := applied[name]; ok {
			// A migration that has shipped must never be edited or renamed:
			// deployed databases already record it and will never run it
			// again, so the change reaches only databases created afterwards,
			// and the two drift apart silently. Comparing the checksum cannot
			// undo that, but it does make it visible on the next boot instead
			// of months later as an unexplained schema difference.
			if recorded != "" && recorded != sum {
				log.Printf("db: WARNING: migration %s has changed since it was applied here "+
					"(recorded %s, now %s). Databases that already ran it will not run it "+
					"again, so this edit reaches only new databases.",
					name, shortSum(recorded), shortSum(sum))
			}
			continue
		}

		if ran == 0 {
			log.Printf("db: applying migrations from %s", dir)
		}
		if err := d.applyMigration(name, string(body), sum); err != nil {
			return err
		}
		ran++
	}

	if ran > 0 {
		log.Printf("db: applied %d migration(s)", ran)
	}

	return nil
}

// checksum fingerprints a migration body for the ledger.
func checksum(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// shortSum abbreviates a checksum for a log line.
func shortSum(sum string) string {
	if len(sum) > 12 {
		return sum[:12]
	}
	return sum
}

// appliedMigrations reads the ledger, mapping each recorded migration to the
// checksum of the body that was applied. The checksum is empty for a row
// written before the column existed.
func (d *Database) appliedMigrations() (map[string]string, error) {
	rows, err := d.db.Query(`SELECT name, checksum FROM ` + migrationsTable)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", migrationsTable, err)
	}
	defer rows.Close()

	applied := make(map[string]string)
	for rows.Next() {
		var name, sum string
		if err := rows.Scan(&name, &sum); err != nil {
			return nil, fmt.Errorf("read %s: %w", migrationsTable, err)
		}
		applied[name] = sum
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
// foreign_keys pragma). It must also not rebuild a table that something
// references: configure() enables foreign keys before this runs, and they
// cannot be turned off inside a transaction, so DROP TABLE would cascade.
//
// An `ALTER TABLE ... ADD COLUMN` that fails with "duplicate column name" is
// skipped rather than failing the boot. SQLite has no `ADD COLUMN IF NOT EXISTS`, so a migration
// that backfills a column only into the databases missing it — because a later
// revision of an earlier migration creates it outright — can be written no
// other way. Skipping is per statement, so the rest of the file still runs, and
// it is scoped to ADD COLUMN because that is the only statement the exception
// exists for. The same message from a CREATE TABLE means a repeated name in its
// column list, and from an ALTER TABLE ... RENAME COLUMN it means a rename onto
// a name already taken — both are mistakes to fail on, not columns already in
// place, and the ledger would record either as done and never offer it again.
//
// This is also what adopts a database migrated by a pre-ledger build: its
// columns are already there, the re-run is a no-op, and the ledger row written
// here means the file is never offered again.
func (d *Database) applyMigration(name, body, sum string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("apply migration %s: %w", name, err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once committed

	for _, stmt := range splitStatements(body) {
		if _, err := tx.Exec(stmt); err != nil {
			if isAddColumn(stmt) && strings.Contains(err.Error(), "duplicate column name") {
				log.Printf("db: %s: column already present, skipping: %s", name, summarize(stmt))
				continue
			}
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}

	if _, err := tx.Exec(
		`INSERT INTO `+migrationsTable+` (name, applied_at, checksum) VALUES (?, ?, ?)`,
		name, time.Now().UTC().Format(time.RFC3339Nano), sum,
	); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration %s: %w", name, err)
	}

	return nil
}

// isAddColumn reports whether stmt is an `ALTER TABLE ... ADD [COLUMN]`, the
// one statement the duplicate-column exception exists for.
//
// It has to be this precise rather than a test for `ALTER TABLE`. A rename onto
// a name the table already has reports the same "duplicate column name", and
// that one is a broken migration, not one already applied:
//
//	ALTER TABLE a RENAME COLUMN x TO z   =>  error in table a after rename:
//	                                         duplicate column name: z
//
// The COLUMN keyword is optional in SQLite, and the table name may be quoted or
// schema-qualified, so the clause is found by reading forward to the first of
// ADD, RENAME or DROP rather than by counting words.
func isAddColumn(stmt string) bool {
	words := headWords(stmt, 8)
	if len(words) < 3 || words[0] != "ALTER" || words[1] != "TABLE" {
		return false
	}
	for _, w := range words[2:] {
		switch w {
		case "ADD":
			return true
		case "RENAME", "DROP":
			return false
		}
	}
	return false
}

// headWords returns up to max leading unquoted words of stmt, upper-cased.
// Quoted runs are skipped whole, so a table named "add" cannot be mistaken for
// the clause keyword. splitStatements has already stripped comments and trimmed
// leading whitespace, so the first word is the statement's own keyword.
func headWords(stmt string, max int) []string {
	var (
		words []string
		word  strings.Builder
	)
	flush := func() {
		if word.Len() > 0 {
			words = append(words, strings.ToUpper(word.String()))
			word.Reset()
		}
	}

	for i := 0; i < len(stmt) && len(words) < max; i++ {
		c := stmt[i]
		if isWordByte(c) {
			word.WriteByte(c)
			continue
		}
		flush()
		if c == '\'' || c == '"' || c == '`' || c == '[' {
			var discard strings.Builder // only reached on a failing statement
			i = copyQuoted(&discard, stmt, i)
		}
	}
	flush()

	if len(words) > max {
		words = words[:max]
	}
	return words
}

// summarize renders a statement as a single short line for a log message.
func summarize(stmt string) string {
	line := strings.Join(strings.Fields(stmt), " ")
	if len(line) > 90 {
		return line[:90] + "..."
	}
	return line
}
