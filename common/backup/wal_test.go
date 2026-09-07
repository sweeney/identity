package backup

// wal_test.go covers WP3 (GHSA-c9v9-fw88-f6qw): copyDB read the main database
// file with os.ReadFile. The databases this backs up run in WAL mode, where
// recently committed transactions live in the -wal sidecar until a checkpoint.
// A file copy of the main database therefore omits committed data — and reports
// success, so the backup looks healthy right up until someone restores it.

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newWALDB creates a WAL-mode SQLite database holding one committed row that
// has not been checkpointed into the main file.
func newWALDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.db")

	db, err := sql.Open("sqlite", path)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec("PRAGMA journal_mode=WAL")
	require.NoError(t, err)
	_, err = db.Exec("CREATE TABLE secrets (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
	require.NoError(t, err)
	_, err = db.Exec("INSERT INTO secrets (value) VALUES ('committed-before-backup')")
	require.NoError(t, err)

	// Deliberately no checkpoint: the row is committed and durable, but it
	// lives in the -wal file, which is exactly the production steady state.
	return path
}

func TestCopyDB_IncludesCommittedWALData(t *testing.T) {
	src := newWALDB(t)
	dst := filepath.Join(t.TempDir(), "backup.sqlite3")

	require.NoError(t, copyDB(src, dst))

	db, err := sql.Open("sqlite", dst)
	require.NoError(t, err)
	defer db.Close()

	var value string
	err = db.QueryRow("SELECT value FROM secrets WHERE id = 1").Scan(&value)
	require.NoError(t, err, "the backup must contain the committed row")
	assert.Equal(t, "committed-before-backup", value)
}

func TestCopyDB_BackupIsOwnerOnly(t *testing.T) {
	src := newWALDB(t)
	dst := filepath.Join(t.TempDir(), "backup.sqlite3")

	require.NoError(t, copyDB(src, dst))

	info, err := os.Stat(dst)
	require.NoError(t, err)
	assert.Equal(t, "-rw-------", info.Mode().String(),
		"a copy of the credential database must not be readable by anyone else")
}
