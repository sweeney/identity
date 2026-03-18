//go:build integration

package db_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
)

func TestOpen_CreatesDatabase(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	database, err := db.Open(path)
	require.NoError(t, err)
	defer database.Close()

	_, err = os.Stat(path)
	assert.NoError(t, err, "database file should exist on disk")
}

func TestOpen_RunsMigrations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	database, err := db.Open(path)
	require.NoError(t, err)
	defer database.Close()

	// All expected tables should exist
	tables := []string{"users", "refresh_tokens", "metadata"}
	for _, table := range tables {
		var name string
		err := database.DB().QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		require.NoError(t, err, "table %q should exist", table)
		assert.Equal(t, table, name)
	}
}

func TestOpen_MigrationsAreIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	// Open and close twice — migrations should not fail or duplicate on second open
	for i := range 2 {
		database, err := db.Open(path)
		require.NoError(t, err, "open attempt %d should succeed", i+1)
		database.Close()
	}
}

func TestOpen_WALModeEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	database, err := db.Open(path)
	require.NoError(t, err)
	defer database.Close()

	var mode string
	err = database.DB().QueryRow("PRAGMA journal_mode").Scan(&mode)
	require.NoError(t, err)
	assert.Equal(t, "wal", mode)
}

func TestOpen_ForeignKeysEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	database, err := db.Open(path)
	require.NoError(t, err)
	defer database.Close()

	var fkEnabled int
	err = database.DB().QueryRow("PRAGMA foreign_keys").Scan(&fkEnabled)
	require.NoError(t, err)
	assert.Equal(t, 1, fkEnabled)
}
