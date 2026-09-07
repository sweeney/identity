//go:build integration

package main

// seed_wp9_test.go covers WP9 (GHSA-j5gf-rvw7-9xcm) on the first-run seed path.
//
// Two ordering/permission defects in one function:
//
//  1. The admin user was created *before* the generated password was persisted.
//     If the write failed — read-only working directory, full disk, a path that
//     is not writable — the account existed with a password that had been
//     printed nowhere and kept nowhere. The only recovery is --reset-admin.
//
//  2. os.WriteFile applies its permission argument only when it *creates* the
//     file. A leftover initial-password.txt with looser permissions kept them,
//     and a symlink at that path was followed, so the plaintext admin password
//     could land in a world-readable file or somewhere else entirely.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// inTempDir runs the seed from a scratch working directory, since the password
// file is written relative to it.
func inTempDir(t *testing.T) string {
	t.Helper()
	origDir, err := os.Getwd()
	require.NoError(t, err)
	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(origDir) }) //nolint:errcheck
	return tmpDir
}

func TestSeedIfEmpty_PasswordFileUnwritable_NoAdminCreated(t *testing.T) {
	svc := newSeedUserService(t)
	tmpDir := inTempDir(t)

	// Make the password file impossible to write by putting a directory in its
	// place — the same observable failure as a read-only filesystem.
	require.NoError(t, os.Mkdir(filepath.Join(tmpDir, initialPasswordFile), 0755))

	err := seedIfEmpty(svc, "", "")
	require.Error(t, err, "seeding must fail when the password cannot be persisted")

	users, listErr := svc.List()
	require.NoError(t, listErr)
	assert.Empty(t, users,
		"no admin may exist whose generated password was never written down")
}

func TestSeedIfEmpty_ExistingLoosePasswordFile_EndsUp0600(t *testing.T) {
	svc := newSeedUserService(t)
	tmpDir := inTempDir(t)

	// A leftover file from an earlier run, with permissions anyone can read.
	path := filepath.Join(tmpDir, initialPasswordFile)
	require.NoError(t, os.WriteFile(path, []byte("stale\n"), 0644))
	require.NoError(t, os.Chmod(path, 0644))

	require.NoError(t, seedIfEmpty(svc, "", ""))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(),
		"the generated admin password must never be left world-readable")
}

func TestSeedIfEmpty_SymlinkAtPasswordFile_NotFollowed(t *testing.T) {
	svc := newSeedUserService(t)
	tmpDir := inTempDir(t)

	target := filepath.Join(tmpDir, "elsewhere.txt")
	require.NoError(t, os.WriteFile(target, []byte(""), 0644))
	require.NoError(t, os.Symlink(target, filepath.Join(tmpDir, initialPasswordFile)))

	require.NoError(t, seedIfEmpty(svc, "", ""))

	contents, err := os.ReadFile(target)
	require.NoError(t, err)
	assert.Empty(t, contents,
		"the password must not be written through a symlink to another path")
}
