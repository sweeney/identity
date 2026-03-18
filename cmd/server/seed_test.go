//go:build integration

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/backup"
	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/store"
)

func newSeedUserService(t *testing.T) *service.UserService {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "seed.db"))
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	userStore := store.NewUserStore(database)
	tokenStore := store.NewTokenStore(database)
	return service.NewUserService(userStore, tokenStore, &backup.NoopManager{}, nil, 10).WithBcryptCost(4)
}

func TestSeedIfEmpty_WithEnvCreds(t *testing.T) {
	svc := newSeedUserService(t)

	err := seedIfEmpty(svc, "admin", "securepassword1")
	require.NoError(t, err)

	users, err := svc.List()
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "admin", users[0].Username)
	assert.Equal(t, domain.RoleAdmin, users[0].Role)
	assert.True(t, users[0].IsActive)
}

func TestSeedIfEmpty_GeneratesPasswordWhenNoCreds(t *testing.T) {
	svc := newSeedUserService(t)

	// Run seedIfEmpty from a temp dir so the password file lands there.
	origDir, err := os.Getwd()
	require.NoError(t, err)
	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	// No username or password — should auto-generate
	err = seedIfEmpty(svc, "", "")
	require.NoError(t, err)

	users, err := svc.List()
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "admin", users[0].Username)
	assert.Equal(t, domain.RoleAdmin, users[0].Role)

	// Password file should exist with 0600 permissions and contain credentials.
	pwFile := filepath.Join(tmpDir, initialPasswordFile)
	info, err := os.Stat(pwFile)
	require.NoError(t, err, "initial-password.txt should exist")
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "file should have 0600 permissions")

	content, err := os.ReadFile(pwFile)
	require.NoError(t, err)
	assert.Contains(t, string(content), "Username: admin")
	assert.Contains(t, string(content), "Password: ")
}

func TestSeedIfEmpty_SkipsWhenUsersExist(t *testing.T) {
	svc := newSeedUserService(t)

	// Run from a temp dir so we can check file cleanup.
	origDir, err := os.Getwd()
	require.NoError(t, err)
	tmpDir := t.TempDir()
	require.NoError(t, os.Chdir(tmpDir))
	t.Cleanup(func() { os.Chdir(origDir) })

	// Simulate a leftover password file from a previous first run.
	pwFile := filepath.Join(tmpDir, initialPasswordFile)
	require.NoError(t, os.WriteFile(pwFile, []byte("old"), 0600))

	// Pre-create a user
	_, err = svc.Create("existing", "Existing", "securepassword1", domain.RoleUser)
	require.NoError(t, err)

	// Seed should be a no-op and clean up the password file.
	err = seedIfEmpty(svc, "admin", "securepassword1")
	require.NoError(t, err)

	users, err := svc.List()
	require.NoError(t, err)
	assert.Len(t, users, 1, "should still be 1 user — seed was skipped")
	assert.Equal(t, "existing", users[0].Username)

	// Password file should have been removed.
	_, err = os.Stat(pwFile)
	assert.True(t, os.IsNotExist(err), "initial-password.txt should be cleaned up")
}

func TestSeedIfEmpty_WeakPassword(t *testing.T) {
	svc := newSeedUserService(t)

	err := seedIfEmpty(svc, "admin", "short")
	require.Error(t, err)
}
