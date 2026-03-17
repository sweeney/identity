//go:build integration

package main

import (
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

	// No username or password — should auto-generate
	err := seedIfEmpty(svc, "", "")
	require.NoError(t, err)

	users, err := svc.List()
	require.NoError(t, err)
	require.Len(t, users, 1)
	assert.Equal(t, "admin", users[0].Username)
	assert.Equal(t, domain.RoleAdmin, users[0].Role)
}

func TestSeedIfEmpty_SkipsWhenUsersExist(t *testing.T) {
	svc := newSeedUserService(t)

	// Pre-create a user
	_, err := svc.Create("existing", "Existing", "securepassword1", domain.RoleUser)
	require.NoError(t, err)

	// Seed should be a no-op
	err = seedIfEmpty(svc, "admin", "securepassword1")
	require.NoError(t, err)

	users, err := svc.List()
	require.NoError(t, err)
	assert.Len(t, users, 1, "should still be 1 user — seed was skipped")
	assert.Equal(t, "existing", users[0].Username)
}

func TestSeedIfEmpty_WeakPassword(t *testing.T) {
	svc := newSeedUserService(t)

	err := seedIfEmpty(svc, "admin", "short")
	require.Error(t, err)
}
