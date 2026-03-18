//go:build integration

package store_test

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func openTestDB(t *testing.T) *db.Database {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })
	return database
}

func newUser(username string) *domain.User {
	return &domain.User{
		ID:           "user-" + username,
		Username:     username,
		DisplayName:  username + " Display",
		PasswordHash: "$2a$04$placeholder",
		Role:         domain.RoleUser,
		IsActive:     true,
		CreatedAt:    time.Now().UTC().Truncate(time.Millisecond),
		UpdatedAt:    time.Now().UTC().Truncate(time.Millisecond),
	}
}

// --- UserStore tests ---

func TestUserStore_CreateAndGetByID(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	u := newUser("alice")

	require.NoError(t, s.Create(u))

	got, err := s.GetByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
	assert.Equal(t, u.Username, got.Username)
	assert.Equal(t, u.DisplayName, got.DisplayName)
	assert.Equal(t, u.Role, got.Role)
	assert.True(t, got.IsActive)
}

func TestUserStore_GetByUsername(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	u := newUser("bob")
	require.NoError(t, s.Create(u))

	got, err := s.GetByUsername("bob")
	require.NoError(t, err)
	assert.Equal(t, u.ID, got.ID)
}

func TestUserStore_GetByUsername_CaseInsensitive(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	require.NoError(t, s.Create(newUser("Charlie")))

	got, err := s.GetByUsername("charlie")
	require.NoError(t, err)
	assert.Equal(t, "user-Charlie", got.ID)
}

func TestUserStore_GetByID_NotFound(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))

	_, err := s.GetByID("nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestUserStore_GetByUsername_NotFound(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))

	_, err := s.GetByUsername("ghost")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestUserStore_Create_DuplicateUsername(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	require.NoError(t, s.Create(newUser("dave")))

	dupe := newUser("dave")
	dupe.ID = "other-id"
	err := s.Create(dupe)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrConflict)
}

func TestUserStore_Update(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	u := newUser("eve")
	require.NoError(t, s.Create(u))

	u.DisplayName = "Eve Updated"
	u.IsActive = false
	require.NoError(t, s.Update(u))

	got, err := s.GetByID(u.ID)
	require.NoError(t, err)
	assert.Equal(t, "Eve Updated", got.DisplayName)
	assert.False(t, got.IsActive)
}

func TestUserStore_Delete(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	u := newUser("frank")
	require.NoError(t, s.Create(u))

	require.NoError(t, s.Delete(u.ID))

	_, err := s.GetByID(u.ID)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestUserStore_List(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	for _, name := range []string{"a", "b", "c"} {
		require.NoError(t, s.Create(newUser(name)))
	}

	users, err := s.List()
	require.NoError(t, err)
	assert.Len(t, users, 3)
}

func TestUserStore_Count(t *testing.T) {
	s := store.NewUserStore(openTestDB(t))
	require.NoError(t, s.Create(newUser("x")))
	require.NoError(t, s.Create(newUser("y")))

	count, err := s.Count()
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}
