//go:build integration

package store_test

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func openConfigDB(t *testing.T) *db.Database {
	t.Helper()
	dir := t.TempDir()
	database, err := db.OpenConfig(filepath.Join(dir, "config.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestConfigStore_CreateAndGet(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	now := time.Now().UTC().Truncate(time.Second)

	ns := &domain.ConfigNamespace{
		Name:      "houses",
		ReadRole:  "admin",
		WriteRole: "admin",
		Document:  []byte(`{"main":"Rivendell"}`),
		UpdatedAt: now,
		UpdatedBy: "user-123",
		CreatedAt: now,
	}
	require.NoError(t, s.Create(ns))

	got, err := s.Get("houses")
	require.NoError(t, err)
	assert.Equal(t, "houses", got.Name)
	assert.Equal(t, "admin", got.ReadRole)
	assert.Equal(t, "admin", got.WriteRole)
	assert.JSONEq(t, `{"main":"Rivendell"}`, string(got.Document))
	assert.Equal(t, "user-123", got.UpdatedBy)
	assert.True(t, got.UpdatedAt.Equal(now))
	assert.True(t, got.CreatedAt.Equal(now))
}

func TestConfigStore_Get_NotFound(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	_, err := s.Get("missing")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestConfigStore_Create_Duplicate_ReturnsConflict(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	now := time.Now().UTC()
	ns := &domain.ConfigNamespace{
		Name: "dup", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}
	require.NoError(t, s.Create(ns))
	err := s.Create(ns)
	assert.True(t, errors.Is(err, domain.ErrConflict),
		"duplicate Create should return ErrConflict, got %v", err)
}

func TestConfigStore_Create_InvalidRole_RejectedByCheckConstraint(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	now := time.Now().UTC()
	err := s.Create(&domain.ConfigNamespace{
		Name: "bad", ReadRole: "root", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	})
	assert.Error(t, err, "CHECK constraint on role column must reject unknown role")
}

func TestConfigStore_UpdateDocument(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	now := time.Now().UTC().Truncate(time.Second)
	ns := &domain.ConfigNamespace{
		Name: "mqtt", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{"topic":"/a"}`), UpdatedAt: now, UpdatedBy: "u1", CreatedAt: now,
	}
	require.NoError(t, s.Create(ns))

	later := now.Add(time.Minute)
	require.NoError(t, s.UpdateDocument("mqtt", []byte(`{"topic":"/b"}`), "u2", later))

	got, err := s.Get("mqtt")
	require.NoError(t, err)
	assert.JSONEq(t, `{"topic":"/b"}`, string(got.Document))
	assert.Equal(t, "u2", got.UpdatedBy)
	assert.True(t, got.UpdatedAt.Equal(later))
	// created_at should not move on a document update
	assert.True(t, got.CreatedAt.Equal(now))
}

func TestConfigStore_UpdateDocument_NotFound(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	err := s.UpdateDocument("missing", []byte(`{}`), "u", time.Now().UTC())
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestConfigStore_UpdateACL(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	now := time.Now().UTC().Truncate(time.Second)
	ns := &domain.ConfigNamespace{
		Name: "prefs", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}
	require.NoError(t, s.Create(ns))

	later := now.Add(time.Minute)
	require.NoError(t, s.UpdateACL("prefs", "user", "admin", later))

	got, err := s.Get("prefs")
	require.NoError(t, err)
	assert.Equal(t, "user", got.ReadRole)
	assert.Equal(t, "admin", got.WriteRole)
	assert.True(t, got.UpdatedAt.Equal(later))
}

func TestConfigStore_UpdateACL_NotFound(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	err := s.UpdateACL("missing", "user", "admin", time.Now().UTC())
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestConfigStore_Delete(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	now := time.Now().UTC()
	ns := &domain.ConfigNamespace{
		Name: "temp", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}
	require.NoError(t, s.Create(ns))
	require.NoError(t, s.Delete("temp"))

	_, err := s.Get("temp")
	assert.ErrorIs(t, err, domain.ErrNotFound)

	// Subsequent delete should also return not-found.
	assert.ErrorIs(t, s.Delete("temp"), domain.ErrNotFound)
}

func TestConfigStore_List_Ordered(t *testing.T) {
	s := store.NewConfigStore(openConfigDB(t))
	now := time.Now().UTC()
	for _, name := range []string{"charlie", "alpha", "bravo"} {
		require.NoError(t, s.Create(&domain.ConfigNamespace{
			Name: name, ReadRole: "admin", WriteRole: "admin",
			Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
		}))
	}

	list, err := s.List()
	require.NoError(t, err)
	require.Len(t, list, 3)
	assert.Equal(t, "alpha", list[0].Name)
	assert.Equal(t, "bravo", list[1].Name)
	assert.Equal(t, "charlie", list[2].Name)
}
