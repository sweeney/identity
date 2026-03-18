//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func TestWebAuthnCredentialStore_CreateAndGetByCredentialID(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")

	now := time.Now().UTC().Truncate(time.Millisecond)
	cred := &domain.WebAuthnCredential{
		ID:              "cred-1",
		UserID:          "user-1",
		CredentialID:    []byte("raw-credential-id"),
		PublicKey:       []byte("cose-public-key"),
		AttestationType: "none",
		AAGUID:          []byte("0123456789abcdef"),
		SignCount:       0,
		Transports:      []string{"internal", "hybrid"},
		Name:            "MacBook Pro",
		CreatedAt:       now,
		LastUsedAt:      now,
	}
	require.NoError(t, s.Create(cred))

	got, err := s.GetByCredentialID([]byte("raw-credential-id"))
	require.NoError(t, err)
	assert.Equal(t, "cred-1", got.ID)
	assert.Equal(t, "user-1", got.UserID)
	assert.Equal(t, []byte("raw-credential-id"), got.CredentialID)
	assert.Equal(t, []byte("cose-public-key"), got.PublicKey)
	assert.Equal(t, "none", got.AttestationType)
	assert.Equal(t, uint32(0), got.SignCount)
	assert.Equal(t, []string{"internal", "hybrid"}, got.Transports)
	assert.Equal(t, "MacBook Pro", got.Name)
}

func TestWebAuthnCredentialStore_CreateDuplicate(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")

	now := time.Now().UTC()
	cred := &domain.WebAuthnCredential{
		ID: "cred-1", UserID: "user-1",
		CredentialID: []byte("dup-id"), PublicKey: []byte("key"),
		AttestationType: "none", CreatedAt: now, LastUsedAt: now,
	}
	require.NoError(t, s.Create(cred))

	cred2 := &domain.WebAuthnCredential{
		ID: "cred-2", UserID: "user-1",
		CredentialID: []byte("dup-id"), PublicKey: []byte("key2"),
		AttestationType: "none", CreatedAt: now, LastUsedAt: now,
	}
	err := s.Create(cred2)
	assert.ErrorIs(t, err, domain.ErrConflict)
}

func TestWebAuthnCredentialStore_ListByUserID(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")
	seedWebAuthnUser(t, db,"user-2")

	now := time.Now().UTC()
	for i, uid := range []string{"user-1", "user-1", "user-2"} {
		cred := &domain.WebAuthnCredential{
			ID: "cred-" + string(rune('a'+i)), UserID: uid,
			CredentialID: []byte("cid-" + string(rune('a'+i))), PublicKey: []byte("key"),
			AttestationType: "none", CreatedAt: now, LastUsedAt: now,
		}
		require.NoError(t, s.Create(cred))
	}

	creds, err := s.ListByUserID("user-1")
	require.NoError(t, err)
	assert.Len(t, creds, 2)

	creds2, err := s.ListByUserID("user-2")
	require.NoError(t, err)
	assert.Len(t, creds2, 1)

	creds3, err := s.ListByUserID("user-999")
	require.NoError(t, err)
	assert.Empty(t, creds3)
}

func TestWebAuthnCredentialStore_UpdateSignCount(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")
	seedCredential(t, s, "cred-1", "user-1")

	require.NoError(t, s.UpdateSignCount("cred-1", 42))

	got, err := s.GetByCredentialID([]byte("cid-cred-1"))
	require.NoError(t, err)
	assert.Equal(t, uint32(42), got.SignCount)
}

func TestWebAuthnCredentialStore_UpdateSignCount_NotFound(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)

	err := s.UpdateSignCount("ghost", 1)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestWebAuthnCredentialStore_UpdateLastUsed(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")
	seedCredential(t, s, "cred-1", "user-1")

	newTime := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	require.NoError(t, s.UpdateLastUsed("cred-1", newTime))

	got, err := s.GetByCredentialID([]byte("cid-cred-1"))
	require.NoError(t, err)
	assert.Equal(t, newTime.Year(), got.LastUsedAt.Year())
}

func TestWebAuthnCredentialStore_Rename(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")
	seedCredential(t, s, "cred-1", "user-1")

	require.NoError(t, s.Rename("cred-1", "My iPhone"))

	got, err := s.GetByCredentialID([]byte("cid-cred-1"))
	require.NoError(t, err)
	assert.Equal(t, "My iPhone", got.Name)
}

func TestWebAuthnCredentialStore_Rename_NotFound(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)

	err := s.Rename("ghost", "X")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestWebAuthnCredentialStore_Delete(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")
	seedCredential(t, s, "cred-1", "user-1")

	require.NoError(t, s.Delete("cred-1"))

	_, err := s.GetByCredentialID([]byte("cid-cred-1"))
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestWebAuthnCredentialStore_Delete_NotFound(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)

	err := s.Delete("ghost")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestWebAuthnCredentialStore_DeleteAllForUser(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)
	seedWebAuthnUser(t, db,"user-1")
	seedCredential(t, s, "cred-1", "user-1")
	seedCredential(t, s, "cred-2", "user-1")

	require.NoError(t, s.DeleteAllForUser("user-1"))

	creds, err := s.ListByUserID("user-1")
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestWebAuthnCredentialStore_GetByCredentialID_NotFound(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnCredentialStore(db)

	_, err := s.GetByCredentialID([]byte("does-not-exist"))
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

// seedWebAuthnUser inserts a minimal user for FK constraints in WebAuthn tests.
// The user ID will be "user-{id}" (matching the newUser helper's convention).
func seedWebAuthnUser(t *testing.T, database *db.Database, id string) {
	t.Helper()
	us := store.NewUserStore(database)
	require.NoError(t, us.Create(&domain.User{
		ID: id, Username: id, DisplayName: id,
		PasswordHash: "$2a$04$placeholder",
		Role: domain.RoleUser, IsActive: true,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		UpdatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}))
}

// seedCredential inserts a test WebAuthn credential.
func seedCredential(t *testing.T, s *store.WebAuthnCredentialStore, id, userID string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, s.Create(&domain.WebAuthnCredential{
		ID: id, UserID: userID,
		CredentialID: []byte("cid-" + id), PublicKey: []byte("pk-" + id),
		AttestationType: "none", CreatedAt: now, LastUsedAt: now,
	}))
}
