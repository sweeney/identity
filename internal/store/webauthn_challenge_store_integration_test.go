//go:build integration

package store_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func TestWebAuthnChallengeStore_CreateAndGetByID(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnChallengeStore(db)

	now := time.Now().UTC()
	ch := &domain.WebAuthnChallenge{
		ID:          "ch-1",
		UserID:      "user-1",
		Challenge:   []byte("random-challenge-bytes"),
		Type:        "registration",
		SessionData: `{"challenge":"abc","userID":"user-1"}`,
		CreatedAt:   now,
		ExpiresAt:   now.Add(120 * time.Second),
	}
	require.NoError(t, s.Create(ch))

	got, err := s.GetByID("ch-1")
	require.NoError(t, err)
	assert.Equal(t, "ch-1", got.ID)
	assert.Equal(t, "user-1", got.UserID)
	assert.Equal(t, []byte("random-challenge-bytes"), got.Challenge)
	assert.Equal(t, "registration", got.Type)
	assert.Contains(t, got.SessionData, "challenge")
}

func TestWebAuthnChallengeStore_GetByID_NotFound(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnChallengeStore(db)

	_, err := s.GetByID("does-not-exist")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestWebAuthnChallengeStore_Delete(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnChallengeStore(db)

	now := time.Now().UTC()
	ch := &domain.WebAuthnChallenge{
		ID: "ch-del", Challenge: []byte("x"), Type: "authentication",
		SessionData: "{}", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	require.NoError(t, s.Create(ch))
	require.NoError(t, s.Delete("ch-del"))

	_, err := s.GetByID("ch-del")
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestWebAuthnChallengeStore_DeleteExpired(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnChallengeStore(db)

	now := time.Now().UTC()
	// Expired challenge
	expired := &domain.WebAuthnChallenge{
		ID: "ch-expired", Challenge: []byte("x"), Type: "authentication",
		SessionData: "{}", CreatedAt: now.Add(-5 * time.Minute), ExpiresAt: now.Add(-1 * time.Minute),
	}
	// Valid challenge
	valid := &domain.WebAuthnChallenge{
		ID: "ch-valid", Challenge: []byte("y"), Type: "registration",
		SessionData: "{}", CreatedAt: now, ExpiresAt: now.Add(5 * time.Minute),
	}
	require.NoError(t, s.Create(expired))
	require.NoError(t, s.Create(valid))

	require.NoError(t, s.DeleteExpired())

	_, err := s.GetByID("ch-expired")
	assert.ErrorIs(t, err, domain.ErrNotFound)

	got, err := s.GetByID("ch-valid")
	require.NoError(t, err)
	assert.Equal(t, "ch-valid", got.ID)
}

func TestWebAuthnChallengeStore_NullUserID(t *testing.T) {
	db := openTestDB(t)
	s := store.NewWebAuthnChallengeStore(db)

	now := time.Now().UTC()
	ch := &domain.WebAuthnChallenge{
		ID: "ch-disc", UserID: "", // discoverable credential flow
		Challenge: []byte("x"), Type: "authentication",
		SessionData: "{}", CreatedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	require.NoError(t, s.Create(ch))

	got, err := s.GetByID("ch-disc")
	require.NoError(t, err)
	assert.Equal(t, "", got.UserID)
}
