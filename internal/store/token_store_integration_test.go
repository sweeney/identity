//go:build integration

package store_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func sha256hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func seedUser(t *testing.T, s domain.UserRepository, username string) *domain.User {
	t.Helper()
	u := newUser(username)
	require.NoError(t, s.Create(u))
	return u
}

func newToken(userID, familyID, raw string) *domain.RefreshToken {
	h := sha256hex(raw)
	return &domain.RefreshToken{
		ID:         "tok-" + h[:8],
		UserID:     userID,
		TokenHash:  h,
		FamilyID:   familyID,
		DeviceHint: "test device",
		IssuedAt:   time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(30 * 24 * time.Hour),
		IsRevoked:  false,
	}
}

// --- TokenStore tests ---

func TestTokenStore_CreateAndGetByHash(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	ts := store.NewTokenStore(database)

	u := seedUser(t, us, "grace")
	tok := newToken(u.ID, "family-1", "rawtoken1")

	require.NoError(t, ts.Create(tok))

	got, err := ts.GetByHash(sha256hex("rawtoken1"))
	require.NoError(t, err)
	assert.Equal(t, tok.ID, got.ID)
	assert.Equal(t, u.ID, got.UserID)
	assert.False(t, got.IsRevoked)
}

func TestTokenStore_GetByHash_NotFound(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)

	_, err := ts.GetByHash("doesnotexist")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotFound)
}

func TestTokenStore_Rotate_ReplacesOldWithNew(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	ts := store.NewTokenStore(database)

	u := seedUser(t, us, "hank")
	old := newToken(u.ID, "family-2", "rawtoken-old")
	require.NoError(t, ts.Create(old))

	newTok := &domain.RefreshToken{
		ID:            "tok-new1234",
		UserID:        u.ID,
		TokenHash:     sha256hex("rawtoken-new"),
		FamilyID:      "family-2",
		ParentTokenID: old.ID,
		DeviceHint:    "test device",
		IssuedAt:      time.Now().UTC(),
		LastUsedAt:    time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(30 * 24 * time.Hour),
	}

	require.NoError(t, ts.Rotate(old.ID, newTok))

	// Old token should now be revoked
	gotOld, err := ts.GetByHash(sha256hex("rawtoken-old"))
	require.NoError(t, err)
	assert.True(t, gotOld.IsRevoked)

	// New token should exist and be valid
	gotNew, err := ts.GetByHash(sha256hex("rawtoken-new"))
	require.NoError(t, err)
	assert.False(t, gotNew.IsRevoked)
}

func TestTokenStore_RevokeFamilyByHash(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	ts := store.NewTokenStore(database)

	u := seedUser(t, us, "iris")
	// Three tokens in same family
	for i, raw := range []string{"fam-tok-a", "fam-tok-b", "fam-tok-c"} {
		tok := newToken(u.ID, "family-3", raw)
		tok.ID = "tok-fam-" + string(rune('a'+i))
		require.NoError(t, ts.Create(tok))
	}

	// Revoke whole family via hash of first token
	require.NoError(t, ts.RevokeFamilyByHash(sha256hex("fam-tok-a")))

	// All three tokens should be revoked
	for _, raw := range []string{"fam-tok-a", "fam-tok-b", "fam-tok-c"} {
		tok, err := ts.GetByHash(sha256hex(raw))
		require.NoError(t, err)
		assert.True(t, tok.IsRevoked, "token %s should be revoked", raw)
	}
}

func TestTokenStore_RevokeByID(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	ts := store.NewTokenStore(database)

	u := seedUser(t, us, "jack")
	tok := newToken(u.ID, "family-4", "rawtoken-jack")
	require.NoError(t, ts.Create(tok))

	require.NoError(t, ts.RevokeByID(tok.ID))

	got, err := ts.GetByHash(sha256hex("rawtoken-jack"))
	require.NoError(t, err)
	assert.True(t, got.IsRevoked)
}

func TestTokenStore_RevokeAllForUser(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	ts := store.NewTokenStore(database)

	u := seedUser(t, us, "kate")
	for i, raw := range []string{"tok-k1", "tok-k2", "tok-k3"} {
		tok := newToken(u.ID, "family-5", raw)
		tok.ID = "tok-k-" + string(rune('0'+i))
		require.NoError(t, ts.Create(tok))
	}

	require.NoError(t, ts.RevokeAllForUser(u.ID))

	for _, raw := range []string{"tok-k1", "tok-k2", "tok-k3"} {
		tok, err := ts.GetByHash(sha256hex(raw))
		require.NoError(t, err)
		assert.True(t, tok.IsRevoked)
	}
}

func TestTokenStore_DeleteExpiredAndOldRevoked(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	ts := store.NewTokenStore(database)

	u := seedUser(t, us, "leo")

	// Expired token
	expiredTok := &domain.RefreshToken{
		ID:         "tok-expired",
		UserID:     u.ID,
		TokenHash:  sha256hex("expired-raw"),
		FamilyID:   "family-exp",
		IssuedAt:   time.Now().UTC().Add(-48 * time.Hour),
		LastUsedAt: time.Now().UTC().Add(-48 * time.Hour),
		ExpiresAt:  time.Now().UTC().Add(-24 * time.Hour), // already expired
	}
	require.NoError(t, ts.Create(expiredTok))

	// Valid token — should survive cleanup
	validTok := newToken(u.ID, "family-valid", "valid-raw")
	require.NoError(t, ts.Create(validTok))

	require.NoError(t, ts.DeleteExpiredAndOldRevoked(7))

	// Expired token should be gone
	_, err := ts.GetByHash(sha256hex("expired-raw"))
	assert.ErrorIs(t, err, domain.ErrNotFound)

	// Valid token should still be there
	_, err = ts.GetByHash(sha256hex("valid-raw"))
	assert.NoError(t, err)
}

func TestTokenStore_CascadeDeleteOnUserDelete(t *testing.T) {
	database := openTestDB(t)
	us := store.NewUserStore(database)
	ts := store.NewTokenStore(database)

	u := seedUser(t, us, "mike")
	tok := newToken(u.ID, "family-6", "cascade-raw")
	require.NoError(t, ts.Create(tok))

	// Deleting user should cascade-delete their tokens
	require.NoError(t, us.Delete(u.ID))

	_, err := ts.GetByHash(sha256hex("cascade-raw"))
	assert.ErrorIs(t, err, domain.ErrNotFound)
}
