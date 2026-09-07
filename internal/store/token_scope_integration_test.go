//go:build integration

package store_test

// token_scope_integration_test.go covers WP5 (GHSA-fj5g-j4mv-7m5g) at the
// persistence layer. The device grant's consented scope has to survive rotation
// — a scope that is dropped on the first refresh silently widens the grant back
// to full privilege — and a token family has to remember which claim code
// produced it, so revoking that code can reach the tokens already issued.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func scopedToken(id, hash, userID string) *domain.RefreshToken {
	now := time.Now().UTC()
	return &domain.RefreshToken{
		ID:          id,
		UserID:      userID,
		TokenHash:   hash,
		FamilyID:    "family-1",
		Audience:    "https://api.example.com",
		Scope:       "read:sensors",
		ClaimCodeID: "claim-1",
		IssuedAt:    now,
		LastUsedAt:  now,
		ExpiresAt:   now.Add(30 * 24 * time.Hour),
	}
}

func TestTokenStore_ScopeAndClaimCode_SurviveRotation(t *testing.T) {
	database := openTestDB(t)
	users := store.NewUserStore(database)
	tokens := store.NewTokenStore(database)

	require.NoError(t, users.Create(&domain.User{
		ID: "user-1", Username: "device-owner", PasswordHash: "x",
		Role: domain.RoleUser, IsActive: true,
	}))

	old := scopedToken("tok-1", "hash-old", "user-1")
	require.NoError(t, tokens.Create(old))

	got, err := tokens.GetByHash("hash-old")
	require.NoError(t, err)
	assert.Equal(t, "read:sensors", got.Scope, "scope must round-trip")
	assert.Equal(t, "claim-1", got.ClaimCodeID, "claim code binding must round-trip")

	next := &domain.RefreshToken{
		ID: "tok-2", UserID: "user-1", TokenHash: "hash-new", FamilyID: "family-1",
		IssuedAt: time.Now().UTC(), LastUsedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(30 * 24 * time.Hour),
	}
	_, err = tokens.RotateToken("hash-old", next)
	require.NoError(t, err)

	rotated, err := tokens.GetByHash("hash-new")
	require.NoError(t, err)
	assert.Equal(t, "read:sensors", rotated.Scope,
		"a rotated token must keep its scope — dropping it widens the grant")
	assert.Equal(t, "claim-1", rotated.ClaimCodeID,
		"a rotated token must stay attached to its claim code")
}

func TestTokenStore_RevokeByClaimCodeID(t *testing.T) {
	database := openTestDB(t)
	users := store.NewUserStore(database)
	tokens := store.NewTokenStore(database)

	require.NoError(t, users.Create(&domain.User{
		ID: "user-1", Username: "device-owner", PasswordHash: "x",
		Role: domain.RoleUser, IsActive: true,
	}))

	fromClaim := scopedToken("tok-1", "hash-claim", "user-1")
	require.NoError(t, tokens.Create(fromClaim))

	unrelated := scopedToken("tok-2", "hash-other", "user-1")
	unrelated.FamilyID = "family-2"
	unrelated.ClaimCodeID = ""
	require.NoError(t, tokens.Create(unrelated))

	require.NoError(t, tokens.RevokeByClaimCodeID("claim-1"))

	revoked, err := tokens.GetByHash("hash-claim")
	require.NoError(t, err)
	assert.True(t, revoked.IsRevoked,
		"revoking a claim code must revoke the tokens it produced")

	untouched, err := tokens.GetByHash("hash-other")
	require.NoError(t, err)
	assert.False(t, untouched.IsRevoked,
		"tokens unrelated to the claim code must be left alone")
}
