//go:build integration

package store_test

// token_client_binding_integration_test.go covers WP4 (GHSA-vrh2-jqhp-4m44) at
// the persistence layer: a refresh token has to remember which OAuth client it
// was issued to, and keep remembering it across rotation, or the binding is
// only good until the first refresh.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func TestTokenStore_ClientBinding_SurvivesRotation(t *testing.T) {
	database := openTestDB(t)
	users := store.NewUserStore(database)
	tokens := store.NewTokenStore(database)

	require.NoError(t, users.Create(&domain.User{
		ID: "u-1", Username: "alice", PasswordHash: "x",
		Role: domain.RoleUser, IsActive: true,
	}))

	now := time.Now().UTC()
	old := &domain.RefreshToken{
		ID: "tok-1", UserID: "u-1", TokenHash: "hash-old", FamilyID: "fam-1",
		ClientID: "photo-app", IssuedAt: now, LastUsedAt: now,
		ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
	require.NoError(t, tokens.Create(old))

	got, err := tokens.GetByHash("hash-old")
	require.NoError(t, err)
	assert.Equal(t, "photo-app", got.ClientID, "the issuing client must round-trip")

	next := &domain.RefreshToken{
		ID: "tok-2", UserID: "u-1", TokenHash: "hash-new", FamilyID: "fam-1",
		IssuedAt: now, LastUsedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	}
	_, err = tokens.RotateToken("hash-old", next)
	require.NoError(t, err)

	rotated, err := tokens.GetByHash("hash-new")
	require.NoError(t, err)
	assert.Equal(t, "photo-app", rotated.ClientID,
		"a rotated token must stay bound to its client — otherwise the binding "+
			"lasts exactly one refresh")
}

// A direct-API login has no OAuth client, and that must stay representable.
func TestTokenStore_NoClientBinding_ForDirectLogin(t *testing.T) {
	database := openTestDB(t)
	users := store.NewUserStore(database)
	tokens := store.NewTokenStore(database)

	require.NoError(t, users.Create(&domain.User{
		ID: "u-1", Username: "alice", PasswordHash: "x",
		Role: domain.RoleUser, IsActive: true,
	}))

	now := time.Now().UTC()
	require.NoError(t, tokens.Create(&domain.RefreshToken{
		ID: "tok-1", UserID: "u-1", TokenHash: "hash-direct", FamilyID: "fam-1",
		IssuedAt: now, LastUsedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	}))

	got, err := tokens.GetByHash("hash-direct")
	require.NoError(t, err)
	assert.Empty(t, got.ClientID)
}

// A token issued before the binding existed carries no client. When the
// presenting client supplies one on rotation, the replacement adopts it —
// that is what lets a pre-migration session survive the upgrade and become
// bound, rather than being refused outright.
func TestTokenStore_RotateToken_AdoptsClientWhenUnbound(t *testing.T) {
	database := openTestDB(t)
	users := store.NewUserStore(database)
	tokens := store.NewTokenStore(database)

	require.NoError(t, users.Create(&domain.User{
		ID: "u-1", Username: "alice", PasswordHash: "x",
		Role: domain.RoleUser, IsActive: true,
	}))

	now := time.Now().UTC()
	require.NoError(t, tokens.Create(&domain.RefreshToken{
		ID: "tok-legacy", UserID: "u-1", TokenHash: "hash-legacy", FamilyID: "fam-1",
		ClientID: "", // predates migration 009
		IssuedAt: now, LastUsedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	}))

	_, err := tokens.RotateToken("hash-legacy", &domain.RefreshToken{
		ID: "tok-adopted", UserID: "u-1", TokenHash: "hash-adopted", FamilyID: "fam-1",
		ClientID: "claude", // the presenting client claims it
		IssuedAt: now, LastUsedAt: now, ExpiresAt: now.Add(30 * 24 * time.Hour),
	})
	require.NoError(t, err)

	adopted, err := tokens.GetByHash("hash-adopted")
	require.NoError(t, err)
	assert.Equal(t, "claude", adopted.ClientID,
		"the replacement must carry the adopting client, closing the binding gap")
}
