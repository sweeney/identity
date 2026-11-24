//go:build integration

package store_test

// token_revoke_reason_integration_test.go: every path that revokes a refresh
// token records why, so a later presentation of that token can be told apart:
// a replay of a rotated token is a theft signal, a token killed by a password
// change is just a client that has not noticed it was signed out.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func reasonOf(t *testing.T, ts *store.TokenStore, raw string) domain.RevokeReason {
	t.Helper()
	got, err := ts.GetByHash(sha256hex(raw))
	require.NoError(t, err)
	require.True(t, got.IsRevoked, "token %q should be revoked", raw)
	return got.RevokedReason
}

func freshReplacement(raw string) *domain.RefreshToken {
	return &domain.RefreshToken{
		ID:         "tok-" + sha256hex(raw)[:8],
		TokenHash:  sha256hex(raw),
		IssuedAt:   time.Now().UTC(),
		LastUsedAt: time.Now().UTC(),
		ExpiresAt:  time.Now().UTC().Add(30 * 24 * time.Hour),
	}
}

func TestRevokeReason_LiveTokenHasNone(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-live")
	require.NoError(t, ts.Create(newToken(u.ID, "fam", "rr-live-1")))

	got, err := ts.GetByHash(sha256hex("rr-live-1"))
	require.NoError(t, err)
	assert.Equal(t, domain.RevokeReason(""), got.RevokedReason)
}

func TestRevokeReason_RotateToken_RecordsRotated(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-rotate")
	require.NoError(t, ts.Create(newToken(u.ID, "fam", "rr-rot-1")))

	_, err := ts.RotateToken(sha256hex("rr-rot-1"), freshReplacement("rr-rot-2"))
	require.NoError(t, err)
	assert.Equal(t, domain.RevokeReasonRotated, reasonOf(t, ts, "rr-rot-1"))

	// RotateToken hands the reason back on a replay, so the caller can classify it.
	old, err := ts.RotateToken(sha256hex("rr-rot-1"), freshReplacement("rr-rot-3"))
	require.ErrorIs(t, err, domain.ErrTokenAlreadyRevoked)
	assert.Equal(t, domain.RevokeReasonRotated, old.RevokedReason)
}

func TestRevokeReason_Rotate_RecordsRotated(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-rotate-id")
	old := newToken(u.ID, "fam", "rr-rid-1")
	require.NoError(t, ts.Create(old))

	repl := newToken(u.ID, "fam", "rr-rid-2")
	require.NoError(t, ts.Rotate(old.ID, repl))
	assert.Equal(t, domain.RevokeReasonRotated, reasonOf(t, ts, "rr-rid-1"))
}

func TestRevokeReason_RevokeByID_RecordsGivenReason(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-byid")
	tok := newToken(u.ID, "fam", "rr-byid-1")
	require.NoError(t, ts.Create(tok))

	require.NoError(t, ts.RevokeByID(tok.ID, domain.RevokeReasonLogout))
	assert.Equal(t, domain.RevokeReasonLogout, reasonOf(t, ts, "rr-byid-1"))
}

func TestRevokeReason_RevokeAllForUser_KeepsEarlierReasons(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-all")
	require.NoError(t, ts.Create(newToken(u.ID, "fam", "rr-all-1")))
	_, err := ts.RotateToken(sha256hex("rr-all-1"), freshReplacement("rr-all-2"))
	require.NoError(t, err)

	require.NoError(t, ts.RevokeAllForUser(u.ID, domain.RevokeReasonPasswordChange))

	assert.Equal(t, domain.RevokeReasonRotated, reasonOf(t, ts, "rr-all-1"),
		"an already-revoked token keeps the reason it was revoked for")
	assert.Equal(t, domain.RevokeReasonPasswordChange, reasonOf(t, ts, "rr-all-2"))
}

func TestRevokeReason_RevokeFamilyByHash_KeepsEarlierReasons(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-fam")
	require.NoError(t, ts.Create(newToken(u.ID, "fam-x", "rr-fam-1")))
	_, err := ts.RotateToken(sha256hex("rr-fam-1"), freshReplacement("rr-fam-2"))
	require.NoError(t, err)

	require.NoError(t, ts.RevokeFamilyByHash(sha256hex("rr-fam-1")))

	assert.Equal(t, domain.RevokeReasonRotated, reasonOf(t, ts, "rr-fam-1"))
	assert.Equal(t, domain.RevokeReasonFamilyRevoked, reasonOf(t, ts, "rr-fam-2"))
}

func TestRevokeReason_RevokeByClaimCodeID(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-claim")
	tok := newToken(u.ID, "fam", "rr-claim-1")
	tok.ClaimCodeID = "claim-code-rr"
	require.NoError(t, ts.Create(tok))

	require.NoError(t, ts.RevokeByClaimCodeID(tok.ClaimCodeID))
	assert.Equal(t, domain.RevokeReasonClaimCodeRevoked, reasonOf(t, ts, "rr-claim-1"))
}

func TestRevokeReason_RevokeByAuthCodeID(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-code")
	tok := newToken(u.ID, "fam", "rr-code-1")
	tok.AuthCodeID = "auth-code-rr"
	require.NoError(t, ts.Create(tok))

	require.NoError(t, ts.RevokeByAuthCodeID(tok.AuthCodeID))
	assert.Equal(t, domain.RevokeReasonAuthCodeReplayed, reasonOf(t, ts, "rr-code-1"))
}

// An expired token is revoked as "expired", not "rotated", and gets no
// replacement. Before, RotateToken rotated it and refresh() refused it
// afterwards, so the firmware's retry of the same token read as a replay of a
// rotated token: theft.
func TestRevokeReason_RotateToken_ExpiredIsNotRotated(t *testing.T) {
	database := openTestDB(t)
	ts := store.NewTokenStore(database)
	u := seedUser(t, store.NewUserStore(database), "rr-expired")
	tok := newToken(u.ID, "fam", "rr-exp-1")
	tok.ExpiresAt = time.Now().UTC().Add(-time.Hour)
	require.NoError(t, ts.Create(tok))

	old, err := ts.RotateToken(sha256hex("rr-exp-1"), freshReplacement("rr-exp-2"))
	require.ErrorIs(t, err, domain.ErrTokenExpired)
	require.NotNil(t, old)
	assert.Equal(t, u.ID, old.UserID)
	assert.Equal(t, domain.RevokeReasonExpired, reasonOf(t, ts, "rr-exp-1"))

	_, err = ts.GetByHash(sha256hex("rr-exp-2"))
	assert.ErrorIs(t, err, domain.ErrNotFound, "an expired token must not produce a replacement")

	// The retry is a reuse of an expired token, not of a rotated one.
	old, err = ts.RotateToken(sha256hex("rr-exp-1"), freshReplacement("rr-exp-3"))
	require.ErrorIs(t, err, domain.ErrTokenAlreadyRevoked)
	assert.Equal(t, domain.RevokeReasonExpired, old.RevokedReason)
}
