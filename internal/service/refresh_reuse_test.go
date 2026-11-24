package service_test

// refresh_reuse_test.go: presenting a revoked refresh token is classified by
// why it was revoked, attributed to a caller, and throttled per family.
//
// On 2026-11-24 a client stuck with a token revoked by a password change
// produced 330 token_family_compromised events in two hours, each with
// ip="" and no client, none saying it was not theft.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

const reuseRaw = "revoked-token-value-long-enough-here-ok"

type reuseHarness struct {
	svc      *service.AuthService
	tokens   *mocks.MockTokenRepository
	recorded *[]*domain.AuthEvent
	now      *time.Time
}

func newReuseHarness(t *testing.T, reason domain.RevokeReason, familyID string) *reuseHarness {
	t.Helper()
	ctrl := gomock.NewController(t)
	users := mocks.NewMockUserRepository(ctrl)
	tokens := mocks.NewMockTokenRepository(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)

	users.EXPECT().GetByID("user-123").Return(activeUser(), nil).AnyTimes()
	tokens.EXPECT().RotateToken(gomock.Any(), gomock.Any()).DoAndReturn(
		func(hash string, _ *domain.RefreshToken) (*domain.RefreshToken, error) {
			return &domain.RefreshToken{
				ID: "tok-dead", UserID: "user-123", TokenHash: hash,
				FamilyID: familyID, ClientID: "thermostat",
				ExpiresAt: time.Now().Add(24 * time.Hour),
				IsRevoked: true, RevokedReason: reason,
			}, domain.ErrTokenAlreadyRevoked
		}).AnyTimes()
	// The family is revoked on every reuse, whatever the reason: harmless
	// when it is already dead, and the safe default when it is not.
	tokens.EXPECT().RevokeFamilyByHash(gomock.Any()).Return(nil).AnyTimes()

	var recorded []*domain.AuthEvent
	audit.EXPECT().Record(gomock.Any()).DoAndReturn(func(e *domain.AuthEvent) error {
		recorded = append(recorded, e)
		return nil
	}).AnyTimes()

	svc := service.NewAuthService(newTestIssuer(t), users, tokens, nil, mocks.NewMockBackupService(ctrl), audit, 0)
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	svc.SetClockForTest(func() time.Time { return now })
	return &reuseHarness{svc: svc, tokens: tokens, recorded: &recorded, now: &now}
}

var reuseCaller = service.RequestMeta{IP: "203.0.113.9", UserAgent: "thermo-fw/2.1"}

func TestRefreshReuse_RotatedToken_IsTheft(t *testing.T) {
	h := newReuseHarness(t, domain.RevokeReasonRotated, "fam-1")

	_, err := h.svc.Refresh(reuseRaw, reuseCaller)
	require.ErrorIs(t, err, service.ErrTokenFamilyCompromised)

	require.Len(t, *h.recorded, 1)
	e := (*h.recorded)[0]
	assert.Equal(t, domain.EventTokenFamilyCompromised, e.EventType)
	assert.Equal(t, "reason=rotated", e.Detail)
	assert.Equal(t, "203.0.113.9", e.IPAddress)
	assert.Equal(t, "thermo-fw/2.1", e.DeviceHint)
	assert.Equal(t, "thermostat", e.ClientID, "the token's own binding names the client")
	assert.Equal(t, "alice", e.Username)
}

// Tokens revoked before reasons were recorded keep the cautious treatment.
func TestRefreshReuse_UnknownReason_IsTheft(t *testing.T) {
	h := newReuseHarness(t, "", "fam-1")

	_, err := h.svc.Refresh(reuseRaw, reuseCaller)
	require.ErrorIs(t, err, service.ErrTokenFamilyCompromised)
	require.Len(t, *h.recorded, 1)
	assert.Equal(t, domain.EventTokenFamilyCompromised, (*h.recorded)[0].EventType)
	assert.Equal(t, "reason=unknown", (*h.recorded)[0].Detail)
}

func TestRefreshReuse_DeliberateRevocations_AreNotTheft(t *testing.T) {
	for _, reason := range []domain.RevokeReason{
		domain.RevokeReasonPasswordChange,
		domain.RevokeReasonLogout,
		domain.RevokeReasonLogoutAll,
		domain.RevokeReasonDeactivated,
		domain.RevokeReasonFamilyRevoked,
		domain.RevokeReasonClaimCodeRevoked,
		domain.RevokeReasonAuthCodeReplayed,
	} {
		t.Run(string(reason), func(t *testing.T) {
			h := newReuseHarness(t, reason, "fam-1")

			_, err := h.svc.Refresh(reuseRaw, reuseCaller)
			// What the client sees is unchanged: it must still clear its
			// tokens and sign in again.
			require.ErrorIs(t, err, service.ErrTokenFamilyCompromised)

			require.Len(t, *h.recorded, 1)
			e := (*h.recorded)[0]
			assert.Equal(t, domain.EventRefreshTokenRevokedReuse, e.EventType)
			assert.Equal(t, "reason="+string(reason), e.Detail)
			assert.Equal(t, "203.0.113.9", e.IPAddress)
			assert.Equal(t, "thermostat", e.ClientID)
		})
	}
}

func TestRefreshReuse_ThrottledPerFamily(t *testing.T) {
	h := newReuseHarness(t, domain.RevokeReasonPasswordChange, "fam-1")
	present := func(after time.Duration) {
		*h.now = h.now.Add(after)
		_, err := h.svc.Refresh(reuseRaw, reuseCaller)
		require.ErrorIs(t, err, service.ErrTokenFamilyCompromised)
	}

	start := *h.now
	present(0)                // recorded in full
	present(30 * time.Second) // suppressed
	present(30 * time.Second) // suppressed
	present(8 * time.Minute)  // suppressed: 9 minutes in
	require.Len(t, *h.recorded, 1, "repeats inside the window are counted, not recorded")

	present(2 * time.Minute) // 11 minutes in: one summary
	require.Len(t, *h.recorded, 2)
	sum := (*h.recorded)[1]
	assert.Equal(t, domain.EventRefreshTokenRevokedReuse, sum.EventType)
	assert.Equal(t,
		"reason=password_change repeated=3 since="+start.Add(30*time.Second).Format(time.RFC3339),
		sum.Detail)

	present(time.Minute) // a new window has started
	assert.Len(t, *h.recorded, 2)
}

func TestRefreshForClient_ReuseCarriesCaller(t *testing.T) {
	h := newReuseHarness(t, domain.RevokeReasonRotated, "fam-1")
	h.tokens.EXPECT().GetByHash(gomock.Any()).Return(&domain.RefreshToken{ClientID: "thermostat"}, nil).AnyTimes()

	_, err := h.svc.RefreshForClient(reuseRaw, "thermostat", reuseCaller)
	require.ErrorIs(t, err, service.ErrTokenFamilyCompromised)
	require.Len(t, *h.recorded, 1)
	assert.Equal(t, "203.0.113.9", (*h.recorded)[0].IPAddress)
	assert.Equal(t, "thermo-fw/2.1", (*h.recorded)[0].DeviceHint)
}

// An over-long User-Agent is cut before it reaches the audit table.
func TestRefreshReuse_UserAgentIsBounded(t *testing.T) {
	h := newReuseHarness(t, domain.RevokeReasonRotated, "fam-1")
	long := make([]byte, 1000)
	for i := range long {
		long[i] = 'a'
	}
	_, _ = h.svc.Refresh(reuseRaw, service.RequestMeta{IP: "203.0.113.9", UserAgent: string(long)})
	require.Len(t, *h.recorded, 1)
	assert.Len(t, (*h.recorded)[0].DeviceHint, 200)
}
