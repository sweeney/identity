package service_test

// refresh_audience_test.go covers resolveAudiences at the seams the end-to-end
// tests cannot reach: a client whose registration has been deleted, a client
// that names nothing, and a service wired without a client repository at all.
//
// The behaviour under test is #39 — a refresh token bound to an OAuth client
// takes its audiences from that client's live registration on every rotation,
// rather than replaying the set frozen at grant time.

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

// boundToken is a refresh token issued through an OAuth grant.
func boundToken(hash, clientID string, stored []string) *domain.RefreshToken {
	return &domain.RefreshToken{
		ID:        "tok-" + clientID,
		UserID:    "user-123",
		TokenHash: hash,
		FamilyID:  "family-" + clientID,
		ClientID:  clientID,
		Audiences: stored,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
}

func TestRefresh_ReReadsClientAudiences(t *testing.T) {
	tests := []struct {
		name     string
		stored   []string
		client   *domain.OAuthClient
		clientEr error
		want     []string
		wantRow  []string // audiences persisted on the rotated token
	}{
		{
			name:    "removal applies",
			stored:  []string{"statehouse", "countinghouse"},
			client:  &domain.OAuthClient{ID: "c", Audiences: []string{"statehouse"}},
			want:    []string{"statehouse"},
			wantRow: []string{"statehouse"},
		},
		{
			name:    "addition applies",
			stored:  []string{"identity.test"},
			client:  &domain.OAuthClient{ID: "c", Audiences: []string{"identity.test", "mqttauth"}},
			want:    []string{"identity.test", "mqttauth"},
			wantRow: []string{"identity.test", "mqttauth"},
		},
		{
			name:    "empty stored set is repaired from the registration",
			stored:  []string{},
			client:  &domain.OAuthClient{ID: "c", Audiences: []string{"config"}},
			want:    []string{"config"},
			wantRow: []string{"config"},
		},
		{
			name:   "client that names nothing yields no audience",
			stored: []string{"statehouse"},
			client: &domain.OAuthClient{ID: "c", Audiences: nil},
			// Not the stored set: a client naming nothing must not keep
			// asserting an audience it no longer registers.
			want:    nil,
			wantRow: []string{},
		},
		{
			name:     "deleted registration grants no audience",
			stored:   []string{"statehouse"},
			clientEr: domain.ErrNotFound,
			want:     nil,
			wantRow:  []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			userRepo := mocks.NewMockUserRepository(ctrl)
			tokenRepo := mocks.NewMockTokenRepository(ctrl)
			clientRepo := mocks.NewMockOAuthClientRepository(ctrl)
			backupSvc := mocks.NewMockBackupService(ctrl)
			auditRepo := mocks.NewMockAuditRepository(ctrl)
			auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

			raw := "bound-refresh-token-value-long-enough"
			hash := service.HashToken(raw)
			old := boundToken(hash, "c", tc.stored)

			// The rotated token is inspected rather than the old one: it is
			// what gets persisted and what the next rotation will read.
			var rotated *domain.RefreshToken
			tokenRepo.EXPECT().GetByHash(hash).Return(old, nil)
			tokenRepo.EXPECT().RotateToken(hash, gomock.Any()).
				DoAndReturn(func(_ string, newTok *domain.RefreshToken) (*domain.RefreshToken, error) {
					rotated = newTok
					return old, nil
				})
			clientRepo.EXPECT().GetByID("c").Return(tc.client, tc.clientEr)
			userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)

			svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo,
				clientRepo, backupSvc, auditRepo, 30*24*time.Hour)

			result, err := svc.Refresh(raw)
			require.NoError(t, err)

			assert.Equal(t, tc.want, jwtAudience(t, result.AccessToken),
				"aud on the freshly minted access token")
			require.NotNil(t, rotated)
			assert.Equal(t, tc.wantRow, rotated.Audiences,
				"audiences persisted on the rotated token — a stale row resurrects the audience on the next rotation")
		})
	}
}

// TestRefresh_UnboundTokenKeepsStoredAudiences guards the direct-login path.
// There is no registration to consult, so the stored set stands, and the
// client repository must not be consulted at all.
func TestRefresh_UnboundTokenKeepsStoredAudiences(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	clientRepo := mocks.NewMockOAuthClientRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	raw := "unbound-refresh-token-value-long-enough"
	hash := service.HashToken(raw)
	old := boundToken(hash, "", []string{"legacy-audience"})

	// Captured at call time: the mock then mutates the same struct to mirror
	// what the real store does, so reading it afterwards would prove nothing.
	var passedNil bool
	tokenRepo.EXPECT().GetByHash(hash).Return(old, nil)
	tokenRepo.EXPECT().RotateToken(hash, gomock.Any()).
		DoAndReturn(func(_ string, newTok *domain.RefreshToken) (*domain.RefreshToken, error) {
			passedNil = newTok.Audiences == nil
			// The store carries the stored set forward when the caller passes
			// nil; mirror that here so the assertion is meaningful.
			if newTok.Audiences == nil {
				newTok.Audiences = old.Audiences
			}
			return old, nil
		})
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)
	// clientRepo deliberately has no EXPECT: consulting it for an unbound
	// token would be a bug, and gomock fails the test if it is called.

	svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo,
		clientRepo, backupSvc, auditRepo, 30*24*time.Hour)

	result, err := svc.Refresh(raw)
	require.NoError(t, err)

	assert.Equal(t, []string{"legacy-audience"}, jwtAudience(t, result.AccessToken))
	assert.True(t, passedNil,
		"an unbound rotation must leave the audience list nil so the store carries the stored set forward")
}

// TestRefresh_NilClientRepoKeepsStoredAudiences covers a deployment wired
// without OAuth at all. Rotation must still work and must not lose the
// audience — that is the pre-#39 behaviour, and it is correct when there is no
// registration to consult.
func TestRefresh_NilClientRepoKeepsStoredAudiences(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)

	raw := "no-client-repo-refresh-token-long-ok"
	hash := service.HashToken(raw)
	old := boundToken(hash, "c", []string{"statehouse"})

	tokenRepo.EXPECT().RotateToken(hash, gomock.Any()).
		DoAndReturn(func(_ string, newTok *domain.RefreshToken) (*domain.RefreshToken, error) {
			require.Nil(t, newTok.Audiences,
				"with no client repository there is nothing to resolve from")
			newTok.Audiences = old.Audiences
			return old, nil
		})
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)

	svc, _ := newTestAuthService(t, ctrl, userRepo, tokenRepo, backupSvc)

	result, err := svc.Refresh(raw)
	require.NoError(t, err)
	assert.Equal(t, []string{"statehouse"}, jwtAudience(t, result.AccessToken))
}
