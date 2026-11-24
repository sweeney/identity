package service_test

// The code exchange and a code replay are where a client's session starts or
// is caught misbehaving; both records name the caller (IP, User-Agent), which
// they did not before: oauth_code_exchanged was logged with ip="".

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

func TestOAuthService_ExchangeCode_AuditNamesCaller(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	now := time.Now().UTC()
	fresh := &domain.AuthCode{
		ID: "code-1", CodeHash: service.HashToken("raw"), ClientID: "client-1", UserID: "user-123",
		RedirectURI: "https://myapp.example.com/callback", CodeChallenge: pkceChallenge(verifier),
		IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	used := *fresh
	usedAt := now.Add(-time.Second)
	used.UsedAt = &usedAt

	for _, tc := range []struct {
		name  string
		code  *domain.AuthCode
		event string
	}{
		{"exchange", fresh, domain.EventOAuthCodeExchanged},
		{"replay", &used, domain.EventOAuthCodeReplayed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			authSvc := mocks.NewMockAuthServicer(ctrl)
			clients := mocks.NewMockOAuthClientRepository(ctrl)
			codes := mocks.NewMockOAuthCodeRepository(ctrl)
			audit := mocks.NewMockAuditRepository(ctrl)

			var recorded []*domain.AuthEvent
			audit.EXPECT().Record(gomock.Any()).DoAndReturn(func(e *domain.AuthEvent) error {
				recorded = append(recorded, e)
				return nil
			}).AnyTimes()
			clients.EXPECT().GetByID("client-1").Return(testClient(), nil)
			codes.EXPECT().GetByHash(gomock.Any()).Return(tc.code, nil)
			codes.EXPECT().MarkUsed(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			authSvc.EXPECT().IssueTokensForGrant(gomock.Any(), gomock.Any()).Return(&service.LoginResult{}, nil).AnyTimes()
			authSvc.EXPECT().RevokeTokensForAuthCode(gomock.Any()).Return(nil).AnyTimes()
			authSvc.EXPECT().UsernameForID("user-123").Return("alice").AnyTimes()

			svc := service.NewOAuthService(authSvc, mocks.NewMockTokenIssuer(ctrl), clients, codes, audit, time.Minute)
			_, _ = svc.ExchangeCode("client-1", "raw", "https://myapp.example.com/callback", verifier,
				service.RequestMeta{IP: "198.51.100.4", UserAgent: "muse-oauth/1.0"})

			require.Len(t, recorded, 1)
			assert.Equal(t, tc.event, recorded[0].EventType)
			assert.Equal(t, "198.51.100.4", recorded[0].IPAddress)
			assert.Equal(t, "muse-oauth/1.0", recorded[0].DeviceHint)
			assert.Equal(t, "client-1", recorded[0].ClientID)
		})
	}
}
