package service_test

// refresh_client_auth_test.go covers #40: /api/v1/auth/refresh called
// AuthService.Refresh, the unbound path, which authenticates no client at all.
//
// A refresh token bound to an OAuth client could therefore be rotated by anyone
// holding it — no client_id, no secret, no registration. /oauth/token enforces
// the binding added in WP4 (#29); this door enforced nothing.
//
// The fix is deliberately narrow (option B). For a *public* client the binding
// was never strong: /oauth/token takes a bare client_id with no secret, so an
// attacker holding a stolen token supplies the right one and the bypass costs
// them nothing they did not already have. For a *confidential* client it is
// real — /oauth/token demands the registered secret and this endpoint demanded
// nothing, making the secret optional from the attacker's side.
//
// So confidential-client tokens are refused here and told where to go. Public
// and device-grant clients are untouched, which matters because docs/api.md is
// the canonical firmware guide and points IoT devices at this exact endpoint.

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

func TestRefresh_ConfidentialClientTokenNeedsClientAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	clientRepo := mocks.NewMockOAuthClientRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	raw := "confidential-bound-refresh-token-long"
	hash := service.HashToken(raw)

	tokenRepo.EXPECT().GetByHash(hash).Return(boundToken(hash, "svc", []string{"config"}), nil)
	clientRepo.EXPECT().GetByID("svc").Return(&domain.OAuthClient{
		ID: "svc", SecretHash: "$2a$10$notarealhashbutnonempty",
	}, nil)
	// The token must not be rotated: refusing after consuming it would sign the
	// legitimate client out as a side effect of the refusal.
	tokenRepo.EXPECT().RotateToken(gomock.Any(), gomock.Any()).Times(0)

	svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo,
		clientRepo, backupSvc, auditRepo, 30*24*time.Hour)

	_, err := svc.Refresh(raw)
	assert.ErrorIs(t, err, service.ErrRefreshRequiresClientAuth,
		"a confidential client's token must not be redeemable without its secret")
}

func TestRefresh_PublicClientTokenStillAccepted(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	clientRepo := mocks.NewMockOAuthClientRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	raw := "public-bound-refresh-token-value-long"
	hash := service.HashToken(raw)
	old := boundToken(hash, "device", []string{"config"})

	// Consulted twice: once for the client-auth decision, once to resolve the
	// audience for rotation (#39).
	tokenRepo.EXPECT().GetByHash(hash).Return(old, nil).AnyTimes()
	clientRepo.EXPECT().GetByID("device").Return(&domain.OAuthClient{
		ID: "device", SecretHash: "", Audiences: []string{"config"},
	}, nil).AnyTimes()
	tokenRepo.EXPECT().RotateToken(hash, gomock.Any()).Return(old, nil)
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)

	svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo,
		clientRepo, backupSvc, auditRepo, 30*24*time.Hour)

	result, err := svc.Refresh(raw)
	require.NoError(t, err,
		"a public/device client must keep working — docs/api.md points firmware at this endpoint")
	assert.NotEmpty(t, result.AccessToken)
}

func TestRefresh_UnboundTokenUnaffectedByClientAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	clientRepo := mocks.NewMockOAuthClientRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	raw := "direct-login-refresh-token-value-long"
	hash := service.HashToken(raw)
	old := boundToken(hash, "", nil)

	tokenRepo.EXPECT().GetByHash(hash).Return(old, nil).AnyTimes()
	tokenRepo.EXPECT().RotateToken(hash, gomock.Any()).Return(old, nil)
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)
	// A direct login has no client, so the registration must never be consulted.

	svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo,
		clientRepo, backupSvc, auditRepo, 30*24*time.Hour)

	_, err := svc.Refresh(raw)
	require.NoError(t, err)
}

// TestRefresh_UnknownTokenDoesNotLeakThroughClientAuth guards the ordering. The
// client-auth check runs before rotation, so a token that does not exist must
// still come back as an ordinary invalid token rather than erroring differently
// — otherwise the check itself becomes an oracle for which hashes are real.
func TestRefresh_UnknownTokenDoesNotLeakThroughClientAuth(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	clientRepo := mocks.NewMockOAuthClientRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	raw := "no-such-refresh-token-value-long-ok"
	hash := service.HashToken(raw)

	tokenRepo.EXPECT().GetByHash(hash).Return(nil, domain.ErrNotFound).AnyTimes()
	tokenRepo.EXPECT().RotateToken(hash, gomock.Any()).Return(nil, domain.ErrNotFound)

	svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo,
		clientRepo, backupSvc, auditRepo, 30*24*time.Hour)

	_, err := svc.Refresh(raw)
	assert.ErrorIs(t, err, service.ErrInvalidRefreshToken)
}

// TestRefreshForClient_ConfidentialUnaffected: the OAuth token endpoint has
// already authenticated the client by the time it reaches here, so the new
// check must not fire on that path and break confidential clients entirely.
func TestRefreshForClient_ConfidentialUnaffected(t *testing.T) {
	ctrl := gomock.NewController(t)
	userRepo := mocks.NewMockUserRepository(ctrl)
	tokenRepo := mocks.NewMockTokenRepository(ctrl)
	clientRepo := mocks.NewMockOAuthClientRepository(ctrl)
	backupSvc := mocks.NewMockBackupService(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	raw := "confidential-via-oauth-endpoint-token"
	hash := service.HashToken(raw)
	old := boundToken(hash, "svc", []string{"config"})

	tokenRepo.EXPECT().GetByHash(hash).Return(old, nil).AnyTimes()
	clientRepo.EXPECT().GetByID("svc").Return(&domain.OAuthClient{
		ID: "svc", SecretHash: "$2a$10$notarealhashbutnonempty", Audiences: []string{"config"},
	}, nil).AnyTimes()
	tokenRepo.EXPECT().RotateToken(hash, gomock.Any()).Return(old, nil)
	userRepo.EXPECT().GetByID("user-123").Return(activeUser(), nil)

	svc := service.NewAuthService(newTestIssuer(t), userRepo, tokenRepo,
		clientRepo, backupSvc, auditRepo, 30*24*time.Hour)

	_, err := svc.RefreshForClient(raw, "svc")
	require.NoError(t, err,
		"the OAuth endpoint authenticates the client itself; this check must not fire there")
}
