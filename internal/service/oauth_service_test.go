package service_test

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

// pkceChallenge computes the S256 code challenge from a verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func newOAuthService(t *testing.T, ctrl *gomock.Controller) (
	*service.OAuthService,
	*mocks.MockAuthServicer,
	*mocks.MockOAuthClientRepository,
	*mocks.MockOAuthCodeRepository,
) {
	t.Helper()
	authSvc := mocks.NewMockAuthServicer(ctrl)
	issuer := mocks.NewMockTokenIssuer(ctrl)
	issuer.EXPECT().MintServiceToken(gomock.Any(), gomock.Any()).Return("mock-token", nil).AnyTimes()
	clients := mocks.NewMockOAuthClientRepository(ctrl)
	codes := mocks.NewMockOAuthCodeRepository(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)
	audit.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	svc := service.NewOAuthService(authSvc, issuer, clients, codes, audit, 60*time.Second)
	return svc, authSvc, clients, codes
}

func testClient() *domain.OAuthClient {
	return &domain.OAuthClient{
		ID:           "client-1",
		Name:         "My App",
		RedirectURIs: []string{"https://myapp.example.com/callback"},
		GrantTypes:   []string{"authorization_code"},
	}
}

// --- ValidateAuthorizeRequest ---

func TestOAuthService_ValidateAuthorizeRequest_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _ := newOAuthService(t, ctrl)

	clients.EXPECT().GetByID("client-1").Return(testClient(), nil)

	client, err := svc.ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback")
	require.NoError(t, err)
	assert.Equal(t, "client-1", client.ID)
}

func TestOAuthService_ValidateAuthorizeRequest_UnknownClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _ := newOAuthService(t, ctrl)

	clients.EXPECT().GetByID("bad-client").Return(nil, domain.ErrNotFound)

	_, err := svc.ValidateAuthorizeRequest("bad-client", "https://myapp.example.com/callback")
	assert.ErrorIs(t, err, service.ErrUnknownClient)
}

func TestOAuthService_ValidateAuthorizeRequest_InvalidRedirectURI(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _ := newOAuthService(t, ctrl)

	clients.EXPECT().GetByID("client-1").Return(testClient(), nil)

	_, err := svc.ValidateAuthorizeRequest("client-1", "https://evil.example.com/callback")
	assert.ErrorIs(t, err, service.ErrInvalidRedirectURI)
}

// --- Authorize ---

func TestOAuthService_Authorize_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc, _, codes := newOAuthService(t, ctrl)

	authSvc.EXPECT().AuthorizeUser("alice", "password", "1.2.3.4").Return("user-123", nil)
	codes.EXPECT().Create(gomock.Any()).Return(nil)

	rawCode, err := svc.Authorize("client-1", "https://myapp.example.com/callback",
		"alice", "password", "challenge-abc", "1.2.3.4")
	require.NoError(t, err)
	assert.NotEmpty(t, rawCode)
}

func TestOAuthService_Authorize_BadCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc, _, _ := newOAuthService(t, ctrl)

	authSvc.EXPECT().AuthorizeUser("alice", "wrong", "").Return("", service.ErrInvalidCredentials)

	_, err := svc.Authorize("client-1", "https://myapp.example.com/callback",
		"alice", "wrong", "challenge-abc", "")
	assert.ErrorIs(t, err, service.ErrInvalidCredentials)
}

// --- ExchangeCode ---

func TestOAuthService_ExchangeCode_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc, _, codes := newOAuthService(t, ctrl)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)

	rawCode := "test-raw-code-value"
	codeHash := service.HashToken(rawCode)

	now := time.Now().UTC()
	authCode := &domain.AuthCode{
		ID:            "code-1",
		CodeHash:      codeHash,
		ClientID:      "client-1",
		UserID:        "user-123",
		RedirectURI:   "https://myapp.example.com/callback",
		CodeChallenge: challenge,
		IssuedAt:      now,
		ExpiresAt:     now.Add(60 * time.Second),
	}

	loginResult := &service.LoginResult{
		AccessToken:  "access.token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "refresh-token",
	}

	codes.EXPECT().GetByHash(codeHash).Return(authCode, nil)
	codes.EXPECT().MarkUsed("code-1", gomock.Any()).Return(nil)
	authSvc.EXPECT().IssueTokensForUser("user-123").Return(loginResult, nil)

	result, err := svc.ExchangeCode("client-1", rawCode, "https://myapp.example.com/callback", verifier)
	require.NoError(t, err)
	assert.Equal(t, "access.token", result.AccessToken)
}

func TestOAuthService_ExchangeCode_InvalidCode(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, codes := newOAuthService(t, ctrl)

	codes.EXPECT().GetByHash(gomock.Any()).Return(nil, domain.ErrNotFound)

	_, err := svc.ExchangeCode("client-1", "bad-code", "https://myapp.example.com/callback", "verifier")
	assert.ErrorIs(t, err, service.ErrInvalidAuthCode)
}

func TestOAuthService_ExchangeCode_ClientMismatch(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, codes := newOAuthService(t, ctrl)

	rawCode := "some-code"
	codeHash := service.HashToken(rawCode)
	now := time.Now().UTC()
	authCode := &domain.AuthCode{
		ID:            "code-2",
		CodeHash:      codeHash,
		ClientID:      "other-client",
		UserID:        "user-123",
		RedirectURI:   "https://myapp.example.com/callback",
		CodeChallenge: "challenge",
		IssuedAt:      now,
		ExpiresAt:     now.Add(60 * time.Second),
	}

	codes.EXPECT().GetByHash(codeHash).Return(authCode, nil)

	_, err := svc.ExchangeCode("client-1", rawCode, "https://myapp.example.com/callback", "verifier")
	assert.ErrorIs(t, err, service.ErrInvalidAuthCode)
}

func TestOAuthService_ExchangeCode_AlreadyUsed(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, codes := newOAuthService(t, ctrl)

	rawCode := "used-code"
	codeHash := service.HashToken(rawCode)
	now := time.Now().UTC()
	usedAt := now.Add(-10 * time.Second)
	authCode := &domain.AuthCode{
		ID:            "code-3",
		CodeHash:      codeHash,
		ClientID:      "client-1",
		UserID:        "user-123",
		RedirectURI:   "https://myapp.example.com/callback",
		CodeChallenge: "challenge",
		IssuedAt:      now.Add(-30 * time.Second),
		ExpiresAt:     now.Add(30 * time.Second),
		UsedAt:        &usedAt,
	}

	codes.EXPECT().GetByHash(codeHash).Return(authCode, nil)

	_, err := svc.ExchangeCode("client-1", rawCode, "https://myapp.example.com/callback", "verifier")
	assert.ErrorIs(t, err, service.ErrAuthCodeAlreadyUsed)
}

func TestOAuthService_ExchangeCode_Expired(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, codes := newOAuthService(t, ctrl)

	rawCode := "expired-code"
	codeHash := service.HashToken(rawCode)
	now := time.Now().UTC()
	authCode := &domain.AuthCode{
		ID:            "code-4",
		CodeHash:      codeHash,
		ClientID:      "client-1",
		UserID:        "user-123",
		RedirectURI:   "https://myapp.example.com/callback",
		CodeChallenge: "challenge",
		IssuedAt:      now.Add(-2 * time.Minute),
		ExpiresAt:     now.Add(-1 * time.Minute),
	}

	codes.EXPECT().GetByHash(codeHash).Return(authCode, nil)

	_, err := svc.ExchangeCode("client-1", rawCode, "https://myapp.example.com/callback", "verifier")
	assert.ErrorIs(t, err, service.ErrAuthCodeExpired)
}

func TestOAuthService_ExchangeCode_PKCEFailed(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, codes := newOAuthService(t, ctrl)

	verifier := "correct-verifier"
	challenge := pkceChallenge(verifier)

	rawCode := "pkce-code"
	codeHash := service.HashToken(rawCode)
	now := time.Now().UTC()
	authCode := &domain.AuthCode{
		ID:            "code-5",
		CodeHash:      codeHash,
		ClientID:      "client-1",
		UserID:        "user-123",
		RedirectURI:   "https://myapp.example.com/callback",
		CodeChallenge: challenge,
		IssuedAt:      now,
		ExpiresAt:     now.Add(60 * time.Second),
	}

	codes.EXPECT().GetByHash(codeHash).Return(authCode, nil)

	_, err := svc.ExchangeCode("client-1", rawCode, "https://myapp.example.com/callback", "wrong-verifier")
	assert.ErrorIs(t, err, service.ErrPKCEVerificationFailed)
}

// --- RefreshToken ---

func TestOAuthService_RefreshToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc, _, _ := newOAuthService(t, ctrl)

	result := &service.LoginResult{
		AccessToken:  "new.access.token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "new-refresh",
	}
	authSvc.EXPECT().Refresh("old-refresh").Return(result, nil)

	got, err := svc.RefreshToken("old-refresh")
	require.NoError(t, err)
	assert.Equal(t, "new.access.token", got.AccessToken)
}

// --- IssueClientCredentials ---

func TestIssueClientCredentials_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _ := newOAuthService(t, ctrl)

	client := &domain.OAuthClient{
		ID:         "svc-1",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"read:users", "write:users"},
		Audience:   "https://api.example.com",
	}

	result, err := svc.IssueClientCredentials(client, "read:users", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, "mock-token", result.AccessToken)
	assert.Equal(t, "read:users", result.Scope)
	assert.Equal(t, 900, result.ExpiresIn)
}

func TestIssueClientCredentials_DefaultScopes(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _ := newOAuthService(t, ctrl)

	client := &domain.OAuthClient{
		ID:         "svc-1",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"read:users", "write:users"},
		Audience:   "https://api.example.com",
	}

	result, err := svc.IssueClientCredentials(client, "", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "read:users write:users", result.Scope)
}

func TestIssueClientCredentials_WrongGrantType(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _ := newOAuthService(t, ctrl)

	client := &domain.OAuthClient{
		ID:         "svc-1",
		GrantTypes: []string{"authorization_code"},
		Scopes:     []string{"read:users"},
		Audience:   "https://api.example.com",
	}

	_, err := svc.IssueClientCredentials(client, "", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrUnauthorizedClient)
}

func TestIssueClientCredentials_InvalidScope(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _ := newOAuthService(t, ctrl)

	client := &domain.OAuthClient{
		ID:         "svc-1",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"read:users"},
		Audience:   "https://api.example.com",
	}

	_, err := svc.IssueClientCredentials(client, "write:users", "1.2.3.4")
	assert.ErrorIs(t, err, service.ErrInvalidScope)
}

func TestIssueClientCredentials_SubsetOfScopes(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, _, _ := newOAuthService(t, ctrl)

	client := &domain.OAuthClient{
		ID:         "svc-1",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"read:users", "write:users", "delete:users"},
		Audience:   "https://api.example.com",
	}

	result, err := svc.IssueClientCredentials(client, "read:users write:users", "1.2.3.4")
	require.NoError(t, err)
	assert.Equal(t, "read:users write:users", result.Scope)
}

func TestGetClient_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _ := newOAuthService(t, ctrl)

	expected := testClient()
	clients.EXPECT().GetByID("client-1").Return(expected, nil)

	got, err := svc.GetClient("client-1")
	require.NoError(t, err)
	assert.Equal(t, "client-1", got.ID)
}

func TestGetClient_NotFound(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, _, clients, _ := newOAuthService(t, ctrl)

	clients.EXPECT().GetByID("unknown").Return(nil, domain.ErrNotFound)

	_, err := svc.GetClient("unknown")
	assert.ErrorIs(t, err, service.ErrUnknownClient)
}

func TestIssueClientCredentials_AuditEvent(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	issuer := mocks.NewMockTokenIssuer(ctrl)
	issuer.EXPECT().MintServiceToken(gomock.Any(), gomock.Any()).Return("mock-token", nil)
	clients := mocks.NewMockOAuthClientRepository(ctrl)
	codes := mocks.NewMockOAuthCodeRepository(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)

	// Assert the audit event has the correct type
	audit.EXPECT().Record(gomock.Any()).DoAndReturn(func(event *domain.AuthEvent) error {
		assert.Equal(t, domain.EventClientCredentials, event.EventType)
		assert.Equal(t, "svc-1", event.ClientID)
		assert.Equal(t, "1.2.3.4", event.IPAddress)
		assert.Contains(t, event.Detail, "scope=read:users")
		return nil
	})

	svc := service.NewOAuthService(authSvc, issuer, clients, codes, audit, 60*time.Second)

	client := &domain.OAuthClient{
		ID:         "svc-1",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"read:users"},
		Audience:   "https://api.example.com",
	}

	_, err := svc.IssueClientCredentials(client, "read:users", "1.2.3.4")
	require.NoError(t, err)
}

func TestIssueClientCredentials_EmptyAudience(t *testing.T) {
	ctrl := gomock.NewController(t)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	issuer := mocks.NewMockTokenIssuer(ctrl)
	issuer.EXPECT().MintServiceToken(gomock.Any(), gomock.Any()).Return("", errors.New("audience is required for service tokens"))
	clients := mocks.NewMockOAuthClientRepository(ctrl)
	codes := mocks.NewMockOAuthCodeRepository(ctrl)
	audit := mocks.NewMockAuditRepository(ctrl)
	audit.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()

	svc := service.NewOAuthService(authSvc, issuer, clients, codes, audit, 60*time.Second)

	client := &domain.OAuthClient{
		ID:         "svc-1",
		GrantTypes: []string{"client_credentials"},
		Scopes:     []string{"read:users"},
		Audience:   "", // empty
	}

	_, err := svc.IssueClientCredentials(client, "read:users", "1.2.3.4")
	assert.Error(t, err)
}
