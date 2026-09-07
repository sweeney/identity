package admin_test

// audience_test.go covers WP1 (GHSA-65pj-9cmp-rvf6) at the admin passkey login
// bridge. POST /admin/login/passkey is public and unauthenticated: it takes an
// access_token, checks only that the subject is an admin, and mints a 2-hour
// admin session cookie. Nothing tied the presented token to this server, so any
// holder of an admin's OAuth-delegated token — a registered client, a sibling
// resource server that received the bearer, a claim-code-paired device — could
// exchange a 15-minute audience-scoped token for a durable admin UI session.
//
// The same handler checked user.Role but never user.IsActive, so a deactivated
// admin could still open a session.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/admin"
	"github.com/sweeney/identity/internal/mocks"
)

// passkeyLoginRouter builds an admin router whose token issuer is `issuerName`
// and whose user lookup returns `user`.
func passkeyLoginRouter(t *testing.T, issuerName string, user *domain.User) (http.Handler, *auth.TokenIssuer) {
	t.Helper()
	ctrl := gomock.NewController(t)
	userSvc := mocks.NewMockUserServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	oauthClients := mocks.NewMockOAuthClientRepository(ctrl)
	auditRepo := mocks.NewMockAuditRepository(ctrl)
	auditRepo.EXPECT().Record(gomock.Any()).Return(nil).AnyTimes()
	userSvc.EXPECT().GetByID(user.ID).Return(user, nil).AnyTimes()

	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, issuerName, 15*time.Minute)
	require.NoError(t, err)

	handler := admin.NewRouter(admin.Config{SessionSecret: testSessionSecret},
		authSvc, userSvc, oauthClients, auditRepo, nil, issuer, nil, nil)
	return handler, issuer
}

func postPasskeyLogin(t *testing.T, handler http.Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"access_token": {token}}
	req := httptest.NewRequest(http.MethodPost, "/admin/login/passkey", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func assertNoAdminSession(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		assert.NotEqual(t, "admin_session", c.Name,
			"no admin session may be established for a rejected login")
	}
}

func TestAdminLoginPasskey_ForeignAudience_Rejected(t *testing.T) {
	adminUsr := &domain.User{ID: "admin-1", Username: "root", Role: domain.RoleAdmin, IsActive: true}
	handler, issuer := passkeyLoginRouter(t, "identity.home", adminUsr)

	// An admin token minted through the OAuth flow for a different service.
	token, err := issuer.Mint(domain.TokenClaims{
		UserID:   adminUsr.ID,
		Username: adminUsr.Username,
		Role:     domain.RoleAdmin,
		IsActive: true,
		Audience: []string{"https://photo-api.example"},
	})
	require.NoError(t, err)

	rr := postPasskeyLogin(t, handler, token)
	assert.Equal(t, http.StatusForbidden, rr.Code,
		"a token minted for another service must not buy an admin session")
	assertNoAdminSession(t, rr)
}

func TestAdminLoginPasskey_SelfAudience_Accepted(t *testing.T) {
	// Control: a token whose audience is this server is still accepted, as is
	// a direct-login token with no audience at all (covered by the existing
	// TestAdminLoginPasskey tests).
	adminUsr := &domain.User{ID: "admin-1", Username: "root", Role: domain.RoleAdmin, IsActive: true}
	handler, issuer := passkeyLoginRouter(t, "identity.home", adminUsr)

	token, err := issuer.Mint(domain.TokenClaims{
		UserID:   adminUsr.ID,
		Username: adminUsr.Username,
		Role:     domain.RoleAdmin,
		IsActive: true,
		Audience: []string{"identity.home"},
	})
	require.NoError(t, err)

	rr := postPasskeyLogin(t, handler, token)
	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

func TestAdminLoginPasskey_DeactivatedAdmin_Rejected(t *testing.T) {
	// The handler checks Role but never IsActive, so a disabled admin account
	// could still open a 2-hour session.
	disabled := &domain.User{ID: "admin-1", Username: "root", Role: domain.RoleAdmin, IsActive: false}
	handler, issuer := passkeyLoginRouter(t, "identity.home", disabled)

	token, err := issuer.Mint(domain.TokenClaims{
		UserID:   disabled.ID,
		Username: disabled.Username,
		Role:     domain.RoleAdmin,
		IsActive: true, // claim is stale; the live record says otherwise
	})
	require.NoError(t, err)

	rr := postPasskeyLogin(t, handler, token)
	assert.Equal(t, http.StatusForbidden, rr.Code,
		"a deactivated admin must not be issued a session")
	assertNoAdminSession(t, rr)
}
