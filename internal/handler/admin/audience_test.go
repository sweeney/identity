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

// --- #37: the admin UI is management plane, so exclusivity applies ---

// TestPasskeyLogin_RefusesDelegatedToken tightens the WP1 rule above from
// "names this server" to "names this server and nothing else".
//
// WP1 stopped a token minted purely for a sibling service being traded for an
// admin session. It did not stop a token that names this server *and* five
// others — which is the shape production actually registers, because a client
// that calls /api/v1/auth/me legitimately needs identity in its audience list.
//
// That token is a live bearer credential at every service it names. Any one of
// them, compromised, could exchange it here for a 2-hour admin session cookie
// that outlives the token and survives refresh-family revocation. The admin UI
// is the management plane; it takes the exclusive rule.
func TestPasskeyLogin_RefusesDelegatedToken(t *testing.T) {
	const issuerName = "https://id.example.com"
	adminUser := &domain.User{
		ID: "admin-1", Username: "admin", Role: domain.RoleAdmin, IsActive: true,
	}
	handler, issuer := passkeyLoginRouter(t, issuerName, adminUser)

	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: adminUser.ID, Username: adminUser.Username,
		Role: domain.RoleAdmin, IsActive: true,
		// The live production shape: names this server, and five others.
		Audience: []string{"config", "countinghouse", "greenhouse", issuerName, "mqttauth", "statehouse"},
	})
	require.NoError(t, err)

	rr := postPasskeyLogin(t, handler, tok)
	assert.Equal(t, http.StatusForbidden, rr.Code,
		"a token delegated to sibling services must not buy an admin session")
	assert.Empty(t, rr.Result().Cookies(),
		"no session cookie may be issued on refusal")
}

// TestPasskeyLogin_AcceptsExclusiveToken keeps the boundary at exclusivity
// rather than refusing every audience-bearing token.
func TestPasskeyLogin_AcceptsExclusiveToken(t *testing.T) {
	const issuerName = "https://id.example.com"
	adminUser := &domain.User{
		ID: "admin-1", Username: "admin", Role: domain.RoleAdmin, IsActive: true,
	}
	handler, issuer := passkeyLoginRouter(t, issuerName, adminUser)

	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: adminUser.ID, Username: adminUser.Username,
		Role: domain.RoleAdmin, IsActive: true,
		Audience: []string{issuerName},
	})
	require.NoError(t, err)

	rr := postPasskeyLogin(t, handler, tok)
	assert.NotEqual(t, http.StatusForbidden, rr.Code,
		"a token naming only this server must still work: %s", rr.Body.String())
}
