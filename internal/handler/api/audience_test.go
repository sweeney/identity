package api_test

// audience_test.go covers WP1 (GHSA-65pj-9cmp-rvf6) at the API router: a user
// access token minted for a *different* audience — an OAuth token delegated to
// a sibling resource server — was accepted as a full identity session, so
// compromise of any downstream service escalated to identity-admin.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/api"
)

// mintForeignAudienceUserToken mints a user token carrying an audience for a
// different service, as OAuthService.ExchangeCode does with client.Audience.
func mintForeignAudienceUserToken(t *testing.T, issuer *auth.TokenIssuer, role domain.Role) string {
	t.Helper()
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID:   "u1",
		Username: "alice",
		Role:     role,
		IsActive: true,
		Audience: []string{"https://photo-api.example"},
	})
	require.NoError(t, err)
	return tok
}

// The audience check must run ahead of the role check, so every protected route
// rejects the token with invalid_audience rather than reaching the handler or
// bottoming out on a role decision.
func TestAPIRouter_UserToken_ForeignAudience_Rejected(t *testing.T) {
	issuer := newURLIssuer(t, "https://id.example.com")
	tok := mintForeignAudienceUserToken(t, issuer, domain.RoleUser)
	h := api.NewRouter(issuer, nil, nil, nil, "")

	routes := []struct{ method, path string }{
		{"GET", "/api/v1/auth/me"},
		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/users"},
		{"GET", "/api/v1/users/some-id"},
		{"PUT", "/api/v1/users/some-id"},
		{"DELETE", "/api/v1/users/some-id"},
	}
	for _, r := range routes {
		t.Run(r.method+" "+r.path, func(t *testing.T) {
			req := httptest.NewRequest(r.method, r.path, nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			assert.Equal(t, http.StatusForbidden, rr.Code,
				"user token minted for another service must not be accepted here")
			assert.Equal(t, "invalid_audience", parseErrorCode(t, rr))
		})
	}
}

// The escalation this closes: an admin's delegated token reaching /auth/me is
// the same token that reaches the user-management routes.
func TestAPIRouter_AdminToken_ForeignAudience_RejectedAtMe(t *testing.T) {
	issuer := newURLIssuer(t, "https://id.example.com")
	tok := mintForeignAudienceUserToken(t, issuer, domain.RoleAdmin)
	h := api.NewRouter(issuer, nil, nil, nil, "")

	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Equal(t, "invalid_audience", parseErrorCode(t, rr))
}
