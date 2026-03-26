package api_test

// security_test.go guards against regressions for security findings fixed across
// red-team rounds. Each test is annotated with the finding ID it covers.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/api"
)

// newURLIssuer creates a TokenIssuer whose issuer string is a full URL, matching
// production configuration. The issuer doubles as the required audience for
// service tokens targeting this identity server.
func newURLIssuer(t *testing.T, issuerURL string) *auth.TokenIssuer {
	t.Helper()
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	ti, err := auth.NewTokenIssuer(key, nil, issuerURL, 15*time.Minute)
	require.NoError(t, err)
	return ti
}

func mintServiceToken(t *testing.T, issuer *auth.TokenIssuer, audience string) string {
	t.Helper()
	tok, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "some-service",
		Audience: audience,
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)
	return tok
}

func parseErrorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		return ""
	}
	return body["error"]
}

// --- Round 7 / M2: RequireAudience is wired into the API router ---
//
// Service tokens whose audience does not match the identity server's issuer must be
// rejected with 403 "invalid_audience" on every protected route. This prevents
// a token issued for service-A from being replayed against this API.

func TestAPIRouter_ServiceToken_WrongAudience_Rejected(t *testing.T) {
	issuer := newURLIssuer(t, "https://id.example.com")
	tok := mintServiceToken(t, issuer, "https://other-api.example.com") // wrong audience
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
				"service token for wrong audience must be rejected")
			assert.Equal(t, "invalid_audience", parseErrorCode(t, rr))
		})
	}
}

func TestAPIRouter_ServiceToken_CorrectAudience_PassesAudienceCheck(t *testing.T) {
	// A service token with the correct audience passes RequireAudience.
	// It is subsequently rejected by RequireAdmin (no user claims in context),
	// but the error code must NOT be "invalid_audience".
	issuer := newURLIssuer(t, "https://id.example.com")
	tok := mintServiceToken(t, issuer, "https://id.example.com") // audience matches issuer
	h := api.NewRouter(issuer, nil, nil, nil, "")

	req := httptest.NewRequest("GET", "/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.NotEqual(t, "invalid_audience", parseErrorCode(t, rr),
		"correct-audience token must not be rejected by audience check")
}

func TestAPIRouter_UserToken_PassesAudienceCheckAndAccessesMe(t *testing.T) {
	// User tokens have no audience claim and must always pass RequireAudience,
	// allowing normal authentication to proceed. The /auth/me handler reads
	// claims from context directly — no service call needed.
	issuer := newURLIssuer(t, "https://id.example.com")
	tok, err := issuer.Mint(domain.TokenClaims{
		UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true,
	})
	require.NoError(t, err)

	h := api.NewRouter(issuer, nil, nil, nil, "")
	req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code,
		"user token must pass audience check and reach the handler")
	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "alice", body["username"])
}
