package oauth_test

// security_test.go guards against regressions for security findings fixed in
// red-team rounds targeting the OAuth handler.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/mocks"
)

func newSecurityTestIssuer(t *testing.T, issuerURL string) *auth.TokenIssuer {
	t.Helper()
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	ti, err := auth.NewTokenIssuer(key, nil, issuerURL, 15*time.Minute)
	require.NoError(t, err)
	return ti
}

// --- Round 7 / M1: Discovery endpoint must use configured issuer, not Host header ---
//
// The /.well-known/oauth-authorization-server endpoint previously constructed the
// issuer URL from r.Host, allowing an attacker to inject an arbitrary host and
// redirect OAuth clients to a fake authorization server.

func TestDiscovery_UsesConfiguredIssuer_NotHostHeader(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")
	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")

	req := httptest.NewRequest("GET", "/.well-known/oauth-authorization-server", nil)
	req.Host = "evil.attacker.com" // must be ignored
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))

	assert.Equal(t, "https://id.example.com", body["issuer"],
		"issuer must come from TokenIssuer config, not Host header")
	assert.NotContains(t, body["issuer"], "evil.attacker.com")
	assert.NotContains(t, body["token_endpoint"], "evil.attacker.com")
	assert.NotContains(t, body["authorization_endpoint"], "evil.attacker.com")
	assert.NotContains(t, body["jwks_uri"], "evil.attacker.com")
}

// --- Round 7 / L1: authorizePasskey must reject service tokens (typ: at+jwt) ---
//
// The authorizePasskey handler calls tokenIssuer.Parse(accessToken). Parse now
// rejects tokens with typ: "at+jwt" (service tokens), preventing a machine-to-machine
// token from being used in the passkey→OAuth authorization bridge.

func TestAuthorizePasskey_ServiceToken_Rejected(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	issuer := newSecurityTestIssuer(t, "https://id.example.com")

	// Mint a service token (typ: at+jwt) — must not be accepted as a user token.
	serviceToken, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "some-service",
		Audience: "https://id.example.com",
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	h := oauth.NewRouter(svc, "", issuer, nil, nil, nil, "", "")

	form := url.Values{
		"access_token":   {serviceToken},
		"client_id":      {"testapp"},
		"redirect_uri":   {"https://app.example.com/callback"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize/passkey", nil)
	req.Host = "id.example.com" // must match Origin suffix for CheckOrigin to pass
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Origin", "https://id.example.com")
	req.Body = http.NoBody
	req.Form = form

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"service token must be rejected by authorizePasskey — not accepted as user identity")
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "invalid_token", body["error"])
}
