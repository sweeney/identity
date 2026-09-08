//go:build integration

package integration_test

// e2e_refresh_client_auth_test.go proves #40 end to end: a refresh token issued
// to a confidential OAuth client cannot be rotated at the unauthenticated
// endpoint, while public and direct-login tokens keep working there.
//
// The probe that found this returned HTTP 200 and an access token carrying the
// client's full audience set, with no client_id and no secret presented.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

// registerConfidentialClient registers a client with a real bcrypt secret hash.
func registerConfidentialClient(t *testing.T, database *db.Database, id, secret string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), 4)
	require.NoError(t, err)
	now := time.Now().UTC()
	require.NoError(t, store.NewOAuthClientStore(database).Create(&domain.OAuthClient{
		ID:           id,
		Name:         id,
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Audiences:    []string{"identity.test"},
		SecretHash:   string(hash),
		CreatedAt:    now,
		UpdatedAt:    now,
	}))
}

// apiRefresh posts to the unauthenticated refresh endpoint.
func apiRefresh(t *testing.T, handler http.Handler, refresh string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh",
		strings.NewReader(`{"refresh_token":"`+refresh+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// TestE2E_ConfidentialClientCannotRefreshUnauthenticated is the fix for #40.
func TestE2E_ConfidentialClientCannotRefreshUnauthenticated(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "confidential-svc"
	const secret = "a-registered-client-secret-value"
	registerConfidentialClient(t, database, clientID, secret)

	code, verifier := authorizeForCode(t, handler, clientID)

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"client_secret": {secret},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "setup: %s", rr.Body.String())

	var tok map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	refresh, _ := tok["refresh_token"].(string)
	require.NotEmpty(t, refresh)

	// The bypass: no client_id, no secret, no registration.
	rr = apiRefresh(t, handler, refresh)
	assert.Equal(t, http.StatusUnauthorized, rr.Code,
		"a confidential client's refresh token must not be redeemable without its secret")
	assert.Contains(t, rr.Body.String(), "client_authentication_required")

	// And the token must survive the refusal — refusing after consuming it
	// would sign the legitimate client out as a side effect.
	form = url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
		"client_secret": {secret},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code,
		"the refused token must still be redeemable through the proper endpoint: %s", rr.Body.String())
}

// TestE2E_PublicClientStillRefreshesUnauthenticated is the compatibility half.
// docs/api.md points IoT firmware at this endpoint with client-bound
// device-grant tokens; refusing those would brick devices built to our own
// documentation.
func TestE2E_PublicClientStillRefreshesUnauthenticated(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "public-device"
	registerMultiAudienceClient(t, database, clientID, []string{"identity.test"})

	_, refresh := grantViaPKCE(t, handler, clientID)

	rr := apiRefresh(t, handler, refresh)
	assert.Equal(t, http.StatusOK, rr.Code,
		"a public client's token must keep working at this endpoint: %s", rr.Body.String())
}

// TestE2E_DirectLoginStillRefreshesUnauthenticated guards the ordinary case.
func TestE2E_DirectLoginStillRefreshesUnauthenticated(t *testing.T) {
	handler, _ := setupE2EServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login",
		strings.NewReader(`{"username":"alice","password":"alicepassword123"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tok map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	refresh, _ := tok["refresh_token"].(string)

	assert.Equal(t, http.StatusOK, apiRefresh(t, handler, refresh).Code)
}
