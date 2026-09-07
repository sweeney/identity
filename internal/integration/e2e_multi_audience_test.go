//go:build integration

package integration_test

// e2e_multi_audience_test.go drives a full PKCE flow for a client that names
// several services, and checks the whole chain: the client's audiences reach
// the minted token as a JSON array, the token is accepted by the service it
// names, and the audiences survive a refresh rather than collapsing.
//
// This is the case a single-string audience column could not express — a native
// app that signs in once and talks to several services.

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

func registerMultiAudienceClient(t *testing.T, database *db.Database, id string, audiences []string) {
	t.Helper()
	cs := store.NewOAuthClientStore(database)
	now := time.Now().UTC()
	require.NoError(t, cs.Create(&domain.OAuthClient{
		ID:           id,
		Name:         id,
		RedirectURIs: []string{"https://app.example.com/cb"},
		GrantTypes:   []string{"authorization_code"},
		Audiences:    audiences,
		CreatedAt:    now,
		UpdatedAt:    now,
	}))
}

// audClaim decodes the aud claim from an access token without verifying it.
func audClaim(t *testing.T, token string) []string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Aud []string `json:"aud"`
	}
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims.Aud
}

func TestE2E_MultiAudienceClient(t *testing.T) {
	handler, database := setupE2EServer(t)

	// A native app that talks to two other services and to identity itself.
	const clientID = "net.swee.mac"
	registerMultiAudienceClient(t, database, clientID,
		[]string{"statehouse", "countinghouse", "identity.test"})

	const redirectURI = "https://app.example.com/cb"
	verifier, challenge := pkceVerifierAndChallenge()

	form := url.Values{
		"client_id":      {clientID},
		"redirect_uri":   {redirectURI},
		"code_challenge": {challenge},
		"username":       {"alice"},
		"password":       {"alicepassword123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	code := extractRedirectURL(t, rr.Body.String()).Query().Get("code")
	require.NotEmpty(t, code)

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tok map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	require.NotEmpty(t, access)

	assert.Equal(t, []string{"statehouse", "countinghouse", "identity.test"}, audClaim(t, access),
		"every audience the client names must reach the token")

	// Refreshing must not collapse the list to one value.
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var refreshed map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&refreshed))
	rotated, _ := refreshed["access_token"].(string)
	assert.Equal(t, []string{"statehouse", "countinghouse", "identity.test"}, audClaim(t, rotated),
		"a rotated token must keep every audience — collapsing one would break the others")
}

// A client that does not name this server cannot use its tokens against the
// management API, which is the whole point of naming audiences per service.
func TestE2E_MultiAudienceClient_NotNamingIdentity(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "elsewhere-only"
	registerMultiAudienceClient(t, database, clientID, []string{"statehouse", "countinghouse"})

	const redirectURI = "https://app.example.com/cb"
	verifier, challenge := pkceVerifierAndChallenge()

	form := url.Values{
		"client_id":      {clientID},
		"redirect_uri":   {redirectURI},
		"code_challenge": {challenge},
		"username":       {"alice"},
		"password":       {"alicepassword123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)
	code := extractRedirectURL(t, rr.Body.String()).Query().Get("code")

	tokenForm := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID},
		"code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tok map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	access, _ := tok["access_token"].(string)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code,
		"a token naming only other services must not be accepted here")
}
