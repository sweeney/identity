//go:build integration

package integration_test

// e2e_audience_rotation_test.go covers what a refresh does to the aud claim.
//
// A refresh token stores the audience set captured when the grant was created,
// and rotation used to replay it verbatim. That made the client registration
// advisory: removing an audience revoked nothing for any client that kept
// refreshing, and because rotation grants a fresh TTL with no absolute family
// lifetime, "kept refreshing" had no upper bound.
//
// Removal is the half that matters. Audience removal reads like a revocation
// mechanism, and a revocation mechanism that does not revoke is worse than
// none — the operator believes access is withdrawn when it is not. This is
// issue #39; it produced a ~12h mqttproxy outage and nearly a second one,
// because audit-audience.sh reads the registration and the registration did
// not describe the tokens actually in flight.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/store"
)

// grantViaPKCE runs a full authorize + exchange and returns the token pair.
func grantViaPKCE(t *testing.T, handler http.Handler, clientID string) (access, refresh string) {
	t.Helper()
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
	access, _ = tok["access_token"].(string)
	refresh, _ = tok["refresh_token"].(string)
	require.NotEmpty(t, access)
	require.NotEmpty(t, refresh)
	return access, refresh
}

// refreshGrant exchanges a refresh token for a new pair via /oauth/token.
func refreshGrant(t *testing.T, handler http.Handler, clientID, refresh string) (string, string) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
		"client_id":     {clientID},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "refresh failed: %s", rr.Body.String())

	var tok map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	access, _ := tok["access_token"].(string)
	next, _ := tok["refresh_token"].(string)
	require.NotEmpty(t, access)
	require.NotEmpty(t, next)
	return access, next
}

// setClientAudiences rewrites a registered client's audience list.
func setClientAudiences(t *testing.T, database *db.Database, clientID string, audiences []string) {
	t.Helper()
	cs := store.NewOAuthClientStore(database)
	client, err := cs.GetByID(clientID)
	require.NoError(t, err)
	client.Audiences = audiences
	require.NoError(t, cs.Update(client))
}

// storedAudiences reads the audience list persisted on the live refresh token.
func storedAudiences(t *testing.T, database *db.Database, clientID string) []string {
	t.Helper()
	var raw string
	err := database.DB().QueryRow(
		`SELECT audiences FROM refresh_tokens
		 WHERE is_revoked = 0 AND client_id = ?
		 ORDER BY issued_at DESC LIMIT 1`, clientID).Scan(&raw)
	require.NoError(t, err)
	var auds []string
	require.NoError(t, json.Unmarshal([]byte(raw), &auds))
	return auds
}

// TestE2E_RefreshAppliesAudienceRemoval is the core of #39: an audience taken
// off the registration must stop appearing on tokens the client refreshes into.
func TestE2E_RefreshAppliesAudienceRemoval(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "net.swee.mac"
	registerMultiAudienceClient(t, database, clientID,
		[]string{"statehouse", "countinghouse", "identity.test"})

	access, refresh := grantViaPKCE(t, handler, clientID)
	require.Equal(t, []string{"statehouse", "countinghouse", "identity.test"}, audClaim(t, access))

	// The operator withdraws this client's access to countinghouse.
	setClientAudiences(t, database, clientID, []string{"statehouse", "identity.test"})

	access, refresh = refreshGrant(t, handler, clientID, refresh)
	assert.Equal(t, []string{"statehouse", "identity.test"}, audClaim(t, access),
		"a withdrawn audience must not survive a refresh — removal is a revocation")

	// It must also not come back on the rotation after that: the refresh token
	// row itself has to stop carrying it, or the next rotation resurrects it.
	assert.Equal(t, []string{"statehouse", "identity.test"}, storedAudiences(t, database, clientID),
		"the persisted refresh token must not keep a withdrawn audience")

	access, _ = refreshGrant(t, handler, clientID, refresh)
	assert.Equal(t, []string{"statehouse", "identity.test"}, audClaim(t, access),
		"a withdrawn audience must stay withdrawn across repeated rotations")
}

// TestE2E_RefreshAppliesAudienceAddition is the other direction. Deferring an
// addition until re-login would be defensible, but it makes a newly-registered
// audience unusable without signing every user out, which is what made the
// mqttauth rollout fail: the registration said ACCEPTED while live tokens
// lacked the audience entirely.
func TestE2E_RefreshAppliesAudienceAddition(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "claude"
	registerMultiAudienceClient(t, database, clientID, []string{"identity.test"})

	_, refresh := grantViaPKCE(t, handler, clientID)

	setClientAudiences(t, database, clientID, []string{"identity.test", "mqttauth"})

	access, _ := refreshGrant(t, handler, clientID, refresh)
	assert.Equal(t, []string{"identity.test", "mqttauth"}, audClaim(t, access),
		"a newly registered audience must reach tokens without forcing a re-login")
}

// TestE2E_RefreshRepairsEmptyAudiences is the migration-011 case from #38.
// Tokens issued during that window carry audiences='[]' and were expected to
// need a manual re-login each, because the empty list propagated on every
// rotation. Re-reading the registration repairs them on the next refresh.
func TestE2E_RefreshRepairsEmptyAudiences(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "countinghouse"
	registerMultiAudienceClient(t, database, clientID, []string{"config", "identity.test"})

	_, refresh := grantViaPKCE(t, handler, clientID)

	// Simulate what migration 011 did to tokens issued during its window.
	_, err := database.DB().Exec(
		`UPDATE refresh_tokens SET audiences = '[]' WHERE is_revoked = 0 AND client_id = ?`, clientID)
	require.NoError(t, err)

	access, _ := refreshGrant(t, handler, clientID, refresh)
	assert.Equal(t, []string{"config", "identity.test"}, audClaim(t, access),
		"a session stranded with an empty audience set must repair itself on refresh")
}

// TestE2E_RefreshPreservesDirectLoginAudience guards the other side. A direct
// API login has no client, so there is no registration to re-read; those tokens
// must keep carrying exactly what they were issued with (nothing), rather than
// picking up some client's audiences or erroring.
func TestE2E_RefreshPreservesDirectLoginAudience(t *testing.T) {
	handler, _ := setupE2EServer(t)

	body := `{"username":"alice","password":"alicepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	var tok map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	access, _ := tok["access_token"].(string)
	refresh, _ := tok["refresh_token"].(string)
	require.Empty(t, audClaim(t, access), "a direct login carries no audience")

	req = httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh",
		strings.NewReader(`{"refresh_token":"`+refresh+`"}`))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, "body: %s", rr.Body.String())

	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	access, _ = tok["access_token"].(string)
	assert.Empty(t, audClaim(t, access),
		"an unbound token must not acquire an audience on rotation")
}
