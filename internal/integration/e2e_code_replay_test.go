//go:build integration

package integration_test

// e2e_code_replay_test.go covers what happens when an authorization code is
// presented twice, and what the audit log records about either exchange.
//
// #25: RFC 6749 §4.1.2 — "If an authorization code is used more than once, the
// authorization server MUST deny the request and SHOULD revoke (when possible)
// all tokens previously issued based on that authorization code." Identity
// denied the second request and revoked nothing, so an attacker who raced the
// legitimate client to the code kept a working 30-day refresh token.
//
// #26: neither the successful exchange nor the replay recorded an audit event,
// so the single clearest signal of a stolen code was invisible.

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
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/store"
)

// authorizeForCode runs the authorize step and returns the code and verifier.
func authorizeForCode(t *testing.T, handler http.Handler, clientID string) (code, verifier string) {
	t.Helper()
	verifier, challenge := pkceVerifierAndChallenge()
	form := url.Values{
		"client_id":      {clientID},
		"redirect_uri":   {"https://app.example.com/cb"},
		"code_challenge": {challenge},
		"username":       {"alice"},
		"password":       {"alicepassword123"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code)

	code = extractRedirectURL(t, rr.Body.String()).Query().Get("code")
	require.NotEmpty(t, code)
	return code, verifier
}

// exchangeCode posts the token request and returns the recorder for inspection.
func exchangeCode(t *testing.T, handler http.Handler, clientID, code, verifier string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/cb"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

// auditEventTypes lists recorded event types, most recent first.
func auditEventTypes(t *testing.T, database *db.Database) []string {
	t.Helper()
	events, err := store.NewAuditStore(database).List(100)
	require.NoError(t, err)
	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, e.EventType)
	}
	return types
}

// TestE2E_CodeReplayRevokesIssuedTokens is #25. The attacker's win condition is
// not getting a second token pair — the replay is correctly denied — it is that
// the first pair, which they may be the ones holding, keeps working.
func TestE2E_CodeReplayRevokesIssuedTokens(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "replay-client"
	registerMultiAudienceClient(t, database, clientID, []string{"identity.test"})

	code, verifier := authorizeForCode(t, handler, clientID)

	rr := exchangeCode(t, handler, clientID, code, verifier)
	require.Equal(t, http.StatusOK, rr.Code)
	var tok map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	refresh, _ := tok["refresh_token"].(string)
	require.NotEmpty(t, refresh)

	// Confirm the token really works before the replay, so a later failure
	// cannot be mistaken for a token that was never valid.
	rr = exchangeRefresh(t, handler, clientID, refresh)
	require.Equal(t, http.StatusOK, rr.Code, "baseline: the issued refresh token must work")
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tok))
	refresh, _ = tok["refresh_token"].(string)

	// The replay itself is denied — this part already worked.
	rr = exchangeCode(t, handler, clientID, code, verifier)
	require.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "invalid_grant")

	// The tokens that code produced must die with it.
	rr = exchangeRefresh(t, handler, clientID, refresh)
	assert.Equal(t, http.StatusBadRequest, rr.Code,
		"a replayed code must revoke the tokens it already issued (RFC 6749 §4.1.2)")
}

// exchangeRefresh posts a refresh_token grant.
func exchangeRefresh(t *testing.T, handler http.Handler, clientID, refresh string) *httptest.ResponseRecorder {
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
	return rr
}

// TestE2E_CodeExchangeIsAudited is #26. A successful exchange is the moment a
// user's session comes into existence for a client; a replay is the single
// clearest signal that a code was stolen. Both were invisible.
func TestE2E_CodeExchangeIsAudited(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "audited-client"
	registerMultiAudienceClient(t, database, clientID, []string{"identity.test"})

	code, verifier := authorizeForCode(t, handler, clientID)

	require.Equal(t, http.StatusOK, exchangeCode(t, handler, clientID, code, verifier).Code)
	assert.Contains(t, auditEventTypes(t, database), domain.EventOAuthCodeExchanged,
		"a successful code exchange must be recorded")

	require.Equal(t, http.StatusBadRequest, exchangeCode(t, handler, clientID, code, verifier).Code)
	assert.Contains(t, auditEventTypes(t, database), domain.EventOAuthCodeReplayed,
		"a replayed code is the clearest signal of theft and must be recorded")
}

// TestE2E_CodeExchangeAuditCarriesClientAndUser checks the events are useful
// rather than merely present: an audit line naming neither the client nor the
// user cannot be acted on.
func TestE2E_CodeExchangeAuditCarriesClientAndUser(t *testing.T) {
	handler, database := setupE2EServer(t)

	const clientID = "detail-client"
	registerMultiAudienceClient(t, database, clientID, []string{"identity.test"})

	code, verifier := authorizeForCode(t, handler, clientID)
	require.Equal(t, http.StatusOK, exchangeCode(t, handler, clientID, code, verifier).Code)

	events, err := store.NewAuditStore(database).List(100)
	require.NoError(t, err)

	var found *domain.AuthEvent
	for _, e := range events {
		if e.EventType == domain.EventOAuthCodeExchanged {
			found = e
			break
		}
	}
	require.NotNil(t, found, "no code-exchange event recorded")
	assert.Equal(t, clientID, found.ClientID, "the event must name the client that redeemed the code")
	assert.Equal(t, "alice", found.Username, "the event must name the user whose session was created")
	assert.NotEmpty(t, found.UserID)
}
