//go:build integration

package integration_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/db"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/admin"
	apihandler "github.com/sweeney/identity/internal/handler/api"
	oauthhandler "github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/store"
)

const (
	e2eJWTSecret  = "e2e-test-secret-key-that-is-long-enough"
	e2eAdminUser  = "admin"
	e2eAdminPass  = "adminpassword123"
	e2eJWTIssuer  = "identity.test"
)

func setupE2EServer(t *testing.T) (http.Handler, *db.Database) {
	t.Helper()
	database, err := db.Open(filepath.Join(t.TempDir(), "e2e.db"))
	require.NoError(t, err)
	t.Cleanup(func() { database.Close() })

	userStore := store.NewUserStore(database)
	tokenStore := store.NewTokenStore(database)
	oauthClientStore := store.NewOAuthClientStore(database)
	oauthCodeStore := store.NewOAuthCodeStore(database)
	auditStore := store.NewAuditStore(database)

	jwtKey, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(jwtKey, nil, e2eJWTIssuer, 15*time.Minute)
	require.NoError(t, err)

	backupMgr := &noopBackup{}
	authSvc := service.NewAuthService(issuer, userStore, tokenStore, backupMgr, auditStore, 30*24*time.Hour)
	userSvc := service.NewUserService(userStore, tokenStore, backupMgr, auditStore, 4)
	oauthSvc := service.NewOAuthService(authSvc, issuer, oauthClientStore, oauthCodeStore, auditStore, 60*time.Second)

	// Create admin user
	_, err = userSvc.Create(e2eAdminUser, "Admin", "adminpassword123", domain.RoleAdmin)
	require.NoError(t, err)

	// Create a regular user
	_, err = userSvc.Create("alice", "Alice", "alicepassword123", domain.RoleUser)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.Handle("/api/v1/", apihandler.NewRouter(issuer, authSvc, userSvc, nil, ""))
	mux.Handle("/oauth/", oauthhandler.NewRouter(oauthSvc, "", issuer, authSvc, nil, e2eJWTSecret, "Test"))
	mux.Handle("/admin/", admin.NewRouter(admin.Config{
		SessionSecret: e2eJWTSecret,
	}, authSvc, userSvc, oauthClientStore, auditStore, backupMgr, issuer, nil))

	return mux, database
}

// noopBackup satisfies domain.BackupService without doing anything.
type noopBackup struct{}

func (n *noopBackup) TriggerAsync()  {}
func (n *noopBackup) RunNow() error  { return nil }

// extractRedirectURL parses the redirect URL from the intermediate redirect page HTML.
// The page contains: <a id="redirect-link" href="...">
var redirectLinkRe = regexp.MustCompile(`id="redirect-link" href="([^"]+)"`)

func extractRedirectURL(t *testing.T, body string) *url.URL {
	t.Helper()
	matches := redirectLinkRe.FindStringSubmatch(body)
	require.True(t, len(matches) >= 2, "redirect link not found in body")
	// HTML-unescape &amp; → &
	raw := strings.ReplaceAll(matches[1], "&amp;", "&")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	return u
}

func pkceVerifierAndChallenge() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func registerOAuthClient(t *testing.T, database *db.Database, id, name string, redirectURIs []string) {
	t.Helper()
	cs := store.NewOAuthClientStore(database)
	now := time.Now().UTC()
	err := cs.Create(&domain.OAuthClient{
		ID:           id,
		Name:         name,
		RedirectURIs: redirectURIs,
		CreatedAt:    now,
		UpdatedAt:    now,
	})
	require.NoError(t, err)
}

// TestE2E_OAuthFlow tests the full authorization code flow with PKCE.
func TestE2E_OAuthFlow(t *testing.T) {
	handler, database := setupE2EServer(t)

	// Register an OAuth client directly in the DB
	registerOAuthClient(t, database, "myapp", "My App", []string{"https://myapp.example.com/callback"})

	verifier, challenge := pkceVerifierAndChallenge()
	state := "test-state-123"
	clientID := "myapp"
	redirectURI := "https://myapp.example.com/callback"

	// Step 1: GET /oauth/authorize — should render login form
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"state":                 {state},
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "My App")

	// Step 2: POST /oauth/authorize — submit credentials
	form := url.Values{
		"client_id":      {clientID},
		"redirect_uri":   {redirectURI},
		"state":          {state},
		"code_challenge": {challenge},
		"username":       {"alice"},
		"password":       {"alicepassword123"},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	// Renders intermediate redirect page (not a 302) to avoid CSP form-action issues
	assert.Equal(t, http.StatusOK, rr.Code)

	locURL := extractRedirectURL(t, rr.Body.String())
	assert.NotEmpty(t, locURL.Query().Get("code"))
	assert.Equal(t, state, locURL.Query().Get("state"))

	code := locURL.Query().Get("code")
	require.NotEmpty(t, code)

	// Step 3: POST /oauth/token — exchange code for tokens
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
	assert.Equal(t, http.StatusOK, rr.Code)

	var tokenResp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tokenResp))
	assert.NotEmpty(t, tokenResp["access_token"])
	assert.NotEmpty(t, tokenResp["refresh_token"])
	assert.Equal(t, "Bearer", tokenResp["token_type"])

	// Step 4: Verify access token works at /api/v1/auth/me
	accessToken, _ := tokenResp["access_token"].(string)
	req = httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var meResp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&meResp))
	assert.Equal(t, "alice", meResp["username"])

	// Step 5: Refresh using /oauth/token with refresh_token grant
	refreshToken, _ := tokenResp["refresh_token"].(string)
	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	req = httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(refreshForm.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)

	var refreshResp map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&refreshResp))
	assert.NotEmpty(t, refreshResp["access_token"])
	assert.NotEmpty(t, refreshResp["refresh_token"])
}

// TestE2E_OAuthFlow_CodeReplay tests that replaying a code returns an error.
func TestE2E_OAuthFlow_CodeReplay(t *testing.T) {
	handler, database := setupE2EServer(t)
	registerOAuthClient(t, database, "app2", "App 2", []string{"https://app2.example.com/callback"})

	verifier, challenge := pkceVerifierAndChallenge()
	clientID := "app2"
	redirectURI := "https://app2.example.com/callback"

	// Authorize and get code
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

	locURL := extractRedirectURL(t, rr.Body.String())
	code := locURL.Query().Get("code")

	exchangeCode := func() int {
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
		return rr.Code
	}

	// First exchange should succeed
	assert.Equal(t, http.StatusOK, exchangeCode())
	// Second exchange (replay) should fail
	assert.Equal(t, http.StatusBadRequest, exchangeCode())
}

// TestE2E_AuditLog tests that auth events are recorded.
func TestE2E_AuditLog(t *testing.T) {
	_, database := setupE2EServer(t)

	auditStore := store.NewAuditStore(database)

	// Record a test event directly
	err := auditStore.Record(&domain.AuthEvent{
		ID:         "test-evt-1",
		EventType:  domain.EventLoginSuccess,
		UserID:     "user-alice",
		Username:   "alice",
		OccurredAt: time.Now().UTC(),
	})
	require.NoError(t, err)

	events, err := auditStore.List(10)
	require.NoError(t, err)
	// setupE2EServer creates 2 users (user_created events) + our manual event = 3+
	require.GreaterOrEqual(t, len(events), 3)
	// Most recent event should be our manually recorded one
	assert.Equal(t, domain.EventLoginSuccess, events[0].EventType)
	assert.Equal(t, "alice", events[0].Username)

	// Verify user_created events are present
	var userCreatedCount int
	for _, e := range events {
		if e.EventType == domain.EventUserCreated {
			userCreatedCount++
		}
	}
	assert.Equal(t, 2, userCreatedCount, "should have 2 user_created events from setup")

	_ = fmt.Sprintf // avoid unused import
}
