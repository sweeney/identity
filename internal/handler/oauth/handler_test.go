package oauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func newTestRouter(svc service.OAuthServicer) http.Handler {
	return oauth.NewRouter(svc, "", nil, nil, nil, "", "")
}

func newTestRouterWithAuth(svc service.OAuthServicer, authSvc service.AuthServicer) http.Handler {
	return oauth.NewRouter(svc, "", nil, authSvc, nil, "", "")
}

func getAuthorize(t *testing.T, h http.Handler, params map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func postForm(t *testing.T, h http.Handler, path string, data url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func validAuthorizeParams() map[string]string {
	return map[string]string{
		"response_type":         "code",
		"client_id":             "client-1",
		"redirect_uri":          "https://myapp.example.com/callback",
		"code_challenge":        "challenge-abc",
		"code_challenge_method": "S256",
		"state":                 "state-xyz",
	}
}

// --- GET /oauth/authorize ---

func TestAuthorizeGet_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback").Return(client, nil)

	h := newTestRouter(svc)
	rr := getAuthorize(t, h, validAuthorizeParams())

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "My App")
}

func TestAuthorizeGet_UnknownClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	svc.EXPECT().ValidateAuthorizeRequest("client-1", gomock.Any()).Return(nil, service.ErrUnknownClient)

	h := newTestRouter(svc)
	rr := getAuthorize(t, h, validAuthorizeParams())

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unknown Client")
}

func TestAuthorizeGet_NonS256Method(t *testing.T) {
	h := newTestRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)))
	params := validAuthorizeParams()
	params["code_challenge_method"] = "plain"
	rr := getAuthorize(t, h, params)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestAuthorizeGet_MissingChallenge(t *testing.T) {
	h := newTestRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)))
	params := validAuthorizeParams()
	delete(params, "code_challenge")
	rr := getAuthorize(t, h, params)
	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// --- POST /oauth/authorize ---

func authorizePostMocks(ctrl *gomock.Controller) (*mocks.MockOAuthServicer, *mocks.MockAuthServicer) {
	svc := mocks.NewMockOAuthServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)
	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback").Return(client, nil)
	authSvc.EXPECT().AuthorizeUser("alice", "password", gomock.Any()).Return("user-alice", nil)
	svc.EXPECT().AuthorizeByUserID("client-1", "https://myapp.example.com/callback", "user-alice", "alice", "challenge-abc", gomock.Any()).
		Return("raw-code-xyz", nil)
	return svc, authSvc
}

func TestAuthorizePost_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc := authorizePostMocks(ctrl)

	h := newTestRouterWithAuth(svc, authSvc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":    {"client-1"},
		"redirect_uri": {"https://myapp.example.com/callback"},
		"state":        {"state-xyz"},
		"code_challenge": {"challenge-abc"},
		"username":     {"alice"},
		"password":     {"password"},
	})

	// Renders an intermediate redirect page (avoids CSP form-action blocking custom schemes)
	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "code=raw-code-xyz")
	assert.Contains(t, body, "state=state-xyz")
	assert.Contains(t, body, "Redirecting")
}

func TestAuthorizePost_StateWithSpecialChars(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc := authorizePostMocks(ctrl)

	h := newTestRouterWithAuth(svc, authSvc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"state":          {"foo&bar=baz#qux"},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
	})

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "code=raw-code-xyz")
	// State must be URL-encoded in the redirect URL
	assert.Contains(t, body, url.QueryEscape("foo&bar=baz#qux"))
}

func TestAuthorizePost_StateWithSpaces(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc := authorizePostMocks(ctrl)

	h := newTestRouterWithAuth(svc, authSvc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"state":          {"hello world"},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
	})

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "code=raw-code-xyz")
	// url.QueryEscape encodes spaces as "+", which html/template further escapes to "&#43;"
	assert.Contains(t, body, "hello")
}

func TestAuthorizePost_EmptyState(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc, authSvc := authorizePostMocks(ctrl)

	h := newTestRouterWithAuth(svc, authSvc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"state":          {""},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
	})

	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.NotContains(t, body, "&amp;state=")
	assert.Contains(t, body, "code=raw-code-xyz")
}

func TestAuthorizePost_CustomSchemeRedirect(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	authSvc := mocks.NewMockAuthServicer(ctrl)

	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "myapp://callback").Return(client, nil)
	authSvc.EXPECT().AuthorizeUser("alice", "password", gomock.Any()).Return("user-alice", nil)
	svc.EXPECT().AuthorizeByUserID("client-1", "myapp://callback", "user-alice", "alice", "challenge-abc", gomock.Any()).
		Return("raw-code-xyz", nil)

	h := newTestRouterWithAuth(svc, authSvc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"myapp://callback"},
		"state":          {"state-xyz"},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
	})

	// Must NOT be a 302 redirect — that would be blocked by CSP form-action 'self'
	// for custom URL schemes. Instead, render an intermediate page with JS redirect.
	assert.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "myapp://callback")
	assert.Contains(t, body, "code=raw-code-xyz")
	assert.Contains(t, body, "Redirecting")
	assert.NotEqual(t, http.StatusFound, rr.Code, "must not use 302 for custom scheme redirects")
}

func TestAuthorizePost_BadCredentials(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback").Return(client, nil)
	svc.EXPECT().Authorize(gomock.Any(), gomock.Any(), "alice", "wrong", gomock.Any(), gomock.Any()).
		Return("", service.ErrInvalidCredentials)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"wrong"},
	})

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "Invalid username or password")
}

// --- POST /oauth/token ---

func TestTokenEndpoint_AuthCode_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	result := &service.LoginResult{
		AccessToken:  "access.token.here",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "refresh-token",
	}
	svc.EXPECT().ExchangeCode("client-1", "code-abc", "https://myapp.example.com/callback", "verifier-xyz").
		Return(result, nil)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"client-1"},
		"code":          {"code-abc"},
		"redirect_uri":  {"https://myapp.example.com/callback"},
		"code_verifier": {"verifier-xyz"},
	})

	assert.Equal(t, http.StatusOK, rr.Code)
	var body map[string]any
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "access.token.here", body["access_token"])
	assert.Equal(t, "refresh-token", body["refresh_token"])
}

func TestTokenEndpoint_AuthCode_InvalidGrant(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	svc.EXPECT().ExchangeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, service.ErrInvalidAuthCode)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"client-1"},
		"code":          {"bad-code"},
		"redirect_uri":  {"https://myapp.example.com/callback"},
		"code_verifier": {"verifier"},
	})

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "invalid_grant", body["error"])
	assert.Equal(t, "The authorization code is invalid or has expired.", body["error_description"])
}

func TestTokenEndpoint_AuthCode_UnifiedErrorMessage(t *testing.T) {
	// All three auth code error types must return the same message to prevent
	// an attacker from distinguishing invalid, already-used, and expired codes.
	errs := []error{
		service.ErrInvalidAuthCode,
		service.ErrAuthCodeAlreadyUsed,
		service.ErrAuthCodeExpired,
	}

	for _, svcErr := range errs {
		t.Run(svcErr.Error(), func(t *testing.T) {
			ctrl := gomock.NewController(t)
			svc := mocks.NewMockOAuthServicer(ctrl)
			svc.EXPECT().ExchangeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
				Return(nil, svcErr)

			h := newTestRouter(svc)
			rr := postForm(t, h, "/oauth/token", url.Values{
				"grant_type":    {"authorization_code"},
				"client_id":     {"client-1"},
				"code":          {"some-code"},
				"redirect_uri":  {"https://myapp.example.com/callback"},
				"code_verifier": {"verifier"},
			})

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			var body map[string]string
			require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
			assert.Equal(t, "invalid_grant", body["error"])
			assert.Equal(t, "The authorization code is invalid or has expired.", body["error_description"],
				"error for %v must be identical to prevent oracle attack", svcErr)
		})
	}
}

func TestTokenEndpoint_RefreshToken_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	result := &service.LoginResult{
		AccessToken:  "new.access.token",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "new-refresh",
	}
	svc.EXPECT().RefreshToken("old-refresh").Return(result, nil)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"old-refresh"},
	})

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestTokenEndpoint_UnsupportedGrantType(t *testing.T) {
	h := newTestRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)))
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type": {"implicit"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "unsupported_grant_type", body["error"])
}

func TestNewRouter_NilService_Returns404(t *testing.T) {
	h := oauth.NewRouter(nil, "", nil, nil, nil, "", "")
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- Passkey prompt ---

const oauthTestSessionKey = "test-oauth-session-key-long-enough"

// mintPromptCookie creates a signed oauth_passkey_prompt cookie for the given userID.
func mintPromptCookie(t *testing.T, userID string) *http.Cookie {
	t.Helper()
	claims := jwt.RegisteredClaims{
		Subject:   userID,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(oauthTestSessionKey))
	require.NoError(t, err)
	return &http.Cookie{Name: "oauth_passkey_prompt", Value: signed}
}

// TestPasskeyPrompt_CustomSchemeSkipURL verifies that a custom-scheme next URL
// (e.g. com.foo.bar://callback) is rendered verbatim in the "Not now" href
// and not replaced with #ZgotmplZ by html/template's URL sanitizer.
func TestPasskeyPrompt_CustomSchemeSkipURL(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	h := oauth.NewRouter(svc, "", nil, nil, nil, oauthTestSessionKey, "")

	nextURL := "com.foo.bar://callback?code=abc123"
	req := httptest.NewRequest(http.MethodGet, "/oauth/passkey-prompt?next="+url.QueryEscape(nextURL), nil)
	req.AddCookie(mintPromptCookie(t, "user-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, nextURL, "SkipURL must render with the custom scheme intact")
	assert.NotContains(t, body, "#ZgotmplZ", "html/template must not sanitize the trusted URL")
}

// TestPasskeyPrompt_NoSession_Redirects verifies that hitting the prompt page
// without a valid session cookie redirects rather than rendering.
func TestPasskeyPrompt_NoSession_Redirects(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	h := oauth.NewRouter(svc, "", nil, nil, nil, oauthTestSessionKey, "")

	req := httptest.NewRequest(http.MethodGet, "/oauth/passkey-prompt?next=com.foo.bar://callback", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}
