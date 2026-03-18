package oauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/mocks"
	"github.com/sweeney/identity/internal/service"
)

func newTestRouter(svc service.OAuthServicer) http.Handler {
	return oauth.NewRouter(svc, "")
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

func TestAuthorizePost_Success(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback").Return(client, nil)
	svc.EXPECT().Authorize("client-1", "https://myapp.example.com/callback", "alice", "password", "challenge-abc", gomock.Any()).
		Return("raw-code-xyz", nil)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":    {"client-1"},
		"redirect_uri": {"https://myapp.example.com/callback"},
		"state":        {"state-xyz"},
		"code_challenge": {"challenge-abc"},
		"username":     {"alice"},
		"password":     {"password"},
	})

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.Contains(t, loc, "code=raw-code-xyz")
	assert.Contains(t, loc, "state=state-xyz")
}

func TestAuthorizePost_StateWithSpecialChars(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback").Return(client, nil)
	svc.EXPECT().Authorize("client-1", "https://myapp.example.com/callback", "alice", "password", "challenge-abc", gomock.Any()).
		Return("raw-code-xyz", nil)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"state":          {"foo&bar=baz#qux"},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
	})

	assert.Equal(t, http.StatusFound, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "raw-code-xyz", loc.Query().Get("code"))
	assert.Equal(t, "foo&bar=baz#qux", loc.Query().Get("state"))
}

func TestAuthorizePost_StateWithSpaces(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback").Return(client, nil)
	svc.EXPECT().Authorize("client-1", "https://myapp.example.com/callback", "alice", "password", "challenge-abc", gomock.Any()).
		Return("raw-code-xyz", nil)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"state":          {"hello world"},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
	})

	assert.Equal(t, http.StatusFound, rr.Code)
	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "raw-code-xyz", loc.Query().Get("code"))
	assert.Equal(t, "hello world", loc.Query().Get("state"))
}

func TestAuthorizePost_EmptyState(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	client := &domain.OAuthClient{ID: "client-1", Name: "My App"}
	svc.EXPECT().ValidateAuthorizeRequest("client-1", "https://myapp.example.com/callback").Return(client, nil)
	svc.EXPECT().Authorize("client-1", "https://myapp.example.com/callback", "alice", "password", "challenge-abc", gomock.Any()).
		Return("raw-code-xyz", nil)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/authorize", url.Values{
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"state":          {""},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
	})

	assert.Equal(t, http.StatusFound, rr.Code)
	loc := rr.Header().Get("Location")
	assert.NotContains(t, loc, "&state=")
	assert.NotContains(t, loc, "?state=")
	// Verify code is still present
	parsed, err := url.Parse(loc)
	require.NoError(t, err)
	assert.Equal(t, "raw-code-xyz", parsed.Query().Get("code"))
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
		"grant_type": {"client_credentials"},
	})
	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "unsupported_grant_type", body["error"])
}

func TestNewRouter_NilService_Returns404(t *testing.T) {
	h := oauth.NewRouter(nil, "")
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}
