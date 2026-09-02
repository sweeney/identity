package oauth_test

import (
	"encoding/json"
	"errors"
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
	return oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")
}

func newTestRouterWithAuth(svc service.OAuthServicer, authSvc service.AuthServicer) http.Handler {
	return oauth.NewRouter(svc, "", nil, authSvc, nil, nil, "", "")
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

// A client not registered for the authorization_code grant must be rejected at
// /oauth/authorize (grant-type confusion).
func TestAuthorizeGet_UnauthorizedClient(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	svc.EXPECT().ValidateAuthorizeRequest("client-1", gomock.Any()).Return(nil, service.ErrUnauthorizedClient)

	h := newTestRouter(svc)
	rr := getAuthorize(t, h, validAuthorizeParams())

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "Unauthorized Client")
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
		"client_id":      {"client-1"},
		"redirect_uri":   {"https://myapp.example.com/callback"},
		"state":          {"state-xyz"},
		"code_challenge": {"challenge-abc"},
		"username":       {"alice"},
		"password":       {"password"},
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
	svc.EXPECT().GetClient("client-1").Return(&domain.OAuthClient{ID: "client-1"}, nil)
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

	svc.EXPECT().GetClient("client-1").Return(&domain.OAuthClient{ID: "client-1"}, nil)
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
			svc.EXPECT().GetClient("client-1").Return(&domain.OAuthClient{ID: "client-1"}, nil)
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
	h := oauth.NewRouter(nil, "", nil, nil, nil, nil, "", "")
	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusNotFound, rr.Code)
}

// --- Passkey prompt ---

const oauthTestSessionKey = "test-oauth-session-key-long-enough"

// mintPromptCookie creates a signed oauth_passkey_prompt cookie for the given
// userID, carrying no validated next URL.
func mintPromptCookie(t *testing.T, userID string) *http.Cookie {
	return mintPromptCookieWithNext(t, userID, "")
}

// mintPromptCookieWithNext creates a signed oauth_passkey_prompt cookie carrying
// a server-validated next URL in the "next" claim. The cookie is HMAC-signed, so
// its next value is trusted (it was validated against the registered redirect_uri
// when the cookie was minted in the authorize flow).
func mintPromptCookieWithNext(t *testing.T, userID, next string) *http.Cookie {
	t.Helper()
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": jwt.NewNumericDate(time.Now().Add(5 * time.Minute)),
	}
	if next != "" {
		claims["next"] = next
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString([]byte(oauthTestSessionKey))
	require.NoError(t, err)
	return &http.Cookie{Name: "oauth_passkey_prompt", Value: signed}
}

// TestPasskeyPrompt_TrustedCustomSchemeNext verifies that a custom-scheme next
// URL carried in the signed prompt cookie (i.e. already validated against the
// registered redirect_uri) is rendered verbatim in the "Not now" href and not
// replaced with #ZgotmplZ by html/template's URL sanitizer.
func TestPasskeyPrompt_TrustedCustomSchemeNext(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, oauthTestSessionKey, "")

	nextURL := "com.foo.bar://callback?code=abc123"
	req := httptest.NewRequest(http.MethodGet, "/oauth/passkey-prompt", nil)
	req.AddCookie(mintPromptCookieWithNext(t, "user-1", nextURL))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, nextURL, "trusted custom-scheme next must render intact")
	assert.NotContains(t, body, "#ZgotmplZ", "html/template must not sanitize the trusted URL")
}

// TestPasskeyPrompt_QueryNextIgnored verifies that an attacker-controllable next
// query parameter is NOT trusted: it is ignored in favour of the signed cookie's
// validated next value, preventing an open redirect.
func TestPasskeyPrompt_QueryNextIgnored(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, oauthTestSessionKey, "")

	trusted := "com.foo.bar://callback?code=abc123"
	evil := "https://evil.example/login"
	req := httptest.NewRequest(http.MethodGet, "/oauth/passkey-prompt?next="+url.QueryEscape(evil), nil)
	req.AddCookie(mintPromptCookieWithNext(t, "user-1", trusted))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, trusted, "validated cookie next must render")
	assert.NotContains(t, body, "evil.example", "attacker query next must not reach the href")
}

// TestPasskeyPrompt_NoTrustedNext verifies that when the cookie carries no
// validated next, the prompt renders no "Not now" href (rather than trusting the
// query parameter or emitting an open redirect).
func TestPasskeyPrompt_NoTrustedNext(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, oauthTestSessionKey, "")

	evil := "https://evil.example/login"
	req := httptest.NewRequest(http.MethodGet, "/oauth/passkey-prompt?next="+url.QueryEscape(evil), nil)
	req.AddCookie(mintPromptCookie(t, "user-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.NotContains(t, body, "evil.example", "attacker query next must not reach the href")
	assert.NotContains(t, body, `id="skip-link"`, "no trusted next means no skip link")
}

// TestPasskeyPromptRegisterFinish_ReadsChallengeFromHeader verifies the finish
// handler accepts the challenge ID via the X-Challenge-ID header (and name via
// X-Passkey-Name) — which is how passkey-prompt.js sends them — not only as
// query params. Mirrors the admin and API finish handlers (headerOrQuery).
func TestPasskeyPromptRegisterFinish_ReadsChallengeFromHeader(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	webauthnSvc := mocks.NewMockWebAuthnServicer(ctrl)
	webauthnSvc.EXPECT().
		FinishRegistration("user-1", "ch-from-header", "MyKey", gomock.Any()).
		Return(&domain.WebAuthnCredential{ID: "cred-1"}, nil)

	h := oauth.NewRouter(svc, "", nil, nil, webauthnSvc, nil, oauthTestSessionKey, "")

	req := httptest.NewRequest(http.MethodPost, "/oauth/passkey-prompt/register/finish", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Challenge-ID", "ch-from-header")
	req.Header.Set("X-Passkey-Name", "MyKey")
	req.AddCookie(mintPromptCookie(t, "user-1"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code)
}

// TestPasskeyPrompt_NoSession_Redirects verifies that hitting the prompt page
// without a valid session cookie redirects rather than rendering.
func TestPasskeyPrompt_NoSession_Redirects(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, oauthTestSessionKey, "")

	req := httptest.NewRequest(http.MethodGet, "/oauth/passkey-prompt?next=com.foo.bar://callback", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

// --- Token endpoint: genuine server faults (issue #23, related observation) ---

// RFC 6749 §5.2 enumerates the token-endpoint error codes and pairs them with
// HTTP 400. `server_error` is not among them — it is an *authorization* endpoint
// code (§4.1.2.1). The default branch is only reached on a genuine
// infrastructure fault, which must surface as 5xx so monitoring and client
// retry logic can tell it apart from a client mistake.
func TestTokenEndpoint_ServerFaultsReturn500(t *testing.T) {
	infraErr := errors.New("get auth code: database is locked")

	t.Run("authorization_code", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc := mocks.NewMockOAuthServicer(ctrl)
		svc.EXPECT().GetClient("client-1").Return(&domain.OAuthClient{ID: "client-1"}, nil)
		svc.EXPECT().ExchangeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
			Return(nil, infraErr)

		h := newTestRouter(svc)
		rr := postForm(t, h, "/oauth/token", url.Values{
			"grant_type":    {"authorization_code"},
			"client_id":     {"client-1"},
			"code":          {"some-code"},
			"redirect_uri":  {"https://myapp.example.com/callback"},
			"code_verifier": {"verifier"},
		})

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
		assert.Equal(t, "server_error", body["error"])
		// The internal cause must never leak to the client.
		assert.NotContains(t, body["error_description"], "database is locked")
	})

	t.Run("refresh_token", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		svc := mocks.NewMockOAuthServicer(ctrl)
		svc.EXPECT().RefreshToken("some-refresh-token").Return(nil, infraErr)

		h := newTestRouter(svc)
		rr := postForm(t, h, "/oauth/token", url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {"some-refresh-token"},
		})

		assert.Equal(t, http.StatusInternalServerError, rr.Code)
		var body map[string]string
		require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
		assert.Equal(t, "server_error", body["error"])
	})
}

// Client-side mistakes must keep their RFC-mandated 400 — the 5xx change above
// must not bleed into the normal error paths.
func TestTokenEndpoint_ClientErrorsStayAt400(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	svc.EXPECT().GetClient("client-1").Return(&domain.OAuthClient{ID: "client-1"}, nil)
	svc.EXPECT().ExchangeCode(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).
		Return(nil, service.ErrAuthCodeAlreadyUsed)

	h := newTestRouter(svc)
	rr := postForm(t, h, "/oauth/token", url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"client-1"},
		"code":          {"used-code"},
		"redirect_uri":  {"https://myapp.example.com/callback"},
		"code_verifier": {"verifier"},
	})

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	var body map[string]string
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&body))
	assert.Equal(t, "invalid_grant", body["error"])
}
