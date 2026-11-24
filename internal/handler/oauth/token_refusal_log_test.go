package oauth_test

// token_refusal_log_test.go: every refusal at /oauth/token leaves one journal
// line saying which grant, which client, how it authenticated and which
// required fields were present — and never a secret, code, verifier or token.
//
// On 2026-11-24 a client got a 400 here and nothing at all was logged, so the
// question "which field was missing?" could not be answered from the server.

import (
	"bytes"
	"encoding/base64"
	"log"
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

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	origOut, origFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(origOut); log.SetFlags(origFlags) })
	return &buf
}

func tokenPost(h http.Handler, form url.Values, basic, ua string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if basic != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(basic)))
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	req.RemoteAddr = "198.51.100.4:5555"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func refusalLines(buf *bytes.Buffer) []string {
	var out []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.HasPrefix(l, "oauth: token refused") {
			out = append(out, l)
		}
	}
	return out
}

func TestTokenRefusalLog_MissingFieldIsNamed(t *testing.T) {
	buf := captureLog(t)
	h := oauth.NewRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)), "", nil, nil, nil, nil, "", "")

	rr := tokenPost(h, url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {"muse"},
		"code":         {"c"},
		"redirect_uri": {"https://agent.example/cb"},
	}, "", "muse-oauth/1.0")
	require.Equal(t, http.StatusBadRequest, rr.Code)

	lines := refusalLines(buf)
	require.Len(t, lines, 1)
	assert.Equal(t,
		`oauth: token refused status=400 error="invalid_request" grant_type="authorization_code" client="muse" client_via=body auth=none `+
			`fields=client_id:+,code:+,redirect_uri:+,code_verifier:- ip="198.51.100.4" ua="muse-oauth/1.0"`,
		lines[0])
}

// The exact case from 2026-11-24 would now read client_via=basic.
func TestTokenRefusalLog_BasicOnlyClientIsAttributed(t *testing.T) {
	buf := captureLog(t)
	h := oauth.NewRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)), "", nil, nil, nil, nil, "", "")

	tokenPost(h, url.Values{"grant_type": {"authorization_code"}, "code": {"c"}}, "muse:s", "")

	lines := refusalLines(buf)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], `client="muse" client_via=basic auth=client_secret_basic`)
	assert.Contains(t, lines[0], `fields=client_id:-,code:+,redirect_uri:-,code_verifier:-`)
}

func TestTokenRefusalLog_NeverContainsSecrets(t *testing.T) {
	buf := captureLog(t)
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	svc.EXPECT().GetClient(gomock.Any()).Return(&domain.OAuthClient{
		ID: "conf", SecretHash: mustHash("right"), GrantTypes: []string{"authorization_code", "refresh_token"},
	}, nil).AnyTimes()
	h := oauth.NewRouter(svc, "", nil, nil, nil, nil, "", "")

	tokenPost(h, url.Values{
		"grant_type": {"authorization_code"}, "client_id": {"conf"},
		"code": {"CODE-MARKER"}, "redirect_uri": {"https://x/cb"}, "code_verifier": {"VERIFIER-MARKER"},
	}, "conf:BASIC-SECRET-MARKER", "")
	tokenPost(h, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"conf"},
		"refresh_token": {"REFRESH-MARKER"}, "client_secret": {"POST-SECRET-MARKER"},
	}, "", "")

	lines := refusalLines(buf)
	require.Len(t, lines, 2)
	assert.Contains(t, lines[0], `status=401 error="invalid_client"`)
	assert.Contains(t, lines[1], `auth=client_secret_post`)
	assert.Contains(t, lines[1], `fields=client_id:+,refresh_token:+`)
	for _, marker := range []string{"CODE-MARKER", "VERIFIER-MARKER", "BASIC-SECRET-MARKER", "REFRESH-MARKER", "POST-SECRET-MARKER"} {
		assert.NotContains(t, buf.String(), marker)
	}
}

func TestTokenRefusalLog_MalformedBasicIsReported(t *testing.T) {
	buf := captureLog(t)
	h := oauth.NewRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)), "", nil, nil, nil, nil, "", "")

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader(url.Values{"grant_type": {"client_credentials"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic not-base64!!")
	h.ServeHTTP(httptest.NewRecorder(), req)

	lines := refusalLines(buf)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], `client="" client_via=none auth=basic_malformed`)
}

func TestTokenRefusalLog_UnknownGrantType(t *testing.T) {
	buf := captureLog(t)
	h := oauth.NewRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)), "", nil, nil, nil, nil, "", "")

	tokenPost(h, url.Values{"grant_type": {"password"}}, "", "")
	lines := refusalLines(buf)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], `error="unsupported_grant_type" grant_type="password"`)
	assert.Contains(t, lines[0], `fields= `)
}

// Caller-controlled values cannot forge extra log lines.
func TestTokenRefusalLog_EscapesCallerValues(t *testing.T) {
	buf := captureLog(t)
	h := oauth.NewRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)), "", nil, nil, nil, nil, "", "")

	tokenPost(h, url.Values{"grant_type": {"x\noauth: token refused status=200"}, "client_id": {"a\nb"}},
		"", "ua\nforged")
	assert.Len(t, refusalLines(buf), 1)
}

// Successful requests and routine device polling are not refusals worth a line.
func TestTokenRefusalLog_QuietOnSuccessAndPolling(t *testing.T) {
	buf := captureLog(t)
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)
	deviceSvc := mocks.NewMockDeviceFlowServicer(ctrl)
	svc.EXPECT().RefreshTokenForClient("good", "app", gomock.Any()).
		Return(&service.LoginResult{AccessToken: "a", RefreshToken: "r", TokenType: "Bearer", ExpiresIn: 900}, nil)
	deviceSvc.EXPECT().PollForToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, service.ErrDeviceAuthorizationPending)
	deviceSvc.EXPECT().PollForToken(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, service.ErrDeviceSlowDown)
	h := newDeviceRouter(svc, deviceSvc, nil)

	require.Equal(t, http.StatusOK, tokenPost(h, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"app"}, "refresh_token": {"good"},
	}, "", "").Code)
	for i := 0; i < 2; i++ {
		require.Equal(t, http.StatusBadRequest, tokenPost(h, url.Values{
			"grant_type": {service.GrantTypeDeviceCode}, "client_id": {"dev"}, "device_code": {"d"},
		}, "", "").Code)
	}
	assert.Empty(t, refusalLines(buf))
}

// The handlers read parameters with FormValue (body and query), so the log
// must report what they saw, not only what arrived in the body.
func TestTokenRefusalLog_ReadsQueryParametersLikeTheHandler(t *testing.T) {
	buf := captureLog(t)
	h := oauth.NewRouter(mocks.NewMockOAuthServicer(gomock.NewController(t)), "", nil, nil, nil, nil, "", "")

	q := url.Values{"grant_type": {"authorization_code"}, "client_id": {"q-client"}, "code": {"c"}}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token?"+q.Encode(), strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.ServeHTTP(httptest.NewRecorder(), req)

	lines := refusalLines(buf)
	require.Len(t, lines, 1)
	assert.Contains(t, lines[0], `grant_type="authorization_code" client="q-client" client_via=body`)
	assert.Contains(t, lines[0], `fields=client_id:+,code:+,redirect_uri:-,code_verifier:-`)
}
