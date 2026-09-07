package oauth_test

// redirect_test.go covers two WP13 (#27) findings.
//
// The authorization redirect was built by concatenating "?code=" onto the
// registered redirect URI. A redirect URI containing a query string is legal
// (RFC 6749 §3.1.2 requires the server to preserve it), and a great many real
// ones carry one — a tenant id, a return path. Concatenating produces
// ...?next=x?code=... which is a single malformed parameter, so the client
// never sees the code and the flow dead-ends.
//
// And discovery dereferenced tokenIssuer without the nil guard used at every
// other call site, so it panicked when passkeys were unconfigured.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/mocks"
)

func TestBuildRedirect_PreservesExistingQuery(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		wantCode    string
		wantKept    map[string]string
	}{
		{
			name:        "no existing query",
			redirectURI: "https://app.example.com/callback",
			wantCode:    "the-code",
		},
		{
			name:        "existing query is preserved",
			redirectURI: "https://app.example.com/callback?tenant=acme",
			wantCode:    "the-code",
			wantKept:    map[string]string{"tenant": "acme"},
		},
		{
			name:        "multiple existing parameters are preserved",
			redirectURI: "https://app.example.com/cb?tenant=acme&next=%2Fdash",
			wantCode:    "the-code",
			wantKept:    map[string]string{"tenant": "acme", "next": "/dash"},
		},
		{
			name:        "trailing question mark",
			redirectURI: "https://app.example.com/callback?",
			wantCode:    "the-code",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := oauth.BuildRedirectForTest(tc.redirectURI, tc.wantCode, "the-state")

			parsed, err := url.Parse(got)
			require.NoError(t, err)
			q := parsed.Query()
			assert.Equal(t, tc.wantCode, q.Get("code"),
				"the client must be able to read the code back out of %s", got)
			assert.Equal(t, "the-state", q.Get("state"))
			for k, v := range tc.wantKept {
				assert.Equal(t, v, q.Get(k),
					"the registered redirect URI's own parameters must survive")
			}
		})
	}
}

// Discovery must not panic when the token issuer is absent.
func TestDiscovery_NilTokenIssuer_DoesNotPanic(t *testing.T) {
	ctrl := gomock.NewController(t)
	svc := mocks.NewMockOAuthServicer(ctrl)

	h := newDeviceRouter(svc, nil, nil) // no token issuer wired
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rr := httptest.NewRecorder()

	require.NotPanics(t, func() { h.ServeHTTP(rr, req) },
		"discovery must guard the token issuer like every other call site does")
	assert.NotEqual(t, http.StatusOK, rr.Code,
		"with no issuer configured there is no metadata to publish")
}
