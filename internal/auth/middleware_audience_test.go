package auth_test

// middleware_audience_test.go covers WP1 (GHSA-65pj-9cmp-rvf6): the `aud` claim
// on *user* access tokens was enforced nowhere in the system. RequireAudience
// validated service tokens only and passed every user token straight through,
// on the false premise that user tokens carry no audience. They do: tokens
// minted through the OAuth/PKCE and device grants carry the client's audience
// (oauth_service.go IssueTokensForUser(code.UserID, client.Audience)).
//
// The direct-login case — a token with no aud at all — must keep passing; that
// is covered by TestRequireAudience_UserTokenPassesThrough in
// middleware_service_token_test.go.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

// audienceErrorCode decodes the error envelope written by the middleware.
func audienceErrorCode(t *testing.T, rr *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		return ""
	}
	return body["error"]
}

// serveWithAudience runs token through RequireAuth + RequireAudience(required).
func serveWithAudience(t *testing.T, issuer *auth.TokenIssuer, required, token string) *httptest.ResponseRecorder {
	t.Helper()
	handler := auth.RequireAuth(issuer, auth.RequireAudience(required)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr
}

func TestRequireAudience_UserToken(t *testing.T) {
	// newTestIssuer issues with issuer string "identity.home"; that doubles as
	// this server's own audience.
	const selfAudience = "identity.home"

	tests := []struct {
		name       string
		audience   []string
		wantStatus int
		wantError  string
	}{
		{
			// The core defect: an OAuth client registered with
			// audience=https://photo-api.example completes PKCE for an admin
			// user. That token says, in its own aud claim, that it is for
			// photo-api — but it was accepted verbatim against this API,
			// so compromise of any downstream resource server escalated to
			// identity-admin takeover.
			name:       "foreign audience is rejected",
			audience:   []string{"https://photo-api.example"},
			wantStatus: http.StatusForbidden,
			wantError:  "invalid_audience",
		},
		{
			name:       "audience matching this server is allowed",
			audience:   []string{selfAudience},
			wantStatus: http.StatusOK,
		},
		{
			// A single aud value that happens to contain a space must not be
			// split into two audiences. Joining on " " and re-splitting made
			// the round trip lossy: one value satisfied two different servers.
			name:       "space-containing audience value is not split",
			audience:   []string{selfAudience + " https://other.example"},
			wantStatus: http.StatusForbidden,
			wantError:  "invalid_audience",
		},
		{
			// The converse: a genuine multi-valued aud must be honoured on
			// every value it names, not collapsed into one opaque string.
			name:       "multi-valued audience matches on any member",
			audience:   []string{"https://other.example", selfAudience},
			wantStatus: http.StatusOK,
		},
		{
			name:       "multi-valued audience naming only other services is rejected",
			audience:   []string{"https://other.example", "https://third.example"},
			wantStatus: http.StatusForbidden,
			wantError:  "invalid_audience",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newTestIssuer(t)
			token, err := issuer.Mint(domain.TokenClaims{
				UserID:   "u1",
				Username: "alice",
				Role:     domain.RoleAdmin,
				IsActive: true,
				Audience: tc.audience,
			})
			require.NoError(t, err)

			rr := serveWithAudience(t, issuer, selfAudience, token)
			assert.Equal(t, tc.wantStatus, rr.Code)
			if tc.wantError != "" {
				assert.Equal(t, tc.wantError, audienceErrorCode(t, rr))
			}
		})
	}
}
