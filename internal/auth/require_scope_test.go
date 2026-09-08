package auth_test

// require_scope_test.go covers RequireScope's user-token branch (#32).
//
// The middleware read sc.HasScope on the service-token branch and, for user
// tokens, treated "is an admin" as "has every scope" — uc.Scope was never
// consulted at all. That was harmless while nothing issued scoped user tokens.
// WP5 (#29) changed that: a device approved for scope=read:sensors now carries
// that claim, and a scope nothing reads is not a restriction.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

// scopeGuard mints a real token, runs it through RequireAuth and then
// RequireScope, and reports the status and whether the guarded handler ran.
// Going through the real chain rather than injecting claims into a context
// keeps the test honest about how the middleware is actually reached.
func scopeGuard(t *testing.T, required, token string) (int, bool) {
	t.Helper()
	reached := false
	inner := auth.RequireScope(required)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	inner.ServeHTTP(rr, req)
	return rr.Code, reached
}

// authedScopeGuard is scopeGuard with RequireAuth in front, which is what
// populates the claims RequireScope reads.
func authedScopeGuard(t *testing.T, issuer *auth.TokenIssuer, required, token string) (int, bool) {
	t.Helper()
	reached := false
	h := auth.RequireAuth(issuer, auth.RequireScope(required)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code, reached
}

func TestRequireScope_UserTokens(t *testing.T) {
	tests := []struct {
		name     string
		role     domain.Role
		scope    string
		required string
		want     int
	}{
		{
			// An unscoped grant is unrestricted by definition — that is what an
			// absent scope claim means, and it is what every direct API login
			// and every unscoped OAuth grant produces.
			name: "unscoped admin passes", role: domain.RoleAdmin, scope: "",
			required: "admin:users", want: http.StatusOK,
		},
		{
			name: "unscoped user passes", role: domain.RoleUser, scope: "",
			required: "read:sensors", want: http.StatusOK,
		},
		{
			name: "scoped token carrying the scope passes", role: domain.RoleUser,
			scope: "read:sensors write:sensors", required: "read:sensors", want: http.StatusOK,
		},
		{
			// The case that matters: a device approved for read:sensors must
			// not reach an endpoint requiring admin:users.
			name: "scoped token missing the scope is refused", role: domain.RoleUser,
			scope: "read:sensors", required: "admin:users", want: http.StatusForbidden,
		},
		{
			// The bug, stated directly. Being an admin is a role, not a scope.
			// A token deliberately narrowed to read:sensors must stay narrowed
			// even when the user behind it happens to be an admin — otherwise
			// the consent screen's scope means nothing for exactly the accounts
			// where it matters most.
			name: "admin holding a narrowed token is still refused", role: domain.RoleAdmin,
			scope: "read:sensors", required: "admin:users", want: http.StatusForbidden,
		},
		{
			// Prefix matching would let read:sensors satisfy read:sensors:all,
			// or admin:user satisfy admin:users.
			name: "scope match is exact, not prefix", role: domain.RoleUser,
			scope: "admin:user", required: "admin:users", want: http.StatusForbidden,
		},
	}

	issuer := newTestIssuer(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			token, err := issuer.Mint(domain.TokenClaims{
				UserID: "u1", Username: "alice", Role: tc.role, IsActive: true, Scope: tc.scope,
			})
			require.NoError(t, err)

			code, reached := authedScopeGuard(t, issuer, tc.required, token)
			assert.Equal(t, tc.want, code)
			assert.Equal(t, tc.want == http.StatusOK, reached,
				"the guarded handler must run only when the scope check passes")
		})
	}
}

func TestRequireScope_ServiceTokensUnchanged(t *testing.T) {
	issuer := newTestIssuer(t)

	tok, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Scope: "read:users", Audience: []string{"identity.home"},
	}, 5*time.Minute)
	require.NoError(t, err)

	code, _ := authedScopeGuard(t, issuer, "read:users", tok)
	assert.Equal(t, http.StatusOK, code)

	code, _ = authedScopeGuard(t, issuer, "write:users", tok)
	assert.Equal(t, http.StatusForbidden, code,
		"a service token without the scope is refused — an empty scope is not a wildcard here")
}

func TestRequireScope_NoClaimsIsUnauthorized(t *testing.T) {
	code, reached := scopeGuard(t, "read:users", "")
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.False(t, reached)
}
