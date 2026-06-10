package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

func TestRequireAuth_ValidToken(t *testing.T) {
	issuer := newTestIssuer(t)

	claims := domain.TokenClaims{
		UserID:   "user-123",
		Username: "alice",
		Role:     domain.RoleUser,
		IsActive: true,
	}
	token, err := issuer.Mint(claims)
	require.NoError(t, err)

	var capturedClaims *domain.TokenClaims
	handler := auth.RequireAuth(issuer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClaims = auth.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, capturedClaims)
	assert.Equal(t, "user-123", capturedClaims.UserID)
}

func TestRequireAuth_MissingHeader(t *testing.T) {
	issuer := newTestIssuer(t)
	handler := auth.RequireAuth(issuer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestRequireAuth_InvalidToken(t *testing.T) {
	issuer := newTestIssuer(t)
	handler := auth.RequireAuth(issuer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.jwt")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestRequireAuth_ExpiredToken(t *testing.T) {
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "identity.home", time.Millisecond)
	require.NoError(t, err)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "bob", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)
	time.Sleep(5 * time.Millisecond)

	handler := auth.RequireAuth(issuer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
}

func TestRequireAuth_InactiveUser(t *testing.T) {
	issuer := newTestIssuer(t)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: false})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireAdmin_AdminUser(t *testing.T) {
	issuer := newTestIssuer(t)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "admin", Role: domain.RoleAdmin, IsActive: true})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAdmin_NonAdminUser(t *testing.T) {
	issuer := newTestIssuer(t)

	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// stubStatusProvider is a UserStatusProvider backed by an in-memory map,
// letting tests simulate the live DB state diverging from the (still-valid)
// access token claims.
type stubStatusProvider struct {
	active map[string]bool
	roles  map[string]domain.Role
	err    error
}

func (s stubStatusProvider) UserStatus(_ context.Context, userID string) (auth.UserStatus, error) {
	if s.err != nil {
		return auth.UserStatus{}, s.err
	}
	role := s.roles[userID]
	if role == "" {
		role = domain.RoleUser
	}
	return auth.UserStatus{IsActive: s.active[userID], Role: role}, nil
}

// A user disabled in the DB must be rejected even while holding a still-valid
// access token minted with act:true. This is the core of issue #11.
func TestRequireAuthWithStatus_DisabledUserRejected(t *testing.T) {
	issuer := newTestIssuer(t)

	// Token was minted while the user was active and is not expired.
	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// DB now says the user is disabled.
	provider := stubStatusProvider{
		active: map[string]bool{"u1": false},
		roles:  map[string]domain.Role{"u1": domain.RoleUser},
	}

	handler := auth.RequireAuthWithStatus(issuer, provider, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// An admin demoted to user in the DB must be rejected by RequireAdmin even
// while holding a still-valid access token minted with rol:admin.
func TestRequireAdmin_DemotedAdminRejected(t *testing.T) {
	issuer := newTestIssuer(t)

	// Token was minted while the user was an admin and is not expired.
	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "admin", Role: domain.RoleAdmin, IsActive: true})
	require.NoError(t, err)

	// DB now says the user is a plain user (active, but demoted).
	provider := stubStatusProvider{
		active: map[string]bool{"u1": true},
		roles:  map[string]domain.Role{"u1": domain.RoleUser},
	}

	handler := auth.RequireAuthWithStatus(issuer, provider, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusForbidden, rr.Code)
}

// A still-active, still-admin user passes through with the fresh status, and
// the claims injected into context reflect the live DB values.
func TestRequireAuthWithStatus_FreshClaimsInjected(t *testing.T) {
	issuer := newTestIssuer(t)

	// Token minted as a plain user...
	token, err := issuer.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// ...but DB has since promoted them to admin. RequireAdmin must honor the
	// fresh role and allow the request.
	provider := stubStatusProvider{
		active: map[string]bool{"u1": true},
		roles:  map[string]domain.Role{"u1": domain.RoleAdmin},
	}

	var captured *domain.TokenClaims
	handler := auth.RequireAuthWithStatus(issuer, provider, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = auth.ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	require.NotNil(t, captured)
	assert.Equal(t, domain.RoleAdmin, captured.Role)
}
