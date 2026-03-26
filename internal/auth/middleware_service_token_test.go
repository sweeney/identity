package auth_test

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

func TestRequireAuth_ServiceToken(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "my-service",
		Audience: "https://api.example.com",
		Scope:    "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should have service claims, not user claims
		sc := auth.ServiceClaimsFromContext(r.Context())
		assert.NotNil(t, sc)
		assert.Equal(t, "my-service", sc.ClientID)
		assert.Equal(t, "read:users", sc.Scope)

		uc := auth.ClaimsFromContext(r.Context())
		assert.Nil(t, uc)

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAuth_UserToken(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.Mint(domain.TokenClaims{
		UserID: "user-1", Username: "alice", Role: domain.RoleUser, IsActive: true,
	})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uc := auth.ClaimsFromContext(r.Context())
		assert.NotNil(t, uc)
		assert.Equal(t, "alice", uc.Username)

		sc := auth.ServiceClaimsFromContext(r.Context())
		assert.Nil(t, sc)

		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireScope_ServiceToken_HasScope(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Audience: "https://api", Scope: "read:users write:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireScope("read:users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireScope_ServiceToken_MissingScope(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Audience: "https://api", Scope: "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireScope("write:users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireScope_AdminUser_PassesAll(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.Mint(domain.TokenClaims{
		UserID: "user-1", Username: "admin", Role: domain.RoleAdmin, IsActive: true,
	})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireScope("any:scope")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireScope_RegularUser_Forbidden(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.Mint(domain.TokenClaims{
		UserID: "user-1", Username: "alice", Role: domain.RoleUser, IsActive: true,
	})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireScope("read:users")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireAdmin_StillWorks(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.Mint(domain.TokenClaims{
		UserID: "user-1", Username: "admin", Role: domain.RoleAdmin, IsActive: true,
	})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAudience_MatchingAudience(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Audience: "https://api.example.com", Scope: "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireAudience("https://api.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAudience_WrongAudience(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Audience: "https://api.example.com", Scope: "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireAudience("https://other.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}

func TestRequireAudience_UserTokenPassesThrough(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.Mint(domain.TokenClaims{
		UserID: "user-1", Username: "alice", Role: domain.RoleUser, IsActive: true,
	})
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireAudience("https://api.example.com")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestRequireAdmin_ServiceToken_Forbidden(t *testing.T) {
	issuer := newTestIssuer(t)
	token, err := issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Audience: "https://api.example.com", Scope: "read:users",
	}, 15*time.Minute)
	require.NoError(t, err)

	handler := auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
}
