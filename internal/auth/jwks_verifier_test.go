package auth_test

import (
	"sync"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

// newJWKSServer builds a test HTTP server that serves the JWKS of the given
// issuer at /.well-known/jwks.json. The returned counter is incremented on
// every JWKS fetch so tests can assert cache/refetch behaviour.
func newJWKSServer(t *testing.T, issuer *auth.TokenIssuer) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var fetches atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(issuer.JWKS())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &fetches
}

func mustIssuer(t *testing.T, issuerName string, ttl time.Duration) *auth.TokenIssuer {
	t.Helper()
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	ti, err := auth.NewTokenIssuer(key, nil, issuerName, ttl)
	require.NoError(t, err)
	return ti
}

func TestJWKSVerifier_Parse_ValidUserToken(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, _ := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
	})
	require.NoError(t, err)

	tok, err := ti.Mint(domain.TokenClaims{
		UserID:   "user-1",
		Username: "alice",
		Role:     domain.RoleAdmin,
		IsActive: true,
	})
	require.NoError(t, err)

	claims, err := v.Parse(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "user-1", claims.UserID)
	assert.Equal(t, "alice", claims.Username)
	assert.Equal(t, domain.RoleAdmin, claims.Role)
	assert.True(t, claims.IsActive)
}

func TestJWKSVerifier_Parse_WrongIssuer_Rejected(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, _ := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://other.example.com", // deliberately mismatched
	})
	require.NoError(t, err)

	tok, err := ti.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), tok)
	assert.Error(t, err)
}

func TestJWKSVerifier_Parse_Expired_ReturnsTokenExpired(t *testing.T) {
	// TTL of 0 is rejected upstream, so use a tiny negative via reflection-
	// free path: mint with 1ns TTL, wait.
	ti := mustIssuer(t, "https://id.example.com", time.Nanosecond)
	srv, _ := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
	})
	require.NoError(t, err)

	tok, err := ti.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)
	time.Sleep(10 * time.Millisecond)

	_, err = v.Parse(context.Background(), tok)
	assert.ErrorIs(t, err, auth.ErrTokenExpired)
}

func TestJWKSVerifier_Parse_Malformed_ReturnsTokenInvalid(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, _ := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
	})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), "not-a-jwt")
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestJWKSVerifier_Parse_EmptyToken_ReturnsTokenInvalid(t *testing.T) {
	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: "http://localhost",
		Issuer:    "http://localhost",
	})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), "")
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

func TestJWKSVerifier_CachesJWKS(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, fetches := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
		CacheTTL:  5 * time.Minute,
	})
	require.NoError(t, err)

	tok, err := ti.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	for i := 0; i < 5; i++ {
		_, err := v.Parse(context.Background(), tok)
		require.NoError(t, err)
	}

	assert.Equal(t, int32(1), fetches.Load(),
		"JWKS should be fetched once and cached for subsequent Parse calls")
}

func TestJWKSVerifier_RefetchesAfterTTL(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, fetches := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
		CacheTTL:  50 * time.Millisecond,
	})
	require.NoError(t, err)

	tok, err := ti.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, int32(1), fetches.Load())

	time.Sleep(80 * time.Millisecond)

	_, err = v.Parse(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, int32(2), fetches.Load(), "second Parse after TTL expiry should refetch")
}

// TestJWKSVerifier_PicksUpRotatedKey simulates the identity service rotating
// its JWT signing key. The verifier must refetch JWKS and accept tokens
// signed with the new key without a restart.
func TestJWKSVerifier_PicksUpRotatedKey(t *testing.T) {
	// Start with original issuer
	originalIssuer := mustIssuer(t, "https://id.example.com", 5*time.Minute)

	// Dynamic JWKS handler: returns whichever issuer is currently assigned.
	var (
		currentIssuer atomic.Pointer[auth.TokenIssuer]
		fetches       atomic.Int32
	)
	currentIssuer.Store(originalIssuer)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(currentIssuer.Load().JWKS())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL:          srv.URL,
		Issuer:             "https://id.example.com",
		CacheTTL:           time.Hour, // long — force miss-based refetch
		RefetchMinInterval: time.Millisecond,
	})
	require.NoError(t, err)

	// Prime the cache with the original key.
	tokOld, err := originalIssuer.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)
	_, err = v.Parse(context.Background(), tokOld)
	require.NoError(t, err)
	assert.Equal(t, int32(1), fetches.Load())

	// Rotate: identity is now signing with a different key.
	newIssuer := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	currentIssuer.Store(newIssuer)

	tokNew, err := newIssuer.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// First attempt with the new token: verifier sees an unknown kid, refetches
	// JWKS (which now advertises the new key), and successfully verifies.
	// Throttle is 1ms so the refetch happens immediately.
	time.Sleep(5 * time.Millisecond)
	_, err = v.Parse(context.Background(), tokNew)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, fetches.Load(), int32(2),
		"an unknown kid must trigger a JWKS refetch")
}

// TestJWKSVerifier_ThrottlesUnknownKid ensures that a flood of tokens with
// an unknown kid does not cause a stampede of JWKS fetches.
func TestJWKSVerifier_ThrottlesUnknownKid(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, fetches := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL:          srv.URL,
		Issuer:             "https://id.example.com",
		RefetchMinInterval: 1 * time.Second, // generous so the test window is inside it
		CacheTTL:           time.Hour,
	})
	require.NoError(t, err)

	// Prime cache with a valid token.
	tok, err := ti.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)
	_, err = v.Parse(context.Background(), tok)
	require.NoError(t, err)
	require.Equal(t, int32(1), fetches.Load())

	// Sign tokens with a rotated issuer (unknown kid from the verifier's perspective).
	rotated := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	bad, err := rotated.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	// Hammer verifier with 20 lookups of the unknown kid inside the throttle window.
	for i := 0; i < 20; i++ {
		_, _ = v.Parse(context.Background(), bad)
	}

	// One additional refetch is allowed (the first miss), but not 20.
	assert.LessOrEqual(t, fetches.Load(), int32(3),
		"unknown-kid storms must be throttled; expected ≤ 3 fetches, got %d", fetches.Load())
}

// TestJWKSVerifier_ParseServiceToken_Valid asserts that service tokens
// minted by identity via client_credentials can be parsed by the verifier.
func TestJWKSVerifier_ParseServiceToken_Valid(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, _ := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
	})
	require.NoError(t, err)

	tok, err := ti.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc-1",
		Audience: "config",
		Scope:    "read:config",
	}, 5*time.Minute)
	require.NoError(t, err)

	got, err := v.ParseServiceToken(context.Background(), tok)
	require.NoError(t, err)
	assert.Equal(t, "svc-1", got.ClientID)
	assert.Equal(t, "config", got.Audience)
	assert.Equal(t, "read:config", got.Scope)
}

// TestJWKSVerifier_Parse_RejectsServiceToken confirms a service token is
// NOT accepted by Parse (user-token path) — mirrors *TokenIssuer.Parse
// behaviour so RequireAuth's user/service split keeps working with JWKS.
func TestJWKSVerifier_Parse_RejectsServiceToken(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, _ := newJWKSServer(t, ti)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
	})
	require.NoError(t, err)

	svcTok, err := ti.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc-1", Audience: "config",
	}, 5*time.Minute)
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), svcTok)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid)
}

// TestJWKSVerifier_StaleCacheFallback exercises the availability guarantee
// that a cached-but-stale key continues to verify tokens when a JWKS
// refetch fails. A transient identity-service blip must not cascade into
// a config-side auth outage if we already hold the signing key.
func TestJWKSVerifier_StaleCacheFallback(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)

	var healthy atomic.Bool
	healthy.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if !healthy.Load() {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ti.JWKS())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
		CacheTTL:  30 * time.Millisecond,
	})
	require.NoError(t, err)

	tok, err := ti.Mint(domain.TokenClaims{
		UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true,
	})
	require.NoError(t, err)

	// Prime the cache while JWKS is reachable.
	_, err = v.Parse(context.Background(), tok)
	require.NoError(t, err)

	// Make JWKS unavailable, then wait past the cache TTL so the next
	// Parse is forced to try a refetch.
	healthy.Store(false)
	time.Sleep(60 * time.Millisecond)

	// Refetch will fail, but the kid is still in the stale cache —
	// Parse must succeed and the claims must come through cleanly.
	claims, err := v.Parse(context.Background(), tok)
	require.NoError(t, err, "stale-cache fallback must keep parsing working during a JWKS outage")
	assert.Equal(t, "u", claims.UserID)
}

// TestJWKSVerifier_RefetchDeduplicated ensures the singleflight group
// collapses concurrent refetches into a single outbound request even when
// many goroutines hit an empty cache simultaneously.
func TestJWKSVerifier_RefetchDeduplicated(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)

	var fetches atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		// Slow response so concurrent callers race into singleflight before
		// the first request completes.
		time.Sleep(40 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ti.JWKS())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: srv.URL,
		Issuer:    "https://id.example.com",
		CacheTTL:  time.Hour,
	})
	require.NoError(t, err)

	tok, err := ti.Mint(domain.TokenClaims{
		UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true,
	})
	require.NoError(t, err)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = v.Parse(context.Background(), tok)
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), fetches.Load(),
		"singleflight must collapse concurrent refetches to one outbound request; got %d", fetches.Load())
}

func TestJWKSVerifier_NetworkFailure_ReturnsTokenInvalid(t *testing.T) {
	// Point the verifier at an unreachable URL so fetch fails.
	v, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{
		IssuerURL: "http://127.0.0.1:1", // invalid port → immediate connection failure
		Issuer:    "https://id.example.com",
	})
	require.NoError(t, err)

	// Make a valid-looking token so parsing reaches the key-lookup stage.
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	tok, err := ti.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), tok)
	assert.ErrorIs(t, err, auth.ErrTokenInvalid,
		"network failure during JWKS fetch should surface as ErrTokenInvalid")
}

func TestJWKSVerifier_Construction_ValidatesInputs(t *testing.T) {
	_, err := auth.NewJWKSVerifier(auth.JWKSVerifierConfig{Issuer: "x"})
	assert.Error(t, err, "missing IssuerURL must fail")

	_, err = auth.NewJWKSVerifier(auth.JWKSVerifierConfig{IssuerURL: "http://x"})
	assert.Error(t, err, "missing Issuer must fail")
}
