package auth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonauth "github.com/sweeney/identity/common/auth"
	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

func userTok(t *testing.T, ti *auth.TokenIssuer) string {
	t.Helper()
	tok, err := ti.Mint(domain.TokenClaims{UserID: "u", Username: "u", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)
	return tok
}

// Metrics() starts empty and reflects a successful fetch after the first Parse.
func TestJWKSVerifier_Metrics_SuccessfulParse(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	srv, _ := newJWKSServer(t, ti)

	v, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL: srv.URL, Issuer: "https://id.example.com",
	})
	require.NoError(t, err)

	m0 := v.Metrics()
	assert.Equal(t, uint64(0), m0.Fetches)
	assert.Equal(t, 0, m0.KeyCount)
	assert.True(t, m0.FetchedAt.IsZero(), "FetchedAt is zero before first parse (lazy fetch)")

	_, err = v.Parse(context.Background(), userTok(t, ti))
	require.NoError(t, err)

	m := v.Metrics()
	assert.Equal(t, uint64(1), m.Fetches)
	assert.Equal(t, uint64(0), m.FetchErrors)
	assert.Equal(t, 1, m.KeyCount)
	assert.False(t, m.FetchedAt.IsZero())
	assert.Empty(t, m.LastFetchError)
}

// A rotated signing key produces a kid-miss, a refetch, and a counted rotation.
func TestJWKSVerifier_Metrics_RotationAndKidMiss(t *testing.T) {
	original := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	var current atomic.Pointer[auth.TokenIssuer]
	current.Store(original)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(current.Load().JWKS())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	v, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL: srv.URL, Issuer: "https://id.example.com",
		CacheTTL: time.Hour, RefetchMinInterval: time.Millisecond,
	})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), userTok(t, original))
	require.NoError(t, err)

	newIssuer := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	current.Store(newIssuer)
	time.Sleep(5 * time.Millisecond)

	_, err = v.Parse(context.Background(), userTok(t, newIssuer))
	require.NoError(t, err)

	m := v.Metrics()
	assert.GreaterOrEqual(t, m.KidMisses, uint64(1), "rotated kid must register a miss")
	assert.Equal(t, uint64(1), m.Rotations, "key set changed exactly once")
	assert.Equal(t, uint64(2), m.Fetches)
	assert.Empty(t, m.LastFetchError)
}

// When a refetch fails but a cached key still verifies, StaleServed and
// FetchErrors increment and LastFetchError is populated.
func TestJWKSVerifier_Metrics_StaleServedOnFetchError(t *testing.T) {
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

	v, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL: srv.URL, Issuer: "https://id.example.com", CacheTTL: 30 * time.Millisecond,
	})
	require.NoError(t, err)

	tok := userTok(t, ti)
	_, err = v.Parse(context.Background(), tok)
	require.NoError(t, err)

	healthy.Store(false)
	time.Sleep(60 * time.Millisecond)

	_, err = v.Parse(context.Background(), tok)
	require.NoError(t, err, "stale cache must keep verifying during a JWKS outage")

	m := v.Metrics()
	assert.GreaterOrEqual(t, m.StaleServed, uint64(1))
	assert.GreaterOrEqual(t, m.FetchErrors, uint64(1))
	assert.NotEmpty(t, m.LastFetchError)
}

// A configured logger receives a structured info record on key rotation.
func TestJWKSVerifier_Logger_RotationLogged(t *testing.T) {
	original := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	var current atomic.Pointer[auth.TokenIssuer]
	current.Store(original)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(current.Load().JWKS())
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	v, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL: srv.URL, Issuer: "https://id.example.com",
		CacheTTL: time.Hour, RefetchMinInterval: time.Millisecond, Logger: logger,
	})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), userTok(t, original))
	require.NoError(t, err)

	newIssuer := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	current.Store(newIssuer)
	time.Sleep(5 * time.Millisecond)
	_, err = v.Parse(context.Background(), userTok(t, newIssuer))
	require.NoError(t, err)

	assert.Contains(t, buf.String(), "jwks keys rotated")
}

// A configured logger receives a structured error record when a fetch fails.
func TestJWKSVerifier_Logger_FetchFailureLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))

	v, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL: "http://127.0.0.1:1", Issuer: "https://id.example.com", Logger: logger,
	})
	require.NoError(t, err)

	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	_, _ = v.Parse(context.Background(), userTok(t, ti))

	assert.Contains(t, buf.String(), "jwks fetch failed")
}

// A nil logger must not panic (default discard handler).
func TestJWKSVerifier_NilLogger_NoPanic(t *testing.T) {
	v, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL: "http://127.0.0.1:1", Issuer: "https://id.example.com",
	})
	require.NoError(t, err)
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	assert.NotPanics(t, func() { _, _ = v.Parse(context.Background(), userTok(t, ti)) })
}
