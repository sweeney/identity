package auth_test

// jwks_resilience_test.go covers WP8 (GHSA-wcj3-fpwg-qwmr) on the verifier.
// This code ships to sibling services by tag, so its failure modes are
// ecosystem-wide.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonauth "github.com/sweeney/identity/common/auth"
	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
)

// controllableJWKS serves the issuer's key set, but lets a test make it fail
// or block on demand.
type controllableJWKS struct {
	srv     *httptest.Server
	fetches atomic.Int32
	failing atomic.Bool
	gate    chan struct{} // non-nil: each fetch waits on it
	mu      sync.Mutex
}

func newControllableJWKS(t *testing.T, issuer *auth.TokenIssuer) *controllableJWKS {
	t.Helper()
	c := &controllableJWKS{}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		c.fetches.Add(1)
		c.mu.Lock()
		gate := c.gate
		c.mu.Unlock()
		if gate != nil {
			select {
			case <-gate:
			case <-r.Context().Done():
				return
			}
		}
		if c.failing.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(issuer.JWKS()) //nolint:errcheck
	})
	c.srv = httptest.NewServer(mux)
	t.Cleanup(c.srv.Close)
	return c
}

func (c *controllableJWKS) setGate(ch chan struct{}) {
	c.mu.Lock()
	c.gate = ch
	c.mu.Unlock()
}

func newVerifier(t *testing.T, url string) *commonauth.JWKSVerifier {
	t.Helper()
	v, err := commonauth.NewJWKSVerifier(commonauth.JWKSVerifierConfig{
		IssuerURL: url,
		Issuer:    "https://id.example.com",
	})
	require.NoError(t, err)
	return v
}

// An unreachable or erroring JWKS endpoint is an infrastructure problem, not a
// verdict on the token. Reporting it as ErrTokenInvalid tells every client its
// token is bad, so they all clear their tokens and log the user out — a
// self-inflicted logout storm across the ecosystem exactly when identity is
// already struggling.
func TestJWKSVerifier_InfraFailure_IsDistinctFromInvalidToken(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	js := newControllableJWKS(t, ti)
	js.failing.Store(true)

	v := newVerifier(t, js.srv.URL)
	tok, err := ti.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), tok)
	require.Error(t, err)
	assert.False(t, errors.Is(err, commonauth.ErrTokenInvalid),
		"a JWKS outage must not be reported as an invalid token — clients log the user out on that")
	assert.True(t, errors.Is(err, commonauth.ErrKeysUnavailable),
		"an infrastructure failure needs its own error so callers can retry rather than sign out")
}

// A genuinely bad signature is still ErrTokenInvalid.
func TestJWKSVerifier_BadSignature_IsStillInvalidToken(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	other := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	js := newControllableJWKS(t, ti)

	v := newVerifier(t, js.srv.URL)
	tok, err := other.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	_, err = v.Parse(context.Background(), tok)
	require.Error(t, err)
	assert.True(t, errors.Is(err, commonauth.ErrTokenInvalid))
}

// The refetch throttle keys off fetchedAt, which stays zero until the first
// *successful* fetch. So while the JWKS endpoint is down — the exact moment
// the throttle matters — it is disabled, and every request hammers it.
func TestJWKSVerifier_ThrottlesRetriesBeforeFirstSuccess(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	js := newControllableJWKS(t, ti)
	js.failing.Store(true)

	v := newVerifier(t, js.srv.URL)
	tok, err := ti.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	for i := 0; i < 25; i++ {
		_, _ = v.Parse(context.Background(), tok)
	}

	assert.LessOrEqual(t, js.fetches.Load(), int32(3),
		"a JWKS outage must not be amplified into a request storm; got %d fetches", js.fetches.Load())
}

// The singleflight winner shares its per-request context with every waiter, so
// one client giving up (timeout, disconnect) cancels the fetch for all of them
// and they all fail an authentication that was about to succeed.
func TestJWKSVerifier_CancelledWinner_DoesNotFailWaiters(t *testing.T) {
	ti := mustIssuer(t, "https://id.example.com", 5*time.Minute)
	js := newControllableJWKS(t, ti)
	gate := make(chan struct{})
	js.setGate(gate)

	v := newVerifier(t, js.srv.URL)
	tok, err := ti.Mint(domain.TokenClaims{UserID: "u1", Username: "alice", Role: domain.RoleUser, IsActive: true})
	require.NoError(t, err)

	winnerCtx, cancelWinner := context.WithCancel(context.Background())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = v.Parse(winnerCtx, tok) // may fail; it is the one that gave up
	}()

	// Give the winner time to enter the fetch and block on the gate.
	time.Sleep(100 * time.Millisecond)

	waiterErr := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := v.Parse(context.Background(), tok)
		waiterErr <- err
	}()
	time.Sleep(100 * time.Millisecond)

	// The first caller gives up. The second is still waiting and still wants
	// its answer.
	cancelWinner()
	close(gate)

	select {
	case err := <-waiterErr:
		assert.NoError(t, err,
			"a caller that gave up must not cancel the fetch for everyone else")
	case <-time.After(5 * time.Second):
		t.Fatal("waiter never completed")
	}
	wg.Wait()
}
