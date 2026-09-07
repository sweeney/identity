package auth_test

// tokensource_wp8_test.go covers WP8 (GHSA-wcj3-fpwg-qwmr) on the outbound
// TokenSource.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/common/auth"
)

// tokenServer counts token requests and records the paths they arrived on.
type tokenServer struct {
	srv      *httptest.Server
	requests atomic.Int32
	delay    time.Duration

	mu    sync.Mutex
	paths []string
}

func newTokenServer(t *testing.T, expiresIn int) *tokenServer {
	t.Helper()
	ts := &tokenServer{}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ts.requests.Add(1)
		ts.mu.Lock()
		ts.paths = append(ts.paths, r.URL.Path)
		ts.mu.Unlock()
		if ts.delay > 0 {
			time.Sleep(ts.delay)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"access_token": "tok-value",
			"token_type":   "Bearer",
			"expires_in":   expiresIn,
		})
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *tokenServer) firstPath() string {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.paths) == 0 {
		return ""
	}
	return ts.paths[0]
}

// Identity rate-limits its token endpoint at 5/min. Without coalescing, a
// service starting up — or recovering from an Invalidate() after a 401 — fires
// one request per concurrent caller and locks itself out with a 429 of its own
// making.
func TestTokenSource_CoalescesConcurrentFetches(t *testing.T) {
	srv := newTokenServer(t, 3600)
	srv.delay = 50 * time.Millisecond

	ts := &auth.TokenSource{
		BaseURL:      srv.srv.URL,
		ClientID:     "svc",
		ClientSecret: "secret",
	}

	var wg sync.WaitGroup
	errs := make(chan error, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := ts.Token(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	assert.Equal(t, int32(1), srv.requests.Load(),
		"50 concurrent callers must produce one token request, not 50 — "+
			"identity limits this endpoint to 5/min")
}

// expires_in is measured from when identity issued the token, not from when
// the response finished arriving. Computing the deadline after the round trip
// over-states the lifetime by the request latency, so the cache keeps serving a
// token that is closer to expiry than it believes — and on a slow link can
// serve one the far end has already rejected.
//
// The numbers here discriminate between the two: with expires_in=31s and a 2s
// round trip, a deadline measured from the request start falls inside the 30s
// refresh buffer on the second call (refetch), while one measured from the
// response does not (stale cache hit).
func TestTokenSource_ExpiryMeasuredFromRequestStart(t *testing.T) {
	srv := newTokenServer(t, 31)
	srv.delay = 2 * time.Second

	ts := &auth.TokenSource{
		BaseURL:      srv.srv.URL,
		ClientID:     "svc",
		ClientSecret: "secret",
	}

	_, err := ts.Token(context.Background())
	require.NoError(t, err)

	srv.delay = 0
	_, err = ts.Token(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int32(2), srv.requests.Load(),
		"the cached expiry must be measured from when the request was sent, "+
			"not from when the response arrived")
}

// A BaseURL with a trailing slash is an ordinary configuration mistake and
// produced a double slash in the path, which identity does not route.
func TestTokenSource_BaseURLTrailingSlashNormalised(t *testing.T) {
	srv := newTokenServer(t, 3600)

	ts := &auth.TokenSource{
		BaseURL:      srv.srv.URL + "/",
		ClientID:     "svc",
		ClientSecret: "secret",
	}

	_, err := ts.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "/oauth/token", srv.firstPath(),
		"a trailing slash on BaseURL must not produce //oauth/token")
	assert.False(t, strings.Contains(srv.firstPath(), "//"))
}
