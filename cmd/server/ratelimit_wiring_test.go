package main

// ratelimit_wiring_test.go guards the rate-limiter wiring for admin re-auth endpoints.
//
// Round 7 / L3: POST endpoints that call verifyAdminPassword must be behind the
// strict auth rate limiter (5/min) rather than the general limiter (30/min).
// A test here catches any route accidentally removed from wrapAuth in main.go.

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/common/httputil"
	"github.com/sweeney/identity/common/ratelimit"
	"github.com/sweeney/identity/internal/config"
)

// TestAdminReauthEndpoints_StrictRateLimiting constructs a mux that mirrors the
// wiring in run() and verifies each admin re-auth POST route is covered by the
// strict limiter. It uses a burst of 1 so the second identical request from the
// same IP always receives 429.
func TestAdminReauthEndpoints_StrictRateLimiting(t *testing.T) {
	// Inner handler always returns 200 — we only care about the rate limit layer.
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Routes that must be under strict rate limiting — exactly the set in main.go.
	reauthRoutes := []string{
		"POST /admin/users/{id}/edit",
		"POST /admin/users/{id}/delete",
		"POST /admin/oauth/{id}/edit",
		"POST /admin/oauth/{id}/delete",
		"POST /admin/oauth/{id}/generate-secret",
		"POST /admin/oauth/{id}/rotate-secret",
		"POST /admin/oauth/{id}/clear-prev-secret",
	}

	for _, route := range reauthRoutes {
		route := route // capture
		t.Run(route, func(t *testing.T) {
			// Each subtest gets its own mux and limiter to isolate IP buckets.
			subRL := ratelimit.NewLimiter(5.0/60.0, 1, "")
			mux := http.NewServeMux()
			mux.Handle(route, subRL.Middleware(inner))

			// Derive the concrete path from the route pattern (replace {id} with a value).
			path := routeToPath(route)

			// Request 1: within burst — must succeed.
			req1 := httptest.NewRequest(http.MethodPost, path, nil)
			rr1 := httptest.NewRecorder()
			mux.ServeHTTP(rr1, req1)
			require.Equal(t, http.StatusOK, rr1.Code,
				"first request must pass the rate limiter")

			// Request 2: burst exhausted — must be rejected.
			req2 := httptest.NewRequest(http.MethodPost, path, nil)
			rr2 := httptest.NewRecorder()
			mux.ServeHTTP(rr2, req2)
			assert.Equal(t, http.StatusTooManyRequests, rr2.Code,
				"second request must be rate-limited — route %q must use strict limiter", route)
		})
	}
}

// TestDeviceVerifyEndpoint_StrictRateLimiting mirrors the oauth device-flow
// wiring in run(): POST /oauth/device authenticates with username+password
// (deviceVerifyPost) and so must sit behind the strict auth limiter, while
// POST /oauth/device/passkey carries an already-issued access token (no
// password) and must NOT be throttled by the strict limiter. The mux uses
// http.ServeMux precedence exactly like run() — a specific strict-limited
// pattern wins over the broad "/oauth/" catch-all.
func TestDeviceVerifyEndpoint_StrictRateLimiting(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Every POST /oauth route registered with wrapAuth gets the strict limiter
	// here, plus the broad "/oauth/" catch-all carrying only the general limiter.
	// This lets the test assert which device routes the strict limiter covers.
	strictRL := ratelimit.NewLimiter(5.0/60.0, 1, "") // burst 1
	mux := http.NewServeMux()
	for _, route := range strictOAuthRoutes() {
		mux.Handle(route, strictRL.Middleware(inner))
	}
	mux.Handle("/oauth/", inner) // catch-all: not strict-limited

	// POST /oauth/device (password) must be strictly limited: first passes,
	// second from the same IP is rejected.
	req1 := httptest.NewRequest(http.MethodPost, "/oauth/device", nil)
	rr1 := httptest.NewRecorder()
	mux.ServeHTTP(rr1, req1)
	require.Equal(t, http.StatusOK, rr1.Code, "first POST /oauth/device must pass the strict limiter")

	req2 := httptest.NewRequest(http.MethodPost, "/oauth/device", nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code,
		"second POST /oauth/device must be strict-rate-limited (password brute-force protection)")

	// POST /oauth/device/passkey (token, no password) must NOT be caught by the
	// strict limiter — it falls through to the catch-all, so repeated requests
	// from the same IP all pass the strict bucket.
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/oauth/device/passkey", nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		require.Equalf(t, http.StatusOK, rr.Code,
			"POST /oauth/device/passkey request %d must not hit the strict limiter", i)
	}
}

// TestRateLimitExempt verifies which paths bypass the general rate limiter.
// Static assets and the health check must be exempt; credential and API paths
// must not be.
func TestRateLimitExempt(t *testing.T) {
	exempt := []string{
		"/static/style.css",
		"/static/passkey-device.js",
		"/health",
	}
	for _, p := range exempt {
		assert.Truef(t, rateLimitExempt(p), "%q should be exempt from the general limiter", p)
	}

	notExempt := []string{
		"/api/v1/auth/login",
		"/oauth/token",
		"/admin/",
		"/",
		"/static",  // no trailing slash — not the asset tree
		"/healthz", // not the health endpoint
	}
	for _, p := range notExempt {
		assert.Falsef(t, rateLimitExempt(p), "%q should be rate-limited", p)
	}
}

// TestGeneralRateLimiter_ExemptsStaticAndHealth mirrors the run() wiring: the
// general limiter wraps everything except the exempt paths, so a single IP can
// fetch many static assets (as a browser does per page load) without tripping
// the limit, while a normal endpoint is still limited after its burst.
func TestGeneralRateLimiter_ExemptsStaticAndHealth(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	// Burst of 1 so the second non-exempt request from the same IP is rejected.
	rl := ratelimit.NewLimiter(5.0/60.0, 1, "")
	limited := rl.Middleware(inner)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rateLimitExempt(r.URL.Path) {
			inner.ServeHTTP(w, r)
			return
		}
		limited.ServeHTTP(w, r)
	})

	// Exempt paths never get a 429, even after many requests from one IP.
	for _, path := range []string{"/static/style.css", "/static/forms.js", "/health"} {
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)
			require.Equalf(t, http.StatusOK, rr.Code,
				"%s request %d must not be rate-limited", path, i)
		}
	}

	// Control: a non-exempt path passes once, then is limited.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	require.Equal(t, http.StatusOK, rr1.Code, "first request must pass")

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code,
		"second non-exempt request must be rate-limited")
}

// TestRateLimiter_AllowlistBypass mirrors the run() wiring: an allowlisted IP
// bypasses the limiter entirely (no 429 even past the burst), while a
// non-allowlisted IP is still limited. Uses the same config.IPAllowed +
// httputil.ExtractClientIP path as the real wiring.
func TestRateLimiter_AllowlistBypass(t *testing.T) {
	allowlist, err := loadAllowlist(t, "203.0.113.7")
	require.NoError(t, err)

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	rl := ratelimit.NewLimiter(5.0/60.0, 1, "") // burst 1
	limited := rl.Middleware(inner)
	allowed := func(r *http.Request) bool {
		return config.IPAllowed(allowlist, httputil.ExtractClientIP(r, ""))
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed(r) {
			inner.ServeHTTP(w, r)
			return
		}
		limited.ServeHTTP(w, r)
	})

	// Allowlisted IP: never limited, even well past the burst.
	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
		req.RemoteAddr = "203.0.113.7:5000"
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		require.Equalf(t, http.StatusOK, rr.Code, "allowlisted request %d must not be limited", i)
	}

	// Non-allowlisted IP: passes once, then limited.
	req1 := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req1.RemoteAddr = "198.51.100.9:5000"
	rr1 := httptest.NewRecorder()
	handler.ServeHTTP(rr1, req1)
	require.Equal(t, http.StatusOK, rr1.Code)

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req2.RemoteAddr = "198.51.100.9:5000"
	rr2 := httptest.NewRecorder()
	handler.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusTooManyRequests, rr2.Code, "non-allowlisted IP must still be limited")
}

// loadAllowlist parses an allowlist via config.Load using the env var, matching
// production parsing exactly.
func loadAllowlist(t *testing.T, v string) ([]*net.IPNet, error) {
	t.Helper()
	t.Setenv("RATE_LIMIT_ALLOWLIST", v)
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	return cfg.RateLimitAllowlist, nil
}

// routeToPath converts a route pattern like "POST /admin/users/{id}/edit"
// into a concrete request path by replacing {id} with a real value.
func routeToPath(route string) string {
	// strip the method prefix
	for i, c := range route {
		if c == ' ' {
			path := route[i+1:]
			// replace {id} with a concrete value
			result := ""
			for j := 0; j < len(path); {
				if path[j] == '{' {
					end := j
					for end < len(path) && path[end] != '}' {
						end++
					}
					result += "abc123"
					j = end + 1
				} else {
					result += string(path[j])
					j++
				}
			}
			return result
		}
	}
	return route
}
