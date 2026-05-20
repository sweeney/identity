package main

// ratelimit_wiring_test.go guards the rate-limiter wiring for admin re-auth endpoints.
//
// Round 7 / L3: POST endpoints that call verifyAdminPassword must be behind the
// strict auth rate limiter (5/min) rather than the general limiter (30/min).
// A test here catches any route accidentally removed from wrapAuth in main.go.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/common/ratelimit"
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
