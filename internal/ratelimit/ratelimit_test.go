package ratelimit_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/ratelimit"
)

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
}

func TestRequestsWithinLimitSucceed(t *testing.T) {
	// Allow 5 requests per second with burst of 5
	limiter := ratelimit.NewLimiter(5, 5, "")
	handler := limiter.Middleware(okHandler())

	for i := 0; i < 5; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}
}

func TestRequestsExceedingLimitGet429(t *testing.T) {
	// Allow 2 requests per second with burst of 2
	limiter := ratelimit.NewLimiter(2, 2, "")
	handler := limiter.Middleware(okHandler())

	// First 2 should succeed (burst)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:12345"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i+1)
	}

	// 3rd request should be rate limited
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// Verify error body
	var body map[string]string
	err := json.NewDecoder(w.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "rate_limit_exceeded", body["error"])
}

func TestDifferentIPsHaveIndependentLimits(t *testing.T) {
	// Allow 1 request per second with burst of 1
	limiter := ratelimit.NewLimiter(1, 1, "")
	handler := limiter.Middleware(okHandler())

	// IP 1 uses its one allowed request
	req1 := httptest.NewRequest(http.MethodGet, "/", nil)
	req1.RemoteAddr = "10.0.0.1:12345"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// IP 1 is now rate limited
	req1b := httptest.NewRequest(http.MethodGet, "/", nil)
	req1b.RemoteAddr = "10.0.0.1:12345"
	w1b := httptest.NewRecorder()
	handler.ServeHTTP(w1b, req1b)
	assert.Equal(t, http.StatusTooManyRequests, w1b.Code)

	// IP 2 should still succeed — independent limit
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.2:12345"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}

func TestRetryAfterHeaderIsSet(t *testing.T) {
	// Rate is 0.5 req/s → Retry-After should be 2
	limiter := ratelimit.NewLimiter(0.5, 1, "")
	handler := limiter.Middleware(okHandler())

	// Exhaust burst
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Next request gets 429 with Retry-After
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.Equal(t, "2", w.Header().Get("Retry-After"))
}

func TestMiddleware_IgnoresCFConnectingIP_WhenTrustProxyEmpty(t *testing.T) {
	// trustProxy is empty — CF-Connecting-IP should be ignored.
	// All requests should land on the same bucket (RemoteAddr).
	limiter := ratelimit.NewLimiter(1, 1, "")
	handler := limiter.Middleware(okHandler())

	// First request succeeds
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request with a different CF-Connecting-IP — should still be rate limited
	// because trustProxy is empty, so we use RemoteAddr (same IP).
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	req2.Header.Set("CF-Connecting-IP", "203.0.113.2")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code, "should be rate limited because CF-Connecting-IP is ignored")
}

func TestMiddleware_UsesCFConnectingIP_WhenTrustProxyCloudflare(t *testing.T) {
	limiter := ratelimit.NewLimiter(1, 1, "cloudflare")
	handler := limiter.Middleware(okHandler())

	// First request from CF IP 203.0.113.1 succeeds
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Second request from different CF IP should also succeed (different bucket)
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.1:12345"
	req2.Header.Set("CF-Connecting-IP", "203.0.113.2")
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code, "different CF IP should have its own bucket")
}

func TestCleanupRemovesStaleEntries(t *testing.T) {
	limiter := ratelimit.NewLimiter(10, 10, "")

	// Make a request to create a visitor
	handler := limiter.Middleware(okHandler())
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, 1, limiter.VisitorCount())

	// Cleanup with a zero max age should remove the entry
	limiter.Cleanup(0)
	assert.Equal(t, 0, limiter.VisitorCount())
}

func TestVisitorCountTracksMultipleIPs(t *testing.T) {
	limiter := ratelimit.NewLimiter(10, 10, "")
	handler := limiter.Middleware(okHandler())

	ips := []string{"10.0.0.1:1111", "10.0.0.2:2222", "10.0.0.3:3333"}
	for _, ip := range ips {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = ip
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	assert.Equal(t, 3, limiter.VisitorCount())
}

func TestMaxVisitors_DeniesWhenFull(t *testing.T) {
	// Create a limiter with a very small max visitors cap for testing.
	limiter := ratelimit.NewLimiterWithMaxVisitors(10, 10, "", 3)
	handler := limiter.Middleware(okHandler())

	// Fill up all 3 visitor slots
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:12345", i+1)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request from IP %d should succeed", i+1)
	}
	assert.Equal(t, 3, limiter.VisitorCount())

	// 4th unique IP should be denied (map is full, no stale entries to clean)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code, "should deny when visitor map is full")

	// The deny-all visitor should NOT be stored
	assert.Equal(t, 3, limiter.VisitorCount(), "deny-all visitor should not be stored")
}

func TestMaxVisitors_EmergencyCleanupFreesSlotsForNewVisitors(t *testing.T) {
	limiter := ratelimit.NewLimiterWithMaxVisitors(10, 10, "", 3)
	handler := limiter.Middleware(okHandler())

	// Fill all 3 slots
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = fmt.Sprintf("10.0.0.%d:12345", i+1)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
	}

	// Age out all entries via cleanup
	limiter.Cleanup(0)
	assert.Equal(t, 0, limiter.VisitorCount())

	// New visitor should now succeed
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.99:12345"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code, "should allow after cleanup frees slots")
}
