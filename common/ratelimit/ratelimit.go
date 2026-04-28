package ratelimit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/sweeney/identity/common/httputil"
	"golang.org/x/time/rate"
)

// visitor tracks the rate limiter and last-seen time for a single IP.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Limiter provides per-IP rate limiting middleware.
type Limiter struct {
	mu          sync.Mutex
	visitors    map[string]*visitor
	rate        rate.Limit
	burst       int
	trustProxy  string
	maxVisitors int
	now         func() time.Time // for testing
}

// NewLimiter creates a rate limiter with a default max of 100,000 tracked visitors.
// r is the rate in requests per second, burst is the maximum burst size.
// trustProxy controls whether proxy headers (e.g. CF-Connecting-IP) are trusted for IP extraction.
// Stale entries are cleaned up every 3 minutes.
func NewLimiter(r float64, burst int, trustProxy string) *Limiter {
	return NewLimiterWithMaxVisitors(r, burst, trustProxy, 100000)
}

// NewLimiterWithMaxVisitors creates a rate limiter with a configurable max visitor cap.
func NewLimiterWithMaxVisitors(r float64, burst int, trustProxy string, maxVisitors int) *Limiter {
	l := &Limiter{
		visitors:    make(map[string]*visitor),
		rate:        rate.Limit(r),
		burst:       burst,
		trustProxy:  trustProxy,
		maxVisitors: maxVisitors,
		now:         time.Now,
	}
	go l.cleanupLoop()
	return l
}

// getVisitor returns the rate limiter for the given IP, creating one if needed.
func (l *Limiter) getVisitor(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	v, exists := l.visitors[ip]
	if exists {
		v.lastSeen = l.now()
		return v.limiter
	}

	// Enforce max visitors
	if len(l.visitors) >= l.maxVisitors {
		// Emergency cleanup — remove entries older than 30 seconds
		l.cleanupLocked(30 * time.Second)
	}
	if len(l.visitors) >= l.maxVisitors {
		// Still full — return a deny-all limiter (don't store it)
		return rate.NewLimiter(0, 0)
	}

	limiter := rate.NewLimiter(l.rate, l.burst)
	l.visitors[ip] = &visitor{limiter: limiter, lastSeen: l.now()}
	return limiter
}

// cleanupLoop removes visitors that haven't been seen in the last 3 minutes.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.Cleanup(3 * time.Minute)
	}
}

// Cleanup removes entries older than maxAge.
func (l *Limiter) Cleanup(maxAge time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cleanupLocked(maxAge)
}

// cleanupLocked removes entries older than maxAge. Caller must hold l.mu.
func (l *Limiter) cleanupLocked(maxAge time.Duration) {
	now := l.now()
	for ip, v := range l.visitors {
		if now.Sub(v.lastSeen) > maxAge {
			delete(l.visitors, ip)
		}
	}
}

// VisitorCount returns the number of tracked IPs. For testing/monitoring.
func (l *Limiter) VisitorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.visitors)
}

// Middleware returns an http.Handler that rate-limits by client IP.
func (l *Limiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := httputil.ExtractClientIP(r, l.trustProxy)
		limiter := l.getVisitor(ip)

		if !limiter.Allow() {
			retryAfter := fmt.Sprintf("%.0f", 1.0/float64(l.rate))
			w.Header().Set("Retry-After", retryAfter)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please try again later.",
			})
			return
		}

		next.ServeHTTP(w, r)
	})
}
