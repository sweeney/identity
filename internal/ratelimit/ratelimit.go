package ratelimit

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// visitor tracks the rate limiter and last-seen time for a single IP.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// Limiter provides per-IP rate limiting middleware.
type Limiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     rate.Limit
	burst    int
	now      func() time.Time // for testing
}

// NewLimiter creates a rate limiter.
// r is the rate in requests per second, burst is the maximum burst size.
// Stale entries are cleaned up every 3 minutes.
func NewLimiter(r float64, burst int) *Limiter {
	l := &Limiter{
		visitors: make(map[string]*visitor),
		rate:     rate.Limit(r),
		burst:    burst,
		now:      time.Now,
	}
	go l.cleanupLoop()
	return l
}

// getVisitor returns the rate limiter for the given IP, creating one if needed.
func (l *Limiter) getVisitor(ip string) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	v, exists := l.visitors[ip]
	if !exists {
		limiter := rate.NewLimiter(l.rate, l.burst)
		l.visitors[ip] = &visitor{limiter: limiter, lastSeen: l.now()}
		return limiter
	}

	v.lastSeen = l.now()
	return v.limiter
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
		ip := ExtractClientIP(r)
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

// ExtractClientIP returns the best-available client IP from the request.
// Prefers CF-Connecting-IP (set by Cloudflare), falls back to RemoteAddr host.
func ExtractClientIP(r *http.Request) string {
	if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
		return cf
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
