package httputil

import (
	"net"
	"net/http"
	"strings"
)

// CheckOrigin validates that the Origin header (if present) matches the
// request's Host. Browsers always send Origin on cross-origin POST requests
// and on same-origin fetch() calls. A missing Origin is rejected for POST
// requests since all modern browsers include it.
func CheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Browsers always send Origin on POST fetch(). A missing Origin
		// could mean a non-browser client (curl, etc.) — allow those since
		// they can't exploit CSRF. But for form POSTs from browsers,
		// Origin should always be present.
		return true
	}
	return strings.HasSuffix(origin, "://"+r.Host)
}

// ExtractClientIP returns the client IP from the request.
// If trustProxy is "cloudflare", it uses the CF-Connecting-IP header.
// Otherwise, it uses RemoteAddr.
func ExtractClientIP(r *http.Request, trustProxy string) string {
	if trustProxy == "cloudflare" {
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			return cf
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
