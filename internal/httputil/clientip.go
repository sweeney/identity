package httputil

import (
	"net"
	"net/http"
)

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
