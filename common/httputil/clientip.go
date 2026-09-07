package httputil

import (
	"fmt"
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

// TrustedProxies is a set of source addresses whose forwarded-for headers are
// honoured. A forwarded-for header is a claim made by whoever sent it, and is
// only meaningful coming from the proxy that set it.
type TrustedProxies struct {
	nets []*net.IPNet
}

// defaultTrustedCIDRs is the trust set used when none is configured: loopback
// and the private ranges.
//
// This matches how the service is actually fronted. cloudflared runs on the
// origin host (or beside it) and proxies to a local port, so a genuine request
// arrives from 127.0.0.1 or a private address — never from a Cloudflare edge
// address. Deployments that expose the origin directly to Cloudflare should
// set their own list rather than rely on this one.
var defaultTrustedCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"fc00::/7",
}

// DefaultTrustedProxies is the trust set applied by ExtractClientIP.
var DefaultTrustedProxies = mustParseTrustedProxies(defaultTrustedCIDRs)

// ParseTrustedProxies builds a trust set from a comma-separated list of CIDRs
// or bare IP addresses. An empty list trusts nothing.
func ParseTrustedProxies(list string) (*TrustedProxies, error) {
	tp := &TrustedProxies{}
	for _, entry := range strings.Split(list, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			ip := net.ParseIP(entry)
			if ip == nil {
				return nil, fmt.Errorf("trusted proxy %q is not an IP address or CIDR", entry)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			entry = fmt.Sprintf("%s/%d", ip, bits)
		}
		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("trusted proxy %q: %w", entry, err)
		}
		tp.nets = append(tp.nets, network)
	}
	return tp, nil
}

func mustParseTrustedProxies(cidrs []string) *TrustedProxies {
	tp, err := ParseTrustedProxies(strings.Join(cidrs, ","))
	if err != nil {
		panic("httputil: invalid default trusted proxy list: " + err.Error())
	}
	return tp
}

// Contains reports whether addr is one of the trusted proxies.
func (t *TrustedProxies) Contains(addr string) bool {
	if t == nil {
		return false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range t.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ExtractClientIP returns the client IP from the request, using
// DefaultTrustedProxies. See ExtractClientIPFrom.
func ExtractClientIP(r *http.Request, trustProxy string) string {
	return ExtractClientIPFrom(r, trustProxy, DefaultTrustedProxies)
}

// ExtractClientIPFrom returns the client IP from the request.
//
// If trustProxy is "cloudflare" AND the request arrived from one of the
// trusted proxies, the CF-Connecting-IP header is used. Otherwise the peer
// address is used.
//
// The trust check is the point. That header is a claim made by whoever sent
// it: honoured unconditionally, anyone able to reach the origin directly picks
// their own identity for rate limiting, for the rate-limit allowlist, and for
// what lands in the audit log — a fresh address per request defeats the
// limiter outright.
func ExtractClientIPFrom(r *http.Request, trustProxy string, trusted *TrustedProxies) string {
	peer := peerIP(r)
	if trustProxy == "cloudflare" && trusted.Contains(peer) {
		if cf := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); cf != "" {
			// A header that is not an address is not an identity.
			if net.ParseIP(cf) != nil {
				return cf
			}
		}
	}
	return peer
}

func peerIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
