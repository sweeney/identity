package httputil_test

// clientip_trust_test.go covers WP6 (GHSA-mpc2-xp7h-7r9x): with
// TRUST_PROXY=cloudflare, CF-Connecting-IP was honoured from any source
// address whatsoever.
//
// That header is only meaningful when it comes from the proxy that set it.
// Trusting it unconditionally means anyone who can reach the origin directly —
// bypassing the tunnel — picks their own identity for rate limiting, audit
// records and the rate-limit allowlist: a fresh IP per request defeats the
// limiter entirely, and any address at all can be written into the audit log.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/common/httputil"
)

func requestFrom(remoteAddr, forwarded string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remoteAddr
	if forwarded != "" {
		r.Header.Set("CF-Connecting-IP", forwarded)
	}
	return r
}

func TestExtractClientIP_TrustsHeaderOnlyFromTrustedProxy(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		forwarded  string
		want       string
	}{
		{
			// cloudflared runs on the origin host and proxies to loopback, so
			// this is the shape of every real request in a tunnel deployment.
			name: "loopback proxy is trusted", remoteAddr: "127.0.0.1:5000",
			forwarded: "203.0.113.9", want: "203.0.113.9",
		},
		{
			name: "private-network proxy is trusted", remoteAddr: "10.0.0.5:5000",
			forwarded: "203.0.113.9", want: "203.0.113.9",
		},
		{
			// The attack: a request straight to the origin from the internet,
			// naming whatever address it likes.
			name: "public source address is not trusted", remoteAddr: "198.51.100.23:44321",
			forwarded: "203.0.113.9", want: "198.51.100.23",
		},
		{
			name:       "spoofed header from a public peer cannot forge a loopback identity",
			remoteAddr: "198.51.100.23:44321", forwarded: "127.0.0.1", want: "198.51.100.23",
		},
		{
			name: "no header falls back to the peer", remoteAddr: "127.0.0.1:5000",
			forwarded: "", want: "127.0.0.1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := httputil.ExtractClientIP(requestFrom(tc.remoteAddr, tc.forwarded), "cloudflare")
			assert.Equal(t, tc.want, got)
		})
	}
}

// With proxy trust off, the header is ignored no matter where it came from.
func TestExtractClientIP_NoProxyTrust_IgnoresHeader(t *testing.T) {
	got := httputil.ExtractClientIP(requestFrom("127.0.0.1:5000", "203.0.113.9"), "")
	assert.Equal(t, "127.0.0.1", got)
}

// An operator whose proxy sits somewhere else can say so.
func TestExtractClientIPFrom_ExplicitTrustedProxies(t *testing.T) {
	trusted, err := httputil.ParseTrustedProxies("198.51.100.0/24")
	require.NoError(t, err)

	got := httputil.ExtractClientIPFrom(requestFrom("198.51.100.23:44321", "203.0.113.9"), "cloudflare", trusted)
	assert.Equal(t, "203.0.113.9", got)

	// And an address outside that list is still not trusted.
	got = httputil.ExtractClientIPFrom(requestFrom("192.0.2.7:44321", "203.0.113.9"), "cloudflare", trusted)
	assert.Equal(t, "192.0.2.7", got)
}

// A header that is not a valid IP is not an identity.
func TestExtractClientIP_MalformedHeaderIgnored(t *testing.T) {
	got := httputil.ExtractClientIP(requestFrom("127.0.0.1:5000", "not-an-ip"), "cloudflare")
	assert.Equal(t, "127.0.0.1", got)
}
