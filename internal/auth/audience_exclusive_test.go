package auth_test

// audience_exclusive_test.go covers #37: the management plane requires a token
// whose audience names this server and nothing else.
//
// RequireAudience accepts a token whose aud *contains* identity, whatever else
// it names. That is right for the ordinary plane — a client that talks to five
// services and also calls /auth/me is doing nothing wrong — but it means a
// token deliberately delegated to five sibling resource servers is also
// accepted on the routes that administer identity itself. Any one of those
// servers, if compromised, holds a token that can create or delete users, as
// soon as the account behind it is an admin.
//
// This is the residual half of GHSA-65pj-9cmp-rvf6. That advisory closed the
// case where aud names only another service; it did not address a token that
// legitimately names identity *and* others — and multi-valued aud did not
// weaken that case, it made it expressible and normal.

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sweeney/identity/internal/auth"
)

func TestAudienceExclusive(t *testing.T) {
	const self = "https://id.swee.net"

	tests := []struct {
		name string
		aud  []string
		want bool
		why  string
	}{
		{
			name: "no audience at all", aud: nil, want: true,
			why: "a direct API login carries no aud — it was never delegated anywhere, which is the strongest case, not the weakest",
		},
		{
			name: "empty list", aud: []string{}, want: true,
			why: "same as absent",
		},
		{
			name: "issuer URL alone", aud: []string{"https://id.swee.net"}, want: true,
			why: "names this server and nothing else",
		},
		{
			name: "bare host alone", aud: []string{"id.swee.net"}, want: true,
			why: "the bare host is an accepted spelling of this server",
		},
		{
			name: "both spellings of this server", aud: []string{"id.swee.net", "https://id.swee.net"}, want: true,
			why: "both name this server, so the token is still delegated nowhere else",
		},
		{
			name: "identity plus one sibling", aud: []string{"https://id.swee.net", "statehouse"}, want: false,
			why: "this is the whole point — the token is also a bearer credential at statehouse",
		},
		{
			name: "the live production shape", want: false,
			aud: []string{"config", "countinghouse", "greenhouse", "id.swee.net", "mqttauth", "statehouse"},
			why: "claude and net.swee.mac both register exactly this",
		},
		{
			name: "sibling only", aud: []string{"statehouse"}, want: false,
			why: "already refused by RequireAudience; must stay refused",
		},
		{
			name: "lookalike host", aud: []string{"id.swee.net.evil.example"}, want: false,
			why: "substring or suffix confusion must not pass",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, auth.AudienceExclusive(tc.aud, self), tc.why)
		})
	}
}

// TestAudienceExclusive_IsStricterThanAllowed states the relationship between
// the two rules directly: anything exclusive is allowed, but not the reverse.
func TestAudienceExclusive_IsStricterThanAllowed(t *testing.T) {
	const self = "https://id.swee.net"
	cases := [][]string{
		nil,
		{"https://id.swee.net"},
		{"id.swee.net"},
		{"https://id.swee.net", "statehouse"},
		{"statehouse"},
	}
	for _, aud := range cases {
		if auth.AudienceExclusive(aud, self) {
			assert.True(t, auth.AudienceAllowed(aud, self),
				"exclusive must imply allowed, or the management plane would accept what the ordinary plane refuses: %v", aud)
		}
	}
}
