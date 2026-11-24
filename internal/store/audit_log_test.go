package store

// audit_log_test.go covers WP11 (GHSA-38rv-3m75-4gqr): the audit line emitted
// to stdout interpolated attacker-controlled values verbatim.
//
// Username is unauthenticated input — a failed login records whatever was
// typed — so a username containing a newline let an attacker write additional,
// fully-formed audit lines into the process log. Anyone reading journalctl, or
// any log shipper parsing it, sees forged events indistinguishable from real
// ones. The same applies to detail and IP address on paths that echo input.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/sweeney/identity/internal/domain"
)

func TestAuditLogLine_EscapesInjectedNewlines(t *testing.T) {
	tests := []struct {
		name     string
		username string
	}{
		{
			name:     "newline-forged audit line",
			username: "attacker\naudit: login.success user=root ip=127.0.0.1",
		},
		{
			name:     "carriage return",
			username: "attacker\raudit: login.success user=root",
		},
		{
			name:     "tab and control characters",
			username: "attacker\tuser=root\x00",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			line := auditLogLine(&domain.AuthEvent{
				EventType: "login.failure",
				Username:  tc.username,
				IPAddress: "1.2.3.4",
			})

			assert.Equal(t, 1, strings.Count(line, "\n")+1,
				"an audit record must emit exactly one line, however it is provoked")
			assert.NotContains(t, line, "\n")
			assert.NotContains(t, line, "\r")
		})
	}
}

// The escaping must not mangle ordinary values.
func TestAuditLogLine_LeavesOrdinaryValuesReadable(t *testing.T) {
	line := auditLogLine(&domain.AuthEvent{
		EventType: "login.success",
		Username:  "alice",
		IPAddress: "192.0.2.10",
		Detail:    "admin UI passkey login",
	})
	assert.Contains(t, line, "login.success")
	assert.Contains(t, line, "alice")
	assert.Contains(t, line, "192.0.2.10")
	assert.Contains(t, line, "admin UI passkey login")
}

// The journal line names the client and the device hint (the caller's
// User-Agent on token-endpoint events, the declared device on a login) when
// the event has them. Without the client, matching an oauth_authorize_success to the app
// that asked for it took timestamp correlation.
func TestAuditLogLine_IncludesClientAndUserAgent(t *testing.T) {
	line := auditLogLine(&domain.AuthEvent{
		EventType:  "refresh_token_revoked_reuse",
		Username:   "sweeney",
		ClientID:   "thermostat",
		DeviceHint: "thermo-fw/2.1",
		IPAddress:  "203.0.113.9",
		Detail:     "reason=password_change",
	})
	assert.Equal(t,
		`audit: refresh_token_revoked_reuse user="sweeney" client="thermostat" device="thermo-fw/2.1" detail="reason=password_change" ip="203.0.113.9"`,
		line)
}

// Fields an event does not have are left out rather than printed empty, so
// existing lines read as before.
func TestAuditLogLine_OmitsAbsentClientAndUserAgent(t *testing.T) {
	line := auditLogLine(&domain.AuthEvent{EventType: "login_success", Username: "alice", IPAddress: "192.0.2.10"})
	assert.Equal(t, `audit: login_success user="alice" ip="192.0.2.10"`, line)
}

// The User-Agent is caller-controlled, so it is escaped like the username.
func TestAuditLogLine_EscapesUserAgent(t *testing.T) {
	line := auditLogLine(&domain.AuthEvent{
		EventType:  "oauth_code_exchanged",
		DeviceHint: "evil\naudit: login_success user=\"root\"",
	})
	assert.NotContains(t, line, "\n")
}
