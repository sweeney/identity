package service

import "strings"

// RequestMeta carries who made a request, for the audit records it produces:
// the client IP (already resolved through TRUST_PROXY) and the User-Agent.
// Neither is trusted for any decision; they exist so an operator reading the
// journal can tell which caller an event came from.
type RequestMeta struct {
	IP        string
	UserAgent string
}

// maxUserAgentLen bounds what a caller can put into the audit table.
const maxUserAgentLen = 200

func (m RequestMeta) userAgent() string {
	ua := m.UserAgent
	if len(ua) > maxUserAgentLen {
		ua = strings.ToValidUTF8(ua[:maxUserAgentLen], "")
	}
	return ua
}
