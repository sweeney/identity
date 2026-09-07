package auth

import "strings"

// Role represents a user's role in the system.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// TokenClaims holds the parsed contents of a JWT access token.
//
// Audience carries the `aud` claim verbatim as a list. It is empty for tokens
// from a direct /api/v1/auth/login — those are usable against this identity
// server only. Tokens minted through the OAuth, device or client-credentials
// grants carry the requesting client's configured audience, and that value is
// a boundary: a token for service A must not be accepted by service B. Use
// HasAudience to test membership rather than comparing or splitting strings —
// a space is a legal character inside a single aud value, so joining the list
// and re-splitting it is lossy in both directions.
type TokenClaims struct {
	UserID   string
	Username string
	Role     Role
	IsActive bool
	Audience []string
}

// HasAudience reports whether aud appears in the token's audience list.
// A token with no audience matches nothing — callers that treat an absent
// audience as "this server only" must test len(Audience) == 0 themselves.
func (c *TokenClaims) HasAudience(aud string) bool {
	return containsAudience(c.Audience, aud)
}

// ServiceTokenClaims holds the parsed contents of a service (client credentials) JWT.
type ServiceTokenClaims struct {
	ClientID  string
	Audience  []string
	Scope     string
	JTI       string
	ExpiresAt int64
	IssuedAt  int64
}

// HasAudience reports whether aud appears in the token's audience list.
func (c *ServiceTokenClaims) HasAudience(aud string) bool {
	return containsAudience(c.Audience, aud)
}

func containsAudience(list []string, aud string) bool {
	for _, a := range list {
		if a == aud {
			return true
		}
	}
	return false
}

// AudienceList builds an audience list from a single configured audience
// string. An empty string yields nil — a token with no aud claim.
func AudienceList(aud string) []string {
	if aud == "" {
		return nil
	}
	return []string{aud}
}

// HasScope returns true if the given scope is in the token's space-delimited scope list.
func (c *ServiceTokenClaims) HasScope(scope string) bool {
	if c.Scope == "" {
		return false
	}
	for _, s := range strings.Split(c.Scope, " ") {
		if s == scope {
			return true
		}
	}
	return false
}
