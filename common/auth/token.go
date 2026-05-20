package auth

import "strings"

// Role represents a user's role in the system.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
)

// TokenClaims holds the parsed contents of a JWT access token.
type TokenClaims struct {
	UserID   string
	Username string
	Role     Role
	IsActive bool
	Audience string
}

// ServiceTokenClaims holds the parsed contents of a service (client credentials) JWT.
type ServiceTokenClaims struct {
	ClientID  string
	Audience  string
	Scope     string
	JTI       string
	ExpiresAt int64
	IssuedAt  int64
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
