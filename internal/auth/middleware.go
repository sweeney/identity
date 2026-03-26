package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/sweeney/identity/internal/domain"
)

type contextKey string

const claimsContextKey contextKey = "auth_claims"
const serviceClaimsContextKey contextKey = "service_claims"

// ClaimsFromContext extracts TokenClaims from a request context set by RequireAuth.
// Returns nil if not present.
func ClaimsFromContext(ctx context.Context) *domain.TokenClaims {
	v := ctx.Value(claimsContextKey)
	if v == nil {
		return nil
	}
	c, _ := v.(*domain.TokenClaims)
	return c
}

// ServiceClaimsFromContext extracts ServiceTokenClaims from a request context.
// Returns nil if the token is not a service token.
func ServiceClaimsFromContext(ctx context.Context) *domain.ServiceTokenClaims {
	v := ctx.Value(serviceClaimsContextKey)
	if v == nil {
		return nil
	}
	c, _ := v.(*domain.ServiceTokenClaims)
	return c
}

// RequireAuth is an HTTP middleware that validates the Bearer token in the
// Authorization header and injects the claims into the request context.
// Returns 401 if the token is missing or invalid, 403 if the user is inactive.
func RequireAuth(issuer *TokenIssuer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid authorization header format")
			return
		}

		// Try parsing as a service token first (has client_id claim)
		svcClaims, svcErr := issuer.ParseServiceToken(parts[1])
		if svcErr == nil && svcClaims != nil {
			ctx := context.WithValue(r.Context(), serviceClaimsContextKey, svcClaims)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// Fall back to user token
		claims, err := issuer.Parse(parts[1])
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}

		if !claims.IsActive {
			writeError(w, http.StatusForbidden, "account_disabled", "account has been disabled")
			return
		}

		ctx := context.WithValue(r.Context(), claimsContextKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequireAdmin is an HTTP middleware (to be chained after RequireAuth) that
// returns 403 if the authenticated user does not have the admin role.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil || claims.Role != domain.RoleAdmin {
			writeError(w, http.StatusForbidden, "forbidden", "admin role required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireScope is middleware that checks the token (user or service) has the required scope.
// Service tokens are checked via the space-delimited scope claim.
// User tokens with admin role pass all scope checks.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Check service token first
			if sc := ServiceClaimsFromContext(r.Context()); sc != nil {
				if sc.HasScope(scope) {
					next.ServeHTTP(w, r)
					return
				}
				writeError(w, http.StatusForbidden, "insufficient_scope", "token missing required scope: "+scope)
				return
			}

			// Check user token — admins pass all scope checks
			if uc := ClaimsFromContext(r.Context()); uc != nil {
				if uc.Role == domain.RoleAdmin {
					next.ServeHTTP(w, r)
					return
				}
				writeError(w, http.StatusForbidden, "insufficient_scope", "token missing required scope: "+scope)
				return
			}

			writeError(w, http.StatusUnauthorized, "unauthorized", "missing authorization")
		})
	}
}

// RequireAudience is middleware that checks a service token's aud claim contains
// the expected audience. User tokens pass through (they don't have aud claims).
// This prevents a token issued for service A from being replayed against service B.
func RequireAudience(audience string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sc := ServiceClaimsFromContext(r.Context())
			if sc != nil {
				// Service token — must have matching audience.
				// Audience may be space-delimited if the JWT aud claim is an array.
				matched := false
				for _, a := range strings.Split(sc.Audience, " ") {
					if a == audience {
						matched = true
						break
					}
				}
				if !matched {
					writeError(w, http.StatusForbidden, "invalid_audience", "token audience does not match this service")
					return
				}
			}
			// User tokens and matched service tokens pass through
			next.ServeHTTP(w, r)
		})
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":   code,
		"message": message,
	})
}
