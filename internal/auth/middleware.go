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

// RequireAuth is an HTTP middleware that validates the Bearer token in the
// Authorization header and injects the claims into the request context.
// Returns 401 if the token is missing or invalid, 403 if the user is inactive.
func RequireAuth(issuer *TokenIssuer, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized", "missing authorization header")
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			writeError(w, http.StatusUnauthorized, "unauthorized", "invalid authorization header format")
			return
		}

		claims, err := issuer.Parse(parts[1])
		if err != nil {
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

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"error":   code,
		"message": message,
	})
}
