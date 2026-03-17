package api

import (
	"net/http"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/service"
)

// NewRouter builds the /api/v1 mux and wires all handlers.
// userSvc or authSvc may be nil if not needed (used in tests to isolate handler groups).
func NewRouter(issuer *auth.TokenIssuer, authSvc service.AuthServicer, userSvc service.UserServicer) http.Handler {
	mux := http.NewServeMux()

	ah := &authHandler{svc: authSvc}
	uh := &userHandler{svc: userSvc}

	// Auth endpoints — no JWT required except logout and me
	mux.Handle("POST /api/v1/auth/login", http.HandlerFunc(ah.login))
	mux.Handle("POST /api/v1/auth/refresh", http.HandlerFunc(ah.refresh))
	mux.Handle("POST /api/v1/auth/logout", auth.RequireAuth(issuer, http.HandlerFunc(ah.logout)))
	mux.Handle("GET /api/v1/auth/me", auth.RequireAuth(issuer, http.HandlerFunc(ah.me)))

	// User endpoints
	mux.Handle("GET /api/v1/users", auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(uh.list))))
	mux.Handle("POST /api/v1/users", auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(uh.create))))
	mux.Handle("GET /api/v1/users/{id}", auth.RequireAuth(issuer, http.HandlerFunc(uh.get)))
	mux.Handle("PUT /api/v1/users/{id}", auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(uh.update))))
	mux.Handle("DELETE /api/v1/users/{id}", auth.RequireAuth(issuer, auth.RequireAdmin(http.HandlerFunc(uh.delete))))

	return mux
}
