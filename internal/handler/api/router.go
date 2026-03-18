package api

import (
	"net/http"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/service"
)

// NewRouter builds the /api/v1 mux and wires all handlers.
// userSvc or authSvc may be nil if not needed (used in tests to isolate handler groups).
// webauthnSvc may be nil if passkeys are not enabled.
func NewRouter(issuer *auth.TokenIssuer, authSvc service.AuthServicer, userSvc service.UserServicer, webauthnSvc service.WebAuthnServicer, trustProxy string) http.Handler {
	mux := http.NewServeMux()

	ah := &authHandler{svc: authSvc, trustProxy: trustProxy}
	uh := &userHandler{svc: userSvc, trustProxy: trustProxy}

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

	// WebAuthn / Passkey endpoints
	if webauthnSvc != nil {
		wh := &webauthnHandler{svc: webauthnSvc, trustProxy: trustProxy}

		// Registration (requires JWT — user must be logged in)
		mux.Handle("POST /api/v1/webauthn/register/begin", auth.RequireAuth(issuer, http.HandlerFunc(wh.registerBegin)))
		mux.Handle("POST /api/v1/webauthn/register/finish", auth.RequireAuth(issuer, http.HandlerFunc(wh.registerFinish)))

		// Authentication (no JWT required — this IS the login)
		mux.Handle("POST /api/v1/webauthn/login/begin", http.HandlerFunc(wh.loginBegin))
		mux.Handle("POST /api/v1/webauthn/login/finish", http.HandlerFunc(wh.loginFinish))

		// Credential management (requires JWT)
		mux.Handle("GET /api/v1/webauthn/credentials", auth.RequireAuth(issuer, http.HandlerFunc(wh.listCredentials)))
		mux.Handle("PATCH /api/v1/webauthn/credentials/{id}", auth.RequireAuth(issuer, http.HandlerFunc(wh.renameCredential)))
		mux.Handle("DELETE /api/v1/webauthn/credentials/{id}", auth.RequireAuth(issuer, http.HandlerFunc(wh.deleteCredential)))
	}

	return mux
}
