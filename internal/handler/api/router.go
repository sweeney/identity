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

	// requireUserAuth wraps a handler with RequireAuth + RequireAudience to ensure:
	// 1. The request has a valid bearer token.
	// 2. Service tokens (client_credentials) are rejected unless they were issued for this
	//    specific identity server (audience must match the issuer string). This prevents
	//    cross-service token replay where a token for service-A is used against this API.
	requireUserAuth := func(next http.Handler) http.Handler {
		return auth.RequireAuth(issuer, auth.RequireAudience(issuer.Issuer())(next))
	}

	// Auth endpoints — no JWT required except logout and me
	mux.Handle("POST /api/v1/auth/login", http.HandlerFunc(ah.login))
	mux.Handle("POST /api/v1/auth/refresh", http.HandlerFunc(ah.refresh))
	mux.Handle("POST /api/v1/auth/logout", requireUserAuth(http.HandlerFunc(ah.logout)))
	mux.Handle("GET /api/v1/auth/me", requireUserAuth(http.HandlerFunc(ah.me)))

	// User endpoints
	mux.Handle("GET /api/v1/users", requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.list))))
	mux.Handle("POST /api/v1/users", requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.create))))
	mux.Handle("GET /api/v1/users/{id}", requireUserAuth(http.HandlerFunc(uh.get)))
	mux.Handle("PUT /api/v1/users/{id}", requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.update))))
	mux.Handle("DELETE /api/v1/users/{id}", requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.delete))))

	// WebAuthn / Passkey endpoints
	if webauthnSvc != nil {
		wh := &webauthnHandler{svc: webauthnSvc, trustProxy: trustProxy}

		// Registration (requires JWT — user must be logged in)
		mux.Handle("POST /api/v1/webauthn/register/begin", requireUserAuth(http.HandlerFunc(wh.registerBegin)))
		mux.Handle("POST /api/v1/webauthn/register/finish", requireUserAuth(http.HandlerFunc(wh.registerFinish)))

		// Authentication (no JWT required — this IS the login)
		mux.Handle("POST /api/v1/webauthn/login/begin", http.HandlerFunc(wh.loginBegin))
		mux.Handle("POST /api/v1/webauthn/login/finish", http.HandlerFunc(wh.loginFinish))

		// Credential management (requires JWT)
		mux.Handle("GET /api/v1/webauthn/credentials", requireUserAuth(http.HandlerFunc(wh.listCredentials)))
		mux.Handle("PATCH /api/v1/webauthn/credentials/{id}", requireUserAuth(http.HandlerFunc(wh.renameCredential)))
		mux.Handle("DELETE /api/v1/webauthn/credentials/{id}", requireUserAuth(http.HandlerFunc(wh.deleteCredential)))
	}

	return mux
}
