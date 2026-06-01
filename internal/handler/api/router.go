package api

import (
	"net/http"
	"strings"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/service"
)

// route describes one registered /api/v1 endpoint. Every route is documented in
// the OpenAPI spec; the spec path-coverage test (internal/spec) diffs
// DocumentedPaths() against the spec's paths, so adding a route here without a
// matching spec entry fails CI.
type route struct {
	method string
	// path is the registered pattern, e.g. "/api/v1/users/{id}".
	path string
}

// routes is the single source of truth for what /api/v1 endpoints exist.
// NewRouter registers a handler for each; DocumentedPaths() exposes the
// spec-relative paths (the /api/v1 prefix stripped) for the coverage test.
func routes() []route {
	return []route{
		{"POST", "/api/v1/auth/login"},
		{"POST", "/api/v1/auth/refresh"},
		{"POST", "/api/v1/auth/logout"},
		{"GET", "/api/v1/auth/me"},

		{"GET", "/api/v1/users"},
		{"POST", "/api/v1/users"},
		{"GET", "/api/v1/users/{id}"},
		{"PUT", "/api/v1/users/{id}"},
		{"DELETE", "/api/v1/users/{id}"},

		{"POST", "/api/v1/webauthn/register/begin"},
		{"POST", "/api/v1/webauthn/register/finish"},
		{"POST", "/api/v1/webauthn/login/begin"},
		{"POST", "/api/v1/webauthn/login/finish"},
		{"GET", "/api/v1/webauthn/credentials"},
		{"PATCH", "/api/v1/webauthn/credentials/{id}"},
		{"DELETE", "/api/v1/webauthn/credentials/{id}"},
	}
}

// DocumentedPaths returns the deduplicated, spec-relative paths served by this
// router (the "/api/v1" base-server prefix removed, method stripped). These must
// appear verbatim as keys in the OpenAPI spec's `paths`.
func DocumentedPaths() []string {
	seen := make(map[string]bool)
	var paths []string
	for _, r := range routes() {
		p := strings.TrimPrefix(r.path, "/api/v1")
		if !seen[p] {
			seen[p] = true
			paths = append(paths, p)
		}
	}
	return paths
}

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

	// handlers maps "METHOD /path" to the handler for that route. Routes whose
	// handler is absent (e.g. WebAuthn when webauthnSvc is nil) are simply not
	// registered. Every key here MUST appear in routes() — the loop below panics
	// otherwise, so a new endpoint cannot be added without a route-table entry.
	handlers := map[string]http.Handler{
		// Auth endpoints — no JWT required except logout and me
		"POST /api/v1/auth/login":   http.HandlerFunc(ah.login),
		"POST /api/v1/auth/refresh": http.HandlerFunc(ah.refresh),
		"POST /api/v1/auth/logout":  requireUserAuth(http.HandlerFunc(ah.logout)),
		"GET /api/v1/auth/me":       requireUserAuth(http.HandlerFunc(ah.me)),

		// User endpoints
		"GET /api/v1/users":         requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.list))),
		"POST /api/v1/users":        requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.create))),
		"GET /api/v1/users/{id}":    requireUserAuth(http.HandlerFunc(uh.get)),
		"PUT /api/v1/users/{id}":    requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.update))),
		"DELETE /api/v1/users/{id}": requireUserAuth(auth.RequireAdmin(http.HandlerFunc(uh.delete))),
	}

	// WebAuthn / Passkey endpoints
	if webauthnSvc != nil {
		wh := &webauthnHandler{svc: webauthnSvc, trustProxy: trustProxy}

		// Registration (requires JWT — user must be logged in)
		handlers["POST /api/v1/webauthn/register/begin"] = requireUserAuth(http.HandlerFunc(wh.registerBegin))
		handlers["POST /api/v1/webauthn/register/finish"] = requireUserAuth(http.HandlerFunc(wh.registerFinish))

		// Authentication (no JWT required — this IS the login)
		handlers["POST /api/v1/webauthn/login/begin"] = http.HandlerFunc(wh.loginBegin)
		handlers["POST /api/v1/webauthn/login/finish"] = http.HandlerFunc(wh.loginFinish)

		// Credential management (requires JWT)
		handlers["GET /api/v1/webauthn/credentials"] = requireUserAuth(http.HandlerFunc(wh.listCredentials))
		handlers["PATCH /api/v1/webauthn/credentials/{id}"] = requireUserAuth(http.HandlerFunc(wh.renameCredential))
		handlers["DELETE /api/v1/webauthn/credentials/{id}"] = requireUserAuth(http.HandlerFunc(wh.deleteCredential))
	}

	known := make(map[string]bool, len(routes()))
	for _, r := range routes() {
		known[r.method+" "+r.path] = true
		if h, ok := handlers[r.method+" "+r.path]; ok {
			mux.Handle(r.method+" "+r.path, h)
		}
	}
	for key := range handlers {
		if !known[key] {
			panic("api: handler registered for route missing from routes(): " + key)
		}
	}

	return mux
}
