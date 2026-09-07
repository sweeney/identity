package api

import (
	"context"
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

	// statusProvider re-reads the user's live IsActive/Role on each authenticated
	// request so that disabling or demoting an account takes effect immediately
	// instead of lingering until the (up to 15-minute) access token expires.
	// It is nil-safe: if userSvc is nil (handler-isolation tests) the middleware
	// falls back to trusting the token claims.
	var statusProvider auth.UserStatusProvider
	if userSvc != nil {
		statusProvider = userStatusProvider{svc: userSvc}
	}

	// requireUserAuth wraps a handler with RequireAuth + RequireAudience to ensure:
	// 1. The request has a valid bearer token.
	// 2. The user is still active and their role is current (live DB check).
	// 3. The token was issued for this specific identity server. Service tokens
	//    (client_credentials) always name an audience and must match the issuer
	//    string; user tokens name one when they were minted through the OAuth,
	//    device or claim-code grants, carrying the requesting client's audience,
	//    and must match it too. Only a direct-login token, which names no
	//    audience at all, passes unrestricted. This prevents cross-service token
	//    replay where a token delegated to service-A is used against this API.
	requireUserAuth := func(next http.Handler) http.Handler {
		return auth.RequireAuthWithStatus(issuer, statusProvider, auth.RequireAudience(issuer.Issuer())(next))
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

	// Bound every request body. The auth endpoints are unauthenticated, so
	// anyone can post to them, and the handlers read the body before deciding
	// anything about it — an unbounded read there is free memory pressure for
	// an attacker. Nothing this API accepts needs more than a few kilobytes;
	// the WebAuthn assertion is the largest, and it is far below the cap.
	return limitRequestBody(mux, maxRequestBodyBytes)
}

// maxRequestBodyBytes caps any single request body. Generous next to the
// largest legitimate payload (a WebAuthn assertion), tiny next to what an
// unbounded read allows.
const maxRequestBodyBytes = 256 << 10 // 256 KiB

// limitRequestBody wraps next so that reading past the cap fails rather than
// allocating. The error is surfaced as 413 in the standard envelope, so a
// client sees a code it can act on instead of a decode failure.
func limitRequestBody(next http.Handler, limit int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			// Reject on the declared length before reading a byte, when the
			// client provides one.
			if r.ContentLength > limit {
				jsonError(w, http.StatusRequestEntityTooLarge, "request_too_large",
					"request body is too large")
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}

// userStatusProvider adapts the UserServicer into auth.UserStatusProvider,
// translating a not-found/error lookup into a non-nil error so the middleware
// denies access (e.g. for a since-deleted user).
type userStatusProvider struct {
	svc service.UserServicer
}

func (p userStatusProvider) UserStatus(_ context.Context, userID string) (auth.UserStatus, error) {
	user, err := p.svc.GetByID(userID)
	if err != nil {
		return auth.UserStatus{}, err
	}
	return auth.UserStatus{IsActive: user.IsActive, Role: user.Role}, nil
}
