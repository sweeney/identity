package oauth

import (
	"html/template"
	"net/http"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/ui"
)

// route describes one route registered by this router. Routes are served at the
// host root (not under /api/v1). `documented` marks routes that appear in the
// OpenAPI spec; the unflagged ones are server-rendered HTML form/page endpoints
// internal to the login flow and are intentionally absent from the spec. The
// spec path-coverage test (internal/spec) diffs DocumentedPaths() against the
// spec, so a new documented route without a spec entry fails CI.
type route struct {
	method     string
	path       string
	documented bool
}

// routes is the single source of truth for what /oauth and discovery endpoints
// exist. NewRouter registers a handler for each.
func routes() []route {
	return []route{
		{"GET", "/oauth/authorize", true},
		{"POST", "/oauth/authorize", true},
		{"POST", "/oauth/authorize/passkey", false},              // HTML form post
		{"GET", "/oauth/passkey-prompt", false},                  // HTML page
		{"POST", "/oauth/passkey-prompt/register/begin", false},  // HTML flow XHR
		{"POST", "/oauth/passkey-prompt/register/finish", false}, // HTML flow XHR
		{"POST", "/oauth/token", true},
		{"POST", "/oauth/introspect", true},
		{"POST", "/oauth/device_authorization", true},
		{"POST", "/oauth/device/claim", true},
		{"GET", "/oauth/device", true},
		{"POST", "/oauth/device", true},
		{"GET", "/.well-known/oauth-authorization-server", true},
	}
}

// DocumentedPaths returns the deduplicated paths served by this router that must
// appear verbatim as keys in the OpenAPI spec's `paths`. Internal HTML-form
// endpoints are excluded.
func DocumentedPaths() []string {
	seen := make(map[string]bool)
	var paths []string
	for _, r := range routes() {
		if !r.documented || seen[r.path] {
			continue
		}
		seen[r.path] = true
		paths = append(paths, r.path)
	}
	return paths
}

// NewRouter builds the /oauth mux.
// If svc is nil, all routes return 404 (no clients registered).
// tokenIssuer may be nil if passkeys are not enabled.
// authSvc and webauthnSvc are used for the post-login passkey prompt (may be nil).
// deviceSvc enables RFC 8628 device flow endpoints when non-nil.
func NewRouter(svc service.OAuthServicer, trustProxy string, tokenIssuer *auth.TokenIssuer, authSvc service.AuthServicer, webauthnSvc service.WebAuthnServicer, deviceSvc service.DeviceFlowServicer, sessionKey, siteName string) http.Handler {
	if svc == nil {
		return http.NotFoundHandler()
	}

	funcs := template.FuncMap{
		"assetVer": func() string { return ui.AssetVersion },
	}
	baseTmpl := template.Must(
		template.New("base.html").Funcs(funcs).ParseFS(ui.TemplateFS, "templates/base.html"),
	)

	h := &oauthHandler{
		svc:         svc,
		authSvc:     authSvc,
		webauthnSvc: webauthnSvc,
		deviceSvc:   deviceSvc,
		tmpl:        &tmplSet{base: baseTmpl, funcs: funcs},
		trustProxy:  trustProxy,
		tokenIssuer: tokenIssuer,
		sessionKey:  sessionKey,
		siteName:    siteName,
	}

	// handlers maps "METHOD /path" to its handler. Device-flow handlers are
	// absent (and so not registered) when deviceSvc is nil. Every key MUST
	// appear in routes() — the loop below panics otherwise, so a new endpoint
	// cannot be added without a route-table entry.
	handlers := map[string]http.HandlerFunc{
		"GET /oauth/authorize":                        h.authorizeGet,
		"POST /oauth/authorize":                       h.authorizePost,
		"POST /oauth/authorize/passkey":               h.authorizePasskey,
		"GET /oauth/passkey-prompt":                   h.passkeyPrompt,
		"POST /oauth/passkey-prompt/register/begin":   h.passkeyPromptRegisterBegin,
		"POST /oauth/passkey-prompt/register/finish":  h.passkeyPromptRegisterFinish,
		"POST /oauth/token":                           h.token,
		"POST /oauth/introspect":                      h.introspect,
		"GET /.well-known/oauth-authorization-server": h.discovery,
	}

	// Device authorization grant (RFC 8628) — only advertised if enabled.
	if deviceSvc != nil {
		handlers["POST /oauth/device_authorization"] = h.deviceAuthorize
		handlers["POST /oauth/device/claim"] = h.deviceClaim
		handlers["GET /oauth/device"] = h.deviceVerifyGet
		handlers["POST /oauth/device"] = h.deviceVerifyPost
	}

	mux := http.NewServeMux()
	known := make(map[string]bool, len(routes()))
	for _, r := range routes() {
		key := r.method + " " + r.path
		known[key] = true
		if fn, ok := handlers[key]; ok {
			mux.HandleFunc(key, fn)
		}
	}
	for key := range handlers {
		if !known[key] {
			panic("oauth: handler registered for route missing from routes(): " + key)
		}
	}

	return mux
}
