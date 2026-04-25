// Package config contains the HTTP handlers for the config service.
//
// Endpoints (all JSON, all admin-auth except list/get which may be
// user-auth when the namespace's read_role permits):
//
//	GET    /api/v1/config                      → list visible namespaces
//	GET    /api/v1/config/{ns}                 → full document (requires read_role)
//	PUT    /api/v1/config/{ns}                 → replace document (requires write_role)
//	DELETE /api/v1/config/{ns}                 → delete namespace (admin-only)
//	POST   /api/v1/config/namespaces           → create namespace (admin-only)
//	PATCH  /api/v1/config/namespaces/{ns}      → update ACL (admin-only)
//	GET    /healthz                            → unauth health probe
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	"github.com/sweeney/identity/internal/service"
	"github.com/sweeney/identity/internal/spec"
	uiconfig "github.com/sweeney/identity/internal/ui-config"
)

// maxBodyBytes caps the request body size the handlers will read. The
// service layer enforces a 64KB ceiling on the stored document post-
// compaction; accept a bit more so whitespace-padded equivalents still
// fit, but reject pathological payloads at the HTTP boundary.
const maxBodyBytes = 128 * 1024

// Router exposes the config service's HTTP handlers. It is an
// http.Handler whose dispatch table is built once in NewRouter.
type Router struct {
	mux *http.ServeMux
}

// ServeHTTP implements http.Handler.
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mux.ServeHTTP(w, req)
}

// Deps bundles the service and auth dependencies the router needs.
type Deps struct {
	Service  *service.ConfigService
	Verifier auth.TokenParser
	Version  string // populated into /healthz for parity with identity

	// SPA bootstrap. When IdentityPublicURL is non-empty the admin UI
	// is mounted at "/" and the bootstrap config is served at
	// /spa-config.json. Leave both empty to disable the UI entirely
	// (the API stays up regardless).
	IdentityPublicURL string
	OAuthClientID     string
}

// NewRouter builds the config service router. The service layer holds the
// data / business logic; the verifier validates Bearer tokens via JWKS
// (or an in-process *TokenIssuer in tests).
func NewRouter(d Deps) *Router {
	mux := http.NewServeMux()

	// Unauth health check so systemd and load balancers can probe the
	// process without a token. The body is deliberately minimal — exposing
	// a build version here would turn every exposed endpoint into a
	// vulnerability fingerprint for scanners. The version is still
	// surfaced internally via logs at startup (see runConfigServer) and
	// via the /openapi.json spec version.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok"}`)
	})
	_ = d.Version // kept in Deps for parity with identity; not echoed at /healthz

	// OpenAPI spec — unauth, served as YAML or JSON.
	mux.HandleFunc("GET /openapi.yaml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(spec.ConfigYAML)
	})
	mux.HandleFunc("GET /openapi.json", func(w http.ResponseWriter, r *http.Request) {
		data, err := spec.ConfigJSON()
		if err != nil {
			http.Error(w, "spec unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})

	authed := func(h http.HandlerFunc) http.Handler {
		return auth.RequireAuth(d.Verifier, requireUserToken(h))
	}

	mux.Handle("GET /api/v1/config", authed(listHandler(d.Service)))
	mux.Handle("GET /api/v1/config/{ns}", authed(getHandler(d.Service)))
	mux.Handle("PUT /api/v1/config/{ns}", authed(putHandler(d.Service)))
	mux.Handle("DELETE /api/v1/config/{ns}", authed(deleteHandler(d.Service)))
	mux.Handle("POST /api/v1/config/namespaces", authed(createHandler(d.Service)))
	mux.Handle("PATCH /api/v1/config/namespaces/{ns}", authed(updateACLHandler(d.Service)))

	// SPA bundle (optional — only mounted when an OAuth client is configured).
	if d.IdentityPublicURL != "" && d.OAuthClientID != "" {
		mountSPA(mux, d.IdentityPublicURL, d.OAuthClientID)
	}

	return &Router{mux: mux}
}

// mountSPA wires the admin UI at /, the static asset tree at /static/*,
// and the bootstrap config at /spa-config.json. All three are unauth —
// authentication is performed entirely client-side via PKCE.
//
// index.html is rendered as a Go template once at construction so
// /static/*.js URLs carry ?v={{AssetVer}} cache-busters. Without that,
// browsers cache the JS bundle indefinitely and a deploy goes
// unnoticed until the user clears their cache. Static assets
// themselves are served from the embedded FS with directory listings
// disabled — http.FileServer's default of rendering an HTML index
// for a directory request would otherwise enumerate every embedded
// file at GET /static/.
func mountSPA(mux *http.ServeMux, identityURL, clientID string) {
	indexBytes, err := uiconfig.StaticFS.ReadFile("static/index.html")
	if err != nil {
		indexBytes = []byte("config admin UI assets missing")
	}
	indexTmpl, tmplErr := template.New("index").Parse(string(indexBytes))

	// Pre-render once: AssetVer is fixed for the process lifetime so
	// there's no need to execute the template on every request.
	var indexRendered []byte
	if tmplErr == nil {
		var buf bytes.Buffer
		if err := indexTmpl.Execute(&buf, struct{ AssetVer string }{uiconfig.AssetVersion}); err == nil {
			indexRendered = buf.Bytes()
		}
	}
	if indexRendered == nil {
		indexRendered = indexBytes // fall back to literal bytes; cache-busting will be a no-op
	}

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		// Reject anything other than the root path so unknown routes
		// don't accidentally render the SPA shell with a 200.
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		_, _ = w.Write(indexRendered)
	})

	staticSub, _ := fs.Sub(uiconfig.StaticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", noListing(http.FileServer(http.FS(staticSub)))))

	mux.HandleFunc("GET /spa-config.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-cache")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"identity_url": identityURL,
			"client_id":    clientID,
		})
	})
}

// noListing wraps an http.FileServer so directory paths return 404
// instead of an auto-generated HTML index. The check is path-shape
// only — Go's mux + StripPrefix already canonicalise away ".." escapes
// before the request reaches us.
func noListing(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "" || strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// requireUserToken rejects requests that authed with a service token AND
// requests whose user token carries an unrecognised role claim. Config
// endpoints are user-only for v1 (admin users for writes; users for
// reads of user-role namespaces). The role whitelist is defence-in-depth:
// today roleAllows silently denies unknown roles, but an attacker-shaped
// role string flowing into policy is a bug surface we can close cheaply.
func requireUserToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := auth.ClaimsFromContext(r.Context())
		if c == nil {
			writeErr(w, http.StatusForbidden, "forbidden", "user token required")
			return
		}
		role := string(c.Role)
		if role != domain.ConfigRoleAdmin && role != domain.ConfigRoleUser {
			writeErr(w, http.StatusForbidden, "forbidden", "unrecognised role in token")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// callerFromRequest extracts the config service Caller from the request
// context. RequireAuth + requireUserToken guarantee the claims are
// non-nil and carry a whitelisted role by the time this runs.
func callerFromRequest(r *http.Request) service.Caller {
	c := auth.ClaimsFromContext(r.Context())
	return service.Caller{Sub: c.UserID, Role: string(c.Role)}
}

// --- handlers ---

func listHandler(svc *service.ConfigService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := callerFromRequest(r)
		list, err := svc.ListVisible(caller)
		if err != nil {
			translateError(w, err)
			return
		}
		type item struct {
			Name      string `json:"name"`
			ReadRole  string `json:"read_role"`
			WriteRole string `json:"write_role"`
			UpdatedAt string `json:"updated_at"`
			CreatedAt string `json:"created_at"`
		}
		out := make([]item, 0, len(list))
		for _, ns := range list {
			out = append(out, item{
				Name:      ns.Name,
				ReadRole:  ns.ReadRole,
				WriteRole: ns.WriteRole,
				UpdatedAt: ns.UpdatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
				CreatedAt: ns.CreatedAt.UTC().Format("2006-01-02T15:04:05.000Z"),
			})
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func getHandler(svc *service.ConfigService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("ns")
		caller := callerFromRequest(r)
		got, err := svc.Get(caller, ns)
		if err != nil {
			translateError(w, err)
			return
		}
		// Return the raw stored document so callers can parse it with a
		// plain JSON decoder. The document is validated as a JSON object
		// on the write path.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(got.Document)
	}
}

func putHandler(svc *service.ConfigService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("ns")
		caller := callerFromRequest(r)

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			writeErr(w, http.StatusRequestEntityTooLarge, "request_too_large", "request body exceeds size limit")
			return
		}
		changed, err := svc.PutDocument(caller, ns, body)
		if err != nil {
			translateError(w, err)
			return
		}
		// 200 either way — callers that care about change detection read
		// resp.changed. A single status simplifies scripting.
		writeJSON(w, http.StatusOK, map[string]any{
			"name":    ns,
			"changed": changed,
		})
	}
}

func deleteHandler(svc *service.ConfigService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("ns")
		caller := callerFromRequest(r)
		if err := svc.Delete(caller, ns); err != nil {
			translateError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

type createBody struct {
	Name      string          `json:"name"`
	ReadRole  string          `json:"read_role"`
	WriteRole string          `json:"write_role"`
	Document  json.RawMessage `json:"document"`
}

func createHandler(svc *service.ConfigService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		caller := callerFromRequest(r)

		var b createBody
		if err := decodeBody(r, &b); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
		doc := []byte(b.Document)
		if len(doc) == 0 {
			doc = []byte(`{}`)
		}
		ns, err := svc.CreateNamespace(caller, service.CreateNamespaceInput{
			Name:      b.Name,
			ReadRole:  b.ReadRole,
			WriteRole: b.WriteRole,
			Document:  doc,
		})
		if err != nil {
			translateError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]string{
			"name":       ns.Name,
			"read_role":  ns.ReadRole,
			"write_role": ns.WriteRole,
		})
	}
}

type aclBody struct {
	ReadRole  string `json:"read_role"`
	WriteRole string `json:"write_role"`
}

func updateACLHandler(svc *service.ConfigService) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns := r.PathValue("ns")
		caller := callerFromRequest(r)

		var b aclBody
		if err := decodeBody(r, &b); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
			return
		}
		if err := svc.UpdateACL(caller, ns, b.ReadRole, b.WriteRole); err != nil {
			translateError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"name":       ns,
			"read_role":  b.ReadRole,
			"write_role": b.WriteRole,
		})
	}
}

// --- helpers ---

func decodeBody(r *http.Request, into any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"message": message,
	})
}

// translateError maps service-layer errors to HTTP responses that match the
// identity error envelope conventions.
func translateError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrConfigNamespaceNotFound):
		writeErr(w, http.StatusNotFound, "not_found", "namespace not found")
	case errors.Is(err, service.ErrConfigNamespaceExists):
		writeErr(w, http.StatusConflict, "conflict", "namespace already exists")
	case errors.Is(err, service.ErrConfigForbidden):
		writeErr(w, http.StatusForbidden, "forbidden", "insufficient role for this operation")
	case errors.Is(err, service.ErrConfigInvalidName):
		writeErr(w, http.StatusBadRequest, "invalid_name",
			"namespace name must match ^[a-z0-9_-]{1,64}$")
	case errors.Is(err, service.ErrConfigInvalidRole):
		writeErr(w, http.StatusBadRequest, "invalid_role",
			"role must be 'admin' or 'user'")
	case errors.Is(err, service.ErrConfigInvalidDocument):
		writeErr(w, http.StatusBadRequest, "invalid_document",
			"document must be a JSON object")
	case errors.Is(err, service.ErrConfigDocumentTooLarge):
		writeErr(w, http.StatusRequestEntityTooLarge, "document_too_large",
			"document exceeds size limit")
	default:
		writeErr(w, http.StatusInternalServerError, "internal_error", "internal error")
	}
}

// Compile-time assertion that Router implements http.Handler.
var _ http.Handler = (*Router)(nil)
