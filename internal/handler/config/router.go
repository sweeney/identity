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
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/service"
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
}

// NewRouter builds the config service router. The service layer holds the
// data / business logic; the verifier validates Bearer tokens via JWKS
// (or an in-process *TokenIssuer in tests).
func NewRouter(d Deps) *Router {
	mux := http.NewServeMux()

	// Unauth health check so systemd and load balancers can probe the
	// process without a token.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"status":"ok","version":"`+jsonEscape(d.Version)+`"}`)
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

	return &Router{mux: mux}
}

// requireUserToken rejects requests that authed with a service token.
// Config endpoints are user-only for v1 (admin users for writes; users
// for reads of user-role namespaces).
func requireUserToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.ClaimsFromContext(r.Context()) == nil {
			writeErr(w, http.StatusForbidden, "forbidden", "user token required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// callerFromRequest extracts the config service Caller from the request
// context. RequireAuth guarantees ClaimsFromContext is non-nil by this
// point.
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
		resp := map[string]any{"name": ns, "changed": changed}
		status := http.StatusOK
		if !changed {
			// 200 either way — callers that care about change detection
			// read resp.changed. Keeping status 200 simplifies scripting.
			status = http.StatusOK
		}
		writeJSON(w, status, resp)
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

// jsonEscape minimally escapes a string for embedding in a static JSON
// literal (used only by /healthz to avoid a json.Encode allocation).
func jsonEscape(s string) string {
	b, _ := json.Marshal(s)
	// marshaled string includes quotes; strip them
	if len(b) >= 2 {
		return string(b[1 : len(b)-1])
	}
	return s
}

// Compile-time assertion that Router implements http.Handler.
var _ http.Handler = (*Router)(nil)
