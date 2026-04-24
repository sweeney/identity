package config_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sweeney/identity/internal/auth"
	"github.com/sweeney/identity/internal/domain"
	confighandler "github.com/sweeney/identity/internal/handler/config"
	"github.com/sweeney/identity/internal/service"
)

// fakeRepo is an in-memory ConfigRepository — duplicated from the service
// tests rather than sharing to keep this test file self-contained.
type fakeRepo struct {
	mu   sync.Mutex
	data map[string]*domain.ConfigNamespace
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{data: map[string]*domain.ConfigNamespace{}}
}

func (r *fakeRepo) List() ([]domain.ConfigNamespaceSummary, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]domain.ConfigNamespaceSummary, 0, len(r.data))
	for _, ns := range r.data {
		out = append(out, domain.ConfigNamespaceSummary{
			Name: ns.Name, ReadRole: ns.ReadRole, WriteRole: ns.WriteRole,
			UpdatedAt: ns.UpdatedAt, CreatedAt: ns.CreatedAt,
		})
	}
	return out, nil
}
func (r *fakeRepo) Get(name string) (*domain.ConfigNamespace, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ns, ok := r.data[name]
	if !ok {
		return nil, domain.ErrNotFound
	}
	c := *ns
	return &c, nil
}
func (r *fakeRepo) Create(ns *domain.ConfigNamespace) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.data[ns.Name]; ok {
		return domain.ErrConflict
	}
	c := *ns
	r.data[ns.Name] = &c
	return nil
}
func (r *fakeRepo) UpdateDocument(name string, document []byte, updatedBy string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ns, ok := r.data[name]
	if !ok {
		return domain.ErrNotFound
	}
	ns.Document = append(ns.Document[:0], document...)
	ns.UpdatedBy = updatedBy
	ns.UpdatedAt = at
	return nil
}
func (r *fakeRepo) UpdateACL(name, rRole, wRole string, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	ns, ok := r.data[name]
	if !ok {
		return domain.ErrNotFound
	}
	ns.ReadRole, ns.WriteRole, ns.UpdatedAt = rRole, wRole, at
	return nil
}
func (r *fakeRepo) Delete(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.data[name]; !ok {
		return domain.ErrNotFound
	}
	delete(r.data, name)
	return nil
}

type fakeBackup struct{}

func (fakeBackup) TriggerAsync() {}
func (fakeBackup) RunNow() error { return nil }

type harness struct {
	t        *testing.T
	issuer   *auth.TokenIssuer
	repo     *fakeRepo
	srv      *httptest.Server
	adminTok string
	userTok  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	key, err := auth.GenerateKey()
	require.NoError(t, err)
	issuer, err := auth.NewTokenIssuer(key, nil, "https://test", 5*time.Minute)
	require.NoError(t, err)

	repo := newFakeRepo()
	svc := service.NewConfigService(repo, fakeBackup{})
	router := confighandler.NewRouter(confighandler.Deps{
		Service:  svc,
		Verifier: issuer, // *TokenIssuer satisfies auth.TokenParser in-process
		Version:  "test",
	})
	srv := httptest.NewServer(router)
	t.Cleanup(srv.Close)

	mint := func(role domain.Role, sub string) string {
		tok, err := issuer.Mint(domain.TokenClaims{
			UserID: sub, Username: sub, Role: role, IsActive: true,
		})
		require.NoError(t, err)
		return tok
	}
	return &harness{
		t:        t,
		issuer:   issuer,
		repo:     repo,
		srv:      srv,
		adminTok: mint(domain.RoleAdmin, "admin-1"),
		userTok:  mint(domain.RoleUser, "user-1"),
	}
}

// do sends an HTTP request with an optional Bearer token and a JSON body.
func (h *harness) do(method, path, token string, body any) (*http.Response, []byte) {
	h.t.Helper()
	var buf io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			buf = strings.NewReader(v)
		case []byte:
			buf = bytes.NewReader(v)
		default:
			b, err := json.Marshal(v)
			require.NoError(h.t, err)
			buf = bytes.NewReader(b)
		}
	}
	req, err := http.NewRequest(method, h.srv.URL+path, buf)
	require.NoError(h.t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(h.t, err)
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, out
}

// --- Auth boundary ---

func TestHealthz_Unauth(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("GET", "/healthz", "", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, string(body), `"status":"ok"`)
}

func TestList_MissingAuth_ReturnsUnauthorized(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do("GET", "/api/v1/config", "", nil)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestList_ServiceToken_Rejected(t *testing.T) {
	h := newHarness(t)
	svcTok, err := h.issuer.MintServiceToken(domain.ServiceTokenClaims{
		ClientID: "svc", Audience: "config",
	}, 5*time.Minute)
	require.NoError(t, err)
	resp, _ := h.do("GET", "/api/v1/config", svcTok, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"config v1 rejects service tokens; user tokens only")
}

// --- Create ---

func TestCreate_AdminSucceeds(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do("POST", "/api/v1/config/namespaces", h.adminTok, map[string]any{
		"name":       "houses",
		"read_role":  "admin",
		"write_role": "admin",
		"document":   json.RawMessage(`{"main":"Rivendell"}`),
	})
	assert.Equal(t, http.StatusCreated, resp.StatusCode)
}

func TestCreate_UserForbidden(t *testing.T) {
	h := newHarness(t)
	resp, _ := h.do("POST", "/api/v1/config/namespaces", h.userTok, map[string]any{
		"name": "prefs", "read_role": "user", "write_role": "user",
		"document": json.RawMessage(`{}`),
	})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestCreate_InvalidName(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("POST", "/api/v1/config/namespaces", h.adminTok, map[string]any{
		"name": "BAD NAME", "read_role": "admin", "write_role": "admin",
		"document": json.RawMessage(`{}`),
	})
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "invalid_name")
}

func TestCreate_Duplicate_Conflict(t *testing.T) {
	h := newHarness(t)
	body := map[string]any{
		"name": "dup", "read_role": "admin", "write_role": "admin",
		"document": json.RawMessage(`{}`),
	}
	resp, _ := h.do("POST", "/api/v1/config/namespaces", h.adminTok, body)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	resp, _ = h.do("POST", "/api/v1/config/namespaces", h.adminTok, body)
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
}

// --- Get / List with role gating ---

func TestGet_UserBlockedFromAdminNamespace_Returns404(t *testing.T) {
	h := newHarness(t)
	// Seed an admin-only namespace directly via the repo.
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "secret", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))
	resp, _ := h.do("GET", "/api/v1/config/secret", h.userTok, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"user must see 404 not 403, to avoid leaking namespace existence")
}

func TestGet_UserCanReadUserNamespace(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "prefs", ReadRole: "user", WriteRole: "admin",
		Document: []byte(`{"theme":"dark"}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))
	resp, body := h.do("GET", "/api/v1/config/prefs", h.userTok, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"theme":"dark"}`, string(body))
}

func TestList_FiltersByVisibility(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	for _, ns := range []domain.ConfigNamespace{
		{Name: "hidden", ReadRole: "admin", WriteRole: "admin"},
		{Name: "visible", ReadRole: "user", WriteRole: "admin"},
	} {
		n := ns
		n.Document = []byte(`{}`)
		n.UpdatedAt, n.CreatedAt = now, now
		n.UpdatedBy = "u"
		require.NoError(t, h.repo.Create(&n))
	}

	resp, body := h.do("GET", "/api/v1/config", h.userTok, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var out []map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	require.Len(t, out, 1)
	assert.Equal(t, "visible", out[0]["name"])
}

// --- PUT ---

func TestPut_WriteRoleEnforced(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "shared", ReadRole: "user", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))

	// User can READ but not WRITE → 403 (since they can read it, we don't pretend it's 404)
	resp, _ := h.do("PUT", "/api/v1/config/shared", h.userTok, json.RawMessage(`{"x":1}`))
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	// Admin can write → 200
	resp, _ = h.do("PUT", "/api/v1/config/shared", h.adminTok, json.RawMessage(`{"x":1}`))
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// GET returns updated document
	resp, body := h.do("GET", "/api/v1/config/shared", h.userTok, nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.JSONEq(t, `{"x":1}`, string(body))
}

func TestPut_UserBlockedFromInvisibleNamespace_Returns404(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "secret", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))

	resp, _ := h.do("PUT", "/api/v1/config/secret", h.userTok, json.RawMessage(`{"x":1}`))
	assert.Equal(t, http.StatusNotFound, resp.StatusCode,
		"invisible-to-user namespace must 404, not 403, on write attempt")
}

func TestPut_InvalidDocument_Returns400(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "n", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))
	resp, body := h.do("PUT", "/api/v1/config/n", h.adminTok, "[]")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "invalid_document")
}

func TestPut_NoOp_ReturnsChangedFalse(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "n", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{"a":1}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))
	resp, body := h.do("PUT", "/api/v1/config/n", h.adminTok, json.RawMessage(`{"a":1}`))
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var out map[string]any
	require.NoError(t, json.Unmarshal(body, &out))
	assert.Equal(t, false, out["changed"])
}

func TestPut_OversizedBody_Returns413(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "n", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))
	// Build a JSON object larger than the handler's 128KB body cap.
	big := &strings.Builder{}
	big.WriteString(`{"k":"`)
	for i := 0; i < 200_000; i++ {
		big.WriteByte('x')
	}
	big.WriteString(`"}`)
	resp, _ := h.do("PUT", "/api/v1/config/n", h.adminTok, big.String())
	assert.Equal(t, http.StatusRequestEntityTooLarge, resp.StatusCode)
}

// --- PATCH ACL ---

func TestPatchACL_AdminOnly(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "n", ReadRole: "admin", WriteRole: "admin",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))

	resp, _ := h.do("PATCH", "/api/v1/config/namespaces/n", h.userTok,
		map[string]string{"read_role": "user", "write_role": "admin"})
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)

	resp, _ = h.do("PATCH", "/api/v1/config/namespaces/n", h.adminTok,
		map[string]string{"read_role": "user", "write_role": "admin"})
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

// --- DELETE ---

func TestDelete_AdminOnly(t *testing.T) {
	h := newHarness(t)
	now := time.Now().UTC()
	require.NoError(t, h.repo.Create(&domain.ConfigNamespace{
		Name: "n", ReadRole: "user", WriteRole: "user",
		Document: []byte(`{}`), UpdatedAt: now, UpdatedBy: "u", CreatedAt: now,
	}))

	resp, _ := h.do("DELETE", "/api/v1/config/n", h.userTok, nil)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode,
		"user must not delete even namespaces they can write")

	resp, _ = h.do("DELETE", "/api/v1/config/n", h.adminTok, nil)
	assert.Equal(t, http.StatusNoContent, resp.StatusCode)

	resp, _ = h.do("GET", "/api/v1/config/n", h.adminTok, nil)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// --- Malformed requests ---

func TestCreate_MalformedJSON_Returns400(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("POST", "/api/v1/config/namespaces", h.adminTok, "{not json}")
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	assert.Contains(t, string(body), "invalid_request")
}

// --- OpenAPI ---

func TestOpenAPI_YAML_Unauth(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("GET", "/openapi.yaml", "", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "yaml")
	assert.Contains(t, string(body), "openapi:")
	assert.Contains(t, string(body), "Config API")
}

func TestOpenAPI_JSON_Unauth(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("GET", "/openapi.json", "", nil)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Contains(t, resp.Header.Get("Content-Type"), "json")
	var v map[string]any
	require.NoError(t, json.Unmarshal(body, &v), "openapi.json must decode")
	assert.Equal(t, "3.0.3", v["openapi"])
	assert.Contains(t, v["info"].(map[string]any)["title"], "Config")
}

// Sanity: we don't leak a stack trace in errors.
func TestErrors_NoInternalLeaks(t *testing.T) {
	h := newHarness(t)
	resp, body := h.do("GET", "/api/v1/config/missing", h.adminTok, nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode)
	var out map[string]string
	require.NoError(t, json.Unmarshal(body, &out))
	assert.NotContains(t, out["message"], "sql",
		"error envelope must not leak database error text")
	assert.NotContains(t, out["message"], "panic",
		"error envelope must not leak internal state")
	_ = fmt.Sprint // keep import hint explicit
}
