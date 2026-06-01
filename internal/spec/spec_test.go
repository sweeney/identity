package spec

import (
	"encoding/json"
	"strings"
	"testing"
)

// Root-served endpoints (/oauth/*, /.well-known/*) live at the host root, not
// under the /api/v1 base server URL. Each must carry a per-path `servers`
// override so OpenAPI tooling resolves their URLs correctly instead of
// prepending /api/v1 (which would 404). See openapi.yaml `x-servers-root`.
func TestRootServedPathsOverrideServer(t *testing.T) {
	data, err := JSON()
	if err != nil {
		t.Fatalf("JSON(): %v", err)
	}
	var doc struct {
		Paths map[string]struct {
			Servers []struct {
				URL string `json:"url"`
			} `json:"servers"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rootServed := []string{
		"/oauth/authorize",
		"/oauth/token",
		"/oauth/device_authorization",
		"/oauth/device/claim",
		"/oauth/device",
		"/oauth/introspect",
		"/.well-known/oauth-authorization-server",
	}
	for _, p := range rootServed {
		item, ok := doc.Paths[p]
		if !ok {
			t.Errorf("path %s missing from spec", p)
			continue
		}
		if len(item.Servers) == 0 {
			t.Errorf("%s: expected a per-path servers override, got none", p)
			continue
		}
		if got := item.Servers[0].URL; strings.Contains(got, "/api/v1") {
			t.Errorf("%s: server URL %q must not include /api/v1", p, got)
		}
	}

	// /api/v1 paths must NOT override the base server.
	for _, p := range []string{"/auth/login", "/users", "/webauthn/login/begin"} {
		if len(doc.Paths[p].Servers) != 0 {
			t.Errorf("%s: should inherit the /api/v1 base server, not override it", p)
		}
	}
}
