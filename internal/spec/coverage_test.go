package spec_test

import (
	"encoding/json"
	"sort"
	"testing"

	apihandler "github.com/sweeney/identity/internal/handler/api"
	oauthhandler "github.com/sweeney/identity/internal/handler/oauth"
	"github.com/sweeney/identity/internal/spec"
)

// TestOpenAPIPathCoverage cross-references the documented routes registered by
// the API and OAuth routers against the `paths` keys in the OpenAPI spec.
// Adding (or removing) a documented endpoint without updating openapi.yaml — or
// vice versa — fails here. Internal HTML-form endpoints, admin UI, and infra
// routes (/health, /openapi.*, /static, /.well-known/jwks.json, /) are
// intentionally undocumented and are excluded by the routers' DocumentedPaths().
func TestOpenAPIPathCoverage(t *testing.T) {
	// Documented routes, as the single source of truth in the router packages.
	registered := make(map[string]bool)
	for _, p := range apihandler.DocumentedPaths() {
		registered[p] = true
	}
	for _, p := range oauthhandler.DocumentedPaths() {
		registered[p] = true
	}

	// Spec paths.
	data, err := spec.JSON()
	if err != nil {
		t.Fatalf("spec.JSON(): %v", err)
	}
	var doc struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal spec: %v", err)
	}
	inSpec := make(map[string]bool, len(doc.Paths))
	for p := range doc.Paths {
		inSpec[p] = true
	}

	for p := range registered {
		if !inSpec[p] {
			t.Errorf("route %q is registered and documented but missing from the OpenAPI spec", p)
		}
	}
	for p := range inSpec {
		if !registered[p] {
			t.Errorf("path %q is in the OpenAPI spec but not a registered documented route", p)
		}
	}

	if t.Failed() {
		t.Logf("registered documented routes: %v", sortedKeys(registered))
		t.Logf("spec paths: %v", sortedKeys(inSpec))
	}
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
