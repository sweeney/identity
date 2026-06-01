package main

import (
	"net/http"

	"github.com/sweeney/identity/internal/spec"
)

// specYAMLHandler serves the OpenAPI spec as YAML. The spec is public and
// non-sensitive, so it carries Access-Control-Allow-Origin: * to let
// browser-based viewers (Swagger UI, Stoplight, etc.) fetch it cross-origin.
func specYAMLHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/yaml")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(spec.YAML) //nolint:errcheck
}

// specJSONHandler serves the OpenAPI spec as JSON, with the same public CORS
// header as specYAMLHandler.
func specJSONHandler(w http.ResponseWriter, r *http.Request) {
	data, err := spec.JSON()
	if err != nil {
		http.Error(w, "spec unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(data) //nolint:errcheck
}
