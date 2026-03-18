package spec

import (
	_ "embed"
	"encoding/json"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed openapi.yaml
var YAML []byte

var (
	jsonOnce sync.Once
	jsonData []byte
	jsonErr  error
)

// JSON returns the OpenAPI spec as JSON, converted from the embedded YAML.
// The conversion is performed once and cached.
func JSON() ([]byte, error) {
	jsonOnce.Do(func() {
		var v any
		if err := yaml.Unmarshal(YAML, &v); err != nil {
			jsonErr = err
			return
		}
		jsonData, jsonErr = json.MarshalIndent(v, "", "  ")
	})
	return jsonData, jsonErr
}
