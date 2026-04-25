package spec

import (
	_ "embed"
	"encoding/json"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed openapi.yaml
var YAML []byte

//go:embed config-openapi.yaml
var ConfigYAML []byte

var (
	jsonOnce sync.Once
	jsonData []byte
	jsonErr  error

	configJSONOnce sync.Once
	configJSONData []byte
	configJSONErr  error
)

// JSON returns the identity OpenAPI spec as JSON, converted from the
// embedded YAML. The conversion is performed once and cached.
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

// ConfigJSON returns the config service OpenAPI spec as JSON.
func ConfigJSON() ([]byte, error) {
	configJSONOnce.Do(func() {
		var v any
		if err := yaml.Unmarshal(ConfigYAML, &v); err != nil {
			configJSONErr = err
			return
		}
		configJSONData, configJSONErr = json.MarshalIndent(v, "", "  ")
	})
	return configJSONData, configJSONErr
}
