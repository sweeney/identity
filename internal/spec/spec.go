package spec

import (
	_ "embed"

	commonspec "github.com/sweeney/identity/common/spec"
)

//go:embed openapi.yaml
var YAML []byte

//go:embed config-openapi.yaml
var ConfigYAML []byte

var (
	identityConv *commonspec.Converter
	configConv   *commonspec.Converter
)

func init() {
	identityConv = commonspec.NewConverter(YAML)
	configConv = commonspec.NewConverter(ConfigYAML)
}

// JSON returns the identity OpenAPI spec as JSON, converted from the embedded YAML.
func JSON() ([]byte, error) { return identityConv.JSON() }

// ConfigJSON returns the config service OpenAPI spec as JSON.
func ConfigJSON() ([]byte, error) { return configConv.JSON() }
