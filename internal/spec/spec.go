package spec

import (
	_ "embed"

	commonspec "github.com/sweeney/identity/common/spec"
)

//go:embed openapi.yaml
var YAML []byte

var identityConv *commonspec.Converter

func init() {
	identityConv = commonspec.NewConverter(YAML)
}

// JSON returns the identity OpenAPI spec as JSON, converted from the embedded YAML.
func JSON() ([]byte, error) { return identityConv.JSON() }
