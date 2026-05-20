package spec

import (
	"encoding/json"
	"sync"

	"gopkg.in/yaml.v3"
)

// Converter converts an embedded OpenAPI YAML to JSON on demand, caching
// the result so the conversion runs at most once per Converter instance.
type Converter struct {
	yamlData []byte
	once     sync.Once
	jsonData []byte
	err      error
}

// NewConverter returns a Converter that will convert yamlData on first JSON call.
func NewConverter(yamlData []byte) *Converter {
	return &Converter{yamlData: yamlData}
}

// YAML returns the raw YAML bytes.
func (c *Converter) YAML() []byte { return c.yamlData }

// JSON converts the YAML to indented JSON, caching the result.
func (c *Converter) JSON() ([]byte, error) {
	c.once.Do(func() {
		var v any
		if err := yaml.Unmarshal(c.yamlData, &v); err != nil {
			c.err = err
			return
		}
		c.jsonData, c.err = json.MarshalIndent(v, "", "  ")
	})
	return c.jsonData, c.err
}
