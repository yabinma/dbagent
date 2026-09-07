// Package toolpack provides the generic tool registry, JSON-Schema param
// validation, uniform result envelope construction, and output-size
// truncation shared by every Toolpack tool (design.md Section 8.5,
// Appendix B), independent of which PlatformAdapter registers tools.
package toolpack

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed schemas/*.json
var schemaFS embed.FS

// categoryFile is a parsed schemas/tools/presto/<category>.schema.json
// file: {"tools": {"<name>": <json-schema>, ...}} or
// {"ops": {"<name>": <json-schema>, ...}, "presto_adjust_memory_config_key_whitelist": [...]}.
type categoryFile struct {
	Tools map[string]map[string]any `json:"tools"`
	Ops   map[string]map[string]any `json:"ops"`
}

// LoadCategory loads and parses one embedded schema file (e.g. "engine",
// "runtime", "host", "writeops" -- matching schemas/tools/presto/<name>.schema.json).
func LoadCategory(name string) (tools map[string]map[string]any, ops map[string]map[string]any, err error) {
	raw, err := schemaFS.ReadFile("schemas/" + name + ".schema.json")
	if err != nil {
		return nil, nil, fmt.Errorf("toolpack: load schema category %q: %w", name, err)
	}
	var cf categoryFile
	if err := json.Unmarshal(raw, &cf); err != nil {
		return nil, nil, fmt.Errorf("toolpack: parse schema category %q: %w", name, err)
	}
	return cf.Tools, cf.Ops, nil
}

// MemoryConfigKeyWhitelist returns the presto.adjust_memory_config
// probe-side parameter whitelist (design.md Appendix B.5).
func MemoryConfigKeyWhitelist() ([]string, error) {
	raw, err := schemaFS.ReadFile("schemas/writeops.schema.json")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Whitelist []string `json:"presto_adjust_memory_config_key_whitelist"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return doc.Whitelist, nil
}
