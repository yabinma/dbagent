package toolpack

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/santhosh-tekuri/jsonschema/v5"
)

// ValidateParams validates args against a parsed JSON Schema (as produced
// by LoadCategory), per design.md Appendix B: "Every tool's params object
// sets additionalProperties: false."
func ValidateParams(schema map[string]any, args map[string]any) error {
	compiler := jsonschema.NewCompiler()
	raw, err := json.Marshal(schema)
	if err != nil {
		return fmt.Errorf("toolpack: marshal schema: %w", err)
	}
	if err := compiler.AddResource("params.json", bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("toolpack: load schema: %w", err)
	}
	compiled, err := compiler.Compile("params.json")
	if err != nil {
		return fmt.Errorf("toolpack: compile schema: %w", err)
	}
	// jsonschema validates against decoded (not typed) data; re-decode
	// args through JSON to normalize numeric types the same way a
	// wire-decoded google.protobuf.Struct would.
	normalized, err := normalizeViaJSON(args)
	if err != nil {
		return err
	}
	if err := compiled.Validate(normalized); err != nil {
		return fmt.Errorf("params validation failed: %w", err)
	}
	return nil
}

func normalizeViaJSON(v any) (any, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}
