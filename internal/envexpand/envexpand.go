// Package envexpand expands ${ENV_VAR} placeholders in decoded YAML scalar
// nodes (design.md Section 11.1.3 FP-M6-10). Semantics match
// rca_common.config._interpolate: only ${NAME} where NAME is
// [A-Za-z_][A-Za-z0-9_]*; undefined vars resolve to the empty string; no $$
// escape. Expansion runs after YAML parsing so secret values containing
// YAML-significant characters stay safe.
package envexpand

import (
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

// envVarRE matches ${VAR} with the same shape as Python's _ENV_VAR_RE.
var envVarRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// ExpandString substitutes ${ENV_VAR} placeholders using the process
// environment. Undefined variables become empty strings.
func ExpandString(s string) string {
	return envVarRE.ReplaceAllStringFunc(s, func(match string) string {
		sub := envVarRE.FindStringSubmatch(match)
		if len(sub) < 2 {
			return ""
		}
		return os.Getenv(sub[1])
	})
}

// ExpandNode walks a decoded yaml.Node tree and rewrites scalar node values
// in place. Mapping keys are left untouched; only scalar *values* expand.
// After expansion the scalar is tagged !!str so secret characters stay
// string-typed on re-encode/decode (matching Python's always-string result).
func ExpandNode(n *yaml.Node) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i := range n.Content {
			ExpandNode(n.Content[i])
		}
	case yaml.MappingNode:
		// Content is [key, value, key, value, ...]. Expand only values.
		for i := 0; i+1 < len(n.Content); i += 2 {
			ExpandNode(n.Content[i+1])
		}
	case yaml.ScalarNode:
		// Expand any scalar that contains a placeholder, and every !!str
		// scalar (quoted strings may contain partial templates). Non-string
		// tags without placeholders (true, 42) are left alone.
		if n.Tag == "!!str" || envVarRE.MatchString(n.Value) {
			n.Value = ExpandString(n.Value)
			n.Tag = "!!str"
		}
	}
}
