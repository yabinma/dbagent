package envexpand

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExpandString_DefinedUndefinedEmpty(t *testing.T) {
	t.Setenv("FOO", "bar")
	t.Setenv("EMPTY", "")
	os.Unsetenv("MISSING")

	if got := ExpandString("x${FOO}y"); got != "xbary" {
		t.Fatalf("defined: got %q", got)
	}
	if got := ExpandString("${EMPTY}"); got != "" {
		t.Fatalf("empty: got %q", got)
	}
	if got := ExpandString("${MISSING}"); got != "" {
		t.Fatalf("undefined: got %q", got)
	}
	if got := ExpandString("no placeholders $FOO ${}"); got != "no placeholders $FOO ${}" {
		t.Fatalf("non-matching: got %q", got)
	}
	if got := ExpandString("${FOO}${FOO}"); got != "barbar" {
		t.Fatalf("repeated: got %q", got)
	}
}

func TestExpandNode_YAMLSignificantChars(t *testing.T) {
	// Values that would corrupt YAML under raw-byte substitution.
	// Shared fixture with Python: testdata/parity.yaml
	t.Setenv("HASH_PW", "p@ss #word")
	t.Setenv("COLON_PW", "a: b")
	t.Setenv("STAR_TOKEN", "*secret")
	t.Setenv("NL_TOKEN", "line1\nline2")

	raw, err := os.ReadFile("testdata/parity.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	ExpandNode(&root)

	var out map[string]any
	if err := root.Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["postgres_dsn"] != "postgres://u:p@ss #word@h/db" {
		t.Fatalf("hash: %v", out["postgres_dsn"])
	}
	if out["bootstrap_token"] != "a: b" {
		t.Fatalf("colon: %v", out["bootstrap_token"])
	}
	if out["star"] != "*secret" {
		t.Fatalf("star: %v", out["star"])
	}
	if out["multi"] != "line1\nline2" {
		t.Fatalf("nl: %v", out["multi"])
	}
	nested := out["nested"].(map[string]any)
	if nested["key"] != "prefix-p@ss #word-suffix" {
		t.Fatalf("nested: %v", nested["key"])
	}
	if out["plain"] != "p@ss #word" {
		t.Fatalf("plain: %v", out["plain"])
	}
}

func TestExpandNode_NilSafe(t *testing.T) {
	ExpandNode(nil)
	var empty yaml.Node
	ExpandNode(&empty)
}

func TestExpandNode_SequenceAndBoolish(t *testing.T) {
	t.Setenv("A", "1")
	raw := []byte(`
items:
  - "${A}"
  - plain
flag: true
num: 42
`)
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	ExpandNode(&root)
	var out map[string]any
	if err := root.Decode(&out); err != nil {
		t.Fatal(err)
	}
	items := out["items"].([]any)
	if items[0] != "1" {
		t.Fatalf("seq expand: %v", items)
	}
	// bool / int must survive expansion unchanged (not stringified).
	if out["flag"] != true {
		t.Fatalf("flag want true got %#v", out["flag"])
	}
	if out["num"] != 42 {
		t.Fatalf("num want 42 got %#v", out["num"])
	}
}

func TestExpandString_PartialAndDollar(t *testing.T) {
	t.Setenv("X", "y")
	if ExpandString("$X ${X}") != "$X y" {
		t.Fatalf("got %q", ExpandString("$X ${X}"))
	}
	// hyphen invalid in name — pattern shouldn't match fully
	if got := ExpandString("${not-valid}"); got != "${not-valid}" {
		t.Fatalf("invalid placeholder altered: %q", got)
	}
}
