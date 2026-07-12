package redact

import (
	"strings"
	"testing"
)

func TestText_RedactsMatchingKeys(t *testing.T) {
	in := "connector.name=hive\n" +
		"connection-password=hunter2\n" +
		"  secret_token : abc123\n" +
		"my-key=xyz\n" +
		"plain_line_no_separator\n"

	out, changed := Text(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	want := "connector.name=hive\n" +
		"connection-password=***REDACTED***\n" +
		"  secret_token :***REDACTED***\n" +
		"my-key=***REDACTED***\n" +
		"plain_line_no_separator\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
}

func TestText_NoRedactionNeeded(t *testing.T) {
	in := "connector.name=hive\ncatalog.location=/etc/presto/catalog\n"
	out, changed := Text(in)
	if changed {
		t.Fatalf("expected wasRedacted=false")
	}
	if out != in {
		t.Fatalf("content should be unchanged, got %q", out)
	}
}

func TestText_PositiveKeyMatrix(t *testing.T) {
	positives := []string{
		"password=x", "PASSWORD=x", "db-password=x",
		"secret=x", "my.secret.value=x",
		"token=x", "access_token=x",
		"credential=x", "credentials=x",
		"api-key=x", "encryption-key=x",
	}
	for _, line := range positives {
		out, changed := Text(line)
		if !changed {
			t.Errorf("expected %q to be redacted", line)
		}
		if out == line {
			t.Errorf("expected %q to change, stayed %q", line, out)
		}
	}
}

func TestText_NegativeKeyMatrix(t *testing.T) {
	negatives := []string{
		"connector.name=hive",
		"query.max-memory=10GB", // contains "key"? no -- check it does NOT match
		"http-server.http.port=8080",
		"node.environment=production",
	}
	for _, line := range negatives {
		out, changed := Text(line)
		if changed {
			t.Errorf("expected %q to NOT be redacted, got %q", line, out)
		}
	}
}

func TestMap_RedactsMatchingKeys(t *testing.T) {
	in := map[string]any{
		"username":       "svc",
		"password":       "hunter2",
		"api-key":        "abc",
		"query.priority": 5,
	}
	out, changed := Map(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	if out["password"] != Placeholder || out["api-key"] != Placeholder {
		t.Fatalf("expected password/api-key redacted, got %+v", out)
	}
	if out["username"] != "svc" || out["query.priority"] != 5 {
		t.Fatalf("expected non-matching keys unchanged, got %+v", out)
	}
}

func TestMap_NoMatchingKeys(t *testing.T) {
	in := map[string]any{"a": 1, "b": "x"}
	out, changed := Map(in)
	if changed {
		t.Fatalf("expected wasRedacted=false")
	}
	if out["a"] != 1 || out["b"] != "x" {
		t.Fatalf("unexpected mutation: %+v", out)
	}
}

// --- design.md Section 8.2 (v1.5): value-based scanning ----------------------

func TestText_URLEmbeddedPasswordIsRedacted(t *testing.T) {
	// The exact W3 regression case: a key that doesn't match KeyPattern
	// ("connection-url") but whose value embeds a URL userinfo password.
	in := "connection-url=jdbc:mysql://svc:hunter2@db:3306/analytics\n"
	out, changed := Text(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	want := "connection-url=jdbc:mysql://svc:" + Placeholder + "@db:3306/analytics\n"
	if out != want {
		t.Fatalf("got:\n%s\nwant:\n%s", out, want)
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("password leaked into redacted output: %s", out)
	}
}

func TestText_EmbeddedPasswordKVPairIsRedacted(t *testing.T) {
	in := "jdbc.options=user=svc;password=hunter2;ssl=true\n"
	out, changed := Text(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("password leaked into redacted output: %s", out)
	}
	if !strings.Contains(out, "password="+Placeholder) {
		t.Fatalf("expected embedded password= pair to be redacted, got: %s", out)
	}
	if !strings.Contains(out, "user=svc") || !strings.Contains(out, "ssl=true") {
		t.Fatalf("expected unrelated fields to survive, got: %s", out)
	}
}

func TestText_EmbeddedSecretKVPairIsRedacted(t *testing.T) {
	in := "startup-flags=--secret=topsecret --verbose\n"
	out, changed := Text(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	if strings.Contains(out, "topsecret") {
		t.Fatalf("secret leaked into redacted output: %s", out)
	}
}

func TestText_NoSeparatorLineStillScannedForEmbeddedURLCredential(t *testing.T) {
	in := "jdbc:mysql://svc:hunter2@db:3306/analytics"
	out, changed := Text(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true for a free-text line with an embedded credential")
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("password leaked into redacted output: %s", out)
	}
}

func TestText_ValueBasedScanDoesNotFalsePositive(t *testing.T) {
	in := "coordinator.uri=http://presto-coordinator:8080\ncatalog.location=/etc/presto/catalog\n"
	out, changed := Text(in)
	if changed {
		t.Fatalf("expected no redaction for URLs without userinfo credentials, got: %s", out)
	}
	if out != in {
		t.Fatalf("content should be unchanged, got %q", out)
	}
}

func TestString_URLUserinfoRedacted(t *testing.T) {
	out, changed := String("jdbc:mysql://user:pass@host/db")
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	if out != "jdbc:mysql://user:"+Placeholder+"@host/db" {
		t.Fatalf("unexpected output: %s", out)
	}
}

// TestString_PrefixedEnvStyleKeyEmbeddedCredentialRedacted is a regression
// test for design.md Section 8.2/8.5 (v1.6): a Docker `Env` entry is a flat
// `NAME=VALUE` string (no separate map key to check against KeyPattern), so
// the value-based scan must catch prefixed/suffixed key forms like
// `POSTGRES_PASSWORD=`, not just the bare `password=`/`secret=` literals.
func TestString_PrefixedEnvStyleKeyEmbeddedCredentialRedacted(t *testing.T) {
	out, changed := String("POSTGRES_PASSWORD=hunter2")
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	if strings.Contains(out, "hunter2") {
		t.Fatalf("password leaked: %s", out)
	}
	if out != "POSTGRES_PASSWORD="+Placeholder {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestString_TokenAndCredentialKeyEmbeddedValuesRedacted(t *testing.T) {
	cases := []struct{ in, wantKey string }{
		{"ACCESS_TOKEN=abc123", "ACCESS_TOKEN"},
		{"db_credential=topsecretvalue", "db_credential"},
		{"encryption-key=abcxyz", "encryption-key"},
	}
	for _, c := range cases {
		out, changed := String(c.in)
		if !changed {
			t.Errorf("%q: expected wasRedacted=true", c.in)
		}
		if out != c.wantKey+"="+Placeholder {
			t.Errorf("%q: unexpected output: %s", c.in, out)
		}
	}
}

func TestString_UnrelatedEmbeddedKVNotRedacted(t *testing.T) {
	out, changed := String("query.max-memory=10GB")
	if changed {
		t.Fatalf("expected wasRedacted=false for a non-secret key=value pair, got %s", out)
	}
	if out != "query.max-memory=10GB" {
		t.Fatalf("expected unchanged output, got %s", out)
	}
}

func TestString_NoCredentialsUnchanged(t *testing.T) {
	out, changed := String("http://host:8080/path")
	if changed {
		t.Fatalf("expected wasRedacted=false, got %s", out)
	}
	if out != "http://host:8080/path" {
		t.Fatalf("expected unchanged output, got %s", out)
	}
}

func TestMap_RecursesIntoNestedMaps(t *testing.T) {
	in := map[string]any{
		"catalog": map[string]any{
			"name":            "mysql",
			"connection-url":  "jdbc:mysql://svc:hunter2@db:3306/analytics",
			"connection-pass": "shouldalsoberedacted", // key matches "password"? no -- "connection-pass" doesn't match KeyPattern; kept as a value-scan control case
		},
	}
	out, changed := Map(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	catalog, ok := out["catalog"].(map[string]any)
	if !ok {
		t.Fatalf("expected nested map to remain a map[string]any, got %T", out["catalog"])
	}
	if catalog["name"] != "mysql" {
		t.Fatalf("expected unrelated nested key to survive, got %+v", catalog)
	}
	url, _ := catalog["connection-url"].(string)
	if strings.Contains(url, "hunter2") {
		t.Fatalf("password leaked through nested map: %+v", catalog)
	}
	if !strings.Contains(url, Placeholder) {
		t.Fatalf("expected nested connection-url password redacted, got %+v", catalog)
	}
}

func TestMap_RecursesIntoSlicesOfMaps(t *testing.T) {
	// Exercises the reflection-based walk into a concretely-typed
	// []map[string]any nested under a map key (not the JSON-decode-typical
	// []any) -- e.g. a tool building its own structured Go payload rather
	// than round-tripping through encoding/json first.
	in := map[string]any{
		"catalogs": []map[string]any{
			{"name": "mysql", "connection-url": "jdbc:mysql://svc:hunter2@db:3306/analytics"},
			{"name": "hive", "connection-url": "jdbc:hive2://host:10000/default"},
		},
	}
	out, changed := Map(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	catalogs, ok := out["catalogs"].([]any)
	if !ok {
		t.Fatalf("expected catalogs to be a []any after recursive redaction, got %T", out["catalogs"])
	}
	if len(catalogs) != 2 {
		t.Fatalf("expected 2 catalogs, got %d", len(catalogs))
	}
	first, ok := catalogs[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first catalog to be a map[string]any, got %T", catalogs[0])
	}
	url, _ := first["connection-url"].(string)
	if strings.Contains(url, "hunter2") {
		t.Fatalf("password leaked through slice-of-maps recursion: %+v", first)
	}
	if !strings.Contains(url, Placeholder) {
		t.Fatalf("expected the first catalog's embedded password redacted, got %+v", first)
	}
	second, ok := catalogs[1].(map[string]any)
	if !ok {
		t.Fatalf("expected second catalog to be a map[string]any, got %T", catalogs[1])
	}
	if second["connection-url"] != "jdbc:hive2://host:10000/default" {
		t.Fatalf("expected the unrelated catalog to survive unchanged, got %+v", second)
	}
}

func TestValue_RedactsTopLevelString(t *testing.T) {
	out, changed := Value("jdbc:mysql://svc:hunter2@db:3306/analytics")
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	if strings.Contains(out.(string), "hunter2") {
		t.Fatalf("password leaked: %v", out)
	}
}

func TestValue_PassesThroughNonStringScalars(t *testing.T) {
	out, changed := Value(42)
	if changed {
		t.Fatalf("expected wasRedacted=false for a non-string scalar")
	}
	if out != 42 {
		t.Fatalf("expected value to pass through unchanged, got %v", out)
	}
}

// --- design.md Section 8.2 (v1.6, S1 follow-up): argv-adjacency scanning ----

// TestValue_ArgvAdjacentFlagValuePairRedacted is the exact S1 regression
// case: a secret split across two adjacent argv-shaped array elements
// (`["--password", "hunter2"]`), with no "=" joining the flag name and its
// value, so the per-element value-based scan (String/embeddedKVPattern)
// alone has no cross-element context to catch it.
func TestValue_ArgvAdjacentFlagValuePairRedacted(t *testing.T) {
	out, changed := Value([]any{"--password", "hunter2"})
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	got, ok := out.([]any)
	if !ok || len(got) != 2 {
		t.Fatalf("unexpected shape: %+v", out)
	}
	if got[0] != "--password" {
		t.Fatalf("expected the flag token itself to survive unchanged, got %+v", got)
	}
	if got[1] != Placeholder {
		t.Fatalf("expected the adjacent value redacted, got %+v", got)
	}
}

// TestValue_ArgvAdjacentShortFlagPairRedacted covers the `-p` short-flag
// convention (mysql/htpasswd/etc.) explicitly called out alongside the
// long-flag forms: its bare name ("p") is too short to contain any
// KeyPattern trigger substring, so it needs the explicit
// argvShortSecretFlags allowlist, not just keyMatchesPattern.
func TestValue_ArgvAdjacentShortFlagPairRedacted(t *testing.T) {
	out, changed := Value([]any{"-p", "hunter2"})
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	got := out.([]any)
	if got[0] != "-p" || got[1] != Placeholder {
		t.Fatalf("unexpected output: %+v", got)
	}
}

// TestValue_ArgvSingleTokenFormStillRedacted is a regression check that
// the pre-existing single-token `--password=hunter2` form (flag and value
// glued together in one array element, no adjacency involved at all) is
// still caught -- via the pre-existing embedded-KV scan (String) -- after
// adding the argv-adjacency pass, and that the adjacency pass doesn't
// double-process it or consume a following, unrelated element.
func TestValue_ArgvSingleTokenFormStillRedacted(t *testing.T) {
	out, changed := Value([]any{"--password=hunter2", "--verbose"})
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	got := out.([]any)
	if got[0] != "--password="+Placeholder {
		t.Fatalf("expected the single-token form redacted, got %+v", got)
	}
	if got[1] != "--verbose" {
		t.Fatalf("expected the unrelated following flag to survive unchanged, got %+v", got)
	}
}

// TestValue_ArgvAdjacencyNegativeMatrix is the required false-positive
// matrix: realistic non-secret argv shapes (a mix of flags with plain
// values, boolean flags with no value, and plain positional arguments)
// must come through completely unchanged -- the adjacency pass must only
// ever fire on the narrow flag-name-then-value shape, never on "any string
// next to any other string".
func TestValue_ArgvAdjacencyNegativeMatrix(t *testing.T) {
	matrix := [][]any{
		{"--verbose", "table_name", "us-east-1"},
		{"--host", "db.example.com", "--port", "5432"},
		{"select", "*", "from", "orders"},
		{"cp", "src.txt", "dst.txt"},
		{"--dry-run", "--verbose"},
		{"tail", "-f", "/var/log/presto/server.log"},
		{"--region", "us-east-1", "--table", "orders"},
		{"curl", "-s", "http://example.com/health"},
	}
	for _, in := range matrix {
		out, changed := Value(in)
		if changed {
			t.Errorf("expected %+v to be left unchanged, got %+v", in, out)
		}
		got, ok := out.([]any)
		if !ok || len(got) != len(in) {
			t.Fatalf("unexpected shape for %+v: %+v", in, out)
		}
		for i := range in {
			if got[i] != in[i] {
				t.Errorf("%+v: element %d changed: got %v want %v", in, i, got[i], in[i])
			}
		}
	}
}

// TestValue_ArgvAdjacencyBooleanFlagFollowedByAnotherFlagNotMisread
// guards against a specific false-positive shape: a secret-shaped boolean
// flag immediately followed by an unrelated flag token (no value for the
// first flag in this array at all) must not have the second flag
// misidentified as the first flag's value.
func TestValue_ArgvAdjacencyBooleanFlagFollowedByAnotherFlagNotMisread(t *testing.T) {
	out, changed := Value([]any{"--password", "--verbose"})
	if changed {
		t.Fatalf("expected wasRedacted=false, got %+v", out)
	}
	got := out.([]any)
	if got[0] != "--password" || got[1] != "--verbose" {
		t.Fatalf("unexpected output: %+v", got)
	}
}

func TestValue_HandlesNilAndAnySlices(t *testing.T) {
	if out, changed := Value(nil); changed || out != nil {
		t.Fatalf("expected nil to pass through unchanged, got %v changed=%v", out, changed)
	}
	in := []any{"jdbc:mysql://svc:hunter2@db:3306/analytics", "plain"}
	out, changed := Value(in)
	if !changed {
		t.Fatalf("expected wasRedacted=true")
	}
	list, ok := out.([]any)
	if !ok || len(list) != 2 {
		t.Fatalf("expected a 2-element []any, got %+v", out)
	}
	if strings.Contains(list[0].(string), "hunter2") {
		t.Fatalf("password leaked: %+v", list)
	}
	if list[1] != "plain" {
		t.Fatalf("expected unrelated element to survive, got %+v", list)
	}
}
