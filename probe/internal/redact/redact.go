// Package redact implements the probe-side redaction filter (design.md
// Section 8.2, tightened in v1.5, scope expanded in v1.6). The stated
// guarantee -- downstream-database passwords and other credentials never
// enter the control plane -- is the acceptance criterion; the mechanism
// satisfies it in three normative, independent forms:
//
//  1. Key-based: values whose keys match KeyPattern
//     ((?i)(password|secret|token|credential|.*-key)) are replaced with
//     Placeholder wholesale.
//  2. Value-based: independent of the key, values are scanned for embedded
//     credentials and only the matching portion is replaced: URL userinfo
//     credentials (scheme://user:secret@host -> scheme://user:***REDACTED***@host,
//     the JDBC connection-url case) and key=value pairs embedded inside a
//     larger value, where the embedded key contains a KeyPattern trigger
//     substring (password=/secret=/token=/credential=/*-key=, and prefixed
//     forms like POSTGRES_PASSWORD= -- the Docker `Env` entry shape).
//  3. Argv-adjacency: independent of both of the above, a string slice
//     (e.g. a decoded-JSON []any or a concretely-typed []string) where one
//     element is shaped like a secret-flag name (--password, --password=,
//     -p, --secret, --token, --api-key, or more generally anything whose
//     bare flag name -- stripped of leading dashes and a trailing "=" --
//     matches KeyPattern's trigger set, per flagNameLooksSecret) has its
//     immediately following element -- the flag's value, when the flag and
//     value are two independent array elements with no "=" joining them --
//     redacted wholesale. This is what catches Docker/K8s command/args
//     arrays like `Cmd: ["--password", "hunter2"]`, which rules 1 and 2
//     alone cannot: rule 1 has no map key to check ("hunter2" is just a
//     bare list element), and rule 2's embedded-KV scan only matches
//     within a single string token (it has no cross-element context).
//     Scoped narrowly to the flag-token-then-value adjacency shape (see
//     flagTokenPattern) so ordinary string arrays with no flag-shaped
//     element (a plain list of hostnames, table names, region names, etc.)
//     are left untouched.
//
// The filter applies to plain-text config content (Text) and recursively
// to structured/JSON payloads (Map/Value). Map/Value are the single
// production entry point for structured output (design.md Section 8.2
// v1.6): tools route through them rather than reimplementing per-tool
// redaction. In-scope tools (Appendix B.1/B.2, expanded in v1.6):
// presto_config, presto_session_properties, the `session` section of
// presto_query_detail (and the same data reached via
// presto_query_json_section), and docker_inspect/k8s_describe.
package redact

import (
	"reflect"
	"regexp"
	"strings"
)

// KeyPattern is the exact regex from design.md Section 8.2.
var KeyPattern = regexp.MustCompile(`(?i)(password|secret|token|credential|.*-key)`)

const Placeholder = "***REDACTED***"

// keyPatternTriggers are the plain-ASCII literal substrings that must be
// present (case-insensitively) somewhere in a key for KeyPattern to have
// any chance of matching it: every one of KeyPattern's alternatives is
// unanchored, so "password"/"secret"/"token"/"credential" matching
// anywhere is exactly a case-insensitive substring test, and `.*-key`
// (also unanchored) reduces to the same thing for "-key". Used as a cheap
// rejection fast-path before invoking the regexp engine at all (see
// keyMatchesPattern) -- a real perf concern here, since Text/Map call
// this on every config line/map key and B5 (design.md Section 14.4)
// budgets the whole 1 MiB pass at under 100ms.
var keyPatternTriggers = []string{"password", "secret", "token", "credential", "-key"}

// keyMatchesPattern is KeyPattern.MatchString(key), fast-pathed: if none
// of keyPatternTriggers appear in the lowercased key, KeyPattern cannot
// match (see keyPatternTriggers' doc), so the regexp engine is skipped
// entirely; otherwise the real regex still runs to confirm (this keeps
// behavior byte-for-byte identical to calling KeyPattern.MatchString
// directly -- the fast path only ever short-circuits a definite "no").
func keyMatchesPattern(key string) bool {
	lower := strings.ToLower(key)
	for _, trigger := range keyPatternTriggers {
		if strings.Contains(lower, trigger) {
			return KeyPattern.MatchString(key)
		}
	}
	return false
}

// urlUserinfoPattern matches `scheme://user:password@` URL userinfo
// credentials (design.md Section 8.2 v1.5, the JDBC `connection-url`
// case: "jdbc:mysql://svc:hunter2@db:3306/analytics"). Only the password
// portion (capture group 2) is replaced; the scheme/username/host survive
// so the redacted value stays useful for diagnosis.
var urlUserinfoPattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^\s/@:]+:)([^\s/@]+)(@)`)

// embeddedKVPattern matches `key=value`-shaped tokens embedded inside a
// larger value (e.g. a JDBC options string like
// "...;password=hunter2;ssl=true", a raw command-line-shaped value like
// "--password=hunter2 --verbose", or a Docker `Env` entry like
// "POSTGRES_PASSWORD=hunter2"), where the key portion contains one of
// KeyPattern's trigger substrings anywhere -- the same unanchored
// substring-match definition of "secret-worthy key" the key-based rule
// (KeyPattern, design.md Section 8.2 rule 1) already uses, applied here to
// an embedded key=value pair rather than a whole map key or config line
// (rule 2: "password=/secret= style key=value pairs embedded inside a
// larger value"). This deliberately also catches prefixed/suffixed forms
// like `POSTGRES_PASSWORD=`/`access_token=`/`encryption-key=`, not just the
// bare `password=`/`secret=` literals -- otherwise a `docker_inspect`
// `Env` entry (which is always shaped `NAME=VALUE`, not a nested map key)
// would slip past both the key-based rule (there is no separate "key" for
// a flat env-string list element) and a narrower value-based pattern.
// Only the value portion (capture group 3) is replaced.
var embeddedKVPattern = regexp.MustCompile(`(?i)([\w.-]*(?:password|secret|token|credential|-key)[\w.-]*)(\s*=\s*)([^;,&\s]+)`)

// flagTokenPattern recognizes an argv-style flag *token* on its own -- one
// or two leading dashes, then a bare flag name, optionally ending in a
// trailing "=" with nothing after it (e.g. "--password", "-p",
// "--password="). It deliberately does NOT match a token that already has
// a value glued on after "=" (e.g. "--password=hunter2") -- that shape is
// a single self-contained token already handled by embeddedKVPattern via
// String(), and must not also be treated as "a flag name whose value is
// the next array element" (which would incorrectly consume the following,
// unrelated array element too).
var flagTokenPattern = regexp.MustCompile(`^-{1,2}[A-Za-z][\w-]*=?$`)

// argvShortSecretFlags are well-known short/abbreviated flag names that
// are unambiguous conventions for a secret value in common CLIs (e.g. `-p`
// for password: mysql, htpasswd, and others), but whose bare form (after
// stripping leading dashes) is too short to contain any of KeyPattern's
// trigger substrings ("password", "secret", "token", "credential",
// "-key") and so would otherwise slip past keyMatchesPattern entirely.
// Deliberately a short, explicit allowlist -- not a heuristic -- kept
// separate from KeyPattern so it only ever applies in this narrow,
// argv-specific two-element adjacency context (flagNameLooksSecret),
// never to whole-map-key or embedded-KV matching.
var argvShortSecretFlags = map[string]bool{
	"p": true,
}

// flagNameLooksSecret reports whether token is shaped like an argv flag
// name (flagTokenPattern) whose bare name -- stripped of leading dashes
// and a trailing "=" -- is secret-worthy: either it matches KeyPattern's
// trigger set (the same "secret-worthy key" definition the key-based rule
// and embedded-KV rule already use) or it's a known short-flag convention
// (argvShortSecretFlags). Used only to decide whether the *next* array
// element should be treated as this flag's value (see Value's argv-
// adjacency pass) -- it never redacts token itself.
func flagNameLooksSecret(token string) bool {
	if !flagTokenPattern.MatchString(token) {
		return false
	}
	bare := strings.TrimSuffix(strings.TrimLeft(token, "-"), "=")
	if bare == "" {
		return false
	}
	if keyMatchesPattern(bare) {
		return true
	}
	return argvShortSecretFlags[strings.ToLower(bare)]
}

// String applies only the value-based scan (URL userinfo credentials,
// embedded key=value pairs whose key contains a KeyPattern trigger
// substring) to a single string, independent of any key. Exported so
// callers with a key/value shape that Map/Text don't natively cover (e.g.
// Appendix B.1 presto_session_properties, whose secret-worthiness is keyed
// by a sibling `name` field rather than a map key literally named
// "password"; or a flat `NAME=VALUE` string like a Docker `Env` entry,
// which has no separate map key at all) can still get the value-based
// guarantee on the value itself.
func String(s string) (redacted string, wasRedacted bool) {
	// Cheap literal-substring pre-checks before invoking the regexp
	// engine at all: neither pattern can possibly match without its
	// trigger substring present. A single strings.ToLower + a handful of
	// strings.Contains calls (both highly optimized stdlib routines) is
	// far cheaper than a regexp attempt -- a deliberate perf choice for
	// B5 (design.md Section 14.4: redaction runs on every config read,
	// budget < 100ms/MiB), since the large majority of real config
	// lines/values contain neither "://" nor any KeyPattern trigger.
	lower := strings.ToLower(s)
	hasURL := strings.Contains(lower, "://")
	hasKVTrigger := false
	for _, trigger := range keyPatternTriggers {
		if strings.Contains(lower, trigger) {
			hasKVTrigger = true
			break
		}
	}
	if !hasURL && !hasKVTrigger {
		return s, false
	}
	out := s
	if hasURL {
		out = urlUserinfoPattern.ReplaceAllString(out, "${1}"+Placeholder+"${3}")
	}
	if hasKVTrigger {
		out = embeddedKVPattern.ReplaceAllString(out, "${1}${2}"+Placeholder)
	}
	return out, out != s
}

// Text redacts a raw config-file-shaped text blob line by line, for lines
// that look like `key = value` / `key: value` / `key=value` assignments
// (Presto's `*.properties` files and most K8s ConfigMap-mounted config use
// this shape -- design.md Appendix B.1 `presto_config`). Key-based
// matching (KeyPattern) redacts the whole value; independent of that,
// every line's value (or the whole line, if no key=value shape is
// recognized) is also scanned for embedded credentials per String above --
// this is what catches `connection-url=jdbc:mysql://user:pass@host/db`,
// whose key alone would never match KeyPattern.
func Text(content string) (redacted string, wasRedacted bool) {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		newLine, changed := redactLine(line)
		lines[i] = newLine
		if changed {
			wasRedacted = true
		}
	}
	return strings.Join(lines, "\n"), wasRedacted
}

// Map recursively redacts a structured (map/JSON-shaped) payload: any key
// matching KeyPattern has its value replaced wholesale with Placeholder;
// every other string value (at any nesting depth, through nested
// maps/slices) is independently scanned for embedded credentials via
// String. This is the recursive entry point design.md Section 8.2 (v1.5)
// requires ("the filter applies... recursively to structured (map/JSON)
// payloads") -- unlike a shallow, top-level-only pass, it walks into
// nested maps and slices of any concrete type.
func Map(m map[string]any) (redacted map[string]any, wasRedacted bool) {
	out := make(map[string]any, len(m))
	changed := false
	for k, v := range m {
		if keyMatchesPattern(k) {
			out[k] = Placeholder
			changed = true
			continue
		}
		newV, c := Value(v)
		out[k] = newV
		if c {
			changed = true
		}
	}
	return out, changed
}

// Value recursively redacts an arbitrary value: strings are scanned via
// String; map[string]any values recurse through Map; any other map or
// slice/array type (e.g. []map[string]any, []string, a decoded-JSON
// []any, or a non-map[string]any map with string keys) is walked via
// reflection so callers don't need to normalize concrete types first.
// Anything else (numbers, bools, nil, non-string-keyed maps) passes
// through unchanged.
func Value(v any) (redacted any, wasRedacted bool) {
	switch t := v.(type) {
	case nil:
		return v, false
	case string:
		return String(t)
	case map[string]any:
		return Map(t)
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		changed := false
		out := make([]any, rv.Len())
		for i := 0; i < rv.Len(); i++ {
			newElem, c := Value(rv.Index(i).Interface())
			out[i] = newElem
			if c {
				changed = true
			}
		}
		if argvChanged := redactArgvAdjacentPairs(rv, out); argvChanged {
			changed = true
		}
		return out, changed
	case reflect.Map:
		if rv.Type().Key().Kind() != reflect.String {
			return v, false
		}
		m := make(map[string]any, rv.Len())
		for _, key := range rv.MapKeys() {
			m[key.String()] = rv.MapIndex(key).Interface()
		}
		return Map(m)
	default:
		return v, false
	}
}

// redactArgvAdjacentPairs implements the argv-adjacency rule (package doc,
// form 3): for each pair of adjacent elements in the *original* slice
// (rv), if element i is a string shaped like a secret flag name
// (flagNameLooksSecret) and element i+1 is a string that doesn't itself
// look like another flag (so a boolean flag immediately followed by an
// unrelated flag, e.g. ["--password", "--verbose"], isn't misread as
// "--verbose" being the password's value), out[i+1] is overwritten with
// Placeholder wholesale -- mirroring the key-based rule's whole-value
// replacement, since a flag's value is exactly the credential, not a
// larger string with an embedded credential. Operates on the pre-redaction
// original values (via rv) so flag detection isn't confused by anything
// the per-element String()/Value() pass may have already done, and writes
// into the already-allocated out slice built by that pass so this stays a
// single additional O(n) walk, not a second full recursive redaction.
func redactArgvAdjacentPairs(rv reflect.Value, out []any) bool {
	changed := false
	for i := 0; i+1 < rv.Len(); i++ {
		flag, ok := rv.Index(i).Interface().(string)
		if !ok || !flagNameLooksSecret(flag) {
			continue
		}
		value, ok := rv.Index(i + 1).Interface().(string)
		if !ok || flagTokenPattern.MatchString(value) {
			continue
		}
		if out[i+1] != Placeholder {
			out[i+1] = Placeholder
			changed = true
		}
	}
	return changed
}

// redactLine splits a `key<sep>value` line on the first `=` or `:` and
// redacts the value if the key matches KeyPattern; otherwise it still
// runs the value-based scan (String) on the value (or, absent a
// recognizable key=value shape, the whole line).
func redactLine(line string) (string, bool) {
	idx := strings.IndexAny(line, "=:")
	if idx < 0 {
		return String(line)
	}
	key := strings.TrimSpace(line[:idx])
	if keyMatchesPattern(key) {
		return line[:idx+1] + Placeholder, true
	}
	value := line[idx+1:]
	newValue, changed := String(value)
	if !changed {
		return line, false
	}
	return line[:idx+1] + newValue, true
}
