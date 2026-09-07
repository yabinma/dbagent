//go:build !race

package redact

// B5 (design.md Section 14.4): "Redaction filter over a 1 MiB config
// payload (runs on every config read) | < 100 ms". See
// tests/benchmark/thresholds.yaml.
//
// design.md Section 14.4's v1.5 "manifest honesty rule": this package
// shipped in M2 and runs on every presto_config/presto_session_properties
// read (Section 8.2/8.5), so the benchmark lands now rather than staying
// `deferred`.
//
// Implemented as a deterministic pass/fail Test (same rationale as B3/B4:
// Section 14.4's bar is a concrete threshold, "pass = threshold met").
//
// Excluded from -race builds (`//go:build !race` above): this is a
// CPU-bound, allocation-heavy regex workload over 1 MiB of text, and the
// race detector's per-memory-access instrumentation inflates its wall
// time by roughly an order of magnitude (measured locally: ~65ms plain,
// >1.4s under -race) -- not representative of the production latency the
// 100ms threshold is actually about. B3/B4 don't need this exclusion
// (their dominant cost is network/goroutine-scheduling, not raw
// CPU-bound computation, so -race overhead doesn't meaningfully change
// their pass/fail outcome against much larger budgets). This is the same,
// well-established rationale most Go projects use for excluding
// perf-sensitive benchmarks from race builds; go test ./... -race simply
// doesn't build/run this file (no failure, no skip-count noise) and the
// unqualified `go test ./...` run still enforces the real threshold.

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

const b5Budget = 100 * time.Millisecond

// buildB5Payload assembles a ~1 MiB Presto-`*.properties`-shaped config
// blob: a realistic mix of lines that key-based redaction catches
// (`connection-password=...`), lines that only value-based scanning
// catches (`connection-url=jdbc:...user:pass@...`), and plenty of
// ordinary unredacted lines, repeated until the payload reaches 1 MiB --
// so the benchmark exercises both redaction mechanisms under Section
// 8.2's realistic "any config-type output" shape, not just a synthetic
// worst case.
func buildB5Payload(targetBytes int) string {
	block := strings.Join([]string{
		"connector.name=mysql",
		"connection-url=jdbc:mysql://svc:hunter2@db.internal:3306/analytics?useSSL=true",
		"connection-user=svc",
		"connection-password=hunter2",
		"query.max-memory=10GB",
		"query.max-memory-per-node=1GB",
		"http-server.http.port=8080",
		"node.environment=production",
		"jdbc.options=user=svc;password=hunter2;ssl=true",
		"discovery.uri=http://coordinator:8080",
		"",
	}, "\n")

	var b strings.Builder
	b.Grow(targetBytes + len(block))
	for b.Len() < targetBytes {
		b.WriteString(block)
	}
	return b.String()
}

func TestB5_Redaction_1MiBConfigPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark-tier test in -short mode")
	}
	const oneMiB = 1 << 20
	payload := buildB5Payload(oneMiB)
	if len(payload) < oneMiB {
		t.Fatalf("test setup: payload is only %d bytes, want >= %d", len(payload), oneMiB)
	}

	start := time.Now()
	redacted, changed := Text(payload)
	elapsed := time.Since(start)

	t.Logf("B5: redacted %d bytes in %s (threshold %s)", len(payload), elapsed, b5Budget)

	if !changed {
		t.Fatalf("expected the payload's embedded credentials to be redacted")
	}
	if strings.Contains(redacted, "hunter2") {
		t.Fatalf("B5 FAILED: a credential leaked through redaction")
	}
	if elapsed > b5Budget {
		t.Errorf("B5 FAILED: redaction took %s, exceeds threshold %s", elapsed, b5Budget)
	}
}

// TestB5_Redaction_1MiBStructuredPayload is B5's structured-payload
// counterpart: the recursive Map() path (Appendix B.1
// presto_session_properties' shape, and any other structured tool
// output) must clear the same threshold as the text path.
func TestB5_Redaction_1MiBStructuredPayload(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark-tier test in -short mode")
	}
	const oneMiB = 1 << 20

	props := []map[string]any{}
	size := 0
	for i := 0; size < oneMiB; i++ {
		p := map[string]any{
			"name":             fmt.Sprintf("catalog.mysql.property.%d", i),
			"value":            "jdbc:mysql://svc:hunter2@db.internal:3306/analytics",
			"connection-key":   "some-non-secret-looking-value-padded-out-for-size-xxxxxxxxxxx",
			"query.max-memory": "10GB",
		}
		props = append(props, p)
		size += 160 // rough per-entry size estimate, good enough to reach ~1 MiB
	}
	payload := map[string]any{"properties": props}

	start := time.Now()
	redactedAny, changed := Map(payload)
	elapsed := time.Since(start)

	t.Logf("B5: redacted %d structured properties in %s (threshold %s)", len(props), elapsed, b5Budget)

	if !changed {
		t.Fatalf("expected the structured payload's embedded credentials to be redacted")
	}
	redactedProps, ok := redactedAny["properties"].([]any)
	if !ok || len(redactedProps) != len(props) {
		t.Fatalf("unexpected redacted shape: %+v", redactedAny)
	}
	first, _ := redactedProps[0].(map[string]any)
	if strings.Contains(fmt.Sprintf("%v", first["value"]), "hunter2") {
		t.Fatalf("B5 FAILED: a credential leaked through structured redaction")
	}
	if elapsed > b5Budget {
		t.Errorf("B5 FAILED: structured redaction took %s, exceeds threshold %s", elapsed, b5Budget)
	}
}
