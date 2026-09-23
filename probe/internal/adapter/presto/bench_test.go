//go:build !race

package presto

// B9 (design.md Section 14.4): "presto_query_json_section JSONPath slice
// over a 10 MB query JSON (deep-read path) | < 500 ms". See
// tests/benchmark/thresholds.yaml.
//
// design.md Section 14.4's v1.5 "manifest honesty rule": toolPrestoQueryJSONSection
// (tools_engine.go) shipped in M2, so the benchmark lands now rather than
// staying `deferred`.
//
// Implemented as a deterministic pass/fail Test (same rationale as
// B3/B4/B5: Section 14.4's bar is a concrete threshold, "pass = threshold
// met"), driving the real toolFunc end-to-end (a.Execute ->
// prestoclient.GetJSON -> jsonpath.Get), not just the jsonpath library in
// isolation -- "deep-read path" includes the JSON decode, per the design
// table's own naming.
//
// Excluded from -race builds (`//go:build !race`, same rationale as
// probe/internal/redact/bench_test.go's B5): this is a CPU/allocation-heavy
// 10 MB JSON decode + JSONPath walk, and the race detector's per-access
// instrumentation inflates its wall time well past the 500ms threshold
// (measured locally: ~58ms plain, >530ms under -race) -- not
// representative of the production latency the threshold targets.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

const b9Budget = 500 * time.Millisecond

// buildB9QueryJSON assembles a >=10 MB `/v1/query/{id}`-shaped payload: a
// deeply nested outputStage tree (stages -> subStages -> ...) padded with
// realistic-looking stage stats, mirroring the shape
// toolPrestoQueryJSONSection actually JSONPath-slices in production
// (design.md Appendix B.1: "payloads can reach MBs").
func buildB9QueryJSON(targetBytes int) []byte {
	type stage struct {
		StageID   string   `json:"stageId"`
		State     string   `json:"state"`
		Stats     any      `json:"stats"`
		SubStages []stage  `json:"subStages,omitempty"`
		Operators []string `json:"operatorSummaries,omitempty"`
	}
	stats := map[string]any{
		"processedInputDataSize":  "512MB",
		"processedInputPositions": 123456789,
		"rawInputDataSize":        "1.2GB",
		"cpuTime":                 "45.30s",
		"wallTime":                "12.10s",
	}
	// A wide operator-summary list is what actually inflates payload size
	// realistically (each stage in a real Presto query can carry dozens of
	// per-operator stat blocks).
	operators := make([]string, 200)
	for i := range operators {
		operators[i] = fmt.Sprintf("operator-%d: HashJoin cpu=12.3ms output=45678rows peak_memory=%dMB", i, i*7)
	}

	buildLeaf := func(id string) stage {
		return stage{StageID: id, State: "FINISHED", Stats: stats, Operators: operators}
	}

	root := stage{StageID: "0", State: "FINISHED", Stats: stats}
	// Grow breadth (not just depth) until the marshaled payload clears the
	// target size -- deep recursion alone would need an impractically
	// large stack for a 10 MB target given typical per-node overhead.
	for size := 0; size < targetBytes; {
		root.SubStages = append(root.SubStages, buildLeaf(fmt.Sprintf("%d", len(root.SubStages)+1)))
		if len(root.SubStages)%50 == 0 {
			probe, _ := json.Marshal(root)
			size = len(probe)
		}
	}

	full := map[string]any{
		"queryId":     "20260101_000000_00001_bench",
		"state":       "FINISHED",
		"self":        "http://coordinator:8080/v1/query/20260101_000000_00001_bench",
		"outputStage": root,
	}
	out, err := json.Marshal(full)
	if err != nil {
		panic(err)
	}
	return out
}

func TestB9_PrestoQueryJSONSection_10MBQueryJSON(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark-tier test in -short mode")
	}
	const tenMB = 10 * 1000 * 1000
	payload := buildB9QueryJSON(tenMB)
	if len(payload) < tenMB {
		t.Fatalf("test setup: payload is only %d bytes, want >= %d", len(payload), tenMB)
	}
	t.Logf("B9: query JSON payload is %d bytes", len(payload))

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/query/bench-query", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	start := time.Now()
	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_query_json_section",
		Args:     map[string]any{"query_id": "bench-query", "jsonpath": "$.outputStage.stageId"},
	})
	elapsed := time.Since(start)

	t.Logf("B9: presto_query_json_section over %d bytes took %s (threshold %s)", len(payload), elapsed, b9Budget)

	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok || data["result"] != "0" {
		t.Fatalf("unexpected jsonpath result: %+v", result.Data)
	}
	if elapsed > b9Budget {
		t.Errorf("B9 FAILED: presto_query_json_section took %s, exceeds threshold %s", elapsed, b9Budget)
	}
}
