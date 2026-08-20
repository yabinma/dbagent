package presto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

func detectedAdapter(t *testing.T, srv *httptest.Server, kind platform.EnvKind) (*Adapter, *fakeEnv) {
	t.Helper()
	env := &fakeEnv{kind: kind, configText: "http-server.authentication.type=NONE\n", baseURL: srv.URL}
	a := New(Config{PlatformKey: "presto-us1", CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	return a, env
}

func TestTools_ReturnsRegisteredSpecsAfterDetect(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)
	specs := a.Tools()
	if len(specs) == 0 {
		t.Fatalf("expected non-empty tool specs")
	}
	found := false
	for _, s := range specs {
		if s.Name == "presto_cluster_info" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected presto_cluster_info in Tools(), got %+v", specs)
	}
}

func TestExecute_PrestoNodes(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "presto_nodes", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	active := data["active"].([]map[string]any)
	if len(active) != 1 || active[0]["node_id"] != "n1" {
		t.Fatalf("unexpected active nodes: %+v", active)
	}
	if _, ok := data["failed"]; !ok {
		t.Fatalf("expected failed key when include_failed defaults true")
	}
}

func TestExecute_PrestoNodes_ExcludeFailed(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_nodes", Args: map[string]any{"include_failed": false},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	if _, ok := data["failed"]; ok {
		t.Fatalf("did not expect failed key when include_failed=false")
	}
}

func rewriteV1QueryFixtureTimestamps(t *testing.T, fixture []any) []any {
	t.Helper()
	now := time.Now().UTC()
	out := make([]any, 0, len(fixture))
	for _, item := range fixture {
		src, ok := item.(map[string]any)
		if !ok {
			out = append(out, item)
			continue
		}
		row := make(map[string]any, len(src))
		for k, v := range src {
			row[k] = v
		}
		stats, _ := row["queryStats"].(map[string]any)
		if stats == nil {
			stats = map[string]any{}
			row["queryStats"] = stats
		} else {
			statsCopy := make(map[string]any, len(stats))
			for k, v := range stats {
				statsCopy[k] = v
			}
			stats = statsCopy
			row["queryStats"] = stats
		}
		qid, _ := row["queryId"].(string)
		switch qid {
		case "q-finished-recent":
			stats["createTime"] = now.Add(-30 * time.Minute).Format(time.RFC3339)
			stats["endTime"] = now.Add(-25 * time.Minute).Format(time.RFC3339)
		case "q-finished-old":
			stats["createTime"] = now.Add(-13 * time.Hour).Format(time.RFC3339)
			stats["endTime"] = now.Add(-12 * time.Hour).Format(time.RFC3339)
		case "q-runaway-old":
			stats["createTime"] = now.Add(-3 * time.Hour).Format(time.RFC3339)
		case "q-bad-ended":
			stats["createTime"] = now.Add(-2 * time.Hour).Format(time.RFC3339)
			stats["endTime"] = "not-a-timestamp"
		default:
			if create, ok := stats["createTime"].(string); ok && create != "" {
				stats["createTime"] = now.Add(-10 * time.Minute).Format(time.RFC3339)
			}
			if end, ok := stats["endTime"].(string); ok && end != "" && end != "not-a-timestamp" {
				stats["endTime"] = now.Add(-5 * time.Minute).Format(time.RFC3339)
			}
		}
		out = append(out, row)
	}
	return out
}

func loadV1QueryFixture(t *testing.T) []any {
	t.Helper()
	raw, err := os.ReadFile("testdata/v1_query_0298.json")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fixture []any
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("decode fixture: %v", err)
	}
	return rewriteV1QueryFixtureTimestamps(t, fixture)
}

func listQueriesTestServer(t *testing.T, v1QueryBody any, statementGuard bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	if statementGuard {
		mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
			t.Fatalf("presto_list_queries must not POST /v1/statement")
		})
	}
	mux.HandleFunc("/v1/query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v1QueryBody)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestExecute_PrestoListQueries_NeverStatement(t *testing.T) {
	body := []any{
		map[string]any{
			"queryId": "q1",
			"state":   "RUNNING",
			"query":   "SELECT 1",
			"queryStats": map[string]any{
				"createTime": time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339),
			},
		},
	}
	srv := listQueriesTestServer(t, body, true)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries", Args: map[string]any{},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows, ok := result.Data.([]map[string]any)
	if !ok {
		t.Fatalf("expected []map rows, got %T", result.Data)
	}
	if len(rows) != 1 || rows[0]["query_id"] != "q1" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestExecute_PrestoListQueries_ContractMapping(t *testing.T) {
	fixture := loadV1QueryFixture(t)
	srv := listQueriesTestServer(t, fixture, false)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args:     map[string]any{"since": "24h", "limit": 200},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows, ok := result.Data.([]map[string]any)
	if !ok {
		t.Fatalf("expected []map rows, got %T", result.Data)
	}
	byID := map[string]map[string]any{}
	for _, row := range rows {
		byID[row["query_id"].(string)] = row
	}

	full := byID["20260708_101512_00042_abcde"]
	if full == nil {
		t.Fatalf("missing full row, got ids=%v", keysOf(byID))
	}
	for _, key := range []string{
		"query_id", "state", "user", "source", "started",
		"query_text_head", "resource_group", "queued_time", "elapsed_time",
	} {
		if _, ok := full[key]; !ok {
			t.Fatalf("row %s missing %q, got %+v", full["query_id"], key, full)
		}
	}
	if _, ok := full["ended"]; ok {
		t.Fatalf("QUEUED row must omit ended, got %+v", full)
	}
	if full["resource_group"] != "global" {
		t.Fatalf("resource_group: got %v", full["resource_group"])
	}
	if full["queued_time"] != "4.32m" {
		t.Fatalf("queued_time: got %v", full["queued_time"])
	}
	if full["elapsed_time"] != "5.01m" {
		t.Fatalf("elapsed_time: got %v", full["elapsed_time"])
	}

	nestedRG := byID["20260708_101512_00043_abcde"]
	if nestedRG == nil || nestedRG["resource_group"] != "global.adhoc" {
		t.Fatalf("expected dotted resource_group, got %+v", nestedRG)
	}

	failed := byID["q-failed"]
	if failed == nil || failed["error_code"] != "EXCEEDED_LOCAL_MEMORY_LIMIT" {
		t.Fatalf("expected error_code on FAILED row, got %+v", failed)
	}
	if _, ok := failed["ended"]; !ok {
		t.Fatalf("FAILED row must carry ended, got %+v", failed)
	}

	minimal := byID["q-minimal"]
	if minimal == nil {
		t.Fatalf("missing minimal row")
	}
	for _, key := range []string{"user", "source", "started", "ended", "error_code", "query_text_head", "resource_group", "queued_time", "elapsed_time"} {
		if _, ok := minimal[key]; ok {
			t.Fatalf("minimal row must omit %q, got %+v", key, minimal)
		}
	}
}

func TestExecute_PrestoListQueries_RequiredFieldMissing(t *testing.T) {
	for _, tc := range []struct {
		body    []any
		wantErr string
	}{
		{[]any{map[string]any{"state": "RUNNING"}}, "query_id"},
		{[]any{map[string]any{"queryId": "q1"}}, "state"},
	} {
		srv := listQueriesTestServer(t, tc.body, false)
		a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

		result, err := a.Execute(context.Background(), platform.ToolCall{
			ToolName: "presto_list_queries", Args: map[string]any{},
		})
		if err != nil {
			t.Fatalf("unexpected transport error: %v", err)
		}
		if result.Error == "" || !strings.Contains(result.Error, tc.wantErr) {
			t.Fatalf("expected error naming %s, got %q", tc.wantErr, result.Error)
		}
	}
}

func TestExecute_PrestoListQueries_NonArrayBody(t *testing.T) {
	srv := listQueriesTestServer(t, map[string]any{"queries": []any{}}, false)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries", Args: map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.Error == "" || !strings.Contains(result.Error, "non-array") {
		t.Fatalf("expected non-array error, got %q", result.Error)
	}
}

func TestExecute_PrestoListQueries_NonObjectElement(t *testing.T) {
	body := []any{
		map[string]any{"queryId": "q1", "state": "RUNNING"},
		"not-an-object",
	}
	srv := listQueriesTestServer(t, body, false)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries", Args: map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.Error == "" || !strings.Contains(result.Error, "not an object") {
		t.Fatalf("expected non-object element error, got %q", result.Error)
	}
}

func TestExecute_PrestoListQueries_Filters(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339)
	body := []any{
		map[string]any{
			"queryId": "q-failed", "state": "FAILED", "query": "SELECT 1",
			"session":    map[string]any{"user": "etl_svc", "source": "airflow"},
			"queryStats": map[string]any{"createTime": now, "endTime": now},
		},
		map[string]any{
			"queryId": "q-running", "state": "RUNNING", "query": "SELECT needle",
			"session":    map[string]any{"user": "analyst", "source": "adhoc"},
			"queryStats": map[string]any{"createTime": now},
		},
	}
	srv := listQueriesTestServer(t, body, false)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args: map[string]any{
			"state": "RUNNING", "user": "analyst", "query_substr": "needle", "limit": 1,
		},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows := result.Data.([]map[string]any)
	if len(rows) != 1 || rows[0]["query_id"] != "q-running" {
		t.Fatalf("unexpected filtered rows: %+v", rows)
	}
}

func TestExecute_PrestoListQueries_Since(t *testing.T) {
	fixture := loadV1QueryFixture(t)
	srv := listQueriesTestServer(t, fixture, false)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args:     map[string]any{"since": "1h", "limit": 200},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows := result.Data.([]map[string]any)
	ids := map[string]bool{}
	for _, row := range rows {
		ids[row["query_id"].(string)] = true
	}
	if !ids["q-finished-recent"] {
		t.Fatalf("terminal row inside window must be kept, got ids=%v", keysOfBool(ids))
	}
	if ids["q-finished-old"] {
		t.Fatalf("terminal row outside window must be dropped, got ids=%v", keysOfBool(ids))
	}
	if !ids["q-runaway-old"] {
		t.Fatalf("non-terminal old row must be kept (runaway case), got ids=%v", keysOfBool(ids))
	}
	if !ids["q-bad-ended"] {
		t.Fatalf("unparseable ended must be kept, got ids=%v", keysOfBool(ids))
	}

	// `d` unit parsed.
	result, err = a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args:     map[string]any{"since": "1d", "limit": 200},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("since=1d: unexpected result: %+v err=%v", result, err)
	}
	rows = result.Data.([]map[string]any)
	ids = map[string]bool{}
	for _, row := range rows {
		ids[row["query_id"].(string)] = true
	}
	if !ids["q-finished-old"] {
		t.Fatalf("1d window must include older terminal row, got ids=%v", keysOfBool(ids))
	}
}

func TestExecute_PrestoListQueries_SinceKeepsNonTerminalWithEpochEndTime(t *testing.T) {
	epochEnd := "1970-01-01T00:00:00.000Z"
	recentCreate := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	oldRealEnd := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	body := []any{
		map[string]any{
			"queryId": "q-queued-epoch",
			"state":   "QUEUED",
			"query":   "SELECT 1",
			"session": map[string]any{"user": "analyst"},
			"queryStats": map[string]any{
				"createTime": recentCreate,
				"endTime":    epochEnd,
			},
		},
		map[string]any{
			"queryId": "q-running-epoch",
			"state":   "RUNNING",
			"query":   "SELECT 2",
			"session": map[string]any{"user": "analyst"},
			"queryStats": map[string]any{
				"createTime": recentCreate,
				"endTime":    epochEnd,
			},
		},
		map[string]any{
			"queryId": "q-queued-old-end",
			"state":   "QUEUED",
			"query":   "SELECT 3",
			"session": map[string]any{"user": "analyst"},
			"queryStats": map[string]any{
				"createTime": recentCreate,
				"endTime":    oldRealEnd,
			},
		},
	}
	srv := listQueriesTestServer(t, body, false)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args:     map[string]any{},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows, ok := result.Data.([]map[string]any)
	if !ok {
		t.Fatalf("expected []map rows, got %T", result.Data)
	}
	if len(rows) != 3 {
		t.Fatalf("default since=1h must keep non-terminal rows (epoch and old real endTime), got %d rows: %+v", len(rows), rows)
	}
	ids := map[string]bool{}
	for _, row := range rows {
		qid := row["query_id"].(string)
		ids[qid] = true
		switch qid {
		case "q-queued-epoch", "q-running-epoch":
			if _, hasEnded := row["ended"]; hasEnded {
				t.Fatalf("epoch endTime must not map to ended on row %q: %+v", qid, row)
			}
		case "q-queued-old-end":
			ended, ok := row["ended"].(string)
			if !ok || ended != oldRealEnd {
				t.Fatalf("real endTime must map to ended on row %q: %+v", qid, row)
			}
		}
	}
	if !ids["q-queued-epoch"] || !ids["q-running-epoch"] || !ids["q-queued-old-end"] {
		t.Fatalf("expected all three non-terminal rows, got ids=%v", keysOfBool(ids))
	}
}

func TestExecute_PrestoListQueries_RedactsQueryText(t *testing.T) {
	secretQuery := "CREATE TABLE t WITH (connection-url = 'jdbc:mysql://svc:hunter2@db:3306/analytics')"
	body := []any{
		map[string]any{
			"queryId": "q-secret", "state": "RUNNING", "query": secretQuery,
			"queryStats": map[string]any{"createTime": time.Now().UTC().Format(time.RFC3339)},
		},
		map[string]any{
			"queryId": "q-clean", "state": "RUNNING", "query": "SELECT 1",
			"queryStats": map[string]any{"createTime": time.Now().UTC().Format(time.RFC3339)},
		},
	}
	srv := listQueriesTestServer(t, body, false)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries", Args: map[string]any{},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true when query text embeds a credential")
	}
	serialized, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(serialized), "hunter2") {
		t.Fatalf("secret leaked: %s", serialized)
	}
	if !strings.Contains(string(serialized), "***REDACTED***") {
		t.Fatalf("expected redaction placeholder in query text, got: %s", serialized)
	}

	result, err = a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args:     map[string]any{"query_substr": "SELECT 1"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("clean row: unexpected result: %+v err=%v", result, err)
	}
	if result.Redacted {
		t.Fatalf("expected redacted=false for clean row set, got %+v", result)
	}
}

func keysOf(m map[string]map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func keysOfBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestExecute_PrestoQueryDetail(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/query/20260709_1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"state":"FAILED","errorCode":{"code":123},"errorType":"USER_ERROR",
			"queryStats":{"elapsedTime":"1.2s"},"outputStage":{"stageId":"0"},"session":{"user":"x"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_query_detail",
		Args:     map[string]any{"query_id": "20260709_1", "sections": []any{"basic", "error", "stats"}},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	if _, ok := data["basic"]; !ok {
		t.Fatalf("expected basic section, got %+v", data)
	}
	if _, ok := data["stages"]; ok {
		t.Fatalf("did not request stages section, got %+v", data)
	}
}

func TestExecute_PrestoQueryJSONSection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/query/q1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"outputStage":{"stageId":"0","subStages":[{"stageId":"1"}]}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_query_json_section",
		Args:     map[string]any{"query_id": "q1", "jsonpath": "$.outputStage.stageId"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	if data["result"] != "0" {
		t.Fatalf("unexpected jsonpath result: %+v", data)
	}
}

// TestExecute_PrestoQueryDetail_RedactsSessionSection is a regression test
// for design.md Section 8.2/8.5 (v1.6): the `session` section of
// presto_query_detail carries the same session-property data
// presto_session_properties does, and must be redacted the same way. Before
// the fix, toolPrestoQueryDetail returned fullMap["session"] verbatim with
// no redaction pass, so a JDBC-userinfo-style connection-url embedded in a
// session property would leak straight to the control plane.
func TestExecute_PrestoQueryDetail_RedactsSessionSection(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/query/20260709_2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"state":"FINISHED","session":{"user":"x","catalogProperties":
			{"mysql":{"connection-url":"jdbc:mysql://svc:hunter2@db:3306/analytics"}}}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_query_detail",
		Args:     map[string]any{"query_id": "20260709_2", "sections": []any{"session"}},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true when the session section embeds a credential, got %+v", result)
	}
	serialized, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatalf("marshal result.Data: %v", err)
	}
	if strings.Contains(string(serialized), "hunter2") {
		t.Fatalf("secret leaked unredacted in presto_query_detail session section: %s", serialized)
	}
	if !strings.Contains(string(serialized), "REDACTED") {
		t.Fatalf("expected a redaction placeholder in the session section, got: %s", serialized)
	}
}

// TestExecute_PrestoQueryJSONSection_RedactsSessionData is a regression
// test for design.md Section 8.2/8.5 (v1.6): presto_query_json_section can
// JSONPath-slice straight to the same `session` data
// presto_query_detail exposes -- an independent bypass route that must be
// redacted too, or fixing presto_query_detail alone leaves a leak channel
// open via this tool. Before the fix, toolPrestoQueryJSONSection returned
// the raw jsonpath.Get result with no redaction pass at all.
func TestExecute_PrestoQueryJSONSection_RedactsSessionData(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/query/q2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"session":{"user":"x","catalogProperties":
			{"mysql":{"connection-url":"jdbc:mysql://svc:hunter2@db:3306/analytics"}}}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_query_json_section",
		Args:     map[string]any{"query_id": "q2", "jsonpath": "$.session"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true when the JSONPath-sliced session data embeds a credential, got %+v", result)
	}
	serialized, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatalf("marshal result.Data: %v", err)
	}
	if strings.Contains(string(serialized), "hunter2") {
		t.Fatalf("secret leaked unredacted via presto_query_json_section (redaction-bypass route): %s", serialized)
	}
	if !strings.Contains(string(serialized), "REDACTED") {
		t.Fatalf("expected a redaction placeholder in the jsonpath result, got: %s", serialized)
	}
}

func TestExecute_PrestoSessionProperties(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		writeStatementResponse(w, []string{"Name", "Value", "Default"}, [][]any{{"query_max_memory", "10GB", "5GB"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "presto_session_properties", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	props := data["properties"].([]map[string]any)
	if len(props) != 1 || props[0]["name"] != "query_max_memory" {
		t.Fatalf("unexpected properties: %+v", props)
	}
}

func TestExecute_PrestoSessionProperties_NameBasedRedaction(t *testing.T) {
	// design.md Appendix B.1 / Section 8.2 (v1.5, S3): presto_session_properties
	// is explicitly in scope for redaction now, same as presto_config. A
	// property whose *name* matches KeyPattern must have its value (and
	// default) fully redacted.
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		writeStatementResponse(w, []string{"Name", "Value", "Default"}, [][]any{
			{"http-server.https.keystore.password", "hunter2", "changeit"},
			{"query.max-memory", "10GB", "5GB"},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "presto_session_properties", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true, got %+v", result)
	}
	data := result.Data.(map[string]any)
	props := data["properties"].([]map[string]any)
	if len(props) != 2 {
		t.Fatalf("unexpected properties: %+v", props)
	}
	if props[0]["value"] != "***REDACTED***" || props[0]["default"] != "***REDACTED***" {
		t.Fatalf("expected the keystore password property fully redacted, got %+v", props[0])
	}
	if props[1]["value"] != "10GB" || props[1]["default"] != "5GB" {
		t.Fatalf("expected the unrelated property to survive unchanged, got %+v", props[1])
	}
}

func TestExecute_PrestoSessionProperties_ValueBasedRedaction(t *testing.T) {
	// A property name that does NOT match KeyPattern, but whose value
	// embeds a URL-userinfo credential, must still be caught (value-based
	// scanning, independent of the key/name).
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		writeStatementResponse(w, []string{"Name", "Value", "Default"}, [][]any{
			{"catalog.mysql.connection-url", "jdbc:mysql://svc:hunter2@db:3306/analytics", ""},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "presto_session_properties", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true, got %+v", result)
	}
	data := result.Data.(map[string]any)
	props := data["properties"].([]map[string]any)
	value, _ := props[0]["value"].(string)
	if strings.Contains(value, "hunter2") {
		t.Fatalf("password leaked into presto_session_properties output: %+v", props)
	}
	if !strings.Contains(value, "***REDACTED***") {
		t.Fatalf("expected the embedded credential to be redacted, got %+v", props)
	}
}

func TestExecute_PrestoSessionProperties_NoRedactionNeeded(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		writeStatementResponse(w, []string{"Name", "Value", "Default"}, [][]any{{"query_max_memory", "10GB", "5GB"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "presto_session_properties", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if result.Redacted {
		t.Fatalf("expected redacted=false for a property with no secret, got %+v", result)
	}
}

func TestExecute_PrestoJMX_ResolvesAlias(t *testing.T) {
	var capturedSQL string
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(buf)
		capturedSQL = string(buf)
		writeStatementResponse(w, []string{"node", "HeapMemoryUsage"}, [][]any{{"n1", "used=123"}})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_jmx", Args: map[string]any{"mbean": "heap"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows := result.Data.([]map[string]any)
	if len(rows) != 1 || rows[0]["mbean"] != "java.lang:type=Memory" {
		t.Fatalf("unexpected rows (alias not resolved?): %+v", rows)
	}
	// The mbean must be the quoted table identifier, not merely mentioned in a
	// comment: `SELECT * FROM jmx.current."java.lang:type=Memory"`. A bare
	// `FROM jmx.current` parses as schema.table and fails on a real cluster.
	if !strings.Contains(capturedSQL, `jmx.current."java.lang:type=Memory"`) {
		t.Fatalf("expected SQL to target the quoted mbean table, got %q", capturedSQL)
	}
}

func TestExecute_PrestoJMX_SQLError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":{"message":"mbean not found","errorCode":"GENERIC_USER_ERROR"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_jmx", Args: map[string]any{"mbean": "com.example:type=Foo"},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.Error == "" {
		t.Fatalf("expected error envelope")
	}
}
