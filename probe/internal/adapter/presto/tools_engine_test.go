package presto

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestExecute_PrestoListQueries(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		writeStatementResponse(w,
			[]string{"query_id", "state", "user", "source", "created", "query"},
			[][]any{
				{"q1", "FAILED", "etl_svc", "airflow", "2026-07-09T10:00:00Z", "SELECT 1"},
				{"q2", "RUNNING", "analyst", "adhoc", "2026-07-09T10:05:00Z", "SELECT 2"},
			},
		)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries", Args: map[string]any{"state": "FAILED"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows := result.Data.([]map[string]any)
	if len(rows) != 1 || rows[0]["query_id"] != "q1" {
		t.Fatalf("unexpected filtered rows: %+v", rows)
	}
}

func TestExecute_PrestoListQueries_SQLError(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"}}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":{"message":"catalog unavailable","errorCode":"CATALOG_NOT_FOUND"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	a, _ := detectedAdapter(t, srv, platform.EnvKindK8s)

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "presto_list_queries", Args: map[string]any{}})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.Error == "" {
		t.Fatalf("expected error envelope for SQL failure")
	}
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
