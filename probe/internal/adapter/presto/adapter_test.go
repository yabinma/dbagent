package presto

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

// fakeEnv is a lightweight platform.RuntimeEnv double for adapter-level
// tests. RuntimeEnv's own K8s/Docker-backed implementations
// (runtimeenv/k8senv, runtimeenv/dockerenv) are already fully unit tested
// against client-go fake / an httptest Docker mock; this fake keeps
// adapter tests focused on Detect/Execute/HealthCheck/WriteOps logic.
type fakeEnv struct {
	kind       platform.EnvKind
	configText string
	configErr  error
	baseURL    string
	baseURLErr error

	targets  []platform.TargetInfo
	logs     []string
	describe platform.DescribeResult
	events   []platform.EventInfo
	usage    []platform.ResourceUsageInfo
	execRes  platform.ExecResult
	execErr  error
}

func (f *fakeEnv) Kind() platform.EnvKind { return f.kind }
func (f *fakeEnv) ListTargets(ctx context.Context, selector string) ([]platform.TargetInfo, error) {
	return f.targets, nil
}
func (f *fakeEnv) Logs(ctx context.Context, target, container string, opts platform.LogOptions) ([]string, error) {
	return f.logs, nil
}
func (f *fakeEnv) Describe(ctx context.Context, target string) (platform.DescribeResult, error) {
	return f.describe, nil
}
func (f *fakeEnv) Events(ctx context.Context, opts platform.EventOptions) ([]platform.EventInfo, error) {
	return f.events, nil
}
func (f *fakeEnv) ResourceUsage(ctx context.Context, selector string) ([]platform.ResourceUsageInfo, error) {
	return f.usage, nil
}
func (f *fakeEnv) Exec(ctx context.Context, target, container string, cmd []string, timeout time.Duration) (platform.ExecResult, error) {
	return f.execRes, f.execErr
}
func (f *fakeEnv) ReadConfig(ctx context.Context, component, file, target string) (string, error) {
	return f.configText, f.configErr
}
func (f *fakeEnv) CoordinatorBaseURL(ctx context.Context) (string, error) {
	return f.baseURL, f.baseURLErr
}

// newPrestoTestServer returns an httptest server that answers the REST
// endpoints Detect()/tools call, with a configurable SQL-query responder.
func newPrestoTestServer(t *testing.T, sqlHandler func(sql string) (columns []string, rows [][]any)) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
	})
	mux.HandleFunc("/v1/cluster", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"runningQueries":1,"queuedQueries":2,"blockedQueries":0,"activeWorkers":3,"totalMemoryBytes":1000,"reservedMemoryBytes":100}`))
	})
	mux.HandleFunc("/v1/node", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"nodeId":"n1","uri":"http://10.0.0.1:8080","coordinator":false,"nodeVersion":{"version":"0.298"}}]`))
	})
	mux.HandleFunc("/v1/node/failed", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		cols, rows := []string{"node_id"}, [][]any{{"n1"}}
		if sqlHandler != nil {
			cols, rows = sqlHandler(string(body))
		}
		writeStatementResponse(w, cols, rows)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func writeStatementResponse(w http.ResponseWriter, columns []string, rows [][]any) {
	colObjs := make([]map[string]string, len(columns))
	for i, c := range columns {
		colObjs[i] = map[string]string{"name": c}
	}
	resp := map[string]any{
		"columns": colObjs,
		"data":    rows,
		"stats":   map[string]string{"state": "FINISHED"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func newCredsDir(t *testing.T, username, password string) string {
	t.Helper()
	dir := t.TempDir()
	if username != "" {
		os.WriteFile(filepath.Join(dir, "username"), []byte(username), 0o600)
	}
	if password != "" {
		os.WriteFile(filepath.Join(dir, "password"), []byte(password), 0o600)
	}
	return dir
}

func TestDetect_NoneAuth_Success(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n", baseURL: srv.URL}
	a := New(Config{PlatformKey: "presto-us1", CredentialsMountPath: t.TempDir()})

	manifest, err := a.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest.Auth.Access != "full" || manifest.Auth.Scheme != "NONE" {
		t.Fatalf("unexpected auth: %+v", manifest.Auth)
	}
	if manifest.EngineVersion != "0.298" {
		t.Fatalf("unexpected version: %s", manifest.EngineVersion)
	}
	if manifest.Deployment != "k8s" || manifest.PlatformType != "presto" {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if len(manifest.Tools) == 0 {
		t.Fatalf("expected tools to be registered")
	}
}

func TestDetect_PasswordAuth_CredentialsMissing(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=PASSWORD\n", baseURL: srv.URL}
	a := New(Config{CredentialsMountPath: t.TempDir()})

	manifest, err := a.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest.Auth.Access == "full" {
		t.Fatalf("expected non-full access when credentials are missing")
	}
	if len(manifest.Auth.Missing) == 0 {
		t.Fatalf("expected missing credentials to be reported")
	}
}

func TestDetect_PasswordAuth_CredentialsPresent_Success(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=PASSWORD\n", baseURL: srv.URL}
	a := New(Config{CredentialsMountPath: newCredsDir(t, "svc", "hunter2")})

	manifest, err := a.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest.Auth.Access != "full" {
		t.Fatalf("expected full access, got %+v", manifest.Auth)
	}
}

func TestDetect_PasswordAuth_HTTPS_MissingCA(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{
		kind: platform.EnvKindK8s,
		configText: "http-server.authentication.type=PASSWORD\n" +
			"http-server.https.enabled=true\n",
		baseURL: srv.URL,
	}
	a := New(Config{CredentialsMountPath: newCredsDir(t, "svc", "hunter2")})

	manifest, err := a.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	found := false
	for _, m := range manifest.Auth.Missing {
		if m == "tls_ca" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected tls_ca in missing list, got %+v", manifest.Auth.Missing)
	}
}

func TestDetect_PasswordAuth_HTTPS_DeploymentCAResolves(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{
		kind: platform.EnvKindK8s,
		configText: "http-server.authentication.type=PASSWORD\n" +
			"http-server.https.enabled=true\n",
		baseURL: srv.URL,
	}
	a := New(Config{
		CredentialsMountPath: newCredsDir(t, "svc", "hunter2"),
		DeploymentCAPEM:      []byte("fake-ca-content"), // not a real cert; only checked for "missing" resolution here
	})

	manifest, err := a.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, m := range manifest.Auth.Missing {
		if m == "tls_ca" {
			t.Fatalf("did not expect tls_ca missing when deployment CA is configured: %+v", manifest.Auth.Missing)
		}
	}
}

func TestDetect_Kerberos_Unsupported(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=KERBEROS\n", baseURL: srv.URL}
	a := New(Config{CredentialsMountPath: t.TempDir()})

	manifest, err := a.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if manifest.Auth.Access != "unsupported" || manifest.Auth.Scheme != "KERBEROS" {
		t.Fatalf("unexpected auth: %+v", manifest.Auth)
	}
}

func TestDetect_SwarmDeployment_RegistersSwarmTools(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindSwarm, configText: "http-server.authentication.type=NONE\n", baseURL: srv.URL}
	a := New(Config{CredentialsMountPath: t.TempDir()})

	manifest, err := a.Detect(context.Background(), env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	names := map[string]bool{}
	for _, tool := range manifest.Tools {
		names[tool.Name] = true
	}
	if !names["container_logs"] || !names["swarm_tasks"] || !names["docker_inspect"] || !names["docker_events"] {
		t.Fatalf("expected swarm-specific tools, got %+v", names)
	}
	if names["pod_logs"] || names["k8s_pods"] {
		t.Fatalf("did not expect k8s-specific tools for swarm deployment")
	}
}

func TestDetect_ReadConfigError(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindK8s, configErr: assertErr("boom")}
	a := New(Config{CredentialsMountPath: t.TempDir()})
	_, err := a.Detect(context.Background(), env)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestDetect_CoordinatorURLError(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n", baseURLErr: assertErr("no coordinator")}
	a := New(Config{CredentialsMountPath: t.TempDir()})
	_, err := a.Detect(context.Background(), env)
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestExecute_UnknownTool(t *testing.T) {
	a := New(Config{})
	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "not_a_real_tool"})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.ExitCode == 0 || result.Error == "" {
		t.Fatalf("expected error envelope, got %+v", result)
	}
}

func TestExecute_ValidationFailure(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n", baseURL: srv.URL}
	a := New(Config{CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_cluster_info",
		Args:     map[string]any{"unexpected": "field"},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.ExitCode == 0 || result.Error == "" {
		t.Fatalf("expected validation error envelope, got %+v", result)
	}
}

func TestExecute_Success(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n", baseURL: srv.URL}
	a := New(Config{PlatformKey: "presto-us1", CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	a.SetProbeID("probe-1")

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "presto_cluster_info", Args: map[string]any{}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.PlatformKey != "presto-us1" || result.ProbeID != "probe-1" {
		t.Fatalf("unexpected envelope identity fields: %+v", result)
	}
	data, ok := result.Data.(map[string]any)
	if !ok || data["version"] != "0.298" {
		t.Fatalf("unexpected data: %+v", result.Data)
	}
}

func TestExecute_ConfigToolRedaction(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{
		kind:       platform.EnvKindK8s,
		configText: "http-server.authentication.type=NONE\n",
		baseURL:    srv.URL,
	}
	a := New(Config{CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	// Override env's ReadConfig response for the presto_config call itself.
	env.configText = "connector.name=hive\npassword=hunter2\n"

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_config",
		Args:     map[string]any{"component": "coordinator", "file": "config"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true, got %+v", result)
	}
	data := result.Data.(map[string]any)
	if data["content"] == env.configText {
		t.Fatalf("expected content to be redacted")
	}
}

func TestExecute_ConfigToolRedaction_URLEmbeddedCredential(t *testing.T) {
	// design.md Section 8.2 (v1.5) / W3 regression: a key
	// ("connection-url") that does NOT match the key-based redaction
	// regex must still have its embedded credential caught by the
	// value-based scan.
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{
		kind:       platform.EnvKindK8s,
		configText: "http-server.authentication.type=NONE\n",
		baseURL:    srv.URL,
	}
	a := New(Config{CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}
	env.configText = "connector.name=mysql\nconnection-url=jdbc:mysql://svc:hunter2@db:3306/analytics\n"

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_config",
		Args:     map[string]any{"component": "coordinator", "file": "catalog:mysql"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true, got %+v", result)
	}
	data := result.Data.(map[string]any)
	content, _ := data["content"].(string)
	if strings.Contains(content, "hunter2") {
		t.Fatalf("password leaked into presto_config output: %s", content)
	}
	if !strings.Contains(content, "connection-url=jdbc:mysql://svc:***REDACTED***@db:3306/analytics") {
		t.Fatalf("expected the connection-url password to be redacted in place, got: %s", content)
	}
}

func TestHealthCheck_BuiltinAndCustomQuery(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n", baseURL: srv.URL}
	a := New(Config{CredentialsMountPath: t.TempDir(), HealthQuery: "SELECT count(*) FROM hive.default.probe_canary LIMIT 1"})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	result, err := a.HealthCheck(context.Background(), platform.HealthSpec{BuiltinProbe: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected health check to pass, got %+v", result)
	}
}

func TestHealthCheck_FailureWhenQueryErrors(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"error":{"message":"canary query failed","errorCode":"GENERIC_INTERNAL_ERROR"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n", baseURL: srv.URL}
	a := New(Config{CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	result, err := a.HealthCheck(context.Background(), platform.HealthSpec{BuiltinProbe: true})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected health check to fail when the canary query errors")
	}
}

func TestWriteOps_EmptyWhenDisabled(t *testing.T) {
	a := New(Config{WriteEnabled: false})
	if ops := a.WriteOps(); len(ops) != 0 {
		t.Fatalf("expected no write ops, got %+v", ops)
	}
}

func TestWriteOps_ReturnsCatalogWhenEnabled(t *testing.T) {
	a := New(Config{WriteEnabled: true})
	ops := a.WriteOps()
	if len(ops) == 0 {
		t.Fatalf("expected write ops catalog to be non-empty")
	}
	names := map[string]bool{}
	for _, op := range ops {
		names[op.Name] = true
	}
	if !names["presto_kill_query"] || !names["k8s_patch_configmap"] {
		t.Fatalf("unexpected write ops catalog: %+v", names)
	}
}

func TestExecuteWrite_DisabledDeployment(t *testing.T) {
	a := New(Config{WriteEnabled: false})
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{Op: "presto_kill_query", SignatureOK: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected write to be rejected when write channel disabled")
	}
}

func TestExecuteWrite_SignatureNotVerified(t *testing.T) {
	a := New(Config{WriteEnabled: true})
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{Op: "presto_kill_query", SignatureOK: false})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected write to be rejected when signature not verified")
	}
}

func TestExecuteWrite_NotImplementedStub(t *testing.T) {
	a := New(Config{WriteEnabled: true})
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{Op: "presto_kill_query", SignatureOK: true})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected 'not implemented until M5' stub result")
	}
	if result.Error == "" {
		t.Fatalf("expected an explanatory error message")
	}
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
func assertErr(s string) error    { return simpleErr(s) }
