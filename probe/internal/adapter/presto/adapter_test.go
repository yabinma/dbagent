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
	"github.com/yabinma/dbagent/probe/internal/prestoclient"
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

	// Write-method call records / injected errors (M5).
	lastPatchCM    struct {
		ns, name string
		patches  map[string]string
	}
	patchCMErr error
	lastReadCM struct {
		ns, name, key string
	}
	readCMText string
	readCMErr  error
	lastRestart    struct{ ns, kind, name string }
	restartErr     error
	lastDeletePod  struct{ ns, name string }
	deletePodErr   error
	lastUpdateEnv  struct {
		service string
		env     map[string]string
	}
	updateEnvErr   error
	lastRestartSvc string
	restartSvcErr  error
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

// Write methods (M5) — recorded for ExecuteWrite unit tests.
func (f *fakeEnv) ReadConfigMapKey(ctx context.Context, namespace, name, key string) (string, error) {
	f.lastReadCM = struct{ ns, name, key string }{namespace, name, key}
	if f.readCMErr != nil {
		return "", f.readCMErr
	}
	if f.readCMText != "" {
		return f.readCMText, nil
	}
	return f.configText, f.configErr
}
func (f *fakeEnv) PatchConfigMap(ctx context.Context, namespace, name string, dataPatches map[string]string) error {
	f.lastPatchCM = struct {
		ns, name string
		patches  map[string]string
	}{namespace, name, dataPatches}
	return f.patchCMErr
}
func (f *fakeEnv) RolloutRestart(ctx context.Context, namespace, kind, name string) error {
	f.lastRestart = struct{ ns, kind, name string }{namespace, kind, name}
	return f.restartErr
}
func (f *fakeEnv) DeletePod(ctx context.Context, namespace, name string) error {
	f.lastDeletePod = struct{ ns, name string }{namespace, name}
	return f.deletePodErr
}
func (f *fakeEnv) UpdateServiceEnv(ctx context.Context, service string, env map[string]string) error {
	f.lastUpdateEnv = struct {
		service string
		env     map[string]string
	}{service, env}
	return f.updateEnvErr
}
func (f *fakeEnv) RestartService(ctx context.Context, service string) error {
	f.lastRestartSvc = service
	return f.restartSvcErr
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

func TestExecuteWrite_RequiresEnv(t *testing.T) {
	a := New(Config{WriteEnabled: true})
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "presto_kill_query", SignatureOK: true,
		Params: map[string]any{"query_id": "q1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected failure when env is nil")
	}
}

func TestExecuteWrite_PrestoKillQuery(t *testing.T) {
	var deleted string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/query/") {
			deleted = strings.TrimPrefix(r.URL.Path, "/v1/query/")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.http.port=8080\n", baseURL: srv.URL}
	a := New(Config{WriteEnabled: true, PlatformKey: "p1", InsecureSkipVerify: true})
	if _, err := a.Detect(context.Background(), env); err != nil {
		// Detect may fail without full Presto; set env+client manually for unit focus.
		a.env = env
		a.presto = prestoclient.New(srv.URL, srv.Client())
	}
	// Ensure env+client wired even if Detect partially failed.
	a.env = env
	if a.presto == nil {
		a.presto = prestoclient.New(srv.URL, srv.Client())
	}

	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "presto_kill_query", SignatureOK: true,
		Params: map[string]any{"query_id": "20240101_q1"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK, got error=%s", result.Error)
	}
	if deleted != "20240101_q1" {
		t.Fatalf("expected DELETE for query, got %q", deleted)
	}
}

func TestExecuteWrite_K8sPatchConfigMap(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindK8s}
	a := New(Config{WriteEnabled: true})
	a.env = env
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "k8s_patch_configmap", SignatureOK: true,
		Params: map[string]any{
			"name": "presto-worker-config", "namespace": "presto",
			"patches": []any{map[string]any{"key": "config.properties", "value": "x=1\n"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK, got %s", result.Error)
	}
	if env.lastPatchCM.name != "presto-worker-config" {
		t.Fatalf("patch not recorded: %+v", env.lastPatchCM)
	}
}

func TestExecuteWrite_ParamValidationRejects(t *testing.T) {
	a := New(Config{WriteEnabled: true})
	a.env = &fakeEnv{kind: platform.EnvKindK8s}
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "presto_kill_query", SignatureOK: true,
		Params: map[string]any{}, // missing query_id
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected param validation failure")
	}
}

func TestExecuteWrite_AdjustMemoryConfigWhitelistRejects(t *testing.T) {
	a := New(Config{WriteEnabled: true})
	a.env = &fakeEnv{kind: platform.EnvKindK8s, configText: "query.max-memory=10GB\n"}
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		PlaybookID: "presto.adjust_memory_config",
		Op:         "k8s_patch_configmap", SignatureOK: true,
		Params: map[string]any{
			"name": "cm", "namespace": "ns",
			"patches": []any{map[string]any{"key": "evil.key", "value": "1"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OK {
		t.Fatalf("expected whitelist reject, got OK detail=%s", result.Detail)
	}
}

func TestExecuteWrite_AdjustMemoryConfigWhitelistAccept(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindK8s, configText: "query.max-memory=10GB\nother=1\n"}
	a := New(Config{WriteEnabled: true})
	a.env = env
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		PlaybookID: "presto.adjust_memory_config",
		Op:         "k8s_patch_configmap", SignatureOK: true,
		Params: map[string]any{
			"name": "cm", "namespace": "ns",
			"patches": []any{map[string]any{"key": "query.max-memory", "value": "50GB"}},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK, got %s", result.Error)
	}
	// Merged content should include the new value.
	got := env.lastPatchCM.patches["config.properties"]
	if !strings.Contains(got, "query.max-memory=50GB") {
		t.Fatalf("expected merged memory config, got %q", got)
	}
}

type simpleErr string

func (e simpleErr) Error() string { return string(e) }
func assertErr(s string) error    { return simpleErr(s) }

func TestExecuteWrite_K8sRolloutRestartAndDeletePod(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindK8s}
	a := New(Config{WriteEnabled: true})
	a.env = env
	r, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "k8s_rollout_restart", SignatureOK: true,
		Params: map[string]any{"kind": "deployment", "name": "w", "namespace": "ns"},
	})
	if err != nil || !r.OK {
		t.Fatalf("rollout: %+v err=%v", r, err)
	}
	if env.lastRestart.name != "w" {
		t.Fatalf("restart not recorded")
	}
	r, err = a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "k8s_delete_pod", SignatureOK: true,
		Params: map[string]any{"name": "pod1", "namespace": "ns"},
	})
	if err != nil || !r.OK {
		t.Fatalf("delete: %+v err=%v", r, err)
	}
}

func TestExecuteWrite_SwarmOps(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindSwarm}
	a := New(Config{WriteEnabled: true})
	a.env = env
	r, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "swarm_update_service_env", SignatureOK: true,
		Params: map[string]any{
			"service": "presto-worker",
			"env":     []any{map[string]any{"key": "A", "value": "1"}},
		},
	})
	if err != nil || !r.OK {
		t.Fatalf("update env: %+v err=%v", r, err)
	}
	r, err = a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "swarm_restart_service", SignatureOK: true,
		Params: map[string]any{"service": "presto-worker"},
	})
	if err != nil || !r.OK {
		t.Fatalf("restart svc: %+v err=%v", r, err)
	}
}

func TestExecuteWrite_PrimitiveFailure(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindK8s, deletePodErr: assertErr("nope")}
	a := New(Config{WriteEnabled: true})
	a.env = env
	r, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "k8s_delete_pod", SignatureOK: true,
		Params: map[string]any{"name": "p", "namespace": "ns"},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if r.OK {
		t.Fatalf("expected failure")
	}
}

func TestExecuteWrite_UnknownOp(t *testing.T) {
	a := New(Config{WriteEnabled: true})
	a.env = &fakeEnv{}
	// unknown op fails schema load / not in catalog
	r, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "not_a_real_op", SignatureOK: true, Params: map[string]any{},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if r.OK {
		t.Fatalf("expected unknown op reject")
	}
}

func TestExecuteWrite_AdjustMemorySwarm(t *testing.T) {
	env := &fakeEnv{kind: platform.EnvKindSwarm, configText: "query.max-memory=10GB\n"}
	a := New(Config{WriteEnabled: true})
	a.env = env
	r, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		PlaybookID: "presto.adjust_memory_config",
		Op:         "swarm_update_service_env", SignatureOK: true,
		Params: map[string]any{
			"service": "presto-worker",
			"env":     []any{map[string]any{"key": "query.max-memory", "value": "50GB"}},
		},
	})
	if err != nil || !r.OK {
		t.Fatalf("got %+v err=%v", r, err)
	}
	if env.lastUpdateEnv.env["query.max-memory"] != "50GB" {
		t.Fatalf("env not updated: %+v", env.lastUpdateEnv)
	}
}

// rollingCoordinatorEnv simulates a K8s coordinator rollout: the first
// CoordinatorBaseURL call (Detect) returns detectURL; every later call
// returns postRolloutURL.
type rollingCoordinatorEnv struct {
	fakeEnv
	detectURL      string
	postRolloutURL string
	baseURLCalls   int
}

func (e *rollingCoordinatorEnv) CoordinatorBaseURL(ctx context.Context) (string, error) {
	e.baseURLCalls++
	if e.baseURLCalls == 1 {
		return e.detectURL, e.baseURLErr
	}
	return e.postRolloutURL, e.baseURLErr
}

func TestExecute_NonRESTToolsSucceedWhenCoordinatorUnresolvable(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	env := &fakeEnv{
		kind:       platform.EnvKindK8s,
		configText: "http-server.authentication.type=NONE\n",
		baseURL:    srv.URL,
		targets:    []platform.TargetInfo{{Name: "presto-coordinator-0", Phase: "Running"}},
	}
	a := New(Config{CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	// Simulate coordinator pod gone (no Ready pod) after Detect succeeded.
	env.baseURLErr = assertErr("no ready coordinator pod")

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "k8s_pods",
		Args:     map[string]any{},
	})
	if err != nil {
		t.Fatalf("k8s_pods transport error: %v", err)
	}
	if result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("k8s_pods should succeed without coordinator URL, got exit=%d err=%q", result.ExitCode, result.Error)
	}

	result, err = a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_config",
		Args:     map[string]any{"component": "coordinator", "file": "config"},
	})
	if err != nil {
		t.Fatalf("presto_config transport error: %v", err)
	}
	if result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("presto_config should succeed without coordinator URL, got exit=%d err=%q", result.ExitCode, result.Error)
	}

	result, err = a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args:     map[string]any{},
	})
	if err != nil {
		t.Fatalf("presto_list_queries transport error: %v", err)
	}
	if result.ExitCode == 0 || result.Error == "" {
		t.Fatalf("presto_list_queries should fail on resolve error, got exit=%d err=%q", result.ExitCode, result.Error)
	}
	if !strings.Contains(result.Error, "resolve coordinator url") {
		t.Fatalf("expected resolve error, got %q", result.Error)
	}
}

func TestExecute_ReResolvesCoordinatorURLAfterRollout(t *testing.T) {
	var statementServer string
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/info" {
			w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
			return
		}
		if r.URL.Path == "/v1/statement" && r.Method == http.MethodPost {
			statementServer = "A"
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/statement" && r.Method == http.MethodPost {
			statementServer = "B"
			writeStatementResponse(w,
				[]string{"query_id", "state", "user", "source", "created", "query"},
				[][]any{{"q1", "RUNNING", "u", "s", "2026-01-01", "SELECT 1"}},
			)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srvA.Close)
	t.Cleanup(srvB.Close)

	env := &rollingCoordinatorEnv{
		fakeEnv:        fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n"},
		detectURL:      srvA.URL,
		postRolloutURL: srvB.URL,
	}
	a := New(Config{PlatformKey: "presto-us1", CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "presto_list_queries",
		Args:     map[string]any{},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("expected success, got exit=%d err=%q", result.ExitCode, result.Error)
	}
	if statementServer != "B" {
		t.Fatalf("presto_list_queries POST landed on server %q, want B (stale Detect-time URL is A)", statementServer)
	}
}

func TestExecuteWrite_PrestoKillQuery_ReResolvesCoordinatorURLAfterRollout(t *testing.T) {
	var deleteServer string
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/info" {
			w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
			return
		}
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/query/") {
			deleteServer = "A"
			http.NotFound(w, r)
			return
		}
		http.NotFound(w, r)
	}))
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/query/") {
			deleteServer = "B"
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srvA.Close)
	t.Cleanup(srvB.Close)

	env := &rollingCoordinatorEnv{
		fakeEnv:        fakeEnv{kind: platform.EnvKindK8s, configText: "http-server.authentication.type=NONE\n"},
		detectURL:      srvA.URL,
		postRolloutURL: srvB.URL,
	}
	a := New(Config{WriteEnabled: true, CredentialsMountPath: t.TempDir()})
	if _, err := a.Detect(context.Background(), env); err != nil {
		t.Fatalf("detect failed: %v", err)
	}

	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		Op: "presto_kill_query", SignatureOK: true,
		Params: map[string]any{"query_id": "20260819_211417_00000_w6mpi"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.OK {
		t.Fatalf("expected OK, got error=%s", result.Error)
	}
	if deleteServer != "B" {
		t.Fatalf("presto_kill_query DELETE landed on server %q, want B (stale Detect-time URL is A)", deleteServer)
	}
}

func TestMergePropertiesHelpers(t *testing.T) {
	got := mergeProperties("a=1\nb=2\n", map[string]string{"a": "9"})
	if !strings.Contains(got, "a=9") {
		t.Fatalf("got %q", got)
	}
	got = setProperty("", "k", "v")
	if !strings.Contains(got, "k=v") {
		t.Fatalf("got %q", got)
	}
}
