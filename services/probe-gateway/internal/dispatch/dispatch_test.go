package dispatch_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/dispatch"
)

type fakeDispatcher struct {
	lastPlatform string
	lastTask     *rcaprobev1.TaskRequest
	result       *rcaprobev1.TaskResult
	data         []byte
	err          error
	// delay, when set, blocks Dispatch until the context is cancelled or
	// the delay elapses — used to exercise the timeout path.
	delay time.Duration
}

func (f *fakeDispatcher) Dispatch(ctx context.Context, platformKey string, task *rcaprobev1.TaskRequest) (*rcaprobev1.TaskResult, []byte, error) {
	f.lastPlatform = platformKey
	f.lastTask = task
	if f.delay > 0 {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(f.delay):
		}
	}
	return f.result, f.data, f.err
}

func TestHandleExecute_ToolCall(t *testing.T) {
	fd := &fakeDispatcher{
		result: &rcaprobev1.TaskResult{TaskId: "t1", ExitCode: 0},
		data:   []byte(`{"tool":"presto_cluster_info","exit_code":0,"redacted":false,"data":{"nodes":3}}`),
	}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "presto-us1",
		"task_id":      "t1",
		"kind":         "tool",
		"tool":         "presto_cluster_info",
		"args":         map[string]any{},
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fd.lastPlatform != "presto-us1" {
		t.Fatalf("platform=%q", fd.lastPlatform)
	}
	if fd.lastTask.GetTool() == nil || fd.lastTask.GetTool().GetToolName() != "presto_cluster_info" {
		t.Fatalf("unexpected task: %+v", fd.lastTask)
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if int(resp["exit_code"].(float64)) != 0 {
		t.Fatalf("exit_code=%v", resp["exit_code"])
	}
}

func TestHandleExecute_RawCommand(t *testing.T) {
	fd := &fakeDispatcher{
		result: &rcaprobev1.TaskResult{TaskId: "t2", ExitCode: 0},
		data:   []byte(`{"data":"ok"}`),
	}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "presto-us1",
		"task_id":      "t2",
		"kind":         "raw_command",
		"command":      "cat /etc/presto/config.properties",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if fd.lastTask.GetRaw() == nil || fd.lastTask.GetRaw().GetCommand() != "cat /etc/presto/config.properties" {
		t.Fatalf("unexpected task: %+v", fd.lastTask)
	}
}

func TestHandleExecute_MissingFields(t *testing.T) {
	srv := dispatch.New(&fakeDispatcher{})
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader([]byte(`{}`)))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestHandleExecute_MethodNotAllowed(t *testing.T) {
	srv := dispatch.New(&fakeDispatcher{})
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/execute", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestHealthz(t *testing.T) {
	srv := dispatch.New(&fakeDispatcher{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

// --- error / envelope / buildTaskRequest branches (review.md C1) -----------

func TestHandleExecute_InvalidJSON(t *testing.T) {
	srv := dispatch.New(&fakeDispatcher{})
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader([]byte(`{not-json`)))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("invalid json")) {
		t.Fatalf("expected invalid json message, got %s", rr.Body.String())
	}
}

func TestHandleExecute_DispatchError_502(t *testing.T) {
	fd := &fakeDispatcher{err: errors.New("probe offline")}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "presto-us1",
		"task_id":      "t-fail",
		"kind":         "tool",
		"tool":         "presto_cluster_info",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("probe offline")) {
		t.Fatalf("expected dispatcher error in body, got %s", rr.Body.String())
	}
}

func TestHandleExecute_NonJSONEnvelopeFallback(t *testing.T) {
	fd := &fakeDispatcher{
		result: &rcaprobev1.TaskResult{TaskId: "t3", ExitCode: 0},
		data:   []byte("plain-text-payload"),
	}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "presto-us1",
		"task_id":      "t3",
		"kind":         "tool",
		"tool":         "presto_cluster_info",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["data"] != "plain-text-payload" {
		t.Fatalf("data=%v want plain-text-payload", resp["data"])
	}
}

func TestHandleExecute_ExitCodeFromEnvelope(t *testing.T) {
	// result.ExitCode is 0 but envelope carries exit_code=7 — envelope wins.
	fd := &fakeDispatcher{
		result: &rcaprobev1.TaskResult{TaskId: "t4", ExitCode: 0, Redacted: true, Truncated: true},
		data:   []byte(`{"exit_code":7,"redacted":true,"truncated":true,"data":{"x":1}}`),
	}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "presto-us1",
		"task_id":      "t4",
		"kind":         "tool",
		"tool":         "presto_cluster_info",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if int(resp["exit_code"].(float64)) != 7 {
		t.Fatalf("exit_code=%v want 7 (from envelope)", resp["exit_code"])
	}
	if resp["redacted"] != true || resp["truncated"] != true {
		t.Fatalf("flags redacted=%v truncated=%v", resp["redacted"], resp["truncated"])
	}
}

func TestHandleExecute_EnvelopeWithoutDataKey(t *testing.T) {
	// When envelope has no "data" key, the whole envelope is used as Data.
	fd := &fakeDispatcher{
		result: &rcaprobev1.TaskResult{TaskId: "t5", ExitCode: 0},
		data:   []byte(`{"nodes":3,"state":"active"}`),
	}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "presto-us1",
		"task_id":      "t5",
		"tool":         "presto_cluster_info", // kind omitted → defaults to tool
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	data, ok := resp["data"].(map[string]any)
	if !ok || data["nodes"] == nil {
		t.Fatalf("expected whole envelope as data, got %v", resp["data"])
	}
}

func TestHandleExecute_WithTimeoutSeconds(t *testing.T) {
	// timeout_seconds installs a context deadline; fakeDispatcher respects it.
	fd := &fakeDispatcher{delay: 2 * time.Second}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key":    "presto-us1",
		"task_id":         "t-to",
		"kind":            "tool",
		"tool":            "presto_cluster_info",
		"timeout_seconds": 1,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	// Dispatch returns ctx.Err() → 502.
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleExecute_BuildTaskRequestErrors(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		want string
	}{
		{
			name: "missing tool",
			body: map[string]any{
				"platform_key": "p", "task_id": "t", "kind": "tool",
			},
			want: "tool required",
		},
		{
			name: "missing command",
			body: map[string]any{
				"platform_key": "p", "task_id": "t", "kind": "raw_command",
			},
			want: "command required",
		},
		{
			name: "unknown kind",
			body: map[string]any{
				"platform_key": "p", "task_id": "t", "kind": "weird",
			},
			want: "unknown kind",
		},
	}
	srv := dispatch.New(&fakeDispatcher{})
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
			}
			if !bytes.Contains(rr.Body.Bytes(), []byte(tc.want)) {
				t.Fatalf("body %q does not contain %q", rr.Body.String(), tc.want)
			}
		})
	}
}

func TestHandleExecute_BodyReadError(t *testing.T) {
	// A reader that fails mid-read exercises the "read body" 400 branch.
	srv := dispatch.New(&fakeDispatcher{})
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", errReader{})
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte("read body")) {
		t.Fatalf("expected read body message, got %s", rr.Body.String())
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, fmt.Errorf("boom") }

// TestServe_AndShutdown covers Serve + Shutdown lifecycle (review.md C1).
func TestServe_AndShutdown(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := dispatch.New(&fakeDispatcher{
		result: &rcaprobev1.TaskResult{TaskId: "t", ExitCode: 0},
		data:   []byte(`{"data":"ok"}`),
	})
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(lis) }()

	// Wait until the listener accepts connections.
	addr := lis.Addr().String()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status=%d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		// http.ErrServerClosed is the normal return after Shutdown.
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after Shutdown")
	}
}

// TestListenAndServe_Lifecycle covers ListenAndServe (binds addr itself).
func TestListenAndServe_Lifecycle(t *testing.T) {
	// Pick a free port first, then hand the address string to ListenAndServe.
	tmp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := tmp.Addr().String()
	tmp.Close()

	srv := dispatch.New(&fakeDispatcher{})
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(addr) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("ListenAndServe returned: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ListenAndServe did not return after Shutdown")
	}
}



func TestHandleExecute_WriteKind(t *testing.T) {
	fd := &fakeDispatcher{
		result: &rcaprobev1.TaskResult{TaskId: "tw", ExitCode: 0},
		data:   []byte(`{"OK":true,"Detail":"killed query q1"}`),
	}
	srv := dispatch.New(fd)
	sigB64 := base64.StdEncoding.EncodeToString(make([]byte, 64))
	body := map[string]any{
		"platform_key":            "p1",
		"task_id":                 "tw",
		"kind":                    "write",
		"playbook_id":             "presto.kill_query",
		"step_index":              0,
		"op":                      "presto_kill_query",
		"params":                  map[string]any{"query_id": "q1"},
		"execution_id":            "exec-1",
		"control_plane_signature": sigB64,
		"timeout_seconds":         30,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	if fd.lastTask == nil || fd.lastTask.GetWrite() == nil {
		t.Fatalf("expected write task, got %+v", fd.lastTask)
	}
	w := fd.lastTask.GetWrite()
	if w.GetOp() != "presto_kill_query" || w.GetPlaybookId() != "presto.kill_query" {
		t.Fatalf("unexpected write: %+v", w)
	}
	if len(w.GetControlPlaneSignature()) != 64 {
		t.Fatalf("sig len %d", len(w.GetControlPlaneSignature()))
	}
}

func TestHandleExecute_WriteMissingFields(t *testing.T) {
	fd := &fakeDispatcher{}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "p1",
		"task_id":      "t",
		"kind":         "write",
		"playbook_id":  "presto.kill_query",
		"execution_id": "e",
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandleExecute_HealthKind(t *testing.T) {
	fd := &fakeDispatcher{
		result: &rcaprobev1.TaskResult{ExitCode: 0},
		data:   []byte(`{"OK":true}`),
	}
	srv := dispatch.New(fd)
	body := map[string]any{
		"platform_key": "p1",
		"task_id":      "th",
		"kind":         "health",
		"builtin":      true,
		"custom_query": "SELECT 1",
		"wait_seconds": 0,
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/execute", bytes.NewReader(raw))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body=%s", rr.Code, rr.Body.String())
	}
	if fd.lastTask.GetHealth() == nil {
		t.Fatalf("expected health task")
	}
}
