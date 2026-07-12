package sessionclient

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/writeops"
)

// fakeAdapter is a minimal platform.PlatformAdapter double for
// dispatch-layer tests (adapter internals are separately unit tested in
// probe/internal/adapter/presto).
type fakeAdapter struct {
	executeResult platform.ToolResult
	executeErr    error
	healthResult  platform.HealthResult
	healthErr     error
	writeResult   platform.WriteResult
	writeErr      error
	lastWriteStep platform.RemediationStep
}

func (f *fakeAdapter) Detect(ctx context.Context, env platform.RuntimeEnv) (platform.Manifest, error) {
	return platform.Manifest{}, nil
}
func (f *fakeAdapter) Tools() []platform.ToolSpec { return nil }
func (f *fakeAdapter) Execute(ctx context.Context, call platform.ToolCall) (platform.ToolResult, error) {
	return f.executeResult, f.executeErr
}
func (f *fakeAdapter) HealthCheck(ctx context.Context, spec platform.HealthSpec) (platform.HealthResult, error) {
	return f.healthResult, f.healthErr
}
func (f *fakeAdapter) WriteOps() []platform.WriteOpSpec { return nil }
func (f *fakeAdapter) ExecuteWrite(ctx context.Context, step platform.RemediationStep) (platform.WriteResult, error) {
	f.lastWriteStep = step
	return f.writeResult, f.writeErr
}

func mustStruct(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	s, err := structpb.NewStruct(m)
	if err != nil {
		t.Fatalf("build struct: %v", err)
	}
	return s
}

func TestHandleTask_ToolCall_Success(t *testing.T) {
	adapter := &fakeAdapter{executeResult: platform.ToolResult{
		Tool: "presto_cluster_info", Data: map[string]any{"version": "0.298"}, ExitCode: 0,
	}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind:   &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "presto_cluster_info", Args: mustStruct(t, nil)}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)

	if outcome.ExitCode != 0 || outcome.Error != "" {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	var decoded map[string]any
	if err := json.Unmarshal(outcome.Payload, &decoded); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if decoded["tool"] != "presto_cluster_info" {
		t.Fatalf("unexpected payload: %+v", decoded)
	}
}

func TestHandleTask_ToolCall_AdapterError(t *testing.T) {
	adapter := &fakeAdapter{executeErr: errBoom}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind:   &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "x"}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode == 0 || outcome.Error == "" {
		t.Fatalf("expected error outcome, got %+v", outcome)
	}
}

func TestHandleTask_ToolCall_TruncatesAtMaxOutputBytes(t *testing.T) {
	bigData := map[string]any{"x": make([]string, 0)}
	lines := make([]string, 1000)
	for i := range lines {
		lines[i] = "some log line with meaningful content to pad this out"
	}
	bigData["x"] = lines
	adapter := &fakeAdapter{executeResult: platform.ToolResult{Tool: "t", Data: bigData}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1", MaxOutputBytes: 200,
		Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "t"}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if !outcome.Truncated {
		t.Fatalf("expected truncation, got %+v", outcome)
	}
}

func TestHandleTask_HealthCheck(t *testing.T) {
	adapter := &fakeAdapter{healthResult: platform.HealthResult{OK: true, Detail: "ok"}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1", Kind: &rcaprobev1.TaskRequest_Health{Health: &rcaprobev1.HealthCheck{Builtin: true}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode != 0 {
		t.Fatalf("expected success exit code, got %+v", outcome)
	}
}

func TestHandleTask_HealthCheck_Failure(t *testing.T) {
	adapter := &fakeAdapter{healthResult: platform.HealthResult{OK: false}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1", Kind: &rcaprobev1.TaskRequest_Health{Health: &rcaprobev1.HealthCheck{Builtin: true}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode == 0 {
		t.Fatalf("expected non-zero exit code for a failed health check")
	}
}

func TestHandleTask_RemediationStep_RejectedWhenWriteDisabled(t *testing.T) {
	adapter := &fakeAdapter{}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind: &rcaprobev1.TaskRequest_Write{Write: &rcaprobev1.RemediationStep{
			PlaybookId: "presto.kill_query", Op: "presto_kill_query", ExecutionId: "e1",
			Params: mustStruct(t, map[string]any{"query_id": "q1"}),
		}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode == 0 {
		t.Fatalf("expected rejection when write_enabled=false")
	}
	if adapter.lastWriteStep.Op != "" {
		t.Fatalf("adapter.ExecuteWrite should not have been called")
	}
}

func TestHandleTask_RemediationStep_ValidSignatureCallsExecuteWrite(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	params := map[string]any{"query_id": "q1"}
	hash, _ := writeops.CanonicalStepHash("e1", "presto.kill_query", 0, "presto_kill_query", params)
	sig := ed25519.Sign(priv, hash)

	adapter := &fakeAdapter{writeResult: platform.WriteResult{OK: true, Detail: "killed"}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind: &rcaprobev1.TaskRequest_Write{Write: &rcaprobev1.RemediationStep{
			PlaybookId: "presto.kill_query", StepIndex: 0, Op: "presto_kill_query", ExecutionId: "e1",
			Params:                mustStruct(t, params),
			ControlPlaneSignature: sig,
		}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{Current: pub}, true, task)
	if outcome.ExitCode != 0 {
		t.Fatalf("expected success, got %+v", outcome)
	}
	if !adapter.lastWriteStep.SignatureOK {
		t.Fatalf("expected adapter to receive SignatureOK=true")
	}
}

func TestHandleTask_RemediationStep_TamperedSignatureRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	hash, _ := writeops.CanonicalStepHash("e1", "presto.kill_query", 0, "presto_kill_query", map[string]any{"query_id": "q1"})
	sig := ed25519.Sign(priv, hash)

	adapter := &fakeAdapter{}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind: &rcaprobev1.TaskRequest_Write{Write: &rcaprobev1.RemediationStep{
			PlaybookId: "presto.kill_query", StepIndex: 0, Op: "presto_kill_query", ExecutionId: "e1",
			Params:                mustStruct(t, map[string]any{"query_id": "TAMPERED"}),
			ControlPlaneSignature: sig,
		}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{Current: pub}, true, task)
	if outcome.ExitCode == 0 {
		t.Fatalf("expected rejection for tampered params")
	}
	if adapter.lastWriteStep.Op != "" {
		t.Fatalf("adapter.ExecuteWrite should not have been called")
	}
}

func TestHandleTask_UnknownKind(t *testing.T) {
	adapter := &fakeAdapter{}
	task := &rcaprobev1.TaskRequest{TaskId: "t1"}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode == 0 {
		t.Fatalf("expected error for a task with no kind set")
	}
}

// fakeExecEnv is a minimal platform.RuntimeEnv double supporting only
// Exec, for raw-command dispatch tests (rawcmd itself is separately unit
// tested in probe/internal/rawcmd).
type fakeExecEnv struct {
	result platform.ExecResult
	err    error
}

func (f *fakeExecEnv) Kind() platform.EnvKind { return platform.EnvKindK8s }
func (f *fakeExecEnv) ListTargets(ctx context.Context, selector string) ([]platform.TargetInfo, error) {
	return nil, nil
}
func (f *fakeExecEnv) Logs(ctx context.Context, target, container string, opts platform.LogOptions) ([]string, error) {
	return nil, nil
}
func (f *fakeExecEnv) Describe(ctx context.Context, target string) (platform.DescribeResult, error) {
	return platform.DescribeResult{}, nil
}
func (f *fakeExecEnv) Events(ctx context.Context, opts platform.EventOptions) ([]platform.EventInfo, error) {
	return nil, nil
}
func (f *fakeExecEnv) ResourceUsage(ctx context.Context, selector string) ([]platform.ResourceUsageInfo, error) {
	return nil, nil
}
func (f *fakeExecEnv) Exec(ctx context.Context, target, container string, cmd []string, timeout time.Duration) (platform.ExecResult, error) {
	return f.result, f.err
}
func (f *fakeExecEnv) ReadConfig(ctx context.Context, component, file, target string) (string, error) {
	return "", nil
}
func (f *fakeExecEnv) CoordinatorBaseURL(ctx context.Context) (string, error) { return "", nil }

func TestHandleTask_RawCommand_Success(t *testing.T) {
	env := &fakeExecEnv{result: platform.ExecResult{Stdout: "output", ExitCode: 0}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1", TimeoutSeconds: 5,
		Kind: &rcaprobev1.TaskRequest_Raw{Raw: &rcaprobev1.RawCommand{Command: "ps aux", ApprovalId: "appr-1"}},
	}
	outcome := HandleTask(context.Background(), &fakeAdapter{}, env, writeops.KeyRing{}, false, task)
	if outcome.ExitCode != 0 {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	var decoded map[string]any
	if err := json.Unmarshal(outcome.Payload, &decoded); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if decoded["stdout"] != "output" {
		t.Fatalf("unexpected payload: %+v", decoded)
	}
}

func TestHandleTask_RawCommand_RejectedByLocalAllowlist(t *testing.T) {
	env := &fakeExecEnv{result: platform.ExecResult{Stdout: "should not run"}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind:   &rcaprobev1.TaskRequest_Raw{Raw: &rcaprobev1.RawCommand{Command: "rm -rf /"}},
	}
	outcome := HandleTask(context.Background(), &fakeAdapter{}, env, writeops.KeyRing{}, false, task)
	if outcome.ExitCode == 0 || outcome.Error == "" {
		t.Fatalf("expected the probe-side allowlist to reject this command, got %+v", outcome)
	}
}

func TestHandleTask_HealthCheck_WithWaitSeconds(t *testing.T) {
	adapter := &fakeAdapter{healthResult: platform.HealthResult{OK: true}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind:   &rcaprobev1.TaskRequest_Health{Health: &rcaprobev1.HealthCheck{Builtin: true, WaitSeconds: 1}},
	}
	start := time.Now()
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode != 0 {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	if time.Since(start) < time.Second {
		t.Fatalf("expected HandleTask to honor the wait_seconds settling window")
	}
}

func TestHandleTask_HealthCheck_ContextCancelledDuringWait(t *testing.T) {
	adapter := &fakeAdapter{healthResult: platform.HealthResult{OK: true}}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1",
		Kind:   &rcaprobev1.TaskRequest_Health{Health: &rcaprobev1.HealthCheck{Builtin: true, WaitSeconds: 30}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	outcome := HandleTask(ctx, adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode == 0 || outcome.Error == "" {
		t.Fatalf("expected an error outcome when the context is already cancelled, got %+v", outcome)
	}
}

func TestHandleTask_HealthCheck_AdapterError(t *testing.T) {
	adapter := &fakeAdapter{healthErr: errBoom}
	task := &rcaprobev1.TaskRequest{
		TaskId: "t1", Kind: &rcaprobev1.TaskRequest_Health{Health: &rcaprobev1.HealthCheck{Builtin: true}},
	}
	outcome := HandleTask(context.Background(), adapter, nil, writeops.KeyRing{}, false, task)
	if outcome.ExitCode == 0 || outcome.Error == "" {
		t.Fatalf("expected error outcome, got %+v", outcome)
	}
}

func TestStructToMap_NilStruct(t *testing.T) {
	m := structToMap(nil)
	if m == nil || len(m) != 0 {
		t.Fatalf("expected an empty (non-nil) map for a nil Struct, got %+v", m)
	}
}

func TestChunkPayload_SmallPayloadSingleChunk(t *testing.T) {
	chunks := ChunkPayload([]byte("hello"), 100)
	if len(chunks) != 1 || string(chunks[0]) != "hello" {
		t.Fatalf("unexpected chunks: %+v", chunks)
	}
}

func TestChunkPayload_EmptyPayloadStillOneChunk(t *testing.T) {
	chunks := ChunkPayload(nil, 100)
	if len(chunks) != 1 || len(chunks[0]) != 0 {
		t.Fatalf("expected exactly one empty chunk, got %+v", chunks)
	}
}

func TestChunkPayload_SplitsAtExactBoundary(t *testing.T) {
	payload := make([]byte, 250)
	for i := range payload {
		payload[i] = byte('a' + i%26)
	}
	chunks := ChunkPayload(payload, 100)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 100 || len(chunks[1]) != 100 || len(chunks[2]) != 50 {
		t.Fatalf("unexpected chunk sizes: %d %d %d", len(chunks[0]), len(chunks[1]), len(chunks[2]))
	}
	reassembled := append(append(chunks[0], chunks[1]...), chunks[2]...)
	if string(reassembled) != string(payload) {
		t.Fatalf("reassembly mismatch")
	}
}

func TestChunkPayload_DefaultsChunkSize(t *testing.T) {
	payload := make([]byte, 300*1024)
	chunks := ChunkPayload(payload, 0)
	if len(chunks) != 2 {
		t.Fatalf("expected 2 chunks at the 256KiB default, got %d", len(chunks))
	}
}

var errBoom = &testError{"boom"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
