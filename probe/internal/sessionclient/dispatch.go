// Package sessionclient is the probe side of `ProbeGateway.Session`
// (design.md Appendix A/Section 8.4): register, heartbeat, and dispatch
// incoming TaskRequests to the PlatformAdapter, chunking results back per
// the wire conventions ("Task results larger than one chunk stream as
// TaskOutputChunk frames followed by a final TaskResult").
//
// Split into pure dispatch/encoding functions (this file, directly unit
// testable with a fake PlatformAdapter, no gRPC needed) and the actual
// stream I/O loop (client.go, tested via bufconn against a minimal fake
// gateway).
package sessionclient

import (
	"context"
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/rawcmd"
	"github.com/yabinma/dbagent/probe/internal/toolpack"
	"github.com/yabinma/dbagent/probe/internal/writeops"
)

const DefaultChunkSize = 256 * 1024 // Appendix A: "≤ 256 KiB per chunk"

// TaskOutcome is what HandleTask produces: a JSON-serializable payload
// plus the TaskResult metadata fields (design.md Section 8.5 envelope /
// Appendix A TaskResult).
type TaskOutcome struct {
	Payload   []byte
	ExitCode  int32
	Truncated bool
	Redacted  bool
	Error     string
}

// HandleTask dispatches one TaskRequest to adapter (ToolCall/HealthCheck)
// or rawcmd/writeops (RawCommand/RemediationStep), per design.md Section
// 8.2's layered command model, and returns the (already
// truncated-at-max_output_bytes) result.
func HandleTask(ctx context.Context, adapter platform.PlatformAdapter, env platform.RuntimeEnv, keys writeops.KeyRing, writeEnabled bool, task *rcaprobev1.TaskRequest) TaskOutcome {
	maxBytes := int(task.GetMaxOutputBytes())
	if maxBytes <= 0 {
		maxBytes = 1 << 20 // Appendix A default: 1 MiB
	}

	switch kind := task.Kind.(type) {
	case *rcaprobev1.TaskRequest_Tool:
		return handleToolCall(ctx, adapter, kind.Tool, maxBytes)
	case *rcaprobev1.TaskRequest_Raw:
		return handleRawCommand(ctx, env, kind.Raw, task, maxBytes)
	case *rcaprobev1.TaskRequest_Write:
		return handleRemediationStep(ctx, adapter, keys, writeEnabled, kind.Write)
	case *rcaprobev1.TaskRequest_Health:
		return handleHealthCheck(ctx, adapter, kind.Health)
	default:
		return TaskOutcome{ExitCode: 1, Error: "unknown task kind"}
	}
}

func handleToolCall(ctx context.Context, adapter platform.PlatformAdapter, tool *rcaprobev1.ToolCall, maxBytes int) TaskOutcome {
	result, err := adapter.Execute(ctx, platform.ToolCall{
		ToolName: tool.GetToolName(),
		Args:     structToMap(tool.GetArgs()),
	})
	if err != nil {
		return TaskOutcome{ExitCode: 1, Error: err.Error()}
	}
	result = toolpack.Truncate(result, maxBytes)
	payload, encErr := json.Marshal(result)
	if encErr != nil {
		return TaskOutcome{ExitCode: 1, Error: encErr.Error()}
	}
	return TaskOutcome{
		Payload:   payload,
		ExitCode:  int32(result.ExitCode),
		Truncated: result.Truncated,
		Redacted:  result.Redacted,
		Error:     result.Error,
	}
}

func handleRawCommand(ctx context.Context, env platform.RuntimeEnv, raw *rcaprobev1.RawCommand, task *rcaprobev1.TaskRequest, maxBytes int) TaskOutcome {
	timeout := time.Duration(task.GetTimeoutSeconds()) * time.Second
	result, err := rawcmd.Execute(ctx, env, "", "", raw.GetCommand(), timeout, maxBytes)
	if err != nil {
		return TaskOutcome{ExitCode: 1, Error: err.Error()}
	}
	payload, encErr := json.Marshal(map[string]any{
		"stdout": result.Stdout, "stderr": result.Stderr, "exit_code": result.ExitCode,
	})
	if encErr != nil {
		return TaskOutcome{ExitCode: 1, Error: encErr.Error()}
	}
	return TaskOutcome{Payload: payload, ExitCode: int32(result.ExitCode), Truncated: result.Truncated}
}

func handleRemediationStep(ctx context.Context, adapter platform.PlatformAdapter, keys writeops.KeyRing, writeEnabled bool, step *rcaprobev1.RemediationStep) TaskOutcome {
	params := structToMap(step.GetParams())
	verifyResult := writeops.VerifyStep(keys, writeEnabled, step.GetExecutionId(), step.GetPlaybookId(),
		step.GetStepIndex(), step.GetOp(), params, step.GetControlPlaneSignature())
	if !verifyResult.OK {
		return TaskOutcome{ExitCode: 1, Error: "write rejected: " + verifyResult.Reason}
	}

	result, err := adapter.ExecuteWrite(ctx, platform.RemediationStep{
		PlaybookID: step.GetPlaybookId(), StepIndex: step.GetStepIndex(), Op: step.GetOp(),
		Params: params, ExecutionID: step.GetExecutionId(), SignatureOK: true,
	})
	if err != nil {
		return TaskOutcome{ExitCode: 1, Error: err.Error()}
	}
	payload, _ := json.Marshal(result)
	exitCode := int32(0)
	if !result.OK {
		exitCode = 1
	}
	return TaskOutcome{Payload: payload, ExitCode: exitCode, Error: result.Error}
}

func handleHealthCheck(ctx context.Context, adapter platform.PlatformAdapter, hc *rcaprobev1.HealthCheck) TaskOutcome {
	if hc.GetWaitSeconds() > 0 {
		select {
		case <-ctx.Done():
			return TaskOutcome{ExitCode: 1, Error: ctx.Err().Error()}
		case <-time.After(time.Duration(hc.GetWaitSeconds()) * time.Second):
		}
	}
	result, err := adapter.HealthCheck(ctx, platform.HealthSpec{
		BuiltinProbe: hc.GetBuiltin(), CustomQuery: hc.GetCustomQuery(),
	})
	if err != nil {
		return TaskOutcome{ExitCode: 1, Error: err.Error()}
	}
	payload, _ := json.Marshal(result)
	exitCode := int32(0)
	if !result.OK {
		exitCode = 1
	}
	return TaskOutcome{Payload: payload, ExitCode: exitCode}
}

// ChunkPayload splits payload into ≤chunkSize pieces (Appendix A: "≤ 256
// KiB per chunk"), returning nil for an empty payload (still chunk_count
// must be >=1 in practice; callers send a single empty chunk in that
// case -- see EncodeChunks).
func ChunkPayload(payload []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	var chunks [][]byte
	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[i:end])
	}
	return chunks
}

// structToMap converts a (possibly nil) *structpb.Struct to a plain map.
// AsMap() is nil-safe (it reads via the generated, nil-safe GetFields())
// and always returns a non-nil map, even for a nil Struct.
func structToMap(s *structpb.Struct) map[string]any {
	return s.AsMap()
}
