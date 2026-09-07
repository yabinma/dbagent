// Package dispatch exposes probe-gateway's internal ExecuteTool HTTP API
// (design.md Section 3.2) so temporal-worker Activities can dispatch
// ToolCall / RawCommand tasks cross-language. M2 only had the in-process
// gwserver.Server.Dispatch method; this package is the M3 wire surface.
package dispatch

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
)

// Dispatcher is the subset of gwserver.Server needed by the HTTP API.
type Dispatcher interface {
	Dispatch(ctx context.Context, platformKey string, task *rcaprobev1.TaskRequest) (*rcaprobev1.TaskResult, []byte, error)
}

// Server is a minimal HTTP server binding POST /internal/v1/execute.
type Server struct {
	dispatcher Dispatcher
	httpServer *http.Server
}

// New constructs a dispatch HTTP server.
func New(d Dispatcher) *Server {
	s := &Server{dispatcher: d}
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/execute", s.handleExecute)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	s.httpServer = &http.Server{Handler: mux}
	return s
}

// ListenAndServe starts the HTTP server on addr (blocks).
func (s *Server) ListenAndServe(addr string) error {
	s.httpServer.Addr = addr
	return s.httpServer.ListenAndServe()
}

// Serve serves on an existing listener (useful for tests).
func (s *Server) Serve(lis net.Listener) error {
	return s.httpServer.Serve(lis)
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the underlying http.Handler for in-process tests.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

type executeRequest struct {
	PlatformKey    string         `json:"platform_key"`
	TaskID         string         `json:"task_id"`
	Kind           string         `json:"kind"` // "tool" | "raw_command" | "write" | "health"
	Tool           string         `json:"tool,omitempty"`
	Args           map[string]any `json:"args,omitempty"`
	Command        string         `json:"command,omitempty"`
	TimeoutSeconds uint32         `json:"timeout_seconds,omitempty"`

	// kind=write (M5, design.md Section 9.5.3)
	PlaybookID               string         `json:"playbook_id,omitempty"`
	StepIndex                uint32         `json:"step_index,omitempty"`
	Op                       string         `json:"op,omitempty"`
	Params                   map[string]any `json:"params,omitempty"`
	ExecutionID              string         `json:"execution_id,omitempty"`
	ControlPlaneSignatureB64 string         `json:"control_plane_signature,omitempty"` // base64

	// kind=health (M5 verify_fix canary)
	Builtin     *bool  `json:"builtin,omitempty"`
	CustomQuery string `json:"custom_query,omitempty"`
	WaitSeconds uint32 `json:"wait_seconds,omitempty"`
}

type executeResponse struct {
	TaskID    string `json:"task_id"`
	ExitCode  int32  `json:"exit_code"`
	Data      any    `json:"data,omitempty"`
	Redacted  bool   `json:"redacted"`
	Truncated bool   `json:"truncated"`
	Error     string `json:"error,omitempty"`
	ProbeID   string `json:"probe_id,omitempty"`
}

func (s *Server) handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	var req executeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.PlatformKey == "" || req.TaskID == "" {
		http.Error(w, "platform_key and task_id required", http.StatusBadRequest)
		return
	}
	task, err := buildTaskRequest(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	if req.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutSeconds)*time.Second)
		defer cancel()
	}
	result, data, err := s.dispatcher.Dispatch(ctx, req.PlatformKey, task)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	resp := executeResponse{TaskID: req.TaskID}
	if result != nil {
		resp.ExitCode = result.GetExitCode()
		resp.Error = result.GetError()
		resp.Redacted = result.GetRedacted()
		resp.Truncated = result.GetTruncated()
	}
	if len(data) > 0 {
		var envelope map[string]any
		if json.Unmarshal(data, &envelope) == nil {
			if v, ok := envelope["redacted"].(bool); ok {
				resp.Redacted = v
			}
			if v, ok := envelope["truncated"].(bool); ok {
				resp.Truncated = v
			}
			if d, ok := envelope["data"]; ok {
				resp.Data = d
			} else {
				resp.Data = envelope
			}
			if ec, ok := envelope["exit_code"].(float64); ok {
				resp.ExitCode = int32(ec)
			}
		} else {
			resp.Data = string(data)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func buildTaskRequest(req executeRequest) (*rcaprobev1.TaskRequest, error) {
	timeout := req.TimeoutSeconds
	if timeout == 0 {
		timeout = 60
	}
	task := &rcaprobev1.TaskRequest{
		TaskId:         req.TaskID,
		TimeoutSeconds: timeout,
	}
	switch req.Kind {
	case "tool", "":
		if req.Tool == "" {
			return nil, fmt.Errorf("tool required for kind=tool")
		}
		var argsStruct *structpb.Struct
		if req.Args != nil {
			s, err := structpb.NewStruct(req.Args)
			if err != nil {
				return nil, fmt.Errorf("args: %w", err)
			}
			argsStruct = s
		}
		task.Kind = &rcaprobev1.TaskRequest_Tool{
			Tool: &rcaprobev1.ToolCall{
				ToolName: req.Tool,
				Args:     argsStruct,
			},
		}
	case "raw_command":
		if req.Command == "" {
			return nil, fmt.Errorf("command required for kind=raw_command")
		}
		task.Kind = &rcaprobev1.TaskRequest_Raw{
			Raw: &rcaprobev1.RawCommand{
				Command: req.Command,
			},
		}
	case "write":
		if req.Op == "" {
			return nil, fmt.Errorf("op required for kind=write")
		}
		if req.ExecutionID == "" || req.PlaybookID == "" {
			return nil, fmt.Errorf("execution_id and playbook_id required for kind=write")
		}
		var paramsStruct *structpb.Struct
		if req.Params != nil {
			s, err := structpb.NewStruct(req.Params)
			if err != nil {
				return nil, fmt.Errorf("params: %w", err)
			}
			paramsStruct = s
		}
		sig, err := base64.StdEncoding.DecodeString(req.ControlPlaneSignatureB64)
		if err != nil {
			// Also accept raw URL-safe base64 (some clients use it).
			sig, err = base64.RawStdEncoding.DecodeString(req.ControlPlaneSignatureB64)
			if err != nil {
				return nil, fmt.Errorf("control_plane_signature: %w", err)
			}
		}
		task.Kind = &rcaprobev1.TaskRequest_Write{
			Write: &rcaprobev1.RemediationStep{
				PlaybookId:            req.PlaybookID,
				StepIndex:             req.StepIndex,
				Op:                    req.Op,
				Params:                paramsStruct,
				ExecutionId:           req.ExecutionID,
				ControlPlaneSignature: sig,
			},
		}
	case "health":
		builtin := true
		if req.Builtin != nil {
			builtin = *req.Builtin
		}
		task.Kind = &rcaprobev1.TaskRequest_Health{
			Health: &rcaprobev1.HealthCheck{
				Builtin:     builtin,
				CustomQuery: req.CustomQuery,
				WaitSeconds: req.WaitSeconds,
			},
		}
	default:
		return nil, fmt.Errorf("unknown kind %q", req.Kind)
	}
	return task, nil
}
