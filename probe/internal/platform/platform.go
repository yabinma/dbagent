// Package platform defines the PlatformAdapter extension point (design.md
// Section 8.3) and the supporting types every adapter implementation
// (Presto today; future platforms later) and the probe's dispatch/session
// layer share. Types here are decoupled from the wire (protobuf) format on
// purpose -- the session layer (probe/internal/sessionclient) is the only
// place that converts to/from the generated rcaprobe.v1 messages, so this
// package (and every PlatformAdapter implementation) stays independent of
// protobuf.
package platform

import (
	"context"
	"time"
)

// EnvKind identifies which runtime environment a probe is deployed into
// (design.md Section 8.1/8.3).
type EnvKind string

const (
	EnvKindK8s   EnvKind = "k8s"
	EnvKindSwarm EnvKind = "swarm"
)

// PlatformAdapter is the Go interface every platform-specific
// implementation converges on (design.md Section 8.3, reproduced exactly:
// Detect/Tools/Execute/HealthCheck/WriteOps/ExecuteWrite).
type PlatformAdapter interface {
	// Detect performs environment detection + auth-scheme detection and
	// returns the capability manifest (design.md Section 8.4 step 4).
	Detect(ctx context.Context, env RuntimeEnv) (Manifest, error)
	// Tools returns the read-only tool catalog (names, param schemas,
	// result shapes).
	Tools() []ToolSpec
	// Execute runs one read-only Toolpack tool call.
	Execute(ctx context.Context, call ToolCall) (ToolResult, error)
	// HealthCheck runs the built-in probe and/or a per-platform configured
	// health_query (design.md Section 9.2 "Canary query").
	HealthCheck(ctx context.Context, spec HealthSpec) (HealthResult, error)
	// WriteOps returns the write-op catalog (empty when the write channel
	// is disabled for this deployment).
	WriteOps() []WriteOpSpec
	// ExecuteWrite executes one signature-verified RemediationStep. Full
	// write-op execution is M5 scope (design.md Section 9); M2 wires the
	// signature-verification/gating path (see probe/internal/writeops) but
	// adapters may return an "unimplemented" WriteResult for the op itself
	// until M5.
	ExecuteWrite(ctx context.Context, step RemediationStep) (WriteResult, error)
}

// RuntimeEnv abstracts the K8s client / Docker client (design.md Section
// 8.3: "RuntimeEnv abstracts the K8s client / Docker client (EnvKind:
// k8s|swarm); adapters obtain configs, logs, and in-container command
// execution through it, so future platform adapters never re-implement
// the environment layer.").
type RuntimeEnv interface {
	Kind() EnvKind

	// ListTargets lists the platform's pods (k8s) or tasks (swarm)
	// matching selector (design.md Appendix B.2 k8s_pods/swarm_tasks).
	ListTargets(ctx context.Context, selector string) ([]TargetInfo, error)

	// Logs returns log lines for target/container (design.md Appendix B.2
	// pod_logs/container_logs). grep, if non-empty, filters probe-side.
	Logs(ctx context.Context, target, container string, opts LogOptions) ([]string, error)

	// Describe returns a k8s "describe"-style text blob or a docker
	// "inspect"-style JSON blob for target (Appendix B.2
	// k8s_describe/docker_inspect).
	Describe(ctx context.Context, target string) (DescribeResult, error)

	// Events lists recent cluster/daemon events (Appendix B.2
	// k8s_events/docker_events).
	Events(ctx context.Context, opts EventOptions) ([]EventInfo, error)

	// ResourceUsage returns per-target CPU/memory usage (Appendix B.2
	// resource_usage: metrics.k8s.io / docker stats).
	ResourceUsage(ctx context.Context, selector string) ([]ResourceUsageInfo, error)

	// Exec runs cmd inside target/container and returns its output
	// (used by jvm_thread_dump/jvm_heap_histo's in-container jcmd, and by
	// the gated raw-command channel, Section 8.2).
	Exec(ctx context.Context, target, container string, cmd []string, timeout time.Duration) (ExecResult, error)

	// ReadConfig reads a Presto config file (ConfigMap key on k8s, an
	// in-container file read equivalent to `docker exec cat` on swarm)
	// per Appendix B.1 presto_config's component/file/target params.
	ReadConfig(ctx context.Context, component, file, target string) (string, error)

	// CoordinatorBaseURL resolves the configured coordinator locator (K8s
	// label selector / Swarm service name, design.md Section 8.4 step 2)
	// to a reachable HTTP(S) base URL for the Presto REST client.
	CoordinatorBaseURL(ctx context.Context) (string, error)

	// --- Write methods (M5, design.md Section 9.5.3) -------------------------

	// PatchConfigMap strategic-merges dataPatches into a ConfigMap's data
	// keys (k8s only; swarm returns an error).
	PatchConfigMap(ctx context.Context, namespace, name string, dataPatches map[string]string) error

	// RolloutRestart triggers a rolling restart of a Deployment or
	// StatefulSet by setting the pod-template annotation
	// kubectl.kubernetes.io/restartedAt (exactly what `kubectl rollout
	// restart` does). kind is "deployment" or "statefulset".
	RolloutRestart(ctx context.Context, namespace, kind, name string) error

	// DeletePod deletes one pod (the controller recreates it).
	DeletePod(ctx context.Context, namespace, name string) error

	// UpdateServiceEnv merges env into a Swarm service's
	// TaskTemplate.ContainerSpec.Env (swarm only; k8s returns an error).
	UpdateServiceEnv(ctx context.Context, service string, env map[string]string) error

	// RestartService force-recreates a Swarm service's tasks by bumping
	// TaskTemplate.ForceUpdate (swarm only; k8s returns an error).
	RestartService(ctx context.Context, service string) error
}

// --- RuntimeEnv supporting types -------------------------------------------------

type LogOptions struct {
	Since    string // duration string, e.g. "30m"
	Lines    int
	Grep     string
	Previous bool
}

type TargetInfo struct {
	Name            string
	Phase           string // k8s pod phase, or swarm task state
	Ready           bool
	Restarts        int
	Node            string
	StartedAt       time.Time
	LastStateReason string // e.g. "OOMKilled", "Error"
}

type DescribeResult struct {
	Text string         // k8s describe-style text
	JSON map[string]any // docker inspect-style JSON
}

type EventOptions struct {
	Since      string
	TypeFilter string // "all" | "warning"
}

type EventInfo struct {
	At      time.Time
	Type    string
	Reason  string
	Object  string
	Message string
}

type ResourceUsageInfo struct {
	Target        string
	CPUMillicores int64
	CPULimit      int64
	MemBytes      int64
	MemLimit      int64
	MemPct        float64
}

type ExecResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// --- PlatformAdapter supporting types ---------------------------------------------

// Manifest is the capability manifest an adapter reports after Detect
// (design.md Section 8.4 step 4 / Appendix A Capabilities message; the
// session layer converts this to the wire Capabilities proto).
type Manifest struct {
	PlatformType  string // "presto"
	Deployment    string // "k8s" | "swarm"
	EngineVersion string
	Tools         []ToolDescriptor
	WriteOps      []string // empty = write channel disabled
	Auth          AuthStatus
}

type AuthStatus struct {
	Scheme  string // NONE | PASSWORD | LDAP | KERBEROS
	HTTPS   bool
	Access  string   // full | unauthenticated | unsupported
	Missing []string // e.g. ["credentials", "tls_ca"]
}

type ToolDescriptor struct {
	Name             string
	ParamsSchemaJSON string
	Category         string // engine | runtime | host
}

// ToolSpec is an adapter's richer, in-process tool description (Tools()),
// vs. ToolDescriptor which is the flatter wire-manifest shape.
type ToolSpec struct {
	Name         string
	Category     string         // engine | runtime | host
	ParamsSchema map[string]any // parsed JSON Schema
}

type ToolCall struct {
	ToolName string
	Args     map[string]any
}

// ToolResult is the uniform result envelope (design.md Section 8.5):
//
//	{"tool": "...", "args": {}, "platform_key": "...", "probe_id": "...",
//	 "collected_at": "RFC3339", "exit_code": 0, "truncated": false,
//	 "redacted": false, "data": {}}
//
// JSON tags matter here: this struct is marshaled verbatim as the chunk
// payload sent to probe-gateway (design.md Appendix A), so its wire shape
// must match Section 8.5 exactly (snake_case).
type ToolResult struct {
	Tool        string         `json:"tool"`
	Args        map[string]any `json:"args"`
	PlatformKey string         `json:"platform_key"`
	ProbeID     string         `json:"probe_id"`
	CollectedAt time.Time      `json:"collected_at"`
	ExitCode    int            `json:"exit_code"`
	Truncated   bool           `json:"truncated"`
	Redacted    bool           `json:"redacted"`
	Data        any            `json:"data"`
	Error       string         `json:"error,omitempty"`
}

type HealthSpec struct {
	BuiltinProbe bool
	CustomQuery  string
	WaitSeconds  int
}

type HealthResult struct {
	OK        bool
	Detail    string
	CheckedAt time.Time
}

type WriteOpSpec struct {
	Name         string
	ParamsSchema map[string]any
}

// RemediationStep mirrors the wire RemediationStep message (Appendix A)
// after signature verification (probe/internal/writeops) has already run.
type RemediationStep struct {
	PlaybookID  string
	StepIndex   uint32
	Op          string
	Params      map[string]any
	ExecutionID string
	SignatureOK bool // true only if writeops.Verify already accepted it
}

type WriteResult struct {
	OK     bool
	Detail string
	Error  string
}
