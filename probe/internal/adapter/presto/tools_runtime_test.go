package presto

import (
	"context"
	stdjson "encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

func TestExecute_PodLogs_K8s(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.logs = []string{"line one", "line two"}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "pod_logs", Args: map[string]any{"target": "coordinator-0"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	lines := data["lines"].([]string)
	if len(lines) != 2 {
		t.Fatalf("unexpected lines: %+v", lines)
	}
}

func TestExecute_ContainerLogs_Swarm(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindSwarm)
	env.logs = []string{"swarm log line"}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "container_logs", Args: map[string]any{"target": "c1"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
}

func TestExecute_K8sPods(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.targets = []platform.TargetInfo{
		{Name: "worker-0", Phase: "Running", Ready: true, Restarts: 0},
		{Name: "worker-1", Phase: "Running", Ready: false, Restarts: 3, LastStateReason: "OOMKilled"},
	}

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "k8s_pods", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows := result.Data.([]map[string]any)
	if len(rows) != 2 || rows[1]["last_state_reason"] != "OOMKilled" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestExecute_SwarmTasks(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindSwarm)
	env.targets = []platform.TargetInfo{{Name: "c1", Phase: "running", Ready: true}}

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "swarm_tasks", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
}

func TestExecute_K8sDescribe(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.describe = platform.DescribeResult{Text: "Name: coordinator-0\nStatus: Running\n"}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "k8s_describe", Args: map[string]any{"target": "coordinator-0"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	if data["text"] == "" {
		t.Fatalf("expected describe text")
	}
}

func TestExecute_DockerInspect(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindSwarm)
	env.describe = platform.DescribeResult{JSON: map[string]any{"Id": "c1"}}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "docker_inspect", Args: map[string]any{"target": "c1"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if result.Redacted {
		t.Fatalf("did not expect redacted=true for a secret-free inspect payload, got %+v", result)
	}
	data := result.Data.(map[string]any)
	json := data["json"].(map[string]any)
	if json["Id"] != "c1" {
		t.Fatalf("unexpected json: %+v", json)
	}
}

// TestExecute_DockerInspect_RedactsEnvSecrets is a regression test for
// design.md Section 8.2/8.5 (v1.6): `docker_inspect` returns the full
// container JSON including `Env`, which routinely carries `*_PASSWORD`
// values (e.g. a Postgres/downstream-database credential baked into the
// container's environment), and command args (e.g. a single `--password=...`
// flag token) -- these must never reach the control plane unredacted.
// Before the fix, toolDescribeOrInspect returned result.JSON verbatim with
// no redaction pass at all, so this test would fail (the literal "hunter2"
// would appear in the envelope's data). See
// TestExecute_DockerInspect_RedactsArgvSplitPasswordPair below for the
// S1 follow-up: a secret split across two separate array elements (e.g.
// `Cmd: ["--password", "hunter2"]`, the flag and its value as distinct
// tokens with no "=" joining them) -- previously a documented limitation,
// now closed by redact.Value's argv-adjacency pass.
func TestExecute_DockerInspect_RedactsEnvSecrets(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindSwarm)
	env.describe = platform.DescribeResult{JSON: map[string]any{
		"Id": "c1",
		"Config": map[string]any{
			"Env": []any{
				"POSTGRES_PASSWORD=hunter2",
				"PATH=/usr/local/bin",
			},
			"Cmd": []any{"presto-server", "--password=hunter2", "--verbose"},
		},
	}}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "docker_inspect", Args: map[string]any{"target": "c1"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true when Env contains a *_PASSWORD value, got %+v", result)
	}

	serialized, err := stdjson.Marshal(result.Data)
	if err != nil {
		t.Fatalf("marshal result.Data: %v", err)
	}
	if strings.Contains(string(serialized), "hunter2") {
		t.Fatalf("secret leaked unredacted in docker_inspect result: %s", serialized)
	}

	data := result.Data.(map[string]any)
	jsonOut := data["json"].(map[string]any)
	cfg := jsonOut["Config"].(map[string]any)
	env2 := cfg["Env"].([]any)
	if env2[0] != "POSTGRES_PASSWORD=***REDACTED***" {
		t.Fatalf("expected the POSTGRES_PASSWORD env entry fully redacted, got %+v", env2)
	}
	if env2[1] != "PATH=/usr/local/bin" {
		t.Fatalf("expected the unrelated env entry to survive unchanged, got %+v", env2)
	}
	cmd := cfg["Cmd"].([]any)
	if cmd[1] != "--password="+"***REDACTED***" {
		t.Fatalf("expected the --password=... arg redacted, got %+v", cmd)
	}
	if cmd[0] != "presto-server" || cmd[2] != "--verbose" {
		t.Fatalf("expected unrelated args to survive unchanged, got %+v", cmd)
	}
}

// TestExecute_DockerInspect_RedactsArgvSplitPasswordPair is the
// docker_inspect-level, end-to-end regression test for design.md Section
// 8.2 (v1.6, S1 follow-up): a container's `Cmd`/`Args` frequently carries
// a secret as two adjacent argv elements (the flag name and its value as
// distinct tokens, no "=" joining them) rather than the single-token
// `--password=hunter2` form. This confirms the fix reaches all the way
// through the already-wired redact.Map path in toolDescribeOrInspect
// (tools_runtime.go), not just the redact package in isolation.
func TestExecute_DockerInspect_RedactsArgvSplitPasswordPair(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindSwarm)
	env.describe = platform.DescribeResult{JSON: map[string]any{
		"Id": "c1",
		"Config": map[string]any{
			"Cmd":        []any{"mysqldump", "--password", "hunter2", "--verbose", "orders"},
			"Entrypoint": []any{"/bin/sh", "-c", "start.sh"},
			"Args":       []any{"-p", "hunter2"},
		},
	}}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "docker_inspect", Args: map[string]any{"target": "c1"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true for an argv-split password pair, got %+v", result)
	}

	serialized, err := stdjson.Marshal(result.Data)
	if err != nil {
		t.Fatalf("marshal result.Data: %v", err)
	}
	if strings.Contains(string(serialized), "hunter2") {
		t.Fatalf("secret leaked unredacted in docker_inspect result: %s", serialized)
	}

	data := result.Data.(map[string]any)
	jsonOut := data["json"].(map[string]any)
	cfg := jsonOut["Config"].(map[string]any)

	cmd := cfg["Cmd"].([]any)
	if cmd[0] != "mysqldump" || cmd[1] != "--password" {
		t.Fatalf("expected the command and flag token to survive unchanged, got %+v", cmd)
	}
	if cmd[2] != "***REDACTED***" {
		t.Fatalf("expected the argv-split password value redacted, got %+v", cmd)
	}
	if cmd[3] != "--verbose" || cmd[4] != "orders" {
		t.Fatalf("expected unrelated trailing args to survive unchanged, got %+v", cmd)
	}

	entrypoint := cfg["Entrypoint"].([]any)
	if entrypoint[0] != "/bin/sh" || entrypoint[1] != "-c" || entrypoint[2] != "start.sh" {
		t.Fatalf("expected an unrelated Entrypoint array to survive completely unchanged, got %+v", entrypoint)
	}

	argsField := cfg["Args"].([]any)
	if argsField[0] != "-p" || argsField[1] != "***REDACTED***" {
		t.Fatalf("expected the -p short-flag password pair redacted, got %+v", argsField)
	}
}

// TestExecute_K8sDescribe_RedactsEmbeddedSecret is a regression test for
// design.md Section 8.2/8.5 (v1.6): `k8s_describe`'s text output can embed
// env values (e.g. Kubernetes renders container env in its describe text)
// -- these must be redacted the same way presto_config's text output is.
// Before the fix, toolDescribeOrInspect returned result.Text verbatim.
func TestExecute_K8sDescribe_RedactsEmbeddedSecret(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.describe = platform.DescribeResult{Text: "Name: coordinator-0\n" +
		"Environment:\n  POSTGRES_PASSWORD: hunter2\n  PATH: /usr/local/bin\n"}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "k8s_describe", Args: map[string]any{"target": "coordinator-0"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	if !result.Redacted {
		t.Fatalf("expected redacted=true when describe text contains a password, got %+v", result)
	}
	data := result.Data.(map[string]any)
	text := data["text"].(string)
	if strings.Contains(text, "hunter2") {
		t.Fatalf("secret leaked unredacted in k8s_describe result: %s", text)
	}
	if !strings.Contains(text, "***REDACTED***") {
		t.Fatalf("expected a redaction placeholder in describe text, got: %s", text)
	}
	if !strings.Contains(text, "PATH: /usr/local/bin") {
		t.Fatalf("expected the unrelated line to survive unchanged, got: %s", text)
	}
}

func TestExecute_K8sEvents(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.events = []platform.EventInfo{{At: time.Now(), Type: "Warning", Reason: "BackOff", Object: "worker-0"}}

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "k8s_events", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows := result.Data.([]map[string]any)
	if len(rows) != 1 || rows[0]["reason"] != "BackOff" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestExecute_DockerEvents(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindSwarm)
	env.events = []platform.EventInfo{{At: time.Now(), Type: "container", Reason: "die", Object: "c1"}}

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "docker_events", Args: map[string]any{"type": "all"}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
}

func TestExecute_ResourceUsage(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.usage = []platform.ResourceUsageInfo{{Target: "worker-0", CPUMillicores: 500, MemBytes: 1000, MemLimit: 2000, MemPct: 50}}

	result, err := a.Execute(context.Background(), platform.ToolCall{ToolName: "resource_usage", Args: map[string]any{}})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	rows := result.Data.([]map[string]any)
	if len(rows) != 1 || rows[0]["mem_pct"] != 50.0 {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}
