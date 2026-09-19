package toolpack

import (
	"errors"
	"testing"
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

func TestLoadCategory_Engine(t *testing.T) {
	tools, ops, err := LoadCategory("engine")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ops != nil {
		t.Fatalf("expected no ops in engine category")
	}
	for _, name := range []string{
		"presto_cluster_info", "presto_nodes", "presto_list_queries",
		"presto_query_detail", "presto_query_json_section", "presto_config",
		"presto_session_properties", "presto_jmx",
	} {
		if _, ok := tools[name]; !ok {
			t.Errorf("expected tool %q in engine category", name)
		}
	}
}

func TestLoadCategory_Runtime(t *testing.T) {
	tools, _, err := LoadCategory("runtime")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{
		"pod_logs", "container_logs", "k8s_pods", "swarm_tasks",
		"k8s_describe", "docker_inspect", "k8s_events", "docker_events", "resource_usage",
	} {
		if _, ok := tools[name]; !ok {
			t.Errorf("expected tool %q in runtime category", name)
		}
	}
}

func TestLoadCategory_Host(t *testing.T) {
	tools, _, err := LoadCategory("host")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{"jvm_thread_dump", "jvm_heap_histo"} {
		if _, ok := tools[name]; !ok {
			t.Errorf("expected tool %q in host category", name)
		}
	}
}

func TestLoadCategory_WriteOps(t *testing.T) {
	_, ops, err := LoadCategory("writeops")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, name := range []string{
		"k8s_patch_configmap", "k8s_rollout_restart", "k8s_delete_pod",
		"swarm_update_service_env", "swarm_restart_service", "presto_kill_query",
	} {
		if _, ok := ops[name]; !ok {
			t.Errorf("expected op %q in writeops category", name)
		}
	}
}

func TestLoadCategory_Unknown(t *testing.T) {
	_, _, err := LoadCategory("does-not-exist")
	if err == nil {
		t.Fatalf("expected error for unknown category")
	}
}

func TestMemoryConfigKeyWhitelist(t *testing.T) {
	keys, err := MemoryConfigKeyWhitelist()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]bool{
		"query.max-memory": true, "query.max-memory-per-node": true,
		"query.max-total-memory-per-node": true, "memory.heap-headroom-per-node": true,
	}
	if len(keys) != len(want) {
		t.Fatalf("unexpected whitelist: %v", keys)
	}
	for _, k := range keys {
		if !want[k] {
			t.Errorf("unexpected whitelist key %q", k)
		}
	}
}

func TestValidateParams_Success(t *testing.T) {
	tools, _, _ := LoadCategory("engine")
	err := ValidateParams(tools["presto_list_queries"], map[string]any{
		"state": "FAILED", "limit": 10,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateParams_RejectsAdditionalProperties(t *testing.T) {
	tools, _, _ := LoadCategory("engine")
	err := ValidateParams(tools["presto_cluster_info"], map[string]any{"unexpected": "field"})
	if err == nil {
		t.Fatalf("expected validation error for additional property")
	}
}

func TestValidateParams_RejectsMissingRequired(t *testing.T) {
	tools, _, _ := LoadCategory("engine")
	err := ValidateParams(tools["presto_query_detail"], map[string]any{})
	if err == nil {
		t.Fatalf("expected validation error for missing required field")
	}
}

func TestValidateParams_RejectsWrongEnum(t *testing.T) {
	tools, _, _ := LoadCategory("engine")
	err := ValidateParams(tools["presto_list_queries"], map[string]any{"state": "NOT_A_STATE"})
	if err == nil {
		t.Fatalf("expected validation error for bad enum value")
	}
}

func TestValidateParams_RejectsBadPattern(t *testing.T) {
	tools, _, _ := LoadCategory("engine")
	err := ValidateParams(tools["presto_list_queries"], map[string]any{"since": "not-a-duration"})
	if err == nil {
		t.Fatalf("expected validation error for bad pattern")
	}
}

func TestBuildEnvelope_Success(t *testing.T) {
	NowFunc = func() time.Time { return time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC) }
	defer func() { NowFunc = time.Now }()

	env := BuildEnvelope("presto_cluster_info", map[string]any{}, "presto-us1", "probe-1", 0, map[string]any{"version": "0.298"}, nil)
	if env.Tool != "presto_cluster_info" || env.ExitCode != 0 || env.Error != "" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
	if !env.CollectedAt.Equal(time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)) {
		t.Fatalf("unexpected CollectedAt: %v", env.CollectedAt)
	}
}

func TestBuildEnvelope_ErrorSetsExitCode(t *testing.T) {
	env := BuildEnvelope("presto_jmx", nil, "presto-us1", "probe-1", 0, nil, errors.New("boom"))
	if env.ExitCode != 1 || env.Error != "boom" {
		t.Fatalf("unexpected envelope: %+v", env)
	}
}

func TestTruncate_NoOpUnderLimit(t *testing.T) {
	result := platform.ToolResult{Data: map[string]any{"a": 1}}
	out := Truncate(result, 1<<20)
	if out.Truncated {
		t.Fatalf("expected no truncation")
	}
}

func TestTruncate_AppliesWhenOverLimit(t *testing.T) {
	bigData := map[string]any{"lines": make([]string, 10000)}
	for i := range bigData["lines"].([]string) {
		bigData["lines"].([]string)[i] = "a line of log output that takes up some space"
	}
	result := platform.ToolResult{Data: bigData}
	out := Truncate(result, 100)
	if !out.Truncated {
		t.Fatalf("expected truncation")
	}
	m, ok := out.Data.(map[string]any)
	if !ok {
		t.Fatalf("expected truncated data to be a map, got %T", out.Data)
	}
	content, ok := m["truncated_content"].(string)
	if !ok || len(content) > 100 {
		t.Fatalf("unexpected truncated content length: %d", len(content))
	}
}

func TestTruncate_ZeroMaxBytesIsNoOp(t *testing.T) {
	result := platform.ToolResult{Data: map[string]any{"a": 1}}
	out := Truncate(result, 0)
	if out.Truncated {
		t.Fatalf("expected no truncation when maxBytes<=0")
	}
}

func TestRegistry_RegisterGetList(t *testing.T) {
	r := NewRegistry()
	r.Register(Spec{Name: "z_tool", Category: "engine"})
	r.Register(Spec{Name: "a_tool", Category: "engine"})

	spec, ok := r.Get("a_tool")
	if !ok || spec.Name != "a_tool" {
		t.Fatalf("unexpected Get result: %+v ok=%v", spec, ok)
	}

	_, ok = r.Get("missing")
	if ok {
		t.Fatalf("expected Get to report not-found")
	}

	list := r.List()
	if len(list) != 2 || list[0].Name != "a_tool" || list[1].Name != "z_tool" {
		t.Fatalf("expected sorted list, got %+v", list)
	}
}
