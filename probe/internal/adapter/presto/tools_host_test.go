package presto

import (
	"context"
	"errors"
	"testing"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

func TestExecute_JVMThreadDump(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.execRes = platform.ExecResult{Stdout: "full thread dump follows...", ExitCode: 0}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "jvm_thread_dump", Args: map[string]any{"target": "coordinator-0"},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	if data["dump"] != "full thread dump follows..." {
		t.Fatalf("unexpected dump: %+v", data)
	}
}

func TestExecute_JVMThreadDump_ExecError(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.execErr = errors.New("exec failed: pod not found")

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "jvm_thread_dump", Args: map[string]any{"target": "missing-pod"},
	})
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	if result.Error == "" {
		t.Fatalf("expected error envelope")
	}
}

func TestExecute_JVMHeapHisto(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.execRes = platform.ExecResult{
		Stdout: " num     #instances         #bytes  class name\n" +
			"----------------------------------------------\n" +
			"   1:         12345        6789012  java.lang.String\n" +
			"   2:          1000         500000  [B\n",
		ExitCode: 0,
	}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "jvm_heap_histo", Args: map[string]any{"target": "worker-0", "top": 10},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	histo := data["histogram"].([]map[string]any)
	if len(histo) != 2 {
		t.Fatalf("unexpected histogram entries: %+v", histo)
	}
	if histo[0]["class"] != "java.lang.String" || histo[0]["instances"] != int64(12345) {
		t.Fatalf("unexpected first entry: %+v", histo[0])
	}
}

func TestExecute_JVMHeapHisto_CapsAtTop(t *testing.T) {
	srv := newPrestoTestServer(t, nil)
	a, env := detectedAdapter(t, srv, platform.EnvKindK8s)
	env.execRes = platform.ExecResult{
		Stdout: "   1:         100         200  a.A\n" +
			"   2:         100         200  b.B\n" +
			"   3:         100         200  c.C\n",
	}

	result, err := a.Execute(context.Background(), platform.ToolCall{
		ToolName: "jvm_heap_histo", Args: map[string]any{"target": "worker-0", "top": 2},
	})
	if err != nil || result.Error != "" {
		t.Fatalf("unexpected result: %+v err=%v", result, err)
	}
	data := result.Data.(map[string]any)
	histo := data["histogram"].([]map[string]any)
	if len(histo) != 2 {
		t.Fatalf("expected top=2 entries, got %d", len(histo))
	}
}

func TestParseHeapHistogram_IgnoresMalformedLines(t *testing.T) {
	out := parseHeapHistogram("not a data line\n1: notanumber 200 x.Y\n", 50)
	if len(out) != 0 {
		t.Fatalf("expected no entries from malformed input, got %+v", out)
	}
}
