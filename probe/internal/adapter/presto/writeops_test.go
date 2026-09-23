package presto

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

// TestM6_AdjustMemoryConfig_ReadsTargetConfigMap_AndFailsClosed is FP-M6-29 / S3:
// applyMemoryConfigWhitelist must ReadConfigMapKey the ConfigMap named in
// step.Params (not a conventional component name) and fail closed on read error.
func TestM6_AdjustMemoryConfig_ReadsTargetConfigMap_AndFailsClosed(t *testing.T) {
	t.Run("reads_target_namespace_name", func(t *testing.T) {
		env := &fakeEnv{
			kind:       platform.EnvKindK8s,
			readCMText: "query.max-memory=10GB\nother.property=keep-me\n",
		}
		a := New(Config{WriteEnabled: true})
		a.env = env
		result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
			PlaybookID: "presto.adjust_memory_config",
			Op:         "k8s_patch_configmap", SignatureOK: true,
			Params: map[string]any{
				"name": "presto-worker-config", "namespace": "presto-ns",
				"patches": []any{map[string]any{"key": "query.max-memory", "value": "50GB"}},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !result.OK {
			t.Fatalf("expected OK, got %s", result.Error)
		}
		if env.lastReadCM.ns != "presto-ns" || env.lastReadCM.name != "presto-worker-config" {
			t.Fatalf("ReadConfigMapKey target = %+v, want ns=presto-ns name=presto-worker-config", env.lastReadCM)
		}
		if env.lastReadCM.key != "config.properties" {
			t.Fatalf("key = %q, want config.properties", env.lastReadCM.key)
		}
		got := env.lastPatchCM.patches["config.properties"]
		if !strings.Contains(got, "query.max-memory=50GB") {
			t.Fatalf("merged memory missing: %q", got)
		}
		if !strings.Contains(got, "other.property=keep-me") {
			t.Fatalf("non-whitelisted property discarded (data-loss bug): %q", got)
		}
	})

	t.Run("fails_closed_on_read_error", func(t *testing.T) {
		env := &fakeEnv{
			kind:      platform.EnvKindK8s,
			readCMErr: errors.New("configmap not found"),
		}
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
			t.Fatalf("unexpected transport error: %v", err)
		}
		if result.OK {
			t.Fatal("expected fail-closed WriteResult{OK:false}")
		}
		if !strings.Contains(result.Error, "read configmap") {
			t.Fatalf("error should name the read failure: %q", result.Error)
		}
		// ConfigMap must be left untouched — no PatchConfigMap call.
		if env.lastPatchCM.name != "" {
			t.Fatalf("PatchConfigMap must not run after read failure, got %+v", env.lastPatchCM)
		}
	})
}

func TestExecuteWrite_AdjustMemoryPreservesOtherProperties(t *testing.T) {
	env := &fakeEnv{
		kind:       platform.EnvKindK8s,
		readCMText: "query.max-memory=10GB\ncoordinator=false\nnode-scheduler.include-coordinator=false\n",
	}
	a := New(Config{WriteEnabled: true})
	a.env = env
	result, err := a.ExecuteWrite(context.Background(), platform.RemediationStep{
		PlaybookID: "presto.adjust_memory_config",
		Op:         "k8s_patch_configmap", SignatureOK: true,
		Params: map[string]any{
			"name": "cm", "namespace": "ns",
			"patches": []any{map[string]any{"key": "query.max-memory-per-node", "value": "8GB"}},
		},
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !result.OK {
		t.Fatalf("%s", result.Error)
	}
	got := env.lastPatchCM.patches["config.properties"]
	for _, want := range []string{"coordinator=false", "node-scheduler.include-coordinator=false", "query.max-memory-per-node=8GB"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in %q", want, got)
		}
	}
}
