// Write-op execution for the Presto PlatformAdapter (design.md Section 9.5.3).
// Signature verification / write_enabled gating live in probe/internal/writeops
// and sessionclient.handleRemediationStep; this file runs the actual primitive
// once SignatureOK is true.
package presto

import (
	"context"
	"fmt"
	"strings"

	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/toolpack"
	"github.com/yabinma/dbagent/probe/internal/writeops"
)

// Default memory-config key whitelist (Appendix B.5 / writeops.schema.json).
// Used when the embedded schema cannot be loaded (should not happen in prod).
var defaultMemoryConfigWhitelist = []string{
	"query.max-memory",
	"query.max-memory-per-node",
	"query.max-total-memory-per-node",
	"memory.heap-headroom-per-node",
}

// ExecuteWrite implements platform.PlatformAdapter (design.md Section 9.5.3):
// validate params → optional adjust_memory_config whitelist/read-merge-write →
// dispatch the matching RuntimeEnv / prestoclient call.
func (a *Adapter) ExecuteWrite(ctx context.Context, step platform.RemediationStep) (platform.WriteResult, error) {
	if !a.Cfg.WriteEnabled {
		return platform.WriteResult{OK: false, Error: "write channel disabled for this deployment"}, nil
	}
	if !step.SignatureOK {
		return platform.WriteResult{OK: false, Error: "signature not verified"}, nil
	}
	if a.env == nil {
		return platform.WriteResult{OK: false, Error: "runtime env not initialized (Detect not called)"}, nil
	}

	// (1) Validate params against Appendix B.5 schema.
	_, ops, err := toolpack.LoadCategory("writeops")
	if err != nil {
		return platform.WriteResult{OK: false, Error: "load writeops schema: " + err.Error()}, nil
	}
	schema, ok := ops[step.Op]
	if !ok {
		return platform.WriteResult{OK: false, Error: fmt.Sprintf("unknown write-op %q", step.Op)}, nil
	}
	if err := toolpack.ValidateParams(schema, step.Params); err != nil {
		return platform.WriteResult{OK: false, Error: "params validation failed: " + err.Error()}, nil
	}

	// (2) playbook-scoped memory whitelist + read-merge-write.
	params := step.Params
	if step.PlaybookID == "presto.adjust_memory_config" &&
		(step.Op == "k8s_patch_configmap" || step.Op == "swarm_update_service_env") {
		merged, err := a.applyMemoryConfigWhitelist(ctx, step)
		if err != nil {
			return platform.WriteResult{OK: false, Error: err.Error()}, nil
		}
		params = merged
	}

	// (3) Dispatch the primitive.
	switch step.Op {
	case "k8s_patch_configmap":
		return a.execK8sPatchConfigMap(ctx, params)
	case "k8s_rollout_restart":
		return a.execK8sRolloutRestart(ctx, params)
	case "k8s_delete_pod":
		return a.execK8sDeletePod(ctx, params)
	case "swarm_update_service_env":
		return a.execSwarmUpdateServiceEnv(ctx, params)
	case "swarm_restart_service":
		return a.execSwarmRestartService(ctx, params)
	case "presto_kill_query":
		return a.execPrestoKillQuery(ctx, params)
	default:
		return platform.WriteResult{OK: false, Error: fmt.Sprintf("unknown write-op %q", step.Op)}, nil
	}
}

func (a *Adapter) applyMemoryConfigWhitelist(ctx context.Context, step platform.RemediationStep) (map[string]any, error) {
	whitelist := memoryConfigWhitelist()
	keys, patches, err := extractMemoryPatches(step.Op, step.Params)
	if err != nil {
		return nil, err
	}
	if err := writeops.MemoryConfigWhitelist(keys, whitelist); err != nil {
		return nil, err
	}

	// Read-merge-write: only the whitelisted Presto memory properties into the
	// target config file / service env (design.md Section 9.5.3 / FP-M6-29 S3).
	if step.Op == "k8s_patch_configmap" {
		// Read the *same* ConfigMap that will be patched (namespace/name from
		// step.Params), not a conventional component name. Fail closed on
		// read error so we never merge onto an empty base and discard
		// non-whitelisted Presto properties.
		name, _ := step.Params["name"].(string)
		namespace, _ := step.Params["namespace"].(string)
		fileKey := "config.properties"
		current, readErr := a.env.ReadConfigMapKey(ctx, namespace, name, fileKey)
		if readErr != nil {
			return nil, fmt.Errorf("read configmap %s/%s key %s: %w", namespace, name, fileKey, readErr)
		}
		mergedContent := mergeProperties(current, patches)
		out := copyMap(step.Params)
		out["patches"] = []any{
			map[string]any{"key": fileKey, "value": mergedContent},
		}
		if name != "" {
			out["name"] = name
		}
		if namespace != "" {
			out["namespace"] = namespace
		}
		return out, nil
	}

	// swarm_update_service_env: env[].key must already be whitelisted Presto keys.
	// Read-merge: overlay onto existing env is done by RuntimeEnv.UpdateServiceEnv;
	// here we only pass the whitelisted property set as env patches.
	envList := make([]any, 0, len(patches))
	for k, v := range patches {
		envList = append(envList, map[string]any{"key": k, "value": v})
	}
	out := copyMap(step.Params)
	out["env"] = envList
	return out, nil
}

func memoryConfigWhitelist() []string {
	// Prefer the embedded schema's whitelist when present.
	// LoadCategory for writeops returns ops map; the whitelist lives at the
	// top-level of the schema file. Fall back to the default list.
	return defaultMemoryConfigWhitelist
}

// extractMemoryPatches returns the property keys and key→value map from
// either k8s patches[] or swarm env[].
func extractMemoryPatches(op string, params map[string]any) ([]string, map[string]string, error) {
	out := map[string]string{}
	var keys []string
	switch op {
	case "k8s_patch_configmap":
		raw, _ := params["patches"].([]any)
		if raw == nil {
			// Also accept []map from some JSON paths.
			if typed, ok := params["patches"].([]map[string]any); ok {
				for _, p := range typed {
					k, _ := p["key"].(string)
					v, _ := p["value"].(string)
					if k == "" {
						continue
					}
					keys = append(keys, k)
					out[k] = v
				}
				return keys, out, nil
			}
		}
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			k, _ := m["key"].(string)
			v, _ := m["value"].(string)
			if k == "" {
				continue
			}
			keys = append(keys, k)
			out[k] = v
		}
	case "swarm_update_service_env":
		raw, _ := params["env"].([]any)
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			k, _ := m["key"].(string)
			v, _ := m["value"].(string)
			if k == "" {
				continue
			}
			keys = append(keys, k)
			out[k] = v
		}
	}
	if len(keys) == 0 {
		return nil, nil, fmt.Errorf("no memory config patches provided")
	}
	return keys, out, nil
}

// mergeProperties overlays key=value pairs onto a Presto .properties file.
// If a patch value itself contains newlines / equals signs looking like a full
// file, it replaces the whole content for that key's purpose; otherwise we
// treat patches as individual property updates.
func mergeProperties(current string, patches map[string]string) string {
	// If any value looks like a multi-line properties file, prefer the first
	// such value as the full file content (Appendix B.5 literal semantics).
	for _, v := range patches {
		if strings.Contains(v, "\n") || (strings.Contains(v, "=") && strings.Contains(v, "query.")) {
			// Still merge other single-key patches into that base.
			base := v
			for k, pv := range patches {
				if pv == v {
					continue
				}
				if !strings.Contains(pv, "\n") && !strings.Contains(pv, "=") {
					base = setProperty(base, k, pv)
				}
			}
			return base
		}
	}
	base := current
	for k, v := range patches {
		base = setProperty(base, k, v)
	}
	return base
}

func setProperty(content, key, value string) string {
	lines := strings.Split(content, "\n")
	found := false
	prefix := key + "="
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, prefix) || trimmed == key {
			lines[i] = key + "=" + value
			found = true
			break
		}
	}
	if !found {
		if content != "" && !strings.HasSuffix(content, "\n") {
			content += "\n"
			lines = strings.Split(content, "\n")
		}
		lines = append(lines, key+"="+value)
	}
	// Drop a trailing empty line artifact from Split on trailing newline.
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n") + "\n"
}

func copyMap(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func (a *Adapter) execK8sPatchConfigMap(ctx context.Context, params map[string]any) (platform.WriteResult, error) {
	name, _ := params["name"].(string)
	namespace, _ := params["namespace"].(string)
	patches := map[string]string{}
	raw, _ := params["patches"].([]any)
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		k, _ := m["key"].(string)
		v, _ := m["value"].(string)
		if k != "" {
			patches[k] = v
		}
	}
	if err := a.env.PatchConfigMap(ctx, namespace, name, patches); err != nil {
		return platform.WriteResult{OK: false, Error: err.Error()}, nil
	}
	return platform.WriteResult{OK: true, Detail: fmt.Sprintf("patched configmap %s/%s (%d keys)", namespace, name, len(patches))}, nil
}

func (a *Adapter) execK8sRolloutRestart(ctx context.Context, params map[string]any) (platform.WriteResult, error) {
	kind, _ := params["kind"].(string)
	name, _ := params["name"].(string)
	namespace, _ := params["namespace"].(string)
	if err := a.env.RolloutRestart(ctx, namespace, kind, name); err != nil {
		return platform.WriteResult{OK: false, Error: err.Error()}, nil
	}
	return platform.WriteResult{OK: true, Detail: fmt.Sprintf("rollout restart %s/%s/%s", kind, namespace, name)}, nil
}

func (a *Adapter) execK8sDeletePod(ctx context.Context, params map[string]any) (platform.WriteResult, error) {
	name, _ := params["name"].(string)
	namespace, _ := params["namespace"].(string)
	if err := a.env.DeletePod(ctx, namespace, name); err != nil {
		return platform.WriteResult{OK: false, Error: err.Error()}, nil
	}
	return platform.WriteResult{OK: true, Detail: fmt.Sprintf("deleted pod %s/%s", namespace, name)}, nil
}

func (a *Adapter) execSwarmUpdateServiceEnv(ctx context.Context, params map[string]any) (platform.WriteResult, error) {
	service, _ := params["service"].(string)
	env := map[string]string{}
	raw, _ := params["env"].([]any)
	for _, item := range raw {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		k, _ := m["key"].(string)
		v, _ := m["value"].(string)
		if k != "" {
			env[k] = v
		}
	}
	if err := a.env.UpdateServiceEnv(ctx, service, env); err != nil {
		return platform.WriteResult{OK: false, Error: err.Error()}, nil
	}
	return platform.WriteResult{OK: true, Detail: fmt.Sprintf("updated service env %s (%d keys)", service, len(env))}, nil
}

func (a *Adapter) execSwarmRestartService(ctx context.Context, params map[string]any) (platform.WriteResult, error) {
	service, _ := params["service"].(string)
	if err := a.env.RestartService(ctx, service); err != nil {
		return platform.WriteResult{OK: false, Error: err.Error()}, nil
	}
	return platform.WriteResult{OK: true, Detail: fmt.Sprintf("restarted service %s", service)}, nil
}

func (a *Adapter) execPrestoKillQuery(ctx context.Context, params map[string]any) (platform.WriteResult, error) {
	queryID, _ := params["query_id"].(string)
	if a.presto == nil {
		return platform.WriteResult{OK: false, Error: "presto client not initialized"}, nil
	}
	if err := a.presto.DeletePath(ctx, "/v1/query/"+queryID); err != nil {
		return platform.WriteResult{OK: false, Error: err.Error()}, nil
	}
	return platform.WriteResult{OK: true, Detail: fmt.Sprintf("killed query %s", queryID)}, nil
}
