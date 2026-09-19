package presto

import (
	"context"

	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/redact"
)

// --- Appendix B.2 Runtime Tools -------------------------------------------------------
// pod_logs/container_logs, k8s_pods/swarm_tasks, k8s_describe/docker_inspect, and
// k8s_events/docker_events are deployment-kind-specific names for the same
// RuntimeEnv operation; the adapter only registers the pair matching
// env.Kind() (design.md Appendix A: Capabilities.tools reflects the
// active deployment only).

func toolPodOrContainerLogs(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	target, _ := args["target"].(string)
	container := getStringDefault(args, "container", "")
	opts := platform.LogOptions{
		Since:    getStringDefault(args, "since", "30m"),
		Lines:    getIntDefault(args, "lines", 1000),
		Grep:     getStringDefault(args, "grep", ""),
		Previous: getBoolDefault(args, "previous", false),
	}
	lines, err := a.env.Logs(ctx, target, container, opts)
	if err != nil {
		return toolResult{}, err
	}
	return toolResult{Data: map[string]any{"lines": lines}}, nil
}

func toolPodsOrTasks(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	selector := getStringDefault(args, "selector", "")
	targets, err := a.env.ListTargets(ctx, selector)
	if err != nil {
		return toolResult{}, err
	}
	out := make([]map[string]any, 0, len(targets))
	for _, t := range targets {
		out = append(out, map[string]any{
			"name":              t.Name,
			"phase":             t.Phase,
			"ready":             t.Ready,
			"restarts":          t.Restarts,
			"node":              t.Node,
			"started_at":        t.StartedAt,
			"last_state_reason": t.LastStateReason,
		})
	}
	return toolResult{Data: out}, nil
}

// toolDescribeOrInspect implements Appendix B.2 `k8s_describe`/`docker_inspect`.
// design.md Section 8.2/8.5 (v1.6): both are explicitly in-scope for
// redaction -- container env vars (routinely carrying `*_PASSWORD` values)
// and command-line args appear in both the k8s "describe" text blob and the
// docker "inspect" JSON blob. JSON (docker_inspect) is routed through the
// recursive redact.Map filter (the Section 8.2 "single production entry
// point" for structured output); text (k8s_describe) goes through the
// equivalent text filter, redact.Text.
func toolDescribeOrInspect(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	target, _ := args["target"].(string)
	result, err := a.env.Describe(ctx, target)
	if err != nil {
		return toolResult{}, err
	}
	if result.JSON != nil {
		redacted, wasRedacted := redact.Map(result.JSON)
		return toolResult{Data: map[string]any{"json": redacted}, Redacted: wasRedacted}, nil
	}
	redactedText, wasRedacted := redact.Text(result.Text)
	return toolResult{Data: map[string]any{"text": redactedText}, Redacted: wasRedacted}, nil
}

func toolEventsK8sOrDocker(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	opts := platform.EventOptions{
		Since:      getStringDefault(args, "since", "1h"),
		TypeFilter: getStringDefault(args, "type", "warning"),
	}
	events, err := a.env.Events(ctx, opts)
	if err != nil {
		return toolResult{}, err
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		out = append(out, map[string]any{
			"at":      e.At,
			"type":    e.Type,
			"reason":  e.Reason,
			"object":  e.Object,
			"message": e.Message,
		})
	}
	return toolResult{Data: out}, nil
}

func toolResourceUsage(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	selector := getStringDefault(args, "selector", "all")
	usage, err := a.env.ResourceUsage(ctx, selector)
	if err != nil {
		return toolResult{}, err
	}
	out := make([]map[string]any, 0, len(usage))
	for _, u := range usage {
		out = append(out, map[string]any{
			"target":         u.Target,
			"cpu_millicores": u.CPUMillicores,
			"cpu_limit":      u.CPULimit,
			"mem_bytes":      u.MemBytes,
			"mem_limit":      u.MemLimit,
			"mem_pct":        u.MemPct,
		})
	}
	return toolResult{Data: out}, nil
}
