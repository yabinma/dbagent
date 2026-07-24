// Package dockerenv implements platform.RuntimeEnv for Docker Swarm
// deployments (design.md Section 8.1/8.3), backed by
// probe/internal/dockerapi's minimal Docker Engine REST API client. Unit
// tests mock the Docker Engine API via httptest (design.md Section 14.2:
// "Docker via API mock").
//
// Addressing convention (documented decision, not specified by the
// design beyond "target:str*" params): "target" identifiers this package
// hands out via ListTargets and expects back in Logs/Describe/Exec are
// short Docker container IDs -- the natural addressable unit in Swarm,
// mirroring how k8senv uses pod names. `CoordinatorBaseURL` uses Swarm's
// built-in overlay-network service DNS (Appendix E: "Swarm:
// coordinator_service: presto-coordinator") rather than resolving a
// specific container/task IP, since that's exactly what Swarm's service
// discovery is for.
package dockerenv

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/yabinma/dbagent/probe/internal/dockerapi"
	"github.com/yabinma/dbagent/probe/internal/platform"
)

type Config struct {
	CoordinatorService string // Swarm service name, e.g. "presto-coordinator"
	WorkerService      string // e.g. "presto-worker"
	CoordinatorPort    int    // default 8080
	CoordinatorHTTPS   bool
	// ConfigPaths maps a `file` param (Appendix B.1 presto_config:
	// "config | jvm | node | catalog:<name>") to an in-container path.
	// Not specified by the design; defaults to the conventional
	// `/etc/presto/...` layout documented in impl-progress.md.
	ConfigPaths map[string]string
}

func (c Config) port() int {
	if c.CoordinatorPort > 0 {
		return c.CoordinatorPort
	}
	return 8080
}

func (c Config) configPath(file string) string {
	if p, ok := c.ConfigPaths[file]; ok {
		return p
	}
	if strings.HasPrefix(file, "catalog:") {
		name := strings.TrimPrefix(file, "catalog:")
		return "/etc/presto/catalog/" + name + ".properties"
	}
	switch file {
	case "config":
		return "/etc/presto/config.properties"
	case "jvm":
		return "/etc/presto/jvm.config"
	case "node":
		return "/etc/presto/node.properties"
	default:
		return "/etc/presto/" + file
	}
}

type Env struct {
	Docker *dockerapi.Client
	Cfg    Config
	// Now is injectable for deterministic Events() window tests; defaults
	// to time.Now when nil.
	Now func() time.Time
}

func New(docker *dockerapi.Client, cfg Config) *Env {
	return &Env{Docker: docker, Cfg: cfg, Now: time.Now}
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) Kind() platform.EnvKind { return platform.EnvKindSwarm }

func (e *Env) ListTargets(ctx context.Context, selector string) ([]platform.TargetInfo, error) {
	services := []string{selector}
	if selector == "" {
		services = []string{e.Cfg.CoordinatorService, e.Cfg.WorkerService}
	}

	var out []platform.TargetInfo
	for _, svc := range services {
		if svc == "" {
			continue
		}
		tasks, err := e.Docker.ListTasks(ctx, map[string]map[string]bool{"service": {svc: true}})
		if err != nil {
			return nil, fmt.Errorf("dockerenv: list tasks for service %s: %w", svc, err)
		}
		for _, t := range tasks {
			out = append(out, taskToTargetInfo(t))
		}
	}
	return out, nil
}

func taskToTargetInfo(t dockerapi.Task) platform.TargetInfo {
	containerID := t.Status.ContainerStatus.ContainerID
	name := containerID
	if name == "" {
		name = t.ID
	}
	ready := t.Status.State == "running" && t.DesiredState == "running"
	lastReason := ""
	if t.Status.State == "failed" {
		lastReason = t.Status.Err
		if lastReason == "" {
			lastReason = "failed"
		}
	}
	started, _ := time.Parse(time.RFC3339, t.Status.Timestamp)
	return platform.TargetInfo{
		Name:            name,
		Phase:           t.Status.State,
		Ready:           ready,
		Node:            t.NodeID,
		StartedAt:       started,
		LastStateReason: lastReason,
	}
}

func (e *Env) Logs(ctx context.Context, target, container string, opts platform.LogOptions) ([]string, error) {
	logOpts := dockerapi.LogsOptions{Tail: opts.Lines}
	if opts.Since != "" {
		if d, err := time.ParseDuration(opts.Since); err == nil {
			logOpts.Since = strconv.FormatInt(e.now().Add(-d).Unix(), 10)
		}
	}
	// design.md Appendix B.2: "previous=true fetches pre-restart logs".
	// Docker's logs endpoint has no direct "previous container" concept
	// (unlike k8s' --previous, which reads the last terminated
	// container's log buffer); for a Swarm task that has been restarted,
	// the old container is gone and a new one replaces it under a new
	// container ID, so "previous" logs would require querying the
	// previous task in the service's task history rather than the
	// current container. That lookup is out of scope for M2 (documented
	// gap, mirrors K8s' log-buffer semantics only loosely) -- the current
	// container's logs are returned regardless of `Previous`.
	lines, err := e.Docker.ContainerLogs(ctx, target, logOpts)
	if err != nil {
		return nil, fmt.Errorf("dockerenv: container logs: %w", err)
	}
	if opts.Grep != "" {
		lines = grepLines(lines, opts.Grep)
	}
	return lines, nil
}

func (e *Env) Describe(ctx context.Context, target string) (platform.DescribeResult, error) {
	inspect, err := e.Docker.ContainerInspect(ctx, target)
	if err != nil {
		return platform.DescribeResult{}, fmt.Errorf("dockerenv: inspect: %w", err)
	}
	return platform.DescribeResult{JSON: inspect}, nil
}

func (e *Env) Events(ctx context.Context, opts platform.EventOptions) ([]platform.EventInfo, error) {
	since := e.now().Add(-1 * time.Hour)
	if opts.Since != "" {
		if d, err := time.ParseDuration(opts.Since); err == nil {
			since = e.now().Add(-d)
		}
	}
	until := e.now()
	events, err := e.Docker.Events(ctx,
		strconv.FormatInt(since.Unix(), 10),
		strconv.FormatInt(until.Unix(), 10),
		opts.TypeFilter,
	)
	if err != nil {
		return nil, fmt.Errorf("dockerenv: events: %w", err)
	}
	out := make([]platform.EventInfo, 0, len(events))
	for _, ev := range events {
		out = append(out, platform.EventInfo{
			At:      time.Unix(ev.Time, 0),
			Type:    ev.Type,
			Reason:  ev.Action,
			Object:  ev.Actor.ID,
			Message: describeEventAttrs(ev.Actor.Attributes),
		})
	}
	return out, nil
}

func describeEventAttrs(attrs map[string]string) string {
	if len(attrs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(attrs))
	for k, v := range attrs {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

func (e *Env) ResourceUsage(ctx context.Context, selector string) ([]platform.ResourceUsageInfo, error) {
	targets, err := e.ListTargets(ctx, selector)
	if err != nil {
		return nil, err
	}
	out := make([]platform.ResourceUsageInfo, 0, len(targets))
	for _, tgt := range targets {
		stats, err := e.Docker.ContainerStats(ctx, tgt.Name)
		if err != nil {
			continue // best-effort: skip containers whose stats aren't available
		}
		out = append(out, statsToUsageInfo(tgt.Name, stats))
	}
	return out, nil
}

func statsToUsageInfo(target string, s *dockerapi.Stats) platform.ResourceUsageInfo {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	var cpuMilli int64
	if sysDelta > 0 && cpuDelta > 0 {
		cpuMilli = int64((cpuDelta / sysDelta) * float64(s.CPUStats.OnlineCPUs) * 1000)
	}
	info := platform.ResourceUsageInfo{
		Target:        target,
		CPUMillicores: cpuMilli,
		MemBytes:      int64(s.MemoryStats.Usage),
		MemLimit:      int64(s.MemoryStats.Limit),
	}
	if s.MemoryStats.Limit > 0 {
		info.MemPct = float64(s.MemoryStats.Usage) / float64(s.MemoryStats.Limit) * 100
	}
	return info
}

func (e *Env) Exec(ctx context.Context, target, container string, cmd []string, timeout time.Duration) (platform.ExecResult, error) {
	stdout, stderr, exitCode, err := e.Docker.Exec(ctx, target, cmd)
	if err != nil {
		return platform.ExecResult{}, fmt.Errorf("dockerenv: exec: %w", err)
	}
	return platform.ExecResult{Stdout: stdout, Stderr: stderr, ExitCode: exitCode}, nil
}

func (e *Env) ReadConfig(ctx context.Context, component, file, target string) (string, error) {
	if target == "" {
		svc := e.Cfg.WorkerService
		if component == "coordinator" {
			svc = e.Cfg.CoordinatorService
		}
		targets, err := e.ListTargets(ctx, svc)
		if err != nil {
			return "", err
		}
		if len(targets) == 0 {
			return "", fmt.Errorf("dockerenv: no running task for service %q", svc)
		}
		target = targets[0].Name
	}
	path := e.Cfg.configPath(file)
	stdout, stderr, exitCode, err := e.Docker.Exec(ctx, target, []string{"cat", path})
	if err != nil {
		return "", fmt.Errorf("dockerenv: read config: %w", err)
	}
	if exitCode != 0 {
		return "", fmt.Errorf("dockerenv: read config %s: exit %d: %s", path, exitCode, stderr)
	}
	return stdout, nil
}

func (e *Env) CoordinatorBaseURL(ctx context.Context) (string, error) {
	if e.Cfg.CoordinatorService == "" {
		return "", fmt.Errorf("dockerenv: coordinator_service not configured")
	}
	scheme := "http"
	if e.Cfg.CoordinatorHTTPS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s:%d", scheme, e.Cfg.CoordinatorService, e.Cfg.port()), nil
}

func grepLines(lines []string, needle string) []string {
	var out []string
	for _, l := range lines {
		if strings.Contains(l, needle) {
			out = append(out, l)
		}
	}
	return out
}

// --- Write methods (M5, design.md Section 9.5.3) -------------------------------------

func (e *Env) PatchConfigMap(ctx context.Context, namespace, name string, dataPatches map[string]string) error {
	return fmt.Errorf("dockerenv: PatchConfigMap is k8s-only")
}

func (e *Env) RolloutRestart(ctx context.Context, namespace, kind, name string) error {
	return fmt.Errorf("dockerenv: RolloutRestart is k8s-only")
}

func (e *Env) DeletePod(ctx context.Context, namespace, name string) error {
	return fmt.Errorf("dockerenv: DeletePod is k8s-only")
}

func (e *Env) UpdateServiceEnv(ctx context.Context, service string, env map[string]string) error {
	svc, err := e.Docker.ServiceInspect(ctx, service)
	if err != nil {
		return fmt.Errorf("dockerenv: update service env inspect: %w", err)
	}
	// Merge into TaskTemplate.ContainerSpec.Env (KEY=VALUE entries).
	merged := mergeEnv(svc.Spec.TaskTemplate.ContainerSpec.Env, env)
	svc.Spec.TaskTemplate.ContainerSpec.Env = merged
	if err := e.Docker.ServiceUpdate(ctx, svc.ID, svc.Version.Index, svc.Spec); err != nil {
		return fmt.Errorf("dockerenv: update service env: %w", err)
	}
	return nil
}

func (e *Env) RestartService(ctx context.Context, service string) error {
	svc, err := e.Docker.ServiceInspect(ctx, service)
	if err != nil {
		return fmt.Errorf("dockerenv: restart service inspect: %w", err)
	}
	svc.Spec.TaskTemplate.ForceUpdate++
	if err := e.Docker.ServiceUpdate(ctx, svc.ID, svc.Version.Index, svc.Spec); err != nil {
		return fmt.Errorf("dockerenv: restart service: %w", err)
	}
	return nil
}

// mergeEnv overlays key=value pairs onto an existing Docker Env list.
func mergeEnv(existing []string, patches map[string]string) []string {
	index := map[string]int{}
	out := make([]string, 0, len(existing)+len(patches))
	for _, e := range existing {
		key := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		index[key] = len(out)
		out = append(out, e)
	}
	for k, v := range patches {
		entry := k + "=" + v
		if i, ok := index[k]; ok {
			out[i] = entry
		} else {
			index[k] = len(out)
			out = append(out, entry)
		}
	}
	return out
}
