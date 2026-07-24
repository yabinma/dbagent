// Package k8senv implements platform.RuntimeEnv for Kubernetes deployments
// (design.md Section 8.1/8.3), backed by k8s.io/client-go. Unit tests use
// the fake clientset (design.md Section 14.2: "K8s via client-go fake").
//
// Pod exec (used for `jvm_thread_dump`/`jvm_heap_histo` and the gated raw
// command channel) goes through an injected PodExecFunc rather than
// client-go's SPDY executor directly, since the fake clientset does not
// support the pods/exec subresource realistically -- this keeps Exec unit
// testable without a real API server (a common, low-risk Go DI pattern).
package k8senv

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	metricsclientset "k8s.io/metrics/pkg/client/clientset/versioned"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

// PodExecFunc runs cmd inside a pod/container and returns its output.
// Production wiring supplies an implementation backed by
// client-go/tools/remotecommand's SPDY executor.
type PodExecFunc func(ctx context.Context, namespace, pod, container string, cmd []string, timeout time.Duration) (stdout, stderr string, exitCode int, err error)

type Config struct {
	Namespace           string
	CoordinatorSelector string // K8s label selector, e.g. "app=presto,role=coordinator"
	CoordinatorPort     int    // default 8080
	CoordinatorHTTPS    bool
	// ConfigMapNames maps a Presto component ("coordinator"/"worker") to
	// the ConfigMap name holding its config files (design.md Appendix B.1
	// presto_config: "Source: K8s ConfigMap ... in-container file read").
	// Not specified by the design beyond "ConfigMap"; defaults to the
	// conventional `presto-<component>-config` naming documented in
	// impl-progress.md.
	ConfigMapNames map[string]string
}

func (c Config) configMapName(component string) string {
	if name, ok := c.ConfigMapNames[component]; ok {
		return name
	}
	return "presto-" + component + "-config"
}

func (c Config) port() int {
	if c.CoordinatorPort > 0 {
		return c.CoordinatorPort
	}
	return 8080
}

type Env struct {
	Clientset kubernetes.Interface
	Metrics   metricsclientset.Interface // nil -> ResourceUsage returns an error
	Cfg       Config
	ExecFn    PodExecFunc // nil -> Exec returns an error
}

func New(clientset kubernetes.Interface, metrics metricsclientset.Interface, cfg Config, execFn PodExecFunc) *Env {
	return &Env{Clientset: clientset, Metrics: metrics, Cfg: cfg, ExecFn: execFn}
}

func (e *Env) Kind() platform.EnvKind { return platform.EnvKindK8s }

func (e *Env) ListTargets(ctx context.Context, selector string) ([]platform.TargetInfo, error) {
	if selector == "" {
		selector = e.Cfg.CoordinatorSelector
	}
	pods, err := e.Clientset.CoreV1().Pods(e.Cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("k8senv: list pods: %w", err)
	}
	out := make([]platform.TargetInfo, 0, len(pods.Items))
	for _, p := range pods.Items {
		out = append(out, podToTargetInfo(p))
	}
	return out, nil
}

func podToTargetInfo(p corev1.Pod) platform.TargetInfo {
	ready := true
	restarts := 0
	lastReason := ""
	for _, cs := range p.Status.ContainerStatuses {
		if !cs.Ready {
			ready = false
		}
		restarts += int(cs.RestartCount)
		if cs.LastTerminationState.Terminated != nil && cs.LastTerminationState.Terminated.Reason != "" {
			lastReason = cs.LastTerminationState.Terminated.Reason
		}
	}
	started := time.Time{}
	if p.Status.StartTime != nil {
		started = p.Status.StartTime.Time
	}
	return platform.TargetInfo{
		Name:            p.Name,
		Phase:           string(p.Status.Phase),
		Ready:           ready,
		Restarts:        restarts,
		Node:            p.Spec.NodeName,
		StartedAt:       started,
		LastStateReason: lastReason,
	}
}

func (e *Env) Logs(ctx context.Context, target, container string, opts platform.LogOptions) ([]string, error) {
	podLogOpts := &corev1.PodLogOptions{
		Container: container,
		Previous:  opts.Previous,
	}
	if opts.Lines > 0 {
		tail := int64(opts.Lines)
		podLogOpts.TailLines = &tail
	}
	if opts.Since != "" {
		if secs, err := parseDurationSeconds(opts.Since); err == nil {
			podLogOpts.SinceSeconds = &secs
		}
	}
	req := e.Clientset.CoreV1().Pods(e.Cfg.Namespace).GetLogs(target, podLogOpts)
	stream, err := req.Stream(ctx)
	if err != nil {
		return nil, fmt.Errorf("k8senv: get logs: %w", err)
	}
	defer stream.Close()

	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 4096)
	for {
		n, rerr := stream.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	lines := splitNonEmpty(string(buf))
	if opts.Grep != "" {
		lines = grepLines(lines, opts.Grep)
	}
	return lines, nil
}

func (e *Env) Describe(ctx context.Context, target string) (platform.DescribeResult, error) {
	pod, err := e.Clientset.CoreV1().Pods(e.Cfg.Namespace).Get(ctx, target, metav1.GetOptions{})
	if err != nil {
		return platform.DescribeResult{}, fmt.Errorf("k8senv: get pod: %w", err)
	}
	events, _ := e.Clientset.CoreV1().Events(e.Cfg.Namespace).List(ctx, metav1.ListOptions{
		FieldSelector: "involvedObject.name=" + target,
	})

	var sb strings.Builder
	fmt.Fprintf(&sb, "Name:         %s\n", pod.Name)
	fmt.Fprintf(&sb, "Namespace:    %s\n", pod.Namespace)
	fmt.Fprintf(&sb, "Node:         %s\n", pod.Spec.NodeName)
	fmt.Fprintf(&sb, "Status:       %s\n", pod.Status.Phase)
	for _, cs := range pod.Status.ContainerStatuses {
		fmt.Fprintf(&sb, "Container %s: ready=%v restarts=%d\n", cs.Name, cs.Ready, cs.RestartCount)
	}
	sb.WriteString("Events:\n")
	if events != nil {
		for _, ev := range events.Items {
			fmt.Fprintf(&sb, "  %s  %s  %s\n", ev.Type, ev.Reason, ev.Message)
		}
	}
	return platform.DescribeResult{Text: sb.String()}, nil
}

func (e *Env) Events(ctx context.Context, opts platform.EventOptions) ([]platform.EventInfo, error) {
	events, err := e.Clientset.CoreV1().Events(e.Cfg.Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("k8senv: list events: %w", err)
	}
	out := make([]platform.EventInfo, 0, len(events.Items))
	for _, ev := range events.Items {
		if opts.TypeFilter == "warning" && ev.Type != "Warning" {
			continue
		}
		at := ev.LastTimestamp.Time
		if at.IsZero() {
			at = ev.EventTime.Time
		}
		out = append(out, platform.EventInfo{
			At:      at,
			Type:    ev.Type,
			Reason:  ev.Reason,
			Object:  ev.InvolvedObject.Name,
			Message: ev.Message,
		})
	}
	return out, nil
}

func (e *Env) ResourceUsage(ctx context.Context, selector string) ([]platform.ResourceUsageInfo, error) {
	if e.Metrics == nil {
		return nil, fmt.Errorf("k8senv: metrics client not configured")
	}
	if selector == "" || selector == "all" {
		selector = ""
	}
	metricsList, err := e.Metrics.MetricsV1beta1().PodMetricses(e.Cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, fmt.Errorf("k8senv: list pod metrics: %w", err)
	}
	// Resource limits require the corresponding Pod spec; best-effort join.
	pods, _ := e.Clientset.CoreV1().Pods(e.Cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	limits := map[string]struct {
		cpuMilli int64
		memBytes int64
	}{}
	if pods != nil {
		for _, p := range pods.Items {
			var cpu, mem int64
			for _, c := range p.Spec.Containers {
				if q, ok := c.Resources.Limits[corev1.ResourceCPU]; ok {
					cpu += q.MilliValue()
				}
				if q, ok := c.Resources.Limits[corev1.ResourceMemory]; ok {
					mem += q.Value()
				}
			}
			limits[p.Name] = struct {
				cpuMilli int64
				memBytes int64
			}{cpu, mem}
		}
	}

	out := make([]platform.ResourceUsageInfo, 0, len(metricsList.Items))
	for _, m := range metricsList.Items {
		var cpuMilli, memBytes int64
		for _, c := range m.Containers {
			if q, ok := c.Usage[corev1.ResourceCPU]; ok {
				cpuMilli += q.MilliValue()
			}
			if q, ok := c.Usage[corev1.ResourceMemory]; ok {
				memBytes += q.Value()
			}
		}
		lim := limits[m.Name]
		info := platform.ResourceUsageInfo{
			Target:        m.Name,
			CPUMillicores: cpuMilli,
			CPULimit:      lim.cpuMilli,
			MemBytes:      memBytes,
			MemLimit:      lim.memBytes,
		}
		if lim.memBytes > 0 {
			info.MemPct = float64(memBytes) / float64(lim.memBytes) * 100
		}
		out = append(out, info)
	}
	return out, nil
}

func (e *Env) Exec(ctx context.Context, target, container string, cmd []string, timeout time.Duration) (platform.ExecResult, error) {
	if e.ExecFn == nil {
		return platform.ExecResult{}, fmt.Errorf("k8senv: exec not configured")
	}
	stdout, stderr, exitCode, err := e.ExecFn(ctx, e.Cfg.Namespace, target, container, cmd, timeout)
	if err != nil {
		return platform.ExecResult{}, err
	}
	return platform.ExecResult{Stdout: stdout, Stderr: stderr, ExitCode: exitCode}, nil
}

func (e *Env) ReadConfig(ctx context.Context, component, file, target string) (string, error) {
	cmName := e.Cfg.configMapName(component)
	cm, err := e.Clientset.CoreV1().ConfigMaps(e.Cfg.Namespace).Get(ctx, cmName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("k8senv: get configmap %s: %w", cmName, err)
	}
	key := configFileToKey(file)
	content, ok := cm.Data[key]
	if !ok {
		return "", fmt.Errorf("k8senv: key %q not found in configmap %s", key, cmName)
	}
	return content, nil
}

// configFileToKey maps the `file` param (Appendix B.1 presto_config:
// "config | jvm | node | catalog:<name>") to a ConfigMap data key.
func configFileToKey(file string) string {
	if strings.HasPrefix(file, "catalog:") {
		name := strings.TrimPrefix(file, "catalog:")
		return "catalog-" + name + ".properties"
	}
	switch file {
	case "config":
		return "config.properties"
	case "jvm":
		return "jvm.config"
	case "node":
		return "node.properties"
	default:
		return file
	}
}

func (e *Env) CoordinatorBaseURL(ctx context.Context) (string, error) {
	pods, err := e.Clientset.CoreV1().Pods(e.Cfg.Namespace).List(ctx, metav1.ListOptions{LabelSelector: e.Cfg.CoordinatorSelector})
	if err != nil {
		return "", fmt.Errorf("k8senv: list coordinator pods: %w", err)
	}
	for _, p := range pods.Items {
		if p.Status.PodIP == "" {
			continue
		}
		allReady := true
		for _, cs := range p.Status.ContainerStatuses {
			if !cs.Ready {
				allReady = false
			}
		}
		if !allReady {
			continue
		}
		scheme := "http"
		if e.Cfg.CoordinatorHTTPS {
			scheme = "https"
		}
		return fmt.Sprintf("%s://%s:%d", scheme, p.Status.PodIP, e.Cfg.port()), nil
	}
	return "", fmt.Errorf("k8senv: no ready coordinator pod matching selector %q", e.Cfg.CoordinatorSelector)
}

// --- helpers -------------------------------------------------------------------------

func parseDurationSeconds(s string) (int64, error) {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	return int64(d.Seconds()), nil
}

func splitNonEmpty(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
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
	if namespace == "" {
		namespace = e.Cfg.Namespace
	}
	// Strategic-merge patch over data keys (Appendix B.5 literal: value = full file content).
	patch := map[string]any{"data": dataPatches}
	raw, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("k8senv: marshal configmap patch: %w", err)
	}
	_, err = e.Clientset.CoreV1().ConfigMaps(namespace).Patch(
		ctx, name, types.StrategicMergePatchType, raw, metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("k8senv: patch configmap %s/%s: %w", namespace, name, err)
	}
	return nil
}

func (e *Env) RolloutRestart(ctx context.Context, namespace, kind, name string) error {
	if namespace == "" {
		namespace = e.Cfg.Namespace
	}
	// Exactly what `kubectl rollout restart` does: set pod-template annotation.
	restartedAt := time.Now().UTC().Format(time.RFC3339)
	patch := map[string]any{
		"spec": map[string]any{
			"template": map[string]any{
				"metadata": map[string]any{
					"annotations": map[string]string{
						"kubectl.kubernetes.io/restartedAt": restartedAt,
					},
				},
			},
		},
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("k8senv: marshal rollout restart patch: %w", err)
	}
	switch strings.ToLower(kind) {
	case "deployment":
		_, err = e.Clientset.AppsV1().Deployments(namespace).Patch(
			ctx, name, types.StrategicMergePatchType, raw, metav1.PatchOptions{},
		)
	case "statefulset":
		_, err = e.Clientset.AppsV1().StatefulSets(namespace).Patch(
			ctx, name, types.StrategicMergePatchType, raw, metav1.PatchOptions{},
		)
	default:
		return fmt.Errorf("k8senv: rollout restart: unknown kind %q (want deployment|statefulset)", kind)
	}
	if err != nil {
		return fmt.Errorf("k8senv: rollout restart %s/%s/%s: %w", kind, namespace, name, err)
	}
	return nil
}

func (e *Env) DeletePod(ctx context.Context, namespace, name string) error {
	if namespace == "" {
		namespace = e.Cfg.Namespace
	}
	err := e.Clientset.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("k8senv: delete pod %s/%s: %w", namespace, name, err)
	}
	return nil
}

func (e *Env) UpdateServiceEnv(ctx context.Context, service string, env map[string]string) error {
	return fmt.Errorf("k8senv: UpdateServiceEnv is swarm-only")
}

func (e *Env) RestartService(ctx context.Context, service string) error {
	return fmt.Errorf("k8senv: RestartService is swarm-only")
}
