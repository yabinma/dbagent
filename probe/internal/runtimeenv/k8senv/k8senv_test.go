package k8senv

import (
	"context"
	"testing"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	fakeclientset "k8s.io/client-go/kubernetes/fake"
	metricsv1beta1 "k8s.io/metrics/pkg/apis/metrics/v1beta1"
	fakemetrics "k8s.io/metrics/pkg/client/clientset/versioned/fake"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

// podMetricsGVR is the metrics.k8s.io GVR the generated typed client
// actually requests for PodMetrics ("pods", not the scheme's default
// pluralization "podmetricses" -- a documented quirk of
// k8s.io/metrics' fake clientset: NewSimpleClientset(objects...) seeds
// the tracker via the default RESTMapper guess, which doesn't match what
// the generated client requests, so PodMetrics fixtures must be seeded
// via Tracker().Create with this explicit GVR instead.
var podMetricsGVR = schema.GroupVersionResource{Group: "metrics.k8s.io", Version: "v1beta1", Resource: "pods"}

func pod(name, namespace string, ready bool, restarts int32, lastReason string, ip string) *corev1.Pod {
	p := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace, Labels: map[string]string{"app": "presto", "role": "coordinator"}},
		Spec:       corev1.PodSpec{NodeName: "node-1"},
		Status: corev1.PodStatus{
			Phase:     corev1.PodRunning,
			PodIP:     ip,
			StartTime: &metav1.Time{Time: time.Now()},
			ContainerStatuses: []corev1.ContainerStatus{
				{Name: "presto", Ready: ready, RestartCount: restarts},
			},
		},
	}
	if lastReason != "" {
		p.Status.ContainerStatuses[0].LastTerminationState.Terminated = &corev1.ContainerStateTerminated{Reason: lastReason}
	}
	return p
}

func TestListTargets(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(
		pod("coordinator-0", "presto", true, 0, "", "10.0.0.1"),
		pod("worker-0", "presto", false, 3, "OOMKilled", "10.0.0.2"),
	)
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	targets, err := env.ListTargets(context.Background(), "app=presto")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	var worker platform.TargetInfo
	for _, tg := range targets {
		if tg.Name == "worker-0" {
			worker = tg
		}
	}
	if worker.Ready {
		t.Fatalf("expected worker-0 not ready")
	}
	if worker.Restarts != 3 || worker.LastStateReason != "OOMKilled" {
		t.Fatalf("unexpected worker info: %+v", worker)
	}
}

func TestLogs_ReturnsLines(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(pod("coordinator-0", "presto", true, 0, "", "10.0.0.1"))
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	// The fake clientset's GetLogs().Stream() always returns a fixed
	// "fake logs" body (a documented client-go fake-package behavior);
	// this test exercises Logs()'s options handling and post-processing
	// (grep filtering, non-empty line splitting) around that fixed body.
	lines, err := env.Logs(context.Background(), "coordinator-0", "presto", platform.LogOptions{
		Since: "30m", Lines: 100, Previous: true,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) == 0 {
		t.Fatalf("expected at least one log line")
	}
}

func TestLogs_GrepFiltersOutNonMatchingLines(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(pod("coordinator-0", "presto", true, 0, "", "10.0.0.1"))
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	lines, err := env.Logs(context.Background(), "coordinator-0", "presto", platform.LogOptions{Grep: "does-not-appear-anywhere"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected grep to filter out all lines, got %v", lines)
	}
}

func TestLogs_InvalidSinceDurationIgnored(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(pod("coordinator-0", "presto", true, 0, "", "10.0.0.1"))
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	// "not-a-duration" fails time.ParseDuration and is silently ignored
	// (SinceSeconds left unset) rather than erroring the whole call.
	_, err := env.Logs(context.Background(), "coordinator-0", "presto", platform.LogOptions{Since: "not-a-duration"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDescribe(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(pod("coordinator-0", "presto", true, 0, "", "10.0.0.1"))
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	result, err := env.Describe(context.Background(), "coordinator-0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Text == "" {
		t.Fatalf("expected non-empty describe text")
	}
}

func TestEvents_FiltersWarningType(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(
		&corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev1", Namespace: "presto"},
			Type:           "Warning",
			Reason:         "BackOff",
			Message:        "restart loop",
			InvolvedObject: corev1.ObjectReference{Name: "worker-0"},
			LastTimestamp:  metav1.Time{Time: time.Now()},
		},
		&corev1.Event{
			ObjectMeta:     metav1.ObjectMeta{Name: "ev2", Namespace: "presto"},
			Type:           "Normal",
			Reason:         "Scheduled",
			InvolvedObject: corev1.ObjectReference{Name: "worker-0"},
			LastTimestamp:  metav1.Time{Time: time.Now()},
		},
	)
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	events, err := env.Events(context.Background(), platform.EventOptions{TypeFilter: "warning"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].Reason != "BackOff" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestEvents_AllTypes(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "ev1", Namespace: "presto"}, Type: "Normal"},
		&corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "ev2", Namespace: "presto"}, Type: "Warning"},
	)
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	events, err := env.Events(context.Background(), platform.EventOptions{TypeFilter: "all"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestResourceUsage(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-0", Namespace: "presto"},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{
			Name: "presto",
			Resources: corev1.ResourceRequirements{Limits: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("2"),
				corev1.ResourceMemory: resource.MustParse("4Gi"),
			}},
		}}},
	})
	metricsClient := fakemetrics.NewSimpleClientset()
	if err := metricsClient.Tracker().Create(podMetricsGVR, &metricsv1beta1.PodMetrics{
		ObjectMeta: metav1.ObjectMeta{Name: "worker-0", Namespace: "presto"},
		Containers: []metricsv1beta1.ContainerMetrics{{
			Name: "presto",
			Usage: corev1.ResourceList{
				corev1.ResourceCPU:    resource.MustParse("500m"),
				corev1.ResourceMemory: resource.MustParse("1Gi"),
			},
		}},
	}, "presto"); err != nil {
		t.Fatalf("seed metrics fixture: %v", err)
	}
	env := New(cs, metricsClient, Config{Namespace: "presto"}, nil)

	usage, err := env.ResourceUsage(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(usage) != 1 {
		t.Fatalf("expected 1 usage entry, got %d", len(usage))
	}
	if usage[0].CPUMillicores != 500 {
		t.Fatalf("unexpected cpu millicores: %d", usage[0].CPUMillicores)
	}
	if usage[0].MemPct <= 0 {
		t.Fatalf("expected non-zero mem pct, got %f", usage[0].MemPct)
	}
}

func TestResourceUsage_NoMetricsClientConfigured(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset()
	env := New(cs, nil, Config{Namespace: "presto"}, nil)
	_, err := env.ResourceUsage(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error when metrics client is nil")
	}
}

func TestExec_UsesInjectedExecFn(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset()
	called := false
	execFn := func(ctx context.Context, namespace, podName, container string, cmd []string, timeout time.Duration) (string, string, int, error) {
		called = true
		if namespace != "presto" || podName != "coordinator-0" {
			t.Fatalf("unexpected exec target: %s/%s", namespace, podName)
		}
		return "dump output", "", 0, nil
	}
	env := New(cs, nil, Config{Namespace: "presto"}, execFn)

	result, err := env.Exec(context.Background(), "coordinator-0", "presto", []string{"jcmd", "1", "Thread.print"}, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !called {
		t.Fatalf("execFn was not called")
	}
	if result.Stdout != "dump output" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestExec_NotConfiguredReturnsError(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset()
	env := New(cs, nil, Config{Namespace: "presto"}, nil)
	_, err := env.Exec(context.Background(), "coordinator-0", "presto", []string{"ls"}, time.Second)
	if err == nil {
		t.Fatalf("expected error when ExecFn is nil")
	}
}

func TestReadConfig(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "presto-coordinator-config", Namespace: "presto"},
		Data: map[string]string{
			"config.properties":       "coordinator=true\nquery.max-memory=50GB\n",
			"catalog-hive.properties": "connector.name=hive\npassword=hunter2\n",
		},
	})
	env := New(cs, nil, Config{Namespace: "presto"}, nil)

	content, err := env.ReadConfig(context.Background(), "coordinator", "config", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content == "" {
		t.Fatalf("expected non-empty content")
	}

	catalogContent, err := env.ReadConfig(context.Background(), "coordinator", "catalog:hive", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if catalogContent == "" {
		t.Fatalf("expected non-empty catalog content")
	}
}

func TestReadConfig_MissingConfigMap(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset()
	env := New(cs, nil, Config{Namespace: "presto"}, nil)
	_, err := env.ReadConfig(context.Background(), "coordinator", "config", "")
	if err == nil {
		t.Fatalf("expected error for missing configmap")
	}
}

func TestReadConfig_CustomConfigMapNames(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "custom-coord-cm", Namespace: "presto"},
		Data:       map[string]string{"jvm.config": "-Xmx16G"},
	})
	env := New(cs, nil, Config{
		Namespace:      "presto",
		ConfigMapNames: map[string]string{"coordinator": "custom-coord-cm"},
	}, nil)

	content, err := env.ReadConfig(context.Background(), "coordinator", "jvm", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if content != "-Xmx16G" {
		t.Fatalf("unexpected content: %q", content)
	}
}

func TestCoordinatorBaseURL(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(pod("coordinator-0", "presto", true, 0, "", "10.0.0.5"))
	env := New(cs, nil, Config{Namespace: "presto", CoordinatorSelector: "role=coordinator"}, nil)

	url, err := env.CoordinatorBaseURL(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "http://10.0.0.5:8080" {
		t.Fatalf("unexpected url: %s", url)
	}
}

func TestCoordinatorBaseURL_HTTPSAndCustomPort(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(pod("coordinator-0", "presto", true, 0, "", "10.0.0.5"))
	env := New(cs, nil, Config{
		Namespace: "presto", CoordinatorSelector: "role=coordinator",
		CoordinatorHTTPS: true, CoordinatorPort: 8443,
	}, nil)

	url, err := env.CoordinatorBaseURL(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://10.0.0.5:8443" {
		t.Fatalf("unexpected url: %s", url)
	}
}

func TestCoordinatorBaseURL_NoReadyPod(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(pod("coordinator-0", "presto", false, 0, "", "10.0.0.5"))
	env := New(cs, nil, Config{Namespace: "presto", CoordinatorSelector: "role=coordinator"}, nil)

	_, err := env.CoordinatorBaseURL(context.Background())
	if err == nil {
		t.Fatalf("expected error when no ready coordinator pod exists")
	}
}

func TestKind(t *testing.T) {
	env := New(fakeclientset.NewSimpleClientset(), nil, Config{}, nil)
	if env.Kind() != platform.EnvKindK8s {
		t.Fatalf("expected EnvKindK8s")
	}
}


func TestPatchConfigMap(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(&corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: "cm1", Namespace: "ns"},
		Data:       map[string]string{"config.properties": "a=1\n"},
	})
	env := New(cs, nil, Config{Namespace: "ns"}, nil)
	err := env.PatchConfigMap(context.Background(), "ns", "cm1", map[string]string{"config.properties": "a=2\n"})
	if err != nil {
		t.Fatalf("%v", err)
	}
	cm, err := cs.CoreV1().ConfigMaps("ns").Get(context.Background(), "cm1", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if cm.Data["config.properties"] != "a=2\n" {
		t.Fatalf("got %q", cm.Data["config.properties"])
	}
}

func TestRolloutRestartDeployment(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(&appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "presto-worker", Namespace: "ns"},
		Spec: appsv1.DeploymentSpec{
			Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "presto"}},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{Labels: map[string]string{"app": "presto"}, Annotations: map[string]string{}},
				Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "presto", Image: "presto:0.298"}}},
			},
		},
	})
	env := New(cs, nil, Config{Namespace: "ns"}, nil)
	if err := env.RolloutRestart(context.Background(), "ns", "deployment", "presto-worker"); err != nil {
		t.Fatalf("%v", err)
	}
	d, err := cs.AppsV1().Deployments("ns").Get(context.Background(), "presto-worker", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if d.Spec.Template.Annotations["kubectl.kubernetes.io/restartedAt"] == "" {
		t.Fatalf("restart annotation missing: %+v", d.Spec.Template.Annotations)
	}
}

func TestDeletePod(t *testing.T) {
	cs := fakeclientset.NewSimpleClientset(&corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "pod1", Namespace: "ns"},
	})
	env := New(cs, nil, Config{Namespace: "ns"}, nil)
	if err := env.DeletePod(context.Background(), "ns", "pod1"); err != nil {
		t.Fatalf("%v", err)
	}
	_, err := cs.CoreV1().Pods("ns").Get(context.Background(), "pod1", metav1.GetOptions{})
	if err == nil {
		t.Fatalf("expected pod deleted")
	}
}

func TestK8sSwarmOnlyWriteMethodsError(t *testing.T) {
	env := New(fakeclientset.NewSimpleClientset(), nil, Config{Namespace: "ns"}, nil)
	if err := env.UpdateServiceEnv(context.Background(), "svc", map[string]string{"A": "1"}); err == nil {
		t.Fatalf("expected swarm-only error")
	}
	if err := env.RestartService(context.Background(), "svc"); err == nil {
		t.Fatalf("expected swarm-only error")
	}
}
