package dockerenv

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yabinma/dbagent/probe/internal/dockerapi"
	"github.com/yabinma/dbagent/probe/internal/platform"
)

func frame(streamType byte, payload string) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = streamType
	l := len(payload)
	b[4], b[5], b[6], b[7] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	copy(b[8:], payload)
	return b
}

func newTestEnv(t *testing.T, handler http.HandlerFunc) *Env {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	fixedNow := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	env := New(docker, Config{CoordinatorService: "presto-coordinator", WorkerService: "presto-worker"})
	env.Now = func() time.Time { return fixedNow }
	return env
}

func TestKind(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {})
	if env.Kind() != platform.EnvKindSwarm {
		t.Fatalf("expected EnvKindSwarm")
	}
}

func TestListTargets_DefaultsToConfiguredServices(t *testing.T) {
	var seenFilters []string
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		seenFilters = append(seenFilters, r.URL.Query().Get("filters"))
		w.Write([]byte(`[{"ID":"t1","DesiredState":"running","Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}}]`))
	})

	targets, err := env.ListTargets(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Both CoordinatorService and WorkerService are queried when selector is empty.
	if len(seenFilters) != 2 {
		t.Fatalf("expected 2 task-list calls (coordinator + worker), got %d: %v", len(seenFilters), seenFilters)
	}
	if !strings.Contains(seenFilters[0], "presto-coordinator") || !strings.Contains(seenFilters[1], "presto-worker") {
		t.Fatalf("unexpected filters: %v", seenFilters)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets (1 per service), got %d", len(targets))
	}
}

// Regression: Appendix B.1 `resource_usage — params: selector:str=all` makes
// "all" the sentinel for "every target". Sending it into the Docker /tasks
// `service` filter as if it were a service name made a real Swarm answer
// `404 {"message":"service all not found"}`, so `resource_usage` (no args)
// always failed. The mock below behaves like the Engine: an unknown service
// in the filter is a 404.
func TestListTargets_AllSelectorSendsNoServiceFilter(t *testing.T) {
	var seenFilters []string
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tasks" {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.Error(w, `{"message":"not found"}`, http.StatusNotFound)
			return
		}
		raw := r.URL.Query().Get("filters")
		seenFilters = append(seenFilters, raw)
		if raw != "" {
			var filters map[string]map[string]bool
			if err := json.Unmarshal([]byte(raw), &filters); err != nil {
				t.Errorf("bad filters json: %v", err)
			}
			for svc := range filters["service"] {
				if svc != "presto-coordinator" && svc != "presto-worker" {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"service ` + svc + ` not found"}`))
					return
				}
			}
		}
		// Unfiltered listing: tasks across two different services.
		_, _ = w.Write([]byte(`[
			{"ID":"t1","ServiceID":"svc-coordinator","NodeID":"n1","DesiredState":"running",
			 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}},
			{"ID":"t2","ServiceID":"svc-worker","NodeID":"n2","DesiredState":"running",
			 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c2"}}}
		]`))
	})

	targets, err := env.ListTargets(context.Background(), "all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seenFilters) != 1 {
		t.Fatalf("expected exactly 1 /tasks call, got %d: %v", len(seenFilters), seenFilters)
	}
	if seenFilters[0] != "" {
		t.Fatalf("expected no service filter for selector %q, got filters=%s", "all", seenFilters[0])
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets across services, got %d: %+v", len(targets), targets)
	}
	if targets[0].Name != "c1" || targets[1].Name != "c2" {
		t.Fatalf("unexpected targets: %+v", targets)
	}
}

func TestResourceUsage_AllSelectorCoversEveryService(t *testing.T) {
	statsBody := `{
		"cpu_stats": {"cpu_usage": {"total_usage": 4000000000}, "system_cpu_usage": 20000000000, "online_cpus": 4},
		"precpu_stats": {"cpu_usage": {"total_usage": 2000000000}, "system_cpu_usage": 10000000000},
		"memory_stats": {"usage": 1073741824, "limit": 4294967296}
	}`
	var mux http.ServeMux
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		if raw := r.URL.Query().Get("filters"); raw != "" {
			// Mirrors the real Engine: "all" is not a service.
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"service not found: ` + raw + `"}`))
			return
		}
		_, _ = w.Write([]byte(`[
			{"ID":"t1","ServiceID":"svc-coordinator","DesiredState":"running",
			 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}},
			{"ID":"t2","ServiceID":"svc-worker","DesiredState":"running",
			 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c2"}}}
		]`))
	})
	mux.HandleFunc("/containers/c1/stats", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(statsBody))
	})
	mux.HandleFunc("/containers/c2/stats", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(statsBody))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	env := New(dockerapi.New(srv.URL, srv.Client()),
		Config{CoordinatorService: "presto-coordinator", WorkerService: "presto-worker"})

	usage, err := env.ResourceUsage(context.Background(), "all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(usage) != 2 {
		t.Fatalf("expected usage for both services' containers, got %d: %+v", len(usage), usage)
	}
	if usage[0].Target != "c1" || usage[1].Target != "c2" {
		t.Fatalf("unexpected usage targets: %+v", usage)
	}
}

// Review W2 / fix.md: ResourceUsage("") must also send no service filter to
// /tasks (same sentinel as "all"), while ListTargets("") keeps swarm_tasks'
// configured-service default.
func TestResourceUsage_EmptySelectorSendsNoServiceFilter(t *testing.T) {
	statsBody := `{
		"cpu_stats": {"cpu_usage": {"total_usage": 4000000000}, "system_cpu_usage": 20000000000, "online_cpus": 4},
		"precpu_stats": {"cpu_usage": {"total_usage": 2000000000}, "system_cpu_usage": 10000000000},
		"memory_stats": {"usage": 1073741824, "limit": 4294967296}
	}`
	var seenFilters []string
	var mux http.ServeMux
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("filters")
		seenFilters = append(seenFilters, raw)
		if raw != "" {
			// Accept only the configured service names used by ListTargets("").
			var filters map[string]map[string]bool
			if err := json.Unmarshal([]byte(raw), &filters); err != nil {
				t.Errorf("bad filters json: %v", err)
				http.Error(w, "bad filters", http.StatusBadRequest)
				return
			}
			for svc := range filters["service"] {
				if svc != "presto-coordinator" && svc != "presto-worker" {
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"message":"service ` + svc + ` not found"}`))
					return
				}
			}
			_, _ = w.Write([]byte(`[
				{"ID":"t1","DesiredState":"running",
				 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}}
			]`))
			return
		}
		_, _ = w.Write([]byte(`[
			{"ID":"t1","ServiceID":"svc-coordinator","DesiredState":"running",
			 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}},
			{"ID":"t2","ServiceID":"svc-worker","DesiredState":"running",
			 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c2"}}}
		]`))
	})
	mux.HandleFunc("/containers/c1/stats", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(statsBody))
	})
	mux.HandleFunc("/containers/c2/stats", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(statsBody))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	env := New(dockerapi.New(srv.URL, srv.Client()),
		Config{CoordinatorService: "presto-coordinator", WorkerService: "presto-worker"})

	usage, err := env.ResourceUsage(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(seenFilters) != 1 {
		t.Fatalf("expected exactly 1 /tasks call, got %d: %v", len(seenFilters), seenFilters)
	}
	if seenFilters[0] != "" {
		t.Fatalf("expected no service filter for ResourceUsage(\"\"), got filters=%s", seenFilters[0])
	}
	if len(usage) != 2 {
		t.Fatalf("expected usage for both containers, got %d: %+v", len(usage), usage)
	}

	// swarm_tasks empty-selector semantics must still filter configured services.
	seenFilters = nil
	targets, err := env.ListTargets(context.Background(), "")
	if err != nil {
		t.Fatalf("ListTargets(\"\"): %v", err)
	}
	if len(seenFilters) != 2 {
		t.Fatalf("ListTargets(\"\") should query coordinator+worker, got %d filters: %v", len(seenFilters), seenFilters)
	}
	if seenFilters[0] == "" || seenFilters[1] == "" {
		t.Fatalf("ListTargets(\"\") must send service filters, got %v", seenFilters)
	}
	if len(targets) != 2 {
		t.Fatalf("ListTargets(\"\") expected 2 targets, got %d", len(targets))
	}
}

func TestListTargets_SingleService(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tasks" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Write([]byte(`[
			{"ID":"t1","NodeID":"n1","DesiredState":"running",
			 "Status":{"State":"running","Timestamp":"2026-07-09T10:00:00Z","ContainerStatus":{"ContainerID":"c1"}}},
			{"ID":"t2","NodeID":"n2","DesiredState":"running",
			 "Status":{"State":"failed","Err":"task: non-zero exit (137)","ContainerStatus":{"ContainerID":"c2"}}}
		]`))
	})

	targets, err := env.ListTargets(context.Background(), "presto-worker")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}
	if targets[0].Name != "c1" || !targets[0].Ready {
		t.Fatalf("unexpected target[0]: %+v", targets[0])
	}
	if targets[1].Ready || targets[1].LastStateReason == "" {
		t.Fatalf("unexpected target[1]: %+v", targets[1])
	}
}

func TestLogs_WithGrepFilter(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/c1/logs" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Write(frame(1, "INFO starting up\n"))
		w.Write(frame(1, "ERROR OutOfMemoryError occurred\n"))
	})

	lines, err := env.Logs(context.Background(), "c1", "", platform.LogOptions{Since: "30m", Grep: "ERROR"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "OutOfMemoryError") {
		t.Fatalf("unexpected lines: %v", lines)
	}
}

func TestDescribe(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/c1/json" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Write([]byte(`{"Id":"c1","State":{"Status":"running"}}`))
	})

	result, err := env.Describe(context.Background(), "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.JSON["Id"] != "c1" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestEvents(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.URL.Query().Get("since") == "" || r.URL.Query().Get("until") == "" {
			t.Fatalf("expected since/until params, got %s", r.URL.RawQuery)
		}
		w.Write([]byte(`{"Type":"container","Action":"die","Actor":{"ID":"c1","Attributes":{"exitCode":"137"}},"time":1000}` + "\n"))
	})

	events, err := env.Events(context.Background(), platform.EventOptions{Since: "1h", TypeFilter: "warning"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 1 || events[0].Reason != "die" {
		t.Fatalf("unexpected events: %+v", events)
	}
}

func TestResourceUsage(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ID":"t1","Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}},"DesiredState":"running"}]`))
	})
	mux.HandleFunc("/containers/c1/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"cpu_stats": {"cpu_usage": {"total_usage": 4000000000}, "system_cpu_usage": 20000000000, "online_cpus": 4},
			"precpu_stats": {"cpu_usage": {"total_usage": 2000000000}, "system_cpu_usage": 10000000000},
			"memory_stats": {"usage": 1073741824, "limit": 4294967296}
		}`))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{WorkerService: "presto-worker"})

	usage, err := env.ResourceUsage(context.Background(), "presto-worker")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(usage) != 1 {
		t.Fatalf("expected 1 usage entry, got %d", len(usage))
	}
	if usage[0].MemBytes != 1073741824 {
		t.Fatalf("unexpected mem bytes: %d", usage[0].MemBytes)
	}
	if usage[0].MemPct != 25.0 {
		t.Fatalf("unexpected mem pct: %f", usage[0].MemPct)
	}
}

func TestExec(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/containers/c1/exec", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"exec1"}`))
	})
	mux.HandleFunc("/exec/exec1/start", func(w http.ResponseWriter, r *http.Request) {
		w.Write(frame(1, "thread dump\n"))
	})
	mux.HandleFunc("/exec/exec1/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ExitCode":0}`))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{})

	result, err := env.Exec(context.Background(), "c1", "", []string{"jcmd", "1", "Thread.print"}, 30*time.Second)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stdout != "thread dump" || result.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestReadConfig_ResolvesTargetFromService(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ID":"t1","Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}},"DesiredState":"running"}]`))
	})
	mux.HandleFunc("/containers/c1/exec", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"exec1"}`))
	})
	mux.HandleFunc("/exec/exec1/start", func(w http.ResponseWriter, r *http.Request) {
		w.Write(frame(1, "coordinator=true\nquery.max-memory=50GB\n"))
	})
	mux.HandleFunc("/exec/exec1/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ExitCode":0}`))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{CoordinatorService: "presto-coordinator", WorkerService: "presto-worker"})

	content, err := env.ReadConfig(context.Background(), "coordinator", "config", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content, "coordinator=true") {
		t.Fatalf("unexpected content: %q", content)
	}
}

func TestReadConfig_ExplicitTarget(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/containers/c9/exec", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"exec9"}`))
	})
	mux.HandleFunc("/exec/exec9/start", func(w http.ResponseWriter, r *http.Request) {
		w.Write(frame(1, "connector.name=hive\n"))
	})
	mux.HandleFunc("/exec/exec9/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ExitCode":0}`))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{})

	content, err := env.ReadConfig(context.Background(), "worker", "catalog:hive", "c9")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(content, "connector.name=hive") {
		t.Fatalf("unexpected content: %q", content)
	}
}

func TestReadConfig_NonZeroExitReturnsError(t *testing.T) {
	var mux http.ServeMux
	mux.HandleFunc("/containers/c9/exec", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"exec9"}`))
	})
	mux.HandleFunc("/exec/exec9/start", func(w http.ResponseWriter, r *http.Request) {
		w.Write(frame(2, "cat: no such file\n"))
	})
	mux.HandleFunc("/exec/exec9/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ExitCode":1}`))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{})

	_, err := env.ReadConfig(context.Background(), "worker", "config", "c9")
	if err == nil {
		t.Fatalf("expected error for non-zero exit")
	}
}

func TestCoordinatorBaseURL(t *testing.T) {
	env := newTestEnv(t, func(w http.ResponseWriter, r *http.Request) {})
	url, err := env.CoordinatorBaseURL(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "http://presto-coordinator:8080" {
		t.Fatalf("unexpected url: %s", url)
	}
}

func TestCoordinatorBaseURL_HTTPSAndCustomPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{CoordinatorService: "presto-coordinator", CoordinatorHTTPS: true, CoordinatorPort: 8443})

	url, err := env.CoordinatorBaseURL(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if url != "https://presto-coordinator:8443" {
		t.Fatalf("unexpected url: %s", url)
	}
}

func TestCoordinatorBaseURL_NotConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{})

	_, err := env.CoordinatorBaseURL(context.Background())
	if err == nil {
		t.Fatalf("expected error when coordinator service is not configured")
	}
}

func TestUpdateServiceEnvAndRestart(t *testing.T) {
	var force uint64
	mux := http.NewServeMux()
	mux.HandleFunc("/services/presto-worker", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ID":      "svc1",
			"Version": map[string]any{"Index": 3},
			"Spec": map[string]any{
				"Name": "presto-worker",
				"TaskTemplate": map[string]any{
					"ContainerSpec": map[string]any{"Env": []string{"X=1"}},
					"ForceUpdate":   force,
				},
			},
		})
	})
	mux.HandleFunc("/services/svc1/update", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		tt := body["TaskTemplate"].(map[string]any)
		if fu, ok := tt["ForceUpdate"].(float64); ok {
			force = uint64(fu)
		}
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	env := New(dockerapi.New(srv.URL, srv.Client()), Config{WorkerService: "presto-worker"})
	if err := env.UpdateServiceEnv(context.Background(), "presto-worker", map[string]string{"Y": "2"}); err != nil {
		t.Fatalf("update env: %v", err)
	}
	if err := env.RestartService(context.Background(), "presto-worker"); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if force < 1 {
		t.Fatalf("expected ForceUpdate bumped, got %d", force)
	}
	if err := env.PatchConfigMap(context.Background(), "ns", "cm", nil); err == nil {
		t.Fatalf("expected k8s-only error")
	}
}

func TestReadConfigMapKey_K8sOnly(t *testing.T) {
	env := New(nil, Config{})
	_, err := env.ReadConfigMapKey(context.Background(), "ns", "cm", "config.properties")
	if err == nil || !strings.Contains(err.Error(), "k8s-only") {
		t.Fatalf("expected k8s-only error, got %v", err)
	}
}

// --- UT-SW-2 (design.md §11.2.5, FP-SW-1): per-key config_paths override and
// per-key /etc/presto/... fallback. ---

func TestConfigPath_PerKeyOverrideAndPerKeyFallback(t *testing.T) {
	cfg := Config{ConfigPaths: map[string]string{
		"config":       "/opt/presto-server/etc/config.properties",
		"catalog:hive": "/opt/presto-server/etc/catalog/hive.properties",
	}}
	cases := []struct{ file, want string }{
		{"config", "/opt/presto-server/etc/config.properties"},
		{"catalog:hive", "/opt/presto-server/etc/catalog/hive.properties"},
		// Absent keys fall back per key, never wholesale.
		{"jvm", "/etc/presto/jvm.config"},
		{"node", "/etc/presto/node.properties"},
		{"catalog:iceberg", "/etc/presto/catalog/iceberg.properties"},
		{"log", "/etc/presto/log"},
	}
	for _, tc := range cases {
		if got := cfg.configPath(tc.file); got != tc.want {
			t.Fatalf("configPath(%q) = %q, want %q", tc.file, got, tc.want)
		}
	}
}

func TestConfigPath_NilMapKeepsEveryDefault(t *testing.T) {
	cfg := Config{}
	cases := []struct{ file, want string }{
		{"config", "/etc/presto/config.properties"},
		{"jvm", "/etc/presto/jvm.config"},
		{"node", "/etc/presto/node.properties"},
		{"catalog:hive", "/etc/presto/catalog/hive.properties"},
		{"anything-else", "/etc/presto/anything-else"},
	}
	for _, tc := range cases {
		if got := cfg.configPath(tc.file); got != tc.want {
			t.Fatalf("configPath(%q) = %q, want %q", tc.file, got, tc.want)
		}
	}
}

// FP-SW-1: ReadConfig issues `cat <overridden path>` inside the container.
func TestReadConfig_ExecsCatOnTheOverriddenPath(t *testing.T) {
	var execCmd []any
	var mux http.ServeMux
	mux.HandleFunc("/containers/c9/exec", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode exec body: %v", err)
		}
		execCmd, _ = body["Cmd"].([]any)
		w.Write([]byte(`{"Id":"exec9"}`))
	})
	mux.HandleFunc("/exec/exec9/start", func(w http.ResponseWriter, r *http.Request) {
		w.Write(frame(1, "coordinator=true\n"))
	})
	mux.HandleFunc("/exec/exec9/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ExitCode":0}`))
	})
	srv := httptest.NewServer(&mux)
	t.Cleanup(srv.Close)
	docker := dockerapi.New(srv.URL, srv.Client())
	env := New(docker, Config{ConfigPaths: map[string]string{
		"config": "/opt/presto-server/etc/config.properties",
	}})

	if _, err := env.ReadConfig(context.Background(), "coordinator", "config", "c9"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []any{"cat", "/opt/presto-server/etc/config.properties"}
	if len(execCmd) != len(want) || execCmd[0] != want[0] || execCmd[1] != want[1] {
		t.Fatalf("exec Cmd = %#v, want %#v", execCmd, want)
	}
}
