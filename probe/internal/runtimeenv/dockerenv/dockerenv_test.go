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
			"ID": "svc1",
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
