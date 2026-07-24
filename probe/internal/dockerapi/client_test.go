package dockerapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func frame(streamType byte, payload string) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = streamType
	l := len(payload)
	b[4] = byte(l >> 24)
	b[5] = byte(l >> 16)
	b[6] = byte(l >> 8)
	b[7] = byte(l)
	copy(b[8:], payload)
	return b
}

func TestListTasks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tasks" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"ID":"t1","ServiceID":"svc1","Slot":1,"NodeID":"n1","DesiredState":"running",
			 "Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}},
			{"ID":"t2","ServiceID":"svc1","Slot":2,"NodeID":"n2","DesiredState":"running",
			 "Status":{"State":"failed","Err":"task: non-zero exit (137)","ContainerStatus":{"ContainerID":"c2"}}}
		]`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	tasks, err := c.ListTasks(context.Background(), nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tasks) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(tasks))
	}
	if tasks[1].Status.State != "failed" || tasks[1].Status.Err == "" {
		t.Fatalf("unexpected task[1]: %+v", tasks[1])
	}
}

func TestListTasks_WithFilters(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		filtersRaw := r.URL.Query().Get("filters")
		if filtersRaw == "" {
			t.Fatalf("expected filters query param")
		}
		var filters map[string]map[string]bool
		if err := json.Unmarshal([]byte(filtersRaw), &filters); err != nil {
			t.Fatalf("bad filters json: %v", err)
		}
		if !filters["service"]["presto-worker"] {
			t.Fatalf("unexpected filters: %+v", filters)
		}
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	_, err := c.ListTasks(context.Background(), map[string]map[string]bool{"service": {"presto-worker": true}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestContainerInspect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/c1/json" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"Id":"c1","State":{"Status":"running"}}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	out, err := c.ContainerInspect(context.Background(), "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out["Id"] != "c1" {
		t.Fatalf("unexpected body: %+v", out)
	}
}

func TestContainerLogs_DemultiplexesFramedStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/c1/logs" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Write(frame(1, "hello stdout\n"))
		w.Write(frame(2, "warn stderr\n"))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	lines, err := c.ContainerLogs(context.Background(), "c1", LogsOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %v", lines)
	}
}

func TestContainerLogs_FallsBackToRawTextWhenNotFramed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("plain line one\nplain line two\n"))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	lines, err := c.ContainerLogs(context.Background(), "c1", LogsOptions{Tail: 100, Since: "0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 2 || lines[0] != "plain line one" {
		t.Fatalf("unexpected lines: %v", lines)
	}
}

func TestEvents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/events" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Write([]byte(`{"Type":"container","Action":"die","Actor":{"ID":"c1","Attributes":{"exitCode":"137"}},"time":1000}` + "\n"))
		w.Write([]byte(`{"Type":"container","Action":"start","Actor":{"ID":"c2","Attributes":{}},"time":1001}` + "\n"))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	events, err := c.Events(context.Background(), "1000000000", "1000000100", "warning")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
	if events[0].Actor.Attributes["exitCode"] != "137" {
		t.Fatalf("unexpected event: %+v", events[0])
	}
}

func TestContainerStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/containers/c1/stats" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{
			"cpu_stats": {"cpu_usage": {"total_usage": 2000000000}, "system_cpu_usage": 10000000000, "online_cpus": 4},
			"precpu_stats": {"cpu_usage": {"total_usage": 1000000000}, "system_cpu_usage": 9000000000},
			"memory_stats": {"usage": 536870912, "limit": 2147483648}
		}`))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	stats, err := c.ContainerStats(context.Background(), "c1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stats.MemoryStats.Usage != 536870912 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestExec_CreateStartInspectSequence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/containers/c1/exec" && r.Method == http.MethodPost:
			_, _ = w.Write([]byte(`{"Id":"exec1"}`))
		case r.URL.Path == "/exec/exec1/start" && r.Method == http.MethodPost:
			w.Write(frame(1, "thread dump output\n"))
		case r.URL.Path == "/exec/exec1/json" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`{"ExitCode":0}`))
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	stdout, stderr, exitCode, err := c.Exec(context.Background(), "c1", []string{"jcmd", "1", "Thread.print"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if stdout != "thread dump output" {
		t.Fatalf("unexpected stdout: %q", stdout)
	}
	if stderr != "" {
		t.Fatalf("unexpected stderr: %q", stderr)
	}
	if exitCode != 0 {
		t.Fatalf("unexpected exit code: %d", exitCode)
	}
}

func TestExec_NonZeroExitCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/containers/c1/exec":
			_, _ = w.Write([]byte(`{"Id":"exec1"}`))
		case r.URL.Path == "/exec/exec1/start":
			w.Write(frame(2, "command not found\n"))
		case r.URL.Path == "/exec/exec1/json":
			_, _ = w.Write([]byte(`{"ExitCode":127}`))
		}
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	_, stderr, exitCode, err := c.Exec(context.Background(), "c1", []string{"nonexistent"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitCode != 127 || stderr != "command not found" {
		t.Fatalf("unexpected result: stderr=%q exitCode=%d", stderr, exitCode)
	}
}

func TestGetJSON_ErrorStatusPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	c := New(srv.URL, srv.Client())
	_, err := c.ContainerInspect(context.Background(), "missing")
	if err == nil {
		t.Fatalf("expected error")
	}
}

func TestServiceInspectAndUpdate(t *testing.T) {
	var updated bool
	var updateBody map[string]any
	mux := http.NewServeMux()
	mux.HandleFunc("/services/presto-worker", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", 405)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ID": "svc1",
			"Version": map[string]any{"Index": 7},
			"Spec": map[string]any{
				"Name": "presto-worker",
				"TaskTemplate": map[string]any{
					"ContainerSpec": map[string]any{
						"Image": "presto:0.298",
						"Env":   []string{"A=1"},
					},
					"ForceUpdate": 0,
				},
			},
		})
	})
	mux.HandleFunc("/services/svc1/update", func(w http.ResponseWriter, r *http.Request) {
		updated = true
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&updateBody)
		if r.URL.Query().Get("version") != "7" {
			http.Error(w, "bad version", 400)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(srv.URL, srv.Client())
	svc, err := c.ServiceInspect(context.Background(), "presto-worker")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if svc.ID != "svc1" || svc.Version.Index != 7 {
		t.Fatalf("unexpected service: %+v", svc)
	}
	svc.Spec.TaskTemplate.ContainerSpec.Env = []string{"A=1", "B=2"}
	svc.Spec.TaskTemplate.ForceUpdate = 1
	if err := c.ServiceUpdate(context.Background(), svc.ID, svc.Version.Index, svc.Spec); err != nil {
		t.Fatalf("update: %v", err)
	}
	if !updated {
		t.Fatalf("update not called")
	}
}
