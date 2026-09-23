package dockerapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// --- UT-SW-3 (design.md §11.2.5, FP-SW-2/FP-SW-3): NewForBaseURL. ---

// serveOnUnixSocket starts an httptest.Server whose listener is a unix socket
// at socketPath, so the client under test performs a real socket dial.
func serveOnUnixSocket(t *testing.T, socketPath string, handler http.Handler) *httptest.Server {
	t.Helper()
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func TestNewForBaseURL_UnixSocketPerformsRealRequest(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	var sawPing bool
	serveOnUnixSocket(t, socketPath, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			sawPing = true
			_, _ = w.Write([]byte("OK"))
		case "/tasks":
			_, _ = w.Write([]byte(`[{"ID":"t1","ServiceID":"svc1","Slot":1,"NodeID":"n1","DesiredState":"running","Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}}]`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))

	client, err := NewForBaseURL("unix://" + socketPath)
	if err != nil {
		t.Fatalf("NewForBaseURL: %v", err)
	}
	if !sawPing {
		t.Fatal("NewForBaseURL did not issue GET /_ping (Stat-only preflight is insufficient for permission failures)")
	}
	if client.BaseURL != "http://docker" {
		t.Fatalf("BaseURL = %q, want the dummy authority http://docker", client.BaseURL)
	}
	if client.HTTP.Timeout != 0 {
		t.Fatalf("client Timeout = %s, want none (contexts bound every request)", client.HTTP.Timeout)
	}
	tasks, err := client.ListTasks(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListTasks over the unix socket: %v", err)
	}
	if len(tasks) != 1 || tasks[0].ID != "t1" || tasks[0].Status.ContainerStatus.ContainerID != "c1" {
		t.Fatalf("unexpected tasks: %#v", tasks)
	}
}

// C1: Stat alone cannot detect a non-root process lacking the docker group.
// A socket that exists (Stat succeeds) but is not connectable must fail at
// NewForBaseURL — before enrollment can spend the bootstrap token.
func TestNewForBaseURL_UnixSocketPermissionDeniedSurfacesPreEnrollment(t *testing.T) {
	// Root bypasses unix socket permission bits, so chmod 000 does not deny.
	if os.Geteuid() == 0 {
		t.Skip("root bypasses socket permission bits; chmod 000 is not a denial")
	}
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	// Mode 000: Stat still succeeds; connect must fail with EACCES for any
	// non-root caller, including the socket owner. That is the production
	// failure mode when UID 65532 meets a root:docker 0660 socket without the
	// host docker GID (Compose group_add / Swarm user:).
	if err := os.Chmod(socketPath, 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(socketPath, 0o700) })

	info, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("precondition: Stat must succeed (the bug was stopping here): %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("precondition: path must remain a socket")
	}

	_, err = NewForBaseURL("unix://" + socketPath)
	if err == nil {
		t.Fatal("expected a connectivity/permission error; Stat-only preflight would wrongly succeed")
	}
	msg := err.Error()
	if !strings.Contains(msg, "cannot reach docker") {
		t.Fatalf("error = %q, want a connectivity failure (not a missing-socket Stat error)", msg)
	}
	// The failure must be a permission denial past Stat — not merely the
	// guidance string that every "cannot reach docker" error already carries.
	if !strings.Contains(msg, "permission denied") {
		t.Fatalf("error = %q, want permission denied (past Stat)", msg)
	}
}

func TestNewForBaseURL_HTTPKeepsTodaysClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	t.Cleanup(srv.Close)

	for _, base := range []string{srv.URL, "https://docker-proxy.internal:2376"} {
		client, err := NewForBaseURL(base)
		if err != nil {
			t.Fatalf("NewForBaseURL(%q): %v", base, err)
		}
		if client.BaseURL != base {
			t.Fatalf("BaseURL = %q, want %q", client.BaseURL, base)
		}
		if client.HTTP != http.DefaultClient {
			t.Fatalf("expected the plain default client for %q", base)
		}
	}
	client, _ := NewForBaseURL(srv.URL)
	if _, err := client.ListTasks(context.Background(), nil); err != nil {
		t.Fatalf("ListTasks over http: %v", err)
	}
}

func TestNewForBaseURL_NamedErrors(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regular, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "absent.sock")

	cases := []struct {
		name    string
		baseURL string
		want    string
	}{
		{
			name:    "unsupported scheme",
			baseURL: "tcp://docker:2375",
			want:    `dockerapi: unsupported docker_api_base_url scheme "tcp://docker:2375" (want unix://, http:// or https://)`,
		},
		{
			name:    "no scheme at all",
			baseURL: "/var/run/docker.sock",
			want:    `dockerapi: unsupported docker_api_base_url scheme "/var/run/docker.sock" (want unix://, http:// or https://)`,
		},
		{
			name:    "missing socket path",
			baseURL: "unix://" + missing,
			want:    "dockerapi: docker socket " + missing + " not found (mount /var/run/docker.sock into the probe container)",
		},
		{
			name:    "path is a regular file",
			baseURL: "unix://" + regular,
			want:    "dockerapi: " + regular + " is not a unix socket",
		},
		{
			name:    "empty unix path",
			baseURL: "unix://",
			want:    `dockerapi: docker socket path "" must be absolute (use unix:///var/run/docker.sock)`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := NewForBaseURL(tc.baseURL)
			if err == nil {
				t.Fatalf("expected an error, got client %#v", client)
			}
			if err.Error() != tc.want {
				t.Fatalf("error = %q, want %q", err.Error(), tc.want)
			}
		})
	}
}

// DW2: an *existing* relative socket must be rejected for being relative, not
// accepted for existing -- the case that separates "checked absoluteness" from
// "happened to fail Stat".
func TestNewForBaseURL_ExistingRelativeSocketIsRejected(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	serveOnUnixSocket(t, filepath.Join(dir, "docker.sock"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	}))
	if _, err := os.Stat("docker.sock"); err != nil {
		t.Fatalf("precondition: the relative socket must exist and Stat cleanly: %v", err)
	}

	_, err := NewForBaseURL("unix://docker.sock")
	if err == nil {
		t.Fatal("expected a relative-path error for an existing relative socket")
	}
	want := `dockerapi: docker socket path "docker.sock" must be absolute (use unix:///var/run/docker.sock)`
	if err.Error() != want {
		t.Fatalf("error = %q, want %q", err.Error(), want)
	}
}
