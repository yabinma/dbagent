// Swarm Docker-access function tests (design.md §11.2.5, FP-SW-1/2/3).
//
// These run the real compiled `probe` binary against the real
// `probe-gateway` binary, a real ephemeral Postgres and mocked platform-side
// externals (fake Presto REST + fake Docker Engine API), exactly like the F8
// registration tests in this package. What they add is the Swarm Docker
// access surface the first real-cluster deployment broke on:
//
//	TestSW1 -- config_paths reaches the in-container `cat`
//	TestSW2 -- the Docker Engine API is reached over a mounted unix socket
//	TestSW3 -- a bad docker_api_base_url is fatal BEFORE enrollment, so the
//	           single-use bootstrap token survives for a corrected run
package m2_probe_link

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- fake Docker Engine API that records the exec commands it is asked to run ---

type recordingDockerAPI struct {
	srv *httptest.Server

	mu       sync.Mutex
	execCmds [][]string
}

func (r *recordingDockerAPI) commands() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]string, len(r.execCmds))
	copy(out, r.execCmds)
	return out
}

func (r *recordingDockerAPI) sawExec(t *testing.T, want []string, timeout time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, cmd := range r.commands() {
			if len(cmd) == len(want) {
				match := true
				for i := range cmd {
					if cmd[i] != want[i] {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

func newRecordingDockerMux(rec *recordingDockerAPI, configContent string) *http.ServeMux {
	mux := http.NewServeMux()
	// NewForBaseURL issues GET /_ping on unix:// so permission failures surface
	// before enrollment (review C1).
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"ID":"t1","DesiredState":"running","Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}}]`))
	})
	mux.HandleFunc("/containers/c1/exec", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Cmd []string `json:"Cmd"`
		}
		_ = decodeJSONBody(r, &body)
		rec.mu.Lock()
		rec.execCmds = append(rec.execCmds, body.Cmd)
		rec.mu.Unlock()
		_, _ = w.Write([]byte(`{"Id":"exec1"}`))
	})
	mux.HandleFunc("/exec/exec1/start", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(dockerFrame(1, configContent))
	})
	mux.HandleFunc("/exec/exec1/json", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ExitCode":0}`))
	})
	return mux
}

func decodeJSONBody(r *http.Request, out any) error {
	return json.NewDecoder(r.Body).Decode(out)
}

// startRecordingDockerAPI serves the fake Engine API over TCP.
func startRecordingDockerAPI(t *testing.T, configContent string) *recordingDockerAPI {
	t.Helper()
	rec := &recordingDockerAPI{}
	srv := httptest.NewServer(newRecordingDockerMux(rec, configContent))
	t.Cleanup(srv.Close)
	rec.srv = srv
	return rec
}

// startRecordingDockerAPIOnUnixSocket serves the same fake Engine API over a
// real unix socket and returns the socket path. No TCP listener is created,
// so the probe can only reach it by dialing the socket (FP-SW-2).
func startRecordingDockerAPIOnUnixSocket(t *testing.T, socketPath, configContent string) *recordingDockerAPI {
	t.Helper()
	rec := &recordingDockerAPI{}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix %s: %v", socketPath, err)
	}
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: newRecordingDockerMux(rec, configContent)}}
	srv.Start()
	t.Cleanup(srv.Close)
	rec.srv = srv
	return rec
}

// --- FP-SW-1 -----------------------------------------------------------------------

func TestSW1_ProbeReadsCoordinatorConfigFromConfiguredPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	presto := startFakePresto(t)
	docker := startRecordingDockerAPI(t, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-sw1-config-paths"
	const token = "tok-sw1"
	seedPlatform(t, dsn, platformKey, token)

	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: docker.srv.URL,
		ConfigPaths: map[string]string{
			"config": "/opt/presto-server/etc/config.properties",
		},
	})

	// The detected manifest is what "online" means here: Detect() read the
	// coordinator config, saw auth=NONE and passed the connectivity test.
	waitForPlatformStatus(t, dsn, platformKey, "online", 20*time.Second)

	want := []string{"cat", "/opt/presto-server/etc/config.properties"}
	if !docker.sawExec(t, want, 10*time.Second) {
		t.Fatalf("fake Docker API never received %v; saw %v", want, docker.commands())
	}
	for _, cmd := range docker.commands() {
		if len(cmd) == 2 && cmd[1] == "/etc/presto/config.properties" {
			t.Fatalf("probe fell back to the default path despite config_paths: %v", cmd)
		}
	}
}

// --- FP-SW-2 -----------------------------------------------------------------------

func TestSW2_ProbeReachesDockerOverMountedUnixSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	presto := startFakePresto(t)
	// Short temp dir: unix socket paths are limited to ~108 bytes.
	socketDir, err := os.MkdirTemp("", "sw2")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "docker.sock")
	docker := startRecordingDockerAPIOnUnixSocket(t, socketPath, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-sw2-unix-socket"
	const token = "tok-sw2"
	seedPlatform(t, dsn, platformKey, token)

	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL,
		DockerAPIURL: "unix://" + socketPath,
	})

	waitForPlatformStatus(t, dsn, platformKey, "online", 20*time.Second)

	want := []string{"cat", "/etc/presto/config.properties"}
	if !docker.sawExec(t, want, 10*time.Second) {
		t.Fatalf("fake Docker API (unix socket) never received %v; saw %v", want, docker.commands())
	}
	// The Engine API was reached with no TCP listener in play at all.
	if docker.srv.Listener.Addr().Network() != "unix" {
		t.Fatalf("fake Docker API listener is %s, expected unix", docker.srv.Listener.Addr().Network())
	}
}

// --- FP-SW-3 -----------------------------------------------------------------------

// runProbeExpectingExit runs the probe binary with the given config and waits
// for it to exit, returning its exit code and combined output.
func runProbeExpectingExit(t *testing.T, probeBin string, pc probeConfig, timeout time.Duration) (int, string) {
	t.Helper()
	dir := t.TempDir()
	credMount := pc.CredentialsMount
	if credMount == "" {
		credMount = filepath.Join(dir, "credentials")
	}
	if err := os.MkdirAll(credMount, 0o755); err != nil {
		t.Fatalf("mkdir credentials mount: %v", err)
	}
	prestoHostPort := strings.TrimPrefix(pc.PrestoURL, "http://")
	_, prestoPort, err := net.SplitHostPort(prestoHostPort)
	if err != nil {
		t.Fatalf("split presto host port: %v", err)
	}
	cfg := fmt.Sprintf(`
platform_key: %q
gateway_address: %q
bootstrap_address: %q
bootstrap_token: %q
coordinator_service: "127.0.0.1"
worker_service: "127.0.0.1"
coordinator_port: %s
docker_api_base_url: %q
credentials_mount: %q
state_dir: %q
write_enabled: false
`,
		pc.PlatformKey, pc.GatewayAddr, pc.BootstrapAddr, pc.BootstrapToken,
		prestoPort, pc.DockerAPIURL, credMount, filepath.Join(dir, "state"))
	cfgPath := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write probe config: %v", err)
	}

	cmd := exec.Command(probeBin)
	cmd.Env = append(os.Environ(), "PROBE_CONFIG="+cfgPath)
	cmd.Dir = pc.WorkDir
	var out strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start probe: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("probe did not exit within %s; output:\n%s", timeout, out.String())
	}
	return cmd.ProcessState.ExitCode(), out.String()
}

func TestSW3_ProbeFailsFastOnBadDockerAPIBaseURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)
	presto := startFakePresto(t)

	const platformKey = "presto-sw3-failfast"
	const token = "tok-sw3"
	seedPlatform(t, dsn, platformKey, token)

	// A short-path temp dir for socket-shaped fixtures.
	fixtureDir, err := os.MkdirTemp("", "sw3")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(fixtureDir) })

	missingSocket := filepath.Join(fixtureDir, "absent.sock")
	regularFile := filepath.Join(fixtureDir, "not-a-socket")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A REAL, listening socket in a directory the probe will be started in,
	// referenced relatively -- it Stats cleanly, so only an absoluteness
	// check rejects it (DW2).
	relDir, err := os.MkdirTemp("", "sw3rel")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(relDir) })
	startRecordingDockerAPIOnUnixSocket(t, filepath.Join(relDir, "docker.sock"), "http-server.authentication.type=NONE\n")

	cases := []struct {
		name    string
		baseURL string
		workDir string
		wantMsg string
	}{
		{
			name:    "missing socket path",
			baseURL: "unix://" + missingSocket,
			wantMsg: "dockerapi: docker socket " + missingSocket + " not found (mount /var/run/docker.sock into the probe container)",
		},
		{
			name:    "path is a regular file",
			baseURL: "unix://" + regularFile,
			wantMsg: "dockerapi: " + regularFile + " is not a unix socket",
		},
		{
			name:    "existing socket referenced relatively",
			baseURL: "unix://docker.sock",
			workDir: relDir,
			wantMsg: `dockerapi: docker socket path "docker.sock" must be absolute (use unix:///var/run/docker.sock)`,
		},
		{
			name:    "unsupported scheme",
			baseURL: "tcp://docker:2375",
			wantMsg: `dockerapi: unsupported docker_api_base_url scheme "tcp://docker:2375" (want unix://, http:// or https://)`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, output := runProbeExpectingExit(t, probeBin, probeConfig{
				PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
				BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: tc.baseURL,
				WorkDir: tc.workDir,
			}, 30*time.Second)
			if code == 0 {
				t.Fatalf("expected a non-zero exit, got 0; output:\n%s", output)
			}
			if !strings.Contains(output, tc.wantMsg) {
				t.Fatalf("expected %q on stderr, got:\n%s", tc.wantMsg, output)
			}
		})
	}

	// Token preservation, asserted positively: the bootstrap token is
	// single-use, so a probe that now enrolls with the SAME token proves no
	// failed run above ever reached Enroll.
	if bootstrapTokenConsumed(t, dsn, platformKey) {
		t.Fatalf("a failed-fast run consumed the single-use bootstrap token")
	}
	socketDir, err := os.MkdirTemp("", "sw3ok")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socketPath := filepath.Join(socketDir, "docker.sock")
	startRecordingDockerAPIOnUnixSocket(t, socketPath, "http-server.authentication.type=NONE\n")

	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: "unix://" + socketPath,
	})
	waitForPlatformStatus(t, dsn, platformKey, "online", 20*time.Second)
	if !bootstrapTokenConsumed(t, dsn, platformKey) {
		t.Fatalf("expected the corrected run to consume the still-unspent token")
	}
}
