// Package m2_probe_link is M2's cross-service functional tier (design.md
// Section 11: "the top-level tests/ tree holds only the cross-service
// tiers"; Section 14.3 checkpoint F8 "Registration flow v3"). Unlike the
// per-package Go tests co-located with each service (which mock/fake the
// *other* service's internals since Go's internal-package visibility
// rules don't allow a single test file to import both
// probe/internal/... and services/probe-gateway/internal/... at once --
// see impl-progress.md), this test runs the real compiled `probe` and
// `probe-gateway` binaries as OS subprocesses talking to each other over
// real mTLS, against a real ephemeral Postgres (migrated with the exact
// M1 alembic migration) and mocked platform-side externals (a fake
// Presto REST server + fake Docker Engine API, both httptest, per
// Section 14.1's isolation bar -- "no test in these two tiers may
// require network access or a live platform").
//
// Covers F8's core: registration flow steps 1-8 end to end, incl. 5a
// (NONE -> ONLINE) and 5b (PASSWORD, no credentials -> PENDING_CREDENTIALS),
// bootstrap token single-use, and (via the real gwserver heartbeat
// reaper) offline-after-timeout.
package m2_probe_link

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	tcwait "github.com/testcontainers/testcontainers-go/wait"
)

// --- shared ephemeral infra (built once for the whole test binary run,
// via TestMain -- a real Postgres container + two `go build`s are too
// expensive to redo per test, and per-test t.Cleanup() would tear the
// container down after the first test finishes, breaking every test
// after it) ---------------------------------------------------------------

var (
	sharedDSN        string
	sharedProbeBin   string
	sharedGatewayBin string
)

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}

	root, err := filepath.Abs(findRepoRoot())
	if err != nil {
		fmt.Println("repoRoot:", err)
		os.Exit(1)
	}
	ctx := context.Background()

	pgContainer, err := postgres.Run(ctx, "postgres:16-alpine",
		postgres.WithDatabase("rca_agent"),
		postgres.WithUsername("rca_agent"),
		postgres.WithPassword("rca_agent"),
		testcontainers.WithWaitStrategy(
			tcwait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(60*time.Second),
		),
	)
	if err != nil {
		fmt.Println("start postgres:", err)
		os.Exit(1)
	}
	defer func() { _ = pgContainer.Terminate(ctx) }()

	dsn, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		fmt.Println("connection string:", err)
		os.Exit(1)
	}
	if err := runAlembicMigrationErr(root, dsn); err != nil {
		fmt.Println("alembic migration:", err)
		os.Exit(1)
	}

	tmpDir, err := os.MkdirTemp("", "m2-probe-link-*")
	if err != nil {
		fmt.Println("mkdir temp:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	probeBin := filepath.Join(tmpDir, "probe")
	gatewayBin := filepath.Join(tmpDir, "probe-gateway")
	if err := buildBinaryErr(root, "./probe/cmd/probe", probeBin); err != nil {
		fmt.Println("build probe:", err)
		os.Exit(1)
	}
	if err := buildBinaryErr(root, "./services/probe-gateway/cmd/probe-gateway", gatewayBin); err != nil {
		fmt.Println("build probe-gateway:", err)
		os.Exit(1)
	}

	sharedDSN, sharedProbeBin, sharedGatewayBin = dsn, probeBin, gatewayBin

	os.Exit(m.Run())
}

func findRepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	// .../tests/functional/m2_probe_link/registration_test.go -> repo root
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func setupSharedInfra(t *testing.T) (dsn, probeBin, gatewayBin string) {
	t.Helper()
	if sharedDSN == "" {
		t.Skip("shared infra not initialized (running with -short, or TestMain setup failed)")
	}
	return sharedDSN, sharedProbeBin, sharedGatewayBin
}

func runAlembicMigrationErr(root, dsn string) error {
	rcaCommonDir := filepath.Join(root, "libs", "py", "rca_common")
	pythonBin := filepath.Join(rcaCommonDir, ".venv", "bin", "python")
	alembicDSN := "postgresql+psycopg2://" + dsn[len("postgres://"):]

	cmd := exec.Command(pythonBin, "-m", "alembic", "upgrade", "head")
	cmd.Dir = rcaCommonDir
	cmd.Env = append(os.Environ(), "RCA_PG_DSN="+alembicDSN)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

func buildBinaryErr(root, pkg, outPath string) error {
	cmd := exec.Command("go", "build", "-o", outPath, pkg)
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w\n%s", err, out)
	}
	return nil
}

// --- fake platform-side externals (Presto REST + Docker Engine API) -----------------

// startFakePresto serves the minimal /v1/info + /v1/statement surface
// PlatformAdapter.Detect()'s connectivity test needs.
func startFakePresto(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
	})
	mux.HandleFunc("/v1/statement", func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"columns": []map[string]string{{"name": "node_id"}},
			"data":    [][]any{{"n1"}},
			"stats":   map[string]string{"state": "FINISHED"},
		}
		enc, _ := json.Marshal(resp)
		w.Write(enc)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// startFakeDockerAPI serves just enough of the Docker Engine API for
// dockerenv.ReadConfig (list a task, exec `cat config.properties`).
func startFakeDockerAPI(t *testing.T, configContent string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/tasks", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"ID":"t1","DesiredState":"running","Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}}]`))
	})
	mux.HandleFunc("/containers/c1/exec", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"Id":"exec1"}`))
	})
	mux.HandleFunc("/exec/exec1/start", func(w http.ResponseWriter, r *http.Request) {
		w.Write(dockerFrame(1, configContent))
	})
	mux.HandleFunc("/exec/exec1/json", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"ExitCode":0}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func dockerFrame(streamType byte, payload string) []byte {
	b := make([]byte, 8+len(payload))
	b[0] = streamType
	l := len(payload)
	b[4], b[5], b[6], b[7] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
	copy(b[8:], payload)
	return b
}

// --- probe-gateway subprocess ---------------------------------------------------

type gatewayProcess struct {
	cmd           *exec.Cmd
	sessionAddr   string
	bootstrapAddr string
	internalAddr  string // HTTP POST /internal/v1/execute (empty if disabled)
	stateDir      string
}

// gatewayStartOpts customizes startGatewaySubprocess. Zero value preserves
// historical F8 registration-only behavior (random pub key, no internal
// HTTP listener). Write-path tests supply a real signing public-key sidecar
// and EnableInternalHTTP so temporal-worker-shaped callers can POST writes.
type gatewayStartOpts struct {
	// SigningPubKeyPath is the control-plane `{key}.pub` sidecar (base64
	// raw ed25519 public key). Empty → generate a random 32-byte key so
	// registration still works for non-write tests.
	SigningPubKeyPath string
	// EnableInternalHTTP binds POST /internal/v1/execute (design.md §3.2 / M5 write wire).
	EnableInternalHTTP bool
}

func startGatewaySubprocess(t *testing.T, gatewayBin, dsn string) *gatewayProcess {
	return startGatewaySubprocessOpts(t, gatewayBin, dsn, gatewayStartOpts{})
}

func startGatewaySubprocessOpts(t *testing.T, gatewayBin, dsn string, opts gatewayStartOpts) *gatewayProcess {
	t.Helper()
	dir := t.TempDir()

	sessionAddr := freePort(t)
	bootstrapAddr := freePort(t)
	var internalAddr string
	if opts.EnableInternalHTTP {
		internalAddr = freePort(t)
	}

	pubKeyPath := opts.SigningPubKeyPath
	if pubKeyPath == "" {
		pubKeyPath = filepath.Join(dir, "signing.key.pub")
		pub := make([]byte, 32)
		_, _ = rand.Read(pub)
		if err := os.WriteFile(pubKeyPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0o644); err != nil {
			t.Fatalf("write signing pub key: %v", err)
		}
	}

	internalLine := ""
	if opts.EnableInternalHTTP {
		internalLine = fmt.Sprintf("internal_listen_addr: %q\n", internalAddr)
	} else {
		// Empty disables the listener (config defaults would otherwise bind :8080).
		internalLine = "internal_listen_addr: \"\"\n"
	}

	cfg := fmt.Sprintf(`
session_listen_addr: %q
bootstrap_listen_addr: %q
postgres_dsn: %q
bootstrap_ca_cert_path: %q
bootstrap_ca_key_path: %q
signing_public_key_path: %q
gateway_replica: functest-replica
heartbeat_timeout: 3s
heartbeat_check_interval: 1s
signing_key_poll_interval: 1h
server_cert_sans: ["127.0.0.1"]
%s
`,
		sessionAddr, bootstrapAddr, dsn,
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		pubKeyPath,
		internalLine,
	)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write gateway config: %v", err)
	}

	cmd := exec.Command(gatewayBin)
	cmd.Env = append(os.Environ(), "PROBE_GATEWAY_CONFIG="+cfgPath)
	logFile, err := os.Create(filepath.Join(dir, "gateway.log"))
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start probe-gateway: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			if content, err := os.ReadFile(filepath.Join(dir, "gateway.log")); err == nil {
				t.Logf("probe-gateway log:\n%s", content)
			}
		}
	})

	waitForTCP(t, sessionAddr)
	waitForTCP(t, bootstrapAddr)
	if opts.EnableInternalHTTP {
		waitForTCP(t, internalAddr)
	}

	return &gatewayProcess{
		cmd: cmd, sessionAddr: sessionAddr, bootstrapAddr: bootstrapAddr,
		internalAddr: internalAddr, stateDir: dir,
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()
	return addr
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s after 5s", addr)
}

// --- probe subprocess -------------------------------------------------------------

type probeConfig struct {
	PlatformKey      string
	GatewayAddr      string
	BootstrapAddr    string
	BootstrapToken   string
	PrestoURL        string
	DockerAPIURL     string
	CredentialsMount string
	// WriteEnabled gates the probe-side write channel (design.md §9.3 /
	// write_enabled deployment flag). Default false matches production-safe
	// registration tests; M5 write-path tests set true.
	WriteEnabled bool
}

func startProbeSubprocess(t *testing.T, probeBin string, pc probeConfig) *exec.Cmd {
	t.Helper()
	dir := t.TempDir()
	if pc.CredentialsMount == "" {
		pc.CredentialsMount = filepath.Join(dir, "credentials")
	}
	if err := os.MkdirAll(pc.CredentialsMount, 0o755); err != nil {
		t.Fatalf("mkdir credentials mount: %v", err)
	}

	prestoHostPort := pc.PrestoURL[len("http://"):]
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
write_enabled: %t
`,
		pc.PlatformKey, pc.GatewayAddr, pc.BootstrapAddr, pc.BootstrapToken,
		prestoPort, pc.DockerAPIURL, pc.CredentialsMount, filepath.Join(dir, "state"),
		pc.WriteEnabled,
	)
	cfgPath := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write probe config: %v", err)
	}

	cmd := exec.Command(probeBin)
	cmd.Env = append(os.Environ(), "PROBE_CONFIG="+cfgPath)
	logFile, err := os.Create(filepath.Join(dir, "probe.log"))
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start probe: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
		if t.Failed() {
			if content, err := os.ReadFile(filepath.Join(dir, "probe.log")); err == nil {
				t.Logf("probe log:\n%s", content)
			}
		}
	})
	return cmd
}

// --- Postgres seeding/assertions ---------------------------------------------------

func seedPlatform(t *testing.T, dsn, platformKey, token string) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	cfgJSON, _ := json.Marshal(map[string]any{"bootstrap_token": token, "bootstrap_token_consumed": false})
	_, err = db.Exec(`INSERT INTO platforms (platform_key, platform_type, deployment, status, config) VALUES ($1, 'presto', 'swarm', 'created', $2::jsonb)`,
		platformKey, string(cfgJSON))
	if err != nil {
		t.Fatalf("seed platform: %v", err)
	}
}

func waitForPlatformStatus(t *testing.T, dsn, platformKey, want string, timeout time.Duration) {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		row := db.QueryRow(`SELECT status FROM platforms WHERE platform_key = $1`, platformKey)
		if err := row.Scan(&last); err == nil && last == want {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("platform %s status never reached %q (last seen: %q)", platformKey, want, last)
}

func bootstrapTokenConsumed(t *testing.T, dsn, platformKey string) bool {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var cfgJSON []byte
	row := db.QueryRow(`SELECT config FROM platforms WHERE platform_key = $1`, platformKey)
	if err := row.Scan(&cfgJSON); err != nil {
		t.Fatalf("query config: %v", err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	consumed, _ := cfg["bootstrap_token_consumed"].(bool)
	return consumed
}

func countProbesForPlatform(t *testing.T, dsn, platformKey string) int {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var count int
	row := db.QueryRow(`SELECT count(*) FROM probes WHERE platform_key = $1`, platformKey)
	if err := row.Scan(&count); err != nil {
		t.Fatalf("count probes: %v", err)
	}
	return count
}

func probeStatus(t *testing.T, dsn, platformKey string) string {
	t.Helper()
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()

	var status string
	row := db.QueryRow(`SELECT status FROM probes WHERE platform_key = $1 ORDER BY registered_at DESC LIMIT 1`, platformKey)
	if err := row.Scan(&status); err != nil {
		t.Fatalf("query probe status: %v", err)
	}
	return status
}

// --- F8: registration flow v3 ------------------------------------------------------

func TestF8_RegistrationFlow_NoneAuth_BecomesOnline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	presto := startFakePresto(t)
	docker := startFakeDockerAPI(t, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-f8-none"
	const token = "tok-f8-none"
	seedPlatform(t, dsn, platformKey, token)

	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: docker.URL,
	})

	// Registration flow v3 steps 3-5a: bootstrap -> mTLS Session ->
	// auth=NONE -> connectivity test passes -> platform ONLINE.
	waitForPlatformStatus(t, dsn, platformKey, "online", 15*time.Second)

	// Bootstrap token is single-use (F8 checkpoint).
	if !bootstrapTokenConsumed(t, dsn, platformKey) {
		t.Fatalf("expected bootstrap token to be marked consumed")
	}

	// A probes row was created for this platform.
	if countProbesForPlatform(t, dsn, platformKey) != 1 {
		t.Fatalf("expected exactly one probe row for %s", platformKey)
	}
}

func TestF8_RegistrationFlow_PasswordAuthNoCredentials_BecomesPendingCredentials(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	presto := startFakePresto(t)
	docker := startFakeDockerAPI(t, "http-server.authentication.type=PASSWORD\n")

	const platformKey = "presto-f8-pending"
	const token = "tok-f8-pending"
	seedPlatform(t, dsn, platformKey, token)

	// No credentials mounted (empty dir) -> registration flow v3 step 5b
	// "Absent -> report PENDING_CREDENTIALS + missing items".
	startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: docker.URL,
	})

	waitForPlatformStatus(t, dsn, platformKey, "pending_credentials", 15*time.Second)
}

func TestF8_BootstrapTokenSingleUse_SecondEnrollWithSameTokenFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	presto := startFakePresto(t)
	docker := startFakeDockerAPI(t, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-f8-singleuse"
	const token = "tok-f8-singleuse"
	seedPlatform(t, dsn, platformKey, token)

	first := startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: docker.URL,
	})
	waitForPlatformStatus(t, dsn, platformKey, "online", 15*time.Second)
	_ = first.Process.Kill()
	_, _ = first.Process.Wait()

	// A second probe attempting to enroll with the SAME (already-consumed)
	// token must never reach a persisted-identity state; it just keeps
	// retrying (reconnect loop) and never gets a probes row using a fresh
	// enrollment. We assert this indirectly: exactly one probe row exists
	// for the platform even after a second enrollment attempt with a
	// distinct state dir (forcing a fresh Enroll call).
	second := startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: docker.URL,
	})
	defer func() {
		_ = second.Process.Kill()
		_, _ = second.Process.Wait()
	}()

	time.Sleep(2 * time.Second) // let it retry/fail a couple of times
	if countProbesForPlatform(t, dsn, platformKey) != 1 {
		t.Fatalf("expected the second enrollment (reused token) to never succeed")
	}
}

func TestF8_HeartbeatTimeout_MarksProbeOffline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, probeBin, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn) // heartbeat_timeout: 3s, check_interval: 1s

	presto := startFakePresto(t)
	docker := startFakeDockerAPI(t, "http-server.authentication.type=NONE\n")

	const platformKey = "presto-f8-heartbeat"
	const token = "tok-f8-heartbeat"
	seedPlatform(t, dsn, platformKey, token)

	proc := startProbeSubprocess(t, probeBin, probeConfig{
		PlatformKey: platformKey, GatewayAddr: gw.sessionAddr, BootstrapAddr: gw.bootstrapAddr,
		BootstrapToken: token, PrestoURL: presto.URL, DockerAPIURL: docker.URL,
	})
	waitForPlatformStatus(t, dsn, platformKey, "online", 15*time.Second)

	// Kill the probe (no more heartbeats) and wait past the gateway's
	// configured heartbeat_timeout for the reaper to mark it offline
	// (design.md Appendix A: "the gateway marks a probe offline after 60s
	// without a heartbeat" -- parametrized down to 3s for this test).
	_ = proc.Process.Kill()
	_, _ = proc.Process.Wait()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if probeStatus(t, dsn, platformKey) == "offline" {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("expected probe to be marked offline after the heartbeat timeout")
}
