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
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
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
		postgres.WithDatabase("dbagent"),
		postgres.WithUsername("dbagent"),
		postgres.WithPassword("dbagent"),
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

// rcaCommonPythonBin finds a Python that has rca_common (and its alembic
// dependency) installed. Which venv exists depends on which CI job is
// running this package: `unit-go` creates libs/py/rca_common/.venv
// specifically for this migration; `functional` instead installs
// rca_common editable into a shared services/worker/.venv alongside
// worker/gateway/dashboard-api. Neither job is wrong -- this just needs to
// find whichever one the caller set up, rather than assuming the first.
// Shared with write_dispatch_test.go's signing helpers, which need the same
// rca_common-importable interpreter for an unrelated reason (D14 signing).
func rcaCommonPythonBin(root string) (string, error) {
	candidates := []string{
		filepath.Join(root, "libs", "py", "rca_common", ".venv", "bin", "python"),
		filepath.Join(root, "services", "worker", ".venv", "bin", "python"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	if p, err := exec.LookPath("python3"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf(
		"no python with rca_common installed found (tried %v, and python3 on PATH)",
		candidates,
	)
}

func runAlembicMigrationErr(root, dsn string) error {
	rcaCommonDir := filepath.Join(root, "libs", "py", "rca_common")
	pythonBin, err := rcaCommonPythonBin(root)
	if err != nil {
		return err
	}
	alembicDSN := "postgresql+psycopg2://" + dsn[len("postgres://"):]

	cmd := exec.Command(pythonBin, "-m", "alembic", "upgrade", "head")
	cmd.Dir = rcaCommonDir
	cmd.Env = append(os.Environ(), "DBAGENT_PG_DSN="+alembicDSN)
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
	mux.HandleFunc("/v1/cluster", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"runningQueries":0,"queuedQueries":0,"blockedQueries":0,"activeWorkers":1,"totalMemoryBytes":1000,"reservedMemoryBytes":100}`))
	})
	mux.HandleFunc("/v1/node", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
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
	// SigningKeyPollInterval overrides signing_key_poll_interval (empty → "1h").
	SigningKeyPollInterval string
}

func startGatewaySubprocess(t *testing.T, gatewayBin, dsn string) *gatewayProcess {
	return startGatewaySubprocessOpts(t, gatewayBin, dsn, gatewayStartOpts{})
}

// maxPortSelectionAttempts caps the port-SELECTION retry in
// startGatewaySubprocessOpts. Five is a working cap, not a bar: one collision
// is already rare, and a host that collides five times running has a different
// problem than this harness can retry around.
const maxPortSelectionAttempts = 5

// startGatewaySubprocessOpts starts the real probe-gateway child on freshly
// reserved loopback addresses and returns once every configured listener
// answers.
//
// The ONLY thing retried here is port SELECTION: if the child cannot serve
// because one of the addresses this harness picked was taken by somebody else
// between release and bind, the harness reserves new addresses and starts a new
// child. Every other child failure fails the test on the first attempt, and
// nothing at all is retried once this function has returned -- a test that
// fails against a gateway that came up is a real failure (design/fix.md).
func startGatewaySubprocessOpts(t *testing.T, gatewayBin, dsn string, opts gatewayStartOpts) *gatewayProcess {
	t.Helper()
	attempts := 0
	gw, err := startGatewayWithPortRetry(maxPortSelectionAttempts, func() (*gatewayProcess, error) {
		attempts++
		return tryStartGateway(t, gatewayBin, dsn, opts, attempts)
	})
	if err != nil {
		t.Fatalf("start probe-gateway (%d attempt(s)): %v", attempts, err)
	}
	return gw
}

// startGatewayWithPortRetry calls start() until it returns a gateway, retrying
// ONLY a *portCollisionError and at most maxAttempts times overall. A failure
// of any other kind is handed straight back to the caller, unretried, as is the
// last collision once the cap is reached. It takes no *testing.T so that the
// retry policy itself is directly testable.
func startGatewayWithPortRetry(maxAttempts int, start func() (*gatewayProcess, error)) (*gatewayProcess, error) {
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var gw *gatewayProcess
		gw, err = start()
		if err == nil {
			return gw, nil
		}
		var collision *portCollisionError
		if !errors.As(err, &collision) {
			return nil, err
		}
	}
	return nil, err
}

// portSelectionHook, when non-nil, is called with the addresses an attempt
// reserved, immediately after they are released and before the child is
// started. Only TestStartGateway_RetriesWhenAReservedPortIsStolen sets it, to
// occupy one of them and prove the selection retry.
var portSelectionHook func(attempt int, addrs []string)

// tryStartGateway is one attempt: reserve, configure, start, wait for the
// listeners. It returns an error (never t.Fatalf) for anything the child does,
// so the caller can tell a port-selection collision from a real failure.
func tryStartGateway(t *testing.T, gatewayBin, dsn string, opts gatewayStartOpts, attempt int) (*gatewayProcess, error) {
	t.Helper()
	dir := t.TempDir()

	nPorts := 2
	if opts.EnableInternalHTTP {
		nPorts = 3
	}
	reserved := reserveGatewayPorts(t, nPorts)
	sessionAddr := reserved.addrs[0]
	bootstrapAddr := reserved.addrs[1]
	var internalAddr string
	if opts.EnableInternalHTTP {
		internalAddr = reserved.addrs[2]
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
	pollInterval := opts.SigningKeyPollInterval
	if pollInterval == "" {
		pollInterval = "1h"
	}

	cfg := fmt.Sprintf(`
session_listen_addr: %q
bootstrap_listen_addr: %q
postgres_dsn: %q
max_db_conns: 10
bootstrap_ca_cert_path: %q
bootstrap_ca_key_path: %q
signing_public_key_path: %q
gateway_replica: functest-replica
heartbeat_timeout: 3s
heartbeat_check_interval: 1s
signing_key_poll_interval: %s
server_cert_sans: ["127.0.0.1"]
%s
`,
		sessionAddr, bootstrapAddr, dsn,
		filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		pubKeyPath,
		pollInterval,
		internalLine,
	)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write gateway config: %v", err)
	}

	cmd := exec.Command(gatewayBin)
	cmd.Env = append(os.Environ(), "PROBE_GATEWAY_CONFIG="+cfgPath)
	logPath := filepath.Join(dir, "gateway.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create log file: %v", err)
	}
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	// Hold the reservations until the last possible moment: the child is the
	// next thing that binds these addresses.
	reserved.release()
	if portSelectionHook != nil {
		portSelectionHook(attempt, reserved.addrs)
	}

	startErr := cmd.Start()
	// The child has its own dup of this descriptor; the parent's copy would
	// otherwise leak once per attempt.
	_ = logFile.Close()
	if startErr != nil {
		return nil, fmt.Errorf("start probe-gateway: %w", startErr)
	}

	waitAddrs := []string{sessionAddr, bootstrapAddr}
	if opts.EnableInternalHTTP {
		waitAddrs = append(waitAddrs, internalAddr)
	}
	for _, addr := range waitAddrs {
		if err := waitForTCPErr(addr); err != nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
			gatewayLog := readGatewayLog(logPath)
			if collided := collidedReservedAddr(gatewayLog, reserved.addrs); collided != "" {
				return nil, &portCollisionError{addr: collided, gatewayLog: gatewayLog, err: err}
			}
			return nil, fmt.Errorf("%w\nprobe-gateway log:\n%s", err, gatewayLog)
		}
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		if t.Failed() {
			if content, err := os.ReadFile(logPath); err == nil {
				t.Logf("probe-gateway log:\n%s", content)
			}
		}
	})

	return &gatewayProcess{
		cmd: cmd, sessionAddr: sessionAddr, bootstrapAddr: bootstrapAddr,
		internalAddr: internalAddr, stateDir: dir,
	}, nil
}

// --- gateway port reservation ------------------------------------------------------

// reservedGatewayPorts is a set of loopback addresses held open at the same
// time. Holding is the whole point: a picker that opens a listener, records its
// address and closes it before picking the next one can be handed the SAME port
// twice by the kernel (7 duplicate triples per 20 000, design/fix.md), and the
// probe-gateway child binds session/bootstrap/internal from overlapping
// goroutines -- so a duplicate is a certain `bind: address already in use`.
type reservedGatewayPorts struct {
	addrs     []string
	listeners []net.Listener
}

// release closes every held listener. Call it immediately before starting the
// child that binds these addresses; the remaining window between release and
// bind is the TOCTOU the selection retry above covers.
func (r *reservedGatewayPorts) release() {
	for _, lis := range r.listeners {
		_ = lis.Close()
	}
	r.listeners = nil
}

// reserveGatewayPorts picks n distinct free loopback addresses and keeps all n
// bound until release() is called.
func reserveGatewayPorts(t *testing.T, n int) *reservedGatewayPorts {
	t.Helper()
	res := &reservedGatewayPorts{}
	for i := 0; i < n; i++ {
		lis, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			res.release()
			t.Fatalf("reserve loopback port %d of %d: %v", i+1, n, err)
		}
		res.listeners = append(res.listeners, lis)
		res.addrs = append(res.addrs, lis.Addr().String())
	}
	return res
}

// portCollisionError reports that the child could not serve because one of the
// addresses THIS harness reserved was already bound by something else: a port
// selection failure, and the only condition startGatewaySubprocessOpts retries.
// It is built only from the child's own `bind: address already in use` line
// naming a reserved address, so no other gateway failure can be mistaken for it.
type portCollisionError struct {
	addr       string
	gatewayLog string
	err        error
}

func (e *portCollisionError) Error() string {
	return fmt.Sprintf("probe-gateway could not bind reserved %s (address already in use): %v\nprobe-gateway log:\n%s",
		e.addr, e.err, e.gatewayLog)
}

func (e *portCollisionError) Unwrap() error { return e.err }

// collidedReservedAddr returns the first reserved address the gateway log
// reports as already bound, or "" if the log shows no such failure. A bind
// failure on an address this harness did not reserve, and any other failure at
// all, return "" -- they are not selection failures and must not be retried.
func collidedReservedAddr(gatewayLog string, reserved []string) string {
	for _, addr := range reserved {
		if strings.Contains(gatewayLog, addr+": bind: address already in use") {
			return addr
		}
	}
	return ""
}

func readGatewayLog(path string) string {
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(gateway log %s unreadable: %v)", path, err)
	}
	return string(content)
}

func waitForTCPErr(addr string) error {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("nothing listening on %s after 5s", addr)
}

// --- port selection regression tests (design/fix.md, CI 35372449098) ---------------

// TestReserveGatewayPorts_SimultaneouslyBindable pins what this harness needs
// from its port picker: the addresses handed to one probe-gateway child are
// distinct, and all of them are bindable at the same instant -- which is what
// the child does with them, from overlapping goroutines. Against the
// listen-close-reuse picker this package used before design/fix.md, the loop
// reports the same address twice (7 triples per 20 000 measured) and the second
// bind of that address fails with `address already in use`: the CI signature.
func TestReserveGatewayPorts_SimultaneouslyBindable(t *testing.T) {
	const trials = 20000
	for trial := 0; trial < trials; trial++ {
		res := reserveGatewayPorts(t, 3)
		addrs := append([]string(nil), res.addrs...)

		seen := make(map[string]int, len(addrs))
		for i, addr := range addrs {
			if prev, dup := seen[addr]; dup {
				res.release()
				t.Fatalf("trial %d: reserved %s for listener %d and listener %d at once (addrs %v)",
					trial, addr, prev, i, addrs)
			}
			seen[addr] = i
		}

		// The child binds all three once the harness lets go; do the same.
		res.release()
		held := make([]net.Listener, 0, len(addrs))
		for _, addr := range addrs {
			lis, err := net.Listen("tcp", addr)
			if err != nil {
				for _, h := range held {
					_ = h.Close()
				}
				t.Fatalf("trial %d: reserved addrs %v are not simultaneously bindable: %v", trial, addrs, err)
			}
			held = append(held, lis)
		}
		for _, h := range held {
			_ = h.Close()
		}
	}
}

// TestStartGatewayWithPortRetry_RetriesPortSelectionOnly pins the retry policy:
// a port-selection collision is retried up to the cap, and nothing else ever is.
func TestStartGatewayWithPortRetry_RetriesPortSelectionOnly(t *testing.T) {
	collision := func(addr string) error {
		return &portCollisionError{
			addr:       addr,
			gatewayLog: "probe-gateway: listen (bootstrap) " + addr + ": listen tcp " + addr + ": bind: address already in use\n",
			err:        fmt.Errorf("nothing listening on %s after 5s", addr),
		}
	}
	ready := &gatewayProcess{sessionAddr: "127.0.0.1:1", bootstrapAddr: "127.0.0.1:2"}

	t.Run("a collision is retried until a child comes up", func(t *testing.T) {
		attempts := 0
		gw, err := startGatewayWithPortRetry(maxPortSelectionAttempts, func() (*gatewayProcess, error) {
			attempts++
			if attempts < 3 {
				return nil, collision("127.0.0.1:41515")
			}
			return ready, nil
		})
		if err != nil {
			t.Fatalf("a recoverable port collision was not retried: %v", err)
		}
		if gw != ready {
			t.Fatalf("returned %+v, want the gateway the third attempt started", gw)
		}
		if attempts != 3 {
			t.Fatalf("attempts = %d, want 3", attempts)
		}
	})

	t.Run("a non-collision failure is never retried", func(t *testing.T) {
		boom := errors.New("probe-gateway: open registry: dial tcp 127.0.0.1:1: connect: connection refused")
		attempts := 0
		gw, err := startGatewayWithPortRetry(maxPortSelectionAttempts, func() (*gatewayProcess, error) {
			attempts++
			return nil, boom
		})
		if gw != nil {
			t.Fatalf("returned a gateway %+v for a failed start", gw)
		}
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, want the child's own failure", err)
		}
		if attempts != 1 {
			t.Fatalf("a failure that is not a port collision was retried: attempts = %d, want 1", attempts)
		}
	})

	t.Run("a child that came up is never restarted", func(t *testing.T) {
		attempts := 0
		gw, err := startGatewayWithPortRetry(maxPortSelectionAttempts, func() (*gatewayProcess, error) {
			attempts++
			return ready, nil
		})
		if err != nil || gw != ready {
			t.Fatalf("gw, err = %+v, %v; want the started gateway and no error", gw, err)
		}
		if attempts != 1 {
			t.Fatalf("attempts = %d, want 1: readiness must end the retry loop", attempts)
		}
	})

	t.Run("collisions stop at the cap", func(t *testing.T) {
		attempts := 0
		_, err := startGatewayWithPortRetry(maxPortSelectionAttempts, func() (*gatewayProcess, error) {
			attempts++
			return nil, collision("127.0.0.1:41515")
		})
		if attempts != maxPortSelectionAttempts {
			t.Fatalf("attempts = %d, want the cap %d", attempts, maxPortSelectionAttempts)
		}
		var collided *portCollisionError
		if !errors.As(err, &collided) {
			t.Fatalf("err = %v, want the last collision reported to the caller", err)
		}
	})
}

// TestCollidedReservedAddr_OnlyOurOwnAddresses pins the classifier that decides
// what counts as a selection collision. Anything but "a reserved address of
// ours is already bound" must read as a real failure.
func TestCollidedReservedAddr_OnlyOurOwnAddresses(t *testing.T) {
	reserved := []string{"127.0.0.1:41000", "127.0.0.1:41515", "127.0.0.1:34525"}
	cases := []struct {
		name       string
		gatewayLog string
		want       string
	}{
		{
			name: "bootstrap address taken (the CI 35372449098 signature)",
			gatewayLog: "probe-gateway: bootstrap CA fingerprint (bootstrap_ca_pin): sha256:x\n" +
				"probe-gateway: internal ExecuteTool HTTP listener on 127.0.0.1:34525\n" +
				"probe-gateway: listen (bootstrap) 127.0.0.1:41515: listen tcp 127.0.0.1:41515: bind: address already in use\n",
			want: "127.0.0.1:41515",
		},
		{
			name:       "session address taken",
			gatewayLog: "probe-gateway: listen (session) 127.0.0.1:41000: listen tcp 127.0.0.1:41000: bind: address already in use\n",
			want:       "127.0.0.1:41000",
		},
		{
			name:       "internal dispatch address taken",
			gatewayLog: "probe-gateway: internal dispatch listener stopped: listen tcp 127.0.0.1:34525: bind: address already in use\n",
			want:       "127.0.0.1:34525",
		},
		{
			name:       "a bind failure on an address we did not reserve is not ours",
			gatewayLog: "probe-gateway: listen (session) 127.0.0.1:39999: listen tcp 127.0.0.1:39999: bind: address already in use\n",
			want:       "",
		},
		{
			name:       "a failure that is not a bind failure is never a selection failure",
			gatewayLog: "probe-gateway: open registry: dial tcp 127.0.0.1:41515: connect: connection refused\n",
			want:       "",
		},
		{
			name:       "an empty log proves nothing",
			gatewayLog: "",
			want:       "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := collidedReservedAddr(tc.gatewayLog, reserved); got != tc.want {
				t.Fatalf("collidedReservedAddr = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestStartGateway_NonPortFailureFailsWithoutRetry drives the real starter
// against a stand-in binary that dies for a reason having nothing to do with
// port selection. The harness must report that failure after exactly one
// attempt, carrying the child's own log, instead of picking new ports.
func TestStartGateway_NonPortFailureFailsWithoutRetry(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fake-probe-gateway")
	script := "#!/bin/sh\n" +
		"echo 'probe-gateway: open registry: dial tcp 127.0.0.1:1: connect: connection refused' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatalf("write stand-in gateway: %v", err)
	}

	attempts := 0
	gw, err := startGatewayWithPortRetry(maxPortSelectionAttempts, func() (*gatewayProcess, error) {
		attempts++
		return tryStartGateway(t, bin, "postgres://unused:unused@127.0.0.1:1/unused?sslmode=disable", gatewayStartOpts{}, attempts)
	})
	if err == nil {
		t.Fatalf("starter returned %+v for a child that died", gw)
	}
	if attempts != 1 {
		t.Fatalf("a non-EADDRINUSE child failure was retried: attempts = %d, want 1", attempts)
	}
	var collided *portCollisionError
	if errors.As(err, &collided) {
		t.Fatalf("a child failure with no bind error was classified as a port collision: %v", err)
	}
	if !strings.Contains(err.Error(), "open registry") {
		t.Fatalf("the child's own log is missing from the reported failure: %v", err)
	}
}

// TestStartGateway_RetriesWhenAReservedPortIsStolen reproduces CI 35372449098:
// something else on the host binds a reserved address between release and the
// child's bind, and the child dies with `bind: address already in use`. The
// harness must reserve new addresses and start a new child rather than fail
// with "nothing listening on ... after 5s".
func TestStartGateway_RetriesWhenAReservedPortIsStolen(t *testing.T) {
	dsn, _, gatewayBin := setupSharedInfra(t)

	var stolen net.Listener
	var firstAttemptAddrs []string
	attempts := 0
	portSelectionHook = func(attempt int, addrs []string) {
		attempts = attempt
		if attempt != 1 {
			return
		}
		firstAttemptAddrs = append([]string(nil), addrs...)
		lis, err := net.Listen("tcp", addrs[1]) // the bootstrap address
		if err != nil {
			t.Errorf("occupy reserved bootstrap addr %s: %v", addrs[1], err)
			return
		}
		stolen = lis
	}
	t.Cleanup(func() {
		portSelectionHook = nil
		if stolen != nil {
			_ = stolen.Close()
		}
	})

	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	if attempts != 2 {
		t.Fatalf("attempts = %d, want exactly one selection retry (2)", attempts)
	}
	if gw.bootstrapAddr == firstAttemptAddrs[1] {
		t.Fatalf("the second child reused the occupied bootstrap addr %s", gw.bootstrapAddr)
	}
	conn, err := net.DialTimeout("tcp", gw.bootstrapAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("the retried gateway is not serving on %s: %v", gw.bootstrapAddr, err)
	}
	_ = conn.Close()
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
	// SigningKeyGraceWindow, when non-empty, is written as
	// signing_key_grace_window (empty → omit; probe default 10m applies).
	SigningKeyGraceWindow string
	// ConfigPaths, when non-empty, is written as the probe's config_paths
	// map (design.md §11.2.3 A, FP-SW-1).
	ConfigPaths map[string]string
	// WorkDir, when non-empty, becomes the probe process's working
	// directory (FP-SW-3's relative-socket case needs the socket to sit in
	// the process's cwd).
	WorkDir string
}

func startProbeSubprocess(t *testing.T, probeBin string, pc probeConfig) *exec.Cmd {
	t.Helper()
	cmd, _ := startProbeSubprocessWithLog(t, probeBin, pc)
	return cmd
}

// startProbeSubprocessWithLog is startProbeSubprocess that also returns the
// probe log path (design.md §9.6.7 FP-KR-23 synchronization point).
func startProbeSubprocessWithLog(t *testing.T, probeBin string, pc probeConfig) (*exec.Cmd, string) {
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

	graceLine := ""
	if pc.SigningKeyGraceWindow != "" {
		graceLine = fmt.Sprintf("signing_key_grace_window: %s\n", pc.SigningKeyGraceWindow)
	}
	if len(pc.ConfigPaths) > 0 {
		keys := make([]string, 0, len(pc.ConfigPaths))
		for k := range pc.ConfigPaths {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		graceLine += "config_paths:\n"
		for _, k := range keys {
			graceLine += fmt.Sprintf("  %q: %q\n", k, pc.ConfigPaths[k])
		}
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
%s
`,
		pc.PlatformKey, pc.GatewayAddr, pc.BootstrapAddr, pc.BootstrapToken,
		prestoPort, pc.DockerAPIURL, pc.CredentialsMount, filepath.Join(dir, "state"),
		pc.WriteEnabled, graceLine,
	)
	cfgPath := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write probe config: %v", err)
	}

	logPath := filepath.Join(dir, "probe.log")
	cmd := exec.Command(probeBin)
	cmd.Env = append(os.Environ(), "PROBE_CONFIG="+cfgPath)
	cmd.Dir = pc.WorkDir
	logFile, err := os.Create(logPath)
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
			if content, err := os.ReadFile(logPath); err == nil {
				t.Logf("probe log:\n%s", content)
			}
		}
	})
	return cmd, logPath
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
