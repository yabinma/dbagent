// F16 / FP-M6-25 (errata pass 13 / design-review DW3; closes code-review W1):
// ManifestRefresh → real sessionclient.refreshManifest → second Register →
// handleMidSessionRegister → credentials_* audit row.
//
// Unlike f16_audit_test.go (which uses fakeProbe and hand-builds the second
// Register), this test composes the real gwserver.Server in-process with the
// real probe binary as a subprocess so the production edge is actually
// exercised. No fakeProbe, no registerWithAuth, no hand-built Register.
package gwserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
)

// TestF16_ManifestRefreshThroughTheRealSessionClientEmitsAudit drives the
// production ManifestRefresh edge with the real probe binary's sessionclient
// against a real in-process gwserver (design.md §11.1.3 F16 errata pass 13).
func TestF16_ManifestRefreshThroughTheRealSessionClientEmitsAudit(t *testing.T) {
	dsn := os.Getenv("F16_REFRESH_DSN")
	if dsn == "" {
		t.Skip("F16_REFRESH_DSN not set (invoked from test_m6_audit_completeness)")
	}

	root := f16RepoRoot(t)
	probeBin := filepath.Join(t.TempDir(), "probe")
	buildProbeBinary(t, root, probeBin)

	// Production registry + audit wiring (same as main.go).
	reg, err := registry.Open(dsn)
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	t.Cleanup(func() { _ = reg.DB.Close() })
	if err := reg.DB.Ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Bootstrap CA + probe client cert (CN == platform_key) pre-persisted so
	// ensureEnrolled takes LoadIfPresent and no bootstrap listener is needed.
	caDir := t.TempDir()
	ca, err := bootstrapca.Bootstrap(filepath.Join(caDir, "ca.crt"), filepath.Join(caDir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrapca.Bootstrap: %v", err)
	}
	platformKey := "f16-refresh-plat"
	certPEM, keyPEM := issueClientCert(t, ca, platformKey)
	stateDir := t.TempDir()
	// Same layout bootstrapclient.Persist writes (client.crt/client.key/ca.crt).
	// Written directly: probe/internal is not importable from this package.
	if err := os.WriteFile(filepath.Join(stateDir, "client.crt"), certPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "client.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "ca.crt"), ca.CACertPEM(), 0o644); err != nil {
		t.Fatal(err)
	}

	// Real mTLS Session listener on 127.0.0.1:0 (production shape).
	srv := New(reg, []byte("fake-signing-public-key-32-bytes!!"), "replica-f16-refresh")
	srv.AuditDB = reg.DB
	srv.HeartbeatTimeout = 30 * time.Second

	serverCert, err := ca.IssueServerCertificate([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("IssueServerCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = lis.Close() })
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	rcaprobev1.RegisterProbeGatewayServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	seedPlatform(t, reg, platformKey)

	// Fake Presto: 401 while credentials mount empty; 200 once credentials exist.
	// Adapter skips the HTTP call when username/password files are absent, so the
	// first Detect reports unauthenticated/missing credentials; after files are
	// written, Detect hits this server and needs a 200 for access=full.
	//
	// credsReady is closed from the test goroutine; the handler alone observes
	// the closed channel (no shared bool write from the test — review W2 race).
	credsReady := make(chan struct{})
	presto := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-credsReady:
			// credentials are present
		default:
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/info":
			w.Write([]byte(`{"nodeVersion":{"version":"0.298"},"coordinator":true}`))
		default:
			w.Write([]byte(`{}`))
		}
	}))
	t.Cleanup(presto.Close)

	// Swarm-shaped Docker API so Detect can read PASSWORD auth scheme.
	docker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/tasks":
			w.Write([]byte(`[{"ID":"t1","DesiredState":"running","Status":{"State":"running","ContainerStatus":{"ContainerID":"c1"}}}]`))
		case r.URL.Path == "/containers/c1/exec":
			w.Write([]byte(`{"Id":"exec1"}`))
		case r.URL.Path == "/exec/exec1/start":
			payload := "http-server.authentication.type=PASSWORD\n"
			b := make([]byte, 8+len(payload))
			b[0] = 1
			l := len(payload)
			b[4], b[5], b[6], b[7] = byte(l>>24), byte(l>>16), byte(l>>8), byte(l)
			copy(b[8:], payload)
			w.Write(b)
		case r.URL.Path == "/exec/exec1/json":
			w.Write([]byte(`{"ExitCode":0}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(docker.Close)

	credsMount := t.TempDir()
	// Empty mount initially → first Register reports pending_credentials.
	startF16Probe(t, probeBin, f16ProbeCfg{
		PlatformKey:      platformKey,
		GatewayAddr:      lis.Addr().String(),
		PrestoURL:        presto.URL,
		DockerAPIURL:     docker.URL,
		CredentialsMount: credsMount,
		StateDir:         stateDir,
	})

	// (4) Wait for first Register: platform pending_credentials + probe row.
	waitForCondition(t, 20*time.Second, func() bool {
		p, err := reg.GetPlatform(context.Background(), platformKey)
		return err == nil && p.Status == registry.PlatformPendingCredentials
	})
	var probeID string
	waitForCondition(t, 5*time.Second, func() bool {
		pr, found, err := reg.FindProbeByPlatform(context.Background(), platformKey)
		if err != nil || !found {
			return false
		}
		probeID = pr.ProbeID
		return probeID != ""
	})
	waitForSession(t, srv, platformKey)

	// (5) Write credentials, then RefreshManifest — the only non-production line.
	if err := os.WriteFile(filepath.Join(credsMount, "username"), []byte("presto"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(credsMount, "password"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	close(credsReady)

	if err := srv.RefreshManifest(platformKey); err != nil {
		t.Fatalf("RefreshManifest: %v", err)
	}

	// (6a) Second Register reached the gateway: platform transitions to online
	// (access == full) — only handleMidSessionRegister can write that.
	waitForCondition(t, 20*time.Second, func() bool {
		p, err := reg.GetPlatform(context.Background(), platformKey)
		return err == nil && p.Status == registry.PlatformOnline
	})

	// (6b) credentials_detected + credentials_verified audit rows scoped to
	// this test's unique platform_key (review C4 — no cross-talk with f16-plat).
	platFilter := `detail->>'platform_key' = $1`
	waitForCondition(t, 5*time.Second, func() bool {
		var detected, verified int
		_ = reg.DB.QueryRow(
			`SELECT count(*) FROM audit_log WHERE action='credentials_detected' AND `+platFilter,
			platformKey,
		).Scan(&detected)
		_ = reg.DB.QueryRow(
			`SELECT count(*) FROM audit_log WHERE action='credentials_verified' AND `+platFilter,
			platformKey,
		).Scan(&verified)
		return detected >= 1 && verified >= 1
	})

	// (6c) actor == probe:<probe_id> for BOTH required actions (review C4).
	// action=$1 and platform=$2 — platFilter above reuses $1 alone and cannot
	// be concatenated when a second bind is already present.
	wantActor := "probe:" + probeID
	for _, action := range []string{"credentials_detected", "credentials_verified"} {
		var actorOut string
		if err := reg.DB.QueryRow(
			`SELECT actor FROM audit_log WHERE action=$1 AND detail->>'platform_key' = $2 ORDER BY seq DESC LIMIT 1`,
			action, platformKey,
		).Scan(&actorOut); err != nil {
			t.Fatalf("actor query for %s: %v", action, err)
		}
		if actorOut != wantActor {
			t.Fatalf("%s actor=%q want %q", action, actorOut, wantActor)
		}
	}
	if srv.AuditDB != reg.DB {
		t.Fatal("AuditDB must be registry.PG.DB (production main.go wiring)")
	}
}

type f16ProbeCfg struct {
	PlatformKey      string
	GatewayAddr      string
	PrestoURL        string
	DockerAPIURL     string
	CredentialsMount string
	StateDir         string
}

func startF16Probe(t *testing.T, probeBin string, pc f16ProbeCfg) {
	t.Helper()
	dir := t.TempDir()
	prestoHostPort := pc.PrestoURL[len("http://"):]
	_, prestoPort, err := net.SplitHostPort(prestoHostPort)
	if err != nil {
		t.Fatalf("split presto host port: %v", err)
	}
	cfg := fmt.Sprintf(`
platform_key: %q
gateway_address: %q
bootstrap_address: "127.0.0.1:1"
bootstrap_token: ""
coordinator_service: "127.0.0.1"
worker_service: "127.0.0.1"
coordinator_port: %s
docker_api_base_url: %q
credentials_mount: %q
state_dir: %q
write_enabled: false
`,
		pc.PlatformKey, pc.GatewayAddr, prestoPort, pc.DockerAPIURL,
		pc.CredentialsMount, pc.StateDir,
	)
	cfgPath := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write probe config: %v", err)
	}
	cmd := exec.Command(probeBin)
	cmd.Env = append(os.Environ(), "PROBE_CONFIG="+cfgPath)
	logFile, err := os.Create(filepath.Join(dir, "probe.log"))
	if err != nil {
		t.Fatalf("create log: %v", err)
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
}

func buildProbeBinary(t *testing.T, root, outPath string) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", outPath, "./probe/cmd/probe")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build probe: %v\n%s", err, out)
	}
}

func f16RepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../services/probe-gateway/internal/gwserver/f16_refresh_integration_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}
