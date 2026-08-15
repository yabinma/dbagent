package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/config"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/gwserver"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/signingkeys"
)

// Note on this package's coverage: `main()` itself is a thin
// env-var-to-config-to-Fatal wiring shim and is deliberately excluded from
// the per-package coverage gate, the same way M1 excluded
// `services/worker/worker/worker_main.py`'s `if __name__ == "__main__":`
// guard -- see impl-progress.md's coverage-script section. Everything it
// calls (runSessionListener, runBootstrapListener, pollSigningKey) is
// independently tested below with real TCP+TLS listeners.

// TestMainWiresAuditDBFromRegistry proves production FP-M6-25 wiring:
// newSessionServer attaches the registry's *sql.DB as AuditDB. Deleting
// `gw.AuditDB = reg.DB` from newSessionServer fails this test (review C3).
func TestMainWiresAuditDBFromRegistry(t *testing.T) {
	// Open with a DSN that constructs a *sql.DB without requiring a live
	// server for pointer-equality of the wiring itself.
	reg, err := registry.Open("postgres://rca:rca@127.0.0.1:1/rca?sslmode=disable")
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	t.Cleanup(func() { _ = reg.DB.Close() })

	gw := newSessionServer(reg, []byte("signing-key"), "replica-1")
	if gw.AuditDB == nil {
		t.Fatal("newSessionServer left AuditDB nil; main must wire reg.DB")
	}
	if gw.AuditDB != reg.DB {
		t.Fatal("AuditDB must be the same *sql.DB as registry.PG.DB")
	}
}

// UT-IG-12: the ConfigMap-shaped key is loaded by config.Load and applied
// through applyDBConnCeiling. max_db_conns: 7 is a non-default value so a
// struct-tag rename cannot pass on a hypothetical default-10 field (the
// named weak form). Against the unfixed tree Stats().MaxOpenConnections
// reads 0 (unlimited).
func TestApplyDBConnCeiling_AppliesLoadedMaxDBConns(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	// Byte-shape the ConfigMap template renders: unquoted int, no ${}.
	content := "" +
		"postgres_dsn: postgres://rca:rca@127.0.0.1:1/rca?sslmode=disable\n" +
		"session_listen_addr: \":8443\"\n" +
		"bootstrap_listen_addr: \":8444\"\n" +
		"internal_listen_addr: \":8080\"\n" +
		"max_db_conns: 7\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if cfg.MaxDBConns != 7 {
		t.Fatalf("Load did not decode max_db_conns: got %d", cfg.MaxDBConns)
	}
	reg, err := registry.Open(cfg.PostgresDSN)
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	t.Cleanup(func() { _ = reg.DB.Close() })
	if err := applyDBConnCeiling(cfg, reg); err != nil {
		t.Fatalf("applyDBConnCeiling: %v", err)
	}
	got := reg.DB.Stats().MaxOpenConnections
	if got != 7 {
		t.Fatalf("MaxOpenConnections=%d, want 7 (0 is unlimited)", got)
	}
}

func TestApplyDBConnCeiling_RefusesAbsentZeroAndNegative(t *testing.T) {
	reg, err := registry.Open("postgres://rca:rca@127.0.0.1:1/rca?sslmode=disable")
	if err != nil {
		t.Fatalf("registry.Open: %v", err)
	}
	t.Cleanup(func() { _ = reg.DB.Close() })

	dir := t.TempDir()
	cases := []struct {
		name string
		yaml string
	}{
		{
			name: "absent key",
			yaml: "postgres_dsn: postgres://x\n",
		},
		{
			name: "explicit zero",
			yaml: "postgres_dsn: postgres://x\nmax_db_conns: 0\n",
		},
		{
			name: "negative",
			yaml: "postgres_dsn: postgres://x\nmax_db_conns: -1\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(dir, tc.name+".yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			err = applyDBConnCeiling(cfg, reg)
			if err == nil {
				t.Fatalf("expected error for %s (got MaxDBConns=%d)", tc.name, cfg.MaxDBConns)
			}
			if reg.DB.Stats().MaxOpenConnections != 0 {
				t.Fatalf("refusal must not apply a ceiling; MaxOpenConnections=%d", reg.DB.Stats().MaxOpenConnections)
			}
		})
	}
}

func TestPollSigningKey_PropagatesRotatedKeyToServer(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "ed25519.key.pub")
	writeSigningPub(t, pubPath, bytes.Repeat([]byte("a"), 32))

	keys := signingkeys.NewReader(pubPath, time.Hour)
	gw := gwserver.New(registry.NewFake(), nil, "replica-1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollSigningKey(ctx, keys, gw, 20*time.Millisecond)

	time.Sleep(100 * time.Millisecond)
	if keys.Current() == nil {
		t.Fatalf("expected pollSigningKey to have loaded the key at least once")
	}
}

func TestPollSigningKey_StopsOnContextCancellation(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "ed25519.key.pub")
	writeSigningPub(t, pubPath, bytes.Repeat([]byte("a"), 32))

	keys := signingkeys.NewReader(pubPath, time.Hour)
	gw := gwserver.New(registry.NewFake(), nil, "replica-1")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollSigningKey(ctx, keys, gw, 10*time.Millisecond)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected pollSigningKey to return promptly after cancellation")
	}
}

func TestPollSigningKey_ToleratesLoadErrors(t *testing.T) {
	// Points at a file that never exists; Load() will keep failing, and
	// pollSigningKey must keep polling (not panic/exit) until cancelled.
	keys := signingkeys.NewReader(filepath.Join(t.TempDir(), "missing.pub"), time.Hour)
	gw := gwserver.New(registry.NewFake(), nil, "replica-1")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pollSigningKey(ctx, keys, gw, 10*time.Millisecond)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected pollSigningKey to return promptly after cancellation")
	}
}

// writeSigningPub writes a base64-encoded ed25519 public key sidecar, matching
// the format signingkeys.Reader expects (same as the Python bootstrap path).
func writeSigningPub(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(raw)), 0o644); err != nil {
		t.Fatalf("write signing pub: %v", err)
	}
}

// startBufconnSessionServer stands up a plaintext bufconn ProbeGateway.Session
// server (same pattern as gwserver's own unit tests) so main_test can register
// a live session and observe outbound GatewayMessages without mTLS.
func startBufconnSessionServer(t *testing.T, gw *gwserver.Server) rcaprobev1.ProbeGatewayClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	rcaprobev1.RegisterProbeGatewayServer(grpcServer, gw)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return rcaprobev1.NewProbeGatewayClient(conn)
}

// connectFakeSession registers one platform session and returns a channel of
// subsequent outbound GatewayMessages, the admission RegisterAck, and a cancel.
func connectFakeSession(t *testing.T, gw *gwserver.Server, platformKey string) (received <-chan *rcaprobev1.GatewayMessage, firstAck *rcaprobev1.RegisterAck, cancel func()) {
	t.Helper()
	reg := gw.Registry
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: platformKey}, "tok-"+platformKey); err != nil && err != registry.ErrPlatformExists {
		t.Fatalf("seed platform: %v", err)
	}
	client := startBufconnSessionServer(t, gw)
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := client.Session(ctx)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	ch := make(chan *rcaprobev1.GatewayMessage, 32)
	go func() {
		for {
			msg, err := stream.Recv()
			if err != nil {
				close(ch)
				return
			}
			ch <- msg
		}
	}()
	if err := stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{PlatformKey: platformKey, ProbeVersion: "0.1.0"},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}
	var ack *rcaprobev1.RegisterAck
	select {
	case msg := <-ch:
		ack = msg.GetAck()
		if ack == nil || !ack.GetAccepted() {
			t.Fatalf("expected accepted RegisterAck, got %+v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RegisterAck")
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		for _, k := range gw.ConnectedPlatforms() {
			if k == platformKey {
				return ch, ack, cancel
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("session never registered on server")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// FP-KR-17
func TestPollSigningKey_PropagatesRotatedKeyToConnectedProbe(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "ed25519.key.pub")
	keyA := bytes.Repeat([]byte("a"), 32)
	keyB := bytes.Repeat([]byte("b"), 32)
	writeSigningPub(t, pubPath, keyA)

	reg := registry.NewFake()
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1"); err != nil {
		t.Fatalf("seed platform: %v", err)
	}
	// Admit with A so the session records A as lastKeySent.
	gw := gwserver.New(reg, keyA, "replica-1")
	received, _, cancelSession := connectFakeSession(t, gw, "presto-us1")
	defer cancelSession()

	// Long tick so a broken impl that converges only after many ticks fails:
	// the assertion window is one tick plus a bounded scheduling margin, not
	// a multi-second multi-tick budget.
	const tick = 250 * time.Millisecond
	const schedMargin = 150 * time.Millisecond
	keys := signingkeys.NewReader(pubPath, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollSigningKey(ctx, keys, gw, tick)

	// Wait for initial load of A (converged — no frame expected).
	// Allow a few ticks for the first Load (poll only fires on ticker).
	deadline := time.Now().Add(3 * tick)
	for keys.Current() == nil || !bytes.Equal(keys.Current(), keyA) {
		if time.Now().After(deadline) {
			t.Fatal("expected pollSigningKey to load A")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Silence across several ticks while unchanged.
	for i := 0; i < 2; i++ {
		select {
		case msg := <-received:
			t.Fatalf("unexpected frame while sidecar unchanged: %+v", msg)
		case <-time.After(tick + schedMargin):
		}
	}

	// Rotate to B — must deliver a RegisterAck with B within ONE tick + margin,
	// never ManifestRefresh. A multi-tick convergence budget would green a
	// broken implementation that only eventually propagates.
	writeSigningPub(t, pubPath, keyB)
	deadline = time.Now().Add(tick + schedMargin)
	var gotAck bool
	for time.Now().Before(deadline) {
		select {
		case msg := <-received:
			if msg.GetRefresh() != nil {
				t.Fatal("must not send ManifestRefresh on key rotation")
			}
			ack := msg.GetAck()
			if ack == nil {
				t.Fatalf("unexpected frame: %+v", msg)
			}
			if !ack.GetAccepted() || !bytes.Equal(ack.GetSigningPublicKey(), keyB) {
				t.Fatalf("expected A.2 RegisterAck with B, got %+v", ack)
			}
			gotAck = true
		case <-time.After(20 * time.Millisecond):
		}
		if gotAck {
			break
		}
	}
	if !gotAck {
		t.Fatal("expected mid-session RegisterAck with rotated key within one poll tick")
	}

	// Unchanged B: no further frames across a couple of ticks.
	for i := 0; i < 2; i++ {
		select {
		case msg := <-received:
			t.Fatalf("unexpected frame after convergence: %+v", msg)
		case <-time.After(tick + schedMargin):
		}
	}
}

// FP-KR-19
func TestPollSigningKey_WrongLengthSidecarNeverBecomesServedOrAdmissionKey(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "ed25519.key.pub")
	keyA := bytes.Repeat([]byte("a"), 32)
	keyB := bytes.Repeat([]byte("b"), 32)
	writeSigningPub(t, pubPath, keyA)

	reg := registry.NewFake()
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us2"}, "tok-2"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	gw := gwserver.New(reg, keyA, "replica-1")
	received, _, cancelSession := connectFakeSession(t, gw, "presto-us1")
	defer cancelSession()

	keys := signingkeys.NewReader(pubPath, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollSigningKey(ctx, keys, gw, 20*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for !bytes.Equal(keys.Current(), keyA) {
		if time.Now().After(deadline) {
			t.Fatal("never loaded A")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Wrong-length sidecar.
	writeSigningPub(t, pubPath, bytes.Repeat([]byte("x"), 31))
	time.Sleep(100 * time.Millisecond)
	if !bytes.Equal(keys.Current(), keyA) {
		t.Fatalf("wrong-length sidecar became Current: %v", keys.Current())
	}

	// Session admitted now must still receive A.
	_, ack2, cancel2 := connectFakeSession(t, gw, "presto-us2")
	defer cancel2()
	if !bytes.Equal(ack2.GetSigningPublicKey(), keyA) {
		t.Fatalf("admission after bad sidecar got key %v, want A", ack2.GetSigningPublicKey())
	}
	select {
	case msg := <-received:
		t.Fatalf("no key-update expected during bad sidecar, got %+v", msg)
	case <-time.After(80 * time.Millisecond):
	}

	// Valid B recovers.
	writeSigningPub(t, pubPath, keyB)
	deadline = time.Now().Add(2 * time.Second)
	var sawB bool
	for time.Now().Before(deadline) {
		if bytes.Equal(keys.Current(), keyB) {
			sawB = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !sawB {
		t.Fatal("valid B never became Current after bad sidecar")
	}
	// Connected session(s) should receive B via propagation.
	deadline = time.Now().Add(2 * time.Second)
	var gotB bool
	for time.Now().Before(deadline) {
		select {
		case msg := <-received:
			if ack := msg.GetAck(); ack != nil && bytes.Equal(ack.GetSigningPublicKey(), keyB) {
				gotB = true
			}
		case <-time.After(20 * time.Millisecond):
		}
		if gotB {
			break
		}
	}
	if !gotB {
		t.Fatal("expected propagation of B to connected session after recovery")
	}
}

// mutexBuffer is a race-safe log capture for pollSigningKey tests.
type mutexBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (m *mutexBuffer) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.b.Write(p)
}

func (m *mutexBuffer) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.b.String()
}

// FP-KR-27
func TestPollSigningKey_ReadinessLineOnlyOnACleanPass(t *testing.T) {
	// Part 1: pure function table.
	cases := []struct {
		name           string
		p              gwserver.SigningKeyPropagation
		prevIncomplete bool
		wantPrefix     string
		wantIncomplete bool
		wantEmpty      bool
		wantZeroDrop   bool
		wantNotReady   bool
	}{
		{"converged silent", gwserver.SigningKeyPropagation{Sent: 0, UpToDate: 0, Dropped: 0}, false, "", false, true, false, false},
		{"sent ready", gwserver.SigningKeyPropagation{Sent: 1, UpToDate: 0, Dropped: 0}, false, "probe-gateway: signing key propagated to all connected sessions (", false, false, true, false},
		{"dropped not ready", gwserver.SigningKeyPropagation{Sent: 1, UpToDate: 2, Dropped: 1}, false, "probe-gateway: signing key propagation incomplete: ", true, false, false, true},
		{"dropped with prev", gwserver.SigningKeyPropagation{Sent: 0, UpToDate: 3, Dropped: 2}, true, "probe-gateway: signing key propagation incomplete: ", true, false, false, true},
		{"carry-over ready", gwserver.SigningKeyPropagation{Sent: 0, UpToDate: 3, Dropped: 0}, true, "probe-gateway: signing key propagated to all connected sessions (", false, false, true, false},
		{"clean silent", gwserver.SigningKeyPropagation{Sent: 0, UpToDate: 3, Dropped: 0}, false, "", false, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line, incomplete := propagationLogLine(tc.p, tc.prevIncomplete)
			if incomplete != tc.wantIncomplete {
				t.Fatalf("incomplete=%v want %v", incomplete, tc.wantIncomplete)
			}
			if tc.wantEmpty {
				if line != "" {
					t.Fatalf("want empty line, got %q", line)
				}
				return
			}
			if !strings.HasPrefix(line, tc.wantPrefix) {
				t.Fatalf("line %q missing prefix %q", line, tc.wantPrefix)
			}
			if tc.wantZeroDrop && !strings.Contains(line, "0 dropped") {
				t.Fatalf("ready line must contain 0 dropped: %q", line)
			}
			if tc.wantNotReady && !strings.Contains(line, "NOT ready") {
				t.Fatalf("not-ready line must contain NOT ready: %q", line)
			}
		})
	}

	// Part 2: real pollSigningKey wiring emits the ready line after rotation.
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "ed25519.key.pub")
	keyA := bytes.Repeat([]byte("a"), 32)
	keyB := bytes.Repeat([]byte("b"), 32)
	writeSigningPub(t, pubPath, keyA)

	reg := registry.NewFake()
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1")
	gw := gwserver.New(reg, keyA, "replica-1")
	_, _, cancelSession := connectFakeSession(t, gw, "presto-us1")
	defer cancelSession()

	var buf mutexBuffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	keys := signingkeys.NewReader(pubPath, time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go pollSigningKey(ctx, keys, gw, 20*time.Millisecond)

	// Load A first.
	deadline := time.Now().Add(2 * time.Second)
	for !bytes.Equal(keys.Current(), keyA) {
		if time.Now().After(deadline) {
			t.Fatal("never loaded A")
		}
		time.Sleep(10 * time.Millisecond)
	}
	writeSigningPub(t, pubPath, keyB)

	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out := buf.String()
		// Incomplete must never appear in this clean-pass harness: fail
		// immediately rather than keep waiting for a later ready line.
		if strings.Contains(out, "signing key propagation incomplete") {
			t.Fatalf("signing key propagation incomplete must not appear in clean-pass real poll; log=%q", out)
		}
		if strings.Contains(out, "signing key propagated to all connected sessions") {
			// Same line must have 0 dropped.
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "signing key propagated to all connected sessions") {
					if !strings.Contains(line, "0 dropped") {
						t.Fatalf("ready line missing 0 dropped: %q", line)
					}
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("ready line never appeared; log=%q", buf.String())
}

// bootstrapCAPinFingerprintFormat is the exact format design.md Section
// 8.4a defines for bootstrap_ca_pin's fingerprint form.
var bootstrapCAPinFingerprintFormat = regexp.MustCompile(`sha256:[0-9a-f]{64}`)

// TestLogCAFingerprint_MatchesFormatAndRealFingerprint is the item-2
// regression test (design.md Section 8.4a "Distribution"): probe-gateway
// must log the bootstrap CA's sha256 fingerprint at startup, in the exact
// "sha256:<64 lowercase hex>" format bootstrap_ca_pin expects, so an
// operator can copy it straight into that config field. Asserts both the
// well-formed-ness of the logged value and that it matches a fingerprint
// computed independently in this test (straight off the on-disk CA cert
// PEM, not via bootstrapca.CA.Fingerprint() itself) -- not just a format
// check.
func TestLogCAFingerprint_MatchesFormatAndRealFingerprint(t *testing.T) {
	ca := testCA(t)

	logged := logCAFingerprint(ca)

	match := bootstrapCAPinFingerprintFormat.FindString(logged)
	if match == "" {
		t.Fatalf("logged line %q does not contain a well-formed sha256:<64 lowercase hex> fingerprint", logged)
	}

	block, _ := pem.Decode(ca.CACertPEM())
	if block == nil {
		t.Fatalf("failed to PEM-decode CA cert")
	}
	sum := sha256.Sum256(block.Bytes)
	want := fmt.Sprintf("sha256:%s", hex.EncodeToString(sum[:]))
	if match != want {
		t.Fatalf("logged fingerprint %q does not match the independently-computed real fingerprint %q", match, want)
	}
}

func testCA(t *testing.T) *bootstrapca.CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := bootstrapca.Bootstrap(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrap ca: %v", err)
	}
	return ca
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("find free port: %v", err)
	}
	addr := lis.Addr().String()
	lis.Close()
	return addr
}

func TestRunBootstrapListener_ServesEnroll(t *testing.T) {
	ca := testCA(t)
	reg := registry.NewFake()
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1")

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runBootstrapListener(ctx, addr, ca, reg, []string{"127.0.0.1"})

	waitForListener(t, addr)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{RootCAs: pool})))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	client := rcaprobev1.NewBootstrapClient(conn)
	resp, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-us1", BootstrapToken: "tok-1", CsrPem: generateTestCSR(t, "presto-us1"),
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if len(resp.GetClientCertPem()) == 0 {
		t.Fatalf("expected a client cert in the response")
	}
}

func TestRunSessionListener_AcceptsMTLSAndRegisters(t *testing.T) {
	ca := testCA(t)
	reg := registry.NewFake()
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1")
	gw := gwserver.New(reg, []byte("signing-key"), "replica-1")

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runSessionListener(ctx, addr, ca, gw, reg, []string{"127.0.0.1"})

	waitForListener(t, addr)

	// Enroll a real client cert against the same CA so the mTLS handshake succeeds.
	clientCertPEM, clientKeyPEM := issueTestClientCert(t, ca, "presto-us1")
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert}, RootCAs: pool,
	})))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	stream, err := rcaprobev1.NewProbeGatewayClient(conn).Session(context.Background())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{PlatformKey: "presto-us1", ProbeVersion: "0.1.0"},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	ack := msg.GetAck()
	if ack == nil || !ack.GetAccepted() {
		t.Fatalf("expected an accepted RegisterAck, got %+v", msg)
	}
}

// --- design.md Section 8.4a: identity binding + renewal (required M3 fixes),
// exercised end to end against the real listener wiring (runSessionListener
// now also serves Bootstrap.Enroll) ------------------------------------------

func TestRunSessionListener_RejectsCrossPlatformRegistration(t *testing.T) {
	ca := testCA(t)
	reg := registry.NewFake()
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-a"}, "tok-a")
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-b"}, "tok-b")
	gw := gwserver.New(reg, []byte("signing-key"), "replica-1")

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runSessionListener(ctx, addr, ca, gw, reg, []string{"127.0.0.1"})
	waitForListener(t, addr)

	// A cert legitimately issued for presto-a...
	clientCertPEM, clientKeyPEM := issueTestClientCert(t, ca, "presto-a")
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert}, RootCAs: pool,
	})))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	stream, err := rcaprobev1.NewProbeGatewayClient(conn).Session(context.Background())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	// ...must not be able to register as presto-b (design.md Section 8.4a:
	// "a certificate issued for one platform must never be able to
	// register... as another").
	if err := stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{PlatformKey: "presto-b", ProbeVersion: "0.1.0"},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}

	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	ack := msg.GetAck()
	if ack == nil || ack.GetAccepted() {
		t.Fatalf("expected a rejected RegisterAck for cross-platform registration, got %+v", msg)
	}
}

func TestRunSessionListener_ServesRenewalOverMTLS(t *testing.T) {
	ca := testCA(t)
	reg := registry.NewFake()
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1")
	gw := gwserver.New(reg, []byte("signing-key"), "replica-1")

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runSessionListener(ctx, addr, ca, gw, reg, []string{"127.0.0.1"})
	waitForListener(t, addr)

	// design.md Section 8.4a: "the Bootstrap service is registered on both
	// listeners" -- renewal calls Enroll on this same mTLS Session
	// listener, authenticating with the still-valid existing cert instead
	// of a (single-use, already-consumed) bootstrap token.
	clientCertPEM, clientKeyPEM := issueTestClientCert(t, ca, "presto-us1")
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert}, RootCAs: pool,
	})))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	resp, err := rcaprobev1.NewBootstrapClient(conn).Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-us1",
		CsrPem:      generateTestCSR(t, "presto-us1"),
		// BootstrapToken intentionally empty: renewal.
	})
	if err != nil {
		t.Fatalf("renewal enroll: %v", err)
	}
	if len(resp.GetClientCertPem()) == 0 {
		t.Fatalf("expected a renewed client cert")
	}
	if string(resp.GetClientCertPem()) == string(clientCertPEM) {
		t.Fatalf("expected a genuinely new certificate from renewal")
	}
}

func TestRunSessionListener_RejectsRenewalWithMismatchedCN(t *testing.T) {
	ca := testCA(t)
	reg := registry.NewFake()
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-a"}, "tok-a")
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-b"}, "tok-b")
	gw := gwserver.New(reg, []byte("signing-key"), "replica-1")

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runSessionListener(ctx, addr, ca, gw, reg, []string{"127.0.0.1"})
	waitForListener(t, addr)

	clientCertPEM, clientKeyPEM := issueTestClientCert(t, ca, "presto-a")
	clientCert, err := tls.X509KeyPair(clientCertPEM, clientKeyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert}, RootCAs: pool,
	})))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_, err = rcaprobev1.NewBootstrapClient(conn).Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-b",
		CsrPem:      generateTestCSR(t, "presto-b"),
	})
	if err == nil {
		t.Fatalf("expected renewal to be rejected for a cert/platform_key CN mismatch")
	}
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener at %s never became ready", addr)
}

// TestRunInternalDispatchListener_HealthzAndShutdown covers
// runInternalDispatchListener (review.md C1): start on an ephemeral port with
// a real gwserver.Server as dispatcher, GET /healthz, then cancel ctx to
// trigger graceful Shutdown. Same pattern as the other run*Listener helpers.
func TestRunInternalDispatchListener_HealthzAndShutdown(t *testing.T) {
	reg := registry.NewFake()
	gw := gwserver.New(reg, []byte("signing-key"), "replica-1")

	addr := freeLoopbackAddr(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runInternalDispatchListener(ctx, addr, gw)
		close(done)
	}()

	// Wait until HTTP /healthz responds (not just TCP accept).
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get("http://" + addr + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				lastErr = nil
				break
			}
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	if lastErr != nil {
		cancel()
		t.Fatalf("internal dispatch /healthz never ready: %v", lastErr)
	}

	resp, err := http.Get("http://" + addr + "/healthz")
	if err != nil {
		cancel()
		t.Fatalf("healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		cancel()
		t.Fatalf("healthz status=%d body=%s", resp.StatusCode, body)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runInternalDispatchListener did not return after context cancel")
	}
}

func generateTestCSR(t *testing.T, cn string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, PublicKey: pub}, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

func issueTestClientCert(t *testing.T, ca *bootstrapca.CA, cn string) (certPEM, keyPEM []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, PublicKey: pub}, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, err = ca.SignCSR(csrPEM, cn)
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}
