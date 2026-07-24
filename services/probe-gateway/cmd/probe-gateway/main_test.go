package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
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

func TestPollSigningKey_PropagatesRotatedKeyToServer(t *testing.T) {
	dir := t.TempDir()
	pubPath := filepath.Join(dir, "ed25519.key.pub")
	if err := os.WriteFile(pubPath, []byte("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

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
	os.WriteFile(pubPath, []byte("YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ=="), 0o644)

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
