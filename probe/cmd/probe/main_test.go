package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
	"github.com/yabinma/dbagent/probe/internal/bootstrapclient"
	"github.com/yabinma/dbagent/probe/internal/config"
	"github.com/yabinma/dbagent/probe/internal/platform"
	"k8s.io/client-go/rest"
)

// Note on this package's coverage: `main()` itself is a thin env-var/
// signal-handling/reconnect-loop shim and is deliberately excluded from
// the per-package coverage gate (see impl-progress.md's coverage-script
// section) -- everything it calls (ensureEnrolled, buildRuntimeEnv,
// runSession) is independently tested below.

func TestEnsureEnrolled_ReusesPersistedIdentity(t *testing.T) {
	ca := testMainCA(t)
	certPEM, keyPEM := issueMainClientCert(t, ca, "presto-us1") // fresh 24h cert, well under the 50%/expiry thresholds
	dir := t.TempDir()
	persisted := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}
	if err := persisted.Persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}

	result, err := ensureEnrolled(context.Background(), config.Probe{StateDir: dir})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.ClientCertPEM) != string(certPEM) {
		t.Fatalf("expected the persisted identity to be reused, got %+v", result)
	}
}

func TestEnsureEnrolled_MalformedPersistedCertErrors(t *testing.T) {
	dir := t.TempDir()
	persisted := &bootstrapclient.Result{ClientCertPEM: []byte("not a cert"), ClientKeyPEM: []byte("key"), CACertPEM: []byte("ca")}
	if err := persisted.Persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}

	_, err := ensureEnrolled(context.Background(), config.Probe{StateDir: dir})
	if err == nil {
		t.Fatalf("expected an error for a malformed persisted client certificate")
	}
}

func TestEnsureEnrolled_ExpiredPersistedCertAndNoTokenErrors(t *testing.T) {
	ca := testMainCA(t)
	certPEM, keyPEM := issueMainClientCertWithValidity(t, ca, "presto-us1", -25*time.Hour, -1*time.Hour) // fully expired
	dir := t.TempDir()
	persisted := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}
	if err := persisted.Persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}

	// design.md Section 8.4a: "The probe MUST treat an expired persisted
	// certificate the same as no certificate at startup" -- with no
	// bootstrap_token configured, that's the same errNoBootstrapToken a
	// genuinely-first-run probe would get.
	_, err := ensureEnrolled(context.Background(), config.Probe{StateDir: dir})
	if err != errNoBootstrapToken {
		t.Fatalf("expected errNoBootstrapToken for an expired cert with no token, got %v", err)
	}
}

func TestEnsureEnrolled_ExpiredPersistedCertReEnrollsWithFreshToken(t *testing.T) {
	addr, tokens, ca := startBootstrapServerForMain(t)
	tokens.set("presto-us1", "tok-1")

	expiredCertPEM, expiredKeyPEM := issueMainClientCertWithValidity(t, ca, "presto-us1", -25*time.Hour, -1*time.Hour)
	dir := t.TempDir()
	persisted := &bootstrapclient.Result{ClientCertPEM: expiredCertPEM, ClientKeyPEM: expiredKeyPEM, CACertPEM: ca.CACertPEM()}
	if err := persisted.Persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}

	result, err := ensureEnrolled(context.Background(), config.Probe{
		StateDir: dir, PlatformKey: "presto-us1", BootstrapToken: "tok-1", BootstrapAddress: addr,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(result.ClientCertPEM) == string(expiredCertPEM) {
		t.Fatalf("expected a freshly-enrolled certificate, not the expired one")
	}
	if _, expired, err := result.RenewalStatus(time.Now()); err != nil || expired {
		t.Fatalf("expected the freshly re-enrolled certificate to be unexpired, err=%v expired=%v", err, expired)
	}
}

func TestEnsureEnrolled_NoTokenAndNothingPersistedErrors(t *testing.T) {
	_, err := ensureEnrolled(context.Background(), config.Probe{StateDir: t.TempDir()})
	if err != errNoBootstrapToken {
		t.Fatalf("expected errNoBootstrapToken, got %v", err)
	}
}

func TestEnsureEnrolled_EnrollsAndPersistsWhenTokenProvided(t *testing.T) {
	addr, tokens, _ := startBootstrapServerForMain(t)
	tokens.set("presto-us1", "tok-1")

	dir := t.TempDir()
	result, err := ensureEnrolled(context.Background(), config.Probe{
		StateDir: dir, PlatformKey: "presto-us1", BootstrapToken: "tok-1", BootstrapAddress: addr,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ClientCertPEM) == 0 {
		t.Fatalf("expected a client cert")
	}

	// It was persisted: a second call must reuse it (and not need the
	// now-consumed token again).
	result2, err := ensureEnrolled(context.Background(), config.Probe{
		StateDir: dir, PlatformKey: "presto-us1", BootstrapToken: "tok-1", BootstrapAddress: addr,
	})
	if err != nil {
		t.Fatalf("unexpected error on reuse: %v", err)
	}
	if string(result2.ClientCertPEM) != string(result.ClientCertPEM) {
		t.Fatalf("expected the persisted cert to be reused")
	}
}

func TestEnsureEnrolled_LoadIfPresentErrorPropagates(t *testing.T) {
	dir := t.TempDir()
	// client.crt present but client.key missing -> LoadIfPresent errors.
	if err := os.WriteFile(dir+"/client.crt", []byte("cert"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := ensureEnrolled(context.Background(), config.Probe{StateDir: dir})
	if err == nil {
		t.Fatalf("expected the LoadIfPresent error to propagate")
	}
}

func TestEnsureEnrolled_EnrollFailurePropagates(t *testing.T) {
	addr, tokens, _ := startBootstrapServerForMain(t)
	tokens.set("presto-us1", "correct-token")

	_, err := ensureEnrolled(context.Background(), config.Probe{
		StateDir: t.TempDir(), PlatformKey: "presto-us1", BootstrapToken: "wrong-token", BootstrapAddress: addr,
	})
	if err == nil {
		t.Fatalf("expected the Enroll failure (wrong token) to propagate")
	}
}

func TestEnsureEnrolled_PersistFailurePropagates(t *testing.T) {
	addr, tokens, _ := startBootstrapServerForMain(t)
	tokens.set("presto-us1", "tok-1")

	dir := t.TempDir()
	// Pre-create "client.crt" as a directory so Persist's WriteFile fails.
	if err := os.Mkdir(dir+"/client.crt", 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	_, err := ensureEnrolled(context.Background(), config.Probe{
		StateDir: dir, PlatformKey: "presto-us1", BootstrapToken: "tok-1", BootstrapAddress: addr,
	})
	if err == nil {
		t.Fatalf("expected the Persist failure to propagate")
	}
}

func TestBuildRuntimeEnv_SwarmDeployment(t *testing.T) {
	env, kind, err := buildRuntimeEnv(config.Probe{CoordinatorService: "presto-coordinator", WorkerService: "presto-worker"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != platform.EnvKindSwarm {
		t.Fatalf("expected EnvKindSwarm, got %s", kind)
	}
	if env == nil {
		t.Fatalf("expected a non-nil RuntimeEnv")
	}
}

func TestBuildRuntimeEnv_K8sDeploymentOutsideClusterErrors(t *testing.T) {
	// No CoordinatorService -> attempts inClusterConfig(), which fails
	// outside a real cluster/test environment by default -- a legitimate,
	// deterministically-testable error path.
	_, _, err := buildRuntimeEnv(config.Probe{})
	if err == nil {
		t.Fatalf("expected an error building a k8s RuntimeEnv outside a cluster")
	}
}

func TestBuildRuntimeEnv_K8sDeploymentWithInjectedConfig(t *testing.T) {
	original := inClusterConfig
	inClusterConfig = func() (*rest.Config, error) {
		return &rest.Config{Host: "https://fake-apiserver.local"}, nil
	}
	defer func() { inClusterConfig = original }()

	env, kind, err := buildRuntimeEnv(config.Probe{Namespace: "presto", CoordinatorLocator: "role=coordinator"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != platform.EnvKindK8s {
		t.Fatalf("expected EnvKindK8s, got %s", kind)
	}
	if env == nil {
		t.Fatalf("expected a non-nil RuntimeEnv")
	}
}

func TestStaticError_Error(t *testing.T) {
	if errNoBootstrapToken.Error() == "" {
		t.Fatalf("expected a non-empty error message")
	}
}

func TestRunSession_ConnectsRegistersAndRuns(t *testing.T) {
	ca := testMainCA(t)
	certPEM, keyPEM := issueMainClientCert(t, ca, "presto-us1")
	enrollment := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}

	srv := newFakeSessionServer()
	addr := startMTLSSessionServer(t, srv, ca)

	cfg := config.Probe{PlatformKey: "presto-us1", GatewayAddress: addr}
	adapter := &noopAdapter{}

	ctx, cancel := context.WithCancel(context.Background())
	runErr := make(chan error, 1)
	go func() { runErr <- runSession(ctx, cfg, enrollment, adapter, nil) }()

	select {
	case msg := <-srv.received:
		if msg.GetRegister().GetPlatformKey() != "presto-us1" {
			t.Fatalf("unexpected register: %+v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for Register")
	}

	cancel()
	select {
	case <-runErr:
	case <-time.After(2 * time.Second):
		t.Fatalf("expected runSession to return after context cancellation")
	}
}

func TestRunSession_InvalidTLSConfigErrors(t *testing.T) {
	enrollment := &bootstrapclient.Result{ClientCertPEM: []byte("bad"), ClientKeyPEM: []byte("bad"), CACertPEM: []byte("bad")}
	err := runSession(context.Background(), config.Probe{GatewayAddress: "127.0.0.1:0"}, enrollment, &noopAdapter{}, nil)
	if err == nil {
		t.Fatalf("expected an error for an invalid TLS config")
	}
}

// --- test helpers -------------------------------------------------------------------

type noopAdapter struct{}

func (a *noopAdapter) Detect(ctx context.Context, env platform.RuntimeEnv) (platform.Manifest, error) {
	return platform.Manifest{}, nil
}
func (a *noopAdapter) Tools() []platform.ToolSpec { return nil }
func (a *noopAdapter) Execute(ctx context.Context, call platform.ToolCall) (platform.ToolResult, error) {
	return platform.ToolResult{}, nil
}
func (a *noopAdapter) HealthCheck(ctx context.Context, spec platform.HealthSpec) (platform.HealthResult, error) {
	return platform.HealthResult{}, nil
}
func (a *noopAdapter) WriteOps() []platform.WriteOpSpec { return nil }
func (a *noopAdapter) ExecuteWrite(ctx context.Context, step platform.RemediationStep) (platform.WriteResult, error) {
	return platform.WriteResult{}, nil
}

func testMainCA(t *testing.T) *bootstrapca.CA {
	t.Helper()
	dir := t.TempDir()
	ca, err := bootstrapca.Bootstrap(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrap ca: %v", err)
	}
	return ca
}

func issueMainClientCert(t *testing.T, ca *bootstrapca.CA, cn string) (certPEM, keyPEM []byte) {
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

// issueMainClientCertWithValidity is issueMainClientCert with an explicit
// (notBefore, notAfter) window expressed as offsets from time.Now(), so
// tests can deterministically craft "renewal due" (<50% validity
// remaining) or "already expired" certificates (design.md Section 8.4a)
// without waiting on a real clock.
func issueMainClientCertWithValidity(t *testing.T, ca *bootstrapca.CA, cn string, notBeforeOffset, notAfterOffset time.Duration) (certPEM, keyPEM []byte) {
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
	now := time.Now()
	certPEM, err = ca.SignCSRWithValidity(csrPEM, cn, now.Add(notBeforeOffset), now.Add(notAfterOffset))
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

// --- minimal in-process Bootstrap server for ensureEnrolled tests -------------------

type mainTokenStore struct {
	mu    sync.Mutex
	valid map[string]string
	used  map[string]bool
}

func (s *mainTokenStore) set(platformKey, token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.valid[platformKey] = token
}

func (s *mainTokenStore) consume(platformKey, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used[platformKey] || s.valid[platformKey] != token {
		return false
	}
	s.used[platformKey] = true
	return true
}

type mainBootstrapServer struct {
	rcaprobev1.UnimplementedBootstrapServer
	ca     *bootstrapca.CA
	tokens *mainTokenStore
}

func (s *mainBootstrapServer) Enroll(ctx context.Context, req *rcaprobev1.EnrollRequest) (*rcaprobev1.EnrollResponse, error) {
	if !s.tokens.consume(req.GetPlatformKey(), req.GetBootstrapToken()) {
		return nil, context.DeadlineExceeded
	}
	certPEM, err := s.ca.SignCSR(req.GetCsrPem(), req.GetPlatformKey())
	if err != nil {
		return nil, err
	}
	return &rcaprobev1.EnrollResponse{ClientCertPem: certPEM, CaCertPem: s.ca.CACertPEM()}, nil
}

func startBootstrapServerForMain(t *testing.T) (addr string, tokens *mainTokenStore, ca *bootstrapca.CA) {
	t.Helper()
	ca = testMainCA(t)
	tokens = &mainTokenStore{valid: map[string]string{}, used: map[string]bool{}}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverCert, err := ca.IssueServerCertificate([]string{"probe-gateway"})
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}})))
	rcaprobev1.RegisterBootstrapServer(grpcServer, &mainBootstrapServer{ca: ca, tokens: tokens})
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String(), tokens, ca
}

// --- minimal in-process ProbeGateway session server for runSession tests -----------

type fakeSessionServer struct {
	rcaprobev1.UnimplementedProbeGatewayServer
	received chan *rcaprobev1.ProbeMessage
}

func newFakeSessionServer() *fakeSessionServer {
	return &fakeSessionServer{received: make(chan *rcaprobev1.ProbeMessage, 16)}
}

func (s *fakeSessionServer) Session(stream rcaprobev1.ProbeGateway_SessionServer) error {
	msg, err := stream.Recv()
	if err != nil {
		return err
	}
	s.received <- msg
	if err := stream.Send(&rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: "probe-1", Accepted: true},
	}}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

func startMTLSSessionServer(t *testing.T, srv *fakeSessionServer, ca *bootstrapca.CA) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// enrollment.TLSConfig() (used by the real runSession, production
	// code) sets no explicit ServerName, so grpc derives it from the dial
	// target's host -- here the loopback IP. Issue the server cert with
	// that IP as a SAN (IssueServerCertificate treats IP-shaped names as
	// IP SANs) so verification succeeds without needing test-only
	// overrides to runSession itself.
	serverCert, err := ca.IssueServerCertificate([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	rcaprobev1.RegisterProbeGatewayServer(grpcServer, srv)
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String()
}

// --- mTLS session listener that also serves Bootstrap.Enroll renewal
// (design.md Section 8.4a: "the Bootstrap service is registered on both
// listeners") for maybeRenew/bootstrapclient.Renew tests --------------------

// mainRenewalBootstrapServer is a minimal Bootstrap.Enroll double
// supporting only design.md Section 8.4a's renewal path (empty
// bootstrap_token + a verified, unexpired mTLS client certificate with
// CN == platform_key) -- mirroring the real
// services/probe-gateway/internal/bootstrapsrv logic this package cannot
// import (Go internal-package visibility restricts
// services/probe-gateway/internal/* to code rooted at
// services/probe-gateway/, the same reason bootstrapclient's own test
// package reimplements a minimal double; see its package comment).
type mainRenewalBootstrapServer struct {
	rcaprobev1.UnimplementedBootstrapServer
	ca *bootstrapca.CA
}

func (s *mainRenewalBootstrapServer) Enroll(ctx context.Context, req *rcaprobev1.EnrollRequest) (*rcaprobev1.EnrollResponse, error) {
	if req.GetBootstrapToken() != "" {
		return nil, fmt.Errorf("mainRenewalBootstrapServer: only renewal (empty bootstrap_token) is supported")
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, fmt.Errorf("mainRenewalBootstrapServer: no peer TLS info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, fmt.Errorf("mainRenewalBootstrapServer: no client certificate presented")
	}
	cn := tlsInfo.State.PeerCertificates[0].Subject.CommonName
	if cn != req.GetPlatformKey() {
		return nil, fmt.Errorf("mainRenewalBootstrapServer: cert CN %q does not match platform_key %q", cn, req.GetPlatformKey())
	}
	certPEM, err := s.ca.SignCSR(req.GetCsrPem(), req.GetPlatformKey())
	if err != nil {
		return nil, err
	}
	return &rcaprobev1.EnrollResponse{ClientCertPem: certPEM, CaCertPem: s.ca.CACertPEM()}, nil
}

func startMTLSSessionServerWithRenewal(t *testing.T, srv *fakeSessionServer, ca *bootstrapca.CA) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverCert, err := ca.IssueServerCertificate([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	rcaprobev1.RegisterProbeGatewayServer(grpcServer, srv)
	rcaprobev1.RegisterBootstrapServer(grpcServer, &mainRenewalBootstrapServer{ca: ca})
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String()
}

func TestMaybeRenew_RenewsWhenDueForRenewal(t *testing.T) {
	ca := testMainCA(t)
	addr := startMTLSSessionServerWithRenewal(t, newFakeSessionServer(), ca)

	// 24h total validity, 1h remaining -- well under the 50% threshold.
	certPEM, keyPEM := issueMainClientCertWithValidity(t, ca, "presto-us1", -23*time.Hour, 1*time.Hour)
	current := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}
	dir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	renewed := maybeRenew(ctx, config.Probe{PlatformKey: "presto-us1", GatewayAddress: addr, StateDir: dir}, current)

	if string(renewed.ClientCertPEM) == string(certPEM) {
		t.Fatalf("expected a renewed (different) client certificate")
	}
	if _, expired, err := renewed.RenewalStatus(time.Now()); err != nil || expired {
		t.Fatalf("expected the renewed cert to be unexpired, err=%v expired=%v", err, expired)
	}

	loaded, found, err := bootstrapclient.LoadIfPresent(dir)
	if err != nil || !found {
		t.Fatalf("expected the renewed cert to be persisted, found=%v err=%v", found, err)
	}
	if string(loaded.ClientCertPEM) != string(renewed.ClientCertPEM) {
		t.Fatalf("persisted cert does not match the renewed cert")
	}
}

func TestMaybeRenew_NoOpWhenFreshCert(t *testing.T) {
	ca := testMainCA(t)
	certPEM, keyPEM := issueMainClientCert(t, ca, "presto-us1") // fresh 24h cert, nowhere near the 50% threshold
	current := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}

	// Deliberately unreachable: a renewal attempt would fail/hang, proving
	// maybeRenew never even tries when the cert isn't due for renewal.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := maybeRenew(ctx, config.Probe{PlatformKey: "presto-us1", GatewayAddress: "127.0.0.1:1", StateDir: t.TempDir()}, current)
	if string(result.ClientCertPEM) != string(certPEM) {
		t.Fatalf("expected the same certificate to be returned unchanged")
	}
}

func TestMaybeRenew_NoOpWhenExpired(t *testing.T) {
	ca := testMainCA(t)
	certPEM, keyPEM := issueMainClientCertWithValidity(t, ca, "presto-us1", -25*time.Hour, -1*time.Hour)
	current := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}

	// design.md Section 8.4a: no silent renewal path for an already-expired
	// certificate -- maybeRenew must leave it untouched (ensureEnrolled is
	// what handles the fresh-token fallback, and only at startup).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := maybeRenew(ctx, config.Probe{PlatformKey: "presto-us1", GatewayAddress: "127.0.0.1:1", StateDir: t.TempDir()}, current)
	if string(result.ClientCertPEM) != string(certPEM) {
		t.Fatalf("expected the expired certificate to be returned unchanged (no renewal attempt)")
	}
}

func TestMaybeRenew_FailureIsNonFatalAndReturnsExisting(t *testing.T) {
	ca := testMainCA(t)
	certPEM, keyPEM := issueMainClientCertWithValidity(t, ca, "presto-us1", -23*time.Hour, 1*time.Hour) // due for renewal
	current := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}

	// Due for renewal, but the gateway is unreachable -> Renew fails; the
	// probe must keep using the still-valid existing certificate rather
	// than crashing or losing its identity.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result := maybeRenew(ctx, config.Probe{PlatformKey: "presto-us1", GatewayAddress: "127.0.0.1:1", StateDir: t.TempDir()}, current)
	if string(result.ClientCertPEM) != string(certPEM) {
		t.Fatalf("expected the existing certificate to be returned when renewal fails")
	}
}

func TestMaybeRenew_RenewalRejectedOnCNMismatch(t *testing.T) {
	ca := testMainCA(t)
	addr := startMTLSSessionServerWithRenewal(t, newFakeSessionServer(), ca)

	// Certificate is CN=presto-a but the probe config claims platform_key
	// presto-b -- the renewal server must reject this (design.md Section
	// 8.4a identity binding applies to renewal too), and maybeRenew must
	// treat that failure the same as any other renewal failure: keep the
	// existing certificate.
	certPEM, keyPEM := issueMainClientCertWithValidity(t, ca, "presto-a", -23*time.Hour, 1*time.Hour)
	current := &bootstrapclient.Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := maybeRenew(ctx, config.Probe{PlatformKey: "presto-b", GatewayAddress: addr, StateDir: t.TempDir()}, current)
	if string(result.ClientCertPEM) != string(certPEM) {
		t.Fatalf("expected the existing certificate to be returned when the renewal server rejects a CN mismatch")
	}
}
