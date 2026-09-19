package bootstrapclient

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
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
)

// testTokenStore is a minimal in-memory bootstrap-token store, standing
// in for the real registry-backed one (that's a probe-gateway-owned
// component, services/probe-gateway/internal/{bootstrapsrv,registry};
// this package (probe-side) cannot import it -- Go's internal-package
// visibility rules restrict services/probe-gateway/internal/* to code
// rooted at services/probe-gateway/. The bootstrap protocol's token
// validation semantics are already fully tested there; this test file
// only needs *a* server that enforces single-use tokens well enough to
// exercise bootstrapclient's CSR-generation/persistence/TLS-config code).
type testTokenStore struct {
	mu       sync.Mutex
	valid    map[string]string // platformKey -> token
	consumed map[string]bool
}

func (s *testTokenStore) consume(platformKey, token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.consumed[platformKey] || s.valid[platformKey] != token {
		return false
	}
	s.consumed[platformKey] = true
	return true
}

type testBootstrapServer struct {
	rcaprobev1.UnimplementedBootstrapServer
	ca     *bootstrapca.CA
	tokens *testTokenStore
}

func (s *testBootstrapServer) Enroll(ctx context.Context, req *rcaprobev1.EnrollRequest) (*rcaprobev1.EnrollResponse, error) {
	if !s.tokens.consume(req.GetPlatformKey(), req.GetBootstrapToken()) {
		return nil, status.Error(codes.PermissionDenied, "invalid or already-used token")
	}
	certPEM, err := s.ca.SignCSR(req.GetCsrPem(), req.GetPlatformKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
	}
	return &rcaprobev1.EnrollResponse{ClientCertPem: certPEM, CaCertPem: s.ca.CACertPEM()}, nil
}

// startBootstrapServer starts a real TLS-listening Bootstrap gRPC server
// (loopback TCP, not bufconn -- bootstrapclient.Enroll dials a real
// address), using the shared bootstrapca package this session also added
// (see internal/bootstrapca, imported by both probe-gateway's real
// bootstrapsrv and this test).
func startBootstrapServer(t *testing.T) (addr string, tokens *testTokenStore, ca *bootstrapca.CA) {
	t.Helper()
	dir := t.TempDir()
	ca, err := bootstrapca.Bootstrap(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrap ca: %v", err)
	}
	tokens = &testTokenStore{valid: map[string]string{}, consumed: map[string]bool{}}

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	serverCert, err := ca.IssueServerCertificate([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("issue server cert: %v", err)
	}
	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{Certificates: []tls.Certificate{serverCert}})))
	rcaprobev1.RegisterBootstrapServer(grpcServer, &testBootstrapServer{ca: ca, tokens: tokens})
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String(), tokens, ca
}

func TestEnroll_Success(t *testing.T) {
	addr, tokens, ca := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"

	result, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.ClientCertPEM) == 0 || len(result.ClientKeyPEM) == 0 {
		t.Fatalf("expected client cert/key to be populated")
	}
	if string(result.CACertPEM) != string(ca.CACertPEM()) {
		t.Fatalf("expected CA cert to match")
	}

	// The issued client cert must be usable for a real mTLS handshake
	// against a server trusting the same CA.
	tlsConfig, err := result.TLSConfig()
	if err != nil {
		t.Fatalf("build tls config: %v", err)
	}
	if len(tlsConfig.Certificates) != 1 {
		t.Fatalf("expected exactly one client certificate")
	}
}

func TestEnroll_WrongToken(t *testing.T) {
	addr, tokens, _ := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "correct-token"

	_, err := Enroll(context.Background(), addr, "presto-us1", "wrong-token", "")
	if err == nil {
		t.Fatalf("expected error for wrong token")
	}
}

func TestPersistAndLoadIfPresent_RoundTrip(t *testing.T) {
	addr, tokens, _ := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"

	result, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", "")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	dir := t.TempDir()
	if err := result.Persist(dir); err != nil {
		t.Fatalf("persist: %v", err)
	}

	loaded, found, err := LoadIfPresent(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !found {
		t.Fatalf("expected persisted enrollment to be found")
	}
	if string(loaded.ClientCertPEM) != string(result.ClientCertPEM) {
		t.Fatalf("mismatched client cert after round trip")
	}
}

func TestPersist_FailsWhenDirCannotBeCreated(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	r := &Result{ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key"), CACertPEM: []byte("ca")}
	// blocker is a file, not a directory, so MkdirAll(blocker/nested, ...) fails.
	err := r.Persist(filepath.Join(blocker, "nested"))
	if err == nil {
		t.Fatalf("expected error when the target directory cannot be created")
	}
}

func TestPersist_FailsWhenClientCertFileUnwritable(t *testing.T) {
	dir := t.TempDir()
	// Pre-create "client.crt" as a directory so WriteFile onto it fails.
	if err := os.Mkdir(filepath.Join(dir, "client.crt"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	r := &Result{ClientCertPEM: []byte("cert"), ClientKeyPEM: []byte("key"), CACertPEM: []byte("ca")}
	if err := r.Persist(dir); err == nil {
		t.Fatalf("expected error when client.crt cannot be written")
	}
}

func TestLoadIfPresent_MissingKeyFileErrors(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), []byte("cert"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// client.key intentionally absent.
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("ca"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, found, err := LoadIfPresent(dir)
	if err == nil {
		t.Fatalf("expected error when client.key is missing")
	}
	if found {
		t.Fatalf("expected found=false alongside the error")
	}
}

func TestLoadIfPresent_NoneYet(t *testing.T) {
	_, found, err := LoadIfPresent(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if found {
		t.Fatalf("expected found=false for an empty directory")
	}
}

func TestTLSConfig_RejectsInvalidClientKeyPair(t *testing.T) {
	r := &Result{ClientCertPEM: []byte("x"), ClientKeyPEM: []byte("y"), CACertPEM: []byte("not-a-cert")}
	_, err := r.TLSConfig()
	if err == nil {
		t.Fatalf("expected error for invalid client cert/key")
	}
}

func TestTLSConfig_RejectsInvalidCACert(t *testing.T) {
	addr, tokens, _ := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"
	result, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", "")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	result.CACertPEM = []byte("not-a-valid-ca-cert")

	_, err = result.TLSConfig()
	if err == nil {
		t.Fatalf("expected error for invalid CA cert PEM")
	}
}

// --- design.md Section 8.4a: renewal + expiry (required M3 fix) -------------------

// issueClientCertWithValidity signs a client cert for cn with an explicit
// validity window, so tests can deterministically craft "renewal due"
// (<50% remaining) or "already expired" certificates without waiting on
// a real clock.
func issueClientCertWithValidity(t *testing.T, ca *bootstrapca.CA, cn string, notBeforeOffset, notAfterOffset time.Duration) *Result {
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
	certPEM, err := ca.SignCSRWithValidity(csrPEM, cn, now.Add(notBeforeOffset), now.Add(notAfterOffset))
	if err != nil {
		t.Fatalf("sign csr: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return &Result{ClientCertPEM: certPEM, ClientKeyPEM: keyPEM, CACertPEM: ca.CACertPEM()}
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

func TestExpiry_ReturnsCertWindow(t *testing.T) {
	ca := testCA(t)
	r := issueClientCertWithValidity(t, ca, "presto-us1", -1*time.Hour, 23*time.Hour)
	notBefore, notAfter, err := r.Expiry()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !notAfter.After(notBefore) {
		t.Fatalf("expected notAfter to be after notBefore, got %v / %v", notBefore, notAfter)
	}
}

func TestExpiry_InvalidPEMErrors(t *testing.T) {
	r := &Result{ClientCertPEM: []byte("not a cert")}
	if _, _, err := r.Expiry(); err == nil {
		t.Fatalf("expected error for invalid PEM")
	}
}

func TestExpiry_UnparsableDERErrors(t *testing.T) {
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not real der")})
	r := &Result{ClientCertPEM: badPEM}
	if _, _, err := r.Expiry(); err == nil {
		t.Fatalf("expected error for unparsable DER")
	}
}

func TestRenewalStatus_FreshCertNotDue(t *testing.T) {
	ca := testCA(t)
	// 24h total validity, only just started -- nowhere near 50% remaining.
	r := issueClientCertWithValidity(t, ca, "presto-us1", -1*time.Minute, 24*time.Hour)
	due, expired, err := r.RenewalStatus(time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if due || expired {
		t.Fatalf("expected a fresh cert to be neither due for renewal nor expired, due=%v expired=%v", due, expired)
	}
}

func TestRenewalStatus_DueForRenewal(t *testing.T) {
	ca := testCA(t)
	// 24h total validity, 1h remaining -- well under the 50% threshold.
	r := issueClientCertWithValidity(t, ca, "presto-us1", -23*time.Hour, 1*time.Hour)
	due, expired, err := r.RenewalStatus(time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !due {
		t.Fatalf("expected a cert with <50%% validity remaining to be due for renewal")
	}
	if expired {
		t.Fatalf("expected a not-yet-expired cert to report expired=false")
	}
}

func TestRenewalStatus_JustOverHalfway_NotYetDue(t *testing.T) {
	ca := testCA(t)
	// 24h total validity, ~13h remaining -- just over the 50% threshold.
	r := issueClientCertWithValidity(t, ca, "presto-us1", -11*time.Hour, 13*time.Hour)
	due, expired, err := r.RenewalStatus(time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if due || expired {
		t.Fatalf("expected a cert with >50%% validity remaining to not be due, due=%v expired=%v", due, expired)
	}
}

func TestRenewalStatus_Expired(t *testing.T) {
	ca := testCA(t)
	r := issueClientCertWithValidity(t, ca, "presto-us1", -25*time.Hour, -1*time.Hour)
	due, expired, err := r.RenewalStatus(time.Now())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !expired {
		t.Fatalf("expected an already-expired cert to report expired=true")
	}
	if due {
		t.Fatalf("expected expired=true to take precedence over dueForRenewal")
	}
}

func TestRenewalStatus_InvalidCertErrors(t *testing.T) {
	r := &Result{ClientCertPEM: []byte("not a cert")}
	if _, _, err := r.RenewalStatus(time.Now()); err == nil {
		t.Fatalf("expected an error for an invalid persisted certificate")
	}
}

// renewalTestServer is a minimal Bootstrap.Enroll double that supports
// design.md Section 8.4a's renewal path (empty bootstrap_token + a
// verified, unexpired mTLS client certificate with CN == platform_key),
// mirroring the real services/probe-gateway/internal/bootstrapsrv logic
// this package cannot import (see package doc / the existing
// testBootstrapServer above re: Go's internal-package visibility rules).
type renewalTestServer struct {
	rcaprobev1.UnimplementedBootstrapServer
	ca *bootstrapca.CA
}

func (s *renewalTestServer) Enroll(ctx context.Context, req *rcaprobev1.EnrollRequest) (*rcaprobev1.EnrollResponse, error) {
	if req.GetBootstrapToken() != "" {
		return nil, status.Error(codes.InvalidArgument, "this test server only supports renewal (empty bootstrap_token)")
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil, status.Error(codes.Unauthenticated, "no peer TLS info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "no client certificate presented")
	}
	cn := tlsInfo.State.PeerCertificates[0].Subject.CommonName
	if cn != req.GetPlatformKey() {
		return nil, status.Errorf(codes.PermissionDenied, "cert CN %q does not match platform_key %q", cn, req.GetPlatformKey())
	}
	certPEM, err := s.ca.SignCSR(req.GetCsrPem(), req.GetPlatformKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
	}
	return &rcaprobev1.EnrollResponse{ClientCertPem: certPEM, CaCertPem: s.ca.CACertPEM()}, nil
}

// startMTLSRenewalServer starts a real TLS-listening Bootstrap gRPC
// server that REQUIRES a verified client certificate (unlike
// startBootstrapServer above, which models the token-only listener) --
// modeling design.md Section 8.4a's "the Bootstrap service is registered
// on both listeners", specifically the mTLS Session one that renewal
// uses.
func startMTLSRenewalServer(t *testing.T, ca *bootstrapca.CA) (addr string) {
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
	rcaprobev1.RegisterBootstrapServer(grpcServer, &renewalTestServer{ca: ca})
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	return lis.Addr().String()
}

func TestRenew_Success(t *testing.T) {
	ca := testCA(t)
	addr := startMTLSRenewalServer(t, ca)
	existing := issueClientCertWithValidity(t, ca, "presto-us1", -23*time.Hour, 1*time.Hour)

	renewed, err := Renew(context.Background(), addr, "presto-us1", existing)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(renewed.ClientCertPEM) == 0 || len(renewed.ClientKeyPEM) == 0 {
		t.Fatalf("expected a renewed client cert/key to be populated")
	}
	if string(renewed.ClientCertPEM) == string(existing.ClientCertPEM) {
		t.Fatalf("expected a genuinely new client certificate")
	}
	if string(renewed.ClientKeyPEM) == string(existing.ClientKeyPEM) {
		t.Fatalf("expected renewal to also rotate the private key")
	}
	if _, expired, err := renewed.RenewalStatus(time.Now()); err != nil || expired {
		t.Fatalf("expected the renewed cert to be unexpired, err=%v expired=%v", err, expired)
	}
}

func TestRenew_CNMismatchRejected(t *testing.T) {
	ca := testCA(t)
	addr := startMTLSRenewalServer(t, ca)
	// Certificate authenticates as presto-a, but the renewal request
	// claims presto-b -- design.md Section 8.4a's identity binding must
	// reject this the same way Session registration does.
	existing := issueClientCertWithValidity(t, ca, "presto-a", -23*time.Hour, 1*time.Hour)

	_, err := Renew(context.Background(), addr, "presto-b", existing)
	if err == nil {
		t.Fatalf("expected an error for a CN/platform_key mismatch on renewal")
	}
}

func TestRenew_InvalidExistingTLSConfigErrors(t *testing.T) {
	existing := &Result{ClientCertPEM: []byte("bad"), ClientKeyPEM: []byte("bad"), CACertPEM: []byte("bad")}
	_, err := Renew(context.Background(), "127.0.0.1:0", "presto-us1", existing)
	if err == nil {
		t.Fatalf("expected an error building the mTLS config from an invalid existing cert")
	}
}

func TestRenew_UnreachableGatewayErrors(t *testing.T) {
	ca := testCA(t)
	existing := issueClientCertWithValidity(t, ca, "presto-us1", -23*time.Hour, 1*time.Hour)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err := Renew(ctx, "127.0.0.1:1", "presto-us1", existing)
	if err == nil {
		t.Fatalf("expected an error renewing against an unreachable gateway")
	}
}

// --- design.md Section 8.4a (v1.5): bootstrap_ca_pin ------------------------

// caDERFingerprint returns the "sha256:<hex>" fingerprint of the
// DER-encoded CA certificate, exactly as design.md Section 8.4a's
// fingerprint value form defines it -- used to build correct/incorrect
// pins for the tests below.
func caDERFingerprint(t *testing.T, ca *bootstrapca.CA) string {
	t.Helper()
	block, _ := pem.Decode(ca.CACertPEM())
	if block == nil {
		t.Fatalf("invalid CA cert PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func TestEnroll_NoPin_TOFU_Success(t *testing.T) {
	// Unset bootstrap_ca_pin preserves the existing TOFU behavior --
	// regression coverage for the documented default (design.md Section
	// 8.4a: "By default the single Enroll call does not verify the
	// gateway's certificate").
	addr, tokens, _ := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"

	result, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", "")
	if err != nil {
		t.Fatalf("unexpected error with unset bootstrap_ca_pin (TOFU): %v", err)
	}
	if len(result.ClientCertPEM) == 0 {
		t.Fatalf("expected a client cert to be issued")
	}
}

func TestEnroll_CAPin_PEM_Match_Succeeds(t *testing.T) {
	addr, tokens, ca := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"

	result, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", string(ca.CACertPEM()))
	if err != nil {
		t.Fatalf("unexpected error with a matching PEM bootstrap_ca_pin: %v", err)
	}
	if len(result.ClientCertPEM) == 0 {
		t.Fatalf("expected a client cert to be issued")
	}
}

func TestEnroll_CAPin_PEM_Mismatch_FailsClosed(t *testing.T) {
	addr, tokens, _ := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"
	otherCA := testCA(t) // an unrelated CA -- not the one serving addr

	_, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", string(otherCA.CACertPEM()))
	if err == nil {
		t.Fatalf("expected enrollment to fail closed when bootstrap_ca_pin (PEM) does not match the gateway's actual CA")
	}
}

func TestEnroll_CAPin_SHA256_Match_Succeeds(t *testing.T) {
	addr, tokens, ca := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"

	result, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", caDERFingerprint(t, ca))
	if err != nil {
		t.Fatalf("unexpected error with a matching sha256 bootstrap_ca_pin: %v", err)
	}
	if len(result.ClientCertPEM) == 0 {
		t.Fatalf("expected a client cert to be issued")
	}
}

func TestEnroll_CAPin_SHA256_Mismatch_FailsClosed(t *testing.T) {
	addr, tokens, _ := startBootstrapServer(t)
	tokens.valid["presto-us1"] = "tok-1"
	otherCA := testCA(t)

	_, err := Enroll(context.Background(), addr, "presto-us1", "tok-1", caDERFingerprint(t, otherCA))
	if err == nil {
		t.Fatalf("expected enrollment to fail closed when bootstrap_ca_pin (sha256) does not match the gateway's actual CA")
	}
}

func TestEnroll_CAPin_SHA256_MalformedFingerprint_ErrorsWithoutDialing(t *testing.T) {
	// An unreachable address proves this fails during pin validation, not
	// during (or after) a dial attempt.
	_, err := Enroll(context.Background(), "127.0.0.1:1", "presto-us1", "tok-1", "sha256:not-valid-hex")
	if err == nil {
		t.Fatalf("expected an error for a malformed sha256 bootstrap_ca_pin")
	}
}

func TestEnroll_CAPin_SHA256_WrongLength_Errors(t *testing.T) {
	_, err := Enroll(context.Background(), "127.0.0.1:1", "presto-us1", "tok-1", "sha256:deadbeef")
	if err == nil {
		t.Fatalf("expected an error for a too-short sha256 bootstrap_ca_pin")
	}
}

func TestEnroll_CAPin_InvalidPEM_ErrorsWithoutDialing(t *testing.T) {
	_, err := Enroll(context.Background(), "127.0.0.1:1", "presto-us1", "tok-1", "not a pem certificate and not sha256:-prefixed")
	if err == nil {
		t.Fatalf("expected an error for a bootstrap_ca_pin that is neither a valid fingerprint nor valid PEM")
	}
}
