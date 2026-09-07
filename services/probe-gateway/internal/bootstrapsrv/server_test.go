package bootstrapsrv

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
)

func generateCSR(t *testing.T, cn string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, PublicKey: pub}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// newBufconnClient starts an in-process gRPC server (design.md Section
// 14.2: "Probes via in-process gRPC (bufconn)") hosting the Bootstrap
// service and returns a connected client + registry for the test to seed.
func newBufconnClient(t *testing.T) (rcaprobev1.BootstrapClient, registry.Registry, *bootstrapca.CA) {
	t.Helper()
	dir := t.TempDir()
	ca, err := bootstrapca.Bootstrap(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrap ca: %v", err)
	}
	reg := registry.NewFake()

	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	rcaprobev1.RegisterBootstrapServer(grpcServer, New(ca, reg))
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return rcaprobev1.NewBootstrapClient(conn), reg, ca
}

func TestEnroll_Success(t *testing.T) {
	client, reg, ca := newBufconnClient(t)
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1"); err != nil {
		t.Fatalf("seed platform: %v", err)
	}

	resp, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey:    "presto-us1",
		BootstrapToken: "tok-1",
		CsrPem:         generateCSR(t, "presto-us1"),
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetClientCertPem()) == 0 {
		t.Fatalf("expected a client cert")
	}
	if string(resp.GetCaCertPem()) != string(ca.CACertPEM()) {
		t.Fatalf("expected the CA cert to be returned")
	}

	// Bootstrap token is single-use (F8 checkpoint).
	_, err = client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-us1", BootstrapToken: "tok-1", CsrPem: generateCSR(t, "presto-us1"),
	})
	if status.Code(err) == 0 {
		t.Fatalf("expected the second Enroll with the same token to fail")
	}
}

func TestEnroll_UnknownPlatform(t *testing.T) {
	client, _, _ := newBufconnClient(t)
	_, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "does-not-exist", BootstrapToken: "tok-1", CsrPem: generateCSR(t, "x"),
	})
	if err == nil {
		t.Fatalf("expected error for unknown platform")
	}
}

func TestEnroll_WrongToken(t *testing.T) {
	client, reg, _ := newBufconnClient(t)
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "correct-token")

	_, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-us1", BootstrapToken: "wrong-token", CsrPem: generateCSR(t, "presto-us1"),
	})
	if err == nil {
		t.Fatalf("expected error for wrong token")
	}
}

func TestEnroll_MissingFields(t *testing.T) {
	client, _, _ := newBufconnClient(t)
	_, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{})
	if err == nil {
		t.Fatalf("expected error for missing fields")
	}
}

func TestEnroll_InvalidCSR(t *testing.T) {
	client, reg, _ := newBufconnClient(t)
	_ = reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1")

	_, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-us1", BootstrapToken: "tok-1", CsrPem: []byte("not a csr"),
	})
	if err == nil {
		t.Fatalf("expected error for invalid CSR")
	}
}

// --- design.md Section 8.4a: renewal (required M3 fix) -----------------------------
//
// Renewal is reached via the mTLS `Session` listener, not the token-only
// Bootstrap one -- these tests use a real TLS-secured (RequireAndVerify-
// ClientCert) bufconn listener to model that, rather than the plaintext
// bufconn newBufconnClient above uses for the token-based tests (which
// intentionally has no peer certificate at all).

// issueCert signs a client cert for cn with an explicit validity window
// via SignCSRWithValidity, so renewal tests can deterministically craft
// "not yet expired" vs "already expired" certificates. Unlike
// generateCSR (which only returns the CSR, discarding its private key --
// fine for the token-based tests above that never need to present the
// resulting cert over a real TLS handshake), this keeps the matching
// private key so the returned cert/key pair is usable as mTLS client
// credentials.
func issueCert(t *testing.T, ca *bootstrapca.CA, cn string, notBeforeOffset, notAfterOffset time.Duration) (certPEM, keyPEM []byte) {
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

// newMTLSBufconnClient starts an in-process gRPC server requiring and
// verifying a client certificate (modeling the real mTLS Session
// listener the Bootstrap service is also registered on for renewal,
// services/probe-gateway/cmd/probe-gateway), and returns a dial function
// that connects using the given client cert/key.
func newMTLSBufconnClient(t *testing.T) (dial func(certPEM, keyPEM []byte) rcaprobev1.BootstrapClient, reg registry.Registry, ca *bootstrapca.CA) {
	t.Helper()
	dir := t.TempDir()
	ca, err := bootstrapca.Bootstrap(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrap ca: %v", err)
	}
	reg = registry.NewFake()

	lis := bufconn.Listen(1024 * 1024)
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
	rcaprobev1.RegisterBootstrapServer(grpcServer, New(ca, reg))
	go func() { _ = grpcServer.Serve(lis) }()
	t.Cleanup(grpcServer.Stop)

	dial = func(certPEM, keyPEM []byte) rcaprobev1.BootstrapClient {
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatalf("load client keypair: %v", err)
		}
		clientTLS := &tls.Config{Certificates: []tls.Certificate{clientCert}, RootCAs: pool, ServerName: "127.0.0.1"}
		conn, err := grpc.NewClient("passthrough:///bufnet",
			grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
			grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)),
		)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return rcaprobev1.NewBootstrapClient(conn)
	}
	return dial, reg, ca
}

func TestEnroll_RenewalViaMTLS_Success(t *testing.T) {
	dial, reg, ca := newMTLSBufconnClient(t)
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1"); err != nil {
		t.Fatalf("seed platform: %v", err)
	}

	// The renewing probe already has a valid (not yet expired) cert.
	existingCertPEM, existingKeyPEM := issueCert(t, ca, "presto-us1", -23*time.Hour, 1*time.Hour)
	client := dial(existingCertPEM, existingKeyPEM)

	resp, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-us1",
		CsrPem:      generateCSR(t, "presto-us1"),
		// BootstrapToken intentionally empty: renewal.
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetClientCertPem()) == 0 {
		t.Fatalf("expected a renewed client cert")
	}
	if string(resp.GetClientCertPem()) == string(existingCertPEM) {
		t.Fatalf("expected a genuinely new certificate, not the same bytes")
	}
}

func TestEnroll_RenewalCNMismatch_Rejected(t *testing.T) {
	dial, reg, ca := newMTLSBufconnClient(t)
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-a"}, "tok-a"); err != nil {
		t.Fatalf("seed platform a: %v", err)
	}
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-b"}, "tok-b"); err != nil {
		t.Fatalf("seed platform b: %v", err)
	}

	// Certificate authenticates as presto-a; the renewal request claims
	// presto-b -- must be rejected (design.md Section 8.4a identity
	// binding, "a certificate issued for one platform must never be able
	// to register (or renew) as another").
	certPEM, keyPEM := issueCert(t, ca, "presto-a", -23*time.Hour, 1*time.Hour)
	client := dial(certPEM, keyPEM)

	_, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-b",
		CsrPem:      generateCSR(t, "presto-b"),
	})
	if err == nil {
		t.Fatalf("expected an error for a CN/platform_key mismatch on renewal")
	}
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied, got %v", status.Code(err))
	}
}

func TestEnroll_RenewalUnknownPlatform_Rejected(t *testing.T) {
	dial, _, ca := newMTLSBufconnClient(t)
	// Cert CN references a platform that was never created in the
	// registry -- covers design.md Section 8.4a's revocation story
	// ("deleting... a platform blocks... renewal"): a certificate remains
	// cryptographically valid even after its platform is gone.
	certPEM, keyPEM := issueCert(t, ca, "ghost-platform", -23*time.Hour, 1*time.Hour)
	client := dial(certPEM, keyPEM)

	_, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "ghost-platform",
		CsrPem:      generateCSR(t, "ghost-platform"),
	})
	if err == nil {
		t.Fatalf("expected an error for an unknown platform")
	}
}

func TestEnroll_RenewalWithoutClientCert_Rejected(t *testing.T) {
	// The plaintext bufconn client (newBufconnClient) carries no TLS peer
	// info at all -- an empty bootstrap_token there must be rejected, not
	// silently treated as authenticated.
	client, reg, _ := newBufconnClient(t)
	if err := reg.CreatePlatform(context.Background(), registry.Platform{PlatformKey: "presto-us1"}, "tok-1"); err != nil {
		t.Fatalf("seed platform: %v", err)
	}

	_, err := client.Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: "presto-us1", CsrPem: generateCSR(t, "presto-us1"),
	})
	if err == nil {
		t.Fatalf("expected an error for a token-less Enroll with no client certificate")
	}
}

// authenticateRenewal's expiry check is defense in depth (production TLS
// transport already rejects an expired client cert during the handshake,
// so an expired-but-otherwise-valid-looking peer context can't occur via
// a real dial) -- tested directly here by constructing the peer context
// by hand, the standard gRPC testing pattern for AuthInfo-dependent logic.
func TestAuthenticateRenewal_ExpiredCertRejected(t *testing.T) {
	dir := t.TempDir()
	ca, err := bootstrapca.Bootstrap(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("bootstrap ca: %v", err)
	}
	reg := registry.NewFake()
	srv := New(ca, reg)

	certPEM, _ := issueCert(t, ca, "presto-us1", -25*time.Hour, -1*time.Hour) // already expired
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}

	ctx := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}},
	})
	if err := srv.authenticateRenewal(ctx, "presto-us1"); err == nil {
		t.Fatalf("expected an error for an expired client certificate")
	}
}

func TestAuthenticateRenewal_NoPeerInfoRejected(t *testing.T) {
	srv := New(nil, registry.NewFake())
	if err := srv.authenticateRenewal(context.Background(), "presto-us1"); err == nil {
		t.Fatalf("expected an error when the context carries no peer info")
	}
}

// fakeNonTLSAuthInfo satisfies credentials.AuthInfo without being
// credentials.TLSInfo -- e.g. what insecure.NewCredentials() attaches to
// a connection, modeling a non-mTLS transport reaching authenticateRenewal.
type fakeNonTLSAuthInfo struct{}

func (fakeNonTLSAuthInfo) AuthType() string { return "insecure" }

func TestAuthenticateRenewal_NonTLSAuthInfoRejected(t *testing.T) {
	srv := New(nil, registry.NewFake())
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: fakeNonTLSAuthInfo{}})
	if err := srv.authenticateRenewal(ctx, "presto-us1"); err == nil {
		t.Fatalf("expected an error for non-TLS AuthInfo")
	}
}
