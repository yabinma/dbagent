// design.md Section 8.4a (D16, normative as of v1.3): two required M3
// fixes to the mTLS bootstrap mechanism M2 introduced -- certificate
// renewal (24h client certs previously had no renewal path, so probes
// went permanently offline after a day) and CN <-> platform_key identity
// binding (a certificate issued for one platform must never be usable to
// register/renew as another). These tests exercise both against the
// REAL, compiled probe-gateway binary (the same subprocess/real-mTLS/
// real-Postgres infra registration_test.go's F8 tests use, built once in
// TestMain): a real certificate is obtained from the real gateway
// subprocess over the real Bootstrap protocol, then used (correctly, for
// renewal; and abusively, for the cross-platform substitution the
// CN-binding fix must reject) directly against that same subprocess's
// real mTLS Session listener via a hand-rolled gRPC client -- the real
// `probe` binary always behaves correctly and so can't exercise the
// misuse scenarios these tests are specifically about.
package m2_probe_link

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
)

// generateFunctestCSR builds a fresh PKCS#10 CSR for the given CN,
// returning the matching PEM-encoded private key too (design.md Section
// 8.4a: renewal rotates the private key, same as first enrollment, so
// the cert returned by a renewal RPC is only usable together with THIS
// new key, not whatever key the pre-renewal certificate used).
func generateFunctestCSR(t *testing.T, cn string) (csrPEM, keyPEM []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}, PublicKey: pub}, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM
}

// enrollDirect performs a real token-based Bootstrap.Enroll against the
// gateway subprocess's real bootstrap listener, returning the raw
// PEM-encoded client cert/key/CA.
func enrollDirect(t *testing.T, bootstrapAddr, platformKey, token string) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: platformKey}, PublicKey: pub}, priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	conn, err := grpc.NewClient(bootstrapAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{InsecureSkipVerify: true}))) //nolint:gosec
	if err != nil {
		t.Fatalf("dial bootstrap listener: %v", err)
	}
	defer conn.Close()

	resp, err := rcaprobev1.NewBootstrapClient(conn).Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: platformKey, BootstrapToken: token, CsrPem: csrPEM,
	})
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return resp.GetClientCertPem(), keyPEM, resp.GetCaCertPem()
}

// dialSessionListenerWithCert opens a raw mTLS connection to the
// gateway's real Session listener using the given client cert/key + CA.
func dialSessionListenerWithCert(t *testing.T, sessionAddr string, certPEM, keyPEM, caPEM []byte) *grpc.ClientConn {
	t.Helper()
	clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("load client keypair: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("failed to parse CA cert PEM")
	}
	conn, err := grpc.NewClient(sessionAddr, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      pool,
	})))
	if err != nil {
		t.Fatalf("dial session listener: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestBootstrapFix_CrossPlatformCertSubstitution_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, _, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	const platformA = "presto-fix-a"
	const platformB = "presto-fix-b"
	seedPlatform(t, dsn, platformA, "tok-fix-a")
	seedPlatform(t, dsn, platformB, "tok-fix-b")

	// A real certificate, genuinely issued (by the real gateway
	// subprocess, over the real Bootstrap protocol) for platform A.
	certPEM, keyPEM, caPEM := enrollDirect(t, gw.bootstrapAddr, platformA, "tok-fix-a")

	// Attempt to register as platform B using that certificate. Section
	// 8.4a: "probe-gateway MUST reject a Session registration whose
	// Register.platform_key differs from the CN of the verified client
	// certificate."
	conn := dialSessionListenerWithCert(t, gw.sessionAddr, certPEM, keyPEM, caPEM)
	stream, err := rcaprobev1.NewProbeGatewayClient(conn).Session(context.Background())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{PlatformKey: platformB, ProbeVersion: "0.1.0"},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	ack := msg.GetAck()
	if ack == nil || ack.GetAccepted() {
		t.Fatalf("expected the real gateway to reject cross-platform cert substitution, got %+v", msg)
	}

	// And platform B was never touched by this attempted forgery.
	if countProbesForPlatform(t, dsn, platformB) != 0 {
		t.Fatalf("expected no probe row to have been created for platform B")
	}

	// The legitimate platform_key (matching the cert's real CN) still works.
	conn2 := dialSessionListenerWithCert(t, gw.sessionAddr, certPEM, keyPEM, caPEM)
	stream2, err := rcaprobev1.NewProbeGatewayClient(conn2).Session(context.Background())
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	if err := stream2.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{PlatformKey: platformA, ProbeVersion: "0.1.0"},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}
	msg2, err := stream2.Recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	if ack2 := msg2.GetAck(); ack2 == nil || !ack2.GetAccepted() {
		t.Fatalf("expected the legitimate registration (matching CN) to be accepted, got %+v", msg2)
	}
}

func TestBootstrapFix_RenewalOverMTLSListener_Succeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, _, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	const platformKey = "presto-fix-renew"
	seedPlatform(t, dsn, platformKey, "tok-fix-renew")

	certPEM, keyPEM, caPEM := enrollDirect(t, gw.bootstrapAddr, platformKey, "tok-fix-renew")

	// design.md Section 8.4a: "the Bootstrap service is registered on both
	// listeners" -- renewal calls Enroll on the mTLS Session listener,
	// authenticating with the existing (here, freshly-issued but still
	// valid) certificate instead of a bootstrap token.
	conn := dialSessionListenerWithCert(t, gw.sessionAddr, certPEM, keyPEM, caPEM)
	renewalCSR, renewalKeyPEM := generateFunctestCSR(t, platformKey)
	resp, err := rcaprobev1.NewBootstrapClient(conn).Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: platformKey,
		CsrPem:      renewalCSR,
		// BootstrapToken intentionally empty: renewal.
	})
	if err != nil {
		t.Fatalf("renewal enroll against the real gateway subprocess failed: %v", err)
	}
	if len(resp.GetClientCertPem()) == 0 {
		t.Fatalf("expected a renewed client cert")
	}
	if string(resp.GetClientCertPem()) == string(certPEM) {
		t.Fatalf("expected a genuinely new certificate from renewal, got the same bytes back")
	}

	// The renewed cert must itself be immediately usable for a real
	// Session registration against the same real gateway -- note it's
	// paired with renewalKeyPEM (the key backing the CSR just submitted),
	// not the original enrollment's keyPEM (design.md Section 8.4a:
	// renewal rotates the private key).
	renewedConn := dialSessionListenerWithCert(t, gw.sessionAddr, resp.GetClientCertPem(), renewalKeyPEM, caPEM)
	stream, err := rcaprobev1.NewProbeGatewayClient(renewedConn).Session(context.Background())
	if err != nil {
		t.Fatalf("open session with renewed cert: %v", err)
	}
	if err := stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{PlatformKey: platformKey, ProbeVersion: "0.1.0"},
	}}); err != nil {
		t.Fatalf("send register: %v", err)
	}
	msg, err := stream.Recv()
	if err != nil {
		t.Fatalf("recv ack: %v", err)
	}
	if ack := msg.GetAck(); ack == nil || !ack.GetAccepted() {
		t.Fatalf("expected the renewed cert to be accepted, got %+v", msg)
	}
}

func TestBootstrapFix_RenewalWithMismatchedCN_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cross-service subprocess test in -short mode")
	}
	dsn, _, gatewayBin := setupSharedInfra(t)
	gw := startGatewaySubprocess(t, gatewayBin, dsn)

	const platformA = "presto-fix-renew-a"
	const platformB = "presto-fix-renew-b"
	seedPlatform(t, dsn, platformA, "tok-renew-a")
	seedPlatform(t, dsn, platformB, "tok-renew-b")

	certPEM, keyPEM, caPEM := enrollDirect(t, gw.bootstrapAddr, platformA, "tok-renew-a")

	conn := dialSessionListenerWithCert(t, gw.sessionAddr, certPEM, keyPEM, caPEM)
	mismatchCSR, _ := generateFunctestCSR(t, platformB)
	_, err := rcaprobev1.NewBootstrapClient(conn).Enroll(context.Background(), &rcaprobev1.EnrollRequest{
		PlatformKey: platformB, // mismatched: cert CN is platformA
		CsrPem:      mismatchCSR,
	})
	if err == nil {
		t.Fatalf("expected the real gateway to reject a renewal request whose platform_key does not match the authenticating cert's CN")
	}
}
