// Package bootstrapca implements probe-gateway's mTLS bootstrap CA
// (design.md Section 8.1/8.4 step 3: "token -> mTLS client certificate
// issued"). The design does not specify a concrete certificate-issuance
// mechanism beyond that one sentence; this package is the documented M2
// decision (see impl-progress.md and proto/rcaprobe/v1/bootstrap.proto):
// probe-gateway holds a self-signed CA keypair, generated idempotently at
// first start-up (mirroring the D14 signing-key bootstrap pattern
// already used for write-channel signing), and signs probe-submitted
// CSRs into client certificates after the caller has separately verified
// the bootstrap token (services/probe-gateway/internal/bootstrapsrv). The
// same CA also signs probe-gateway's own server certificate, so the
// probe can trust the gateway using the CA cert returned alongside its
// client cert.
package bootstrapca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

const (
	caValidity     = 10 * 365 * 24 * time.Hour // long-lived root, per typical internal-CA practice
	clientValidity = 24 * time.Hour            // short-lived client certs; probes re-enroll well within this window on any restart requiring a fresh cert (existing valid certs are simply reused otherwise)
	serverValidity = 90 * 24 * time.Hour
)

type CA struct {
	cert    *x509.Certificate
	certPEM []byte
	key     ed25519.PrivateKey
}

// Bootstrap idempotently loads (if certPath/keyPath already exist) or
// generates (first run) the bootstrap CA -- the same idempotent-pre-
// install-job pattern as D14's `bootstrap_signing_key`.
func Bootstrap(certPath, keyPath string) (*CA, error) {
	if fileExists(certPath) && fileExists(keyPath) {
		return load(certPath, keyPath)
	}
	return generate(certPath, keyPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func generate(certPath, keyPath string) (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: generate key: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "dbagent probe-gateway bootstrap CA"},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: create CA cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalPKCS8(priv)})

	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}

	return &CA{cert: cert, certPEM: certPEM, key: priv}, nil
}

func load(certPath, keyPath string) (*CA, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: read key: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("bootstrapca: invalid cert PEM at %s", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: parse cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("bootstrapca: invalid key PEM at %s", keyPath)
	}
	priv, err := unmarshalPKCS8Ed25519(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: parse key: %w", err)
	}
	return &CA{cert: cert, certPEM: certPEM, key: priv}, nil
}

// CACertPEM returns the CA certificate (PEM), sent to probes in
// EnrollResponse.ca_cert_pem.
func (ca *CA) CACertPEM() []byte { return ca.certPEM }

// Fingerprint returns the CA certificate's SHA-256 fingerprint (the hash of
// the DER-encoded certificate) in the exact "sha256:<64 lowercase hex>"
// format design.md Section 8.4a defines for the `bootstrap_ca_pin` probe
// config value. probe-gateway logs this at every startup (Section 8.4a
// "Distribution") so an operator can copy it straight from the log into
// that config field.
func (ca *CA) Fingerprint() string {
	sum := sha256.Sum256(ca.cert.Raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// SignCSR parses a PEM-encoded PKCS#10 CSR, verifies its self-signature,
// and issues a client certificate for it (CN=platformKey) valid for the
// standard clientValidity window (24h, design.md Section 8.4a). Callers
// must independently verify the bootstrap token, or (for renewal,
// Section 8.4a) an already-verified unexpired client certificate with a
// matching CN, before calling this
// (services/probe-gateway/internal/bootstrapsrv) -- SignCSR itself does
// not know about tokens or renewal.
func (ca *CA) SignCSR(csrPEM []byte, platformKey string) ([]byte, error) {
	now := time.Now()
	return ca.SignCSRWithValidity(csrPEM, platformKey, now.Add(-5*time.Minute), now.Add(clientValidity))
}

// SignCSRWithValidity is SignCSR with an explicit NotBefore/NotAfter
// window instead of the fixed 24h clientValidity. Exported so tests
// (probe-gateway-side and probe-side alike, per design.md Section 8.4a's
// renewal/expiry requirements) can deterministically craft certificates
// in specific expiry states -- e.g. "less than 50% validity remaining"
// (renewal due) or "already expired" -- without waiting on a real clock.
// Production code should call SignCSR; this is the shared implementation.
func (ca *CA) SignCSRWithValidity(csrPEM []byte, platformKey string, notBefore, notAfter time.Time) ([]byte, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("bootstrapca: invalid CSR PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("bootstrapca: CSR signature invalid: %w", err)
	}

	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: platformKey},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, fmt.Errorf("bootstrapca: sign CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

// IssueServerCertificate issues probe-gateway's own mTLS-listener server
// certificate (signed by the same bootstrap CA, so probes that trust the
// CA cert from EnrollResponse also trust this).
// IssueServerCertificate issues a server certificate for the given SAN
// list; entries that parse as an IP address become IP SANs, everything
// else becomes a DNS SAN (so callers -- production and tests alike --
// can pass either hostnames like "probe-gateway" or loopback/test IPs
// like "127.0.0.1" through the same parameter).
func (ca *CA) IssueServerCertificate(names []string) (tls.Certificate, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	var dnsNames []string
	var ipAddresses []net.IP
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else {
			dnsNames = append(dnsNames, n)
		}
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "probe-gateway"},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddresses,
		NotBefore:    time.Now().Add(-5 * time.Minute),
		NotAfter:     time.Now().Add(serverValidity),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, pub, ca.key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("bootstrapca: issue server cert: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: marshalPKCS8(priv)})

	// design.md Section 8.4a (v1.5): "probe-gateway MUST include the
	// bootstrap CA certificate in the chain it presents on the bootstrap
	// listener (leaf + CA)" so a client pinning bootstrap_ca_pin's
	// sha256:<hex> fingerprint form can verify it directly from the
	// presented chain, without needing the CA cert out-of-band. Appending
	// the CA cert's PEM block after the leaf's is exactly how Go's
	// tls.X509KeyPair builds a multi-certificate chain (it splits on PEM
	// blocks and keeps the block order); this is harmless for the mTLS
	// Session listener too (standard TLS practice to present the full
	// chain up to -- but not including -- the root the peer already
	// trusts, and here the "root" IS the bootstrap CA, so including it
	// costs nothing and only helps peers that haven't cached it yet).
	chainPEM := append(append([]byte{}, certPEM...), ca.certPEM...)
	return tls.X509KeyPair(chainPEM, keyPEM)
}

func randSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

// marshalPKCS8 panics on error, which cannot happen for a well-formed
// ed25519.PrivateKey (the only type this package ever passes in) --
// x509.MarshalPKCS8PrivateKey only errors for unsupported key types.
func marshalPKCS8(priv ed25519.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		panic(fmt.Sprintf("bootstrapca: marshal PKCS8 (unreachable for ed25519): %v", err))
	}
	return der
}

func unmarshalPKCS8Ed25519(der []byte) (ed25519.PrivateKey, error) {
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("bootstrapca: expected ed25519 key, got %T", key)
	}
	return priv, nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
