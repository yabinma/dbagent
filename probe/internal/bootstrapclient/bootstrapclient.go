// Package bootstrapclient implements the probe side of mTLS bootstrap
// enrollment AND renewal (proto/rcaprobe/v1/bootstrap.proto, design.md
// Section 8.4 step 3 and Section 8.4a): generate a keypair + CSR, call
// `Bootstrap.Enroll` with the one-time bootstrap token, and persist the
// returned client cert + CA cert to disk for the subsequent mTLS
// `ProbeGateway.Session` connection. Renewal (Section 8.4a, required M3
// fix) re-runs the same exchange over the mTLS Session listener with an
// empty token, once less than 50% of the current client certificate's
// validity remains -- the existing valid certificate itself is the proof
// of identity in place of the (already-consumed) token.
//
// Trust-on-first-use note (documented decision, see impl-progress.md):
// the initial Enroll call has no CA cert yet to validate the gateway's
// bootstrap-listener server certificate against, so that single call
// connects with `InsecureSkipVerify` -- the bootstrap token itself
// (delivered out-of-band via the dashboard, design.md Section 8.4 steps
// 1-2) is the actual trust anchor for this one step. Every connection
// after Enroll succeeds (the real mTLS Session stream, and every renewal
// call) fully validates both directions using the returned CA cert +
// issued client cert.
package bootstrapclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
)

type Result struct {
	ClientCertPEM []byte
	ClientKeyPEM  []byte
	CACertPEM     []byte
}

// newKeyAndCSR generates a fresh ed25519 keypair and a PKCS#10 CSR with
// CN=platformKey, shared by both Enroll and Renew (design.md Section
// 8.4a: "The probe generates an ed25519 keypair and a PKCS#10 CSR").
func newKeyAndCSR(platformKey string) (csrPEM, keyPEM []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrapclient: generate key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:   pkix.Name{CommonName: platformKey},
		PublicKey: pub,
	}, priv)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrapclient: create csr: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("bootstrapclient: marshal key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return csrPEM, keyPEM, nil
}

// sha256PinPrefix is the `sha256:<64 lowercase hex>` value form of
// bootstrap_ca_pin (design.md Section 8.4a v1.5): the SHA-256 of the
// DER-encoded bootstrap CA certificate.
const sha256PinPrefix = "sha256:"

// bootstrapEnrollTLSConfig builds the tls.Config used for the one-time
// Bootstrap.Enroll dial, implementing design.md Section 8.4a's v1.5
// `bootstrap_ca_pin` semantics:
//
//   - caPin == "": TOFU (documented tradeoff, unchanged default) -- the
//     one-time out-of-band bootstrap token is the trust anchor for this
//     one call.
//   - caPin == "sha256:<hex>": fingerprint form. No default chain/hostname
//     verification is performed (InsecureSkipVerify=true is paired with a
//     VerifyPeerCertificate callback doing the real check, standard Go TLS
//     pattern for custom verification) -- Enroll succeeds only if some
//     certificate in the chain the gateway presents hashes to the pin. The
//     gateway MUST present leaf+CA on the bootstrap listener
//     (internal/bootstrapca.IssueServerCertificate) for this to be
//     checkable against the CA fingerprint specifically.
//   - otherwise: caPin is treated as the bootstrap CA certificate, inline
//     PEM. Enroll performs standard TLS verification (chain + hostname)
//     with that CA as the sole trusted root.
//
// In both non-empty forms there is no fallback to TOFU on a pin mismatch
// or malformed pin -- Enroll fails closed.
func bootstrapEnrollTLSConfig(caPin string) (*tls.Config, error) {
	if caPin == "" {
		// See package doc: intentionally unverified for this one bootstrap
		// call; the token is the trust anchor here.
		return &tls.Config{InsecureSkipVerify: true}, nil //nolint:gosec
	}

	if strings.HasPrefix(caPin, sha256PinPrefix) {
		want := strings.ToLower(strings.TrimPrefix(caPin, sha256PinPrefix))
		wantBytes, err := hex.DecodeString(want)
		if err != nil || len(wantBytes) != sha256.Size {
			return nil, fmt.Errorf("bootstrapclient: invalid bootstrap_ca_pin fingerprint %q: must be sha256:<64 hex chars>", caPin)
		}
		return &tls.Config{
			// Default verification is disabled because it's replaced below
			// by an explicit, stricter check (fingerprint match, not chain
			// validity to a system root) -- this is Go's documented
			// pattern for custom peer verification, not a weakening: a
			// pin mismatch below still fails Enroll closed.
			InsecureSkipVerify: true, //nolint:gosec
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				for _, raw := range rawCerts {
					sum := sha256.Sum256(raw)
					if subtle.ConstantTimeCompare(sum[:], wantBytes) == 1 {
						return nil
					}
				}
				return fmt.Errorf("bootstrapclient: bootstrap_ca_pin mismatch: no certificate in the gateway's presented chain matches %s", caPin)
			},
		}, nil
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caPin)) {
		return nil, fmt.Errorf("bootstrapclient: invalid bootstrap_ca_pin: not a sha256:<hex> fingerprint and not a valid PEM certificate")
	}
	return &tls.Config{RootCAs: pool}, nil
}

// Enroll dials gatewayAddr's Bootstrap listener and exchanges
// bootstrapToken + a freshly generated CSR for a signed client cert.
//
// caPin implements design.md Section 8.4a's `bootstrap_ca_pin` deployment
// parameter (v1.5 semantics): when empty, the connection is
// trust-on-first-use (see package doc); when set, the gateway's presented
// certificate chain is verified against the pin and TOFU is not used --
// a mismatch fails Enroll closed, with no fallback.
func Enroll(ctx context.Context, gatewayAddr, platformKey, bootstrapToken, caPin string) (*Result, error) {
	csrPEM, keyPEM, err := newKeyAndCSR(platformKey)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := bootstrapEnrollTLSConfig(caPin)
	if err != nil {
		return nil, err
	}
	creds := credentials.NewTLS(tlsConfig)
	conn, err := grpc.NewClient(gatewayAddr, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("bootstrapclient: dial %s: %w", gatewayAddr, err)
	}
	defer conn.Close()

	client := rcaprobev1.NewBootstrapClient(conn)
	resp, err := client.Enroll(ctx, &rcaprobev1.EnrollRequest{
		PlatformKey:    platformKey,
		BootstrapToken: bootstrapToken,
		CsrPem:         csrPEM,
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrapclient: enroll: %w", err)
	}

	return &Result{
		ClientCertPEM: resp.GetClientCertPem(),
		ClientKeyPEM:  keyPEM,
		CACertPEM:     resp.GetCaCertPem(),
	}, nil
}

// Renew re-enrolls over the already-established mTLS `Session` listener
// (design.md Section 8.4a): gatewayAddr must be the mTLS Session address
// (the Bootstrap service is registered on both listeners,
// services/probe-gateway/cmd/probe-gateway), and existing supplies the
// still-valid client certificate that authenticates this call in place
// of a bootstrap token (left empty). A fresh keypair + CSR are generated,
// same as Enroll, so renewal also rotates the private key.
func Renew(ctx context.Context, gatewayAddr, platformKey string, existing *Result) (*Result, error) {
	tlsConfig, err := existing.TLSConfig()
	if err != nil {
		return nil, fmt.Errorf("bootstrapclient: renew: build tls config: %w", err)
	}
	conn, err := grpc.NewClient(gatewayAddr, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return nil, fmt.Errorf("bootstrapclient: renew: dial %s: %w", gatewayAddr, err)
	}
	defer conn.Close()

	csrPEM, keyPEM, err := newKeyAndCSR(platformKey)
	if err != nil {
		return nil, err
	}

	client := rcaprobev1.NewBootstrapClient(conn)
	resp, err := client.Enroll(ctx, &rcaprobev1.EnrollRequest{
		PlatformKey: platformKey,
		CsrPem:      csrPEM,
		// BootstrapToken intentionally left empty: the mTLS client
		// certificate carried by tlsConfig above is the proof of identity
		// for this call (design.md Section 8.4a).
	})
	if err != nil {
		return nil, fmt.Errorf("bootstrapclient: renew: enroll: %w", err)
	}

	return &Result{
		ClientCertPEM: resp.GetClientCertPem(),
		ClientKeyPEM:  keyPEM,
		CACertPEM:     resp.GetCaCertPem(),
	}, nil
}

// Expiry parses the client certificate's NotBefore/NotAfter, as persisted
// (or freshly issued) -- the input to RenewalStatus below.
func (r *Result) Expiry() (notBefore, notAfter time.Time, err error) {
	block, _ := pem.Decode(r.ClientCertPEM)
	if block == nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrapclient: invalid client cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bootstrapclient: parse client cert: %w", err)
	}
	return cert.NotBefore, cert.NotAfter, nil
}

// RenewalStatus reports, as of now, whether the client certificate has
// already expired, or has less than 50% of its total validity window
// remaining (design.md Section 8.4a: "The probe MUST renew whenever less
// than 50% of certificate validity remains (checked at startup and on
// every reconnect)"). expired takes precedence: "The probe MUST treat an
// expired persisted certificate the same as no certificate at startup"
// -- no renewal is attempted for an expired certificate (the mTLS
// handshake required to call Renew would reject it anyway); recovery is
// re-enrollment with a fresh bootstrap token.
func (r *Result) RenewalStatus(now time.Time) (dueForRenewal, expired bool, err error) {
	notBefore, notAfter, err := r.Expiry()
	if err != nil {
		return false, false, err
	}
	if !now.Before(notAfter) {
		return false, true, nil
	}
	total := notAfter.Sub(notBefore)
	remaining := notAfter.Sub(now)
	return remaining*2 < total, false, nil
}

// Persist writes the enrollment result to the conventional file layout
// under dir (clientCert/clientKey/caCert PEM files), so a restarted probe
// process can reuse them without re-enrolling (the bootstrap token is
// single-use -- design.md F8 checkpoint).
func (r *Result) Persist(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "client.crt"), r.ClientCertPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "client.key"), r.ClientKeyPEM, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), r.CACertPEM, 0o644); err != nil {
		return err
	}
	return nil
}

// LoadIfPresent loads a previously persisted enrollment result from dir,
// if all three files exist; (nil, false, nil) if not (first-ever
// enrollment is required).
func LoadIfPresent(dir string) (*Result, bool, error) {
	certPath := filepath.Join(dir, "client.crt")
	keyPath := filepath.Join(dir, "client.key")
	caPath := filepath.Join(dir, "ca.crt")

	if _, err := os.Stat(certPath); os.IsNotExist(err) {
		return nil, false, nil
	}
	cert, err := os.ReadFile(certPath)
	if err != nil {
		return nil, false, err
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, false, err
	}
	ca, err := os.ReadFile(caPath)
	if err != nil {
		return nil, false, err
	}
	return &Result{ClientCertPEM: cert, ClientKeyPEM: key, CACertPEM: ca}, true, nil
}

// TLSConfig builds the mTLS client config for the Session stream from an
// enrollment Result.
func (r *Result) TLSConfig() (*tls.Config, error) {
	cert, err := tls.X509KeyPair(r.ClientCertPEM, r.ClientKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("bootstrapclient: load client keypair: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(r.CACertPEM) {
		return nil, fmt.Errorf("bootstrapclient: invalid CA cert PEM")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      pool,
	}, nil
}
