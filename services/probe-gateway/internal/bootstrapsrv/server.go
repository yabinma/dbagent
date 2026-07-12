// Package bootstrapsrv implements the `Bootstrap.Enroll` gRPC service
// (proto/rcaprobe/v1/bootstrap.proto): validates a probe's one-time
// bootstrap token against the registry (design.md Section 8.4 step 1/3,
// F8 checkpoint "bootstrap token single-use") and, on success, signs its
// CSR via the bootstrap CA.
//
// design.md Section 8.4a (D16, normative as of v1.3) also makes this the
// renewal endpoint: when this service is registered on the mTLS `Session`
// listener too (services/probe-gateway/cmd/probe-gateway), a request with
// an empty bootstrap_token is a renewal -- the caller's already-verified,
// unexpired client certificate (CN == platform_key) substitutes for the
// token, since the token is single-use and would already be consumed by
// the time a 24h client certificate needs renewing.
package bootstrapsrv

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
)

type Server struct {
	rcaprobev1.UnimplementedBootstrapServer

	CA       *bootstrapca.CA
	Registry registry.Registry
}

func New(ca *bootstrapca.CA, reg registry.Registry) *Server {
	return &Server{CA: ca, Registry: reg}
}

func (s *Server) Enroll(ctx context.Context, req *rcaprobev1.EnrollRequest) (*rcaprobev1.EnrollResponse, error) {
	if req.GetPlatformKey() == "" || len(req.GetCsrPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "platform_key and csr_pem are required")
	}

	if req.GetBootstrapToken() == "" {
		// Renewal (design.md Section 8.4a): the bootstrap token is
		// single-use, so a probe renewing its 24h client cert has none
		// left to present. A verified, unexpired mTLS client certificate
		// with CN == platform_key on this connection is the substitute
		// proof of identity.
		if err := s.authenticateRenewal(ctx, req.GetPlatformKey()); err != nil {
			return nil, err
		}
		// Registry-side authorization is still enforced on renewal (design.md
		// Section 8.4a "Revocation": "deleting or disabling a platform blocks
		// Session registration and renewal regardless of remaining certificate
		// validity") -- a certificate remains cryptographically valid even
		// after its platform is gone, so renewal must independently confirm
		// the platform still exists.
		if _, err := s.Registry.GetPlatform(ctx, req.GetPlatformKey()); err != nil {
			if err == registry.ErrPlatformNotFound {
				return nil, status.Error(codes.NotFound, "unknown platform_key")
			}
			return nil, status.Errorf(codes.Internal, "get platform: %v", err)
		}
	} else {
		if _, err := s.Registry.ConsumeBootstrapToken(ctx, req.GetPlatformKey(), req.GetBootstrapToken()); err != nil {
			if err == registry.ErrPlatformNotFound {
				return nil, status.Error(codes.NotFound, "unknown platform_key")
			}
			if err == registry.ErrInvalidToken {
				return nil, status.Error(codes.PermissionDenied, "bootstrap token invalid or already used")
			}
			return nil, status.Errorf(codes.Internal, "consume bootstrap token: %v", err)
		}
	}

	clientCertPEM, err := s.CA.SignCSR(req.GetCsrPem(), req.GetPlatformKey())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "sign csr: %v", err)
	}

	return &rcaprobev1.EnrollResponse{
		ClientCertPem: clientCertPEM,
		CaCertPem:     s.CA.CACertPEM(),
	}, nil
}

// authenticateRenewal implements the identity check design.md Section
// 8.4a requires for a token-less Enroll (renewal) call: the RPC must have
// arrived over an mTLS connection (i.e. the mTLS `Session` listener, not
// the token-only `Bootstrap` listener -- see
// services/probe-gateway/cmd/probe-gateway's dual registration), the
// presented client certificate's CN must equal the claimed platform_key,
// and the certificate must not (yet) be expired. Production TLS transport
// (tls.Config{ClientAuth: tls.RequireAndVerifyClientCert}) already
// rejects an expired certificate at the handshake before this handler is
// ever reached; the expiry check here is defense in depth (and is
// directly unit-testable independent of a real handshake).
func (s *Server) authenticateRenewal(ctx context.Context, platformKey string) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return status.Error(codes.Unauthenticated, "renewal (empty bootstrap_token) requires an authenticated mTLS client certificate")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return status.Error(codes.Unauthenticated, "renewal (empty bootstrap_token) requires an authenticated mTLS client certificate")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	if cert.Subject.CommonName != platformKey {
		return status.Errorf(codes.PermissionDenied, "certificate CN %q does not match platform_key %q", cert.Subject.CommonName, platformKey)
	}
	if !time.Now().Before(cert.NotAfter) {
		return status.Error(codes.PermissionDenied, "client certificate has expired; re-enroll with a fresh bootstrap token")
	}
	return nil
}
