// Command probe-gateway is the entrypoint for the probe-gateway service
// (design.md Section 3.2): terminates the mTLS `ProbeGateway.Session`
// stream from probes and the separate `Bootstrap.Enroll` enrollment
// listener (proto/rcaprobe/v1/bootstrap.proto), backed by the shared
// Postgres registry.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/internal/bootstrapca"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/bootstrapsrv"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/config"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/dispatch"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/gwserver"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/registry"
	"github.com/yabinma/dbagent/services/probe-gateway/internal/signingkeys"
)

func main() {
	configPath := os.Getenv("PROBE_GATEWAY_CONFIG")
	if configPath == "" {
		configPath = "/etc/dbagent/probe-gateway/config.yaml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("probe-gateway: load config: %v", err)
	}

	reg, err := registry.Open(cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("probe-gateway: open registry: %v", err)
	}
	if err := applyDBConnCeiling(cfg, reg); err != nil {
		log.Fatalf("%v", err)
	}

	ca, err := bootstrapca.Bootstrap(cfg.BootstrapCACertPath, cfg.BootstrapCAKeyPath)
	if err != nil {
		log.Fatalf("probe-gateway: bootstrap CA: %v", err)
	}
	logCAFingerprint(ca)

	keys := signingkeys.NewReader(cfg.SigningPublicKeyPath, cfg.SigningKeyGraceWindow)
	if err := keys.Load(); err != nil {
		log.Printf("probe-gateway: initial signing key load failed (will retry): %v", err)
	}

	gw := newSessionServer(reg, keys.Current(), cfg.GatewayReplica)
	gw.HeartbeatTimeout = cfg.HeartbeatTimeout

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go gw.ReapStaleProbes(ctx, cfg.HeartbeatCheckInterval)
	go pollSigningKey(ctx, keys, gw, cfg.SigningKeyPollInterval)

	if cfg.InternalListenAddr != "" {
		go runInternalDispatchListener(ctx, cfg.InternalListenAddr, gw)
	}
	go runBootstrapListener(ctx, cfg.BootstrapListenAddr, ca, reg, cfg.ServerCertSANs)
	runSessionListener(ctx, cfg.SessionListenAddr, ca, gw, reg, cfg.ServerCertSANs)
}

// applyDBConnCeiling refuses an undeclared or unlimited pool and applies the
// ConfigMap-declared cap to the registry handle. Extracted so its deletion
// breaks TestApplyDBConnCeiling_AppliesLoadedMaxDBConns (UT-IG-12).
func applyDBConnCeiling(cfg config.Config, reg *registry.PG) error {
	if cfg.MaxDBConns <= 0 {
		return fmt.Errorf(
			"probe-gateway: max_db_conns is required and must be > 0 (got %d)",
			cfg.MaxDBConns,
		)
	}
	reg.DB.SetMaxOpenConns(cfg.MaxDBConns)
	return nil
}

// newSessionServer constructs the Session server with production wiring
// (FP-M6-25): credentials_* audit rows share the registry's *sql.DB pool.
// Extracted so the AuditDB assignment cannot be deleted without breaking
// TestMainWiresAuditDBFromRegistry.
func newSessionServer(reg *registry.PG, signingPublicKey []byte, gatewayReplica string) *gwserver.Server {
	gw := gwserver.New(reg, signingPublicKey, gatewayReplica)
	gw.AuditDB = reg.DB
	return gw
}

// runInternalDispatchListener serves POST /internal/v1/execute so the
// Python temporal-worker can call ExecuteTool (design.md Section 3.2, M3).
func runInternalDispatchListener(ctx context.Context, addr string, gw *gwserver.Server) {
	srv := dispatch.New(gw)
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	log.Printf("probe-gateway: internal ExecuteTool HTTP listener on %s", addr)
	if err := srv.ListenAndServe(addr); err != nil && err != http.ErrServerClosed {
		log.Printf("probe-gateway: internal dispatch listener stopped: %v", err)
	}
}

// logCAFingerprint logs the bootstrap CA's sha256 fingerprint at startup in
// the exact "sha256:<64 lowercase hex>" format design.md Section 8.4a
// defines for `bootstrap_ca_pin` (the "Distribution" clause: "probe-gateway
// logs the CA's sha256: fingerprint at every startup"), so an operator can
// copy the value straight from the log into that probe config field.
// Factored out of main() (which itself is excluded from this package's
// coverage gate, per this file's own header comment) so the log line is
// directly, independently testable.
func logCAFingerprint(ca *bootstrapca.CA) string {
	line := fmt.Sprintf("probe-gateway: bootstrap CA fingerprint (bootstrap_ca_pin): %s", ca.Fingerprint())
	log.Print(line)
	return line
}

func runSessionListener(ctx context.Context, addr string, ca *bootstrapca.CA, gw *gwserver.Server, reg registry.Registry, sans []string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("probe-gateway: listen (session) %s: %v", addr, err)
	}

	serverCert, err := ca.IssueServerCertificate(sans)
	if err != nil {
		log.Fatalf("probe-gateway: issue server cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(ca.CACertPEM())
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	rcaprobev1.RegisterProbeGatewayServer(grpcServer, gw)
	// design.md Section 8.4a: "the bootstrap token is single-use... [renewal]
	// call[s] Enroll on the mTLS Session listener (the Bootstrap service is
	// registered on both listeners)".
	rcaprobev1.RegisterBootstrapServer(grpcServer, bootstrapsrv.New(ca, reg))

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("probe-gateway: mTLS Session listener on %s", addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Printf("probe-gateway: session listener stopped: %v", err)
	}
}

func runBootstrapListener(ctx context.Context, addr string, ca *bootstrapca.CA, reg registry.Registry, sans []string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("probe-gateway: listen (bootstrap) %s: %v", addr, err)
	}

	serverCert, err := ca.IssueServerCertificate(sans)
	if err != nil {
		log.Fatalf("probe-gateway: issue bootstrap server cert: %v", err)
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{serverCert}}

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsConfig)))
	rcaprobev1.RegisterBootstrapServer(grpcServer, bootstrapsrv.New(ca, reg))

	go func() {
		<-ctx.Done()
		grpcServer.GracefulStop()
	}()

	log.Printf("probe-gateway: Bootstrap.Enroll listener on %s", addr)
	if err := grpcServer.Serve(lis); err != nil {
		log.Printf("probe-gateway: bootstrap listener stopped: %v", err)
	}
}

// pollSigningKey periodically re-reads the signing public key sidecar
// (design.md §9.6 / D14), serves it via SetSigningPublicKey, then
// converges every connected session onto it with PropagateSigningKey
// (mid-session RegisterAck, Appendix A.2). Does not broadcast
// ManifestRefresh — a key rotation does not change a manifest.
func pollSigningKey(ctx context.Context, keys *signingkeys.Reader, gw *gwserver.Server, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	var incomplete bool
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := keys.Load(); err != nil {
				log.Printf("probe-gateway: reload signing key: %v", err)
				continue
			}
			// Serve the new key first so concurrent admissions get it, then
			// converge already-connected sessions onto it.
			gw.SetSigningPublicKey(keys.Current())
			p := gw.PropagateSigningKey()
			var line string
			line, incomplete = propagationLogLine(p, incomplete)
			if line != "" {
				log.Print(line)
			}
		}
	}
}

// propagationLogLine renders one propagation pass for the operator and carries
// the "a previous pass was incomplete" flag forward. The returned bool is
// always authoritative; an empty line means "log nothing this tick".
// prevIncomplete is true when an earlier pass since the last clean one
// reported Dropped > 0.
func propagationLogLine(p gwserver.SigningKeyPropagation, prevIncomplete bool) (line string, incomplete bool) {
	switch {
	case p.Dropped > 0:
		return fmt.Sprintf(
			"probe-gateway: signing key propagation incomplete: %d updated, %d already current, %d session(s) not reachable this pass; NOT ready, retrying next tick",
			p.Sent, p.UpToDate, p.Dropped), true
	case p.Sent > 0 || prevIncomplete:
		return fmt.Sprintf(
			"probe-gateway: signing key propagated to all connected sessions (%d updated, %d already current, 0 dropped)",
			p.Sent, p.UpToDate), false
	default:
		return "", false
	}
}
