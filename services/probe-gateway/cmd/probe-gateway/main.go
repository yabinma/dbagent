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
		configPath = "/etc/rca-agent/probe-gateway/config.yaml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("probe-gateway: load config: %v", err)
	}

	reg, err := registry.Open(cfg.PostgresDSN)
	if err != nil {
		log.Fatalf("probe-gateway: open registry: %v", err)
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

	gw := gwserver.New(reg, keys.Current(), cfg.GatewayReplica)
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
// (design.md D14 rotation) and pushes it into gw, so key rotation takes
// effect without a probe-gateway restart.
func pollSigningKey(ctx context.Context, keys *signingkeys.Reader, gw *gwserver.Server, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if err := keys.Load(); err != nil {
				log.Printf("probe-gateway: reload signing key: %v", err)
				continue
			}
			gw.SetSigningPublicKey(keys.Current())
		}
	}
}
