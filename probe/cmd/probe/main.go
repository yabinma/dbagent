// Command probe is the entrypoint for the data-plane probe (design.md
// Section 8): enrolls via mTLS bootstrap on first run (or reuses a
// persisted identity), then runs the ProbeGateway.Session client loop
// against a Presto PlatformAdapter.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/probe/internal/adapter/presto"
	"github.com/yabinma/dbagent/probe/internal/bootstrapclient"
	"github.com/yabinma/dbagent/probe/internal/config"
	probecreds "github.com/yabinma/dbagent/probe/internal/credentials"
	"github.com/yabinma/dbagent/probe/internal/dockerapi"
	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/runtimeenv/dockerenv"
	"github.com/yabinma/dbagent/probe/internal/runtimeenv/k8senv"
	"github.com/yabinma/dbagent/probe/internal/sessionclient"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	metricsclientset "k8s.io/metrics/pkg/client/clientset/versioned"
)

func main() {
	configPath := os.Getenv("PROBE_CONFIG")
	if configPath == "" {
		configPath = "/etc/rca-probe/config.yaml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("probe: load config: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	enrollment, err := ensureEnrolled(ctx, cfg)
	if err != nil {
		log.Fatalf("probe: enrollment: %v", err)
	}

	env, _, err := buildRuntimeEnv(cfg)
	if err != nil {
		log.Fatalf("probe: build runtime env: %v", err)
	}

	adapter := presto.New(presto.Config{
		PlatformKey:          cfg.PlatformKey,
		CredentialsMountPath: cfg.CredentialsMount,
		InsecureSkipVerify:   cfg.InsecureSkipVerify,
		WriteEnabled:         cfg.WriteEnabled,
	})

	// design.md Section 8.4 step 7: watch the credentials mount and
	// re-run detection automatically when files appear/change.
	watcher := probecreds.NewWatcher(cfg.CredentialsMount, 30*time.Second, func() {
		log.Printf("probe: credentials changed, re-running Detect")
		if _, err := adapter.Detect(ctx, env); err != nil {
			log.Printf("probe: re-detect after credentials change failed: %v", err)
		}
	})
	go watcher.Start(ctx)

	for {
		// design.md Section 8.4a: "The probe MUST renew whenever less than
		// 50% of certificate validity remains (checked at startup and on
		// every reconnect)" -- this loop iterates once at startup and again
		// every time runSession returns (i.e. every reconnect), so checking
		// here covers both.
		enrollment = maybeRenew(ctx, cfg, enrollment)

		if err := runSession(ctx, cfg, enrollment, adapter, env); err != nil {
			log.Printf("probe: session ended: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			log.Printf("probe: reconnecting to %s", cfg.GatewayAddress)
		}
	}
}

func ensureEnrolled(ctx context.Context, cfg config.Probe) (*bootstrapclient.Result, error) {
	existing, found, err := bootstrapclient.LoadIfPresent(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	if found {
		// design.md Section 8.4a: "The probe MUST treat an expired
		// persisted certificate the same as no certificate at startup" --
		// there is no silent renewal path for an already-expired
		// certificate (the mTLS handshake Renew needs would reject it
		// anyway), so fall through to a fresh token-based Enroll below.
		_, expired, err := existing.RenewalStatus(time.Now())
		if err != nil {
			return nil, err
		}
		if !expired {
			return existing, nil
		}
		log.Printf("probe: persisted client certificate has expired; re-enrolling with a fresh bootstrap token")
	}

	if cfg.BootstrapToken == "" {
		return nil, errNoBootstrapToken
	}
	result, err := bootstrapclient.Enroll(ctx, cfg.BootstrapAddress, cfg.PlatformKey, cfg.BootstrapToken, cfg.BootstrapCAPin)
	if err != nil {
		return nil, err
	}
	if err := result.Persist(cfg.StateDir); err != nil {
		return nil, err
	}
	return result, nil
}

// maybeRenew implements design.md Section 8.4a's renewal trigger: once
// less than 50% of the current client certificate's validity remains, it
// renews over the mTLS `Session` listener (bootstrapclient.Renew) using
// the still-valid certificate as proof of identity, and persists the
// result. An already-expired certificate is left untouched here (no
// silent renewal for expired certs; recovery is a fresh admin-issued
// bootstrap token, i.e. a redeploy -- ensureEnrolled handles that case at
// startup). A renewal failure (e.g. transient network issue) is logged
// and non-fatal: the caller keeps using the still-valid `current`
// certificate and will retry on the next reconnect.
func maybeRenew(ctx context.Context, cfg config.Probe, current *bootstrapclient.Result) *bootstrapclient.Result {
	due, expired, err := current.RenewalStatus(time.Now())
	if err != nil {
		log.Printf("probe: check certificate renewal status: %v", err)
		return current
	}
	if expired || !due {
		return current
	}

	log.Printf("probe: client certificate has less than 50%% of its validity remaining; renewing")
	renewed, err := bootstrapclient.Renew(ctx, cfg.GatewayAddress, cfg.PlatformKey, current)
	if err != nil {
		log.Printf("probe: certificate renewal failed (will retry on next reconnect): %v", err)
		return current
	}
	if err := renewed.Persist(cfg.StateDir); err != nil {
		log.Printf("probe: persist renewed certificate: %v", err)
		return current
	}
	log.Printf("probe: renewed client certificate")
	return renewed
}

var errNoBootstrapToken = &staticError{"probe: no persisted enrollment and no bootstrap_token configured"}

type staticError struct{ msg string }

func (e *staticError) Error() string { return e.msg }

func runSession(ctx context.Context, cfg config.Probe, enrollment *bootstrapclient.Result, adapter platform.PlatformAdapter, env platform.RuntimeEnv) error {
	tlsConfig, err := enrollment.TLSConfig()
	if err != nil {
		return err
	}
	conn, err := grpc.NewClient(cfg.GatewayAddress, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	if err != nil {
		return err
	}
	defer conn.Close()

	stream, err := rcaprobev1.NewProbeGatewayClient(conn).Session(ctx)
	if err != nil {
		return err
	}

	client := sessionclient.New(stream, adapter, env, cfg.PlatformKey, "0.1.0", cfg.WriteEnabled)
	return client.Run(ctx)
}

// inClusterConfig is a seam over rest.InClusterConfig so tests can inject
// a well-formed (but non-live) *rest.Config and exercise the rest of
// buildRuntimeEnv's K8s branch without running inside a real cluster.
var inClusterConfig = rest.InClusterConfig

func buildRuntimeEnv(cfg config.Probe) (platform.RuntimeEnv, platform.EnvKind, error) {
	if cfg.CoordinatorService != "" {
		// Swarm deployment (Appendix E: "Swarm: coordinator_service: presto-coordinator").
		dockerClient := dockerapi.New(cfg.DockerAPIBaseURL, nil)
		env := dockerenv.New(dockerClient, dockerenv.Config{
			CoordinatorService: cfg.CoordinatorService,
			WorkerService:      cfg.WorkerService,
			CoordinatorHTTPS:   cfg.CoordinatorHTTPS,
			CoordinatorPort:    cfg.CoordinatorPort,
		})
		return env, platform.EnvKindSwarm, nil
	}

	restConfig, err := inClusterConfig()
	if err != nil {
		return nil, "", err
	}
	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, "", err
	}
	metricsClient, err := metricsclientset.NewForConfig(restConfig)
	if err != nil {
		log.Printf("probe: metrics client unavailable (resource_usage tool will error): %v", err)
		metricsClient = nil
	}
	env := k8senv.New(clientset, metricsClient, k8senv.Config{
		Namespace:           cfg.Namespace,
		CoordinatorSelector: cfg.CoordinatorLocator,
		CoordinatorHTTPS:    cfg.CoordinatorHTTPS,
		CoordinatorPort:     cfg.CoordinatorPort,
	}, nil)
	return env, platform.EnvKindK8s, nil
}
