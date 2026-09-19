// Package config loads the probe's deployment parameters (design.md
// Appendix E "Probe deployment parameters").
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/yabinma/dbagent/internal/envexpand"
)

// Probe mirrors design.md Appendix E's `probe:` deployment-parameter block.
type Probe struct {
	PlatformKey      string `yaml:"platform_key"`
	GatewayAddress   string `yaml:"gateway_address"`
	BootstrapAddress string `yaml:"bootstrap_address"` // Bootstrap.Enroll listener; separate from gateway_address's mTLS Session listener
	BootstrapToken   string `yaml:"bootstrap_token"`   // single-use; empty after enrollment
	// BootstrapCAPin implements design.md Section 8.4a's optional
	// bootstrap_ca_pin (Appendix E): either the bootstrap CA certificate
	// as inline PEM, or "sha256:<64 lowercase hex>" -- the SHA-256 of the
	// DER-encoded CA certificate. When set, Bootstrap.Enroll verifies the
	// gateway's certificate against the pin instead of trust-on-first-use;
	// REQUIRED on untrusted networks. Empty (default) preserves TOFU.
	BootstrapCAPin     string `yaml:"bootstrap_ca_pin"`
	CoordinatorLocator string `yaml:"coordinator_locator"`
	CredentialsMount   string `yaml:"credentials_mount"`
	WriteEnabled       bool   `yaml:"write_enabled"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	StateDir           string `yaml:"state_dir"` // where enrollment cert/key/ca are persisted
	CoordinatorHTTPS   bool   `yaml:"coordinator_https"`
	CoordinatorPort    int    `yaml:"coordinator_port"`
	Namespace          string `yaml:"namespace"`           // K8s namespace; ignored for swarm
	CoordinatorService string `yaml:"coordinator_service"` // Swarm coordinator locator form (Appendix E)
	WorkerService      string `yaml:"worker_service"`
	// DockerAPIBaseURL selects how the probe reaches the Docker Engine API on
	// Swarm/Docker deployments (design.md §11.2.3 B, FP-SW-2/3). Accepted
	// forms: "unix://<absolute path>" (the default,
	// unix:///var/run/docker.sock -- the probe dials the mounted socket
	// directly and the shipped stack contains no socket proxy),
	// "http://host:port" and "https://host:port" (the test transport, and the
	// still-supported operator option of an external socket proxy). Any other
	// scheme, or a unix path that is missing or is not a socket, is a fatal
	// startup error raised before enrollment.
	DockerAPIBaseURL string `yaml:"docker_api_base_url"`
	// ConfigPaths overrides where the probe reads platform config files inside
	// the coordinator/worker container (design.md §11.2.3 A, FP-SW-1): a map
	// from the Appendix B.1 `presto_config` `file` value
	// ("config" | "jvm" | "node" | "catalog:<name>") to an ABSOLUTE
	// in-container path. Absent keys keep the conventional /etc/presto/...
	// default per key, never wholesale; a relative or empty value is a named
	// load-time error. Swarm/Docker only -- ignored on Kubernetes, where
	// RuntimeEnv.ReadConfig resolves a ConfigMap key rather than a path.
	ConfigPaths map[string]string `yaml:"config_paths"`
	// SigningKeyGraceWindow is D14's rotation grace: how long the
	// pre-rotation control-plane signing public key keeps verifying
	// write-ops after a mid-session key update (design.md §9.6 /
	// Appendix A.2). Default 10m. Held per probe process so it survives
	// reconnects (A.2 rule 8).
	SigningKeyGraceWindow time.Duration `yaml:"signing_key_grace_window"`
}

func defaults() Probe {
	return Probe{
		CredentialsMount:      "/etc/dbagent-probe/platform-credentials",
		StateDir:              "/var/lib/dbagent-probe",
		DockerAPIBaseURL:      "unix:///var/run/docker.sock",
		SigningKeyGraceWindow: 10 * time.Minute,
	}
}

// validateConfigPaths enforces design.md §11.2.3 A's absolute-path rule on
// every config_paths value. Keys are visited in sorted order so a config with
// several bad values always reports the same one first.
func validateConfigPaths(paths map[string]string) error {
	if len(paths) == 0 {
		return nil
	}
	keys := make([]string, 0, len(paths))
	for k := range paths {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := paths[key]
		if value == "" || !filepath.IsAbs(value) {
			return fmt.Errorf("probe config: config_paths[%q] must be an absolute path, got %q", key, value)
		}
	}
	return nil
}

func Load(path string) (Probe, error) {
	cfg := defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Probe{}, err
	}
	if len(raw) == 0 {
		return cfg, nil
	}
	// Post-parse ${ENV_VAR} expansion (design.md FP-M6-10): expand after
	// YAML parsing so secret values with YAML-significant characters are safe.
	// Re-marshal + Unmarshal into cfg preserves defaults for unset fields
	// (yaml.Node.Decode would zero missing fields).
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return Probe{}, err
	}
	envexpand.ExpandNode(&root)
	expanded, err := yaml.Marshal(&root)
	if err != nil {
		return Probe{}, err
	}
	if err := yaml.Unmarshal(expanded, &cfg); err != nil {
		return Probe{}, err
	}
	// design.md §11.2.3 A (FP-SW-1): config_paths values must be absolute
	// in-container paths, and this is enforced at load time -- after ${VAR}
	// expansion, so an unset variable expanding to "" is caught here rather
	// than producing a bare `cat` against the container's working directory.
	if err := validateConfigPaths(cfg.ConfigPaths); err != nil {
		return Probe{}, err
	}
	// Docker Swarm / Compose secret-file convention: when bootstrap_token is
	// empty after ${VAR} expansion, load it from BOOTSTRAP_TOKEN_FILE (the
	// mounted secret path). Keeps secrets out of process env while letting
	// probe-swarm-stack.yml enroll (FP-M6-12).
	if cfg.BootstrapToken == "" {
		if filePath := os.Getenv("BOOTSTRAP_TOKEN_FILE"); filePath != "" {
			rawTok, err := os.ReadFile(filePath)
			if err != nil {
				return Probe{}, err
			}
			cfg.BootstrapToken = strings.TrimSpace(string(rawTok))
		}
	}
	return cfg, nil
}
