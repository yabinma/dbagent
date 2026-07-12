// Package config loads the probe's deployment parameters (design.md
// Appendix E "Probe deployment parameters").
package config

import (
	"os"

	"gopkg.in/yaml.v3"
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
	// DockerAPIBaseURL overrides the Docker Engine API base URL for Swarm
	// deployments (default assumes a docker socket proxy reachable at
	// "http://docker"). Configurable mainly so functional tests can point
	// it at an httptest-mocked Docker API instead of a real daemon.
	DockerAPIBaseURL string `yaml:"docker_api_base_url"`
}

func defaults() Probe {
	return Probe{
		CredentialsMount: "/etc/rca-probe/platform-credentials",
		StateDir:         "/var/lib/rca-probe",
		DockerAPIBaseURL: "http://docker",
	}
}

func Load(path string) (Probe, error) {
	cfg := defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Probe{}, err
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Probe{}, err
	}
	return cfg, nil
}
