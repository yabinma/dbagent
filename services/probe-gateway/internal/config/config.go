// Package config loads probe-gateway's deployment configuration (design.md
// Section 6/Appendix E extended with probe-gateway-specific values not
// covered by the control-plane YAML, since probe-gateway is a separate Go
// binary with its own small config surface: listen addresses, the
// Postgres DSN it shares with the rest of the control plane, and the
// bootstrap-CA / signing-key file paths).
package config

import (
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	// SessionListenAddr is the mTLS ProbeGateway.Session listener
	// (design.md Section 8.1: "the probe initiates an outbound gRPC
	// bidirectional stream ... mTLS").
	SessionListenAddr string `yaml:"session_listen_addr"`
	// BootstrapListenAddr is the server-TLS-only Bootstrap.Enroll
	// listener (proto/rcaprobe/v1/bootstrap.proto).
	BootstrapListenAddr string `yaml:"bootstrap_listen_addr"`

	PostgresDSN string `yaml:"postgres_dsn"`

	BootstrapCACertPath string `yaml:"bootstrap_ca_cert_path"`
	BootstrapCAKeyPath  string `yaml:"bootstrap_ca_key_path"`

	// SigningPublicKeyPath points at the control-plane's
	// `{key_path}.pub` sidecar (D14; rca_common.signing.signer
	// writes it -- see services/probe-gateway/internal/signingkeys).
	SigningPublicKeyPath string `yaml:"signing_public_key_path"`
	// SigningKeyGraceWindow mirrors design.md D14's "10-minute grace
	// window" default.
	SigningKeyGraceWindow time.Duration `yaml:"signing_key_grace_window"`

	GatewayReplica         string        `yaml:"gateway_replica"`
	HeartbeatTimeout       time.Duration `yaml:"heartbeat_timeout"`
	HeartbeatCheckInterval time.Duration `yaml:"heartbeat_check_interval"`
	SigningKeyPollInterval time.Duration `yaml:"signing_key_poll_interval"`

	// ServerCertSANs are the Subject Alternative Names (DNS names and/or
	// IP addresses -- bootstrapca.IssueServerCertificate treats
	// IP-shaped entries as IP SANs automatically) probe-gateway's mTLS
	// Session and Bootstrap.Enroll server certificates are issued with.
	// Defaults to the K8s Service DNS name convention ("probe-gateway");
	// override for compose/bare-metal deployments using a different
	// hostname, or to add an IP SAN for IP-address-only environments.
	ServerCertSANs []string `yaml:"server_cert_sans"`
}

func defaults() Config {
	return Config{
		SessionListenAddr:      ":8443",
		BootstrapListenAddr:    ":8444",
		BootstrapCACertPath:    "/etc/rca-agent/probe-gateway/bootstrap-ca.crt",
		BootstrapCAKeyPath:     "/etc/rca-agent/probe-gateway/bootstrap-ca.key",
		SigningPublicKeyPath:   "/etc/rca-agent/signing/ed25519.key.pub",
		SigningKeyGraceWindow:  10 * time.Minute,
		GatewayReplica:         "probe-gateway-0",
		HeartbeatTimeout:       60 * time.Second,
		HeartbeatCheckInterval: 15 * time.Second,
		SigningKeyPollInterval: 30 * time.Second,
		ServerCertSANs:         []string{"probe-gateway"},
	}
}

// Load reads a YAML config file, applying defaults for any unset fields.
func Load(path string) (Config, error) {
	cfg := defaults()
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}
