package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_AppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(path, []byte("platform_key: presto-us1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PlatformKey != "presto-us1" {
		t.Fatalf("unexpected platform_key: %s", cfg.PlatformKey)
	}
	if cfg.CredentialsMount != "/etc/rca-probe/platform-credentials" {
		t.Fatalf("expected default credentials_mount, got %s", cfg.CredentialsMount)
	}
	if cfg.DockerAPIBaseURL != "http://docker" {
		t.Fatalf("expected default docker_api_base_url, got %s", cfg.DockerAPIBaseURL)
	}
}

func TestLoad_FullExample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	content := `
platform_key: presto-analytics-us1
gateway_address: probe-gateway.rca.example.com:8443
bootstrap_address: probe-gateway.rca.example.com:8444
bootstrap_token: "abc123"
bootstrap_ca_pin: "sha256:deadbeef"
coordinator_locator: "app=presto,role=coordinator"
credentials_mount: /etc/rca-probe/platform-credentials
write_enabled: false
insecure_skip_verify: false
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.GatewayAddress != "probe-gateway.rca.example.com:8443" {
		t.Fatalf("unexpected gateway_address: %s", cfg.GatewayAddress)
	}
	if cfg.BootstrapToken != "abc123" {
		t.Fatalf("unexpected bootstrap_token: %s", cfg.BootstrapToken)
	}
	if cfg.BootstrapCAPin != "sha256:deadbeef" {
		t.Fatalf("unexpected bootstrap_ca_pin: %s", cfg.BootstrapCAPin)
	}
	if cfg.WriteEnabled {
		t.Fatalf("expected write_enabled=false")
	}
}

func TestLoad_BootstrapCAPinDefaultsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(path, []byte("platform_key: presto-us1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.BootstrapCAPin != "" {
		t.Fatalf("expected bootstrap_ca_pin to default empty (TOFU), got %q", cfg.BootstrapCAPin)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatalf("expected error for missing file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(path, []byte("not: [valid"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected error for invalid yaml")
	}
}
