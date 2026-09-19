package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
	if cfg.CredentialsMount != "/etc/dbagent-probe/platform-credentials" {
		t.Fatalf("expected default credentials_mount, got %s", cfg.CredentialsMount)
	}
	if cfg.DockerAPIBaseURL != "unix:///var/run/docker.sock" {
		t.Fatalf("expected default docker_api_base_url, got %s", cfg.DockerAPIBaseURL)
	}
}

func TestLoad_FullExample(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	content := `
platform_key: presto-analytics-us1
gateway_address: probe-gateway.example.com:8443
bootstrap_address: probe-gateway.example.com:8444
bootstrap_token: "abc123"
bootstrap_ca_pin: "sha256:deadbeef"
coordinator_locator: "app=presto,role=coordinator"
credentials_mount: /etc/dbagent-probe/platform-credentials
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
	if cfg.GatewayAddress != "probe-gateway.example.com:8443" {
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

func TestLoad_EnvInterpolation(t *testing.T) {
	t.Setenv("BOOTSTRAP_TOKEN", "tok-from-env")
	dir := t.TempDir()
	path := dir + "/cfg.yaml"
	if err := os.WriteFile(path, []byte("platform_key: p1\nbootstrap_token: ${BOOTSTRAP_TOKEN}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BootstrapToken != "tok-from-env" {
		t.Fatalf("got %q", cfg.BootstrapToken)
	}
	if cfg.CredentialsMount == "" {
		t.Fatal("defaults lost")
	}
}

func TestLoad_BootstrapTokenFileWhenEmpty(t *testing.T) {
	// Swarm path: config expands ${BOOTSTRAP_TOKEN} to empty; file supplies it.
	t.Setenv("BOOTSTRAP_TOKEN", "")
	dir := t.TempDir()
	tokFile := dir + "/bootstrap_token"
	if err := os.WriteFile(tokFile, []byte("  secret-from-file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BOOTSTRAP_TOKEN_FILE", tokFile)
	path := dir + "/cfg.yaml"
	if err := os.WriteFile(path, []byte("platform_key: p1\nbootstrap_token: ${BOOTSTRAP_TOKEN}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BootstrapToken != "secret-from-file" {
		t.Fatalf("got %q", cfg.BootstrapToken)
	}
}

// FP-KR-20
func TestLoad_SigningKeyGraceWindowDefaultAndOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(path, []byte("platform_key: presto-us1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SigningKeyGraceWindow != 10*time.Minute {
		t.Fatalf("default signing_key_grace_window = %s, want 10m", cfg.SigningKeyGraceWindow)
	}

	path2 := filepath.Join(dir, "probe2.yaml")
	if err := os.WriteFile(path2, []byte("platform_key: p1\nsigning_key_grace_window: 30s\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg2, err := Load(path2)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.SigningKeyGraceWindow != 30*time.Second {
		t.Fatalf("override = %s, want 30s", cfg2.SigningKeyGraceWindow)
	}
}

// --- UT-SW-1 (design.md §11.2.5): config_paths + the new defaults, and the
// documented Appendix E example loading through Load. ---

// FP-SW-1
func TestLoad_ConfigPathsParsesEveryFileForm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	content := `platform_key: p1
config_paths:
  config:          /opt/presto-server/etc/config.properties
  jvm:             /opt/presto-server/etc/jvm.config
  node:            /opt/presto-server/etc/node.properties
  "catalog:hive":  /opt/presto-server/etc/catalog/hive.properties
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := map[string]string{
		"config":       "/opt/presto-server/etc/config.properties",
		"jvm":          "/opt/presto-server/etc/jvm.config",
		"node":         "/opt/presto-server/etc/node.properties",
		"catalog:hive": "/opt/presto-server/etc/catalog/hive.properties",
	}
	if len(cfg.ConfigPaths) != len(want) {
		t.Fatalf("config_paths = %#v, want %d entries", cfg.ConfigPaths, len(want))
	}
	for k, v := range want {
		if cfg.ConfigPaths[k] != v {
			t.Fatalf("config_paths[%q] = %q, want %q", k, cfg.ConfigPaths[k], v)
		}
	}
}

// FP-SW-1
func TestLoad_ConfigPathsAbsentIsNil(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(path, []byte("platform_key: p1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigPaths != nil {
		t.Fatalf("expected nil config_paths, got %#v", cfg.ConfigPaths)
	}
}

// FP-SW-1
func TestLoad_ConfigPathsExpandsEnvVars(t *testing.T) {
	t.Setenv("PRESTO_ETC", "/opt/presto-server/etc")
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(path, []byte("platform_key: p1\nconfig_paths:\n  config: ${PRESTO_ETC}/config.properties\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.ConfigPaths["config"]; got != "/opt/presto-server/etc/config.properties" {
		t.Fatalf("config_paths[config] = %q", got)
	}
}

// FP-SW-1: relative, empty and post-expansion-empty values are each a named
// load-time error (design review DW2).
func TestLoad_ConfigPathsMustBeAbsolute(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		env     map[string]string
		wantMsg string
	}{
		{
			name:    "relative",
			yaml:    "platform_key: p1\nconfig_paths:\n  config: etc/presto/config.properties\n",
			wantMsg: `probe config: config_paths["config"] must be an absolute path, got "etc/presto/config.properties"`,
		},
		{
			name:    "empty",
			yaml:    "platform_key: p1\nconfig_paths:\n  jvm: \"\"\n",
			wantMsg: `probe config: config_paths["jvm"] must be an absolute path, got ""`,
		},
		{
			name:    "empty after expansion",
			yaml:    "platform_key: p1\nconfig_paths:\n  node: ${PRESTO_ETC_UNSET}\n",
			env:     map[string]string{"PRESTO_ETC_UNSET": ""},
			wantMsg: `probe config: config_paths["node"] must be an absolute path, got ""`,
		},
		{
			name:    "catalog key relative",
			yaml:    "platform_key: p1\nconfig_paths:\n  \"catalog:hive\": catalog/hive.properties\n",
			wantMsg: `probe config: config_paths["catalog:hive"] must be an absolute path, got "catalog/hive.properties"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			dir := t.TempDir()
			path := filepath.Join(dir, "probe.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o644); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path)
			if err == nil {
				t.Fatalf("expected an error for %s", tc.name)
			}
			if err.Error() != tc.wantMsg {
				t.Fatalf("error = %q, want %q", err.Error(), tc.wantMsg)
			}
		})
	}
}

// FP-SW-2/FP-SW-7: the renamed container-path defaults and the unix-socket
// Docker API default.
func TestLoad_DefaultsAreDbagentPaths(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "probe.yaml")
	if err := os.WriteFile(path, []byte("platform_key: p1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.DockerAPIBaseURL != "unix:///var/run/docker.sock" {
		t.Fatalf("docker_api_base_url default = %q", cfg.DockerAPIBaseURL)
	}
	if cfg.CredentialsMount != "/etc/dbagent-probe/platform-credentials" {
		t.Fatalf("credentials_mount default = %q", cfg.CredentialsMount)
	}
	if cfg.StateDir != "/var/lib/dbagent-probe" {
		t.Fatalf("state_dir default = %q", cfg.StateDir)
	}
}

// FP-SW-11 (design review D4): the block Appendix E prints is a file that
// actually loads. testdata/appendix-e-example.yaml is kept byte-identical to
// it (asserted by tests/delivery/test_delivery_docs.py against
// docs/configuration.md, which in turn is byte-identical to the appendix).
func TestLoad_AppendixEExampleLoads(t *testing.T) {
	t.Setenv("BOOTSTRAP_TOKEN", "tok-from-env")
	cfg, err := Load(filepath.Join("testdata", "appendix-e-example.yaml"))
	if err != nil {
		t.Fatalf("Appendix E example does not load: %v", err)
	}
	if cfg.PlatformKey != "presto-analytics-us1" {
		t.Fatalf("platform_key = %q", cfg.PlatformKey)
	}
	if cfg.GatewayAddress != "probe-gateway.example.com:443" {
		t.Fatalf("gateway_address = %q", cfg.GatewayAddress)
	}
	if cfg.BootstrapAddress != "probe-gateway.example.com:8443" {
		t.Fatalf("bootstrap_address = %q", cfg.BootstrapAddress)
	}
	if cfg.BootstrapToken != "tok-from-env" {
		t.Fatalf("bootstrap_token = %q", cfg.BootstrapToken)
	}
	if cfg.BootstrapCAPin != "" {
		t.Fatalf("bootstrap_ca_pin = %q", cfg.BootstrapCAPin)
	}
	if cfg.StateDir != "/var/lib/dbagent-probe" {
		t.Fatalf("state_dir = %q", cfg.StateDir)
	}
	if cfg.CredentialsMount != "/etc/dbagent-probe/platform-credentials" {
		t.Fatalf("credentials_mount = %q", cfg.CredentialsMount)
	}
	if cfg.WriteEnabled {
		t.Fatalf("write_enabled = true")
	}
	if cfg.InsecureSkipVerify {
		t.Fatalf("insecure_skip_verify = true")
	}
	if cfg.SigningKeyGraceWindow != 10*time.Minute {
		t.Fatalf("signing_key_grace_window = %s", cfg.SigningKeyGraceWindow)
	}
	if cfg.CoordinatorLocator != "app=presto,role=coordinator" {
		t.Fatalf("coordinator_locator = %q", cfg.CoordinatorLocator)
	}
	if cfg.Namespace != "presto" {
		t.Fatalf("namespace = %q", cfg.Namespace)
	}
	if cfg.CoordinatorService != "presto-coordinator" {
		t.Fatalf("coordinator_service = %q", cfg.CoordinatorService)
	}
	if cfg.WorkerService != "presto-worker" {
		t.Fatalf("worker_service = %q", cfg.WorkerService)
	}
	if cfg.CoordinatorPort != 8080 {
		t.Fatalf("coordinator_port = %d", cfg.CoordinatorPort)
	}
	if cfg.CoordinatorHTTPS {
		t.Fatalf("coordinator_https = true")
	}
	if cfg.DockerAPIBaseURL != "unix:///var/run/docker.sock" {
		t.Fatalf("docker_api_base_url = %q", cfg.DockerAPIBaseURL)
	}
	wantPaths := map[string]string{
		"config":       "/opt/presto-server/etc/config.properties",
		"jvm":          "/opt/presto-server/etc/jvm.config",
		"node":         "/opt/presto-server/etc/node.properties",
		"catalog:hive": "/opt/presto-server/etc/catalog/hive.properties",
	}
	if len(cfg.ConfigPaths) != len(wantPaths) {
		t.Fatalf("config_paths = %#v", cfg.ConfigPaths)
	}
	for k, v := range wantPaths {
		if cfg.ConfigPaths[k] != v {
			t.Fatalf("config_paths[%q] = %q, want %q", k, cfg.ConfigPaths[k], v)
		}
	}
}
