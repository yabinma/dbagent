package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad_AppliesDefaultsForUnsetFields(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("postgres_dsn: postgres://x\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.PostgresDSN != "postgres://x" {
		t.Fatalf("unexpected postgres_dsn: %s", cfg.PostgresDSN)
	}
	if cfg.SessionListenAddr != ":8443" {
		t.Fatalf("expected default session_listen_addr, got %s", cfg.SessionListenAddr)
	}
	if cfg.HeartbeatTimeout != 60*time.Second {
		t.Fatalf("expected default heartbeat_timeout, got %s", cfg.HeartbeatTimeout)
	}
	if cfg.SigningKeyGraceWindow != 10*time.Minute {
		t.Fatalf("expected default grace window, got %s", cfg.SigningKeyGraceWindow)
	}
}

func TestLoad_OverridesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	content := "session_listen_addr: \":9999\"\nheartbeat_timeout: 30s\ngateway_replica: replica-a\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.SessionListenAddr != ":9999" {
		t.Fatalf("unexpected session_listen_addr: %s", cfg.SessionListenAddr)
	}
	if cfg.HeartbeatTimeout != 30*time.Second {
		t.Fatalf("unexpected heartbeat_timeout: %s", cfg.HeartbeatTimeout)
	}
	if cfg.GatewayReplica != "replica-a" {
		t.Fatalf("unexpected gateway_replica: %s", cfg.GatewayReplica)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err == nil {
		t.Fatalf("expected error for missing config file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("not: [valid: yaml"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatalf("expected error for invalid yaml")
	}
}

func TestLoad_EnvInterpolation(t *testing.T) {
	t.Setenv("PG_DSN", "postgres://u:p@h/db")
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(path, []byte("postgres_dsn: ${PG_DSN}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PostgresDSN != "postgres://u:p@h/db" {
		t.Fatalf("got %q", cfg.PostgresDSN)
	}
	if cfg.InternalListenAddr != ":8080" {
		t.Fatalf("default internal lost: %q", cfg.InternalListenAddr)
	}
}
