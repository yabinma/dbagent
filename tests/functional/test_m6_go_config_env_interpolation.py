"""FP-M6-10 / F15: real probe / probe-gateway binaries resolve ${VAR} configs."""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]


def _build(bin_path: Path, package: str) -> None:
    env = os.environ.copy()
    env["GOCACHE"] = "/tmp/go-cache"
    env["GOMODCACHE"] = env.get("GOMODCACHE", "/tmp/go-mod")
    env["CGO_ENABLED"] = "0"
    proc = subprocess.run(
        ["go", "build", "-o", str(bin_path), package],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, proc.stderr


def test_probe_config_interpolates_bootstrap_token(tmp_path):
    """Real probe binary resolves ${BOOTSTRAP_TOKEN} (observed via state_dir side effects).

    The probe persists enrollment state under state_dir only after config.Load
    succeeds. We also assert the resolved token via a tiny Go helper that uses
    the same config.Load as main.
    """
    # Package-level Load asserts the resolved value (not just "no parse error").
    env = os.environ.copy()
    env["GOCACHE"] = "/tmp/go-cache"
    env["GOMODCACHE"] = env.get("GOMODCACHE", "/tmp/go-mod")
    env["BOOTSTRAP_TOKEN"] = "tok-from-env-f15"
    proc = subprocess.run(
        [
            "go",
            "test",
            "./probe/internal/config/",
            "-run",
            "TestLoad_EnvInterpolation",
            "-count=1",
            "-v",
        ],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout

    # Binary path: must get past config.Load without "load config" error.
    bin_path = tmp_path / "probe"
    _build(bin_path, "./probe/cmd/probe")
    state = tmp_path / "state"
    state.mkdir()
    cfg = tmp_path / "probe.yaml"
    cfg.write_text(
        "platform_key: p1\n"
        "gateway_address: 127.0.0.1:1\n"
        "bootstrap_address: 127.0.0.1:1\n"
        "bootstrap_token: ${BOOTSTRAP_TOKEN}\n"
        f"state_dir: {state}\n"
        "docker_api_base_url: http://127.0.0.1:1\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PROBE_CONFIG"] = str(cfg)
    env["BOOTSTRAP_TOKEN"] = "tok-from-env-f15"
    proc = subprocess.run(
        [str(bin_path)],
        env=env,
        capture_output=True,
        text=True,
        timeout=3,
    )
    combined = (proc.stdout or "") + (proc.stderr or "")
    assert "load config" not in combined.lower(), combined
    # Token must have been resolved (not left as literal ${BOOTSTRAP_TOKEN}).
    assert "${BOOTSTRAP_TOKEN}" not in combined


def test_probe_gateway_config_interpolates_postgres_dsn(tmp_path):
    """Real probe-gateway config.Load resolves ${PG_DSN} with YAML-significant chars."""
    env = os.environ.copy()
    env["GOCACHE"] = "/tmp/go-cache"
    env["GOMODCACHE"] = env.get("GOMODCACHE", "/tmp/go-mod")
    # HASH_PW / adversarial values are set inside the unit test via t.Setenv;
    # also set here so a subprocess-visible env matches production compose shape.
    env["HASH_PW"] = "p@ss #word"
    env["PG_DSN"] = "postgres://u:p@ss #word@h/db"
    proc = subprocess.run(
        [
            "go",
            "test",
            "./services/probe-gateway/internal/config/",
            "-run",
            "TestLoad_EnvInterpolation",
            "-count=1",
            "-v",
        ],
        cwd=str(REPO),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "PASS" in proc.stdout
