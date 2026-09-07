"""Tests for the signing-key bootstrap entrypoint script (design.md D14:
"idempotent pre-install job"). Imported by path since the script is meant
to be invoked standalone (Helm hook / compose init container), not
packaged as part of `worker`.
"""
from __future__ import annotations

import base64
import importlib.util
import os
import stat
import sys
from pathlib import Path

_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "bootstrap_signing_key.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("bootstrap_signing_key", _SCRIPT_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


bootstrap_signing_key_script = _load_module()


def test_generates_new_key_with_0600_perms_and_exits_zero(tmp_path, caplog):
    key_path = tmp_path / "signing" / "ed25519.key"
    with caplog.at_level("INFO", logger="bootstrap_signing_key"):
        exit_code = bootstrap_signing_key_script.main(["--key-path", str(key_path)])

    assert exit_code == 0
    assert key_path.exists()
    assert stat.S_IMODE(os.stat(key_path).st_mode) == 0o600

    assert "generated new" in caplog.text
    assert "public key (base64):" in caplog.text


def test_is_idempotent_on_second_invocation(tmp_path, caplog):
    key_path = tmp_path / "ed25519.key"
    bootstrap_signing_key_script.main(["--key-path", str(key_path)])
    raw_1 = key_path.read_bytes()

    with caplog.at_level("INFO", logger="bootstrap_signing_key"):
        exit_code = bootstrap_signing_key_script.main(["--key-path", str(key_path)])
    raw_2 = key_path.read_bytes()

    assert exit_code == 0
    assert raw_1 == raw_2
    assert "loaded existing" in caplog.text


def test_reads_key_path_from_env_var(tmp_path, monkeypatch):
    key_path = tmp_path / "from-env" / "ed25519.key"
    monkeypatch.setenv("DBAGENT_SIGNING_KEY_PATH", str(key_path))

    exit_code = bootstrap_signing_key_script.main([])

    assert exit_code == 0
    assert key_path.exists()


def test_returns_nonzero_on_os_error(tmp_path, monkeypatch):
    # A path whose parent cannot be created (parent is a file, not a dir)
    # forces bootstrap_signing_key() to raise OSError.
    blocking_file = tmp_path / "not-a-directory"
    blocking_file.write_text("x")
    key_path = blocking_file / "ed25519.key"

    exit_code = bootstrap_signing_key_script.main(["--key-path", str(key_path)])

    assert exit_code == 1


def test_public_key_is_valid_base64_32_bytes(tmp_path, caplog):
    key_path = tmp_path / "ed25519.key"
    with caplog.at_level("INFO", logger="bootstrap_signing_key"):
        bootstrap_signing_key_script.main(["--key-path", str(key_path)])
    line = next(l for l in caplog.text.splitlines() if "public key (base64):" in l)
    b64 = line.split("public key (base64):", 1)[1].strip()
    assert len(base64.b64decode(b64)) == 32
