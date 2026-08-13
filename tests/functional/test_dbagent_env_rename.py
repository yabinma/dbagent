"""FP-SW-8 function test (design.md §11.2.5): the `DBAGENT_*` environment
namespace, enforced fail-closed at every entry point.

Every Python entry point of §11.2.3 C.3 is launched as a real subprocess with
exactly one legacy `RCA_*` variable set and an otherwise valid environment; it
must exit non-zero naming both the old and the new variable. The dashboard-web
image's `sh` entrypoint is a second, independent implementation of the same
rule and is exercised once per shell-scope variable.

This file is on FP-SW-10's closed allowlist -- it necessarily names the legacy
variables.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

LEGACY_ENV_RENAMES = {
    "RCA_PG_DSN": "DBAGENT_PG_DSN",
    "RCA_POSTGRES_DSN": "DBAGENT_POSTGRES_DSN",
    "RCA_WORKER_CONFIG": "DBAGENT_WORKER_CONFIG",
    "RCA_GATEWAY_CONFIG": "DBAGENT_GATEWAY_CONFIG",
    "RCA_GATEWAY_HOST": "DBAGENT_GATEWAY_HOST",
    "RCA_GATEWAY_PORT": "DBAGENT_GATEWAY_PORT",
    "RCA_DASHBOARD_CONFIG": "DBAGENT_DASHBOARD_CONFIG",
    "RCA_DASHBOARD_HOST": "DBAGENT_DASHBOARD_HOST",
    "RCA_DASHBOARD_PORT": "DBAGENT_DASHBOARD_PORT",
    "RCA_SIGNING_KEY_PATH": "DBAGENT_SIGNING_KEY_PATH",
    "RCA_API_BASE_URL": "DBAGENT_API_BASE_URL",
    "RCA_API_UPSTREAM": "DBAGENT_API_UPSTREAM",
    "RCA_DOCROOT": "DBAGENT_DOCROOT",
}


def _sentence(old: str) -> str:
    return f"{old} is no longer read; rename it to {LEGACY_ENV_RENAMES[old]} (design.md §11.2.3 C.2)"


# The seven Python entry points of §11.2.3 C.3, each paired with the legacy
# variable its own component reads (so the case is realistic rather than
# arbitrary) and with the argv that reaches its detector.
PYTHON_ENTRY_POINTS = [
    ("gateway.main:main", "RCA_GATEWAY_CONFIG", ["-c", "from gateway.main import main; main()"]),
    ("worker.worker_main:main", "RCA_WORKER_CONFIG", ["-c", "from worker.worker_main import main; main()"]),
    ("dashboard_api.main:main", "RCA_DASHBOARD_CONFIG", ["-c", "from dashboard_api.main import main; main()"]),
    (
        "dashboard_api.bootstrap_admin:main",
        "RCA_DASHBOARD_CONFIG",
        ["-c", "from dashboard_api.bootstrap_admin import main; main()"],
    ),
    (
        "scripts/seed_playbooks.py",
        "RCA_POSTGRES_DSN",
        [str(REPO_ROOT / "services/worker/scripts/seed_playbooks.py")],
    ),
    (
        "scripts/bootstrap_signing_key.py",
        "RCA_SIGNING_KEY_PATH",
        [str(REPO_ROOT / "services/worker/scripts/bootstrap_signing_key.py")],
    ),
    (
        "migrations/env.py",
        "RCA_PG_DSN",
        [
            "-c",
            "import runpy; runpy.run_path("
            f"{str(REPO_ROOT / 'libs/py/rca_common/migrations/env.py')!r})",
        ],
    ),
]


def _clean_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in LEGACY_ENV_RENAMES}
    # An otherwise valid environment: the entry points that need a config path
    # get one under the new namespace.
    env["DBAGENT_WORKER_CONFIG"] = str(REPO_ROOT / "deploy/compose/config/dbagent.yaml")
    env["DBAGENT_GATEWAY_CONFIG"] = env["DBAGENT_WORKER_CONFIG"]
    env["DBAGENT_DASHBOARD_CONFIG"] = env["DBAGENT_WORKER_CONFIG"]
    return env


def _run(
    argv: list[str], env: dict[str, str], *, timeout: float = 120
) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *argv],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


@pytest.mark.parametrize(
    "name,legacy,argv", PYTHON_ENTRY_POINTS, ids=[e[0] for e in PYTHON_ENTRY_POINTS]
)
def test_entry_points_reject_legacy_rca_env_vars(name, legacy, argv):
    env = _clean_env()
    env[legacy] = "set-by-an-operator-who-has-not-read-the-upgrade-note"
    proc = _run(argv, env)
    assert proc.returncode != 0, f"{name} started with {legacy} set:\n{proc.stdout}\n{proc.stderr}"
    combined = proc.stdout + proc.stderr
    assert _sentence(legacy) in combined, f"{name} did not name {legacy} -> {LEGACY_ENV_RENAMES[legacy]}:\n{combined}"


@pytest.mark.parametrize(
    "name,legacy,argv", PYTHON_ENTRY_POINTS, ids=[e[0] for e in PYTHON_ENTRY_POINTS]
)
def test_clean_environment_does_not_trip_the_detector(name, legacy, argv):
    # The entry points may still fail for unrelated reasons (no database, no
    # alembic context, ...); what must not happen is the legacy diagnostic.
    # gateway.main is now uvicorn's worker-manager (FP-IG-20): a clean
    # environment starts the supervisor and does not exit, which is not a
    # detector trip. Bound that case so the suite does not wait 120s.
    timeout = 8 if name == "gateway.main:main" else 120
    try:
        proc = _run(argv, _clean_env(), timeout=timeout)
        combined = proc.stdout + proc.stderr
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or b""
        err = exc.stderr or b""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        if isinstance(err, bytes):
            err = err.decode("utf-8", "replace")
        combined = out + err
    for old in LEGACY_ENV_RENAMES:
        assert _sentence(old) not in combined, f"{name} tripped on a clean environment:\n{combined}"


# --- the dashboard-web `sh` entrypoint: a second, independent implementation ---

NGINX_ENTRYPOINT = REPO_ROOT / "deploy/docker/nginx/10-dbagent-config.sh"
SHELL_SCOPE_LEGACY = ["RCA_API_BASE_URL", "RCA_API_UPSTREAM", "RCA_DOCROOT"]


@pytest.mark.parametrize("legacy", SHELL_SCOPE_LEGACY)
def test_dashboard_web_entrypoint_rejects_legacy_env(legacy, tmp_path):
    assert NGINX_ENTRYPOINT.is_file()
    env = _clean_env()
    env[legacy] = "legacy-value"
    env["DBAGENT_DOCROOT"] = str(tmp_path)
    proc = subprocess.run(
        ["sh", str(NGINX_ENTRYPOINT)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert _sentence(legacy) in proc.stdout + proc.stderr
    assert not (tmp_path / "config.js").exists(), "the entrypoint wrote config.js despite refusing"


def test_dashboard_web_entrypoint_still_writes_config_js_on_a_clean_environment(tmp_path):
    env = _clean_env()
    env["DBAGENT_DOCROOT"] = str(tmp_path)
    env["DBAGENT_API_BASE_URL"] = "/api/v1"
    proc = subprocess.run(
        ["sh", str(NGINX_ENTRYPOINT)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    written = (tmp_path / "config.js").read_text(encoding="utf-8")
    assert '__DBAGENT_CONFIG__' in written
    assert '"apiBaseUrl": "/api/v1"' in written


# --- the operator-facing upgrade note ---


def test_upgrade_runbook_names_every_old_to_new_pair():
    doc = (REPO_ROOT / "docs/runbooks/upgrade-and-rollback.md").read_text(encoding="utf-8")
    for old, new in LEGACY_ENV_RENAMES.items():
        assert old in doc, f"{old} missing from the upgrade runbook"
        assert new in doc, f"{new} missing from the upgrade runbook"
        # The pair must be legible as a pair, not merely both present somewhere.
        assert f"{old}" in doc and f"{new}" in doc
    # The pairs are documented on one line each, old -> new.
    for old, new in LEGACY_ENV_RENAMES.items():
        assert any(
            old in line and new in line for line in doc.splitlines()
        ), f"{old} -> {new} is not documented as a pair on one line"
