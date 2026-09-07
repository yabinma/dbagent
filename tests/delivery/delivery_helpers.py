"""Helpers for the delivery-artifact tier (unique basename — never helpers.py)."""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEPLOY = REPO_ROOT / "deploy"
VERSIONS_ENV = DEPLOY / "versions.env"
DOCKER_DIR = DEPLOY / "docker"
CHARTS = DEPLOY / "charts"
COMPOSE = DEPLOY / "compose"
DOCS = REPO_ROOT / "docs"
CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"

PRODUCT_DOCKERFILES = [
    "ingest-gateway.Dockerfile",
    "temporal-worker.Dockerfile",
    "probe-gateway.Dockerfile",
    "dashboard-api.Dockerfile",
    "dashboard-web.Dockerfile",
    "probe.Dockerfile",
]


def load_versions() -> dict[str, str]:
    out: dict[str, str] = {}
    for line in VERSIONS_ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip()
    return out


def require_bin(name: str) -> str:
    from shutil import which

    path = which(name)
    if not path:
        raise RuntimeError(
            f"required tool {name!r} not found on PATH "
            f"(install the pin from deploy/versions.env; delivery tests never skip)"
        )
    return path


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kwargs)


def helm_template(chart: Path, values: list[str] | None = None, set_args: list[str] | None = None) -> str:
    require_bin("helm")
    cmd = ["helm", "template", "t", str(chart)]
    for v in values or []:
        cmd.extend(["-f", v])
    for s in set_args or []:
        cmd.extend(["--set", s])
    proc = run(cmd, cwd=str(REPO_ROOT))
    if proc.returncode != 0:
        raise RuntimeError(f"helm template failed: {proc.stderr or proc.stdout}")
    return proc.stdout


def parse_manifests(rendered: str) -> list[dict]:
    docs = []
    for doc in yaml.safe_load_all(rendered):
        if doc:
            docs.append(doc)
    return docs
