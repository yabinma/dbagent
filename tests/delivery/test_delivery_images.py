"""FP-M6-1..4: product image Dockerfiles, build.sh, nginx runtime, packaging invariants."""
from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

from delivery_helpers import (
    DOCKER_DIR,
    PRODUCT_DOCKERFILES,
    REPO_ROOT,
    VERSIONS_ENV,
    load_versions,
)


def test_six_product_images_one_process_each():
    files = sorted(p.name for p in DOCKER_DIR.glob("*.Dockerfile"))
    assert files == sorted(PRODUCT_DOCKERFILES)
    for name in PRODUCT_DOCKERFILES:
        text = (DOCKER_DIR / name).read_text(encoding="utf-8")
        # Final stage: exactly one ENTRYPOINT or CMD.
        stages = re.split(r"(?mi)^\s*FROM\s+", text)
        final = stages[-1]
        entrypoints = re.findall(r"(?mi)^\s*ENTRYPOINT\b", final)
        cmds = re.findall(r"(?mi)^\s*CMD\b", final)
        assert len(entrypoints) + len(cmds) >= 1, name
        assert len(entrypoints) <= 1 and len(cmds) <= 1, name


def test_from_args_declared_before_first_from():
    """C1: every ARG consumed by a FROM must be a global build-arg (pre-first-FROM)."""
    for name in PRODUCT_DOCKERFILES:
        text = (DOCKER_DIR / name).read_text(encoding="utf-8")
        first_from = re.search(r"(?mi)^\s*FROM\b", text)
        assert first_from, name
        preamble = text[: first_from.start()]
        global_args = set(re.findall(r"(?mi)^\s*ARG\s+(\w+)", preamble))
        for m in re.finditer(r"(?mi)^\s*FROM\s+\$\{(\w+)\}", text):
            arg = m.group(1)
            assert arg in global_args, (
                f"{name}: FROM ${{{arg}}} but ARG {arg} is not declared before the first FROM"
            )


def test_build_script_and_dockerignore_and_version_pins():
    build = DOCKER_DIR / "build.sh"
    assert build.is_file()
    assert build.stat().st_mode & stat.S_IXUSR
    text = build.read_text(encoding="utf-8")
    assert "gen-proto.sh" in text
    assert "generate-pydantic" in text
    assert "generate-ts" in text
    assert "buildx" in text
    for comp in [
        "ingest-gateway",
        "temporal-worker",
        "probe-gateway",
        "dashboard-api",
        "dashboard-web",
        "probe",
    ]:
        assert comp in text

    di = REPO_ROOT / ".dockerignore"
    assert di.is_file()
    body = di.read_text(encoding="utf-8")
    for needle in ["**/.venv", "**/node_modules", ".git"]:
        assert needle in body
    # Must NOT exclude generated trees.
    assert "gen/" not in body or re.search(r"(?m)^(?!#)gen/", body) is None


def test_versions_env_is_the_only_pin_source():
    vers = load_versions()
    required = [
        "PYTHON_IMAGE",
        "GO_IMAGE",
        "GO_RUNTIME_IMAGE",
        "NODE_IMAGE",
        "NGINX_IMAGE",
        "POSTGRES_IMAGE",
        "MINIO_IMAGE",
        "MINIO_MC_IMAGE",
        "TEMPORAL_AUTOSETUP_IMAGE",
        "TEMPORAL_UI_IMAGE",
        "LITELLM_IMAGE",
        "PRESTO_IMAGE",
        "KIND_NODE_IMAGE",
        "TEMPORAL_CHART_VERSION",
        "HELM_VERSION",
        "KIND_VERSION",
        "BUF_VERSION",
        "GO_VERSION",
        "PYTHON_VERSION",
        "NODE_VERSION",
    ]
    for k in required:
        assert k in vers, k

    # Chart.lock agrees with TEMPORAL_CHART_VERSION.
    lock = (REPO_ROOT / "deploy/charts/rca-agent/Chart.lock").read_text(encoding="utf-8")
    assert vers["TEMPORAL_CHART_VERSION"] in lock
    tgz = REPO_ROOT / "deploy/charts/rca-agent/charts" / f"temporal-{vers['TEMPORAL_CHART_VERSION']}.tgz"
    assert tgz.is_file(), tgz

    # Every Dockerfile FROM ARG default resolves to a versions.env key value.
    for name in PRODUCT_DOCKERFILES:
        text = (DOCKER_DIR / name).read_text(encoding="utf-8")
        for m in re.finditer(r"ARG\s+(\w+)=([^\s]+)", text):
            arg, default = m.group(1), m.group(2)
            if arg in vers:
                assert default == vers[arg] or default in vers.values(), (name, arg, default)


def test_dashboard_web_nginx_config_and_runtime_config_js():
    conf = (DOCKER_DIR / "nginx/default.conf.template").read_text(encoding="utf-8")
    assert "try_files $uri /index.html" in conf
    assert "/healthz" in conf
    assert "proxy_pass ${RCA_API_UPSTREAM}" in conf

    script = DOCKER_DIR / "nginx/10-rca-config.sh"
    assert script.is_file()
    assert script.stat().st_mode & stat.S_IXUSR

    with tempfile.TemporaryDirectory() as td:
        # Execute with RCA_API_BASE_URL set.
        env = os.environ.copy()
        env["RCA_API_BASE_URL"] = "https://api.example/v1"
        env["RCA_DOCROOT"] = td
        subprocess.run(["sh", str(script)], check=True, env=env)
        js = Path(td, "config.js").read_text(encoding="utf-8")
        assert 'window.__RCA_CONFIG__ = {"apiBaseUrl": "https://api.example/v1"};' in js

        # Unset → default /api/v1
        env.pop("RCA_API_BASE_URL", None)
        subprocess.run(["sh", str(script)], check=True, env=env)
        js = Path(td, "config.js").read_text(encoding="utf-8")
        assert 'window.__RCA_CONFIG__ = {"apiBaseUrl": "/api/v1"};' in js


def test_packaging_invariants_no_go_python_mix_nonroot_no_latest():
    vers = load_versions()
    # No :latest in deploy/**
    for p in (REPO_ROOT / "deploy").rglob("*"):
        if p.is_file() and p.suffix in {".yml", ".yaml", ".Dockerfile", ".env", ".md", ".sh", ".tpl"} or p.name.endswith("Dockerfile"):
            text = p.read_text(encoding="utf-8", errors="replace")
            # Allow comments mentioning latest, but not image tags.
            for m in re.finditer(r"(?i)(?:image:|FROM\s+)\s*[^\s]*:latest\b", text):
                raise AssertionError(f":latest tag in {p}: {m.group(0)}")

    for name in PRODUCT_DOCKERFILES:
        text = (DOCKER_DIR / name).read_text(encoding="utf-8")
        stages = re.split(r"(?mi)^\s*FROM\s+", text)
        final = stages[-1]
        # non-root USER
        assert re.search(r"(?mi)^\s*USER\s+", final), f"{name} missing USER in final stage"
        user = re.findall(r"(?mi)^\s*USER\s+(\S+)", final)[-1]
        assert user not in {"root", "0"}, name
        # No Go+Python mix in final image: final should not install both runtimes.
        lower = final.lower()
        full_lower = text.lower()
        if name in ("probe.Dockerfile", "probe-gateway.Dockerfile"):
            assert "python" not in lower
            # Runtime base is GO_RUNTIME_IMAGE (distroless/static), declared pre-FROM.
            assert "go_runtime_image" in full_lower or "distroless" in full_lower
        if name in (
            "ingest-gateway.Dockerfile",
            "temporal-worker.Dockerfile",
            "dashboard-api.Dockerfile",
        ):
            assert "golang" not in lower and "distroless" not in lower
            assert "python" in full_lower or "USER 10001" in final or "useradd" in full_lower
        if name == "dashboard-web.Dockerfile":
            assert "nginx" in full_lower
