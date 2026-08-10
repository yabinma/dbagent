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
    lock = (REPO_ROOT / "deploy/charts/dbagent/Chart.lock").read_text(encoding="utf-8")
    assert vers["TEMPORAL_CHART_VERSION"] in lock
    tgz = REPO_ROOT / "deploy/charts/dbagent/charts" / f"temporal-{vers['TEMPORAL_CHART_VERSION']}.tgz"
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
    assert "proxy_pass ${DBAGENT_API_UPSTREAM}" in conf

    script = DOCKER_DIR / "nginx/10-dbagent-config.sh"
    assert script.is_file()
    assert script.stat().st_mode & stat.S_IXUSR

    with tempfile.TemporaryDirectory() as td:
        # Execute with DBAGENT_API_BASE_URL set.
        env = os.environ.copy()
        env["DBAGENT_API_BASE_URL"] = "https://api.example/v1"
        env["DBAGENT_DOCROOT"] = td
        subprocess.run(["sh", str(script)], check=True, env=env)
        js = Path(td, "config.js").read_text(encoding="utf-8")
        assert 'window.__DBAGENT_CONFIG__ = {"apiBaseUrl": "https://api.example/v1"};' in js

        # Unset → default /api/v1
        env.pop("DBAGENT_API_BASE_URL", None)
        subprocess.run(["sh", str(script)], check=True, env=env)
        js = Path(td, "config.js").read_text(encoding="utf-8")
        assert 'window.__DBAGENT_CONFIG__ = {"apiBaseUrl": "/api/v1"};' in js


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


# --- FP-SW-5 (design.md §11.2.5): the registry coordinate is `dbagent` and is
# single-sourced from deploy/versions.env. ---

# The closed C.1 row-2a list: the only places allowed to repeat the value,
# because Helm cannot read versions.env and the documented `docker compose` /
# `docker stack` commands do not load it.
ROW_2A_LOCATIONS = [
    "deploy/charts/dbagent/values.yaml",
    "deploy/charts/dbagent-probe/values.yaml",
    "tests/e2e/values-dbagent.yaml",
    "tests/e2e/values-dbagent-probe.yaml",
    "deploy/compose/control-plane.yml",
    "deploy/compose/probe.yml",
    "deploy/compose/probe-swarm-stack.yml",
]

# Byte pattern so non-UTF-8 / binary tracked files are not silently omitted
# (review W1 / FP-SW-5 — same technique as FP-SW-10's forward guard).
_GHCR_YABINMA_BYTES = re.compile(rb"ghcr\.io/yabinma/[A-Za-z0-9._/-]*")


def _git_tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=str(REPO_ROOT), capture_output=True, text=True, check=True
    ).stdout.split("\n")
    return [REPO_ROOT / f for f in out if f]


def test_registry_coordinate_is_dbagent_and_single_sourced():
    import yaml

    vers = load_versions()
    registry = vers["REGISTRY"]
    # Assert components without embedding the complete slash-delimited
    # coordinate (FP-SW-5: read versions.env; do not become a second source).
    host, org, name = registry.split("/")
    assert host == "ghcr.io", f"REGISTRY host is {host!r}, expected ghcr.io"
    assert org == "yabinma", f"REGISTRY org is {org!r}, expected yabinma"
    assert name == "dbagent", f"REGISTRY name is {name!r}, expected dbagent"

    # Each row-2a location that sets a registry value equals versions.env
    # byte-for-byte. A location that sets none is skipped, not demanded.
    checked = 0
    for rel in ROW_2A_LOCATIONS:
        path = REPO_ROOT / rel
        assert path.is_file(), rel
        text = path.read_text(encoding="utf-8")
        if rel.endswith((".yml",)):
            found = re.findall(r"\$\{REGISTRY:-([^}]+)\}", text)
            for value in found:
                assert value == registry, f"{rel}: ${{REGISTRY:-{value}}} != {registry}"
                checked += 1
            continue
        data = yaml.safe_load(text) or {}
        values = []
        if isinstance(data.get("global"), dict) and "imageRegistry" in data["global"]:
            values.append(data["global"]["imageRegistry"])
        if isinstance(data.get("image"), dict) and "registry" in data["image"]:
            values.append(data["image"]["registry"])
        for value in values:
            assert value == registry, f"{rel}: {value!r} != {registry!r}"
            checked += 1
    assert checked >= 5, "expected the row-2a locations to actually set a registry"

    # Tree-wide: no other git-tracked file carries a host/org registry literal
    # (DW6 -- a duplicate in a root script, a service or a doc must fail).
    # Closed exemption list only: versions.env and the row-2a repeat locations
    # (plus design/ and gen/, which are local/generated and may name the
    # coordinate in prose). This test file is NOT exempt — it asserts via
    # components so it must not embed the complete coordinate itself.
    exempt = {"deploy/versions.env", *ROW_2A_LOCATIONS}
    offenders: list[str] = []
    scanned = 0
    candidates: list[Path] = []
    for path in _git_tracked_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        if rel in exempt or rel.startswith(("design/", "gen/")):
            continue
        if not path.is_file():
            continue
        candidates.append(path)
        data = path.read_bytes()
        scanned += 1
        for match in _GHCR_YABINMA_BYTES.finditer(data):
            offenders.append(f"{rel}: {match.group(0)!r}")
    # Every candidate was scanned bytewise — no decode-and-skip path.
    assert scanned == len(candidates), (
        f"scanned {scanned} of {len(candidates)} candidates; some files were omitted"
    )
    assert scanned > 100, f"the tree-wide walk only saw {scanned} files; exemptions too broad"
    assert not offenders, (
        "host/org registry literal outside the closed list:\n" + "\n".join(offenders)
    )

    # build.sh sources versions.env and must carry no literal of its own.
    # Split the host/org needle so this assertion does not itself form the
    # contiguous byte sequence the tree-wide scan rejects.
    build_sh = (DOCKER_DIR / "build.sh").read_text(encoding="utf-8")
    assert "ghcr.io/" + "yabinma" not in build_sh
    assert 'REGISTRY="${REGISTRY:-' not in build_sh

    # Third-party ghcr.io pins are unaffected and stay in versions.env.
    assert vers["LITELLM_IMAGE"].startswith("ghcr.io/berriai/litellm:")


# --- FP-SW-7 (design.md §11.2.5): container paths and image-internal
# identifiers are `dbagent`, and the named-volume mountpoints stay pre-chowned. ---

# Assembled, not written out: FP-SW-10's forward guard rejects these literals
# outside its closed allowlist, and this file is not on it.
_LEGACY_AGENT = f"rca-{'agent'}"
_LEGACY_PROBE = f"rca-{'probe'}"
LEGACY_PATHS = [f"/etc/{_LEGACY_AGENT}", f"/etc/{_LEGACY_PROBE}", f"/var/lib/{_LEGACY_PROBE}"]


def test_container_paths_are_dbagent_and_volume_mountpoints_are_prechowned():
    import yaml

    from delivery_helpers import CHARTS, COMPOSE, helm_template, parse_manifests

    # 1. No Dockerfile, chart template or compose file references a legacy path.
    scanned = list(DOCKER_DIR.rglob("*")) + list(CHARTS.rglob("*")) + list(COMPOSE.rglob("*"))
    for path in scanned:
        if not path.is_file() or path.suffix in {".tgz", ".lock"}:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, ValueError):
            continue
        for legacy in LEGACY_PATHS:
            assert legacy not in text, f"{path}: legacy container path {legacy}"

    # 2. Every path used as a named-volume mountpoint is created and chowned in
    #    the Dockerfile of the image that mounts it (DEPLOY-ISSUES 3/5/9,
    #    re-asserted at the new paths).
    compose = yaml.safe_load((COMPOSE / "control-plane.yml").read_text(encoding="utf-8"))
    named_volumes = set((compose.get("volumes") or {}).keys())
    mountpoints: set[str] = set()
    for svc in (compose.get("services") or {}).values():
        for vol in svc.get("volumes") or []:
            if not isinstance(vol, str) or ":" not in vol:
                continue
            source, target = vol.split(":")[0], vol.split(":")[1]
            if source in named_volumes and target.startswith("/etc/dbagent"):
                mountpoints.add(target)
    probe_compose = yaml.safe_load((COMPOSE / "probe.yml").read_text(encoding="utf-8"))
    probe_named = set((probe_compose.get("volumes") or {}).keys())
    for vol in probe_compose["services"]["probe"].get("volumes") or []:
        source, target = str(vol).split(":")[0], str(vol).split(":")[1]
        if source in probe_named:
            mountpoints.add(target)

    assert "/etc/dbagent/signing" in mountpoints
    assert "/etc/dbagent/probe-gateway-ca" in mountpoints
    assert "/var/lib/dbagent-probe" in mountpoints

    dockerfiles = {name: (DOCKER_DIR / name).read_text(encoding="utf-8") for name in PRODUCT_DOCKERFILES}
    for mountpoint in sorted(mountpoints):
        prepared = [
            name
            for name, text in dockerfiles.items()
            if mountpoint in text and ("chown" in text or "--chown" in text)
        ]
        assert prepared, f"no Dockerfile pre-creates and chowns {mountpoint}"

    # 3. The nginx entrypoint exists only under its new filename and writes the
    #    new browser config global.
    nginx_dir = DOCKER_DIR / "nginx"
    scripts = sorted(p.name for p in nginx_dir.glob("*.sh"))
    assert scripts == ["10-dbagent-config.sh"], scripts
    entrypoint = (nginx_dir / "10-dbagent-config.sh").read_text(encoding="utf-8")
    assert "window.__DBAGENT_CONFIG__" in entrypoint
    web_client = (REPO_ROOT / "web/src/api/client.ts").read_text(encoding="utf-8")
    assert "__DBAGENT_CONFIG__" in web_client
    assert (REPO_ROOT / "web/public/config.js").read_text(encoding="utf-8").count("__DBAGENT_CONFIG__") >= 1

    # 4. The row-18 console-script chain, pinned positively at every link (DW5).
    pyproject = (REPO_ROOT / "services/dashboard-api/pyproject.toml").read_text(encoding="utf-8")
    assert 'dbagent-dashboard-api = "dashboard_api.main:main"' in pyproject
    assert 'dbagent-dashboard-bootstrap-admin = "dashboard_api.bootstrap_admin:main"' in pyproject
    assert "\nrca-dashboard-api = " not in pyproject
    assert f"rca-dashboard-{'bootstrap'}-admin" not in pyproject
    # ... while the distribution name three lines above does NOT move (C.5).
    assert 'name = "rca-dashboard-api"' in pyproject

    api_dockerfile = (DOCKER_DIR / "dashboard-api.Dockerfile").read_text(encoding="utf-8")
    assert 'ENTRYPOINT ["dbagent-dashboard-api"]' in api_dockerfile

    compose_text = (COMPOSE / "control-plane.yml").read_text(encoding="utf-8")
    bootstrap = compose["services"]["bootstrap-admin"]
    assert bootstrap.get("entrypoint") == ["dbagent-dashboard-bootstrap-admin"], bootstrap.get("entrypoint")
    assert "dbagent-dashboard-api" in compose_text

    rendered = helm_template(CHARTS / "dbagent")
    jobs = [d for d in parse_manifests(rendered) if d.get("kind") == "Job"]
    bootstrap_jobs = [
        j for j in jobs if "bootstrap-admin" in (j.get("metadata", {}).get("name") or "")
    ]
    assert bootstrap_jobs, "chart renders no bootstrap-admin Job"
    commands = []
    for job in bootstrap_jobs:
        for container in job["spec"]["template"]["spec"]["containers"]:
            commands.extend(container.get("command") or [])
            commands.extend(container.get("args") or [])
    assert "dbagent-dashboard-bootstrap-admin" in commands, commands

    # 5. Row 14 and row 32, asserted as the NEW value present.
    probe_main = (REPO_ROOT / "probe/cmd/probe/main.go").read_text(encoding="utf-8")
    assert '"/etc/dbagent-probe/config.yaml"' in probe_main
    gen_proto = (REPO_ROOT / "scripts/gen-proto.sh").read_text(encoding="utf-8")
    assert 'PY_VENV="${PY_VENV:-$HOME/.cache/dbagent-protoc-venv}"' in gen_proto
