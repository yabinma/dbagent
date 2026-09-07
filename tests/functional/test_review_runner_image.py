"""FP-RR-1: exercise the real review image, including nested legacy Python mounts."""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = "deploy/review-runner/Dockerfile"
PROJECTS = (
    "libs/py/rca_common",
    "services/worker",
    "services/gateway",
    "services/dashboard-api",
)
VENV_PATHS = tuple(f"/workspace/{project}/.venv" for project in PROJECTS[:2])
INPUTS = {"go.mod", "go.sum", ".dockerignore"} | {
    f"{project}/pyproject.toml" for project in PROJECTS
}
FALLBACK_PACKAGES = [
    "./services/probe-gateway/internal/audit",
    "./services/probe-gateway/internal/gwserver",
    "./services/probe-gateway/internal/registry",
    "./tests/functional/m2_probe_link",
]
COMMAND = (
    'go test ./... -count=1 -v -race -p 1 -timeout 300s '
    '-coverprofile="$MEASURE_COVER" 2>&1; test_rc=$?; '
    'go tool cover -func="$MEASURE_COVER" 2>/dev/null | tail -1; exit "$test_rc"'
)
PROBES = [
    {"name": "go", "argv": ["go", "version"],
     "stdout": "go version go1.26.4 linux/amd64", "stderr": ""},
    {"name": "python", "argv": ["python3", "--version"],
     "stdout": "Python 3.12.3", "stderr": ""},
    {"name": "alembic", "argv": ["python3", "-c", "import alembic; print('alembic '+alembic.__version__)"],
     "stdout": "alembic 1.18.5", "stderr": ""},
]


def _normalize_stream(stream: bytes) -> str:
    return stream.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").removesuffix("\n")


def _assert_probe(probe: dict, result: subprocess.CompletedProcess) -> None:
    assert result.returncode == 0, (probe["name"], result)
    assert _normalize_stream(result.stdout) == probe["stdout"], (probe["name"], result)
    assert _normalize_stream(result.stderr) == probe["stderr"], (probe["name"], result)


def _assert_go_mod_version(go_mod: str, actual: bytes, pinned: str) -> None:
    directives = re.findall(r"^go[ \t]+([^\s]+)[ \t]*(?://[^\n]*)?$", go_mod, re.MULTILINE)
    assert len(directives) == 1, directives
    version = directives[0]
    if re.fullmatch(r"[0-9]+\.[0-9]+", version):
        version += ".0"
    expected = f"go version go{version} linux/amd64"
    assert _normalize_stream(actual) == expected
    assert pinned == expected


def _assert_command(command: str) -> None:
    assert command == COMMAND


def _assert_live_declaration() -> None:
    design = REPO_ROOT / "design/design.md"
    if not design.exists():
        return  # Clean CI checkouts still execute every real-image assertion below.
    lines = design.read_text().splitlines()
    routes = [json.loads(line.removeprefix("Container test route: "))
              for line in lines if line.startswith("Container test route: ")]
    fallbacks = [json.loads(line.removeprefix("Container-dependent packages: "))
                 for line in lines if line.startswith("Container-dependent packages: ")]
    assert len(routes) == 1
    route = routes[0]
    assert set(route) == {"command", "dockerfile", "inputs", "probes"}
    assert route["probes"] == PROBES
    _assert_command(route["command"])
    assert route["dockerfile"] == DOCKERFILE
    assert set(route["inputs"]) == INPUTS
    assert len(route["inputs"]) == len(INPUTS)
    assert fallbacks == [FALLBACK_PACKAGES]


def _docker(*args: str, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess:
    result = subprocess.run(["docker", *args], capture_output=True, timeout=timeout)
    if check:
        assert result.returncode == 0, result.stdout.decode() + result.stderr.decode()
    return result


def _image_run(image: str, argv: list[str], *, env: tuple[str, ...] = ()) -> subprocess.CompletedProcess:
    name = "review-runner-probe-" + uuid.uuid4().hex
    options = ["--env", "GOTOOLCHAIN=local"]
    for value in env:
        options.extend(["--env", value])
    try:
        return _docker("run", "--rm", "--name", name, "--platform", "linux/amd64",
                       "--network", "none", *options, image, *argv, check=False)
    finally:
        # Also contain a timed-out or otherwise failed invocation to this fixture.
        if _docker("container", "inspect", name, check=False).returncode == 0:
            _docker("rm", "-f", "-v", name)
        assert _docker("container", "inspect", name, check=False).returncode != 0


@pytest.fixture(scope="module")
def review_runner_image():
    image = "dbagent-review-runner-test:" + uuid.uuid4().hex
    assert (REPO_ROOT / DOCKERFILE).is_file(), f"missing declared runner: {DOCKERFILE}"
    try:
        _docker("build", "--platform", "linux/amd64", "--file", str(REPO_ROOT / DOCKERFILE),
                "--tag", image, str(REPO_ROOT), timeout=1800)
        yield image
    finally:
        if _docker("image", "inspect", image, check=False).returncode == 0:
            _docker("image", "rm", image)
        assert _docker("image", "inspect", image, check=False).returncode != 0


def _assert_mounted_python(image: str, workspace: Path, existing_venvs: bool) -> None:
    for project in PROJECTS:
        shutil.copytree(REPO_ROOT / project, workspace / project,
                        ignore=shutil.ignore_patterns(".venv", "__pycache__", "*.pyc", "*.egg-info",
                                                     ".*cache", ".coverage*", ".benchmarks"))
    sentinels = {}
    for project in PROJECTS[:2]:
        venv = workspace / project / ".venv"
        if existing_venvs:
            (venv / "bin").mkdir(parents=True)
            for relative, content in {"bin/python": b"#!/bin/sh\nexit 97\n",
                                      "pyvenv.cfg": b"home = /host-sentinel\n",
                                      "sentinel": b"host virtualenv must survive\x00\xff"}.items():
                path = venv / relative
                path.write_bytes(content)
                sentinels[path] = content
            (venv / "bin/python").chmod(0o755)
    name = "review-runner-mount-" + uuid.uuid4().hex
    volumes = []
    try:
        _docker("run", "--detach", "--rm", "--name", name, "--platform", "linux/amd64",
                "--network", "none", "--env", "GOTOOLCHAIN=local",
                "--mount", f"type=bind,src={workspace},dst=/workspace",
                image, "/bin/sh", "-c", "exec sleep 300")
        inspected = json.loads(_docker("container", "inspect", name).stdout)[0]
        mounts = [mount for mount in inspected["Mounts"] if mount["Type"] == "volume"]
        volumes = [mount["Name"] for mount in mounts]
        assert len(mounts) == 2
        assert {mount["Destination"] for mount in mounts} == set(VENV_PATHS)
        assert len(set(volumes)) == 2
        script = (
            "import pathlib, alembic, rca_common.config, worker, gateway, dashboard_api; "
            "assert alembic.__version__ == '1.18.5'; "
            "modules = [rca_common.config, worker, gateway, dashboard_api]; "
            "roots = ['/workspace/libs/py/rca_common', '/workspace/services/worker', "
            "'/workspace/services/gateway', '/workspace/services/dashboard-api']; "
            "assert all(pathlib.Path(m.__file__).resolve().is_relative_to(root) "
            "for m, root in zip(modules, roots)), [m.__file__ for m in modules]; "
            "print('mounted imports OK')"
        )
        for venv in VENV_PATHS:
            _docker("exec", name, "/bin/sh", "-c",
                    f'test ! -e {venv}/pyvenv.cfg && test -L {venv}/bin/python '
                    f'&& test -L {venv}/bin/python3')
            for binary in ("python", "python3"):
                python = f"{venv}/bin/{binary}"
                _assert_probe(PROBES[1], _docker("exec", name, python, "--version", check=False))
                _assert_probe({"name": "mounted imports", "stdout": "mounted imports OK", "stderr": ""},
                              _docker("exec", name, python, "-c", script, check=False))
        # --rm must remove the anonymous volumes as part of normal container removal.
        _docker("stop", "--time", "1", name)
        assert _docker("container", "inspect", name, check=False).returncode != 0
        for volume in volumes:
            assert _docker("volume", "inspect", volume, check=False).returncode != 0
    finally:
        if _docker("container", "inspect", name, check=False).returncode == 0:
            _docker("rm", "-f", "-v", name)
        for volume in volumes:
            if _docker("volume", "inspect", volume, check=False).returncode == 0:
                _docker("volume", "rm", volume)
        assert _docker("container", "inspect", name, check=False).returncode != 0
        for volume in volumes:
            assert _docker("volume", "inspect", volume, check=False).returncode != 0
    for path, content in sentinels.items():
        assert path.read_bytes() == content
    if not existing_venvs:
        for project in PROJECTS[:2]:
            venv = workspace / project / ".venv"
            assert not venv.is_symlink()
            assert not venv.exists() or (venv.is_dir() and not list(venv.iterdir()))


def test_review_runner_image_probes(review_runner_image, tmp_path):
    _assert_live_declaration()
    for probe in PROBES:
        result = _image_run(review_runner_image, probe["argv"])
        _assert_probe(probe, result)
        if probe["name"] == "go":
            _assert_go_mod_version((REPO_ROOT / "go.mod").read_text(), result.stdout, probe["stdout"])
    checks = [
        (["/bin/sh", "-lc", "go version"], PROBES[0]["stdout"]),
        (["/bin/sh", "-c", "test -x /bin/sh && test -x /usr/bin/socat && command -v tail >/dev/null"], ""),
        (["go", "env", "GOTOOLCHAIN"], "local"),
        (["go", "env", "CGO_ENABLED"], "1"),
        (["python3", "-m", "pip", "check"], "No broken requirements found."),
        (["go", "env", "GOMODCACHE"], "/opt/review-go/pkg/mod"),
        (["go", "mod", "download"], ""),
    ]
    for argv, stdout in checks:
        _assert_probe({"name": argv, "stdout": stdout, "stderr": ""},
                      _image_run(review_runner_image, argv, env=("GOPROXY=off",)))
    empty_cache = _image_run(review_runner_image, ["go", "mod", "download"],
                             env=("GOPROXY=off", "GOMODCACHE=/empty-module-cache"))
    assert empty_cache.returncode != 0, "negative control unexpectedly found a populated cache"
    assert b"module lookup disabled by GOPROXY=off" in empty_cache.stderr
    for existing_venvs in (False, True):
        _assert_mounted_python(review_runner_image, tmp_path / str(existing_venvs), existing_venvs)


def test_review_runner_probe_comparison_mutants():
    for probe, old, new in zip(PROBES, ("go1.26.4", "Python 3.12.3", "alembic 1.18.5"),
                               ("go1.26.3", "Python 3.12.4", "alembic 1.18.4")):
        stdout = probe["stdout"].encode()
        for ending in (b"", b"\n", b"\r\n", b"\r"):
            _assert_probe(probe, subprocess.CompletedProcess([], 0, stdout + ending, b""))
        for changed_stdout, stderr, status in (
            (probe["stdout"].replace(old, new).encode(), b"", 0),
            (stdout, b"warning\n", 0),
            (stdout, b"", 1),
            (stdout + b"\n\n", b"", 0),
            (stdout + b"\r\n\r\n", b"", 0),
            (stdout + b" ", b"", 0),
        ):
            with pytest.raises(AssertionError):
                _assert_probe(probe, subprocess.CompletedProcess([], status, changed_stdout, stderr))


def test_review_runner_go_mod_version_mutants():
    for directive, accepted in (("1.26.4", "1.26.4"), ("1.27", "1.27.0"),
                                ("1.27.1", "1.27.1"), ("1.27rc1", "1.27rc1"),
                                ("1.27beta1", "1.27beta1")):
        stdout = f"go version go{accepted} linux/amd64"
        _assert_go_mod_version(f"module example\n\ngo {directive}\n", (stdout + "\r\n").encode(), stdout)
    for directive, actual, pinned in (
        ("1.26.5", "1.26.4", "1.26.4"),
        ("1.26.4", "1.26.5", "1.26.5"),
        ("1.26.4", "1.26.5", "1.26.4"),
        ("1.26.4", "1.26.4", "1.26.5"),
        ("1.27", "1.27", "1.27"),
        ("1.27", "1.27.1", "1.27.1"),
        ("1.27.1", "1.27.0", "1.27.0"),
        ("1.27rc1", "1.27rc1.0", "1.27rc1.0"),
        ("1.27beta1", "1.27beta1.0", "1.27beta1.0"),
        ("1.27rc1", "1.27.0", "1.27.0"),
        ("1.27beta1", "1.27.0", "1.27.0"),
    ):
        with pytest.raises(AssertionError):
            _assert_go_mod_version(f"go {directive}\n", f"go version go{actual} linux/amd64".encode(),
                                   f"go version go{pinned} linux/amd64")


def test_review_runner_command_mutants():
    _assert_command(COMMAND)
    for old, new in (("-race ", ""), ("-race", "-race=false"), ("-p 1 ", ""),
                     ("-p 1", "-p 2"), ("-timeout 300s ", ""),
                     ("300s", "299s"), ("300s", "301s")):
        with pytest.raises(AssertionError):
            _assert_command(COMMAND.replace(old, new))
