"""Regression (design/fix.md D1): B1's cleanup must drop a run directory whose
contents the invoking user cannot unlink.

The B1 driver container runs as the runner image's default user, root, and
writes into the bind-mounted run directory. On a ROOTFUL daemon -- every
GitHub-hosted runner -- those files land on the host owned by uid 0 inside
mode-0755 directories, so `rm -rf` fails with EACCES and `b1_cleanup` failed
the whole target after a green measurement (CI 35119588259 / 35119599800, and
the ordinary b1 step of 35080052686). A developer host runs a rootless daemon,
where container root IS the invoking user, so the defect was invisible locally.

These tests reproduce the *shape* of that run directory on either kind of
daemon by having a container write as a uid that is neither this process's nor
the CI runner's, and then exercise the launcher's real `b1_cleanup`. The
premise is asserted, not assumed: if this host's `rm -rf` can delete what the
container wrote, the test says so and fails rather than passing for the wrong
reason.
"""
from __future__ import annotations

import os
import subprocess
import uuid
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
LAUNCHER = REPO_ROOT / "scripts" / "integration-test.sh"

# The launcher's B1 lifecycle region, delimited by two literals declared here:
# the first constant of the B1 block and the top-level dispatcher that follows
# every function definition. Everything between them is assignments and
# function definitions only, so sourcing it defines b1_cleanup and runs nothing.
REGION_START = 'B1_IMAGE_TAG="dbagent-review-runner:b1"'
REGION_END = '\ncase "$WHAT" in'

# A stand-in for the runner image, chosen because this tier already starts it
# (tests/functional/conftest.py and every other testcontainers module), so the
# real container path is exercised without adding an image dependency. The tag
# the launcher actually uses is pinned by tests/functional/test_manifests.py.
STAND_IN_IMAGE = "postgres:16-alpine"

# Neither this process's uid nor the GitHub runner's (1001). Under a rootful
# daemon the files land on the host owned by exactly this uid; under a rootless
# one they land on a subuid. Both are unlinkable by the user running the suite.
FOREIGN_UID = 4242

# What the driver actually leaves behind, as the CI logs recorded it.
_POPULATE = (
    "mkdir -p /run/dbagent-b1/pytest-cache/v/cache"
    " && printf x > /run/dbagent-b1/pytest-cache/v/cache/nodeids"
    " && mkdir -p /run/dbagent-b1/profile-ci-scale"
    " && printf x > /run/dbagent-b1/profile-ci-scale/gateway.yaml"
    " && printf x > /run/dbagent-b1/profile-ci-scale/gateway.log"
)


def _docker(*args: str, check: bool = True, timeout: float = 300) -> subprocess.CompletedProcess:
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check:
        assert result.returncode == 0, result.stdout + result.stderr
    return result


def _lifecycle_region() -> str:
    """The launcher's own B1 lifecycle code, as text, or a named failure."""
    launcher = LAUNCHER.read_text(encoding="utf-8")
    assert REGION_START in launcher, f"launcher no longer opens the B1 block with {REGION_START!r}"
    assert REGION_END in launcher, "launcher no longer ends with a top-level target dispatcher"
    region = launcher[launcher.index(REGION_START):launcher.rindex(REGION_END)]
    assert "b1_cleanup() {" in region, "b1_cleanup is not in the extracted region"
    return region


def _make_run_dir(root: Path, name: str) -> Path:
    """A directory shaped like the one b1_prepare hands the driver container."""
    run_dir = root / name
    for child in ("coverage", "pytest-cache", "pycache"):
        (run_dir / child).mkdir(parents=True)
    for path in (run_dir, run_dir / "coverage", run_dir / "pytest-cache", run_dir / "pycache"):
        path.chmod(0o777)
    return run_dir


def _populate_as_a_foreign_uid(run_dir: Path) -> None:
    _docker("run", "--rm", "--user", f"{FOREIGN_UID}:{FOREIGN_UID}",
            "-v", f"{run_dir}:/run/dbagent-b1", "--entrypoint", "sh",
            STAND_IN_IMAGE, "-c", _POPULATE)


def _host_rm(path: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["rm", "-rf", str(path)], capture_output=True, text=True)


def _run_cleanup(run_dir: Path, *, image: str, image_built: int) -> subprocess.CompletedProcess:
    """Call the launcher's real b1_cleanup over `run_dir` and report its flags."""
    program = "\n".join((
        "set -uo pipefail",
        'eval "$B1_LIFECYCLE_REGION"',
        'B1_RUN_ID="$1"',
        'B1_RUN_DIR="$2"',
        'B1_IMAGE_TAG="$3"',
        'B1_IMAGE_BUILT="$4"',
        "b1_cleanup",
        'echo "b1_cleanup_rc=$?"',
        'echo "cleanup_failed=${B1_CLEANUP_FAILED}"',
        'echo "run_dir_failed=${B1_RUN_DIR_FAILED:-ABSENT}"',
    ))
    env = dict(os.environ, B1_LIFECYCLE_REGION=_lifecycle_region())
    return subprocess.run(
        ["bash", "-c", program, "b1-cleanup-regression",
         uuid.uuid4().hex, str(run_dir), image, str(image_built)],
        capture_output=True, text=True, env=env, timeout=300,
    )


@pytest.fixture
def run_dir_root(tmp_path: Path):
    """Leave nothing undeletable behind, whatever the test did to the tree."""
    root = tmp_path / "b1-run-dirs"
    root.mkdir()
    root.chmod(0o777)
    yield root
    if root.is_dir():
        _docker("run", "--rm", "-v", f"{root}:/reclaim", "--entrypoint", "sh",
                STAND_IN_IMAGE, "-c", "find /reclaim -mindepth 1 -delete", check=False)


def test_b1_cleanup_removes_a_run_dir_written_by_another_uid(run_dir_root: Path):
    """The defect itself: cleanup succeeds over files this user cannot unlink."""
    control = _make_run_dir(run_dir_root, "control")
    subject = _make_run_dir(run_dir_root, "dbagent-b1-subject")
    _populate_as_a_foreign_uid(control)
    _populate_as_a_foreign_uid(subject)

    # Premise. If a plain host `rm -rf` can empty this, the reproduction is not
    # the CI shape and nothing below would mean anything.
    attempt = _host_rm(control)
    assert control.is_dir() and attempt.returncode != 0, (
        "this host removed a foreign-uid run directory unaided; the defect "
        f"shape was not reproduced: rc={attempt.returncode} {attempt.stderr!r}"
    )
    assert "Permission denied" in attempt.stderr, attempt.stderr

    result = _run_cleanup(subject, image=STAND_IN_IMAGE, image_built=1)
    detail = result.stdout + result.stderr
    assert not subject.exists(), detail
    assert "cleanup_failed=0" in result.stdout, detail
    assert "run_dir_failed=0" in result.stdout, detail
    assert "b1_cleanup_rc=0" in result.stdout, detail
    # The census was empty, so the containers verdict must not be printed.
    assert "left containers behind" not in result.stderr, detail
    assert "could not remove its run directory" not in result.stderr, detail


def test_b1_cleanup_blames_the_run_dir_and_not_containers_when_it_cannot_remove_it(
    run_dir_root: Path,
):
    """The surviving failure: still fatal, reported as what it is."""
    stuck = _make_run_dir(run_dir_root, "dbagent-b1-stuck")
    _populate_as_a_foreign_uid(stuck)

    # image_built=0 is the one state in which the launcher has no root-capable
    # path available, so the removal genuinely cannot succeed.
    result = _run_cleanup(stuck, image=STAND_IN_IMAGE, image_built=0)
    detail = result.stdout + result.stderr
    assert stuck.is_dir(), detail
    assert "run_dir_failed=1" in result.stdout, detail
    assert "cleanup_failed=0" in result.stdout, detail
    assert "could not remove its run directory" in result.stderr, detail
    assert "left containers behind" not in result.stderr, detail


def test_b1_cleanup_removes_an_ordinary_run_dir_without_a_container(run_dir_root: Path):
    """The rootless path: nothing foreign in the tree, no purge container needed."""
    ordinary = _make_run_dir(run_dir_root, "dbagent-b1-ordinary")
    (ordinary / "pytest-cache" / "v" / "cache").mkdir(parents=True)
    (ordinary / "pytest-cache" / "v" / "cache" / "nodeids").write_text("x")
    (ordinary / "placement.json").write_text("{}")

    # An image tag that does not exist: if the purge ran it would be reported,
    # and the removal must not depend on it.
    result = _run_cleanup(ordinary, image="dbagent-b1-no-such-image:regression", image_built=1)
    detail = result.stdout + result.stderr
    assert not ordinary.exists(), detail
    assert "cleanup_failed=0" in result.stdout, detail
    assert "run_dir_failed=0" in result.stdout, detail
    assert result.stderr == "", result.stderr


def test_b1_cleanup_without_a_run_id_touches_nothing(run_dir_root: Path):
    """The guard that keeps a stray call from removing another run's directory."""
    untouched = _make_run_dir(run_dir_root, "dbagent-b1-untouched")
    program = "\n".join((
        "set -uo pipefail",
        'eval "$B1_LIFECYCLE_REGION"',
        'B1_RUN_DIR="$1"',
        "b1_cleanup",
        'echo "b1_cleanup_rc=$?"',
    ))
    env = dict(os.environ, B1_LIFECYCLE_REGION=_lifecycle_region())
    result = subprocess.run(
        ["bash", "-c", program, "b1-cleanup-regression", str(untouched)],
        capture_output=True, text=True, env=env, timeout=60,
    )
    assert "b1_cleanup_rc=0" in result.stdout, result.stdout + result.stderr
    assert untouched.is_dir()
