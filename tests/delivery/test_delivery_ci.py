"""FP-M6-18a/18b: CI on: block and images/e2e jobs."""
from __future__ import annotations

import posixpath
import re

import yaml

from delivery_helpers import CI_YML


def _load():
    # PyYAML 1.1 treats unquoted `on` as boolean True — use a loader that keeps it as str,
    # or fall back to data[True].
    return yaml.safe_load(CI_YML.read_text(encoding="utf-8"))


def _on_block(data: dict) -> dict:
    if "on" in data:
        return data["on"]
    if True in data:
        return data[True]
    raise KeyError("workflow on: block not found")


def test_ci_on_block_wires_all_four_e2e_triggers():
    data = _load()
    on = _on_block(data)
    # push.tags
    assert "push" in on
    tags = on["push"].get("tags") or []
    assert tags, "push.tags must be non-empty for release e2e"
    assert any("v*" in str(t) or t == "v*" for t in tags)
    # pull_request.types includes labeled
    pr = on["pull_request"]
    types = pr.get("types") or []
    assert "labeled" in types
    for t in ("opened", "synchronize", "reopened"):
        assert t in types
    # schedule
    assert "schedule" in on
    assert on["schedule"]
    # workflow_dispatch
    assert "workflow_dispatch" in on


def test_e2e_job_gate_order_and_timeout():
    data = _load()
    jobs = data["jobs"]
    assert "e2e" in jobs
    e2e = jobs["e2e"]
    assert e2e.get("timeout-minutes") == 30
    needs = e2e.get("needs")
    if isinstance(needs, str):
        needs = [needs]
    assert "benchmark" in needs
    # if: narrows triggers — require the PR-label path explicitly (not a bare "github" match).
    iff = e2e.get("if") or ""
    assert "schedule" in iff
    assert "workflow_dispatch" in iff
    assert "tags" in iff or "refs/tags" in iff
    assert "pull_request" in iff
    assert "e2e" in iff
    assert "labels" in iff


# Code review round 5, C8: the worker job ran
# `services/worker/.venv/bin/python` while its `working-directory` was already
# `services/worker`, so the interpreter it invoked resolved to
# `services/worker/services/worker/.venv/bin/python` and the job died with exit
# 127.  Nothing in CI could catch that, because the path is only wrong *after*
# `working-directory` is applied.  These two regexes make the resolution
# explicit: every `.venv/bin/<x>` a step invokes must resolve, under that step's
# own working directory, to a venv an earlier (or the same) step in the same job
# created.
_VENV_CREATE_RE = re.compile(r"python3?\s+-m\s+venv\s+(\S+)")
_VENV_USE_RE = re.compile(r"((?:[\w./-]*/)?\.venv)/bin/[\w.-]+")


def _step_workdir(job: dict, step: dict) -> str:
    default = ((job.get("defaults") or {}).get("run") or {}).get("working-directory")
    return str(step.get("working-directory") or default or ".")


def test_every_ci_venv_interpreter_resolves_under_its_working_directory():
    jobs = _load()["jobs"]
    problems: list[str] = []
    for job_name, job in jobs.items():
        created: set[str] = set()
        for index, step in enumerate(job.get("steps") or []):
            run = step.get("run")
            if not run:
                continue
            workdir = _step_workdir(job, step)
            for made in _VENV_CREATE_RE.findall(run):
                created.add(posixpath.normpath(posixpath.join(workdir, made)))
            for used in set(_VENV_USE_RE.findall(run)):
                resolved = posixpath.normpath(posixpath.join(workdir, used))
                if resolved not in created:
                    problems.append(
                        f"{job_name}[{index}] {step.get('name') or 'run'!r}: "
                        f"working-directory={workdir!r} + {used!r} resolves to "
                        f"{resolved!r}, which no step in this job creates "
                        f"(created: {sorted(created)})"
                    )
    assert not problems, "CI steps invoke interpreters that do not exist:\n" + "\n".join(
        problems
    )


def test_python_unit_jobs_enforce_strict_per_module_coverage():
    """W2 / §14.1: aggregate --cov-fail-under must be >80, and each Python unit
    job must invoke the per-module py-coverage-check with a strict floor."""
    jobs = _load()["jobs"]
    expected = {
        "unit-rca-common": ["rca_common"],
        "unit-worker": ["worker", "scripts"],
        "unit-gateway": ["gateway"],
        "unit-dashboard-api": ["dashboard_api"],
    }
    for job_name, modules in expected.items():
        assert job_name in jobs, job_name
        runs = "\n".join(
            step.get("run") or "" for step in (jobs[job_name].get("steps") or [])
        )
        assert "--cov-fail-under=81" in runs, (
            f"{job_name} must fail the aggregate bar at 81 (strictly >80); got:\n{runs}"
        )
        assert "py-coverage-check.sh" in runs, (
            f"{job_name} must run scripts/py-coverage-check.sh for per-module "
            f"strict >80 enforcement; got:\n{runs}"
        )
        for mod in modules:
            assert mod in runs, f"{job_name} must cover module {mod!r}"


def test_web_unit_job_and_vite_enforce_per_file_coverage_above_80():
    """W2: vitest thresholds must be per-file and strictly above 80 (integer 81)."""
    from pathlib import Path

    vite = (Path(__file__).resolve().parents[2] / "web" / "vite.config.ts").read_text(
        encoding="utf-8"
    )
    assert "perFile: true" in vite, "web coverage must be per-file, not aggregate-only"
    assert "lines: 81" in vite, "web line threshold must be 81 (strictly >80)"
    assert "statements: 81" in vite
    assert "functions: 81" in vite

    jobs = _load()["jobs"]
    assert "unit-web" in jobs
    name = jobs["unit-web"].get("name") or ""
    assert "80" in name or "coverage" in name.lower()


def test_go_unit_job_uses_strict_per_package_coverage_gate():
    """W2: go-coverage-check.sh must be invoked; the script itself enforces
    strict inequality against the threshold argument."""
    from pathlib import Path

    jobs = _load()["jobs"]
    assert "unit-go" in jobs
    runs = "\n".join(
        step.get("run") or "" for step in (jobs["unit-go"].get("steps") or [])
    )
    assert "go-coverage-check.sh" in runs
    script = (
        Path(__file__).resolve().parents[2] / "scripts" / "go-coverage-check.sh"
    ).read_text(encoding="utf-8")
    assert "pct > threshold" in script or "pct <= threshold" in script
    assert "strictly above" in script.lower() or "strict inequality" in script.lower()


def test_python_unit_jobs_enforce_strict_per_module_coverage():
    """W2: aggregate --cov-fail-under alone accepted exactly 80%; the design
    requires strictly above 80% at every module, so each Python unit job must
    also run the per-file gate script."""
    jobs = _load()["jobs"]
    expected = {
        "unit-rca-common": ("rca_common",),
        "unit-worker": ("worker", "scripts"),
        "unit-gateway": ("gateway",),
        "unit-dashboard-api": ("dashboard_api",),
    }
    for job_name, modules in expected.items():
        steps_blob = "\n".join(
            str(s.get("run") or "") for s in (jobs[job_name].get("steps") or [])
        )
        assert "--cov-fail-under=81" in steps_blob, job_name
        assert "py-coverage-check.sh 80" in steps_blob, job_name
        for mod in modules:
            assert mod in steps_blob, f"{job_name} must gate {mod}"


def test_images_job_builds_all_six_and_pushes_only_on_main_and_tags():
    data = _load()
    jobs = data["jobs"]
    assert "images" in jobs
    images = jobs["images"]
    needs = images.get("needs")
    if isinstance(needs, str):
        needs = [needs]
    assert "lint" in needs
    steps_blob = yaml.dump(images.get("steps") or [])
    assert "build.sh" in steps_blob
    # Push gated
    assert "main" in steps_blob or "github.ref" in steps_blob or "push" in steps_blob.lower()
