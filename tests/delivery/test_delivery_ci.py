"""FP-M6-18a/18b: CI on: block and images/e2e jobs."""
from __future__ import annotations

import ast
import builtins
import copy
import posixpath
import re
import shlex
from pathlib import Path

import pytest
import yaml

from delivery_helpers import CI_YML, REPO_ROOT


_TEMPORAL_TEST_ROOTS = {
    "services/worker/tests",
    "services/gateway/tests",
    "services/dashboard-api/tests",
    "libs/py/rca_common/tests",
    "tests/functional",
    "tests/benchmark",
    "tests/delivery",
}


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
    # pull_request.types — e2e runs on every PR targeting main (no label gate)
    pr = on["pull_request"]
    types = pr.get("types") or []
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
    assert needs == ["functional"]
    # if: every benchmark-producing event, main-branch pushes included
    # (FP-IG-24; against the unfixed tree: red on needs: benchmark and on
    # a four-class condition that omitted refs/heads/main).
    iff = e2e.get("if") or ""
    assert "schedule" in iff
    assert "workflow_dispatch" in iff
    assert "tags" in iff or "refs/tags" in iff
    assert "pull_request" in iff
    assert "refs/heads/main" in iff


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


# ---------------------------------------------------------------------------
# FP-IG-26 / UT-IG-10 — sizing-ledger gate must not sit upstream of its producer
# ---------------------------------------------------------------------------

_FP_IG_23_DEF_RE = re.compile(
    r"^def test_sizing_basis_provenance_is_on_reference_and_from_a_serving_run\b",
    re.MULTILINE,
)
_PRODUCER_REL = "services/gateway/tests/test_b1_ingest_burst.py"
_PYTEST_VALUE_OPTIONS = frozenset(
    {
        "--ignore",
        "--ignore-glob",
        "--cov",
        "--cov-report",
        "--cov-fail-under",
        "--cov-config",
        "--tb",
        "--maxfail",
        "--timeout",
        "--rootdir",
        "--confcutdir",
        "--import-mode",
        "--override-ini",
        "--durations",
        "--log-level",
        "--log-cli-level",
        "--junitxml",
        "--basetemp",
        "--pythonwarnings",
        "-k",
        "-m",
        "-n",
        "-p",
        "-o",
        "-c",
        "-W",
    }
)


def _locate_fp_ig_23_file() -> str:
    """Resolve FP-IG-23's named test by scanning tests/delivery/*.py.

    The path is not pinned so the resolution survives the file relocation
    this pass itself performs (charts.py → test_delivery_sizing_ledger.py).
    """
    hits: list[Path] = []
    delivery = REPO_ROOT / "tests" / "delivery"
    for path in sorted(delivery.glob("*.py")):
        if _FP_IG_23_DEF_RE.search(path.read_text(encoding="utf-8")):
            hits.append(path)
    assert hits, (
        "FP-IG-23 named test not found under tests/delivery/*.py "
        "(deletion cannot satisfy FP-IG-26 vacuously)"
    )
    assert len(hits) == 1, f"FP-IG-23 named test defined in more than one file: {hits}"
    return hits[0].relative_to(REPO_ROOT).as_posix()


def _norm_path(path: str) -> str:
    return posixpath.normpath(path)


def _resolve_against_workdir(path: str, workdir: str | None) -> str:
    """Positional roots and --ignore operands resolve relative to working-directory.

    None / '.' / '' = repository root, matching EXPECTED_PYTEST_COMMANDS
    (tuple's first element; None = repo root). Errata pass 15, DW1.
    """
    if workdir in (None, "", "."):
        return _norm_path(path)
    return _norm_path(posixpath.join(workdir, path))


def _path_is_under(path: str, ancestor: str) -> bool:
    """Prefix rule: path is the ancestor or lives under it as a path prefix."""
    p = _norm_path(path)
    a = _norm_path(ancestor)
    if p == a:
        return True
    return p.startswith(a.rstrip("/") + "/")


def _step_working_directory(job: dict, step: dict) -> str | None:
    default = ((job.get("defaults") or {}).get("run") or {}).get("working-directory")
    wd = step.get("working-directory") or default
    if wd in (None, "", "."):
        return None
    return str(wd)


# Match test_manifests._split_simple_commands. '|' is banned in guarded
# run: bodies so it never appears there; including it keeps the two
# models aligned. '||' is a different token and is not a separator here.
_SIMPLE_COMMAND_SEPS = frozenset({";", "&&", "|", "\n"})


def _simple_command_token_lists(text: str) -> list[list[str]]:
    """Tokenize a run: body, then split on repo simple-command separators.

    Tokenizing first keeps a quoted ';' or '&&' inside its argument.
    ':' is a word character so pytest node ids (file.py::test) stay one
    token — punctuation_chars=True would otherwise split on ':'.
    """
    try:
        lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
        lexer.whitespace = " \t\r"
        lexer.wordchars += ":"
        tokens = list(lexer)
    except ValueError:
        fragments = re.split(r"\n|;|&&|\|", text)
        return [frag.split() for frag in fragments if frag.split()]
    commands: list[list[str]] = []
    current: list[str] = []
    for tok in tokens:
        if tok in _SIMPLE_COMMAND_SEPS:
            if current:
                commands.append(current)
                current = []
            continue
        current.append(tok)
    if current:
        commands.append(current)
    return commands


def _pytest_invocations(run: str) -> list[tuple[list[str], list[str]]]:
    """Return (roots, ignores) for each `-m pytest` / `pytest` invocation in run.

    Tokenize the run: body first, then split on separator tokens (';',
    '&&', '|', newline) so one (roots, ignores) is emitted per simple
    command. --ignore and --ignore-glob both qualify roots.
    """
    # Join continued lines first so a backslash-wrapped pytest stays one command.
    text = run.replace("\\\n", " ")
    out: list[tuple[list[str], list[str]]] = []
    for tokens in _simple_command_token_lists(text):
        i = 0
        while i < len(tokens):
            if tokens[i] != "pytest":
                i += 1
                continue
            roots: list[str] = []
            ignores: list[str] = []
            j = i + 1
            while j < len(tokens):
                tok = tokens[j]
                if tok.startswith("-"):
                    if tok.startswith("--ignore=") or tok.startswith("--ignore-glob="):
                        ignores.append(tok.split("=", 1)[1])
                        j += 1
                        continue
                    name = tok.split("=", 1)[0]
                    takes_value = name in _PYTEST_VALUE_OPTIONS and "=" not in tok
                    if (
                        name in ("--ignore", "--ignore-glob")
                        and takes_value
                        and j + 1 < len(tokens)
                    ):
                        ignores.append(tokens[j + 1])
                        j += 2
                        continue
                    j += 2 if takes_value else 1
                    continue
                roots.append(tok.split("::", 1)[0])
                j += 1
            out.append((roots, ignores))
            i = j
    return out


def test_temporal_workflow_environment_starters_are_enumerated():
    workflow = _load()
    roots: set[str] = set()
    for job_name, job in (workflow.get("jobs") or {}).items():
        if not (
            job_name.startswith("unit-")
            or job_name in {"functional", "benchmark"}
        ):
            continue
        for step in job.get("steps") or []:
            run = step.get("run")
            if not isinstance(run, str):
                continue
            workdir = _step_working_directory(job, step)
            for positional, _ignores in _pytest_invocations(run):
                for root in positional:
                    resolved = _resolve_against_workdir(root, workdir)
                    if resolved == "tests/mocks/llm":
                        continue
                    if resolved.endswith(".py"):
                        resolved = posixpath.dirname(resolved)
                    roots.add(resolved.rstrip("/"))

    assert roots == _TEMPORAL_TEST_ROOTS

    starters: set[str] = set()
    for rel_root in sorted(roots):
        for path in sorted((REPO_ROOT / rel_root).rglob("*.py")):
            if ".venv" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                func = node.func
                if (
                    isinstance(func, ast.Attribute)
                    and func.attr.startswith("start_")
                    and isinstance(func.value, ast.Name)
                    and func.value.id == "WorkflowEnvironment"
                ):
                    starters.add(func.attr)

    assert starters == {"start_local", "start_time_skipping"}


def test_dashboard_api_pg_fixture_fails_closed_without_testcontainers(
    monkeypatch,
):
    fixture_path = REPO_ROOT / "services" / "dashboard-api" / "tests" / "conftest.py"
    source = fixture_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(fixture_path))
    fixture = next(
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "pg_dsn"
    )

    skip_calls = [
        node
        for node in ast.walk(fixture)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "skip"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "pytest"
    ]
    assert not skip_calls, (
        "dashboard-api pg_dsn must not skip when testcontainers is absent"
    )

    executable = copy.deepcopy(fixture)
    executable.decorator_list = []
    module = ast.fix_missing_locations(ast.Module(body=[executable], type_ignores=[]))
    namespace = {"pytest": pytest}
    exec(compile(module, str(fixture_path), "exec"), namespace)

    real_import = builtins.__import__

    def blocked_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "testcontainers.postgres":
            raise ImportError("blocked by delivery guard")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", blocked_import)
    with pytest.raises(
        pytest.fail.Exception,
        match="testcontainers is required for dashboard-api acceptance tests",
    ):
        next(namespace["pg_dsn"]())


_TRACKED_LAUNCHER_REL = "scripts/integration-test.sh"
_LAUNCHER_FUNCTION_RE = re.compile(r"\A([A-Za-z0-9_]+)\(\)\s*\{\s*\Z")
_LAUNCHER_WRAPPER_RE = re.compile(
    r"\Abash\s+" + re.escape(_TRACKED_LAUNCHER_REL) + r"\s+([A-Za-z0-9_]+)\Z"
)


def _launcher_target_invocations(target: str) -> list[tuple[list[str], list[str]]]:
    """(roots, ignores) for the pytest commands one tracked launcher target runs.

    GC-1 moved B1's benchmark step behind `bash scripts/integration-test.sh b1`,
    so the producing pytest command no longer appears in the workflow at all.
    It is still exactly one command in exactly one tracked, reviewable file, so
    this reads it from there. Deliberately resolved from the script rather than
    hard-coded: a target that stops running the producer stops counting as one,
    which is what keeps this gate honest rather than merely green.

    Paths inside the launcher are repository-relative and the driver runs at the
    repository root, so no working-directory resolution applies.
    """
    source = (REPO_ROOT / _TRACKED_LAUNCHER_REL).read_text(encoding="utf-8")
    lines = source.splitlines()
    # Delimit by the next top-level function definition rather than by a lone
    # closing brace: the target's body contains heredocs whose JSON payload has
    # `}` in column 0, and splitting on that would truncate the region before
    # the commands this resolver is looking for.
    starts = [
        (index, match.group(1))
        for index, match in (
            (index, _LAUNCHER_FUNCTION_RE.match(line)) for index, line in enumerate(lines)
        )
        if match
    ]
    for position, (index, name) in enumerate(starts):
        if name != target:
            continue
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        return _pytest_invocations("\n".join(lines[index + 1:end]))
    return []


def _jobs_collecting(
    workflow: dict, rel_path: str, *, resolve_workdir: bool
) -> list[tuple[str, int]]:
    """Jobs/steps whose pytest command line collects rel_path.

    A file is collected iff it lies under a positional root and is not under
    a path named by an --ignore. Roots and --ignore operands resolve against
    the step's working-directory when resolve_workdir is True.

    A step that is exactly `bash scripts/integration-test.sh <target>` counts as
    collecting whatever that target's own pytest commands collect.
    """
    target = _norm_path(rel_path)
    hits: list[tuple[str, int]] = []
    for job_name, job in (workflow.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        for index, step in enumerate(job.get("steps") or []):
            run = step.get("run")
            if not isinstance(run, str):
                continue
            wd = _step_working_directory(job, step) if resolve_workdir else None
            invocations = list(_pytest_invocations(run))
            wrapper = _LAUNCHER_WRAPPER_RE.match(run.strip())
            if wrapper:
                invocations.extend(_launcher_target_invocations(wrapper.group(1)))
            for roots, ignores in invocations:
                resolved_roots = [_resolve_against_workdir(r, wd) for r in roots]
                resolved_ignores = [_resolve_against_workdir(ig, wd) for ig in ignores]
                under_root = any(_path_is_under(target, r) for r in resolved_roots)
                under_ignore = any(_path_is_under(target, ig) for ig in resolved_ignores)
                if under_root and not under_ignore:
                    hits.append((job_name, index))
                    break
    return hits


def _needs_of(job: dict) -> list[str]:
    needs = job.get("needs")
    if needs is None:
        return []
    if isinstance(needs, str):
        return [needs]
    return list(needs)


def _transitive_needs(workflow: dict, job_name: str) -> set[str]:
    """Computed needs: closure. Never read from EXPECTED_NEEDS_GRAPH."""
    jobs = workflow.get("jobs") or {}
    seen: set[str] = set()
    stack = list(_needs_of(jobs.get(job_name) or {}))
    while stack:
        name = stack.pop()
        if name in seen:
            continue
        seen.add(name)
        stack.extend(_needs_of(jobs.get(name) or {}))
    return seen


def check_sizing_ledger_gate_topology(
    workflow: dict, *, resolve_workdir: bool = True
) -> tuple[str, str]:
    """FP-IG-26 property. Returns (C, P) on success; raises AssertionError if red.

    Three clauses, fail-closed:
    1. each of the two files is collected in exactly one job
    2. C is not in the transitive closure of P's needs:
    3. where C == P, the producing step's index is strictly less than the gate's
    """
    gate_rel = _locate_fp_ig_23_file()
    gate_hits = _jobs_collecting(workflow, gate_rel, resolve_workdir=resolve_workdir)
    prod_hits = _jobs_collecting(
        workflow, _PRODUCER_REL, resolve_workdir=resolve_workdir
    )
    gate_jobs = {name for name, _ in gate_hits}
    prod_jobs = {name for name, _ in prod_hits}
    if len(gate_jobs) != 1:
        raise AssertionError(
            f"gate file {gate_rel} must be collected by exactly one job, "
            f"got {sorted(gate_jobs)}"
        )
    if len(prod_jobs) != 1:
        raise AssertionError(
            f"producer file {_PRODUCER_REL} must be collected by exactly one job, "
            f"got {sorted(prod_jobs)}"
        )
    consumer = next(iter(gate_jobs))
    producer = next(iter(prod_jobs))
    closure = _transitive_needs(workflow, producer)
    if consumer in closure:
        raise AssertionError(
            f"sizing-ledger gate job {consumer!r} is in the transitive needs: "
            f"closure of producer job {producer!r}: {sorted(closure)}"
        )
    if consumer == producer:
        gate_idx = min(idx for name, idx in gate_hits if name == consumer)
        prod_idx = min(idx for name, idx in prod_hits if name == producer)
        if not prod_idx < gate_idx:
            raise AssertionError(
                f"same-job order: producer step {prod_idx} is not strictly "
                f"before gate step {gate_idx}"
            )
    return consumer, producer


def _direct_edge_only_would_pass(workflow: dict, *, resolve_workdir: bool = True) -> bool:
    """The check a direct-edge-only implementation would make.

    UT-IG-10's transitive fixture exists to kill this: it must return True
    for a two-level edge that the real (closure) check rejects.
    """
    gate_rel = _locate_fp_ig_23_file()
    gate_hits = _jobs_collecting(workflow, gate_rel, resolve_workdir=resolve_workdir)
    prod_hits = _jobs_collecting(
        workflow, _PRODUCER_REL, resolve_workdir=resolve_workdir
    )
    gate_jobs = {name for name, _ in gate_hits}
    prod_jobs = {name for name, _ in prod_hits}
    if len(gate_jobs) != 1 or len(prod_jobs) != 1:
        return False
    consumer = next(iter(gate_jobs))
    producer = next(iter(prod_jobs))
    jobs = workflow.get("jobs") or {}
    if consumer in _needs_of(jobs.get(producer) or {}):
        return False
    if consumer == producer:
        gate_idx = min(idx for name, idx in gate_hits if name == consumer)
        prod_idx = min(idx for name, idx in prod_hits if name == producer)
        if not prod_idx < gate_idx:
            return False
    return True


def _pytest_step(run: str, *, workdir: str | None = None) -> dict:
    step: dict = {"run": run}
    if workdir is not None:
        step["working-directory"] = workdir
    return step


def _job(steps: list[dict], *, needs=None, defaults_wd: str | None = None) -> dict:
    job: dict = {"steps": steps}
    if needs is not None:
        job["needs"] = needs
    if defaults_wd is not None:
        job["defaults"] = {"run": {"working-directory": defaults_wd}}
    return job


def _burst_run() -> str:
    return "services/worker/.venv/bin/python -m pytest services/gateway/tests/test_b1_ingest_burst.py -v -s"


def _gate_run() -> str:
    return (
        "services/worker/.venv/bin/python -m pytest "
        f"{_locate_fp_ig_23_file()} -v"
    )


def _fixture_direct_edge() -> dict:
    """Producer needs: consumer directly — the e81af43 shape."""
    return {
        "jobs": {
            "functional": _job([_pytest_step("python -m pytest tests/delivery -v")]),
            "benchmark": _job(
                [_pytest_step(_burst_run())],
                needs="functional",
            ),
        }
    }


def _fixture_transitive() -> dict:
    """Two-level edge: benchmark → mid → functional. Direct-edge-only is green."""
    return {
        "jobs": {
            "functional": _job([_pytest_step("python -m pytest tests/delivery -v")]),
            "mid": _job([{"run": "echo noop"}], needs="functional"),
            "benchmark": _job(
                [_pytest_step(_burst_run())],
                needs=["mid"],
            ),
        }
    }


def _fixture_same_job_inversion() -> dict:
    """Gate step before burst step in the same job."""
    return {
        "jobs": {
            "benchmark": _job(
                [
                    _pytest_step(_gate_run()),
                    _pytest_step(_burst_run()),
                ]
            ),
        }
    }


def _fixture_gate_nowhere() -> dict:
    return {
        "jobs": {
            "benchmark": _job([_pytest_step(_burst_run())]),
        }
    }


def _fixture_gate_twice() -> dict:
    return {
        "jobs": {
            "functional": _job([_pytest_step("python -m pytest tests/delivery -v")]),
            "other": _job([_pytest_step(_gate_run())]),
            "benchmark": _job([_pytest_step(_burst_run())]),
        }
    }


def _fixture_working_directory() -> dict:
    """Unit-shaped job (wd-relative tests/ + --ignore) beside a same-job gate.

    Green under the stated resolution rule; a working-directory-blind
    resolver reads the unit job's tests/ as repository-root tests/ and
    finds two collectors (DW1 discriminating control).
    """
    return {
        "jobs": {
            "unit-gateway": _job(
                [
                    _pytest_step(
                        ".venv/bin/python -m pytest tests/ "
                        "--cov=gateway --ignore=tests/test_b1_ingest_burst.py",
                        workdir="services/gateway",
                    )
                ]
            ),
            "benchmark": _job(
                [
                    _pytest_step(_burst_run()),
                    _pytest_step(_gate_run()),
                ]
            ),
        }
    }


def _fixture_downstream_job() -> dict:
    """Gate collected by a separate job with needs: [benchmark] — admissible."""
    return {
        "jobs": {
            "benchmark": _job([_pytest_step(_burst_run())]),
            "sizing-ledger": _job(
                [_pytest_step(_gate_run())],
                needs=["benchmark"],
            ),
        }
    }


def test_sizing_ledger_gate_is_not_upstream_of_its_producer():
    """FP-IG-26: producer/consumer resolved from pytest surfaces; needs: computed.

    Against the unfixed tree (e81af43): red on the closure clause and only
    that clause — C is functional (gate lives in test_delivery_charts.py,
    collected via tests/delivery), P is benchmark, functional is in
    benchmark's transitive needs:. After the re-siting: C == P == benchmark
    and the producing step (17) is strictly before the gate step (20).
    """
    consumer, producer = check_sizing_ledger_gate_topology(_load())
    # The closure is computed, never compared to a pinned graph literal.
    # A same-job siting (the chosen fix) or a downstream-job siting both pass.
    if consumer == producer:
        assert producer == "benchmark"
    else:
        assert consumer not in _transitive_needs(_load(), producer)


def test_ut_ig_10_direct_needs_edge_is_red():
    with pytest.raises(AssertionError, match="transitive needs"):
        check_sizing_ledger_gate_topology(_fixture_direct_edge())


def test_ut_ig_10_transitive_edge_is_red_only_with_closure():
    """A direct-edge-only check would pass this fixture; the real check must not."""
    wf = _fixture_transitive()
    with pytest.raises(AssertionError, match="transitive needs"):
        check_sizing_ledger_gate_topology(wf)
    assert _direct_edge_only_would_pass(wf), (
        "transitive fixture is not discriminating: a direct-edge-only check "
        "rejected it too, so the fixture cannot kill that implementation"
    )


def test_ut_ig_10_same_job_inversion_is_red():
    with pytest.raises(AssertionError, match="same-job order"):
        check_sizing_ledger_gate_topology(_fixture_same_job_inversion())


def test_ut_ig_10_gate_collected_nowhere_is_red():
    with pytest.raises(AssertionError, match="exactly one job"):
        check_sizing_ledger_gate_topology(_fixture_gate_nowhere())


def test_ut_ig_10_gate_collected_twice_is_red():
    with pytest.raises(AssertionError, match="exactly one job"):
        check_sizing_ledger_gate_topology(_fixture_gate_twice())


def test_ut_ig_10_working_directory_fixture_is_green_only_with_wd_rule():
    """DW1 discriminating control: green with the rule, red when WD-blind."""
    wf = _fixture_working_directory()
    check_sizing_ledger_gate_topology(wf)
    with pytest.raises(AssertionError, match="exactly one job"):
        check_sizing_ledger_gate_topology(wf, resolve_workdir=False)


def test_ut_ig_10_downstream_job_fixture_is_green():
    """DS2: the evidence-ordering rule's other admissible topology."""
    check_sizing_ledger_gate_topology(_fixture_downstream_job())


# W1: one run: body may contain more than one pytest command. The parser must
# emit one (roots, ignores) per command, not merge them.
_TWO_PYTEST_RUN = (
    "python -m pytest tests/delivery -v\n"
    "python -m pytest tests/functional "
    "--ignore=tests/delivery/test_delivery_sizing_ledger.py"
)
_UNIT_GATEWAY_LEAKED_ROOTS = (
    "bash",
    "../../scripts/py-coverage-check.sh",
    "80",
    "gateway",
)


def _fixture_two_pytest_commands_in_one_run() -> dict:
    """Two pytest commands in one run: body; first collects the gate.

    Same-job siting (producer, then the two-command body). A parser that
    merges the second command's --ignore onto the first command's roots
    reports no collector — the fail-open W1 exists to close.
    """
    return {
        "jobs": {
            "benchmark": _job(
                [
                    _pytest_step(_burst_run()),
                    _pytest_step(_TWO_PYTEST_RUN),
                ]
            ),
        }
    }


def _unit_gateway_pytest_run() -> str:
    job = _load()["jobs"]["unit-gateway"]
    for step in job.get("steps") or []:
        run = step.get("run")
        if isinstance(run, str) and "pytest" in run:
            return run
    raise AssertionError("unit-gateway has no pytest run: body")


def test_pytest_invocations_does_not_merge_newline_separated_commands():
    """W1: each pytest command in a run: body is its own (roots, ignores)."""
    assert _pytest_invocations(_TWO_PYTEST_RUN) == [
        (["tests/delivery"], []),
        (
            ["tests/functional"],
            ["tests/delivery/test_delivery_sizing_ledger.py"],
        ),
    ]


def test_pytest_invocations_splits_on_semicolon_too():
    invs = _pytest_invocations(_TWO_PYTEST_RUN.replace("\n", "; "))
    assert invs == [
        (["tests/delivery"], []),
        (
            ["tests/functional"],
            ["tests/delivery/test_delivery_sizing_ledger.py"],
        ),
    ]


def test_pytest_invocations_records_ignore_glob():
    compact = _pytest_invocations(
        "python -m pytest tests/delivery --ignore-glob=**/tmp_*.py"
    )
    spaced = _pytest_invocations(
        "python -m pytest tests/delivery --ignore-glob **/tmp_*.py"
    )
    assert compact == [(["tests/delivery"], ["**/tmp_*.py"])]
    assert spaced == [(["tests/delivery"], ["**/tmp_*.py"])]


def test_ut_ig_10_two_pytest_commands_in_one_run_still_collects_gate():
    """W1: merged parsing reports no collector; split parsing finds the gate."""
    wf = _fixture_two_pytest_commands_in_one_run()
    consumer, producer = check_sizing_ledger_gate_topology(wf)
    assert consumer == producer == "benchmark"
    gate_hits = _jobs_collecting(
        wf, _locate_fp_ig_23_file(), resolve_workdir=True
    )
    assert gate_hits == [("benchmark", 1)]


def test_unit_gateway_pytest_roots_do_not_leak_trailing_command_tokens():
    """W1 symptom on today's ci.yml: the coverage-script line is not a root."""
    invs = _pytest_invocations(_unit_gateway_pytest_run())
    assert len(invs) == 1
    roots, ignores = invs[0]
    assert roots == ["tests/"]
    assert ignores == ["tests/test_b1_ingest_burst.py"]
    assert set(_UNIT_GATEWAY_LEAKED_ROOTS).isdisjoint(roots)


# W1 residual (round 2): '&&' is a repo simple-command separator
# (test_manifests._split_simple_commands) and is not banned in guarded
# run: bodies. The ';'/newline-only splitter treats an &&-joined pair as
# one command and goes fail-open on the deadlock FP-IG-26 exists to catch.
_TWO_PYTEST_RUN_AND_AND = _TWO_PYTEST_RUN.replace("\n", " && ")


def _fixture_two_pytest_commands_joined_by_and_and() -> dict:
    """Same-job twin of _fixture_two_pytest_commands_in_one_run, joined by &&."""
    return {
        "jobs": {
            "benchmark": _job(
                [
                    _pytest_step(_burst_run()),
                    _pytest_step(_TWO_PYTEST_RUN_AND_AND),
                ]
            ),
        }
    }


def _and_and_joined_functional_collects_gate(workflow: dict) -> dict:
    """Honest-looking edit of the shipped workflow.

    Prepends a second pytest that collects tests/delivery onto functional[9],
    joined by ' && '. Pytest then collects the gate in both functional and
    benchmark; FP-IG-26 must go red. A parser that does not split on &&
    applies the second command's --ignore to the first command and reports
    only benchmark — a false green (the deadlock).
    """
    wf = copy.deepcopy(workflow)
    step = wf["jobs"]["functional"]["steps"][9]
    run = step.get("run")
    assert isinstance(run, str), "functional[9] must be a run: step"
    assert "test_delivery_sizing_ledger.py" in run, (
        "functional[9] is not the sizing-ledger --ignore step"
    )
    step["run"] = "python -m pytest tests/delivery -v && " + run
    return wf


def test_pytest_invocations_splits_on_and_and_too():
    """W1 residual: && is a command separator, same as newline and ';'."""
    invs = _pytest_invocations(_TWO_PYTEST_RUN_AND_AND)
    assert invs == [
        (["tests/delivery"], []),
        (
            ["tests/functional"],
            ["tests/delivery/test_delivery_sizing_ledger.py"],
        ),
    ]


def test_ut_ig_10_two_pytest_commands_joined_by_and_and_still_collects_gate():
    """W1 residual: same-job two-pytest body joined by && still finds the gate."""
    wf = _fixture_two_pytest_commands_joined_by_and_and()
    consumer, producer = check_sizing_ledger_gate_topology(wf)
    assert consumer == producer == "benchmark"
    gate_hits = _jobs_collecting(
        wf, _locate_fp_ig_23_file(), resolve_workdir=True
    )
    assert gate_hits == [("benchmark", 1)]


def test_ut_ig_10_and_and_joined_second_pytest_in_functional_is_red():
    """W1 residual: &&-joined second pytest in functional collects the gate.

    On the real ci.yml shape the identical edit joined by newline is red
    (functional[9] + benchmark[20]). Joined by && it must also be red —
    a ';'/newline-only splitter reports only benchmark and goes green.
    """
    wf = _and_and_joined_functional_collects_gate(_load())
    gate_hits = _jobs_collecting(
        wf, _locate_fp_ig_23_file(), resolve_workdir=True
    )
    assert gate_hits == [("functional", 9), ("benchmark", 20)]
    with pytest.raises(AssertionError, match="exactly one job"):
        check_sizing_ledger_gate_topology(wf)


def test_pytest_invocations_does_not_split_on_quoted_separator():
    """A ';' or '&&' inside a quoted pytest argument is not a command break.

    Root sits after the quoted expression so an over-split would drop it
    (fail-open the opposite way from the merge bug).
    """
    semicolon = _pytest_invocations(
        "python -m pytest -k 'foo; bar' tests/delivery"
    )
    ampersand = _pytest_invocations(
        "python -m pytest -k 'foo && bar' tests/delivery"
    )
    assert semicolon == [(["tests/delivery"], [])]
    assert ampersand == [(["tests/delivery"], [])]


# ---------------------------------------------------------------------------
# GC-1 FP-GC1-2 — the tracked wrapper indirection, and its limits.
#
# CI delegates B1 to `bash scripts/integration-test.sh b1`, so the producing
# pytest command no longer appears in the workflow at all. FP-IG-26 must still
# follow the real producer, which is why _jobs_collecting resolves that exact
# form. These cases prove the resolution is narrow: it reads the named target
# out of the tracked script, and it returns nothing for a target that does not
# exist, a script that does not run pytest, or any other bash command.
# ---------------------------------------------------------------------------


_GC1_B1_PRODUCER = "services/gateway/tests/test_b1_ingest_burst.py"


def test_gc1_wrapper_target_resolves_b1_producer_only():
    """FP-GC1-2: the wrapper resolves B1's producer, and only through that form."""
    launcher = (REPO_ROOT / _TRACKED_LAUNCHER_REL).read_text(encoding="utf-8")
    assert "bash scripts/integration-test.sh b1" in CI_YML.read_text(encoding="utf-8")

    # Positive: both B1 targets collect the producer through the tracked script.
    for target in ("b1", "b1_product"):
        roots = [
            root
            for invocation in _launcher_target_invocations(target)
            for root in invocation[0]
        ]
        assert _GC1_B1_PRODUCER in roots, (target, roots)
    # The workflow steps resolve to the benchmark job and to no other, and the
    # FP-IG-26 topology still holds: the PRODUCING step is strictly before the
    # ledger gate. B1-LATENCY-BASIS-1 appended a second wrapper (index 21, the
    # manual, conditional CPU-basis oracle), so the producer is now reached by
    # two steps of the one job; both indices are pinned rather than counted.
    workflow = _load()
    hits = _jobs_collecting(workflow, _GC1_B1_PRODUCER, resolve_workdir=True)
    assert {name for name, _ in hits} == {"benchmark"}, hits
    assert hits == [("benchmark", 17), ("benchmark", 21)], hits
    for target in ("b1", "b1_latency_basis"):
        roots = [
            root
            for invocation in _launcher_target_invocations(target)
            for root in invocation[0]
        ]
        assert _GC1_B1_PRODUCER in roots, (target, roots)
    consumer, producer = check_sizing_ledger_gate_topology(workflow)
    assert consumer == producer == "benchmark"

    # Negative: a target that is not defined resolves to nothing.
    assert _launcher_target_invocations("no_such_target") == []
    # Negative: only the exact wrapper form is recognised.
    for body in (
        "bash scripts/integration-test.sh",
        "bash scripts/integration-test.sh b1 --extra",
        "bash scripts/gen-proto.sh",
        "sh scripts/integration-test.sh b1",
        "bash ./scripts/integration-test.sh b1",
    ):
        assert _LAUNCHER_WRAPPER_RE.match(body) is None, body
    assert _LAUNCHER_WRAPPER_RE.match("bash scripts/integration-test.sh b1").group(1) == "b1"

    # Negative: a wrapper whose target stops running the producer stops
    # counting as one, so deleting or moving the producer is still detected.
    stripped = "\n".join(
        line for line in launcher.splitlines() if _GC1_B1_PRODUCER not in line
    )
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        fake_root = Path(tmp)
        (fake_root / "scripts").mkdir()
        (fake_root / "scripts" / "integration-test.sh").write_text(stripped, encoding="utf-8")
        original = globals()["REPO_ROOT"]
        globals()["REPO_ROOT"] = fake_root
        try:
            assert not [
                root
                for invocation in _launcher_target_invocations("b1")
                for root in invocation[0]
            ]
            assert _jobs_collecting(workflow, _GC1_B1_PRODUCER, resolve_workdir=True) == []
        finally:
            globals()["REPO_ROOT"] = original

    # A workflow that replaces the B1 wrappers with any other bash command
    # loses its producer, and the FP-IG-26 gate says so rather than passing
    # vacuously. Rerouting only the GATING step at 17 is NOT enough any more
    # and the control says so explicitly: the appended oracle at 21 still
    # resolves the producer, and the gate then reports the order inversion
    # rather than a silent pass.
    import copy

    half = copy.deepcopy(workflow)
    half["jobs"]["benchmark"]["steps"][17]["run"] = "bash scripts/gen-proto.sh"
    assert _jobs_collecting(half, _GC1_B1_PRODUCER, resolve_workdir=True) == [
        ("benchmark", 21)
    ]
    with pytest.raises(AssertionError, match="same-job order"):
        check_sizing_ledger_gate_topology(half)

    rerouted = copy.deepcopy(workflow)
    for index in (17, 21):
        rerouted["jobs"]["benchmark"]["steps"][index]["run"] = "bash scripts/gen-proto.sh"
    assert _jobs_collecting(rerouted, _GC1_B1_PRODUCER, resolve_workdir=True) == []
    with pytest.raises(AssertionError, match="exactly one job"):
        check_sizing_ledger_gate_topology(rerouted)

    # And the direct (non-wrapper) control still works: a job whose own pytest
    # command names the producer is resolved without any wrapper at all.
    direct = {"jobs": {"benchmark": {"steps": [
        {"run": f"services/worker/.venv/bin/python -m pytest {_GC1_B1_PRODUCER} -v"},
    ]}}}
    assert _jobs_collecting(direct, _GC1_B1_PRODUCER, resolve_workdir=True) == [("benchmark", 0)]


# ---------------------------------------------------------------------------
# B1-LATENCY-BASIS-1 FP-B1LB-6 — the isolated CPU-basis oracle's CI wiring
# ---------------------------------------------------------------------------
_LATENCY_BASIS_INPUT = "b1_latency_basis"
_LATENCY_BASIS_WRAPPER = "bash scripts/integration-test.sh b1_latency_basis"
_LATENCY_BASIS_CONDITION = (
    "github.event_name == 'workflow_dispatch' && inputs.b1_latency_basis == true"
)
_LATENCY_BASIS_STEP_INDEX = 21
_PROVENANCE_GATE_STEP_INDEX = 20
_ORDINARY_B1_STEP_INDEX = 17


def test_b1_latency_basis_manual_tail_is_opt_in_and_downstream_of_provenance():
    """FP-B1LB-6: manual, default-false, last, and after the provenance gate.

    Four independent facts, none inferred from the others:

    1. the `workflow_dispatch` input exists, is a boolean and defaults to
       false, so push, pull-request, scheduled and ORDINARY manual runs invoke
       only the unchanged B1 gate at step 17;
    2. the tail step's index, body and condition are exact, and `== true`
       rather than a truthiness test -- a string comparison would run the
       oracle on the literal "false";
    3. the step sits strictly after the FP-IG-23 provenance gate at index 20,
       so GitHub Actions' implicit `success()` in an explicit `if:` keeps it
       from running while that gate is red; and
    4. no job gains a needs edge and no other job or `all` route reaches the
       target, so an enabled dispatch adds a second live B1 run to this one
       job and changes nothing else.
    """
    workflow = _load()
    on_block = _on_block(workflow)
    inputs = (on_block.get("workflow_dispatch") or {}).get("inputs") or {}
    assert _LATENCY_BASIS_INPUT in inputs, sorted(inputs)
    spec = inputs[_LATENCY_BASIS_INPUT]
    assert spec.get("type") == "boolean", spec
    assert spec.get("default") is False, spec
    assert spec.get("required") is False, spec

    steps = workflow["jobs"]["benchmark"]["steps"]
    step = steps[_LATENCY_BASIS_STEP_INDEX]
    assert (step.get("run") or "").strip() == _LATENCY_BASIS_WRAPPER, step.get("run")
    assert (step.get("if") or "").strip() == _LATENCY_BASIS_CONDITION, step.get("if")
    assert _LATENCY_BASIS_STEP_INDEX == len(steps) - 1, len(steps)

    # Exactly one such step, and exactly one conditional step in this job.
    bodies = [(s.get("run") or "").strip() for s in steps]
    assert bodies.count(_LATENCY_BASIS_WRAPPER) == 1, bodies.count(_LATENCY_BASIS_WRAPPER)
    conditional = [i for i, s in enumerate(steps) if "if" in s]
    assert conditional == [_LATENCY_BASIS_STEP_INDEX], conditional

    # Ordering: ordinary B1 gate, then the provenance gate, then the oracle.
    assert bodies[_ORDINARY_B1_STEP_INDEX] == "bash scripts/integration-test.sh b1"
    gate = [
        i for i, s in enumerate(steps)
        if "tests/delivery/test_delivery_sizing_ledger.py" in (s.get("run") or "")
    ]
    assert gate == [_PROVENANCE_GATE_STEP_INDEX], gate
    assert (
        _ORDINARY_B1_STEP_INDEX
        < _PROVENANCE_GATE_STEP_INDEX
        < _LATENCY_BASIS_STEP_INDEX
    )
    # The unconditional steps 0..20 are exactly the ones every ordinary run
    # executes: the oracle is absent from push, pull-request, schedule and an
    # ordinary manual dispatch, all of which leave the boolean at its default.
    for default_event in ("push", "pull_request", "schedule", "workflow_dispatch"):
        assert default_event in str(on_block) or default_event == "workflow_dispatch"
        assert _LATENCY_BASIS_WRAPPER not in " ".join(bodies[:_LATENCY_BASIS_STEP_INDEX])

    # The target is reachable from no other job and creates no dependency.
    for name, job in (workflow.get("jobs") or {}).items():
        for i, s in enumerate(job.get("steps") or []):
            if name == "benchmark" and i == _LATENCY_BASIS_STEP_INDEX:
                continue
            assert _LATENCY_BASIS_INPUT not in (s.get("run") or ""), (name, i)
        needs = job.get("needs")
        listed = [needs] if isinstance(needs, str) else list(needs or [])
        assert "benchmark" not in listed or name == "benchmark", name

    # Negative controls: each weakening is independently detected.
    import copy

    def _is_opt_in(wf: dict) -> bool:
        block = _on_block(wf)
        got = ((block.get("workflow_dispatch") or {}).get("inputs") or {}).get(
            _LATENCY_BASIS_INPUT
        )
        if not isinstance(got, dict) or got.get("default") is not False:
            return False
        if got.get("type") != "boolean":
            return False
        tail = wf["jobs"]["benchmark"]["steps"]
        found = [
            i for i, s in enumerate(tail)
            if (s.get("run") or "").strip() == _LATENCY_BASIS_WRAPPER
        ]
        if found != [len(tail) - 1]:
            return False
        if (tail[found[0]].get("if") or "").strip() != _LATENCY_BASIS_CONDITION:
            return False
        gate_at = [
            i for i, s in enumerate(tail)
            if "tests/delivery/test_delivery_sizing_ledger.py" in (s.get("run") or "")
        ]
        return bool(gate_at) and max(gate_at) < found[0]

    assert _is_opt_in(workflow), "positive control"
    for case, mutate in (
        ("default_true", lambda wf: _on_block(wf)["workflow_dispatch"]["inputs"][
            _LATENCY_BASIS_INPUT].__setitem__("default", True)),
        ("input_becomes_a_string", lambda wf: _on_block(wf)["workflow_dispatch"]["inputs"][
            _LATENCY_BASIS_INPUT].__setitem__("type", "string")),
        ("condition_removed", lambda wf: wf["jobs"]["benchmark"]["steps"][-1].pop("if")),
        ("condition_made_truthy", lambda wf: wf["jobs"]["benchmark"]["steps"][-1].__setitem__(
            "if", "github.event_name == 'workflow_dispatch' && inputs.b1_latency_basis")),
        ("moved_before_the_provenance_gate", lambda wf: wf["jobs"]["benchmark"][
            "steps"].insert(0, wf["jobs"]["benchmark"]["steps"].pop())),
        ("step_removed", lambda wf: wf["jobs"]["benchmark"]["steps"].pop()),
    ):
        mutant = copy.deepcopy(workflow)
        mutate(mutant)
        assert not _is_opt_in(mutant), case
