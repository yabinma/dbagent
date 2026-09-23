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
    # ci-runtime-2 FP-CIR2-3: the only route to the instrumented pytest_e2e
    # command is one unconditional `bash tests/e2e/run.sh` step; a skipped,
    # tolerated, duplicated or redirected run would hide the timing records
    # (and the phase budget) without failing the job.
    assert _e2e_run_step_failures(e2e) == []
    step = next(s for s in e2e["steps"] if "tests/e2e/run.sh" in str(s.get("run") or ""))
    mutants = {
        "step_if_false": lambda j: _e2e_run_step(j).update({"if": "false"}),
        "step_continue_on_error": lambda j: _e2e_run_step(j).update({"continue-on-error": True}),
        "job_continue_on_error": lambda j: j.update({"continue-on-error": True}),
        "second_invocation": lambda j: j["steps"].append(copy.deepcopy(step)),
        "other_script": lambda j: _e2e_run_step(j).update({"run": "bash tests/e2e/other.sh"}),
        "extra_args": lambda j: _e2e_run_step(j).update(
            {"run": "PYTEST_ADDOPTS=-s bash tests/e2e/run.sh"}
        ),
    }
    for name, mutate in mutants.items():
        job = copy.deepcopy(e2e)
        mutate(job)
        assert _e2e_run_step_failures(job) != [], f"{name} must be red"


def _e2e_run_step(job: dict) -> dict:
    return next(s for s in job["steps"] if "tests/e2e/" in str(s.get("run") or ""))


def _e2e_run_step_failures(job: dict) -> list[str]:
    """One unconditional `bash tests/e2e/run.sh` step in the e2e job."""
    fails: list[str] = []
    if "continue-on-error" in job:
        fails.append("e2e job tolerates failure")
    steps = job.get("steps") or []
    runs = [s for s in steps if "tests/e2e/" in str(s.get("run") or "")]
    if len(runs) != 1:
        fails.append(f"expected one tests/e2e step, found {len(runs)}")
    for s in runs:
        if str(s.get("run") or "").strip() != "bash tests/e2e/run.sh":
            fails.append(f"e2e step runs {s.get('run')!r}")
        for key in ("if", "continue-on-error"):
            if key in s:
                fails.append(f"e2e run step carries {key}: {s[key]!r}")
    return fails


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


#: ci-runtime-1 FP-CIR1-3/5/6: the unit-go route, restated as literals here
#: rather than read from the workflow it protects.
_UNIT_GO_PROFILE = "/tmp/dbagent-ci-go.coverprofile"
_UNIT_GO_COMMAND = (
    f"go test ./... -race -coverprofile={_UNIT_GO_PROFILE} "
    "-covermode=atomic -timeout 300s -p 1"
)
_UNIT_GO_COVERAGE_RUN = f"bash scripts/go-coverage-check.sh 80 {_UNIT_GO_PROFILE}"
_GO_COVERAGE_SCRIPT = REPO_ROOT / "scripts" / "go-coverage-check.sh"


def test_go_unit_job_uses_strict_per_package_coverage_gate():
    """W2 / ci-runtime-1 FP-CIR1-3, FP-CIR1-6: unit-go's one Go pass writes the
    profile its coverage gate reads, and the gate is strict.

    Named for a coverage step that measures something other than the -race
    pass it follows: a second `go test` run, a different or stale profile, a
    gate that can run after a failed test, or a lowered floor. unit-go runs
    exactly one `go test` step (the combined literal), the IMMEDIATELY next
    step is the gate on the same literal profile, neither step can be skipped
    or made non-fatal, the script's CI (two-argument) branch launches no Go at
    all, and the script's inequality is still strict.
    """
    jobs = _load()["jobs"]
    assert "unit-go" in jobs
    steps = jobs["unit-go"].get("steps") or []
    go_steps = [
        i for i, step in enumerate(steps)
        if re.search(r"(^|\n)\s*go test\b", step.get("run") or "")
    ]
    assert len(go_steps) == 1, go_steps
    gi = go_steps[0]
    assert steps[gi]["run"].strip() == _UNIT_GO_COMMAND
    assert gi + 1 < len(steps), "no coverage step after the Go pass"
    assert steps[gi + 1]["run"].strip() == _UNIT_GO_COVERAGE_RUN
    gate_steps = [i for i, s in enumerate(steps) if "go-coverage-check.sh" in (s.get("run") or "")]
    assert gate_steps == [gi + 1], gate_steps
    profile = re.search(r"-coverprofile=(\S+)", steps[gi]["run"]).group(1)
    assert steps[gi + 1]["run"].split()[-1] == profile == _UNIT_GO_PROFILE
    for index in (gi, gi + 1):
        assert "if" not in steps[index], index
        assert "continue-on-error" not in steps[index], index
        assert "shell" not in steps[index], index
    assert "continue-on-error" not in jobs["unit-go"] and "if" not in jobs["unit-go"]

    script = _GO_COVERAGE_SCRIPT.read_text(encoding="utf-8")
    assert "pct > threshold" in script or "pct <= threshold" in script
    assert "strictly above" in script.lower() or "strict inequality" in script.lower()
    # The two-argument (CI) branch reads a profile; only the else-branch runs Go.
    ci_branch = script.split('if [ "$#" -eq 2 ]; then', 1)[1].split("\nelse\n", 1)[0]
    assert not re.search(r"(^|\n)\s*go\s", ci_branch), "the CI branch runs a go command"
    assert 'PROFILE="$2"' in ci_branch


def _coverage_run(tmp_path: Path, *args: str) -> tuple[int, str, bool]:
    """Run the coverage script with a `go` shim first on PATH.

    The shim records that it was started and fails, so a run that reached Go
    both leaves the marker and cannot print PASS. Returns (exit code, combined
    output, whether Go was started).
    """
    import os
    import subprocess

    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    marker = tmp_path / "go-was-started"
    go = shim / "go"
    go.write_text(f'#!/bin/sh\ntouch "{marker}"\nexit 97\n', encoding="utf-8")
    go.chmod(0o755)
    env = {**os.environ, "PATH": f"{shim}:{os.environ.get('PATH', '/usr/bin:/bin')}"}
    for key in list(env):
        if key.startswith(("PYTHON", "PYTEST")):
            env.pop(key)
    if marker.exists():
        marker.unlink()
    done = subprocess.run(
        ["bash", str(_GO_COVERAGE_SCRIPT), *args],
        env=env, capture_output=True, text=True, timeout=60,
    )
    return done.returncode, done.stdout + done.stderr, marker.exists()


def _profile(tmp_path: Path, name: str, text: str) -> str:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


def _main_func_line(rel: str) -> int:
    lines = (REPO_ROOT / rel).read_text(encoding="utf-8").splitlines()
    return next(i for i, ln in enumerate(lines, start=1) if ln.startswith("func main()"))


_MOD = "github.com/yabinma/dbagent/"


def test_go_coverage_reuses_profile_fail_closed(tmp_path: Path):
    """ci-runtime-1 FP-CIR1-5 [function test]: the CI path consumes a profile,
    never starts Go, and fails closed on anything it cannot read in full.

    Named for a coverage gate that turns bad input into a pass -- a missing,
    empty, malformed, non-atomic or statement-free profile read as 100% --
    or that quietly re-runs the suite. Every two-argument run below has a
    `go` shim first on PATH that records being started; it never is. The
    strict `>80%` arithmetic and the gen/go and `main()` exclusions are
    exercised on tiny synthetic profiles; the one-argument local path still
    starts Go to build its own profile, and a failing Go stops it before PASS.
    """
    main_go = "probe/cmd/probe/main.go"
    main_line = _main_func_line(main_go)
    valid = (
        "mode: atomic\n"
        f"{_MOD}probe/internal/a/x.go:1.1,2.2 9 1\n"
        f"{_MOD}probe/internal/a/x.go:3.1,4.2 1 0\n"
        # generated code: excluded entirely, so its misses cost nothing
        f"{_MOD}gen/go/x/y.pb.go:1.1,9.9 500 0\n"
        # main(): excluded by line range, so its misses cost nothing either
        f"{_MOD}{main_go}:{main_line}.1,{main_line + 1}.2 400 0\n"
        "\n"
    )
    code, out, started = _coverage_run(tmp_path, "80", _profile(tmp_path, "ok.out", valid))
    assert (code, started) == (0, False), out
    assert "PASS: every package and the repo total are strictly above 80" in out
    assert "TOTAL (excluding generated code + main()): 9/10 = 90.0%" in out

    # Strict inequality: exactly 80.0% is a failure, per package and in total.
    at_80 = (
        "mode: atomic\n"
        f"{_MOD}probe/internal/a/x.go:1.1,2.2 8 3\n"
        f"{_MOD}probe/internal/a/x.go:3.1,4.2 2 0\n"
    )
    code, out, started = _coverage_run(tmp_path, "80", _profile(tmp_path, "eighty.out", at_80))
    assert code != 0 and not started, out
    assert "FAIL" in out and "PASS" not in out

    # The main() exclusion is the function only: an uncovered statement
    # elsewhere in the same file still counts.
    outside_main = valid + f"{_MOD}{main_go}:1.1,1.9 5 0\n"
    code, out, started = _coverage_run(
        tmp_path, "80", _profile(tmp_path, "outside.out", outside_main)
    )
    assert code != 0 and not started, out
    assert "probe/cmd/probe" in out and "PASS" not in out

    bad_inputs = {
        "absent": str(tmp_path / "does-not-exist.out"),
        "empty": _profile(tmp_path, "empty.out", ""),
        "header_only": _profile(tmp_path, "header.out", "mode: atomic\n"),
        "non_atomic": _profile(tmp_path, "set.out", valid.replace("mode: atomic", "mode: set")),
        "no_header": _profile(tmp_path, "nohdr.out", valid.split("\n", 1)[1]),
        "malformed_record": _profile(
            tmp_path, "bad.out", valid + f"{_MOD}probe/internal/a/x.go:5.1 1 1\n"
        ),
        "truncated_record": _profile(
            tmp_path, "trunc.out", valid + f"{_MOD}probe/internal/a/x.go:5.1,6.2 1\n"
        ),
        "only_generated_code": _profile(
            tmp_path, "gen.out", f"mode: atomic\n{_MOD}gen/go/x/y.pb.go:1.1,9.9 5 5\n"
        ),
        "zero_statement_records": _profile(
            tmp_path, "zero.out", f"mode: atomic\n{_MOD}probe/internal/a/x.go:1.1,2.2 0 3\n"
        ),
        "empty_path": "",
    }
    for label, path in bad_inputs.items():
        code, out, started = _coverage_run(tmp_path, "80", path)
        assert code != 0, (label, out)
        assert not started, (label, out)
        assert "PASS" not in out, (label, out)
        assert "FAILED" in out, (label, out)

    code, out, started = _coverage_run(tmp_path, "80", _profile(tmp_path, "x.out", valid), "extra")
    assert code == 2 and not started, out

    # The one-argument local route still generates its own profile with Go,
    # and a failed Go run ends it before any verdict is printed.
    code, out, started = _coverage_run(tmp_path, "80")
    assert started, out
    assert code != 0 and "PASS" not in out, out


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
# pytest-command parser for CI run: bodies. Resolves each pytest invocation's
# positional roots (and --ignore / --ignore-glob operands) against the step's
# working directory, so the temporal-workflow starter inventory below sees the
# directories CI actually collects.
# ---------------------------------------------------------------------------

#: pytest options that consume the following token, so that token is never
#: read as a positional root.
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


# W1: one run: body may contain more than one pytest command. The parser must
# emit one (roots, ignores) per command, not merge them; a merged pair would
# qualify the first command's roots with the second command's --ignore. The
# sizing-ledger path is only a sample --ignore operand here.
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
# run: bodies. A ';'/newline-only splitter would treat an &&-joined pair as
# one command and hand the second command's operands to the first.
_TWO_PYTEST_RUN_AND_AND = _TWO_PYTEST_RUN.replace("\n", " && ")


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
# bench-on-demand FP-BOD-1/2: the wrapper indirection is gone with the target.
# CI no longer delegates any B1 run to `scripts/integration-test.sh` and there
# is no live CI producer of sizing-ledger rows. The FP-IG-26 producer-order
# check, its resolution helpers and its fixture builders are all retired
# (b1-leftover-cleanup FP-LC-1); only the pytest-command parser above remains.
# The `images` job's tag gate is pinned by
# test_manifests.py::test_release_record_gates_image_push.
# ---------------------------------------------------------------------------

