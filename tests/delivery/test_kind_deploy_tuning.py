"""kind-deploy-tuning: the kind B1 burst's p99 is observed, never a verdict.

design/slices/kind-deploy-tuning/design.md, FP-KDT-2 and FP-KDT-3, plus the
§5 unit tests of ``tests/e2e/kind_b1_observation.py``. The CI functional job
runs this file a second time under
``--cov=tests.e2e.kind_b1_observation --cov-branch --cov-fail-under=81``.

Everything here is static or local. None of it substitutes for the one live
kind run the slice's acceptance bar requires; that proof is read from a real
e2e job log.
"""
from __future__ import annotations

import ast
import math
import os
import re
import signal
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

from delivery_helpers import (
    CI_YML,
    KIND_B1_P99_FILE,
    REPO_ROOT,
    kind_b1_p99_mutants,
    kind_b1_p99_observation_failures,
)
from tests.e2e.kind_b1_observation import (
    KIND_B1_P99_PATH,
    KIND_B1_P99_PROPERTY,
    KindB1ObservationError,
    emit_kind_b1_p99,
)

E2E = REPO_ROOT / "tests" / "e2e"
RUN_SH = E2E / "run.sh"
LIVE_TEST = E2E / "test_e2e_load.py"
HELPER_SRC = E2E / "kind_b1_observation.py"
LINE_RE = re.compile(
    r"^B1 kind p99_ms=(?P<p99>[^,]+),threshold_ms=150\.0,under_150=(?P<under>true|false)$"
)
CLEAR_FN = "clear_kind_b1_p99_line"
REQUIRE_FN = "require_kind_b1_p99_line"
MISSING_ERROR = "missing kind B1 p99 line"
SOURCING_GUARD = 'if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then'
FAILURE_STEP = "Upload phase timing and pod logs on failure"


class _PropertySpy:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def __call__(self, name: str, value: object) -> None:
        self.calls.append((name, value))


# ---------------------------------------------------------------------------
# §5 unit tests: emit_kind_b1_p99 in-process.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("p99", "under"),
    [(149.999, True), (150.0, False), (2132.672, False), (0.5, True)],
)
def test_emit_kind_b1_p99_records_writes_prints_and_returns_one_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], p99: float, under: bool
):
    spy = _PropertySpy()
    out = tmp_path / "b1-kind-p99.txt"

    # A false comparison is not an exception: the call simply returns.
    line = emit_kind_b1_p99(p99, 150.0, spy, out)

    expected = (
        f"B1 kind p99_ms={p99!r},threshold_ms=150.0,"
        f"under_150={'true' if under else 'false'}"
    )
    assert line == expected
    match = LINE_RE.match(line)
    assert match is not None, line
    assert float(match.group("p99")) == p99
    assert spy.calls == [(KIND_B1_P99_PROPERTY, under)]
    assert type(spy.calls[0][1]) is bool
    assert out.read_bytes() == (expected + "\n").encode("utf-8")
    assert capsys.readouterr().out == expected + "\n"


def test_emit_kind_b1_p99_exactly_at_threshold_is_false():
    spy = _PropertySpy()
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        line = emit_kind_b1_p99(150.0, 150.0, spy, Path(tmp) / "x.txt")
    assert line.endswith(",under_150=false")
    assert spy.calls == [("b1_kind_p99_lt_150_ms", False)]


def test_emit_kind_b1_p99_creates_the_output_parent(tmp_path: Path):
    out = tmp_path / "not" / "yet" / "there" / "b1-kind-p99.txt"
    assert not out.parent.exists()
    line = emit_kind_b1_p99(12.25, 150.0, _PropertySpy(), out)
    assert out.read_text(encoding="utf-8") == line + "\n"


def test_emit_kind_b1_p99_overwrites_an_earlier_line(tmp_path: Path):
    out = tmp_path / "b1-kind-p99.txt"
    out.write_text("stale\nlines\n", encoding="utf-8")
    line = emit_kind_b1_p99(99.0, 150.0, _PropertySpy(), out)
    assert out.read_text(encoding="utf-8") == line + "\n"


@pytest.mark.parametrize("bad", [math.nan, math.inf, -math.inf])
def test_emit_kind_b1_p99_refuses_a_non_finite_measurement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], bad: float
):
    spy = _PropertySpy()
    out = tmp_path / "b1-kind-p99.txt"
    # A line left by an earlier run must not survive as a misleading proof.
    out.write_text("B1 kind p99_ms=1.0,threshold_ms=150.0,under_150=true\n", encoding="utf-8")

    with pytest.raises(KindB1ObservationError, match="not a finite measurement"):
        emit_kind_b1_p99(bad, 150.0, spy, out)

    assert spy.calls == []
    assert not out.exists()
    assert capsys.readouterr().out == ""
    # ...and it is an explicit error class, not a threshold assertion.
    assert issubclass(KindB1ObservationError, ValueError)
    assert not issubclass(KindB1ObservationError, AssertionError)


def test_emit_kind_b1_p99_non_finite_with_no_earlier_file(tmp_path: Path):
    out = tmp_path / "absent" / "b1-kind-p99.txt"
    with pytest.raises(KindB1ObservationError):
        emit_kind_b1_p99(math.nan, 150.0, _PropertySpy(), out)
    assert not out.exists()


def test_emit_kind_b1_p99_failed_write_is_an_integrity_error(tmp_path: Path):
    # The output "parent" is a regular file: the write cannot happen, and the
    # failure is loud rather than a silently missing observation.
    blocker = tmp_path / "blocker"
    blocker.write_text("", encoding="utf-8")
    with pytest.raises(OSError):
        emit_kind_b1_p99(10.0, 150.0, _PropertySpy(), blocker / "b1-kind-p99.txt")


# ---------------------------------------------------------------------------
# FP-KDT-2 [function test]
# ---------------------------------------------------------------------------


def _helper_verdict_failures(src: str) -> list[str]:
    """Why the helper module could turn the comparison into a verdict."""
    fails: list[str] = []
    tree = ast.parse(src)
    fn = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "emit_kind_b1_p99"),
        None,
    )
    if fn is None:
        return ["emit_kind_b1_p99 not found"]
    for node in ast.walk(tree):
        if isinstance(node, ast.Assert):
            fails.append(f"assert at line {node.lineno}")
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
            if any(n.split(".")[0] == "pytest" for n in names):
                fails.append("imports pytest")
    # Every raise sits under the non-finite guard, nowhere else.
    guards = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.If) and "isfinite" in ast.unparse(n.test)
    ]
    guarded = {id(r) for g in guards for r in ast.walk(g) if isinstance(r, ast.Raise)}
    for node in ast.walk(fn):
        if isinstance(node, ast.Raise) and id(node) not in guarded:
            fails.append(f"threshold-reachable raise at line {node.lineno}")
        if isinstance(node, (ast.While, ast.For)):
            fails.append(f"loop (retry) at line {node.lineno}")
    # The comparison with the threshold happens exactly once, and nothing
    # branches on its result.
    compares = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Compare) and "threshold" in ast.unparse(n)
    ]
    if len(compares) != 1 or [type(o) for o in compares[0].ops] != [ast.Lt]:
        fails.append(f"threshold compared {len(compares)} times, not once with <")
    for node in ast.walk(fn):
        if isinstance(node, (ast.If, ast.While, ast.IfExp)):
            if "under" in {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}:
                if not isinstance(node, ast.IfExp):
                    fails.append(f"branches on the comparison at line {node.lineno}")
    returns = [n for n in ast.walk(fn) if isinstance(n, ast.Return)]
    if len(returns) != 1 or fn.body[-1] is not returns[0]:
        fails.append("a return path other than the final one")
    return fails


def test_kind_burst_p99_is_observed_and_not_a_verdict(tmp_path: Path):
    """FP-KDT-2 [function test]: the live node reports p99; p99 decides nothing.

    Named for these failures: the live function omits ``baseline.p99`` or
    reads a fabricated value; ``P99_MS`` changes; the helper is called after
    a correctness assert; or a 150.0/above-threshold observation becomes an
    assert, raise, skip, retry or pytest outcome. Checked on the live AST, on
    the helper's own AST, and on the helper's in-process behaviour.
    """
    src = LIVE_TEST.read_text(encoding="utf-8")
    assert kind_b1_p99_observation_failures(src) == []

    # Each named regression of the real source is refused.
    for name, mutated in kind_b1_p99_mutants(src):
        assert mutated != src, f"mutant {name} no longer applies to the live source"
        assert kind_b1_p99_observation_failures(mutated) != [], name

    # The live output path is the one run.sh prints and the failure artifact
    # carries.
    assert str(KIND_B1_P99_PATH) == KIND_B1_P99_FILE
    assert KIND_B1_P99_PATH.parent == Path("/tmp/rca-e2e")

    # The helper cannot turn the comparison into a verdict...
    helper_src = HELPER_SRC.read_text(encoding="utf-8")
    assert _helper_verdict_failures(helper_src) == []
    for mutant in (
        helper_src.replace(
            "    under = p99 < threshold\n",
            "    under = p99 < threshold\n    assert under, 'slow'\n", 1),
        helper_src.replace(
            "    under = p99 < threshold\n",
            "    under = p99 < threshold\n    if not under:\n        raise RuntimeError('slow')\n", 1),
        helper_src.replace(
            "    under = p99 < threshold\n",
            "    under = p99 < threshold\n    if not under:\n        return ''\n", 1),
        helper_src.replace("    under = p99 < threshold\n", "    under = p99 <= threshold\n", 1),
        helper_src.replace("import math\n", "import math\nimport pytest\n", 1),
    ):
        assert mutant != helper_src
        assert _helper_verdict_failures(mutant) != []

    # ...and in-process, 150.0 and a far miss both simply return.
    for p99 in (150.0, 2132.672):
        spy = _PropertySpy()
        line = emit_kind_b1_p99(p99, 150.0, spy, tmp_path / "obs.txt")
        assert line.endswith("under_150=false")
        assert spy.calls == [(KIND_B1_P99_PROPERTY, False)]


# ---------------------------------------------------------------------------
# FP-KDT-3 [function test]
# ---------------------------------------------------------------------------


def _bash_definition_lines(text: str, name: str) -> list[int]:
    """0-based line indexes of bash definitions of *name* (brace on same or next line)."""
    pattern = re.compile(
        rf"^[ \t]*(?:function[ \t]+)?{re.escape(name)}[ \t]*(?:\([ \t]*\))?[ \t\r\n]*\{{", re.M
    )
    return [text.count("\n", 0, m.start()) for m in pattern.finditer(text)]


def _next_code_line(lines: list[str], start: int) -> int:
    j = start
    while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith("#")):
        j += 1
    return j


def _kind_p99_run_sh_failures(text: str) -> list[str]:
    """Definition counts and executable call order of the two functions."""
    fails: list[str] = []
    lines = text.splitlines()
    guard = [i for i, ln in enumerate(lines) if ln.strip() == SOURCING_GUARD]
    if len(guard) != 1:
        return [f"expected one sourcing guard, found {len(guard)}"]
    g = guard[0]
    if "set -euo pipefail" not in [ln.strip() for ln in lines[:5]]:
        fails.append("run.sh no longer starts with set -euo pipefail")
    bodies: set[int] = set()
    for fn in (CLEAR_FN, REQUIRE_FN):
        for d in _bash_definition_lines(text, fn):
            end = next((i for i in range(d, len(lines)) if lines[i] == "}"), len(lines) - 1)
            bodies.update(range(d, end + 1))
    for fn in (CLEAR_FN, REQUIRE_FN):
        defs = _bash_definition_lines(text, fn)
        if len(defs) != 1:
            fails.append(f"{fn} defined {len(defs)} times, not once")
        elif defs[0] > g:
            fails.append(f"{fn} is defined after the sourcing guard")
        mentions = [
            i for i, ln in enumerate(lines)
            if fn in ln and not ln.lstrip().startswith("#") and i not in bodies
        ]
        calls = [i for i in mentions if lines[i].strip() == fn]
        others = [i for i in mentions if i not in calls]
        if len(calls) != 1:
            fails.append(f"{fn} has {len(calls)} bare calls, not one")
        if others:
            fails.append(f"{fn} is used in a non-bare form: {[lines[i] for i in others]}")
        if calls and calls[0] < g:
            fails.append(f"{fn} is called before the sourcing guard")

    mkdir = [i for i, ln in enumerate(lines) if ln.strip() == "mkdir -p /tmp/rca-e2e"]
    phases = {
        m.group(1): i for i, ln in enumerate(lines)
        for m in [re.match(r'^\s*phase "([a-z0-9_]+)"', ln)] if m
    }
    clear_calls = [i for i, ln in enumerate(lines) if ln.strip() == CLEAR_FN]
    if clear_calls:
        c = clear_calls[0]
        if not mkdir or mkdir[0] > c:
            fails.append("clear runs before /tmp/rca-e2e is created")
        first_phase = min((i for i in phases.values() if i > g), default=None)
        if first_phase is None or c > first_phase:
            fails.append("clear does not run before the first phase")

    require_calls = [i for i, ln in enumerate(lines) if ln.strip() == REQUIRE_FN]
    if require_calls and "pytest_e2e" in phases:
        r = require_calls[0]
        start = phases["pytest_e2e"]
        # The phase body is a single-quoted bash -c block closed by a lone `'`.
        close = next((i for i in range(start + 1, len(lines)) if lines[i] == "'"), None)
        if close is None or _next_code_line(lines, close + 1) != r:
            fails.append("require does not directly follow the pytest_e2e phase")
        after = _next_code_line(lines, r + 1)
        if after >= len(lines) or lines[after].strip() != "stop_live_log_sidecar":
            fails.append("require is not directly before stop_live_log_sidecar")
        teardown = phases.get("teardown")
        if teardown is not None and teardown < r:
            fails.append("require runs after teardown")
    elif "pytest_e2e" not in phases:
        fails.append('missing phase "pytest_e2e"')
    for fn in (CLEAR_FN, REQUIRE_FN):
        default = '  local path="${1:-' + KIND_B1_P99_FILE + '}"'
        defs = _bash_definition_lines(text, fn)
        if defs and (defs[0] + 1 >= len(lines) or lines[defs[0] + 1] != default):
            fails.append(f"{fn} does not default to {KIND_B1_P99_FILE}")
    return fails


def _source_run_sh(tmp_path: Path, body: str) -> subprocess.CompletedProcess:
    script = textwrap.dedent(
        f"""\
        set -euo pipefail
        # shellcheck disable=SC1091
        source "{RUN_SH}"
        """
    ) + textwrap.dedent(body)
    proc = subprocess.Popen(
        ["bash", "-c", script],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        proc.communicate()
        raise AssertionError(
            "sourcing run.sh must stop at its sourcing guard within seconds"
        ) from None
    return subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)


def test_kind_p99_line_reaches_the_e2e_job_log(tmp_path: Path):
    """FP-KDT-3 [function test]: the line is cleared, required and printed.

    Named for these failures: run.sh fails to clear an old file, does not
    require the new one after pytest_e2e, or does not print it before
    teardown; or the failure upload no longer includes /tmp/rca-e2e/**. The
    real run.sh is sourced and both named functions are called against a
    temporary path; the definition count and executable call order are pinned
    so the sourced functions are the ones the executable path calls.
    """
    text = RUN_SH.read_text(encoding="utf-8")
    assert _kind_p99_run_sh_failures(text) == []

    # The static pin goes red when the thing it names is broken.
    guard_line = SOURCING_GUARD + "\n"
    require_call = "\nrequire_kind_b1_p99_line\nstop_live_log_sidecar\n"
    clear_call = "\nclear_kind_b1_p99_line\n\n"
    assert require_call in text and clear_call in text and guard_line in text
    for mutant in (
        text.replace(require_call, "\nstop_live_log_sidecar\n", 1),
        text.replace(require_call, "\nrequire_kind_b1_p99_line || true\nstop_live_log_sidecar\n", 1),
        text.replace(require_call, "\nstop_live_log_sidecar\nrequire_kind_b1_p99_line\n", 1),
        text.replace(clear_call, "\n\n", 1),
        text.replace(clear_call, "\n\n", 1).replace(
            'phase "build_and_cluster"', 'clear_kind_b1_p99_line\nphase "build_and_cluster"', 1),
        text + "\nrequire_kind_b1_p99_line() { :; }\n",
        text.replace("mkdir -p /tmp/rca-e2e\n", "", 1),
        text.replace('  local path="${1:-/tmp/rca-e2e/b1-kind-p99.txt}"\n  rm -f',
                     '  local path="${1:-/tmp/rca-e2e/other.txt}"\n  rm -f', 1),
    ):
        assert mutant != text
        assert _kind_p99_run_sh_failures(mutant) != []

    line_dir = tmp_path / "rca-e2e"
    line_dir.mkdir()
    line_file = line_dir / "b1-kind-p99.txt"
    neighbour = line_dir / "phases.txt"
    neighbour.write_text("keep me\n", encoding="utf-8")

    # (1) A stale file is removed, and only that file.
    line_file.write_text("B1 kind p99_ms=1.0,threshold_ms=150.0,under_150=true\n", encoding="utf-8")
    cleared = _source_run_sh(tmp_path, f'{CLEAR_FN} "{line_file}"\n')
    assert cleared.returncode == 0, cleared.stderr
    assert not line_file.exists(), "the stale kind p99 line survived clear"
    assert neighbour.read_text(encoding="utf-8") == "keep me\n"
    # Clearing an absent file is not an error.
    again = _source_run_sh(tmp_path, f'{CLEAR_FN} "{line_file}"\n')
    assert again.returncode == 0, again.stderr

    # (2) Absent and empty files are a named instrumentation failure.
    missing = _source_run_sh(tmp_path, f'{REQUIRE_FN} "{line_file}"\n')
    assert missing.returncode != 0
    assert MISSING_ERROR in missing.stderr.decode()
    assert missing.stdout == b""
    line_file.write_bytes(b"")
    empty = _source_run_sh(tmp_path, f'{REQUIRE_FN} "{line_file}"\n')
    assert empty.returncode != 0
    assert MISSING_ERROR in empty.stderr.decode()

    # (3) A present file is printed byte-for-byte; a miss is still success,
    # because this check is about the carrier, never the latency.
    for payload in (
        b"B1 kind p99_ms=12.5,threshold_ms=150.0,under_150=true\n",
        b"B1 kind p99_ms=2132.672,threshold_ms=150.0,under_150=false\n",
    ):
        line_file.write_bytes(payload)
        shown = _source_run_sh(tmp_path, f'{REQUIRE_FN} "{line_file}"\necho AFTER\n')
        assert shown.returncode == 0, shown.stderr
        assert shown.stdout == payload + b"AFTER\n"

    # (4) The live test writes the path run.sh defaults to, and the failure
    # upload still carries /tmp/rca-e2e/** (the line lives under it).
    live = LIVE_TEST.read_text(encoding="utf-8")
    assert f'Path("{KIND_B1_P99_FILE}")' in live
    workflow = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["e2e"]["steps"]
    failure = [s for s in steps if s.get("name") == FAILURE_STEP]
    assert len(failure) == 1, [s.get("name") for s in steps]
    assert failure[0].get("if") == "failure()"
    assert "/tmp/rca-e2e/**" in str(failure[0]["with"]["path"]).split()
    assert KIND_B1_P99_FILE.startswith("/tmp/rca-e2e/")
    assert any("bash tests/e2e/run.sh" in str(s.get("run", "")) for s in steps)
