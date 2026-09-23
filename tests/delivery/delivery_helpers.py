"""Helpers for the delivery-artifact tier (unique basename — never helpers.py)."""
from __future__ import annotations

import ast
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


# ---------------------------------------------------------------------------
# kind-deploy-tuning (FP-KDT-2/4): the live kind burst's non-failing p99
# observation, checked on the real source with `ast`. Shared by the FP-KDT-2
# and FP-KDT-4 function tests so both reject the same regressions.
# ---------------------------------------------------------------------------

KIND_B1_LIVE_TEST = "test_b1_ingest_burst_profile"
KIND_B1_HELPER = "emit_kind_b1_p99"
KIND_B1_HELPER_MODULE = "tests.e2e.kind_b1_observation"
KIND_B1_P99_FILE = "/tmp/rca-e2e/b1-kind-p99.txt"
KIND_B1_P99_MS = 150.0
#: pytest outcome calls that would turn the reading into a verdict.
_PYTEST_OUTCOMES = frozenset({"skip", "xfail", "fail", "importorskip", "exit"})


def _kind_live_function(tree: ast.Module) -> ast.FunctionDef | None:
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == KIND_B1_LIVE_TEST:
            return node
    return None


def _is_baseline_run(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Assign):
        return False
    if [ast.unparse(t) for t in stmt.targets] != ["baseline"]:
        return False
    return any(
        isinstance(n, ast.Attribute) and n.attr == "run_open_loop_baseline"
        for n in ast.walk(stmt.value)
    )


def kind_b1_p99_observation_failures(src: str) -> list[str]:
    """Why the live kind node's p99 reading is missing or has become a verdict.

    Required, on the real source: one module-level import of the helper; the
    threshold ``P99_MS`` bound once to ``150.0``; the node taking the
    ``record_property`` fixture; exactly one call of the helper, as a bare
    top-level statement immediately after the baseline assignment (so before
    ``audit_after_base`` and every baseline correctness assert), with the
    arguments ``baseline.p99, P99_MS, record_property,
    Path("/tmp/rca-e2e/b1-kind-p99.txt")``. Refused: any other reference to
    ``.p99`` or ``P99_MS`` in the node (an assert, raise, branch or retry on
    the reading), any pytest outcome call, a decorator beyond
    ``pytest.mark.e2e``, and a rebinding of ``baseline``.
    """
    fails: list[str] = []
    tree = ast.parse(src)

    imports = [
        n for n in tree.body
        if isinstance(n, ast.ImportFrom) and n.module == KIND_B1_HELPER_MODULE
    ]
    if len(imports) != 1 or [(a.name, a.asname) for a in imports[0].names] != [
        (KIND_B1_HELPER, None)
    ]:
        fails.append("the helper is not imported once, unaliased, at module scope")

    binds = [
        n for n in ast.walk(tree)
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
        and any(
            isinstance(t, ast.Name) and t.id == "P99_MS"
            for t in (n.targets if isinstance(n, ast.Assign) else [n.target])
        )
    ]
    if len(binds) != 1 or binds[0] not in tree.body:
        fails.append(f"P99_MS is bound {len(binds)} times, not once at module scope")
    else:
        value = binds[0].value
        if not (
            isinstance(value, ast.Constant)
            and type(value.value) is float
            and value.value == KIND_B1_P99_MS
        ):
            fails.append(f"P99_MS changed: {ast.unparse(value)}")

    fn = _kind_live_function(tree)
    if fn is None:
        fails.append(f"{KIND_B1_LIVE_TEST} not found")
        return fails

    decorators = [ast.unparse(d) for d in fn.decorator_list]
    if decorators != ["pytest.mark.e2e"]:
        fails.append(f"the node carries decorators beyond pytest.mark.e2e: {decorators}")
    if "record_property" not in [a.arg for a in fn.args.args]:
        fails.append("the node does not take the record_property fixture")

    calls = [
        n for n in ast.walk(fn)
        if isinstance(n, ast.Call)
        and isinstance(n.func, ast.Name) and n.func.id == KIND_B1_HELPER
    ]
    if len(calls) != 1:
        fails.append(f"expected one {KIND_B1_HELPER} call in the node, found {len(calls)}")
        return fails
    call = calls[0]

    stmt_index = next(
        (
            i for i, stmt in enumerate(fn.body)
            if isinstance(stmt, ast.Expr) and stmt.value is call
        ),
        None,
    )
    if stmt_index is None:
        fails.append("the observation is not a bare top-level statement of the node")

    rendered = [ast.unparse(a) for a in call.args]
    expected = ["baseline.p99", "P99_MS", "record_property", f"Path({KIND_B1_P99_FILE!r})"]
    if rendered != expected or call.keywords:
        fails.append(f"the observation's arguments are {rendered} (keywords "
                     f"{[k.arg for k in call.keywords]}), not {expected}")

    baseline_binds = [
        n for n in ast.walk(fn)
        if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.NamedExpr))
        and any(
            isinstance(t, ast.Name) and t.id == "baseline"
            for t in (
                n.targets if isinstance(n, ast.Assign)
                else [n.target]
            )
        )
    ]
    base_index = next((i for i, s in enumerate(fn.body) if _is_baseline_run(s)), None)
    if base_index is None or len(baseline_binds) != 1:
        fails.append("baseline is not bound exactly once from run_open_loop_baseline")
    elif stmt_index is not None and stmt_index != base_index + 1:
        fails.append(
            "the observation does not immediately follow run_open_loop_baseline "
            f"(baseline at statement {base_index}, observation at {stmt_index})"
        )
    if stmt_index is not None and base_index is not None and any(
        isinstance(s, ast.Assert) for s in fn.body[base_index + 1:stmt_index]
    ):
        fails.append("the observation follows a baseline correctness assert")

    inside = {id(n) for n in ast.walk(call)}
    for node in ast.walk(fn):
        if id(node) in inside:
            continue
        if isinstance(node, ast.Attribute) and node.attr == "p99":
            fails.append(f"the node reads .p99 outside the observation (line {node.lineno})")
        if isinstance(node, ast.Name) and node.id == "P99_MS":
            fails.append(f"the node reads P99_MS outside the observation (line {node.lineno})")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "pytest"
            and node.func.attr in _PYTEST_OUTCOMES
        ):
            fails.append(f"the node calls pytest.{node.func.attr} (line {node.lineno})")
    return fails


def kind_b1_p99_mutants(src: str) -> list[tuple[str, str]]:
    """Named regressions of the real live source; each must be refused.

    Built from the shipped bytes, not from a synthetic snippet, so a mutant
    that stops applying (``mutated == src``) is itself a failure the caller
    asserts on.
    """
    tree = ast.parse(src)
    fn = _kind_live_function(tree)
    assert fn is not None, KIND_B1_LIVE_TEST
    stmt = next(
        s for s in fn.body
        if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call)
        and isinstance(s.value.func, ast.Name) and s.value.func.id == KIND_B1_HELPER
    )
    lines = src.split("\n")
    call_block = lines[stmt.lineno - 1:stmt.end_lineno]
    without = lines[:stmt.lineno - 1] + lines[stmt.end_lineno:]
    first_assert = "    assert served + errors == 6000"
    moved = "\n".join(without).replace(
        first_assert, "\n".join(call_block) + "\n" + first_assert, 1
    )
    after_call = "\n".join(lines[:stmt.end_lineno])
    rest = "\n".join(lines[stmt.end_lineno:])

    def insert(block: str) -> str:
        return after_call + "\n" + block + "\n" + rest

    return [
        ("missing_observation", "\n".join(without)),
        ("constant_p99", src.replace("baseline.p99, P99_MS", "12.0, P99_MS", 1)),
        ("fabricated_p99", src.replace(
            "baseline.p99, P99_MS", "baseline.max_lateness_ms, P99_MS", 1)),
        ("changed_threshold", src.replace("P99_MS = 150.0", "P99_MS = 1500.0", 1)),
        ("literal_threshold", src.replace("baseline.p99, P99_MS", "baseline.p99, 150.0", 1)),
        ("p99_assert", insert("    assert baseline.p99 < P99_MS")),
        ("p99_raise", insert(
            "    if baseline.p99 >= P99_MS:\n        raise AssertionError('slow')")),
        ("p99_skip", insert(
            "    if baseline.p99 >= P99_MS:\n        pytest.skip('slow')")),
        ("p99_xfail", insert("    pytest.xfail('kind latency')")),
        ("retry_decorator", src.replace(
            f"@pytest.mark.e2e\ndef {KIND_B1_LIVE_TEST}(",
            f"@pytest.mark.e2e\n@pytest.mark.flaky(reruns=2)\ndef {KIND_B1_LIVE_TEST}(", 1)),
        ("result_gated", src.replace(
            f"    {KIND_B1_HELPER}(\n", f"    line = {KIND_B1_HELPER}(\n", 1)),
        ("moved_after_correctness_assert", moved),
        ("no_fixture", src.replace(
            "dashboard_url, record_property):", "dashboard_url):", 1)),
    ]
