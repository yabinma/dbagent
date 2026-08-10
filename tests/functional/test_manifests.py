"""Sanity checks for the benchmark/functional checkpoint manifests
(design.md Section 14.3/14.4). FP-M6-26: honesty rules enforced in code.

Errata passes 11-21 / design.md section 11.1.3: linked covered tests must
contain an executable threshold assertion (parser-backed), with L0 binding
resolution, collection/skip/dead/swallowed rules, and CI-pin machinery.
"""
from __future__ import annotations

import ast
import configparser
import copy
import os
import re
import subprocess
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_BENCHMARK_IDS = {f"B{i}" for i in range(1, 15)}
EXPECTED_CHECKPOINT_IDS = {f"F{i}" for i in range(1, 19)}
VALID_STATUSES = {"covered", "partial", "deferred"}
SHIPPED_MILESTONES = {"M1", "M2", "M3", "M4", "M5", "M6"}

GO_GUARD = "tests/functional/manifest_honesty/thresholds_test.go"
GO_GUARD_FUNC = "func TestManifestGoTestsAssertTheirThresholds("

_FORWARD_PHRASES = [
    r"needs",
    r"remains a",
    r"remains an",
    r"remains the",
    r"is deferred",
    r"are deferred",
    r"deferred to",
    r"still deferred",
    r"still partial",
    r"revisit at",
    r"revisited at",
    r"will be covered",
    r"will be addressed",
    r"to be covered",
    r"not built yet",
    r"not yet built",
    r"TODO",
]
_PHRASE_RE = re.compile(
    r"\b(?:" + "|".join(_FORWARD_PHRASES) + r")\b",
    re.IGNORECASE,
)
_MILESTONE_RE = re.compile(r"\bM[1-9]\b")

_ORDERED_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_NUMERIC_BINOPS = (ast.Add, ast.Sub, ast.Mult, ast.Div)
_NESTED_SCOPE = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)
_NUMERIC_DEPTH_CAP = 3

THRESHOLD_REASONS: frozenset[str] = frozenset({
    "missing_file",
    "unknown_suffix",
    "missing_go_guard",
    "build_context",
    "not_collected",
    "nonexistent_linked_test",
    "ambiguous_test_name",
    "skipped",
    "no_candidate",
    "dead_candidate",
    "not_a_threshold_comparison",
    "swallowed_candidate",
    "no_fail_in_branch",
    "both_operands_numeric",
    "star_import",
    "unresolved_identifier",
    "no_numeric_term",
    "not_testify",
    "bad_testing_t",
    "spread_operand",
    "bad_tolerance",
    "dot_import",
})
assert len(THRESHOLD_REASONS) == 22

CI_PIN_REASONS: frozenset[str] = frozenset({
    "go_build_tag_flag",
    "go_race_or_short_flag",
    "go_env_key",
    "go_version_mismatch",
    "missing_setup_go",
    "go_runner_drift",
    "go_test_job_inventory",
    "job_inventory",
    "python_optimize_flag",
    "python_env_key",
    "github_env_write",
    "e2e_command_drift",
    "missing_e2e_hygiene_gate",
    "pytest_collection_override",
    "setup_go_ordering",
    "run_not_recognized",
    "go_test_command_unparsed",
    "github_path_write_drift",
    "pytest_config_inventory",
    "conftest_collection_hook",
    "pytest_command_drift",
    "pytest_config_unreadable",
    "step_envelope_drift",
    "guarded_step_shape",
    "command_operand_drift",
    "go_test_command_drift",
    "needs_graph_drift",
    "guard_context_drift",
})
assert len(CI_PIN_REASONS) == 28
assert THRESHOLD_REASONS & CI_PIN_REASONS == set()

EXPECTED_CI_JOBS = {
    "lint",
    "manifest-guard",
    "unit-rca-common",
    "unit-worker",
    "unit-gateway",
    "unit-dashboard-api",
    "unit-web",
    "unit-go",
    "functional",
    "benchmark",
    "images",
    "e2e",
}
GO_TEST_JOBS = {"unit-go", "functional", "benchmark", "manifest-guard"}
GO_TOOLCHAIN_ENV_NAMES = {"CC", "CXX", "FC", "AR", "PKG_CONFIG"}
PYTHON_OPT_JOBS = {"functional", "benchmark", "e2e", "manifest-guard"}
RACE_SHORT_BAN_JOBS = {"functional", "benchmark", "manifest-guard"}

GUARDED_STEPS: dict[str, list[int]] = {
    "unit-rca-common": [3],
    "unit-worker": [3],
    "unit-gateway": [3],
    "unit-dashboard-api": [3],
    "unit-go": [7],
    "functional": [9, 10],
    "benchmark": [7, 8, 9, 10, 11, 12, 13, 14, 15, 17],
    "manifest-guard": [5, 6],
}

EXPECTED_NEEDS_GRAPH: dict[str, tuple[str, ...]] = {
    "lint": (),
    "manifest-guard": (),
    "unit-rca-common": ("lint",),
    "unit-worker": ("lint",),
    "unit-gateway": ("lint",),
    "unit-dashboard-api": ("lint",),
    "unit-web": ("lint",),
    "unit-go": ("lint",),
    "functional": (
        "unit-dashboard-api",
        "unit-gateway",
        "unit-go",
        "unit-rca-common",
        "unit-web",
        "unit-worker",
    ),
    "benchmark": ("functional",),
    "images": ("lint",),
    "e2e": ("benchmark",),
}
assert set(EXPECTED_NEEDS_GRAPH) == EXPECTED_CI_JOBS

EXPECTED_GO_TEST_COMMANDS: dict[str, list[tuple[str | None, str]]] = {
    "unit-go": [(None, "go test ./... -race -timeout 300s -p 1")],
    "functional": [(None, "go test ./tests/functional/... -v -timeout 300s")],
    "benchmark": [
        (None, "go test ./services/probe-gateway/internal/gwserver/... -run TestB3 -v -timeout 60s"),
        (None, "go test ./services/probe-gateway/internal/gwserver/... -run TestB4 -v -timeout 60s"),
        (None, "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s"),
        (None, "go test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s"),
    ],
    "manifest-guard": [
        (None, "go test ./tests/functional/manifest_honesty/... -v -timeout 300s"),
    ],
}
assert set(EXPECTED_GO_TEST_COMMANDS) == GO_TEST_JOBS

EXPECTED_PYTEST_COMMANDS: dict[str, list[tuple[str | None, str]]] = {
    "unit-rca-common": [(
        "libs/py/rca_common",
        ".venv/bin/python -m pytest tests/ --cov=rca_common "
        "--cov-report=term-missing --cov-fail-under=81",
    )],
    "unit-worker": [(
        "services/worker",
        ".venv/bin/python -m pytest tests/ --cov=worker --cov=scripts "
        "--cov-report=term-missing --cov-fail-under=81",
    )],
    "unit-gateway": [(
        "services/gateway",
        ".venv/bin/python -m pytest tests/ --cov=gateway "
        "--cov-report=term-missing --cov-fail-under=81",
    )],
    "unit-dashboard-api": [(
        "services/dashboard-api",
        ".venv/bin/python -m pytest tests/ --cov=dashboard_api "
        "--cov-report=term-missing --cov-fail-under=81",
    )],
    "functional": [(
        None,
        "services/worker/.venv/bin/python -m pytest "
        "services/worker/tests services/gateway/tests "
        "services/dashboard-api/tests tests/functional tests/delivery "
        "tests/mocks/llm -v --ignore=tests/functional/m2_probe_link",
    )],
    "benchmark": [
        (None, "services/worker/.venv/bin/python -m pytest tests/functional/test_manifests.py -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "libs/py/rca_common/tests/test_rawcmd.py::test_b6_static_validator_under_5ms -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "services/dashboard-api/tests/test_b12_hot_endpoints.py -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "services/worker/tests/test_investigation_workflow.py"
         "::test_b13_round_loop_overhead_under_1s -v"),
        (None, "services/worker/.venv/bin/python -m pytest "
         "services/worker/tests/test_context_assembly.py"
         "::test_b14_prompt_build_under_200ms_and_no_latest_truncation -v"),
        (None, "services/worker/.venv/bin/python -m pytest tests/benchmark/test_pg_scale.py -v -s"),
    ],
    "manifest-guard": [
        (None, "services/worker/.venv/bin/python -m pytest tests/functional/test_manifests.py -v"),
    ],
}
assert set(GUARDED_STEPS) == GO_TEST_JOBS | set(EXPECTED_PYTEST_COMMANDS)

EXPECTED_E2E_PYTEST_COMMAND = "python3 -m pytest tests/e2e -v --tb=short"
EXPECTED_E2E_HYGIENE_COMMAND = (
    'bad="$(awk \'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); '
    'if (p != "PYTHON" && p != "PYTEST") continue; print k } }\')"; '
    'if [ -n "$bad" ]; then printf \'e2e env hygiene: forbidden PYTHON*/PYTEST* '
    'environment key present before the measured invocation:\\n%s\\n\' "$bad" >&2; exit 1; fi'
)
EXPECTED_CI_HYGIENE_RUN = (
    'bad="$(awk \'BEGIN { for (k in ENVIRON) { p = substr(k, 1, 6); '
    'if (p != "PYTHON" && p != "PYTEST") continue; print k } }\')"; '
    'if [ -n "$bad" ]; then printf \'FP-M6-31 A10(v): forbidden PYTHON*/PYTEST* '
    'environment key present before the measured invocation:\\n%s\\n\' "$bad" >&2; exit 1; fi'
)
EXPECTED_E2E_GITHUB_PATH_LINES = {
    'echo "$(go env GOPATH)/bin" >> "$GITHUB_PATH"',
}

# (AG)(5): the images GHCR-push body is pinned as a reviewable literal — never
# derived from the workflow file it is supposed to protect (review C2).
EXPECTED_IMAGES_PUSH_RUN = (
    "set -euo pipefail\n"
    "source deploy/versions.env\n"
    'echo "${{ secrets.GITHUB_TOKEN }}" | docker login ghcr.io -u "${{ github.actor }}" --password-stdin\n'
    'SHORT_SHA="${GITHUB_SHA::12}"\n'
    "for c in ingest-gateway temporal-worker probe-gateway dashboard-api dashboard-web probe; do\n"
    '  docker push "${REGISTRY}/${c}:${APP_VERSION}"\n'
    '  docker push "${REGISTRY}/${c}:sha-${SHORT_SHA}"\n'
    "done"
)

UNPARSED_RUN_STEPS: dict[str, list[str]] = {
    "functional": [EXPECTED_CI_HYGIENE_RUN],
    "benchmark": [EXPECTED_CI_HYGIENE_RUN],
    "manifest-guard": [EXPECTED_CI_HYGIENE_RUN],
    "images": [EXPECTED_IMAGES_PUSH_RUN],
}


RUN_COMMAND_WORDS = frozenset({
    "go",
    "bash",
    "echo",
    "python",
    "npm",
    "set",
    "source",
    "export",
    "curl",
    "tar",
    "sudo",
    "chmod",
    "helm",
    ".venv/bin/pip",
    ".venv/bin/python",
    "services/worker/.venv/bin/pip",
    "services/worker/.venv/bin/python",
    "services/gateway/.venv/bin/pip",
    "services/dashboard-api/.venv/bin/pip",
})
assert len(RUN_COMMAND_WORDS) == 19

GUARDED_STEP_COMMAND_WORDS = frozenset({
    "go", "bash", ".venv/bin/python", "services/worker/.venv/bin/python",
})
BASH_SCRIPTS = frozenset({
    "scripts/gen-proto.sh",
    "scripts/go-coverage-check.sh",
    "../../scripts/py-coverage-check.sh",
    "../../../scripts/py-coverage-check.sh",
    "deploy/docker/build.sh",
    "tests/e2e/run.sh",
})
SUDO_NESTED_COMMANDS = frozenset({"mv"})
PYTHON_MODULES = frozenset({"pytest", "venv", "compileall"})
GO_INSTALL_TARGETS = frozenset({
    "google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.5",
    "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1",
})
COMMAND_OPERANDS = RUN_COMMAND_WORDS | SUDO_NESTED_COMMANDS

EXPECTED_CHAIN_CONFIG_FILES = frozenset({
    "pytest.ini",
    "libs/py/rca_common/alembic.ini",
    "libs/py/rca_common/pyproject.toml",
    "services/gateway/pyproject.toml",
    "services/worker/pyproject.toml",
    "services/dashboard-api/pyproject.toml",
})
PYTEST_OPTION_ALLOWLIST = frozenset({"asyncio_mode"})
ADMITTED_DECORATOR_ORIGINS = frozenset({"pytest.fixture", "pytest_asyncio.fixture"})
SKIP_MARKERS = frozenset({
    "skip", "skipif", "xfail", "expectedFailure", "skipIf", "skipUnless",
})
SUPPRESSOR_CM = frozenset({"raises", "warns", "suppress", "xfail"})
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_LITERAL_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./:=@+-")
# (AG)(1)(4) braced expansions: default-deny. Accept only bare ${NAME} and the
# numeric-offset form ${NAME::digits} / ${NAME:offset:length} that ci.yml uses
# (e.g. ${GITHUB_SHA::12}). Reject @P/@Q/… transforms, :-/:=/:?/:+ defaults,
# #/%// pattern ops, ${!indirection}, ${#length}, and every other transform.
_BRACED_PARAM_RE = re.compile(
    r"\A[A-Za-z_][A-Za-z0-9_]*"
    r"(?:"
    r":[0-9]*:[0-9]+"  # :offset:length, including empty offset (::12)
    r"|"
    r":[0-9]+"  # :offset alone
    r")?\Z"
)

CONDITIONAL_JOBS = {
    "e2e": (
        "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch' || "
        "startsWith(github.ref, 'refs/tags/') || (github.event_name == 'pull_request' && "
        "contains(github.event.pull_request.labels.*.name, 'e2e'))"
    ),
}
CONDITIONAL_STEPS = {
    "images": [(7, "github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')")],
    "e2e": [(7, "failure()")],
}


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _normalize_ws(s: str) -> str:
    return " ".join(str(s).split())



def test_thresholds_yaml_lists_every_benchmark_exactly_once():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    ids = [b["id"] for b in data["benchmarks"]]
    assert set(ids) == EXPECTED_BENCHMARK_IDS
    assert len(ids) == len(set(ids)), "duplicate benchmark id"


def test_checkpoints_yaml_lists_every_checkpoint_exactly_once():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    ids = [c["id"] for c in data["checkpoints"]]
    assert set(ids) == EXPECTED_CHECKPOINT_IDS
    assert len(ids) == len(set(ids)), "duplicate checkpoint id"


def test_checkpoint_inventory_covers_f1_through_f18():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    ids = {c["id"] for c in data["checkpoints"]}
    assert ids == {f"F{i}" for i in range(1, 19)}


def test_every_benchmark_has_a_valid_status_and_owning_milestone():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    for b in data["benchmarks"]:
        assert b["status"] in VALID_STATUSES, b["id"]
        assert b["owning_milestone"].startswith("M"), b["id"]
        if b["status"] != "deferred":
            assert b["tests"], f"{b['id']} is not deferred but has no linked test"


def test_every_checkpoint_has_a_valid_status_and_owning_milestone():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    for c in data["checkpoints"]:
        assert c["status"] in VALID_STATUSES, c["id"]
        assert c["owning_milestone"].startswith("M"), c["id"]
        if c["status"] != "deferred":
            assert c["tests"] or c.get("notes"), (
                f"{c['id']} is not deferred but has no linked test or explanatory notes"
            )


def test_m1_checkpoint_f14_links_to_the_real_m1_functional_test():
    data = _load(REPO_ROOT / "tests" / "functional" / "checkpoints.yaml")
    f14 = next(c for c in data["checkpoints"] if c["id"] == "F14")
    assert f14["owning_milestone"] == "M1"
    assert any("test_m1_foundation.py" in t for t in f14["tests"])


def test_no_deferred_or_partial_entry_for_a_shipped_milestone():
    failures: list[str] = []
    for path, key in [
        (REPO_ROOT / "tests/benchmark/thresholds.yaml", "benchmarks"),
        (REPO_ROOT / "tests/functional/checkpoints.yaml", "checkpoints"),
    ]:
        data = _load(path)
        for entry in data[key]:
            owner = entry.get("owning_milestone")
            status = entry.get("status")
            if owner in SHIPPED_MILESTONES and status in {"deferred", "partial"}:
                failures.append(
                    f"{entry['id']}: owning_milestone={owner} status={status}"
                )
    assert not failures, "shipped-milestone honesty failures:\n" + "\n".join(failures)


def test_notes_do_not_promise_work_for_a_shipped_milestone():
    failures: list[str] = []
    for path, key in [
        (REPO_ROOT / "tests/benchmark/thresholds.yaml", "benchmarks"),
        (REPO_ROOT / "tests/functional/checkpoints.yaml", "checkpoints"),
    ]:
        data = _load(path)
        for entry in data[key]:
            owner = entry.get("owning_milestone")
            if owner not in SHIPPED_MILESTONES:
                continue
            notes = entry.get("notes") or ""
            for sentence in re.split(r"[.;\n]+", notes):
                s = sentence.strip()
                if not s:
                    continue
                if _PHRASE_RE.search(s) and _MILESTONE_RE.search(s):
                    failures.append(f"{entry['id']}: {s!r}")
    assert not failures, "notes promise work for a shipped milestone:\n" + "\n".join(failures)


# ---------------------------------------------------------------------------
# L0 binding enumeration (restated; do not import from B11 guard)
# ---------------------------------------------------------------------------


def _name_targets(tgt: ast.AST) -> list[ast.Name]:
    if isinstance(tgt, ast.Name):
        return [tgt]
    if isinstance(tgt, (ast.Tuple, ast.List)):
        out: list[ast.Name] = []
        for elt in tgt.elts:
            out.extend(_name_targets(elt))
        return out
    if isinstance(tgt, ast.Starred):
        return _name_targets(tgt.value)
    return []


def _binding_occurrences(tree: ast.Module) -> dict[str, list[ast.AST]]:
    """L0 exhaustive: every binding occurrence of every name, every scope."""
    occ: dict[str, list[ast.AST]] = {}

    def add(name: str, node: ast.AST) -> None:
        occ.setdefault(name, []).append(node)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                add(alias.asname or alias.name.split(".")[0], node)
        elif isinstance(node, ast.Assign):
            for tgt in node.targets:
                for n in _name_targets(tgt):
                    add(n.id, node)
        elif isinstance(node, ast.AnnAssign):
            if node.target is not None:
                for n in _name_targets(node.target):
                    add(n.id, node)
        elif isinstance(node, ast.AugAssign):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, ast.NamedExpr):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, ast.comprehension):
            for n in _name_targets(node.target):
                add(n.id, node)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    for n in _name_targets(item.optional_vars):
                        add(n.id, node)
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                add(node.name, node)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            add(node.name, node)
        elif isinstance(node, ast.ClassDef):
            add(node.name, node)
        elif isinstance(node, ast.arguments):
            for arg in [*node.posonlyargs, *node.args, *node.kwonlyargs]:
                add(arg.arg, arg)
            for arg in (node.vararg, node.kwarg):
                if arg is not None:
                    add(arg.arg, arg)
        elif isinstance(node, ast.MatchAs) and node.name:
            add(node.name, node)
        elif isinstance(node, ast.MatchStar) and node.name:
            add(node.name, node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            add(node.rest, node)
        elif isinstance(node, ast.Global):
            for n in node.names:
                add(n, node)
        elif isinstance(node, ast.Nonlocal):
            for n in node.names:
                add(n, node)
        elif isinstance(node, ast.Delete):
            for tgt in node.targets:
                for n in _name_targets(tgt):
                    add(n.id, node)
    return occ


def _file_has_star_import(tree: ast.Module) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                if alias.name == "*":
                    return True
    return False


def _stmt_of(node: ast.AST, parents: dict[int, tuple[ast.AST, str]]) -> ast.AST:
    cur: ast.AST = node
    while not isinstance(cur, ast.stmt):
        info = parents.get(id(cur))
        if info is None:
            return node
        cur = info[0]
    return cur


def _resolve_module_binding(tree: ast.Module, name: str) -> ast.stmt | None:
    """(H): star poison; exactly one occurrence anywhere; must be direct tree.body."""
    if _file_has_star_import(tree):
        return None
    occ = _binding_occurrences(tree)
    nodes = occ.get(name) or []
    if len(nodes) != 1:
        return None
    parents = _build_parent_map(tree)
    holder = _stmt_of(nodes[0], parents)
    if holder not in tree.body:
        return None
    return holder  # type: ignore[return-value]


def _numeric_name_bindings(tree: ast.Module) -> dict[str, ast.AST]:
    result: dict[str, ast.AST] = {}
    for name in _binding_occurrences(tree):
        stmt = _resolve_module_binding(tree, name)
        if stmt is None:
            continue
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            t = stmt.targets[0]
            if isinstance(t, ast.Name):
                result[name] = stmt.value
        elif (
            isinstance(stmt, ast.AnnAssign)
            and isinstance(stmt.target, ast.Name)
            and stmt.value is not None
        ):
            result[name] = stmt.value
    return result


def _resolves_to_pytest(tree: ast.Module, p: str) -> bool:
    stmt = _resolve_module_binding(tree, p)
    if not isinstance(stmt, ast.Import):
        return False
    for a in stmt.names:
        bound = a.asname or a.name.split(".")[0]
        if bound == p and a.name == "pytest":
            return True
    return False


def _resolves_to_pytest_fail(tree: ast.Module, f: str) -> bool:
    stmt = _resolve_module_binding(tree, f)
    if not isinstance(stmt, ast.ImportFrom):
        return False
    if stmt.level != 0 or stmt.module != "pytest":
        return False
    for a in stmt.names:
        if a.name == "fail" and (a.asname or a.name) == f:
            return True
    return False


# ---------------------------------------------------------------------------
# Constant-folding dead-branch predicates
# ---------------------------------------------------------------------------


def _is_constant_true(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_constant_false(node.operand)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return all(_is_constant_true(v) for v in node.values)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return any(_is_constant_true(v) for v in node.values)
    return False


def _is_constant_false(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return not bool(node.value)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return _is_constant_true(node.operand)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
        return any(_is_constant_false(v) for v in node.values)
    if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.Or):
        return all(_is_constant_false(v) for v in node.values)
    return False


def _is_numeric_term(node: ast.AST, bindings: dict[str, ast.AST], depth: int = 0) -> bool:
    if depth > _NUMERIC_DEPTH_CAP:
        return False
    if isinstance(node, ast.Constant):
        return isinstance(node.value, (int, float)) and not isinstance(node.value, bool)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.UAdd, ast.USub)):
        return _is_numeric_term(node.operand, bindings, depth + 1)
    if isinstance(node, ast.BinOp) and isinstance(node.op, _NUMERIC_BINOPS):
        return (
            _is_numeric_term(node.left, bindings, depth + 1)
            and _is_numeric_term(node.right, bindings, depth + 1)
        )
    if isinstance(node, ast.Name) and node.id in bindings:
        return _is_numeric_term(bindings[node.id], bindings, depth + 1)
    return False


def _operand_reasons(
    operands: list[ast.AST],
    bindings: dict[str, ast.AST],
    tree: ast.Module,
    func: ast.AST,
) -> str | None:
    """Row 8/9: both_operands_numeric or the no-numeric three-way split."""
    flags = [_is_numeric_term(op, bindings) for op in operands]
    if all(flags):
        return "both_operands_numeric"
    if any(flags):
        return None  # qualifies on operands
    # row 9: no numeric term
    if _file_has_star_import(tree):
        return "star_import"
    # any bare Name operand bound outside the linked function?
    body_ids = {id(s) for s in tree.body}
    for op in operands:
        if not isinstance(op, ast.Name):
            continue
        name = op.id
        occ = _binding_occurrences(tree).get(name) or []
        for n in occ:
            # binding outside the linked function: direct tree.body member
            # walk up to stmt
            parents = _build_parent_map(tree)
            holder = _stmt_of(n, parents)
            if holder in tree.body:
                return "unresolved_identifier"
    return "no_numeric_term"


def _is_threshold_compare_shape(node: ast.AST) -> bool:
    """Condition (i) only: is an ordering Compare."""
    if not isinstance(node, ast.Compare) or not node.ops:
        return False
    return all(isinstance(op, _ORDERED_OPS) for op in node.ops)


def _stmt_explicitly_fails(stmt: ast.stmt, tree: ast.Module) -> bool:
    if isinstance(stmt, ast.Raise):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        func = stmt.value.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.attr == "fail" and _resolves_to_pytest(tree, func.value.id):
                return True
        if isinstance(func, ast.Name) and _resolves_to_pytest_fail(tree, func.id):
            return True
    return False


def _body_has_explicit_fail(body: list[ast.stmt], tree: ast.Module) -> bool:
    return any(_stmt_explicitly_fails(s, tree) for s in body)


def _build_parent_map(tree: ast.AST) -> dict[int, tuple[ast.AST, str]]:
    parents: dict[int, tuple[ast.AST, str]] = {}
    for parent in ast.walk(tree):
        for field, value in ast.iter_fields(parent):
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        parents[id(item)] = (parent, field)
            elif isinstance(value, ast.AST):
                parents[id(value)] = (parent, field)
    return parents


def _ancestor_chain(node: ast.AST, func: ast.AST, parents: dict) -> list[tuple[ast.AST, str]]:
    chain: list[tuple[ast.AST, str]] = []
    cur: ast.AST = node
    while cur is not func:
        info = parents.get(id(cur))
        if info is None:
            break
        parent, field = info
        chain.append((parent, field))
        cur = parent
    return chain


def _in_nested_scope(node: ast.AST, func: ast.AST, parents: dict) -> bool:
    for parent, _field in _ancestor_chain(node, func, parents):
        if isinstance(parent, _NESTED_SCOPE) and parent is not func:
            return True
    return False


def _in_constantly_dead_branch(node: ast.AST, func: ast.AST, parents: dict) -> bool:
    for parent, field in _ancestor_chain(node, func, parents):
        if isinstance(parent, (ast.If, ast.While)):
            if field == "body" and _is_constant_false(parent.test):
                return True
            if isinstance(parent, ast.If) and field == "orelse" and _is_constant_true(parent.test):
                return True
    return False


def _decorator_final_name(dec: ast.AST) -> str | None:
    cur = dec
    if isinstance(cur, ast.Call):
        cur = cur.func
    if isinstance(cur, ast.Name):
        return cur.id
    if isinstance(cur, ast.Attribute):
        return cur.attr
    return None


def _is_skip_decorator(dec: ast.AST) -> bool:
    return _decorator_final_name(dec) in SKIP_MARKERS


def _pytestmark_opaque(value: ast.AST) -> bool:
    """True when the pytestmark RHS cannot be fully inspected for skip markers.

    (R)(3): a call result or bare name disqualifies conservatively; a plain
    Attribute (e.g. ``pytest.mark.e2e``) or a list/tuple of inspectable
    Attributes is fully inspectable.
    """
    if isinstance(value, ast.Name):
        return True
    if isinstance(value, ast.Call):
        return True
    if isinstance(value, ast.Attribute):
        return False
    if isinstance(value, (ast.List, ast.Tuple)):
        return any(_pytestmark_opaque(elt) for elt in value.elts)
    # Any other form (f-string, binop, …) is opaque.
    return True


def _pytestmark_value_skips(value: ast.AST) -> bool:
    """True if *value* is a skip marker or cannot be fully inspected."""
    for n in ast.walk(value):
        if isinstance(n, ast.Name) and n.id in SKIP_MARKERS:
            return True
        if isinstance(n, ast.Attribute) and n.attr in SKIP_MARKERS:
            return True
    return _pytestmark_opaque(value)


def _module_scope_pytestmark_values(tree: ast.Module) -> list[ast.AST | None]:
    """Collect RHS values for every module-scope ``pytestmark`` binding.

    Module-scope by construction: recurse into the nested statement blocks of
    **every** compound statement reachable at module scope by walking child
    nodes generically (not a fixed per-type container branch list). Nested
    statement containers that are not ``ast.stmt`` themselves — ``ExceptHandler``
    (covers both ``try``/``except`` and ``try``/``except*`` / ``TryStar``),
    ``match_case``, and ``withitem`` — are handled in that generic child walk so
    new compound statement types that hold ordinary statement lists keep working
    without a new hand-listed branch.

    **Excluded** (non-module scopes): bodies of ``FunctionDef`` /
    ``AsyncFunctionDef`` / ``ClassDef`` / ``Lambda``. Their **module-evaluated
    surfaces** are still scanned (decorators, argument defaults / kw_defaults,
    annotations, class bases/keywords, comprehension/generator outer
    expressions).

    **ClassDef exception:** a class-body ``global pytestmark`` reopens the
    module binding for that name; same-name assignments in *that* class scope
    (including nested control flow) are module bindings evaluated at class
    definition time. Ordinary class attributes without ``global``, and bodies
    of nested functions (even with their own ``global pytestmark`` — uncalled
    at import), are still excluded.

    **withitem.optional_vars** is both a binding target (``as pytestmark``) and
    an expression surface (walrus in a subscript/as-target); both are scanned.

    **Wildcard imports** (``from x import *``, ``alias.name == "*"``) are
    default-denied without resolving ``__all__`` or the imported module.

    For every other statement, binding bookkeeping never early-returns past
    the generic expression walk: RHS values, ``AnnAssign.annotation``, and
    evaluated target expressions (``Assign`` / ``AnnAssign`` / ``AugAssign`` /
    ``Delete``) are all scanned for walrus bindings.

    Each entry is either an inspectable RHS expression, or ``None`` when the
    binding shape itself makes the final value unknowable (import, augassign,
    destructure, for target, with-as, except-as, annotation-only, PEP 695
    ``type`` alias, …) — callers treat ``None`` as opaque / default-deny.
    """
    values: list[ast.AST | None] = []

    def note_simple(value: ast.AST | None) -> None:
        values.append(value)

    def note_opaque() -> None:
        values.append(None)

    def bind_from_target(tgt: ast.AST, value: ast.AST | None, *, simple_ok: bool) -> None:
        """Record a binding of ``pytestmark`` via *tgt*.

        When *simple_ok* and *tgt* is a bare ``Name`` (and for Assign, a single
        non-destructuring target), the RHS is inspectable; otherwise opaque.
        """
        names = _name_targets(tgt)
        if not any(n.id == "pytestmark" for n in names):
            return
        if simple_ok and isinstance(tgt, ast.Name) and tgt.id == "pytestmark" and value is not None:
            note_simple(value)
        else:
            note_opaque()

    def note_match_pattern_bindings(pattern: ast.AST) -> None:
        # match patterns can bind names — treat pytestmark binds as opaque
        for n in ast.walk(pattern):
            if isinstance(n, ast.MatchAs) and n.name == "pytestmark":
                note_opaque()
            if isinstance(n, ast.MatchStar) and n.name == "pytestmark":
                note_opaque()
            if isinstance(n, ast.MatchMapping) and n.rest == "pytestmark":
                note_opaque()

    def visit_arguments(args: ast.arguments) -> None:
        """Scan module-evaluated argument defaults and annotations only."""
        for d in args.defaults:
            visit_expr(d)
        for d in args.kw_defaults:
            visit_expr(d)
        for arg in (*args.posonlyargs, *args.args, *args.kwonlyargs):
            visit_expr(arg.annotation)
        if args.vararg is not None:
            visit_expr(args.vararg.annotation)
        if args.kwarg is not None:
            visit_expr(args.kwarg.annotation)

    def visit_comprehension_like(
        elt_or_key_value: tuple[ast.AST, ...] | tuple[ast.AST, ast.AST],
        generators: list[ast.comprehension],
    ) -> None:
        """Comprehension/genexp: targets are local; elt/iters/ifs are outer."""
        for part in elt_or_key_value:
            visit_expr(part)
        for gen in generators:
            visit_expr(gen.iter)
            for if_ in gen.ifs:
                visit_expr(if_)

    def visit_expr(node: ast.AST | None) -> None:
        """Walk expressions for walrus bindings; skip nested function bodies."""
        if node is None:
            return
        if isinstance(node, ast.Lambda):
            # Defaults evaluate at definition time in the enclosing scope;
            # the lambda body does not.
            visit_arguments(node.args)
            return
        if isinstance(node, ast.GeneratorExp):
            visit_comprehension_like((node.elt,), node.generators)
            return
        if isinstance(node, (ast.ListComp, ast.SetComp)):
            visit_comprehension_like((node.elt,), node.generators)
            return
        if isinstance(node, ast.DictComp):
            visit_comprehension_like((node.key, node.value), node.generators)
            return
        if isinstance(node, ast.NamedExpr):
            bind_from_target(node.target, node.value, simple_ok=True)
            visit_expr(node.value)
            return
        for child in ast.iter_child_nodes(node):
            visit_expr(child)

    def visit_stmts(stmts: list[ast.stmt]) -> None:
        for stmt in stmts:
            visit_stmt(stmt)

    def _class_scope_declares_global_pytestmark(stmts: list[ast.stmt]) -> bool:
        """True if this class scope has ``global pytestmark`` (not nested def/class)."""
        stack: list[ast.AST] = list(stmts)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.Global) and "pytestmark" in node.names:
                return True
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                # Nested scopes own their own global declarations.
                continue
            if isinstance(node, ast.ExceptHandler):
                stack.extend(node.body)
                continue
            if isinstance(node, ast.match_case):
                stack.extend(node.body)
                continue
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                    stack.append(child)
        return False

    def _visit_nested_classdefs_only(stmts: list[ast.stmt]) -> None:
        """Without class-scope global, only nested ClassDef may reopen module binds."""
        stack: list[ast.AST] = list(stmts)
        while stack:
            node = stack.pop()
            if isinstance(node, ast.ClassDef):
                visit_stmt(node)
                continue
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.ExceptHandler):
                stack.extend(node.body)
                continue
            if isinstance(node, ast.match_case):
                stack.extend(node.body)
                continue
            if isinstance(node, ast.stmt):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.stmt, ast.ExceptHandler, ast.match_case)):
                        stack.append(child)

    def visit_module_child(node: ast.AST) -> None:
        """Generic module-scope descent for one AST child of a compound stmt.

        Statement nodes recurse via ``visit_stmt``. Statement-containing
        non-stmt containers (``ExceptHandler``, ``match_case``, ``withitem``)
        expose their nested statement blocks here so ``Try`` / ``TryStar`` /
        ``Match`` / ``With`` need no per-type body branches. Everything else
        is an expression surface (walrus, etc.).
        """
        if isinstance(node, ast.stmt):
            visit_stmt(node)
            return
        if isinstance(node, ast.ExceptHandler):
            # Shared by ast.Try and ast.TryStar (except*); name is a string bind.
            if node.name == "pytestmark":
                note_opaque()
            visit_expr(node.type)
            visit_stmts(node.body)
            return
        if isinstance(node, ast.match_case):
            note_match_pattern_bindings(node.pattern)
            visit_expr(node.guard)
            visit_stmts(node.body)
            return
        if isinstance(node, ast.withitem):
            visit_expr(node.context_expr)
            if node.optional_vars is not None:
                # Binding target (``as pytestmark`` / destructure) — opaque.
                bind_from_target(node.optional_vars, None, simple_ok=False)
                # Expression surface too: walrus in as-target subscripts etc.
                # (e.g. ``as d[0 if (pytestmark := …) else 0]``).
                visit_expr(node.optional_vars)
            return
        visit_expr(node)

    def visit_stmt(stmt: ast.stmt) -> None:
        # ---- Non-module scopes: surfaces only, never bodies ----
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Nested scope: the def name is module-scoped, but the body is not.
            # Decorators, defaults, and annotations *are* evaluated at def time
            # in the enclosing (module) scope — scan those without entering body.
            # An uncalled nested def with ``global pytestmark`` does NOT bind
            # at import time; its body is never entered here.
            if stmt.name == "pytestmark":
                note_opaque()
            for dec in stmt.decorator_list:
                visit_expr(dec)
            visit_arguments(stmt.args)
            visit_expr(stmt.returns)
            return
        if isinstance(stmt, ast.ClassDef):
            # Class body is normally a nested scope; bases/keywords/decorators
            # are module-evaluated. Exception: class-body ``global pytestmark``
            # makes same-name assignments in *this* class scope module bindings
            # (executed at class definition / import time).
            if stmt.name == "pytestmark":
                note_opaque()
            for dec in stmt.decorator_list:
                visit_expr(dec)
            for base in stmt.bases:
                visit_expr(base)
            for kw in stmt.keywords:
                visit_expr(kw.value)
            if _class_scope_declares_global_pytestmark(stmt.body):
                # Re-enter as module-like for this class scope only. Nested
                # FunctionDef still excludes its body (uncalled at import);
                # nested ClassDef re-checks its own global.
                visit_stmts(stmt.body)
            else:
                # Ordinary class attrs (pytestmark without global) stay local.
                # Nested classes may still declare global pytestmark.
                _visit_nested_classdefs_only(stmt.body)
            return

        # ---- Binding forms at this statement (not driven by child walk) ----
        # Binding bookkeeping must NEVER early-return for Assign / AnnAssign /
        # AugAssign / Delete: after noting the bind, fall through so the generic
        # child walk visits EVERY module-evaluated expression surface — RHS
        # value, AnnAssign.annotation, and evaluated target expressions
        # (e.g. subscript/walrus in ``d[(pytestmark:=...)] = 1``). Only Import
        # and Global/Nonlocal (no expression children) and FunctionDef /
        # ClassDef (body exclusion, surfaces already scanned) return early.
        if isinstance(stmt, (ast.Import, ast.ImportFrom)):
            for alias in stmt.names:
                # Default-deny star imports: may rebind pytestmark via __all__
                # without resolving the imported module.
                if alias.name == "*":
                    note_opaque()
                    continue
                bound = alias.asname or alias.name.split(".")[0]
                if bound == "pytestmark":
                    note_opaque()
            return
        if isinstance(stmt, ast.Assign):
            # Multi-target chain ``a = b = x`` shares one RHS; destructure is opaque.
            for tgt in stmt.targets:
                names = _name_targets(tgt)
                if not any(n.id == "pytestmark" for n in names):
                    continue
                if isinstance(tgt, ast.Name) and tgt.id == "pytestmark":
                    note_simple(stmt.value)
                else:
                    note_opaque()
            # Fall through: value + evaluated targets (subscript/walrus).
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and stmt.target.id == "pytestmark":
                if stmt.value is not None:
                    note_simple(stmt.value)
                else:
                    note_opaque()  # annotation-only: value unknown
            elif any(n.id == "pytestmark" for n in _name_targets(stmt.target)):
                note_opaque()
            # Fall through: annotation + value + evaluated target.
        elif isinstance(stmt, ast.AugAssign):
            if any(n.id == "pytestmark" for n in _name_targets(stmt.target)):
                note_opaque()
            # Fall through: value + evaluated target.
        elif isinstance(stmt, ast.Delete):
            for tgt in stmt.targets:
                if any(n.id == "pytestmark" for n in _name_targets(tgt)):
                    note_opaque()
            # Fall through: evaluated target expressions (subscript/walrus).
        elif isinstance(stmt, (ast.Global, ast.Nonlocal)):
            if "pytestmark" in stmt.names:
                note_opaque()
            return
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            # For/AsyncFor loop targets bind in the enclosing scope. The target
            # is an expression node, so the generic child walk would not record
            # it as a binding — note it here, then fall through to descent.
            bind_from_target(stmt.target, None, simple_ok=False)
        elif isinstance(stmt, ast.TypeAlias):
            # PEP 695 ``type Name = …`` binds *name* at this scope (module, or
            # class-with-global-pytestmark). The value is a type expression /
            # type-alias object, never a pytest Mark — real pytest aborts
            # collection with TypeError if pytestmark is a TypeAlias. Always
            # opaque; do not interpret the value as a marker. Fall through so
            # value / type_params are scanned for walrus like other surfaces.
            bind_from_target(stmt.name, None, simple_ok=False)

        # ---- Generic compound descent (any depth, no per-type body list) ----
        # if/for/while/with/try/try*/match/assert/expr/assign/annassign/… :
        # walk every child. Nested stmt lists and ExceptHandler/match_case/
        # withitem bodies are reached via visit_module_child;
        # FunctionDef/ClassDef/Lambda bodies stay excluded by the early
        # returns above and visit_expr's Lambda.
        for child in ast.iter_child_nodes(stmt):
            visit_module_child(child)

    visit_stmts(tree.body)
    return values


def _pytestmark_skips(tree: ast.Module) -> bool:
    """True if any module-scope ``pytestmark`` binding skips the module.

    Scan **every** module-scope binding (pytest rebinds win): a later
    ``pytestmark = pytest.mark.skip`` after a non-skip marker still skips,
    including bindings nested in module-level control flow. Opaque RHS or
    unknowable binding shape → conservative True. Fully inspectable non-skip
    bindings do not short-circuit the scan.
    """
    for value in _module_scope_pytestmark_values(tree):
        if value is None:
            return True  # unknowable shape → default-deny
        if _pytestmark_value_skips(value):
            return True
        # Inspectable non-skip binding — keep scanning for a later rebind.
    return False


def _is_block_exit(stmt: ast.stmt, tree: ast.Module) -> bool:
    if isinstance(stmt, (ast.Return, ast.Raise, ast.Continue, ast.Break)):
        return True
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
        func = stmt.value.func
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            if func.attr in {"skip", "xfail", "exit"} and _resolves_to_pytest(tree, func.value.id):
                return True
        if isinstance(func, ast.Name):
            # bare skip/xfail/exit from from pytest import ...
            for name in ("skip", "xfail", "exit"):
                if func.id == name or True:
                    stmt_b = _resolve_module_binding(tree, func.id)
                    if (
                        isinstance(stmt_b, ast.ImportFrom)
                        and stmt_b.level == 0
                        and stmt_b.module == "pytest"
                    ):
                        for a in stmt_b.names:
                            if a.name in {"skip", "xfail", "exit"} and (a.asname or a.name) == func.id:
                                return True
                    break
    return False


def _candidate_is_dead(node: ast.AST, func: ast.AST, parents: dict, tree: ast.Module) -> bool:
    """(R)(1): preceded by unconditional block exit at any ancestor list level."""
    # Build statement-list membership
    cur: ast.AST = node
    while cur is not func:
        info = parents.get(id(cur))
        if info is None:
            return False
        parent, field = info
        # if cur is a stmt in a list on parent
        if isinstance(cur, ast.stmt):
            lst = getattr(parent, field, None) if isinstance(field, str) else None
            if isinstance(lst, list) and cur in lst:
                idx = lst.index(cur)
                for earlier in lst[:idx]:
                    if isinstance(earlier, ast.stmt) and _is_block_exit(earlier, tree):
                        return True
        cur = parent
    return False


def _failure_type_of_candidate(node: ast.AST, tree: ast.Module) -> str | None:
    """Return failure type name, or None for unknown (any handler disqualifies)."""
    if isinstance(node, ast.Assert):
        return "AssertionError"
    if isinstance(node, ast.If):
        for s in node.body:
            if isinstance(s, ast.Raise):
                if s.exc is None:
                    return None  # bare raise → unknown
                exc = s.exc
                if isinstance(exc, ast.Call):
                    exc = exc.func
                if isinstance(exc, ast.Name):
                    return exc.id
                if isinstance(exc, ast.Attribute):
                    return exc.attr
                return None
            if isinstance(s, ast.Expr) and isinstance(s.value, ast.Call):
                func = s.value.func
                if isinstance(func, ast.Attribute) and func.attr == "fail":
                    return "BaseException"  # pytest.Failed
                if isinstance(func, ast.Name) and _resolves_to_pytest_fail(tree, func.id):
                    return "BaseException"
    return "AssertionError"


def _handler_can_catch(handler: ast.ExceptHandler, fail_type: str | None, tree: ast.Module) -> bool:
    if handler.type is None:
        return True
    def final_name(t: ast.AST) -> str | None:
        if isinstance(t, ast.Name):
            return t.id
        if isinstance(t, ast.Attribute):
            return t.attr
        return None

    def one_catches(t: ast.AST) -> bool:
        if isinstance(t, ast.Tuple):
            return any(one_catches(e) for e in t.elts)
        name = final_name(t)
        if name is None:
            return True  # unclassifiable
        if name == "BaseException":
            return True
        if name == "Exception":
            return fail_type != "BaseException"
        if fail_type is None:
            return True
        if name == fail_type:
            return True
        # Name with a binding occurrence → unclassifiable alias
        if isinstance(t, ast.Name):
            occ = _binding_occurrences(tree).get(t.id) or []
            if occ:
                return True
        return False

    return one_catches(handler.type)


def _handler_reraises(handler: ast.ExceptHandler) -> bool:
    if not handler.body:
        return False
    return isinstance(handler.body[-1], ast.Raise)


def _candidate_failure_is_swallowed(
    node: ast.AST, func: ast.AST, parents: dict, tree: ast.Module
) -> bool:
    # (R)(2) try handlers
    fail_type = _failure_type_of_candidate(node, tree)
    for parent, field in _ancestor_chain(node, func, parents):
        if isinstance(parent, (ast.Try, getattr(ast, "TryStar", ast.Try))):
            if field != "body":
                continue
            for h in parent.handlers:
                if _handler_can_catch(h, fail_type, tree) and not _handler_reraises(h):
                    return True
        # (R)(2b) suppressing with
        if isinstance(parent, (ast.With, ast.AsyncWith)) and field == "body":
            for item in parent.items:
                expr = item.context_expr
                if isinstance(expr, ast.Call):
                    fn = expr.func
                    final = None
                    if isinstance(fn, ast.Name):
                        final = fn.id
                    elif isinstance(fn, ast.Attribute):
                        final = fn.attr
                    if final in SUPPRESSOR_CM:
                        return True
    return False


def _python_basename_collected(path: Path) -> bool:
    name = path.name
    return (name.startswith("test_") and name.endswith(".py")) or name.endswith("_test.py")


def _python_test_asserts_threshold(
    src: str, name: str, *, path: Path | None = None
) -> tuple[bool, str | None]:
    """Return (ok, reason_or_None) with exact threshold vocabulary tokens."""
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return False, "nonexistent_linked_test"
    if not isinstance(tree, ast.Module):
        return False, "nonexistent_linked_test"

    if path is not None and not _python_basename_collected(path):
        return False, "not_collected"

    # (M) identity over Module.body only
    matches = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    ]
    if not matches:
        return False, "nonexistent_linked_test"
    if len(matches) > 1:
        return False, "ambiguous_test_name"
    func = matches[0]

    # (M) python_functions default test*
    if not name.startswith("test"):
        return False, "not_collected"

    # (R)(3) skipped
    if any(_is_skip_decorator(d) for d in func.decorator_list):
        return False, "skipped"
    if _pytestmark_skips(tree):
        # Module-scope ``from x import *`` is pytestmark-opaque (walker) *and*
        # poisons numeric-name resolution (H). Prefer the dedicated
        # ``star_import`` vocabulary token so the pinned (H) fixture keeps its
        # reason; the pytestmark default-deny still holds via the walker.
        if _file_has_star_import(tree):
            return False, "star_import"
        return False, "skipped"

    bindings = _numeric_name_bindings(tree)
    parents = _build_parent_map(tree)

    # candidates: Assert/If under func, not in nested scope (AB: dead branch IS candidate)
    candidates: list[ast.AST] = []
    for node in ast.walk(func):
        if not isinstance(node, (ast.Assert, ast.If)):
            continue
        if _in_nested_scope(node, func, parents):
            continue
        candidates.append(node)

    # source order
    candidates.sort(key=lambda n: getattr(n, "lineno", 0) or 0)

    if not candidates:
        return False, "no_candidate"

    first_reason: str | None = None
    for cand in candidates:
        reason = _evaluate_candidate(cand, func, parents, tree, bindings)
        if reason is None:
            return True, None
        if first_reason is None:
            first_reason = reason
    return False, first_reason


def _evaluate_candidate(
    cand: ast.AST,
    func: ast.AST,
    parents: dict,
    tree: ast.Module,
    bindings: dict[str, ast.AST],
) -> str | None:
    """Return None if qualifies, else first failing reason in (W)(3) order."""
    # 1 dead_candidate
    if _candidate_is_dead(cand, func, parents, tree):
        return "dead_candidate"
    # 1a constantly dead branch
    if _in_constantly_dead_branch(cand, func, parents):
        return "not_a_threshold_comparison"
    # 2 swallowed
    if _candidate_failure_is_swallowed(cand, func, parents, tree):
        return "swallowed_candidate"
    # 3 form
    if isinstance(cand, ast.Assert):
        test = cand.test
        if not _is_threshold_compare_shape(test):
            return "not_a_threshold_comparison"
        operands: list[ast.AST] = [test.left, *test.comparators]
        op_reason = _operand_reasons(operands, bindings, tree, func)
        if op_reason is not None:
            return op_reason
        return None
    else:
        assert isinstance(cand, ast.If)
        test = cand.test
        if not _is_threshold_compare_shape(test):
            return "not_a_threshold_comparison"
        # 5 fail branch
        if not _body_has_explicit_fail(cand.body, tree):
            return "no_fail_in_branch"
        operands = [test.left, *test.comparators]
        op_reason = _operand_reasons(operands, bindings, tree, func)
        if op_reason is not None:
            return op_reason
        return None


def _go_guard_present(root: Path = REPO_ROOT) -> bool:
    guard = root / GO_GUARD
    if not guard.is_file():
        return False
    return GO_GUARD_FUNC in guard.read_text(encoding="utf-8")


def _resolve_test_file(link: str, root: Path = REPO_ROOT) -> Path | None:
    path_part = link.split("::", 1)[0].strip()
    if not path_part:
        return None
    candidate = root / path_part
    if candidate.is_file():
        return candidate
    return None


def _link_test_name(link: str) -> str | None:
    if "::" not in link:
        return None
    name = link.split("::", 1)[1].strip()
    return name.split(".")[-1] if name else None


def _link_names_benchmark(link: str, bench_id: str) -> bool:
    lower = link.lower()
    bid = bench_id.lower()
    if "::" in link:
        name = link.split("::", 1)[1].lower()
        if bid in name or f"test_{bid}" in name or f"test{bid}" in name:
            return True
    return f"test_{bid}" in lower or f"bench_{bid}" in lower or f"/{bid.lower()}_" in lower


def _link_asserts_threshold(link: str, root: Path = REPO_ROOT) -> tuple[bool, str | None]:
    path = _resolve_test_file(link, root)
    if path is None:
        return False, "missing_file"
    test_name = _link_test_name(link)
    if test_name is None:
        return False, "nonexistent_linked_test"
    suffix = path.suffix.lower()
    if suffix == ".py":
        src = path.read_text(encoding="utf-8")
        return _python_test_asserts_threshold(src, test_name, path=path)
    if suffix == ".go":
        if not _go_guard_present(root):
            return False, "missing_go_guard"
        return True, None
    return False, "unknown_suffix"


def _entry_link_failures(entry: dict, root: Path = REPO_ROOT) -> list[str]:
    failures: list[str] = []
    bid = entry["id"]
    links = entry.get("tests") or []
    if not links:
        failures.append(f"{bid}: covered but tests list empty")
        return failures
    named = [lnk for lnk in links if _link_names_benchmark(lnk, bid)]
    if not named:
        failures.append(
            f"{bid}: covered but no linked test names the benchmark id; links={links}"
        )
        return failures
    checked = 0
    for lnk in named:
        checked += 1
        ok, reason = _link_asserts_threshold(lnk, root)
        if reason:
            failures.append(f"{bid}: {lnk}: {reason}")
        elif not ok:
            failures.append(f"{bid}: {lnk}: no qualifying threshold assertion")
    assert checked == len(named), "early exit in link loop"
    return failures


def test_covered_benchmarks_link_to_threshold_asserting_tests():
    data = _load(REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml")
    failures: list[str] = []
    for b in data["benchmarks"]:
        if b["status"] != "covered":
            continue
        failures.extend(_entry_link_failures(b, REPO_ROOT))
    assert not failures, "\n".join(failures)


# ---------------------------------------------------------------------------
# Shell grammar (AG) + CI pin machinery
# ---------------------------------------------------------------------------


@dataclass
class Word:
    literal_value: str
    literal_prefix: str
    is_dynamic: bool
    raw_text: str = ""


@dataclass
class SimpleCommand:
    assignments: list[Word] = field(default_factory=list)
    command_word: Word | None = None
    args: list[Word] = field(default_factory=list)
    redirections: list[tuple[str, Word]] = field(default_factory=list)


def _delete_continuations(s: str) -> str:
    return s.replace("\\\n", "")


def _shell_words(script: str) -> list[Word] | None:
    """(AG)(1) closed grammar. Returns None → run_not_recognized."""
    s = _delete_continuations(script)
    words: list[Word] = []
    i = 0
    n = len(s)
    state = "unquoted"  # unquoted | single | double

    def fail():
        return None

    while i < n:
        # skip unquoted whitespace / newlines (separators handled as ops)
        if state == "unquoted" and s[i] in " \t":
            i += 1
            continue
        # comment
        if state == "unquoted" and s[i] == "#":
            # start of word?
            if i == 0 or s[i - 1] in " \t\n":
                while i < n and s[i] != "\n":
                    i += 1
                continue
            return fail()
        # operators in unquoted
        if state == "unquoted":
            # refused ops first: ||, <<, <<<, & variants etc.
            if s.startswith("||", i):
                return fail()  # (AK)(3) refuse ||
            if s.startswith("&&", i):
                words.append(Word("&&", "&&", False, "&&"))
                i += 2
                continue
            if s.startswith(">>", i):
                words.append(Word(">>", ">>", False, ">>"))
                i += 2
                continue
            if s[i] in ";|\n>":
                ch = s[i]
                words.append(Word(ch, ch, False, ch))
                i += 1
                continue
            # refused single chars / multi
            if s[i] in "&(){}[]<>`!*?~,":
                return fail()
            if s.startswith("<<", i):
                return fail()

        # start a word
        lit_parts: list[str] = []
        lit_prefix_parts: list[str] = []
        raw_parts: list[str] = []
        is_dynamic = False
        prefix_closed = False

        while i < n:
            c = s[i]
            if state == "unquoted":
                if c in " \t":
                    break
                if c in ";|\n" or s.startswith("&&", i) or s.startswith("||", i) or s.startswith(">>", i):
                    break
                if c in "&(){}[]<>`!*?~,":
                    return fail()
                if c == "#":
                    return fail()
                if c == "'":
                    raw_parts.append(c)
                    i += 1
                    state = "single"
                    continue
                if c == '"':
                    raw_parts.append(c)
                    i += 1
                    state = "double"
                    continue
                if c == "$":
                    # expansions
                    dyn, ni, raw = _parse_dollar(s, i)
                    if dyn is None:
                        return fail()
                    is_dynamic = True
                    prefix_closed = True
                    raw_parts.append(raw)
                    i = ni
                    continue
                if c == "\\":
                    return fail()  # backslash not after continuation deletion
                if c not in _LITERAL_OK:
                    return fail()
                lit_parts.append(c)
                if not prefix_closed:
                    lit_prefix_parts.append(c)
                raw_parts.append(c)
                i += 1
                continue
            if state == "single":
                if c == "'":
                    raw_parts.append(c)
                    i += 1
                    state = "unquoted"
                    continue
                lit_parts.append(c)
                if not prefix_closed:
                    lit_prefix_parts.append(c)
                raw_parts.append(c)
                i += 1
                continue
            if state == "double":
                if c == '"':
                    raw_parts.append(c)
                    i += 1
                    state = "unquoted"
                    continue
                if c in "`\\":
                    return fail()
                if c == "$":
                    dyn, ni, raw = _parse_dollar(s, i)
                    if dyn is None:
                        return fail()
                    is_dynamic = True
                    prefix_closed = True
                    raw_parts.append(raw)
                    i = ni
                    continue
                lit_parts.append(c)
                if not prefix_closed:
                    lit_prefix_parts.append(c)
                raw_parts.append(c)
                i += 1
                continue
        if state != "unquoted":
            return fail()
        lit = "".join(lit_parts)
        pref = "".join(lit_prefix_parts)
        raw = "".join(raw_parts)
        if not raw:
            continue
        # whitespace in literal value refused
        if any(ch.isspace() for ch in lit):
            return fail()
        words.append(Word(lit, pref, is_dynamic, raw))
    if state != "unquoted":
        return fail()
    return words


def _parse_dollar(s: str, i: int) -> tuple[bool | None, int, str]:
    """Return (ok_dynamic, new_index, raw). ok_dynamic False-ish as None on fail."""
    assert s[i] == "$"
    n = len(s)
    if i + 1 >= n:
        return None, i, ""
    nxt = s[i + 1]
    # ANSI-C / special refused
    if nxt in "'\"0123456789@*?#!$-":
        return None, i, ""
    if nxt == "{":
        # ${ ... } balanced, no $ ` ( ); content default-deny (review C1).
        j = i + 2
        depth = 1
        while j < n and depth:
            c = s[j]
            if c in "$`()":
                return None, i, ""
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
            j += 1
        if depth:
            return None, i, ""
        # Content between the outer braces (excludes the closing `}`).
        content = s[i + 2 : j - 1]
        # Only bare ${NAME} and numeric offset/length forms used by ci.yml.
        # Rejects @P (prompt expansion / command execution), :-/:=/:?/:+,
        # #/%// pattern ops, ${!x} indirection, ${#x} length, nested braces.
        if not _BRACED_PARAM_RE.fullmatch(content):
            return None, i, ""
        return True, j, s[i:j]
    if nxt == "(":
        # $( ... ) recursive: full closed parser, fail closed (AG)(1)(4) / review C1
        j = i + 2
        depth = 1
        while j < n and depth:
            c = s[j]
            if c == "(":
                depth += 1
            elif c == ")":
                depth -= 1
            j += 1
        if depth:
            return None, i, ""
        inner = s[i + 2 : j - 1]
        # Recursively apply the full closed parser (words + command-word allowlist
        # + operand grammar). Inner parse failure propagates as outer refusal.
        if _parse_run(inner) is None:
            return None, i, ""
        return True, j, s[i:j]
    # $NAME
    if nxt.isalpha() or nxt == "_":
        j = i + 2
        while j < n and (s[j].isalnum() or s[j] == "_"):
            j += 1
        return True, j, s[i:j]
    return None, i, ""


def _split_simple_commands(words: list[Word]) -> list[SimpleCommand] | None:
    """Split on ; && | newline. Refuse bad redirections."""
    seps = {";", "&&", "|", "\n"}
    ops_redir = {">", ">>"}
    commands: list[SimpleCommand] = []
    cur: list[Word] = []

    def flush(seq: list[Word]) -> SimpleCommand | None:
        if not seq:
            return SimpleCommand()  # empty discarded later
        cmd = SimpleCommand()
        i = 0
        # leading assignments
        while i < len(seq) and _ASSIGN_RE.match(seq[i].literal_prefix or seq[i].literal_value):
            # assignment words use literal prefix matching
            if not _ASSIGN_RE.match(seq[i].literal_prefix):
                break
            cmd.assignments.append(seq[i])
            i += 1
        if i >= len(seq):
            return cmd  # assignment-only
        # optional: redirection before command is refused
        if seq[i].literal_value in ops_redir:
            return None
        cmd.command_word = seq[i]
        i += 1
        while i < len(seq):
            if seq[i].literal_value in ops_redir:
                if i + 1 >= len(seq):
                    return None
                cmd.redirections.append((seq[i].literal_value, seq[i + 1]))
                i += 2
                continue
            cmd.args.append(seq[i])
            i += 1
        return cmd

    for w in words:
        if w.literal_value in seps and not w.is_dynamic:
            c = flush(cur)
            if c is None:
                return None
            if c.command_word is not None or c.assignments:
                commands.append(c)
            cur = []
        else:
            cur.append(w)
    c = flush(cur)
    if c is None:
        return None
    if c.command_word is not None or c.assignments:
        commands.append(c)
    return commands


def _parse_run(script: str) -> list[SimpleCommand] | None:
    words = _shell_words(script)
    if words is None:
        return None
    cmds = _split_simple_commands(words)
    if cmds is None:
        return None
    # validate command words
    for cmd in cmds:
        if cmd.command_word is None:
            continue
        cw = cmd.command_word
        if cw.is_dynamic:
            return None
        if cw.literal_value not in RUN_COMMAND_WORDS:
            return None
        for a in cmd.args:
            if a.literal_value == "go":
                return None
        for _op, tgt in cmd.redirections:
            if tgt.literal_value == "go":
                return None
    return cmds


def _flag_name(word: Word) -> str | None:
    pref = word.literal_prefix
    if not pref.startswith("-"):
        return None
    t = pref.lstrip("-")
    if "=" in t:
        t = t.split("=", 1)[0]
    return t or None


def _inline_assign_name(word: Word) -> str | None:
    pref = word.literal_prefix
    m = _ASSIGN_RE.match(pref)
    if not m:
        return None
    return pref.split("=", 1)[0]


def _is_go_test_cmd(cmd: SimpleCommand) -> bool:
    if cmd.command_word is None:
        return False
    if cmd.command_word.literal_value != "go":
        return False
    if not cmd.args:
        return False
    return cmd.args[0].literal_value == "test" and not cmd.args[0].is_dynamic


def _is_pytest_cmd(cmd: SimpleCommand) -> bool:
    if cmd.command_word is None:
        return False
    base = cmd.command_word.literal_value.rsplit("/", 1)[-1]
    if base == "pytest":
        return True
    for a in cmd.args:
        if a.literal_value == "pytest":
            return True
    return False


def _norm_cmd(cmd: SimpleCommand) -> str:
    parts: list[str] = []
    if cmd.command_word:
        parts.append(cmd.command_word.raw_text or cmd.command_word.literal_value)
    for a in cmd.args:
        parts.append(a.raw_text or a.literal_value)
    # Prefer literal values for pin equality (design: words raw texts)
    # Use literal_value with original spacing intent: join single spaces
    parts2: list[str] = []
    if cmd.command_word:
        parts2.append(cmd.command_word.literal_value)
    for a in cmd.args:
        parts2.append(a.literal_value)
    return " ".join(parts2)


def _option_word(w: Word) -> bool:
    return w.literal_prefix.startswith("-")


def _basename(w: Word) -> str:
    v = w.literal_value
    return v.rsplit("/", 1)[-1]


def _check_operands(cmd: SimpleCommand) -> bool:
    """(AL)(2). True if ok."""
    if cmd.command_word is None:
        return True
    cw = cmd.command_word.literal_value
    args = cmd.args
    if cw == "go":
        if not args:
            return False
        if args[0].is_dynamic:
            return False
        first = args[0].literal_value
        if first not in {"test", "install", "env", "vet"}:
            return False
        if first == "env":
            if [a.literal_value for a in args] != ["env", "GOPATH"]:
                return False
            if any(a.is_dynamic or _option_word(a) for a in args):
                return False
            return True
        if first == "vet":
            if [a.literal_value for a in args] != ["vet", "./..."]:
                return False
            if any(a.is_dynamic for a in args):
                return False
            return True
        if first == "install":
            if len(args) != 2:
                return False
            if args[1].is_dynamic or _option_word(args[1]):
                return False
            if args[1].literal_value not in GO_INSTALL_TARGETS:
                return False
            for a in args:
                base = _basename(a).split("@", 1)[0]
                if base in {"go", "python", "python3", "pytest"}:
                    return False
            return True
        # test: closed by EXPECTED_GO_TEST_COMMANDS later; operands free here
        return True
    if cw == "bash":
        if not args:
            return False
        if any(_option_word(a) for a in args):
            return False
        if args[0].is_dynamic or args[0].literal_value not in BASH_SCRIPTS:
            return False
        return True
    if cw in {"python", ".venv/bin/python", "services/worker/.venv/bin/python"}:
        if len(args) < 2:
            return False
        if args[0].is_dynamic or args[0].literal_value != "-m":
            return False
        if args[1].is_dynamic or args[1].literal_value not in PYTHON_MODULES:
            return False
        if any(a.literal_value == "-c" for a in args):
            return False
        return True
    if cw == "npm":
        if len(args) != 1 or args[0].is_dynamic:
            return False
        return args[0].literal_value in {"ci", "test"}
    if cw == "set":
        return [a.literal_value for a in args] == ["-euo", "pipefail"]
    if cw == "source":
        return len(args) == 1 and not args[0].is_dynamic and args[0].literal_value == "deploy/versions.env"
    if cw == "export":
        if not args:
            return False
        return all(_ASSIGN_RE.match(a.literal_prefix) for a in args)
    if cw == "echo":
        return True
    if cw == "curl":
        return all((not _option_word(a)) or a.literal_value in {"-fsSL", "-o", "-O"} for a in args)
    if cw == "tar":
        return all((not _option_word(a)) or a.literal_value in {"-xzf", "-xz", "-C"} for a in args)
    if cw == "sudo":
        if not args or any(_option_word(a) for a in args):
            return False
        if args[0].is_dynamic or args[0].literal_value not in SUDO_NESTED_COMMANDS:
            return False
        # nested mv
        nested = SimpleCommand(command_word=args[0], args=list(args[1:]))
        return _check_operands(nested)
    if cw == "mv":
        if len(args) != 2:
            return False
        if any(a.is_dynamic or _option_word(a) for a in args):
            return False
        for a in args:
            if _basename(a) in {"go", "python", "python3", "pytest"}:
                return False
        return True
    if cw == "chmod":
        if not args:
            return False
        if any(a.is_dynamic or _option_word(a) for a in args):
            return False
        return True
    if cw == "helm":
        if not args or args[0].is_dynamic:
            return False
        if args[0].literal_value not in {"version"}:
            return False
        if any(a.literal_value.startswith("--") for a in args):
            return False
        return True
    if cw.endswith("/pip") or cw in {
        ".venv/bin/pip",
        "services/worker/.venv/bin/pip",
        "services/gateway/.venv/bin/pip",
        "services/dashboard-api/.venv/bin/pip",
    }:
        if len(args) < 2:
            return False
        if args[0].is_dynamic or args[0].literal_value != "install":
            return False
        for a in args:
            if _option_word(a) and a.literal_value not in {"--upgrade", "-e"}:
                return False
            if not _option_word(a) and a is not args[0]:
                if a.is_dynamic or a.literal_value.startswith("/") or "://" in a.literal_value:
                    return False
        return True
    return False


def _go_mod_version(root: Path) -> str | None:
    text = (root / "go.mod").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("go "):
            return line.split()[1]
    return None


def _go_mod_toolchain(root: Path) -> str | None:
    text = (root / "go.mod").read_text(encoding="utf-8")
    for line in text.splitlines():
        if line.startswith("toolchain "):
            return line.split()[1].removeprefix("go")
    return None


def _env_keys(mapping) -> list[str]:
    if not mapping or not isinstance(mapping, dict):
        return []
    return list(mapping.keys())


def _is_forbidden_go_env_key(k: str) -> bool:
    return k.startswith("GO") or k.startswith("CGO") or k in GO_TOOLCHAIN_ENV_NAMES


def _is_forbidden_py_env_key(k: str) -> bool:
    return k.startswith("PYTHON") or k.startswith("PYTEST")


def _job_steps(job: dict) -> list[dict]:
    return list(job.get("steps") or [])


def _step_run(step: dict) -> str | None:
    r = step.get("run")
    return r if isinstance(r, str) else None


def _collect_run_parse(workflow: dict) -> dict[str, list[tuple[int, str, list[SimpleCommand] | None]]]:
    """job -> list of (step_index, run_text, parsed_or_None)."""
    out: dict[str, list[tuple[int, str, list[SimpleCommand] | None]]] = {}
    for jn, job in (workflow.get("jobs") or {}).items():
        rows = []
        for i, step in enumerate(_job_steps(job)):
            run = _step_run(step)
            if run is None:
                continue
            parsed = _parse_run(run)
            rows.append((i, run, parsed))
        out[jn] = rows
    return out


def _expand_commands_with_subs(
    cmds: list[SimpleCommand], run: str
) -> list[SimpleCommand] | None:
    """Collect simple commands inside every $( ) region, recursively.

    Returns None (fail closed) if any substitution fails the full closed
    parser — (AG)(1)(4) / review C1. Nested commands join the inventory for
    every command-word, operand, flag, assignment and guarded-step rule.
    """
    extra: list[SimpleCommand] = []
    s = _delete_continuations(run)
    i = 0
    while i < len(s):
        if s.startswith("$(", i):
            j = i + 2
            depth = 1
            while j < len(s) and depth:
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    depth -= 1
                j += 1
            if depth:
                return None
            inner = s[i + 2 : j - 1]
            sub = _parse_run(inner)
            if sub is None:
                return None
            nested = _expand_commands_with_subs(sub, inner)
            if nested is None:
                return None
            extra.extend(nested)
            i = j
        else:
            i += 1
    return list(cmds) + extra


def _words_from_commands(cmds: list[SimpleCommand]) -> list[Word]:
    """Flatten assignment, command-word, argument and redirection-target words."""
    out: list[Word] = []
    for cmd in cmds:
        out.extend(cmd.assignments)
        if cmd.command_word is not None:
            out.append(cmd.command_word)
        out.extend(cmd.args)
        for _op, tgt in cmd.redirections:
            out.append(tgt)
    return out


def _ci_pin_failures(workflow: dict, root: Path = REPO_ROOT) -> list[str]:
    fails: list[str] = []

    def add(token: str, msg: str = "") -> None:
        fails.append(token if not msg else f"{token}:{msg}")

    jobs = workflow.get("jobs") or {}
    if set(jobs) != EXPECTED_CI_JOBS:
        add("job_inventory")

    # shell: / defaults: (AG)(6)
    if "defaults" in workflow:
        add("run_not_recognized", "workflow defaults")
    for jn, job in jobs.items():
        if "defaults" in job:
            add("run_not_recognized", f"{jn} defaults")
        if "strategy" in job:
            add("step_envelope_drift", f"{jn} strategy")
        if "continue-on-error" in job:
            add("step_envelope_drift", f"{jn} continue-on-error")
        for i, step in enumerate(_job_steps(job)):
            if "shell" in step:
                add("run_not_recognized", f"{jn}[{i}] shell")
            if "continue-on-error" in step:
                add("step_envelope_drift", f"{jn}[{i}] continue-on-error")

    # needs graph
    computed_needs: dict[str, tuple[str, ...]] = {}
    for jn, job in jobs.items():
        needs = job.get("needs")
        if needs is None:
            computed_needs[jn] = ()
        elif isinstance(needs, str):
            computed_needs[jn] = (needs,)
        else:
            computed_needs[jn] = tuple(sorted(needs))
    if computed_needs != EXPECTED_NEEDS_GRAPH:
        add("needs_graph_drift")
    if computed_needs.get("manifest-guard") != ():
        add("needs_graph_drift", "manifest-guard must have empty needs")

    # (AX) guard context
    mg = jobs.get("manifest-guard")
    if mg is not None:
        if mg.get("name") != "manifest-guard":
            add("guard_context_drift", f"name={mg.get('name')!r}")
    for jn, job in jobs.items():
        if jn != "manifest-guard" and job.get("name") == "manifest-guard":
            add("guard_context_drift", f"{jn} steals name")

    # conditional jobs/steps
    for jn, job in jobs.items():
        if "if" in job:
            text = _normalize_ws(job["if"])
            expected = CONDITIONAL_JOBS.get(jn)
            if expected is None or _normalize_ws(expected) != text:
                add("step_envelope_drift", f"job if {jn}")
        elif jn in CONDITIONAL_JOBS:
            add("step_envelope_drift", f"missing job if {jn}")
        # absolute: guarded jobs cannot be conditional
        if jn in GUARDED_STEPS and "if" in job:
            add("step_envelope_drift", f"guarded job if {jn}")
        if jn == "manifest-guard" and "if" in job:
            add("step_envelope_drift", "manifest-guard if")

    for jn, pairs in CONDITIONAL_STEPS.items():
        job = jobs.get(jn)
        if not job:
            add("step_envelope_drift", f"missing job {jn}")
            continue
        steps = _job_steps(job)
        found = []
        for i, step in enumerate(steps):
            if "if" in step:
                found.append((i, _normalize_ws(step["if"])))
        expected = [(i, _normalize_ws(t)) for i, t in pairs]
        if found != expected:
            # allow only the expected ones; extra ifs elsewhere in other jobs checked below
            pass
        for i, t in expected:
            if i >= len(steps) or "if" not in steps[i] or _normalize_ws(steps[i]["if"]) != t:
                add("step_envelope_drift", f"step if {jn}[{i}]")

    for jn, job in jobs.items():
        steps = _job_steps(job)
        for i, step in enumerate(steps):
            if "if" not in step:
                continue
            allowed = {(jn2, idx) for jn2, pairs in CONDITIONAL_STEPS.items() for idx, _ in pairs}
            if (jn, i) not in allowed:
                add("step_envelope_drift", f"unexpected if {jn}[{i}]")
            if jn in GUARDED_STEPS and i in GUARDED_STEPS[jn]:
                add("step_envelope_drift", f"if on guarded step {jn}[{i}]")

    # env scopes
    for k in _env_keys(workflow.get("env")):
        if _is_forbidden_go_env_key(k):
            add("go_env_key", f"workflow {k}")
        if _is_forbidden_py_env_key(k):
            add("python_env_key", f"workflow {k}")

    run_data = _collect_run_parse(workflow)

    # UNPARSED equality — pin is a hard-coded literal (AG)(5) / review C2
    unparsed_expected: dict[str, list[str]] = {
        "functional": [EXPECTED_CI_HYGIENE_RUN],
        "benchmark": [EXPECTED_CI_HYGIENE_RUN],
        "manifest-guard": [EXPECTED_CI_HYGIENE_RUN],
        "images": [EXPECTED_IMAGES_PUSH_RUN],
    }

    for jn, rows in run_data.items():
        refused = [run.strip() for i, run, parsed in rows if parsed is None]
        expected = unparsed_expected.get(jn, [])
        if [r.strip() for r in refused] != [e.strip() for e in expected]:
            add("run_not_recognized", f"{jn} unparsed mismatch")

    # (AG)(5) belt: no *pinned* unreadable string may contain lowercase
    # go / python / pytest (case-sensitive). Hygiene legitimately holds
    # PYTHON/PYTEST uppercase only.
    for jn, pinned_list in unparsed_expected.items():
        for r in pinned_list:
            if "go" in r or "python" in r or "pytest" in r:
                add("run_not_recognized", f"{jn} pinned contains go|python|pytest")

    # lexical GITHUB_ENV ban and flag scans over words
    go_test_jobs_found: set[str] = set()
    guarded_computed: dict[str, list[int]] = {}
    pytest_cmds: dict[str, list[tuple[str | None, str]]] = {}
    go_test_cmds: dict[str, list[tuple[str | None, str]]] = {}

    go_version = _go_mod_version(root)
    toolchain = _go_mod_toolchain(root)

    for jn, job in jobs.items():
        steps = _job_steps(job)
        # job env
        if jn in GO_TEST_JOBS or jn in PYTHON_OPT_JOBS:
            for k in _env_keys(job.get("env")):
                if jn in GO_TEST_JOBS and _is_forbidden_go_env_key(k):
                    add("go_env_key", f"{jn} {k}")
                if jn in PYTHON_OPT_JOBS and _is_forbidden_py_env_key(k):
                    add("python_env_key", f"{jn} {k}")

        setup_idxs: list[int] = []
        go_idxs: list[int] = []
        g_idxs: list[int] = []

        for i, step in enumerate(steps):
            uses = step.get("uses") or ""
            if isinstance(uses, str) and uses.startswith("actions/setup-go@"):
                setup_idxs.append(i)
                if jn in GO_TEST_JOBS:
                    if "if" in step:
                        add("go_version_mismatch", f"{jn} setup-go if")
                    with_ = step.get("with") or {}
                    gv = with_.get("go-version")
                    if "go-version-file" in with_ or not isinstance(gv, str):
                        add("go_version_mismatch", f"{jn} go-version form")
                    elif gv.strip('"').strip("'") != go_version:
                        add("go_version_mismatch", f"{jn} {gv}!={go_version}")
                    if toolchain and toolchain != go_version:
                        add("go_version_mismatch", "toolchain")

            # step env
            if jn in GO_TEST_JOBS or jn in PYTHON_OPT_JOBS:
                for k in _env_keys(step.get("env")):
                    if jn in GO_TEST_JOBS and _is_forbidden_go_env_key(k):
                        add("go_env_key", f"{jn}[{i}] {k}")
                    if jn in PYTHON_OPT_JOBS and _is_forbidden_py_env_key(k):
                        add("python_env_key", f"{jn}[{i}] {k}")

            run = _step_run(step)
            if run is None:
                continue

            # GITHUB_ENV lexical
            if jn in PYTHON_OPT_JOBS and "GITHUB_ENV" in run:
                add("github_env_write", f"{jn}[{i}]")

            # e2e GITHUB_PATH equality
            if jn == "e2e" and "GITHUB_PATH" in run:
                path_lines = {ln.strip() for ln in run.splitlines() if "GITHUB_PATH" in ln}
                if path_lines != EXPECTED_E2E_GITHUB_PATH_LINES and not path_lines.issubset(EXPECTED_E2E_GITHUB_PATH_LINES):
                    # collect all path writes in e2e job later
                    pass

            parsed = _parse_run(run)
            if parsed is None:
                continue

            all_cmds = _expand_commands_with_subs(parsed, run)
            if all_cmds is None:
                # Nested substitution failed closed after outer parse — treat
                # as unrecognized (belt; _parse_dollar already refuses).
                add("run_not_recognized", f"{jn}[{i}] nested sub")
                continue

            # operand checks on every nested command too (AL)(2) / C1
            for cmd in all_cmds:
                if not _check_operands(cmd):
                    add("command_operand_drift", f"{jn}[{i}] {cmd.command_word and cmd.command_word.literal_value}")

            # flags / assignments on every word of every nested command (C1)
            words = _words_from_commands(all_cmds)
            for w in words:
                fn = _flag_name(w)
                an = _inline_assign_name(w)
                if fn == "tags":
                    add("go_build_tag_flag", f"{jn}[{i}]")
                if jn in RACE_SHORT_BAN_JOBS and fn in {"race", "short"}:
                    add("go_race_or_short_flag", f"{jn}[{i}]")
                if an and _is_forbidden_go_env_key(an):
                    add("go_env_key", f"{jn}[{i}] inline {an}")
                if jn in PYTHON_OPT_JOBS:
                    if fn in {"O", "OO"}:
                        add("python_optimize_flag", f"{jn}[{i}]")
                    if an and _is_forbidden_py_env_key(an):
                        add("python_env_key", f"{jn}[{i}] inline {an}")

            has_go_test = False
            has_pytest = False
            for cmd in all_cmds:
                if _is_go_test_cmd(cmd):
                    has_go_test = True
                    # static + no assignments
                    if cmd.assignments or any(w.is_dynamic for w in [cmd.command_word, *cmd.args] if w):
                        add("go_test_command_unparsed", f"{jn}[{i}]")
                    else:
                        wd = step.get("working-directory")
                        go_test_cmds.setdefault(jn, []).append((wd, _norm_cmd(cmd)))
                if _is_pytest_cmd(cmd):
                    has_pytest = True
                    wd = step.get("working-directory")
                    pytest_cmds.setdefault(jn, []).append((wd, _norm_cmd(cmd)))

            if has_go_test:
                go_test_jobs_found.add(jn)
                go_idxs.append(i)
            if has_go_test or has_pytest:
                g_idxs.append(i)
                # (AK)(4) guarded step shape — outer parsed commands only for
                # the step envelope; $() anywhere in the run is still banned.
                outer_words = _shell_words(run) or []
                if "|" in {w.literal_value for w in outer_words}:
                    add("guarded_step_shape", f"{jn}[{i}] pipe")
                if any(w.literal_value in {">", ">>"} for w in outer_words):
                    add("guarded_step_shape", f"{jn}[{i}] redir")
                if "$(" in run:
                    add("guarded_step_shape", f"{jn}[{i}] subshell")
                for cmd in parsed:
                    if cmd.assignments:
                        add("guarded_step_shape", f"{jn}[{i}] assign")
                    if cmd.command_word and cmd.command_word.literal_value not in GUARDED_STEP_COMMAND_WORDS:
                        add("guarded_step_shape", f"{jn}[{i}] cw")

        if g_idxs:
            guarded_computed[jn] = g_idxs

        if jn in GO_TEST_JOBS:
            if len(setup_idxs) != 1:
                add("missing_setup_go", jn)
            elif go_idxs and setup_idxs[0] >= min(go_idxs):
                add("setup_go_ordering", jn)
            elif not go_idxs:
                add("missing_setup_go", f"{jn} no go test")
            # runner
            if job.get("runs-on") != "ubuntu-latest":
                add("go_runner_drift", jn)
            if "container" in job:
                add("go_runner_drift", f"{jn} container")

    if go_test_jobs_found != GO_TEST_JOBS:
        add("go_test_job_inventory")

    if guarded_computed != GUARDED_STEPS:
        add("step_envelope_drift", "guarded inventory")

    # pytest command equality
    for jn, expected in EXPECTED_PYTEST_COMMANDS.items():
        got = pytest_cmds.get(jn, [])
        if got != expected:
            add("pytest_command_drift", jn)
    for jn in pytest_cmds:
        if jn not in EXPECTED_PYTEST_COMMANDS:
            add("pytest_command_drift", f"extra {jn}")

    for jn, expected in EXPECTED_GO_TEST_COMMANDS.items():
        got = go_test_cmds.get(jn, [])
        if got != expected:
            add("go_test_command_drift", jn)
    for jn in go_test_cmds:
        if jn not in EXPECTED_GO_TEST_COMMANDS:
            add("go_test_command_drift", f"extra {jn}")

    # e2e GITHUB_PATH job-wide
    e2e = jobs.get("e2e")
    if e2e:
        path_lines: set[str] = set()
        for step in _job_steps(e2e):
            run = _step_run(step)
            if not run:
                continue
            for ln in run.splitlines():
                if "GITHUB_PATH" in ln:
                    path_lines.add(ln.strip())
        if path_lines != EXPECTED_E2E_GITHUB_PATH_LINES:
            add("github_path_write_drift")

    # extract unique tokens (first component)
    tokens = []
    for f in fails:
        tokens.append(f.split(":", 1)[0])
    return tokens


def _e2e_runner_failures(run_sh_text: str) -> list[str]:
    fails: list[str] = []
    # exactly one -m pytest
    pytest_lines = [ln for ln in run_sh_text.splitlines() if "-m pytest" in ln]
    # normalize command: drop continuations, collapse ws
    # find the invocation
    text = run_sh_text.replace("\\\n", " ")
    # locate python3 -m pytest ...
    import re as _re
    m = _re.search(r"python3\s+-m\s+pytest\b[^\n]*", text)
    count = len(_re.findall(r"-m\s+pytest\b", text))
    if count != 1:
        fails.append("e2e_command_drift")
    else:
        # extract full command line roughly
        for ln in run_sh_text.replace("\\\n", " ").splitlines():
            if "-m pytest" in ln:
                norm = " ".join(ln.split())
                # strip leading stuff in phase body
                if "python3 -m pytest" in norm:
                    idx = norm.index("python3 -m pytest")
                    cmd = norm[idx:]
                    # strip trailing quotes/backslashes
                    cmd = cmd.rstrip("\'\"")
                    if cmd != EXPECTED_E2E_PYTEST_COMMAND:
                        fails.append("e2e_command_drift")
                break

    # flag O/OO in whitespace tokens with quote strip
    for tok in run_sh_text.split():
        t = tok
        if len(t) >= 2 and t[0] == t[-1] and t[0] in "'\"":
            t = t[1:-1]
        flag = t.lstrip("-")
        if "=" in flag:
            flag = flag.split("=", 1)[0]
        name = flag if t.startswith("-") else None
        # after stripping dashes once or twice
        if t.startswith("-"):
            fn = t.lstrip("-").split("=", 1)[0]
            if fn in {"O", "OO"}:
                fails.append("e2e_command_drift")

    # PYTHON/PYTEST assign or export
    for ln in run_sh_text.splitlines():
        s = ln.strip()
        if s.startswith("export "):
            rest = s[len("export "):].strip()
            name = rest.split("=", 1)[0].split()[0] if rest else ""
            if name.startswith("PYTHON") or name.startswith("PYTEST"):
                fails.append("python_env_key")
        for tok in s.split():
            if "=" in tok and not tok.startswith("-"):
                nm = tok.split("=", 1)[0]
                if nm.startswith("PYTHON") or nm.startswith("PYTEST"):
                    fails.append("python_env_key")

    # hygiene gate
    defs = [ln for ln in run_sh_text.splitlines() if ln.startswith("env_hygiene_gate()")]
    if len([1 for ln in run_sh_text.splitlines() if "env_hygiene_gate() {" in ln or ln.strip() == "env_hygiene_gate() {"]) != 1:
        # count function defs
        pass
    if run_sh_text.count("env_hygiene_gate() {") != 1:
        fails.append("missing_e2e_hygiene_gate")
    else:
        # body one line
        import re as _re2
        m = _re2.search(r"env_hygiene_gate\(\) \{\n  (.*?)\n\}", run_sh_text)
        if not m or m.group(1).strip() != EXPECTED_E2E_HYGIENE_COMMAND:
            fails.append("missing_e2e_hygiene_gate")

    # bare call
    call_lines = [i for i, ln in enumerate(run_sh_text.splitlines()) if ln.strip() == "env_hygiene_gate"]
    if len(call_lines) != 1:
        fails.append("missing_e2e_hygiene_gate")
    else:
        lines = run_sh_text.splitlines()
        idx = call_lines[0]
        # next non-blank non-comment
        j = idx + 1
        while j < len(lines) and (not lines[j].strip() or lines[j].strip().startswith("#")):
            j += 1
        if j >= len(lines) or not lines[j].lstrip().startswith('phase "pytest_e2e"'):
            fails.append("missing_e2e_hygiene_gate")

    return fails


def _is_config_shaped(name: str) -> bool:
    if name.endswith((".ini", ".toml", ".cfg")):
        return True
    if name == "setup.py":
        return True
    base = name.lstrip(".")
    return base.startswith("pytest")


def _covered_py_links(root: Path = REPO_ROOT) -> list[str]:
    data = _load(root / "tests" / "benchmark" / "thresholds.yaml")
    links = []
    for b in data["benchmarks"]:
        if b.get("status") != "covered":
            continue
        for lnk in b.get("tests") or []:
            if lnk.split("::", 1)[0].endswith(".py"):
                links.append(lnk)
    return links


def _chain_dirs(root: Path, links: list[str]) -> set[Path]:
    dirs: set[Path] = set()
    for lnk in links:
        rel = lnk.split("::", 1)[0]
        p = (root / rel).resolve()
        cur = p.parent
        root_r = root.resolve()
        while True:
            dirs.add(cur)
            if cur == root_r or cur.parent == cur:
                break
            cur = cur.parent
            if root_r not in cur.parents and cur != root_r:
                break
    dirs.add(root.resolve())
    return dirs


def _collect_toml_keys(data: dict, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    for k, v in data.items():
        dotted = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            keys |= _collect_toml_keys(v, dotted)
        else:
            keys.add(k)  # option keys are leaf names
    return keys


def _pytest_keys_from_file(path: Path) -> tuple[set[str] | None, str | None]:
    """Return (keys, error_token)."""
    name = path.name
    try:
        if name.endswith((".ini", ".cfg")):
            cp = configparser.RawConfigParser(strict=True)
            cp.read(path, encoding="utf-8")
            dedicated = name.lstrip(".").startswith("pytest")
            keys: set[str] = set()
            for sec in cp.sections():
                if dedicated or "pytest" in sec.lower():
                    keys |= set(cp.options(sec))
            if dedicated:
                # every key in every section
                keys = set()
                for sec in cp.sections():
                    keys |= set(cp.options(sec))
            return keys, None
        if name.endswith(".toml"):
            data = tomllib.loads(path.read_text(encoding="utf-8"))
            dedicated = name.lstrip(".").startswith("pytest")
            keys = set()
            if dedicated:
                def all_leaf_keys(d, acc):
                    for k, v in d.items():
                        if isinstance(v, dict):
                            all_leaf_keys(v, acc)
                        else:
                            acc.add(k)
                all_leaf_keys(data, keys)
            else:
                def walk(d, path_parts):
                    for k, v in d.items():
                        parts = path_parts + [k]
                        dotted = ".".join(parts)
                        if isinstance(v, dict):
                            if "pytest" in dotted.lower():
                                for kk, vv in v.items():
                                    if not isinstance(vv, dict):
                                        keys.add(kk)
                                    else:
                                        walk({kk: vv}, parts)
                            else:
                                walk(v, parts)
                walk(data, [])
            return keys, None
        return set(), None
    except Exception:
        return None, "pytest_config_unreadable"


def _conftest_hook_failures(path: Path) -> list[str]:
    fails: list[str] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"))
    except SyntaxError:
        fails.append("conftest_collection_hook")
        return fails
    if not isinstance(tree, ast.Module):
        return fails
    # (AI) any module-scope binding matching ^pytest_
    occ = _binding_occurrences(tree)
    parents = _build_parent_map(tree)
    for name, nodes in occ.items():
        for n in nodes:
            holder = _stmt_of(n, parents)
            if holder not in tree.body:
                continue
            if name.startswith("pytest_"):
                # exception: bare import pytest_asyncio
                if (
                    isinstance(holder, ast.Import)
                    and len(holder.names) == 1
                    and holder.names[0].name == "pytest_asyncio"
                    and holder.names[0].asname is None
                ):
                    continue
                fails.append("conftest_collection_hook")
            if name in {"collect_ignore", "collect_ignore_glob"}:
                fails.append("conftest_collection_hook")

    # decorators on module-scope defs
    for stmt in tree.body:
        if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        for dec in stmt.decorator_list:
            if not _decorator_admitted(tree, dec):
                fails.append("conftest_collection_hook")
    return fails


def _decorator_admitted(tree: ast.Module, dec: ast.AST) -> bool:
    """(AM) resolve decorator origin."""
    cur = dec
    if isinstance(cur, ast.Call):
        cur = cur.func
        if isinstance(cur, ast.Call):
            return False  # two Call layers
    root = None
    attr = None
    if isinstance(cur, ast.Name):
        root = cur.id
    elif isinstance(cur, ast.Attribute) and isinstance(cur.value, ast.Name):
        root = cur.value.id
        attr = cur.attr
    else:
        return False
    stmt = _resolve_module_binding(tree, root)
    if stmt is None:
        return False
    origin = None
    if isinstance(stmt, ast.Import):
        for a in stmt.names:
            bound = a.asname or a.name.split(".")[0]
            if bound != root:
                continue
            if a.asname is None and "." in a.name:
                return False
            if attr is None:
                return False
            origin = f"{a.name}.{attr}"
            break
    elif isinstance(stmt, ast.ImportFrom) and stmt.level == 0:
        for a in stmt.names:
            if (a.asname or a.name) != root:
                continue
            origin = f"{stmt.module}.{a.name}"
            if attr:
                origin = f"{origin}.{attr}"
            break
    else:
        return False
    return origin in ADMITTED_DECORATOR_ORIGINS


def _pytest_collection_failures(root: Path, links: list[str]) -> list[str]:
    fails: list[str] = []
    dirs = _chain_dirs(root, links)
    found: set[str] = set()
    for d in dirs:
        if not d.is_dir():
            continue
        for p in d.iterdir():
            if not p.is_file():
                continue
            if _is_config_shaped(p.name):
                rel = str(p.relative_to(root.resolve()))
                found.add(rel)
    if found != EXPECTED_CHAIN_CONFIG_FILES:
        fails.append("pytest_config_inventory")

    for rel in sorted(found & EXPECTED_CHAIN_CONFIG_FILES):
        path = root / rel
        keys, err = _pytest_keys_from_file(path)
        if err:
            fails.append(err)
            continue
        if keys is None:
            continue
        if not keys <= PYTEST_OPTION_ALLOWLIST:
            fails.append("pytest_collection_override")

    for d in dirs:
        conf = d / "conftest.py"
        if conf.is_file():
            fails.extend(_conftest_hook_failures(conf))
    return fails


# ---------------------------------------------------------------------------
# Threshold assertion fixtures (38 neg / 14 pos)
# ---------------------------------------------------------------------------

_TEST_NAME = "test_b99_ok"


def _fx(body: str, *, preamble: str = "", name: str = _TEST_NAME) -> str:
    indented = "\n".join(
        ("    " + line if line.strip() else line) for line in body.strip("\n").split("\n")
    )
    return f"{preamble}def {name}():\n{indented}\n"


THRESHOLD_ASSERTION_FIXTURES: list[tuple[str, str, Callable[[], str]]] = [
    ("docstring_only_threshold_claim", "no_candidate", lambda: _fx('"""B11 threshold p99 < 200 ms."""\nmeasured = 999999\nreturn measured\n')),
    ("comment_only_threshold_claim", "no_candidate", lambda: _fx("# B11 threshold p99 < 200 ms\nmeasured = 999999\nreturn measured\n")),
    ("assertion_message_only", "not_a_threshold_comparison", lambda: _fx('measured = 999999\nassert measured, "B11 rate must be >= 1000.0/s"\n')),
    ("threshold_only_in_a_log_line", "no_candidate", lambda: _fx('rate = 1.0\nprint(f"B11 rate={rate} threshold 1000.0")\n')),
    ("assert_in_an_uncalled_nested_def", "no_candidate", lambda: _fx("def _unused():\n    rate = 1.0\n    assert rate >= 1000.0\nrate = 1.0\nreturn rate\n")),
    ("assert_under_a_literal_false_branch", "not_a_threshold_comparison", lambda: _fx("rate = 1.0\nif False:\n    assert rate >= 1000.0\n")),
    ("equality_instead_of_a_threshold", "not_a_threshold_comparison", lambda: _fx("measured = 999999\nassert measured == 999999\n")),
    ("threshold_operand_is_a_runtime_value", "no_numeric_term", lambda: _fx('import os\nrate = 1.0\nassert rate >= float(os.environ["B11_BAR"])\n')),
    ("assert_test_is_a_short_circuit_boolop", "not_a_threshold_comparison", lambda: _fx("measured = 999999.0\nassert True or (measured < 1000.0)\n")),
    ("raise_branch_under_a_short_circuit_condition", "not_a_threshold_comparison", lambda: _fx('measured = 1.0\nif False and measured >= 1000.0:\n    raise AssertionError("over")\n')),
    ("assert_nested_under_a_short_circuit_branch", "not_a_threshold_comparison", lambda: _fx("def _cheap():\n    return False\nmeasured = 999999.0\nif False and _cheap():\n    assert measured < 1000.0\n")),
    ("both_operands_are_numeric_terms", "both_operands_numeric", lambda: _fx("assert 1.0 < 2.0\n")),
    ("assert_negates_the_comparison", "not_a_threshold_comparison", lambda: _fx("measured = 1.0\nassert not (measured >= 1000.0)\n")),
    ("module_constant_mutated_by_augassign", "unresolved_identifier", lambda: _fx('import os\nrate = 1.0\nassert rate >= BUDGET\n', preamble='BUDGET = 1000.0\nBUDGET += float(os.environ["B11_BAR"])\n\n')),
    ("module_constant_rebound_by_a_for_target", "unresolved_identifier", lambda: _fx("rate = 1.0\nassert rate >= BUDGET\n", preamble="BUDGET = 1000.0\nfor BUDGET in (1.0, 2.0):\n    pass\n\n")),
    ("module_constant_rebound_by_a_walrus", "unresolved_identifier", lambda: _fx('import os\nrate = 1.0\nassert rate >= BUDGET\n', preamble='BUDGET = 1000.0\nif (BUDGET := float(os.environ["B11_BAR"])):\n    pass\n\n')),
    ("numeric_name_also_bound_inside_the_test", "unresolved_identifier", lambda: _fx('import os\nBUDGET = float(os.environ["B11_BAR"])\nrate = 1.0\nassert rate >= BUDGET\n', preamble="BUDGET = 1000.0\n\n")),
    ("module_star_import_poisons_numeric_names", "star_import", lambda: _fx("rate = 1.0\nassert rate >= BUDGET\n", preamble="BUDGET = 1000.0\nfrom runtime_budget import *\n\n")),
    ("fail_call_on_an_unrelated_receiver", "no_fail_in_branch", lambda: _fx('class L:\n    def fail(self, m): pass\nlogger = L()\nmeasured = 1.0\nif measured >= 1000.0:\n    logger.fail("over")\n')),
    ("locally_defined_fail_function", "no_fail_in_branch", lambda: _fx('def fail(msg): pass\nmeasured = 1.0\nif measured >= 1000.0:\n    fail("over")\n')),
    ("pytest_name_rebound_before_the_fail_call", "no_fail_in_branch", lambda: _fx('import pytest\npytest = type("P", (), {"fail": staticmethod(lambda m: None)})()\nmeasured = 1.0\nif measured >= 1000.0:\n    pytest.fail("over")\n')),
    ("self_fail_branch", "no_fail_in_branch", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    self.fail("over")\n')),
    ("hidden_nested_test_function", "nonexistent_linked_test", lambda: "def _outer():\n    def test_b99_ok():\n        measured = 1.0\n        assert measured < 1000.0\n"),
    ("test_function_inside_a_class", "nonexistent_linked_test", lambda: "class TestSuite:\n    def test_b99_ok(self):\n        measured = 1.0\n        assert measured < 1000.0\n"),
    ("top_level_function_not_named_test", "not_collected", lambda: "def check_b99():\n    measured = 1.0\n    assert measured < 1000.0\n"),
    ("assert_after_an_unconditional_return", "dead_candidate", lambda: _fx("return\nmeasured = 1.0\nassert measured < 1000.0\n")),
    ("assert_after_an_unconditional_pytest_skip", "dead_candidate", lambda: _fx('pytest.skip("later")\nmeasured = 1.0\nassert measured < 1000.0\n', preamble="import pytest\n\n")),
    ("assert_swallowed_by_except_assertionerror", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept AssertionError:\n    pass\n")),
    ("assert_swallowed_by_a_bare_except", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept:\n    pass\n")),
    ("assert_swallowed_by_except_exception", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept Exception:\n    pass\n")),
    ("assert_swallowed_by_a_tuple_handler", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept (ValueError, Exception):\n    pass\n")),
    ("assert_swallowed_by_an_unrecognized_handler_type", "swallowed_candidate", lambda: _fx("measured = 1.0\ntry:\n    assert measured < 1000.0\nexcept _ERRORS:\n    pass\n", preamble="_ERRORS = (ValueError, Exception)\n\n")),
    ("raise_branch_swallowed_by_its_own_exception_type", "swallowed_candidate", lambda: _fx('measured = 1.0\ntry:\n    if measured >= 1000.0:\n        raise RuntimeError("over")\nexcept RuntimeError:\n    pass\n')),
    ("assert_inside_a_pytest_raises_block", "swallowed_candidate", lambda: _fx("import pytest\nmeasured = 1.0\nwith pytest.raises(AssertionError):\n    assert measured < 1000.0\n")),
    ("assert_inside_a_contextlib_suppress_block", "swallowed_candidate", lambda: _fx("import contextlib\nmeasured = 1.0\nwith contextlib.suppress(AssertionError):\n    assert measured < 1000.0\n")),
    ("skip_decorated_test_function", "skipped", lambda: "import pytest\n\n@pytest.mark.skip\ndef test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n"),
    # Rebind: non-skip then skip — pytest uses the last binding; must still disqualify (review C4).
    ("module_pytestmark_skips_the_file", "skipped", lambda: "import pytest\npytestmark = pytest.mark.e2e\npytestmark = pytest.mark.skip\n\ndef test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n"),
    ("linked_file_basename_not_collected", "not_collected", lambda: _fx("measured = 1.0\nassert measured < 20.0\n")),
]


THRESHOLD_ASSERTION_POSITIVE_CONTROLS: list[tuple[str, Callable[[], str]]] = [
    ("plain_assert_against_a_literal", lambda: _fx("p99 = 1.0\nassert p99 < 20.0, f\"p99={p99}\"\n")),
    ("assert_against_a_module_constant", lambda: _fx("p99 = 1.0\nassert p99 < P99_MS\n", preamble="P99_MS = 150.0\n\n")),
    ("assert_against_a_derived_constant", lambda: _fx("offered_rate = 1000.0\nassert offered_rate >= BURST_RATE * 0.99\n", preamble="BURST_RATE = 1000\n\n")),
    ("explicit_raise_branch", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    raise AssertionError("over budget")\n')),
    ("pytest_fail_branch", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    pytest.fail("over budget")\n', preamble="import pytest\n\n")),
    ("chained_comparison_with_a_measured_operand", lambda: _fx("p99 = 1.0\nassert 0 < p99 < 20.0\n")),
    ("module_constant_read_in_several_places", lambda: ("BURST_RATE = 1000\nTOTAL = BURST_RATE * 30\n\ndef _helper():\n    return BURST_RATE\n\ndef test_b99_ok():\n    offered = 1000.0\n    _ = BURST_RATE\n    assert offered >= BURST_RATE * 0.99\n")),
    ("fail_imported_from_pytest", lambda: _fx('measured = 1.0\nif measured >= 1000.0:\n    fail("over")\n', preamble="from pytest import fail\n\n")),
    ("async_module_level_test", lambda: "async def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n"),
    # (R)(3) / review W1: module-level non-skip pytestmark must be accepted.
    ("custom_marker_on_the_test_function", lambda: "import pytest\npytestmark = pytest.mark.e2e\n\ndef test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n"),
    ("assert_inside_a_try_with_an_unrelated_handler", lambda: _fx("p99 = 1.0\ntry:\n    assert p99 < 20.0\nexcept ValueError:\n    pass\n")),
    ("assert_inside_a_try_whose_handler_reraises", lambda: _fx("p99 = 1.0\ntry:\n    assert p99 < 20.0\nexcept Exception:\n    raise\n")),
    ("assert_after_a_conditional_return", lambda: _fx("warm = False\nif warm:\n    return\np99 = 1.0\nassert p99 < 20.0\n")),
    ("assert_inside_an_ordinary_with_block", lambda: _fx("class F:\n    def __enter__(self): return self\n    def __exit__(self, *a): return False\nwith F() as session:\n    p99 = 1.0\n    assert p99 < 20.0\n")),
]


@pytest.mark.parametrize(
    "case_id, expected_reason, builder",
    THRESHOLD_ASSERTION_FIXTURES,
    ids=[c[0] for c in THRESHOLD_ASSERTION_FIXTURES],
)
def test_threshold_assertion_checker_rejects_known_bypasses(
    case_id: str, expected_reason: str, builder: Callable[[], str], tmp_path: Path
):
    src = builder()
    name = _TEST_NAME
    if case_id == "top_level_function_not_named_test":
        name = "check_b99"
    path = None
    if case_id == "linked_file_basename_not_collected":
        path = tmp_path / "helpers.py"
        path.write_text(src, encoding="utf-8")
    ok, reason = _python_test_asserts_threshold(src, name, path=path)
    assert ok is False, f"{case_id}: expected reject"
    assert reason == expected_reason, f"{case_id}: got {reason!r} want {expected_reason!r}"


@pytest.mark.parametrize(
    "case_id, builder",
    THRESHOLD_ASSERTION_POSITIVE_CONTROLS,
    ids=[c[0] for c in THRESHOLD_ASSERTION_POSITIVE_CONTROLS],
)
def test_threshold_assertion_checker_accepts_real_shapes(
    case_id: str, builder: Callable[[], str]
):
    src = builder()
    ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
    assert ok is True, f"{case_id}: expected accept, got reason={reason!r}"
    assert reason is None


# ---------------------------------------------------------------------------
# Focused (R)(3) pytestmark module-scope binding controls (review C1).
# Outside the design-pinned 38/14 tables so the fixture count stays fixed.
# ---------------------------------------------------------------------------

# (case_id, src) or (case_id, src, expected_reason). Default reason is "skipped".
# Star-import cases report the dedicated ``star_import`` token (H takes
# precedence over the pytestmark default-deny that also fires for ``import *``).
_PYTESTMARK_SKIP_CASES: list[tuple[str, ...]] = [
    # Control-flow rebind: runtime skips, top-level-only scan would miss it.
    (
        "skip_rebinding_inside_if_true",
        "import pytest\npytestmark = pytest.mark.e2e\nif True:\n"
        "    pytestmark = pytest.mark.skip\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "skip_only_inside_if_true",
        "import pytest\nif True:\n    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "skip_inside_try_body",
        "import pytest\ntry:\n    pytestmark = pytest.mark.skip\n"
        "except Exception:\n    pass\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "augassign_pytestmark_is_opaque",
        "import pytest\npytestmark = pytest.mark.e2e\n"
        "pytestmark += pytest.mark.e2e\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "destructure_binding_is_opaque",
        "import pytest\npytestmark, _other = pytest.mark.e2e, None\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "import_binding_is_opaque",
        "from somewhere import pytestmark\n\ndef test_b99_ok():\n"
        "    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "for_target_binding_is_opaque",
        "import pytest\nfor pytestmark in [pytest.mark.e2e]:\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_if_test",
        "import pytest\nif (pytestmark := pytest.mark.skip):\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "list_form_with_skip_component",
        "import pytest\npytestmark = [pytest.mark.e2e, pytest.mark.skip]\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Module-evaluated def-attached surfaces (review C1 round 4): decorators,
    # argument defaults, and lambda defaults run at definition time in the
    # enclosing scope — a walker that only excludes whole FunctionDef/Lambda
    # nodes would miss these and falsely accept the linked test.
    (
        "walrus_skip_in_function_decorator",
        "import pytest\n"
        "@((pytestmark := pytest.mark.skip))\n"
        "def _helper():\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_function_default",
        "import pytest\n"
        "def _helper(m=(pytestmark := pytest.mark.skip)):\n    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_lambda_default",
        "import pytest\n"
        "_f = lambda m=(pytestmark := pytest.mark.skip): m\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 5: except* (ast.TryStar) handler is module-scope; a
    # walker that only branches on ast.Try (not generically on ExceptHandler)
    # would miss this and falsely accept the linked threshold test.
    (
        "skip_inside_except_star_handler",
        "import pytest\n"
        "try:\n"
        "    raise ExceptionGroup('eg', [ValueError('x')])\n"
        "except* ValueError:\n"
        "    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Deep nesting of with/for: generic child walk must reach arbitrary depth
    # without a fixed per-type container branch list.
    (
        "skip_deeply_nested_with_for",
        "import pytest\n"
        "class _CM:\n"
        "    def __enter__(self): return self\n"
        "    def __exit__(self, *a): return False\n"
        "with _CM():\n"
        "    for _ in (1,):\n"
        "        with _CM():\n"
        "            for _ in (1,):\n"
        "                pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 6: AnnAssign.annotation and evaluated target expressions
    # are module-evaluated; a walker that early-returns after only stmt.value
    # would miss walrus bindings on those surfaces and falsely accept.
    (
        "walrus_skip_in_annassign_annotation",
        "import pytest\n"
        "_holder: (pytestmark := pytest.mark.skip)\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_assign_target_subscript",
        "import pytest\n"
        "_d = {}\n"
        "_d[(pytestmark := pytest.mark.skip)] = 1\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_augassign_target_subscript",
        "import pytest\n"
        "_d = {0: 0}\n"
        "_d[(pytestmark := pytest.mark.skip)] += 1\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    (
        "walrus_skip_in_delete_target_subscript",
        "import pytest\n"
        "_d = {0: 0}\n"
        "del _d[(pytestmark := pytest.mark.skip)]\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 7: withitem.optional_vars is an expression surface —
    # walrus in the as-target must reject; plain ``as pytestmark`` already did.
    (
        "walrus_skip_in_withitem_optional_vars",
        "import pytest\n"
        "import contextlib\n"
        "_d = {0: 0}\n"
        "with contextlib.nullcontext(1) as _d[\n"
        "    0 if (pytestmark := pytest.mark.skip) else 0\n"
        "]:\n"
        "    pass\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 7: star import may rebind pytestmark via __all__;
    # default-deny without resolving the imported module. Full-path reason is
    # ``star_import`` (H vocabulary); walker still treats it as pytestmark-opaque.
    (
        "wildcard_import_is_opaque",
        "from helper import *\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
        "star_import",
    ),
    # Review C1 round 7: class-body ``global pytestmark`` + assignment is a
    # MODULE-scope binding evaluated at class definition (import) time.
    (
        "class_body_global_pytestmark_skip",
        "import pytest\n"
        "class _C:\n"
        "    global pytestmark\n"
        "    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
    # Review C1 round 8: PEP 695 ``type pytestmark = …`` binds at module scope.
    # The value is a type-alias object, not a Mark (real pytest: TypeError);
    # walker must opaque/default-deny, not treat the RHS as a marker.
    (
        "type_alias_pytestmark_is_opaque",
        "import pytest\n"
        "type pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    measured = 1.0\n    assert measured < 1000.0\n",
    ),
]

_PYTESTMARK_ACCEPT_CASES: list[tuple[str, str]] = [
    (
        "non_skip_marker_at_module_scope",
        "import pytest\npytestmark = pytest.mark.e2e\n\ndef test_b99_ok():\n"
        "    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    (
        "non_skip_inside_if_true",
        "import pytest\nif True:\n    pytestmark = pytest.mark.e2e\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Accept control: function-body pytestmark is a nested scope and must NOT
    # reject (walker must not descend into FunctionDef bodies).
    (
        "function_local_pytestmark_ignored",
        "import pytest\ndef _helper():\n    pytestmark = pytest.mark.skip\n"
        "    return pytestmark\n\ndef test_b99_ok():\n"
        "    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Ordinary class attr pytestmark WITHOUT global is class-local, not module.
    (
        "class_body_pytestmark_ignored",
        "import pytest\nclass _C:\n    pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Bounds the decorator scan: a non-pytestmark walrus must not disqualify.
    (
        "non_pytestmark_walrus_in_function_decorator",
        "import pytest\n"
        "@((other := pytest.mark.e2e))\n"
        "def _helper():\n    pass\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 6: ordinary annotated assign must not over-reject when
    # annotation recursion was added (no pytestmark on any surface).
    (
        "ordinary_annotated_assign_accepted",
        "x: int = 5\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 7: normal non-wildcard import must not default-deny
    # (only explicit pytestmark aliases and star imports are opaque).
    (
        "normal_non_wildcard_import_accepted",
        "from somewhere import other\nimport helper\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 7: uncalled nested def with global pytestmark does NOT
    # bind at import — must not reject.
    (
        "class_nested_function_global_pytestmark_ignored",
        "import pytest\n"
        "class _C:\n"
        "    def _helper(self):\n"
        "        global pytestmark\n"
        "        pytestmark = pytest.mark.skip\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
    # Review C1 round 8: ordinary type alias must not over-reject when
    # TypeAlias binding dispatch was added.
    (
        "ordinary_type_alias_accepted",
        "type Alias = int\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
    ),
]


@pytest.mark.parametrize(
    "case",
    _PYTESTMARK_SKIP_CASES,
    ids=[c[0] for c in _PYTESTMARK_SKIP_CASES],
)
def test_pytestmark_skips_rejects_module_scope_binding_shapes(case: tuple[str, ...]):
    case_id, src = case[0], case[1]
    expected_reason = case[2] if len(case) > 2 else "skipped"
    tree = ast.parse(src)
    assert _pytestmark_skips(tree) is True, case_id
    ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
    assert ok is False, f"{case_id}: expected reject"
    assert reason == expected_reason, f"{case_id}: got {reason!r} want {expected_reason!r}"


@pytest.mark.parametrize(
    "case_id, src",
    _PYTESTMARK_ACCEPT_CASES,
    ids=[c[0] for c in _PYTESTMARK_ACCEPT_CASES],
)
def test_pytestmark_skips_accepts_non_skip_and_nested_scopes(
    case_id: str, src: str
):
    tree = ast.parse(src)
    assert _pytestmark_skips(tree) is False, case_id
    ok, reason = _python_test_asserts_threshold(src, _TEST_NAME)
    assert ok is True, f"{case_id}: expected accept, got reason={reason!r}"
    assert reason is None


# ---------------------------------------------------------------------------
# LINK_LOOP_FIXTURES (9)
# ---------------------------------------------------------------------------


def _write_good(path: Path, name: str = "test_b99_ok") -> None:
    path.write_text(
        f"def {name}():\n    p99 = 1.0\n    assert p99 < 20.0\n",
        encoding="utf-8",
    )


def _link_loop_valid_first_missing(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_good.py")
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_good.py::test_b99_ok", "gone.py::test_b99_gone"],
    }


def _link_loop_unknown_test(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_good.py")
    (tmp_path / "test_other.py").write_text("def other():\n    pass\n", encoding="utf-8")
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_good.py::test_b99_ok", "test_other.py::test_b99_gone"],
    }


def _link_loop_weak(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_good.py")
    (tmp_path / "test_weak.py").write_text(
        "def test_b99_weak():\n    measured = 1\n    assert measured == 1\n",
        encoding="utf-8",
    )
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_good.py::test_b99_ok", "test_weak.py::test_b99_weak"],
    }


def _link_loop_all_ok(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_a.py")
    _write_good(tmp_path / "test_b.py")
    return {
        "id": "B99",
        "status": "covered",
        "tests": ["test_a.py::test_b99_ok", "test_b.py::test_b99_ok"],
    }


def _link_loop_single(tmp_path: Path) -> dict:
    _write_good(tmp_path / "test_a.py")
    return {"id": "B99", "status": "covered", "tests": ["test_a.py::test_b99_ok"]}


def _link_loop_empty(tmp_path: Path) -> dict:
    return {"id": "B99", "status": "covered", "tests": []}


def _link_loop_unknown_suffix(tmp_path: Path) -> dict:
    (tmp_path / "b99_notes.md").write_text("x", encoding="utf-8")
    return {"id": "B99", "status": "covered", "tests": ["b99_notes.md::test_b99_ok"]}


def _link_loop_go_no_guard(tmp_path: Path) -> dict:
    (tmp_path / "bench_b99_test.go").write_text(
        "package t\nfunc TestB99() {}\n", encoding="utf-8"
    )
    return {"id": "B99", "status": "covered", "tests": ["bench_b99_test.go::TestB99"]}


def _link_loop_ambiguous(tmp_path: Path) -> dict:
    (tmp_path / "test_dup.py").write_text(
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n\n"
        "def test_b99_ok():\n    p99 = 1.0\n    assert p99 < 20.0\n",
        encoding="utf-8",
    )
    return {"id": "B99", "status": "covered", "tests": ["test_dup.py::test_b99_ok"]}


LINK_LOOP_FIXTURES: list[tuple[str, str | None, int, Callable]] = [
    ("valid_first_link_then_missing_file", "missing_file", 1, _link_loop_valid_first_missing),
    ("valid_first_link_then_unknown_test_name", "nonexistent_linked_test", 1, _link_loop_unknown_test),
    ("valid_first_link_then_link_without_a_threshold_assert", "not_a_threshold_comparison", 1, _link_loop_weak),
    ("all_links_qualify", None, 0, _link_loop_all_ok),
    ("single_link_entry_qualifies", None, 0, _link_loop_single),
    ("covered_entry_with_no_links", None, 1, _link_loop_empty),
    ("link_with_an_unknown_suffix", "unknown_suffix", 1, _link_loop_unknown_suffix),
    ("go_link_without_the_go_guard", "missing_go_guard", 1, _link_loop_go_no_guard),
    ("two_functions_with_the_linked_name", "ambiguous_test_name", 1, _link_loop_ambiguous),
]


@pytest.mark.parametrize(
    "case_id, expected_token, n_fail, builder",
    LINK_LOOP_FIXTURES,
    ids=[c[0] for c in LINK_LOOP_FIXTURES],
)
def test_every_link_of_a_covered_entry_is_checked(
    case_id: str,
    expected_token: str | None,
    n_fail: int,
    builder: Callable,
    tmp_path: Path,
):
    entry = builder(tmp_path)
    fails = _entry_link_failures(entry, root=tmp_path)
    assert len(fails) == n_fail, f"{case_id}: {fails}"
    if expected_token is not None:
        assert any(expected_token in f for f in fails), f"{case_id}: {fails}"


def test_threshold_assertion_fixture_count():
    assert len(THRESHOLD_ASSERTION_FIXTURES) == 38
    assert len(THRESHOLD_ASSERTION_POSITIVE_CONTROLS) == 14
    assert len(LINK_LOOP_FIXTURES) == 9
    assert len(CI_PIN_FIXTURES) == 104
    for _cid, reason, _b in THRESHOLD_ASSERTION_FIXTURES:
        assert reason in THRESHOLD_REASONS
    for _cid, tok, _n, _b in LINK_LOOP_FIXTURES:
        if tok is not None:
            assert tok in THRESHOLD_REASONS
    for row in CI_PIN_FIXTURES:
        assert row[2] in CI_PIN_REASONS
    assert THRESHOLD_REASONS & CI_PIN_REASONS == set()

# ---------------------------------------------------------------------------
# CI_PIN_FIXTURES
# ---------------------------------------------------------------------------


def _load_wf() -> dict:
    return yaml.safe_load((REPO_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8"))


def _b5_step(wf: dict) -> dict:
    return wf["jobs"]["benchmark"]["steps"][10]


def _b9_step(wf: dict) -> dict:
    return wf["jobs"]["benchmark"]["steps"][12]


def _set_run(step: dict, text: str) -> None:
    step["run"] = text


def _ci_pin_workflow_cases():
    cases = []

    def add(cid, reason, mut):
        cases.append((cid, "workflow", reason, mut))

    add(
        "tags_flag_split_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -tags integration -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "tags_flag_equals_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -tags=integration -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "tags_flag_double_dash_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... --tags=integration -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "race_flag_equals_true_in_benchmark",
        "go_race_or_short_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s -race=true",
        ),
    )
    add(
        "short_flag_equals_true_in_functional",
        "go_race_or_short_flag",
        lambda wf: _set_run(
            wf["jobs"]["functional"]["steps"][10],
            "go test ./tests/functional/... -v -timeout 300s -short=true",
        ),
    )
    add(
        "short_flag_split_form_in_benchmark",
        "go_race_or_short_flag",
        lambda wf: _set_run(
            _b9_step(wf),
            "go test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s -short",
        ),
    )
    add(
        "goflags_env_at_workflow_scope",
        "go_env_key",
        lambda wf: wf.__setitem__("env", {"GOFLAGS": "-tags=integration"}),
    )
    add(
        "cgo_enabled_env_at_job_scope",
        "go_env_key",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("env", {"CGO_ENABLED": "0"}),
    )
    add(
        "goos_env_at_step_scope",
        "go_env_key",
        lambda wf: _b5_step(wf).__setitem__("env", {"GOOS": "darwin"}),
    )
    add(
        "gotoolchain_env_at_job_scope",
        "go_env_key",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("env", {"GOTOOLCHAIN": "go1.27.0"}),
    )
    add(
        "inline_goflags_assignment_in_a_run",
        "go_env_key",
        lambda wf: _set_run(
            _b5_step(wf),
            "GOFLAGS=-tags=integration go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )

    def remove_setup(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        wf["jobs"]["benchmark"]["steps"] = [
            s for s in steps if not str(s.get("uses", "")).startswith("actions/setup-go@")
        ]

    add("setup_go_step_removed_from_benchmark", "missing_setup_go", remove_setup)

    def bad_ver(wf):
        for s in wf["jobs"]["benchmark"]["steps"]:
            if str(s.get("uses", "")).startswith("actions/setup-go@"):
                s.setdefault("with", {})["go-version"] = "1.25.0"

    add("setup_go_version_disagrees_with_go_mod", "go_version_mismatch", bad_ver)

    def ver_file(wf):
        for s in wf["jobs"]["benchmark"]["steps"]:
            if str(s.get("uses", "")).startswith("actions/setup-go@"):
                s["with"] = {"go-version-file": "go.mod"}

    add("setup_go_uses_go_version_file", "go_version_mismatch", ver_file)
    add(
        "go_job_not_on_ubuntu_latest",
        "go_runner_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("runs-on", ["self-hosted", "linux"]),
    )

    def move_b5(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        step = [s for s in steps if "TestB5" in str(s.get("run", ""))][0]
        wf["jobs"]["benchmark"]["steps"] = [s for s in steps if s is not step]
        wf["jobs"]["benchmark-go"] = {
            "runs-on": "ubuntu-latest",
            "steps": [
                {"uses": "actions/checkout@v4"},
                {"uses": "actions/setup-go@v5", "with": {"go-version": "1.26.4"}},
                step,
            ],
        }

    add("go_test_moved_to_a_new_job", "go_test_job_inventory", move_b5)

    def rename_bench(wf):
        wf["jobs"]["bench"] = wf["jobs"].pop("benchmark")

    add("benchmark_job_renamed", "job_inventory", rename_bench)

    def curl_O(wf):
        run = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = run.replace("-o /tmp/kind", "-O")

    add("curl_dash_O_in_the_e2e_job", "python_optimize_flag", curl_O)
    add(
        "pythonoptimize_env_in_the_e2e_job",
        "python_env_key",
        lambda wf: wf["jobs"]["e2e"].__setitem__("env", {"PYTHONOPTIMIZE": "1"}),
    )

    def github_env(wf):
        wf["jobs"]["e2e"]["steps"].append({"run": 'echo "PYTHONOPTIMIZE=1" >> "$GITHUB_ENV"'})

    add("e2e_step_writes_github_env", "github_env_write", github_env)
    add(
        "quoted_tags_equals_form",
        "go_build_tag_flag",
        lambda wf: _set_run(
            _b5_step(wf),
            'go test ./probe/internal/redact/... "-tags=integration" -run TestB5 -v -timeout 60s',
        ),
    )

    def setup_after(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        setup = [s for s in steps if str(s.get("uses", "")).startswith("actions/setup-go@")][0]
        rest = [s for s in steps if s is not setup]
        wf["jobs"]["benchmark"]["steps"] = rest + [setup]

    add("setup_go_after_go_test", "setup_go_ordering", setup_after)
    add(
        "unbalanced_quote_in_a_run_block",
        "run_not_recognized",
        lambda wf: _set_run(_b5_step(wf), "go test ./probe/internal/redact/... -run 'TestB5"),
    )
    add(
        "heredoc_in_a_go_test_job_run_block",
        "run_not_recognized",
        lambda wf: _set_run(
            _b9_step(wf),
            "cat <<EOF > /tmp/x\nhello\nEOF\ngo test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s",
        ),
    )
    add(
        "go_test_flags_from_a_shell_variable",
        "go_test_command_unparsed",
        lambda wf: _set_run(
            _b5_step(wf),
            "EXTRA=-tags=integration\ngo test ./probe/internal/redact/... $EXTRA -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "go_test_launched_through_eval",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "eval go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )

    def path_prepend(wf):
        wf["jobs"]["e2e"]["steps"].append({"run": 'echo "/tmp/shim" >> "$GITHUB_PATH"'})

    add("e2e_step_prepends_a_path_entry", "github_path_write_drift", path_prepend)
    add(
        "ansi_c_quoted_tags_flag",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... $'-tags=integration' -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "go_test_under_a_reserved_word",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            'if true; then go test ./probe/internal/redact/... "$EXTRA"; fi',
        ),
    )
    add(
        "go_test_through_an_unlisted_wrapper",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "nohup go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "go_test_wrapped_in_sudo",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "sudo go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "inline_shell_program_passed_to_bash",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            'bash -c "go test ./probe/internal/redact/... -tags=integration -run TestB5"',
        ),
    )
    add(
        "unpinned_compound_command_in_a_go_test_job",
        "run_not_recognized",
        lambda wf: wf["jobs"]["benchmark"]["steps"].append(
            {"run": 'for p in ./probe/...; do go test "$p"; done'}
        ),
    )

    def edit_push(wf):
        r = wf["jobs"]["images"]["steps"][7]["run"]
        wf["jobs"]["images"]["steps"][7]["run"] = r + "\necho extra\n"

    add("pinned_push_step_edited", "run_not_recognized", edit_push)
    add(
        "step_declares_an_alternate_shell",
        "run_not_recognized",
        lambda wf: _b9_step(wf).__setitem__("shell", "python"),
    )

    def override_ini(wf):
        r = wf["jobs"]["functional"]["steps"][9]["run"]
        wf["jobs"]["functional"]["steps"][9]["run"] = (
            r.rstrip() + ' -o "python_functions=test_ci_*"\n'
        )

    add("functional_pytest_gains_an_override_ini", "pytest_command_drift", override_ini)

    def config_flag(wf):
        r = wf["jobs"]["benchmark"]["steps"][17]["run"]
        wf["jobs"]["benchmark"]["steps"][17]["run"] = r.rstrip() + " -c /tmp/alt.ini\n"

    add("benchmark_pytest_gains_a_config_flag", "pytest_command_drift", config_flag)

    def deselect(wf):
        r = wf["jobs"]["benchmark"]["steps"][17]["run"]
        wf["jobs"]["benchmark"]["steps"][17]["run"] = r.rstrip() + (
            " --deselect tests/benchmark/test_pg_scale.py::test_b11_audit_llm_insert_throughput\n"
        )

    add("benchmark_pytest_gains_a_deselection", "pytest_command_drift", deselect)

    def ignore_wide(wf):
        r = wf["jobs"]["functional"]["steps"][9]["run"]
        wf["jobs"]["functional"]["steps"][9]["run"] = r.rstrip() + " --ignore=tests/functional\n"

    add("functional_pytest_ignore_widened", "pytest_command_drift", ignore_wide)
    add(
        "unit_gateway_pytest_working_directory_changed",
        "pytest_command_drift",
        lambda wf: wf["jobs"]["unit-gateway"]["steps"][3].__setitem__("working-directory", "."),
    )
    add(
        "guarded_step_gains_a_false_condition",
        "step_envelope_drift",
        lambda wf: _b5_step(wf).__setitem__("if", "${{ false }}"),
    )
    add(
        "guarded_step_gains_continue_on_error",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["functional"]["steps"][9].__setitem__("continue-on-error", True),
    )
    add(
        "go_test_job_gains_continue_on_error",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("continue-on-error", True),
    )
    add(
        "job_holding_a_guarded_step_gains_a_condition",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["functional"].__setitem__("if", "github.event_name != 'schedule'"),
    )
    add(
        "upstream_job_gains_a_condition",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["lint"].__setitem__("if", "github.event_name != 'push'"),
    )
    add(
        "guarded_job_declares_a_matrix",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("strategy", {"matrix": {"n": []}}),
    )

    def del_b9(wf):
        steps = wf["jobs"]["benchmark"]["steps"]
        wf["jobs"]["benchmark"]["steps"] = [
            s for s in steps if "TestB9" not in str(s.get("run", ""))
        ]

    add("guarded_step_inventory_shifts", "step_envelope_drift", del_b9)
    add(
        "go_test_short_circuited_by_an_or",
        "run_not_recognized",
        lambda wf: _set_run(
            _b5_step(wf),
            "echo ok || go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s",
        ),
    )
    add(
        "pytest_failure_masked_by_an_or",
        "run_not_recognized",
        lambda wf: _set_run(
            wf["jobs"]["benchmark"]["steps"][17],
            "services/worker/.venv/bin/python -m pytest tests/benchmark/test_pg_scale.py -v -s || echo ok",
        ),
    )
    add(
        "go_test_piped_into_another_command",
        "guarded_step_shape",
        lambda wf: _set_run(
            _b9_step(wf),
            "go test ./probe/internal/adapter/presto/... -run TestB9 -v -timeout 60s | echo done",
        ),
    )

    def wrap_b6(wf):
        # C1 (round 2): Bash prompt expansion ${PAYLOAD@P} executes command
        # substitutions embedded in the parameter value. Default-deny braced
        # grammar refuses @P (and all other @-transforms) as run_not_recognized
        # rather than accepting the step as readable. Count stays 104.
        wf["jobs"]["benchmark"]["steps"][11]["run"] = (
            "services/worker/.venv/bin/python -m pytest "
            "libs/py/rca_common/tests/test_rawcmd.py::test_b6_static_validator_under_5ms -v\n"
            "PAYLOAD='$(go env -w GOFLAGS=-exec=/bin/true)'\n"
            'echo "${PAYLOAD@P}"\n'
        )

    add("pytest_wrapped_in_a_command_substitution", "run_not_recognized", wrap_b6)

    def source_guarded(wf):
        r = wf["jobs"]["functional"]["steps"][9]["run"]
        wf["jobs"]["functional"]["steps"][9]["run"] = "source deploy/versions.env\n" + r

    add("source_command_inside_a_guarded_step", "guarded_step_shape", source_guarded)

    def redir(wf):
        r = wf["jobs"]["benchmark"]["steps"][14]["run"]
        wf["jobs"]["benchmark"]["steps"][14]["run"] = r.rstrip() + " > /tmp/b13.log\n"

    add("guarded_step_redirects_its_output", "guarded_step_shape", redir)

    def assign_prefix(wf):
        r = wf["jobs"]["benchmark"]["steps"][13]["run"]
        # Prefix the first non-empty line with an assignment word (AK)(4).
        lines = r.splitlines(keepends=True)
        for i, ln in enumerate(lines):
            if ln.strip():
                lines[i] = "TMPDIR=/tmp " + ln.lstrip()
                break
        wf["jobs"]["benchmark"]["steps"][13]["run"] = "".join(lines)

    add("guarded_step_gains_an_assignment_prefix", "guarded_step_shape", assign_prefix)

    def ifs_smuggle(wf):
        r = "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s"
        wf["jobs"]["benchmark"]["steps"][10]["run"] = "bash -c 'go${IFS}test${IFS}./x'\n" + r

    add("inline_shell_program_smuggled_through_ifs", "command_operand_drift", ifs_smuggle)
    add(
        "inline_python_program_launches_pytest",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][6], "python -c 'print(1)'"),
    )
    add(
        "python_module_outside_the_pin",
        "command_operand_drift",
        lambda wf: _set_run(
            wf["jobs"]["lint"]["steps"][6],
            "python -m pip install pytest-randomly\npython -m compileall -q .",
        ),
    )
    add(
        "go_run_replaces_go_vet",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][7], "go run ./probe/cmd/probe"),
    )

    def sudo_bash(wf):
        r = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = r.replace(
            "sudo mv /tmp/kind /usr/local/bin/kind", "sudo bash tests/e2e/run.sh"
        )

    add("sudo_wraps_an_unlisted_program", "command_operand_drift", sudo_bash)

    def sudo_go(wf):
        r = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = r.replace(
            "sudo mv /tmp/kind /usr/local/bin/kind", "sudo mv /tmp/kind /usr/local/bin/go"
        )

    add("sudo_shadows_the_go_binary", "command_operand_drift", sudo_go)
    add(
        "bash_runs_a_script_outside_the_pin",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["functional"]["steps"][5], "bash /tmp/gen.sh"),
    )

    def bash_pipe(wf):
        r = wf["jobs"]["e2e"]["steps"][5]["run"]
        wf["jobs"]["e2e"]["steps"][5]["run"] = r.replace("| tar -xz -C /tmp", "| bash")

    add("bash_reads_its_program_from_a_pipe", "command_operand_drift", bash_pipe)

    def pip_url(wf):
        r = wf["jobs"]["benchmark"]["steps"][6]["run"]
        wf["jobs"]["benchmark"]["steps"][6]["run"] = (
            r + "\nservices/worker/.venv/bin/pip install https://example.invalid/x.whl\n"
        )

    add("pip_installs_from_a_url", "command_operand_drift", pip_url)

    def tar_prog(wf):
        r = wf["jobs"]["functional"]["steps"][7]["run"]
        wf["jobs"]["functional"]["steps"][7]["run"] = r.replace(
            "tar -xzf /tmp/helm.tgz -C /tmp",
            "tar --use-compress-program=/tmp/x -xf /tmp/helm.tgz -C /tmp",
        )

    add("tar_uses_a_compress_program", "command_operand_drift", tar_prog)

    def set_plus(wf):
        r = wf["jobs"]["images"]["steps"][6]["run"]
        wf["jobs"]["images"]["steps"][6]["run"] = r.replace("set -euo pipefail", "set +e")

    add("set_disables_errexit_in_an_unguarded_step", "command_operand_drift", set_plus)
    add(
        "go_test_lists_its_tests_instead_of_running_them",
        "go_test_command_drift",
        lambda wf: _set_run(
            _b5_step(wf),
            "go test ./probe/internal/redact/... -run TestB5 -v -timeout 60s -list .",
        ),
    )
    add(
        "go_test_compiles_without_running",
        "go_test_command_drift",
        lambda wf: _set_run(_b9_step(wf), "go test -c ./probe/internal/adapter/presto"),
    )
    add(
        "go_test_runs_under_a_no_op_exec",
        "go_test_command_drift",
        lambda wf: _set_run(
            wf["jobs"]["functional"]["steps"][10],
            "go test ./tests/functional/... -v -timeout 300s -exec /bin/true",
        ),
    )
    add(
        "go_test_step_gains_a_working_directory",
        "go_test_command_drift",
        lambda wf: wf["jobs"]["unit-go"]["steps"][7].__setitem__("working-directory", "probe"),
    )

    def install_shadow(wf):
        r = wf["jobs"]["lint"]["steps"][4]["run"]
        wf["jobs"]["lint"]["steps"][4]["run"] = (
            r + "\ngo install github.com/example/toolchain/cmd/go@v1.0.0\n"
        )

    add("go_install_shadows_the_go_toolchain", "command_operand_drift", install_shadow)
    add(
        "upstream_job_declares_an_empty_matrix",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["lint"].__setitem__("strategy", {"matrix": {"n": []}}),
    )

    def go_env_w(wf):
        r = wf["jobs"]["benchmark"]["steps"][4]["run"]
        wf["jobs"]["benchmark"]["steps"][4]["run"] = (
            r + "\nX=\ngo env -w GO${X}FLAGS=-exec=/bin/true\n"
        )

    add("go_env_persistently_records_goflags", "command_operand_drift", go_env_w)

    def go_env_diff(wf):
        r = wf["jobs"]["lint"]["steps"][4]["run"]
        wf["jobs"]["lint"]["steps"][4]["run"] = r.replace("go env GOPATH", "go env GOMODCACHE")

    add("go_env_reads_a_different_variable", "command_operand_drift", go_env_diff)
    add(
        "go_vet_runs_a_vettool",
        "command_operand_drift",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][7], "go vet -vettool=/tmp/x ./..."),
    )

    def install_unpin(wf):
        r = wf["jobs"]["lint"]["steps"][4]["run"]
        wf["jobs"]["lint"]["steps"][4]["run"] = r.replace(
            "google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1",
            "example.com/cmd/tool@latest",
        )

    add("go_install_targets_an_unpinned_module", "command_operand_drift", install_unpin)
    add(
        "cgo_enabled_inline_assignment_in_an_unguarded_run",
        "go_env_key",
        lambda wf: _set_run(wf["jobs"]["lint"]["steps"][7], "CGO_ENABLED=0 go vet ./..."),
    )
    add(
        "cgo_cflags_env_at_step_scope",
        "go_env_key",
        lambda wf: _b5_step(wf).__setitem__("env", {"CGO_CFLAGS": "-I/tmp/x"}),
    )
    add(
        "cc_env_at_workflow_scope",
        "go_env_key",
        lambda wf: wf.__setitem__("env", {"CC": "/tmp/shim/cc"}),
    )
    add(
        "guard_job_gains_a_needs_edge",
        "needs_graph_drift",
        lambda wf: wf["jobs"]["manifest-guard"].__setitem__("needs", "lint"),
    )
    add(
        "benchmark_needs_rewired_past_the_unit_tier",
        "needs_graph_drift",
        lambda wf: wf["jobs"]["benchmark"].__setitem__("needs", "lint"),
    )
    add(
        "guard_job_gains_a_job_level_condition",
        "step_envelope_drift",
        lambda wf: wf["jobs"]["manifest-guard"].__setitem__(
            "if", "github.event_name == 'push'"
        ),
    )
    add(
        "guard_job_removed_from_the_workflow",
        "job_inventory",
        lambda wf: wf["jobs"].pop("manifest-guard", None),
    )
    add(
        "guard_job_renamed_out_of_its_required_context",
        "guard_context_drift",
        lambda wf: wf["jobs"]["manifest-guard"].__setitem__(
            "name", "manifest honesty + CI pin"
        ),
    )
    add(
        "another_job_takes_the_guards_context",
        "guard_context_drift",
        lambda wf: wf["jobs"]["images"].__setitem__("name", "manifest-guard"),
    )
    return cases


def _ci_pin_runner_cases():
    def mut_O(t: str) -> str:
        return t.replace(
            "python3 -m pytest tests/e2e -v --tb=short",
            "python3 -O -m pytest tests/e2e -v --tb=short",
        )

    def mut_export(t: str) -> str:
        return t.replace("env_hygiene_gate\n", "export PYTHONOPTIMIZE=1\nenv_hygiene_gate\n")

    def mut_del_gate(t: str) -> str:
        return t.replace("env_hygiene_gate\n", "")

    def mut_between(t: str) -> str:
        return t.replace("env_hygiene_gate\n", "env_hygiene_gate\necho between\n")

    return [
        ("run_sh_pytest_gains_dash_O", "runner", "e2e_command_drift", mut_O),
        ("run_sh_exports_pythonoptimize", "runner", "python_env_key", mut_export),
        ("run_sh_hygiene_gate_deleted", "runner", "missing_e2e_hygiene_gate", mut_del_gate),
        (
            "run_sh_statement_between_gate_and_phase",
            "runner",
            "missing_e2e_hygiene_gate",
            mut_between,
        ),
    ]


def _ci_pin_tree_cases():
    cases = []

    def add(cid, reason, mut):
        cases.append((cid, "tree", reason, mut))

    add(
        "root_pytest_ini_sets_addopts",
        "pytest_collection_override",
        lambda root: (root / "pytest.ini").write_text(
            "[pytest]\nasyncio_mode = auto\naddopts = -p no:cacheprovider\n",
            encoding="utf-8",
        ),
    )
    add(
        "nested_pytest_toml_in_tests_e2e",
        "pytest_config_inventory",
        lambda root: (root / "tests/e2e/pytest.toml").write_text(
            '[pytest]\npython_functions = ["check_*"]\n', encoding="utf-8"
        ),
    )
    add(
        "dot_pytest_ini_beside_a_linked_test",
        "pytest_config_inventory",
        lambda root: (root / "tests/benchmark/.pytest.ini").write_text(
            "[pytest]\n", encoding="utf-8"
        ),
    )
    add(
        "dot_pytest_toml_at_the_repo_root",
        "pytest_config_inventory",
        lambda root: (root / ".pytest.toml").write_text("[pytest]\n", encoding="utf-8"),
    )

    def worker_funcs(root):
        p = root / "services/worker/pyproject.toml"
        text = p.read_text(encoding="utf-8")
        text = text.replace(
            "[tool.pytest.ini_options]",
            '[tool.pytest.ini_options]\npython_functions = ["check_*"]',
        )
        p.write_text(text, encoding="utf-8")

    add("worker_pyproject_declares_python_functions", "pytest_collection_override", worker_funcs)

    def collect_ignore(root):
        p = root / "tests/e2e/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else ""
        p.write_text(t + '\ncollect_ignore = ["test_e2e_load.py"]\n', encoding="utf-8")

    add("conftest_declares_collect_ignore", "conftest_collection_hook", collect_ignore)

    def native_table(root):
        p = root / "services/worker/pyproject.toml"
        t = p.read_text(encoding="utf-8")
        t = t.replace(
            "[tool.pytest.ini_options]",
            '[tool.pytest]\npython_functions = ["check_*"]',
        )
        p.write_text(t, encoding="utf-8")

    add("worker_pyproject_uses_the_native_pytest_table", "pytest_collection_override", native_table)

    def unread_section(root):
        p = root / "pytest.ini"
        p.write_text(
            p.read_text(encoding="utf-8") + "\n[tool:pytest]\npython_files = check_*.py\n",
            encoding="utf-8",
        )

    add("root_pytest_ini_key_under_an_unread_section", "pytest_collection_override", unread_section)

    def unreadable(root):
        p = root / "libs/py/rca_common/pyproject.toml"
        p.write_text(p.read_text(encoding="utf-8") + "\n[\n", encoding="utf-8")

    add("inventoried_pyproject_does_not_parse", "pytest_config_unreadable", unreadable)

    def unlisted_hook(root):
        p = root / "tests/benchmark/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(t + "\ndef pytest_collection(session):\n    pass\n", encoding="utf-8")

    add("conftest_declares_an_unlisted_collection_hook", "conftest_collection_hook", unlisted_hook)

    def specname(root):
        p = root / "tests/e2e/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + '\n@pytest.hookimpl(specname="pytest_collection_modifyitems")\n'
            "def _reorder(session, config, items):\n    items.clear()\n",
            encoding="utf-8",
        )

    add("conftest_binds_a_hook_through_specname", "conftest_collection_hook", specname)

    def alias_hook(root):
        p = root / "tests/functional/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + '\nfrom pytest import hookimpl as _h\n@_h(specname="pytest_ignore_collect")\n'
            "def _skip(collection_path, config):\n    return True\n",
            encoding="utf-8",
        )

    add("conftest_imports_hookimpl_under_an_alias", "conftest_collection_hook", alias_hook)

    def alias_fixture(root):
        p = root / "tests/functional/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + '\nfrom pytest import hookimpl as fixture\n'
            '@fixture(specname="pytest_collection_modifyitems")\n'
            "def _drop(session, config, items):\n    items.clear()\n",
            encoding="utf-8",
        )

    add("conftest_aliases_hookimpl_as_fixture", "conftest_collection_hook", alias_fixture)

    def assign_fixture(root):
        p = root / "tests/benchmark/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else "import pytest\n"
        p.write_text(
            t
            + "\nfixture = pytest.hookimpl\n@fixture(specname=\"pytest_ignore_collect\")\n"
            "def _skip(collection_path, config):\n    return True\n",
            encoding="utf-8",
        )

    add("conftest_binds_fixture_by_assignment", "conftest_collection_hook", assign_fixture)

    def star(root):
        p = root / "tests/e2e/conftest.py"
        t = p.read_text(encoding="utf-8") if p.is_file() else ""
        t = (
            t.replace("import pytest", "from pytest import *")
            if "import pytest" in t
            else "from pytest import *\n" + t
        )
        p.write_text(t, encoding="utf-8")

    add("conftest_star_imports_pytest", "conftest_collection_hook", star)
    return cases


def _build_ci_pin_fixtures():
    rows = []
    rows.extend(_ci_pin_workflow_cases())
    rows.extend(_ci_pin_runner_cases())
    rows.extend(_ci_pin_tree_cases())

    def toolchain_mut(root: Path) -> None:
        p = root / "go.mod"
        p.write_text(p.read_text(encoding="utf-8") + "\ntoolchain go1.27.0\n", encoding="utf-8")

    rows.append(("go_mod_declares_a_newer_toolchain", "tree", "go_version_mismatch", toolchain_mut))
    return rows


CI_PIN_FIXTURES = _build_ci_pin_fixtures()


def _materialize_tree(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    for rel in EXPECTED_CHAIN_CONFIG_FILES:
        src = REPO_ROOT / rel
        dest = root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "go.mod").write_text((REPO_ROOT / "go.mod").read_text(encoding="utf-8"), encoding="utf-8")
    for rel in [
        "conftest.py",
        "tests/functional/conftest.py",
        "tests/e2e/conftest.py",
        "tests/benchmark/conftest.py",
        "services/worker/tests/conftest.py",
        "services/dashboard-api/tests/conftest.py",
    ]:
        src = REPO_ROOT / rel
        if src.is_file():
            dest = root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    for rel in [
        "tests/e2e/test_e2e_load.py",
        "tests/benchmark/test_pg_scale.py",
        "tests/functional/test_manifests.py",
        "services/worker/tests/test_x.py",
        "services/gateway/tests/test_x.py",
        "services/dashboard-api/tests/test_x.py",
        "libs/py/rca_common/tests/test_x.py",
    ]:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if not p.exists():
            p.write_text("# dummy\n", encoding="utf-8")
    return root


def test_ci_pins_the_checker_assumptions():
    wf = _load_wf()
    fails = _ci_pin_failures(wf, REPO_ROOT)
    assert fails == [], fails
    run_sh = (REPO_ROOT / "tests/e2e/run.sh").read_text(encoding="utf-8")
    assert _e2e_runner_failures(run_sh) == []
    links = _covered_py_links(REPO_ROOT)
    assert _pytest_collection_failures(REPO_ROOT, links) == []
    env_min = {"PATH": "/usr/bin:/bin", "HOME": "/tmp", "LC_ALL": "C"}
    r0 = subprocess.run(["/bin/bash", "-e", "-c", EXPECTED_E2E_HYGIENE_COMMAND], env=env_min)
    assert r0.returncode == 0
    r1 = subprocess.run(
        ["/bin/bash", "-e", "-c", EXPECTED_E2E_HYGIENE_COMMAND],
        env={**env_min, "PYTHONOPTIMIZE": "1"},
    )
    assert r1.returncode != 0
    r2 = subprocess.run(
        ["/bin/bash", "-e", "-c", EXPECTED_E2E_HYGIENE_COMMAND],
        env={**env_min, "PYTEST_PLUGINS": "x"},
    )
    assert r2.returncode != 0
    assert pytest.version_tuple[0] in (8, 9)


@pytest.mark.parametrize(
    "case_id, kind, expected, mutator",
    CI_PIN_FIXTURES,
    ids=[c[0] for c in CI_PIN_FIXTURES],
)
def test_ci_pin_rejects_known_drift(case_id, kind, expected, mutator, tmp_path: Path):
    if kind == "workflow":
        wf = _load_wf()
        mutator(wf)
        fails = _ci_pin_failures(wf, REPO_ROOT)
        assert expected in fails, f"{case_id}: {fails}"
    elif kind == "runner":
        text = (REPO_ROOT / "tests/e2e/run.sh").read_text(encoding="utf-8")
        fails = _e2e_runner_failures(mutator(text))
        assert expected in fails, f"{case_id}: {fails}"
    elif kind == "tree":
        root = _materialize_tree(tmp_path)
        mutator(root)
        if case_id == "go_mod_declares_a_newer_toolchain":
            wf = _load_wf()
            fails = _ci_pin_failures(wf, root)
            assert expected in fails, f"{case_id}: {fails}"
        else:
            links = [
                "tests/e2e/test_e2e_load.py::test_b1_ingest_burst_profile",
                "tests/benchmark/test_pg_scale.py::test_b2_fingerprint_correlation_p99_under_20ms",
                "services/worker/tests/test_x.py::test_x",
                "services/gateway/tests/test_x.py::test_x",
                "services/dashboard-api/tests/test_x.py::test_x",
                "libs/py/rca_common/tests/test_x.py::test_x",
                "tests/functional/test_manifests.py::test_x",
            ]
            fails = _pytest_collection_failures(root, links)
            assert expected in fails, f"{case_id}: {fails}"
    else:
        raise AssertionError(kind)
