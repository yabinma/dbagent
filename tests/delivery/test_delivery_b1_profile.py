"""FP-IG-8/13/14/15/19 and UT-IG-7: B1 harness surface, classifiers, generators."""
from __future__ import annotations

import ast
import asyncio
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import time
import tokenize
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
REF_PATH = REPO_ROOT / "services" / "gateway" / "tests" / "b1_reference_profile.py"
E2E_PATH = REPO_ROOT / "tests" / "e2e" / "b1_e2e_profile.py"
REF_TEST = REPO_ROOT / "services" / "gateway" / "tests" / "test_b1_ingest_burst.py"
E2E_TEST = REPO_ROOT / "tests" / "e2e" / "test_e2e_load.py"
# GC-3: the live-only discovery module and the stdlib-only topology helper it
# shares with the host launcher. The live module is deliberately not
# `test_`-prefixed, so no directory collection discovers it.
PROBE_TEST = REPO_ROOT / "services" / "gateway" / "tests" / "b1_topology_probe_live.py"
PROBE_HELPER = REPO_ROOT / "services" / "gateway" / "tests" / "b1_topology_probe.py"
GC3_DECISION = REPO_ROOT / "tests" / "benchmark" / "b1_topology_decision.json"


def _load(path: Path, name: str):
    import sys

    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # dataclasses requires the module to be in sys.modules before exec.
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


ref = _load(REF_PATH, "b1_ref")
e2e = _load(E2E_PATH, "b1_e2e")


# ---------------------------------------------------------------------------
# UT-IG-7 / FP-IG-8
# ---------------------------------------------------------------------------

CLASSIFIER_TABLE = [
    # (status, body, error, expected)
    (202, b'{"investigation_id":"x"}', None, "served"),
    (200, b'{"status":"merged","investigation_id":"x"}', None, "served"),
    (200, b'{"status":"rejected","reason":"platform_not_ready"}', None, "error"),
    (200, b'{"status":"weird"}', None, "error"),
    (200, b"not-json", None, "error"),
    (302, b"", None, "error"),
    (401, b"{}", None, "error"),
    (400, b"{}", None, "error"),
    (500, b"{}", None, "error"),
    (None, None, ConnectionError("reset"), "error"),
    (None, None, TimeoutError("timeout"), "error"),
]


def test_both_tiers_classify_every_response_identically():
    """FP-IG-8 / UT-IG-7: both classifiers agree with the fixed table."""
    for status, body, err, expected in CLASSIFIER_TABLE:
        a = ref.classify_response(status, body, err)
        b = e2e.classify_response(status, body, err)
        assert a == expected, f"ref: status={status} body={body!r} -> {a} want {expected}"
        assert b == expected, f"e2e: status={status} body={body!r} -> {b} want {expected}"
        assert a == b


# ---------------------------------------------------------------------------
# FP-IG-13
# ---------------------------------------------------------------------------

SHARED_CONSTANTS = {
    "BURST_RATE": 1000,
    "BURST_SECONDS": 30,
    "BASE_RATE": 200,
    "P99_MS": 150.0,
    "SUSTAINED_FLOOR": 200,
    "MAX_IN_FLIGHT": 1000,
}

# Timeout / keepalive must equal float(BURST_SECONDS) → 30.0 (FP-IG-13 / C4).
_TIMEOUT_DERIVED_VALUE = 30.0
_TIMEOUT_CONSTANTS = ("KEEPALIVE_EXPIRY", "CLIENT_TIMEOUT")


def _module_assigns(path: Path) -> dict[str, ast.AST]:
    return _source_assigns(path.read_text(encoding="utf-8"))


def _source_assigns(src: str) -> dict[str, ast.AST]:
    tree = ast.parse(src)
    out = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name):
                out[t.id] = node.value
        # GC-3: the per-model declaration maps carry an annotation, so an
        # Assign-only reader would silently report them as "missing" -- which
        # is exactly the shape of a pin that passes for the wrong reason.
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            if isinstance(node.target, ast.Name):
                out[node.target.id] = node.value
    return out


def _is_float_of_name(node: ast.AST, name: str) -> bool:
    """True iff ``float(<name>)``."""
    if not isinstance(node, ast.Call):
        return False
    func = node.func
    if not (isinstance(func, ast.Name) and func.id == "float"):
        return False
    if len(node.args) != 1 or node.keywords:
        return False
    arg = node.args[0]
    return isinstance(arg, ast.Name) and arg.id == name


def _eval_simple_constant(node: ast.AST, assigns: dict[str, ast.AST]) -> object:
    """Evaluate a small closed set of constant / derived module expressions."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name) and node.id in assigns:
        return _eval_simple_constant(assigns[node.id], assigns)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mult):
        left = _eval_simple_constant(node.left, assigns)
        right = _eval_simple_constant(node.right, assigns)
        if isinstance(left, (int, float)) and isinstance(right, (int, float)):
            return left * right
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name) and func.id == "float" and len(node.args) == 1:
            inner = _eval_simple_constant(node.args[0], assigns)
            if isinstance(inner, (int, float)):
                return float(inner)
        if isinstance(func, ast.Name) and func.id == "int" and len(node.args) == 1:
            # int(a * b / c) style used by PROLOGUE / SATURATION — not required here.
            pass
    raise AssertionError(f"cannot evaluate pin expression: {ast.dump(node)}")


def _has_environ_read(path: Path) -> bool:
    return _source_has_environ_read(path.read_text(encoding="utf-8"))


def _source_has_environ_read(src: str) -> bool:
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr in ("environ", "getenv"):
            if isinstance(node.value, ast.Name) and node.value.id == "os":
                return True
        if isinstance(node, ast.Call):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "getenv":
                return True
            if isinstance(f, ast.Name) and f.id == "getenv":
                return True
    return False


def _call_kwargs(call: ast.Call) -> dict[str, ast.AST]:
    return {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}


def _const_or_name(node: ast.AST) -> object:
    """Return a Constant value, or a Name id string, for pin comparison."""
    if isinstance(node, ast.Constant):
        return node.value
    if isinstance(node, ast.Name):
        return ("name", node.id)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) and isinstance(
        node.operand, ast.Constant
    ):
        return -node.operand.value
    raise AssertionError(f"unsupported pin expression: {ast.dump(node)}")


# ---------------------------------------------------------------------------
# FP-B1DF-3 — the copied raw-client block, its pins, and the no-scan shape.
# The block replaces the FP-IG-13 HTTPX/httpcore surface (design slice
# b1-driver-fix §3.4): what is pinned is now B1's own client, not HTTPX's
# construction arguments.
# ---------------------------------------------------------------------------

RAW_BEGIN = "# B1-RAW-CLIENT:BEGIN"
RAW_END = "# B1-RAW-CLIENT:END"

# Imports the copied block needs; identical in both driver modules (§3.4).
_RAW_REQUIRED_IMPORTS = (
    "import asyncio",
    "from collections import OrderedDict",
    "from dataclasses import dataclass",
    "from urllib.parse import urlsplit",
)
_RAW_FORBIDDEN_MODULES = ("httpx", "httpcore")
_RAW_RETIRED_CLASSES = ("B1ReservationPool", "B1ReservationTransport")
_RAW_REQUIRED_CLASSES = (
    "B1HttpResponse",
    "B1ProtocolError",
    "B1PoolSnapshot",
    "B1RawHttp11Client",
)
# The compatibility factory's construction, pinned argument by argument.
_RAW_FACTORY_PINS = {
    "max_connections": ("name", "max_connections"),
    "timeout": ("name", "CLIENT_TIMEOUT"),
    "keepalive_expiry": ("name", "KEEPALIVE_EXPIRY"),
    "http_version": "HTTP/1.1",
    "retries": 0,
    "follow_redirects": False,
    "trust_env": False,
}
# Capacity validation must precede construction, exactly as before.
_RAW_CAPACITY_GUARDS = (
    "isinstance(max_connections, bool)",
    "isinstance(max_connections, int)",
    "max_connections <= 0",
)
# The four populations FP-B1DF-1 forbids the request path to scan.
_POPULATION_ATTRS = ("_connections", "_idle", "_requests", "_waiters")
_SCAN_BUILTINS = frozenset(
    {
        "any", "all", "next", "sorted", "min", "max", "sum", "list", "tuple",
        "set", "frozenset", "filter", "map", "reversed", "enumerate", "zip",
        "iter",
    }
)
# Entered per request; everything reachable from here is the request path.
_REQUEST_PATH_ROOT = "post"


def _raw_block(path: Path, src: str) -> str:
    """Return the byte range between the two raw-client markers."""
    assert src.count(RAW_BEGIN) == 1, (
        f"{path.name}: raw-client marker {RAW_BEGIN} must appear exactly once"
    )
    assert src.count(RAW_END) == 1, (
        f"{path.name}: raw-client marker {RAW_END} must appear exactly once"
    )
    start = src.index(RAW_BEGIN)
    end = src.index(RAW_END) + len(RAW_END)
    assert start < end, f"{path.name}: raw-client markers are inverted"
    return src[start:end]


def _module_imports(src: str) -> set[str]:
    out: set[str] = set()
    for node in ast.parse(src).body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            out.add(ast.unparse(node))
    return out


def _imported_module_roots(src: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _references_population(node: ast.AST) -> str | None:
    """Name of the first of the four populations this expression touches."""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Attribute) and sub.attr in _POPULATION_ATTRS:
            return sub.attr
    return None


def _is_drain_step(stmt: ast.AST, attr: str) -> bool:
    """True for ``x = self.<attr>.pop*(...)`` — removal, never a scan."""
    if not isinstance(stmt, (ast.Assign, ast.AnnAssign)):
        return False
    value = stmt.value
    if not isinstance(value, ast.Call) or not isinstance(value.func, ast.Attribute):
        return False
    if value.func.attr not in ("pop", "popitem"):
        return False
    target = value.func.value
    return isinstance(target, ast.Attribute) and target.attr == attr


def _assert_no_population_scan(path: Path, where: str, fn: ast.AST) -> None:
    """FP-B1DF-1: no request-path operation iterates a population collection."""
    for sub in ast.walk(fn):
        if isinstance(sub, ast.For):
            attr = _references_population(sub.iter)
            assert attr is None, (
                f"{path.name}: request-path scan over self.{attr} "
                f"in {where} (for loop)"
            )
        elif isinstance(sub, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            for generator in sub.generators:
                attr = _references_population(generator.iter)
                assert attr is None, (
                    f"{path.name}: request-path scan over self.{attr} "
                    f"in {where} (comprehension)"
                )
        elif isinstance(sub, ast.While):
            attr = _references_population(sub.test)
            if attr is not None:
                assert sub.body and _is_drain_step(sub.body[0], attr), (
                    f"{path.name}: request-path scan over self.{attr} "
                    f"in {where} (while loop that does not drain it)"
                )
        elif isinstance(sub, ast.Call):
            func = sub.func
            if isinstance(func, ast.Name) and func.id in _SCAN_BUILTINS:
                attr = _references_population(sub)
                assert attr is None, (
                    f"{path.name}: request-path scan over self.{attr} "
                    f"in {where} (builtin {func.id})"
                )
            if isinstance(func, ast.Attribute) and func.attr in ("values", "items", "keys"):
                attr = _references_population(func.value)
                assert attr is None, (
                    f"{path.name}: request-path scan over self.{attr} "
                    f"in {where} (dict view)"
                )


def _request_path_functions(
    tree: ast.Module, cls: ast.ClassDef
) -> dict[str, ast.AST]:
    """Transitive closure of ``post`` over self-methods and module helpers."""
    methods = {
        n.name: n
        for n in cls.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    module_fns = {
        n.name: n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    assert _REQUEST_PATH_ROOT in methods, "raw client has no post() entry point"
    resolved: dict[str, ast.AST] = {}
    pending = [(_REQUEST_PATH_ROOT, methods[_REQUEST_PATH_ROOT])]
    while pending:
        name, fn = pending.pop()
        if name in resolved:
            continue
        resolved[name] = fn
        for sub in ast.walk(fn):
            if not isinstance(sub, ast.Call):
                continue
            func = sub.func
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id == "self"
                and func.attr in methods
            ):
                pending.append((func.attr, methods[func.attr]))
            elif isinstance(func, ast.Name) and func.id in module_fns:
                pending.append((func.id, module_fns[func.id]))
    return resolved


def _assert_raw_client_pinned(path: Path, src: str) -> None:
    """Pin the raw client's identity, factory arguments and request-path shape."""
    block = _raw_block(path, src)
    tree = ast.parse(src)

    imports = _module_imports(src)
    for required in _RAW_REQUIRED_IMPORTS:
        assert any(line.startswith(required) for line in imports), (
            f"{path.name}: raw-client import missing: {required}"
        )
    for forbidden in _RAW_FORBIDDEN_MODULES:
        assert forbidden not in _imported_module_roots(src), (
            f"{path.name}: forbidden client dependency imported: {forbidden}"
        )

    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    for retired in _RAW_RETIRED_CLASSES:
        assert retired not in classes, (
            f"{path.name}: retired reservation subclass is back: {retired}"
        )
    for required in _RAW_REQUIRED_CLASSES:
        assert required in classes, f"{path.name}: raw-client class missing: {required}"
        assert f"class {required}" in block, (
            f"{path.name}: raw-client class {required} is outside the marked block"
        )

    factory = next(
        (
            n
            for n in tree.body
            if isinstance(n, ast.FunctionDef) and n.name == "build_httpx_client"
        ),
        None,
    )
    assert factory is not None, f"{path.name}: compatibility factory missing"
    assert "def build_httpx_client" in block, (
        f"{path.name}: the factory is outside the marked block"
    )
    assert [a.arg for a in factory.args.kwonlyargs] == ["max_connections"], (
        f"{path.name}: the factory must take keyword-only max_connections"
    )
    body = factory.body
    if (
        isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]  # the factory's own docstring, never a guard
    guard = body[0]
    assert isinstance(guard, ast.If), (
        f"{path.name}: factory validation must precede construction"
    )
    guard_src = ast.unparse(guard.test)
    for fragment in _RAW_CAPACITY_GUARDS:
        assert fragment in guard_src, (
            f"{path.name}: factory capacity validation lost {fragment!r}"
        )
    raised = guard.body[0]
    assert isinstance(raised, ast.Raise) and isinstance(raised.exc, ast.Call), (
        f"{path.name}: factory capacity validation must raise"
    )
    assert _call_func_name(raised.exc) == "ValueError", (
        f"{path.name}: factory capacity validation must raise ValueError"
    )

    constructions = [
        n
        for n in ast.walk(factory)
        if isinstance(n, ast.Call) and _call_func_name(n) == "B1RawHttp11Client"
    ]
    assert len(constructions) == 1, (
        f"{path.name}: the factory must construct exactly one raw client, "
        f"got {len(constructions)}"
    )
    call = constructions[0]
    assert not call.args, f"{path.name}: the raw client takes keyword arguments only"
    kwargs = _call_kwargs(call)
    assert set(kwargs) == set(_RAW_FACTORY_PINS), (
        f"{path.name}: raw-client factory pin set is "
        f"{sorted(kwargs)}, want {sorted(_RAW_FACTORY_PINS)}"
    )
    for key, expected in _RAW_FACTORY_PINS.items():
        bound = _const_or_name(kwargs[key])
        assert bound == expected, (
            f"{path.name}: raw-client factory pin {key}={bound!r} want {expected!r}"
        )

    assert not _source_has_environ_read(src), (
        f"{path.name} reads os.environ/getenv"
    )

    client_class = classes["B1RawHttp11Client"]
    origin = next(
        (
            n
            for n in client_class.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name == "_bind_origin"
        ),
        None,
    )
    assert origin is not None, f"{path.name}: the client has no origin binding"
    origin_src = ast.unparse(origin)
    assert "self._origin" in origin_src and "raise ValueError" in origin_src, (
        f"{path.name}: the client must pin a single origin"
    )
    assert any(
        isinstance(n, ast.Compare)
        and any(isinstance(op, ast.NotEq) for op in n.ops)
        and "self._origin" in ast.unparse(n)
        for n in ast.walk(origin)
    ), f"{path.name}: a second origin is accepted by _bind_origin"

    for name, fn in _request_path_functions(tree, client_class).items():
        _assert_no_population_scan(path, f"B1RawHttp11Client.{name}", fn)


def _assert_raw_blocks_identical(ref_src: str, e2e_src: str) -> None:
    """FP-B1DF-3: the two copied blocks are byte-identical."""
    ref_block = _raw_block(REF_PATH, ref_src)
    e2e_block = _raw_block(E2E_PATH, e2e_src)
    assert ref_block == e2e_block, (
        "raw-client block drift between the reference and e2e driver copies"
    )


def _assert_timeout_constants_pinned(path: Path, assigns: dict[str, ast.AST]) -> None:
    """Pin CLIENT_TIMEOUT / KEEPALIVE_EXPIRY value and derivation (C4)."""
    for name in _TIMEOUT_CONSTANTS:
        assert name in assigns, f"{path.name} missing {name}"
        node = assigns[name]
        assert _is_float_of_name(node, "BURST_SECONDS"), (
            f"{path.name}.{name} must be float(BURST_SECONDS), got {ast.dump(node)}"
        )
        value = _eval_simple_constant(node, assigns)
        assert value == _TIMEOUT_DERIVED_VALUE, (
            f"{path.name}.{name}={value!r} want {_TIMEOUT_DERIVED_VALUE}"
        )


# Enclosing phase function → (required max_connections name, expected call count).
# design.md §11.3.3 H / FP-IG-13: reference + e2e baseline use max_in_flight;
# e2e saturation uses clients. A bare union of both names is not a pin.
_PHASE_CAPACITY_BY_FILE: dict[str, dict[str, tuple[str, int]]] = {
    "b1_reference_profile.py": {
        "run_open_loop": ("max_in_flight", 1),
    },
    "b1_e2e_profile.py": {
        "run_open_loop_baseline": ("max_in_flight", 1),
        "run_closed_loop_saturation": ("clients", 1),
    },
}


def _call_func_name(call: ast.Call) -> str | None:
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _build_httpx_client_calls_in(fn: ast.AST) -> list[ast.Call]:
    out: list[ast.Call] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and _call_func_name(node) == "build_httpx_client":
            out.append(node)
    return out


def _assert_phase_capacity_bindings(path: Path, src: str) -> None:
    """Every build_httpx_client call must pass its enclosing phase's capacity (C2).

    Reference open-loop / e2e baseline: max_connections=max_in_flight.
    E2e saturation: max_connections=clients.
    Each mapped phase function has an exact required argument and call cardinality;
    calls outside the map, wrong names, or wrong counts are red.
    """
    expected = _PHASE_CAPACITY_BY_FILE.get(path.name)
    assert expected is not None, f"{path.name}: no phase-capacity map registered"

    tree = ast.parse(src)
    found: dict[str, list[ast.Call]] = {name: [] for name in expected}
    extras: list[str] = []

    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Module-level build_httpx_client is never a phase binding.
            for call in _build_httpx_client_calls_in(node):
                extras.append("<module>")
            continue
        calls = _build_httpx_client_calls_in(node)
        if node.name in found:
            found[node.name].extend(calls)
        else:
            for _ in calls:
                extras.append(node.name)

    assert not extras, (
        f"{path.name}: build_httpx_client outside mapped phase functions: {extras}"
    )

    for fname, (required_arg, cardinality) in expected.items():
        calls = found[fname]
        assert len(calls) == cardinality, (
            f"{path.name}.{fname}: expected {cardinality} build_httpx_client "
            f"call(s), got {len(calls)}"
        )
        for call in calls:
            kwargs = _call_kwargs(call)
            assert "max_connections" in kwargs, (
                f"{path.name}.{fname}: build_httpx_client missing max_connections="
            )
            bound = _const_or_name(kwargs["max_connections"])
            assert bound == ("name", required_arg), (
                f"{path.name}.{fname}: max_connections={bound} "
                f"want ('name', {required_arg!r})"
            )


def test_b1_harness_surface_is_pinned_and_environment_independent():
    """FP-B1DF-3: constants, no env reads, raw-client pin on every surface.

    Re-pinned, not renamed: the shared-constant, timeout-derivation,
    no-environment and phase-capacity checks are the ones FP-IG-13 always
    made; only the client identity they are made against has changed from
    HTTPX/httpcore to the copied raw block (slice §3.4).
    """
    sources = {path: path.read_text(encoding="utf-8") for path in (REF_PATH, E2E_PATH)}
    _assert_raw_blocks_identical(sources[REF_PATH], sources[E2E_PATH])
    # Profile modules: full pin + no env.
    for path in (REF_PATH, E2E_PATH):
        assigns = _module_assigns(path)
        for name, expected in SHARED_CONSTANTS.items():
            assert name in assigns, f"{path.name} missing {name}"
            # evaluate simple constants
            node = assigns[name]
            if isinstance(node, ast.Constant):
                assert node.value == expected, f"{path.name}.{name}={node.value}"
            elif name == "MAX_IN_FLIGHT":
                # Must be Name(BURST_RATE) or the literal 1000.
                val = _eval_simple_constant(node, assigns)
                assert val == expected, f"{path.name}.{name}={val}"
        # Timeout / keepalive full assignment inventory (C4 remaining gap).
        _assert_timeout_constants_pinned(path, assigns)
        text = path.read_text(encoding="utf-8")
        assert "E2E_B1_CONCURRENCY" not in text
        if path == REF_PATH:
            assert "INGEST_GATEWAY_WORKERS" in assigns, (
                "reference profile missing INGEST_GATEWAY_WORKERS"
            )
            node = assigns["INGEST_GATEWAY_WORKERS"]
            assert isinstance(node, ast.Constant) and node.value == 4, (
                f"INGEST_GATEWAY_WORKERS={getattr(node, 'value', node)}"
            )
        assert not _has_environ_read(path), f"{path} reads os.environ/getenv"
        _assert_raw_client_pinned(path, text)
        _assert_phase_capacity_bindings(path, text)
        # The run functions keep taking an injected client, now annotated as
        # the raw client (§3.4's four annotation-only edits).
        assert "B1RawHttp11Client | None" in text, (
            f"{path.name}: injected-client annotation was not migrated"
        )

    # Actual B1 harness test modules: no profile overrides via env, and the
    # e2e link must not read os.environ at all (review C4). The reference
    # benchmark may set a child-process env for the gateway under test —
    # that is process management, not a B1 surface override — but may not
    # read B1 profile knobs from the environment.
    for path in (REF_TEST, E2E_TEST):
        text = path.read_text(encoding="utf-8")
        assert "E2E_B1_CONCURRENCY" not in text
    assert not _has_environ_read(E2E_TEST), f"{E2E_TEST} reads os.environ/getenv"
    # Reference test must not *read* getenv for profile control; writing
    # DBAGENT_GATEWAY_CONFIG into a child env is allowed.
    ref_test_src = REF_TEST.read_text(encoding="utf-8")
    assert "getenv" not in ref_test_src
    assert "os.environ.get" not in ref_test_src


def _raw_surface_checks(path: Path, src: str) -> None:
    """Every single-file pin the raw-client surface carries (§3.4)."""
    _assert_timeout_constants_pinned(path, _source_assigns(src))
    _assert_raw_client_pinned(path, src)
    _assert_phase_capacity_bindings(path, src)


# Independent negative fixtures (§3.4): each removes or changes exactly one
# pin and must fail for its own named reason, never for a neighbour's.
_RAW_BLOCK_MUTATIONS: list[tuple[str, Path, str, str, str]] = [
    # (id, path, old, new, expected reason fragment)
    (
        "factory_omits_timeout",
        REF_PATH,
        "        max_connections=max_connections,\n        timeout=CLIENT_TIMEOUT,\n",
        "        max_connections=max_connections,\n",
        "raw-client factory pin set is",
    ),
    (
        "factory_omits_keepalive_expiry",
        REF_PATH,
        "        keepalive_expiry=KEEPALIVE_EXPIRY,\n",
        "",
        "raw-client factory pin set is",
    ),
    (
        "factory_omits_capacity",
        REF_PATH,
        "        max_connections=max_connections,\n        timeout=CLIENT_TIMEOUT,",
        "        timeout=CLIENT_TIMEOUT,",
        "raw-client factory pin set is",
    ),
    (
        "factory_adds_a_proxy_argument",
        REF_PATH,
        "        trust_env=False,\n    )",
        '        trust_env=False,\n        proxy="http://proxy.invalid",\n    )',
        "raw-client factory pin set is",
    ),
    (
        "timeout_weakened_to_a_literal",
        REF_PATH,
        "        max_connections=max_connections,\n        timeout=CLIENT_TIMEOUT,",
        "        max_connections=max_connections,\n        timeout=0.001,",
        "raw-client factory pin timeout=",
    ),
    (
        "keepalive_expiry_weakened_to_a_literal",
        REF_PATH,
        "        keepalive_expiry=KEEPALIVE_EXPIRY,",
        "        keepalive_expiry=0.001,",
        "raw-client factory pin keepalive_expiry=",
    ),
    (
        "capacity_weakened_to_a_literal",
        REF_PATH,
        "        max_connections=max_connections,\n        timeout=CLIENT_TIMEOUT,",
        "        max_connections=1,\n        timeout=CLIENT_TIMEOUT,",
        "raw-client factory pin max_connections=",
    ),
    (
        "protocol_downgraded_to_http10",
        REF_PATH,
        '        http_version="HTTP/1.1",',
        '        http_version="HTTP/1.0",',
        "raw-client factory pin http_version=",
    ),
    (
        "one_retry_allowed",
        REF_PATH,
        "        retries=0,",
        "        retries=1,",
        "raw-client factory pin retries=",
    ),
    (
        "redirects_followed",
        REF_PATH,
        "        follow_redirects=False,",
        "        follow_redirects=True,",
        "raw-client factory pin follow_redirects=",
    ),
    (
        "environment_trusted",
        REF_PATH,
        "        trust_env=False,\n    )",
        "        trust_env=True,\n    )",
        "raw-client factory pin trust_env=",
    ),
    (
        "client_timeout_constant_weakened",
        REF_PATH,
        "CLIENT_TIMEOUT = float(BURST_SECONDS)",
        "CLIENT_TIMEOUT = 0.001",
        "must be float(BURST_SECONDS)",
    ),
    (
        "keepalive_expiry_constant_weakened",
        REF_PATH,
        "KEEPALIVE_EXPIRY = float(BURST_SECONDS)",
        "KEEPALIVE_EXPIRY = 0.001",
        "must be float(BURST_SECONDS)",
    ),
    (
        "capacity_validation_weakened",
        REF_PATH,
        "        or max_connections <= 0\n    ):\n        raise ValueError",
        "        or max_connections < -1\n    ):\n        raise ValueError",
        "factory capacity validation lost 'max_connections <= 0'",
    ),
    (
        "reservation_pool_restored",
        REF_PATH,
        "class B1RawHttp11Client:",
        "class B1ReservationPool:\n    pass\n\n\nclass B1RawHttp11Client:",
        "retired reservation subclass is back: B1ReservationPool",
    ),
    (
        "httpx_dependency_reintroduced",
        REF_PATH,
        "import asyncio\nimport json",
        "import asyncio\nimport httpx\nimport json",
        "forbidden client dependency imported: httpx",
    ),
    (
        "block_import_dropped",
        REF_PATH,
        "from collections import OrderedDict\n",
        "",
        "raw-client import missing: from collections import OrderedDict",
    ),
    (
        "environment_read_added",
        REF_PATH,
        "        self._closed = False\n",
        '        self._closed = bool(os.environ.get("B1_CLIENT_CLOSED"))\n',
        "reads os.environ/getenv",
    ),
    (
        "second_origin_allowed",
        REF_PATH,
        "        elif origin != self._origin:\n"
        '            raise ValueError(f"client is bound to {self._origin}, got {origin}")\n',
        "        elif origin == self._origin:\n            pass\n",
        "a second origin is accepted by _bind_origin",
    ),
    (
        "acquire_scans_the_connections",
        REF_PATH,
        "        if len(self._connections) < self._max_connections:",
        "        if len([c for c in self._connections.values()]) < self._max_connections:",
        "request-path scan over self._connections "
        "in B1RawHttp11Client._checkout (comprehension)",
    ),
    (
        "release_scans_the_idle_connections",
        REF_PATH,
        "        if self._give_to_waiter(conn):",
        "        for _parked in self._idle.values():\n"
        "            _parked.cid\n"
        "        if self._give_to_waiter(conn):",
        "request-path scan over self._idle in B1RawHttp11Client._recycle (for loop)",
    ),
    (
        "drop_scans_through_a_builtin",
        REF_PATH,
        "        self._connections.pop(conn.cid, None)",
        "        next(iter(self._connections), None)\n"
        "        self._connections.pop(conn.cid, None)",
        "request-path scan over self._connections in B1RawHttp11Client._drop",
    ),
    (
        "waiter_loop_stops_draining",
        REF_PATH,
        "            request_id, waiter = self._waiters.popitem(last=False)\n"
        "            if waiter.done():",
        "            request_id, waiter = self._oldest_waiter()\n"
        "            if waiter.done():",
        "request-path scan over self._waiters "
        "in B1RawHttp11Client._give_to_waiter (while loop that does not drain it)",
    ),
    (
        "snapshot_pulled_onto_the_request_path",
        REF_PATH,
        "        return B1HttpResponse(status_code, body)",
        "        self.pool_snapshot()\n        return B1HttpResponse(status_code, body)",
        "request-path scan over self._requests in B1RawHttp11Client.pool_snapshot",
    ),
    (
        "end_marker_removed",
        REF_PATH,
        "# B1-RAW-CLIENT:END\n",
        "",
        f"raw-client marker {RAW_END} must appear exactly once",
    ),
    (
        "phase_capacity_replaced_by_a_literal",
        REF_PATH,
        "client = build_httpx_client(max_connections=max_in_flight)",
        "client = build_httpx_client(max_connections=1)",
        "want ('name', 'max_in_flight')",
    ),
    (
        "e2e_copy_changed_alone",
        E2E_PATH,
        "        # The four populations. No request-path helper iterates any of them.\n",
        "        # The four populations.\n",
        "raw-client block drift between the reference and e2e driver copies",
    ),
]


@pytest.mark.parametrize(
    "mutation_id,path,old,new,reason",
    _RAW_BLOCK_MUTATIONS,
    ids=[m[0] for m in _RAW_BLOCK_MUTATIONS],
)
def test_b1_raw_client_blocks_reject_independent_mutations(
    mutation_id: str, path: Path, old: str, new: str, reason: str
):
    """FP-B1DF-3 negative: every pin, copy and no-scan rule fails on its own."""
    sources = {p: p.read_text(encoding="utf-8") for p in (REF_PATH, E2E_PATH)}
    assert old in sources[path], f"anchor for {mutation_id} missing from {path.name}"
    mutated = sources[path].replace(old, new, 1)
    assert mutated != sources[path], f"failed to apply {mutation_id}"
    sources[path] = mutated

    with pytest.raises(AssertionError) as exc:
        # Single-file surface first, then cross-copy identity, so a mutation
        # of one copy is reported as its own defect rather than as drift.
        _raw_surface_checks(path, mutated)
        _assert_raw_blocks_identical(sources[REF_PATH], sources[E2E_PATH])
    assert reason in str(exc.value), (
        f"{mutation_id} failed for the wrong reason: {exc.value}"
    )


# Phase-capacity mutations (C2 / FP-IG-13): each enclosing phase is pinned to
# exactly one argument. Swapping max_in_flight ↔ clients, or replacing either
# with a literal, must go red at every call site. The reference swap mirrors
# the reviewer's standing mutation (clients = 1; max_connections=clients).
_PHASE_CAPACITY_MUTATIONS: list[tuple[str, Path, str, str]] = [
    (
        "ref_open_loop_swap_to_clients",
        REF_PATH,
        "        client = build_httpx_client(max_connections=max_in_flight)\n",
        "        clients = 1\n"
        "        client = build_httpx_client(max_connections=clients)\n",
    ),
    (
        "ref_open_loop_value_literal",
        REF_PATH,
        "client = build_httpx_client(max_connections=max_in_flight)",
        "client = build_httpx_client(max_connections=1)",
    ),
    (
        "e2e_baseline_swap_to_clients",
        E2E_PATH,
        "client = build_httpx_client(max_connections=max_in_flight)",
        "client = build_httpx_client(max_connections=clients)",
    ),
    (
        "e2e_baseline_value_literal",
        E2E_PATH,
        "client = build_httpx_client(max_connections=max_in_flight)",
        "client = build_httpx_client(max_connections=1)",
    ),
    (
        "e2e_saturation_swap_to_max_in_flight",
        E2E_PATH,
        "client = build_httpx_client(max_connections=clients)",
        "client = build_httpx_client(max_connections=max_in_flight)",
    ),
    (
        "e2e_saturation_value_literal",
        E2E_PATH,
        "client = build_httpx_client(max_connections=clients)",
        "client = build_httpx_client(max_connections=1)",
    ),
]


@pytest.mark.parametrize(
    "mutation_id,path,old,new",
    _PHASE_CAPACITY_MUTATIONS,
    ids=[m[0] for m in _PHASE_CAPACITY_MUTATIONS],
)
def test_fp_ig13_guard_rejects_phase_capacity_swap_or_value(
    mutation_id: str, path: Path, old: str, new: str
):
    """FP-IG-13 / C2: phase-capacity swap or value mutation is red at every site."""
    src = path.read_text(encoding="utf-8")
    assert old in src, f"anchor for {mutation_id} missing from {path.name}"
    mutated = src.replace(old, new, 1)
    assert mutated != src, f"failed to apply {mutation_id}"
    try:
        _assert_phase_capacity_bindings(path, mutated)
    except AssertionError:
        return  # expected red
    raise AssertionError(
        f"phase-capacity mutation {mutation_id} still passed the phase pin"
    )


# ---------------------------------------------------------------------------
# FP-IG-14 / FP-IG-15 — behavioural, stub transport
# ---------------------------------------------------------------------------


class StubTransport:
    def __init__(self, delay_s: float = 0.0, fail_after: int | None = None):
        self.delay_s = delay_s
        self.fail_after = fail_after
        self.calls = 0
        self.dispatch_times: list[float] = []

    async def post(self, url, *, content, headers):
        self.dispatch_times.append(time.perf_counter())
        self.calls += 1
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        if self.fail_after is not None and self.calls > self.fail_after:
            return None, None, TimeoutError("boom")
        return 202, b'{"investigation_id":"x"}', None


@pytest.mark.asyncio
async def test_reference_generator_is_open_loop_with_due_time_latency():
    """FP-IG-14."""
    n = 20
    rate = 50
    transport = StubTransport(delay_s=0.05)
    reqs = [(b"{}", {"Content-Type": "application/json"}) for _ in range(n)]
    t0 = time.perf_counter()
    result = await ref.run_open_loop(
        endpoint="http://stub/events",
        requests=reqs,
        rate=rate,
        transport=transport,
        max_in_flight=100,
        prologue=None,
        include_sync_warmup=False,
    )
    # No dispatch before due
    for i, dt in enumerate(transport.dispatch_times):
        due = t0 + i / rate
        assert dt + 1e-3 >= due, f"request {i} dispatched early: {dt} < {due}"
    assert result.offered == n
    assert len(result.latencies_ms) == n
    # p99 rises with delay
    assert result.p99 >= 40.0

    # Prologue excluded: pathologically slow prologue, fast measured window
    class SplitTransport:
        def __init__(self):
            self.n = 0
            self.inner_slow = StubTransport(delay_s=0.3)
            self.inner_fast = StubTransport(delay_s=0.01)

        async def post(self, url, *, content, headers):
            self.n += 1
            if self.n <= 1 + 5:  # warmup + 5 prologue
                return await self.inner_slow.post(url, content=content, headers=headers)
            return await self.inner_fast.post(url, content=content, headers=headers)

    split = SplitTransport()
    warmup = (b'{"w":1}', {})
    prologue = [(f'{{"p":{i}}}'.encode(), {}) for i in range(5)]
    reqs2 = [(f'{{"m":{i}}}'.encode(), {}) for i in range(10)]
    result2 = await ref.run_open_loop(
        endpoint="http://stub/events",
        requests=reqs2,
        rate=100,
        transport=split,
        max_in_flight=100,
        warmup=warmup,
        prologue=prologue,
        include_sync_warmup=True,
    )
    assert result2.offered == 10
    assert result2.served == 10
    assert result2.p99 < 100  # measured window is fast


@pytest.mark.asyncio
async def test_e2e_generator_baseline_is_open_loop_and_burst_is_closed_loop_saturation():
    """FP-IG-15."""
    n = 20
    transport = StubTransport(delay_s=0.02)
    reqs = [(b"{}", {}) for _ in range(n)]
    result = await e2e.run_open_loop_baseline(
        endpoint="http://stub/events",
        requests=reqs,
        transport=transport,
        rate=50,
        prologue=None,
        max_in_flight=100,
        include_sync_warmup=False,
    )
    assert result.offered == n
    assert result.phase == "baseline"
    assert result.errors == 0

    counter = {"i": 0}

    def factory():
        counter["i"] += 1
        return b"{}", {}

    sat = await e2e.run_closed_loop_saturation(
        endpoint="http://stub/events",
        request_factory=factory,
        clients=5,
        duration_s=0.3,
        transport=StubTransport(delay_s=0.01),
    )
    assert sat.phase == "saturation"
    assert sat.offered > 0
    assert sat.max_in_flight <= 5
    # closed-loop: clients issue back-to-back — more than 5 requests in 0.3s
    assert sat.offered >= 5


def test_e2e_acceptance_matrix_matches_all_ten_cases_including_case10_divergence():
    """C6 / FP-IG-9: complete deterministic schedule inventory at BASE_RATE.

    All ten acceptance cases run against the e2e statistics/oracle. Case 10
    (``round6_dispatch_hold``) must **pass** at the e2e tier (no rate floor),
    diverging from the reference tier where it fails clause 6.
    """
    assert len(e2e.ACCEPTANCE_EXPECTED) == 10
    for name, expected in e2e.ACCEPTANCE_EXPECTED.items():
        verdict, fails = e2e.run_acceptance_case(name)
        assert verdict == expected, f"{name}: got {verdict} fails={fails}"
        matrix = e2e.run_acceptance_matrix(name)
        assert matrix["final"] == expected, f"{name} final={matrix}"
        s1, s2, s3, s4 = e2e.ACCEPTANCE_SUPERSEDED[name]
        assert matrix["form1"] == s1, f"{name} form1={matrix['form1']} want {s1}"
        assert matrix["form2"] == s2, f"{name} form2={matrix['form2']} want {s2}"
        assert matrix["form3"] == s3, f"{name} form3={matrix['form3']} want {s3}"
        assert matrix["form4"] == s4, f"{name} form4={matrix['form4']} want {s4}"

    # Explicit case-10 divergence from the reference profile.
    ref_verdict, _ = ref.run_acceptance_case("round6_dispatch_hold")
    e2e_verdict, _ = e2e.run_acceptance_case("round6_dispatch_hold")
    assert ref_verdict == "fail", "reference case 10 must fail the rate floor"
    assert e2e_verdict == "pass", "e2e case 10 must pass (no rate floor)"


# ---------------------------------------------------------------------------
# FP-IG-19 — assertion presence (reuses manifest checker seam)
# ---------------------------------------------------------------------------

# Import the *real* seam — not a reimplementation (C3 / design.md FP-IG-19).
import sys

_MANIFESTS_PATH = REPO_ROOT / "tests" / "functional" / "test_manifests.py"
_mspec = importlib.util.spec_from_file_location("test_manifests_seam", _MANIFESTS_PATH)
assert _mspec and _mspec.loader
_manifests = importlib.util.module_from_spec(_mspec)
sys.modules[_mspec.name] = _manifests
_mspec.loader.exec_module(_manifests)
_python_qualifying_comparison = _manifests._python_qualifying_comparison

# Ordering ∪ {Eq}: equality admitted only for B1 accounting clauses (call-site).
_ORDERING_OPS = (ast.Lt, ast.LtE, ast.Gt, ast.GtE)
_B1_OPS = _ORDERING_OPS + (ast.Eq,)


def _cmp_names(cmp: ast.Compare) -> set[str]:
    names: set[str] = set()
    for n in ast.walk(cmp):
        if isinstance(n, ast.Name):
            names.add(n.id)
        if isinstance(n, ast.Attribute):
            names.add(n.attr)
    return names


def _cmp_ops(cmp: ast.Compare) -> tuple[type, ...]:
    return tuple(type(op) for op in cmp.ops)


def _node_compare(node: ast.AST) -> ast.Compare | None:
    if isinstance(node, (ast.Assert, ast.If)) and isinstance(node.test, ast.Compare):
        return node.test
    return None


# GC-1 renamed the reference node and re-pointed the live fixture; both names
# are declared once so every pin below moves together.
CI_SCALE_REF_TEST = "test_b1_ci_scale_reference_profile"
PRODUCT_REF_TEST = "test_b1_product_exclusive_reference_profile"
CI_SCALE_FIXTURE = "b1_ci_scale_run"
PRODUCT_FIXTURE = "b1_product_run"
# GC-3 (FP-GC3-2): the discovery fixture. It is named here because the marker
# map identifies live consumers by PARAMETER NAME -- a new live fixture that
# this file does not know about is invisible to the map, which is exactly how
# an unmarked live node would end up inside the traced coverage phase.
PROBE_FIXTURE = "b1_topology_probe_run"
LIVE_RUN_IMPL = "_run_b1_reference"

# Exact nineteen-node FAILURE inventory. Each entry: (test_file, test_name,
# required_names, required_op_types or None, equality_admitted).
# Equality is admitted ONLY for B1 accounting clauses.
#
# e2e-b1-kind-policy: the kind due-time p99 comparison is NOT in this inventory
# because it can no longer fail anything. It is an observation, pinned by
# `_e2ebd_observation_failures` with its own exact bytes, signature, top-level
# node, five-way order and outcome-consumer rejection. Admitting the property
# call here would let a non-failing node be counted as a gate.
B1_FAILURE_INVENTORY: list[tuple[Path, str, frozenset[str], frozenset[type] | None, bool]] = [
    # --- FP-IG-7 / FP-GC1-1 CI-scale reference: 7 B1 clauses + max_in_flight = 8 ---
    # Renamed, not retired, by the GC-1 slice: same clauses, restated against
    # the CI-scale bar literals for the declared 2/1/1 CPU affinity allocation.
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"platform_online"}), frozenset({ast.Eq}), True),
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"served", "errors", "offered"}), frozenset({ast.Eq}), True),
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"errors"}), frozenset({ast.Eq}), True),
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"served", "offered"}), frozenset({ast.Eq}), True),
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"p99", "CI_SCALE_P99_MS"}), frozenset({ast.Lt}), False),
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"committed", "served"}), frozenset({ast.Eq}), True),
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"served_rate", "CI_SCALE_SUSTAINED_FLOOR"}), frozenset({ast.GtE}), False),
    (REF_TEST, CI_SCALE_REF_TEST, frozenset({"max_in_flight", "CI_SCALE_MAX_IN_FLIGHT"}), frozenset({ast.Lt}), False),
    # --- FP-IG-9 e2e: eleven failure clauses (clause 5's p99 is observational) ---
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"platform_online"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"served", "errors"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"errors"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"served"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"committed", "served"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"sat_served", "sat_errors", "issued"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"sat_errors"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"restart_delta"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"unhealthy_count"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"sat_committed", "sat_served"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"audit_actions"}), frozenset({ast.Eq}), True),
]


def _inventory_match(
    nodes: list[ast.AST],
    required_names: frozenset[str],
    required_ops: frozenset[type] | None,
    equality_admitted: bool,
    *,
    consumed: set[int] | None = None,
) -> int | None:
    """One-to-one exact operand-set match (C5 / FP-IG-19).

    A node matches only when its name set equals ``required_names`` exactly
    (no superset aliasing: ``{served, errors, offered}`` must not satisfy
    ``{errors}``) and ops agree. Each AST node may be consumed at most once
    so nineteen inventory entries require nineteen distinct assertions.
    Returns the matched node's id, or None.
    """
    for node in nodes:
        nid = id(node)
        if consumed is not None and nid in consumed:
            continue
        cmp = _node_compare(node)
        if cmp is None:
            continue
        names = _cmp_names(cmp)
        # Exact cardinality + membership — supersets do not alias.
        if names != required_names:
            continue
        ops = _cmp_ops(cmp)
        if any(op is ast.Eq for op in ops) and not equality_admitted:
            continue
        if required_ops is not None and not required_ops.intersection(ops):
            continue
        return nid
    return None


def _nodes_for(path: Path, test_name: str) -> list[ast.AST]:
    tree = ast.parse(path.read_text(encoding="utf-8"))

    def operand_rule(cmp: ast.Compare) -> bool:
        # Equality admitted only when the comparison's ops are pure Eq (accounting)
        # or pure ordering. Mixed chains are rejected.
        ops = _cmp_ops(cmp)
        if all(op is ast.Eq for op in ops):
            return True  # accounting — caller filters by inventory equality_admitted
        if all(op in _ORDERING_OPS for op in ops):
            return True
        return False

    return _python_qualifying_comparison(
        tree,
        test_name,
        operators=_B1_OPS,
        operand_rule=operand_rule,
    )


def _nodes_for_src(src: str, test_name: str) -> list[ast.AST]:
    tree = ast.parse(src)

    def operand_rule(cmp: ast.Compare) -> bool:
        ops = _cmp_ops(cmp)
        if all(op is ast.Eq for op in ops):
            return True
        if all(op in _ORDERING_OPS for op in ops):
            return True
        return False

    return _python_qualifying_comparison(
        tree,
        test_name,
        operators=_B1_OPS,
        operand_rule=operand_rule,
    )


def test_every_required_b1_assertion_is_present_in_both_tiers():
    """FP-IG-19: exact nineteen-node failure inventory via the shared seam."""
    assert len(B1_FAILURE_INVENTORY) == 19, f"inventory size {len(B1_FAILURE_INVENTORY)}"
    cache: dict[tuple[str, str], list[ast.AST]] = {}
    consumed_by_key: dict[tuple[str, str], set[int]] = {}
    for path, test_name, names, ops, eq_ok in B1_FAILURE_INVENTORY:
        key = (str(path), test_name)
        if key not in cache:
            cache[key] = _nodes_for(path, test_name)
            consumed_by_key[key] = set()
        nodes = cache[key]
        matched = _inventory_match(
            nodes, names, ops, eq_ok, consumed=consumed_by_key[key]
        )
        assert matched is not None, (
            f"missing qualifying comparison for {names} ops={ops} in {path.name}::{test_name}; "
            f"found {[ast.dump(_node_compare(n)) for n in nodes if _node_compare(n)]}"
        )
        consumed_by_key[key].add(matched)
    # Audit action set must exclude event_rejected (clause 12 content).
    assert "event_rejected" not in e2e.INGEST_AUDIT_ACTIONS


def _mutate_source(src: str, mutation: str) -> str:
    """Apply one of the eight required negative mutations (design.md FP-IG-19).

    Replacements target complete multi-line statement blocks so the mutated
    source remains parseable (the guard is AST-based).
    """
    if mutation == "accounting_deleted":
        # 1. served + errors == offered deleted (reference multi-line assert)
        old = (
            "    assert served + errors == offered, (\n"
            "        f\"served+errors!=offered {served}+{errors}!={offered}; "
            "{b1_ci_scale_run['fingerprint']}\"\n"
            "    )"
        )
        assert old in src, "accounting_deleted anchor missing"
        return src.replace(old, "    # mutated: served + errors == offered deleted", 1)
    if mutation == "platform_online_deleted":
        # 2. ONLINE precondition deleted (e2e multi-line assert)
        old = (
            "    assert platform_online == True, (  # noqa: E712 — named Eq for FP-IG-19\n"
            "        \"platform must be ONLINE before B1 load; refusing to measure the reject path\"\n"
            "    )"
        )
        assert old in src, "platform_online_deleted anchor missing"
        return src.replace(old, "    # mutated: platform_online deleted", 1)
    if mutation == "committed_weakened":
        # 3. committed == served weakened to >=
        old = (
            "    assert committed == served, (\n"
            "        f\"committed={committed} served={served}; "
            "{b1_ci_scale_run['fingerprint']}\"\n"
            "    )"
        )
        assert old in src, "committed_weakened anchor missing"
        return src.replace(
            old,
            "    assert committed >= served, (\n"
            "        f\"committed={committed} served={served}; "
            "{b1_ci_scale_run['fingerprint']}\"\n"
            "    )",
            1,
        )
    if mutation == "p99_deleted":
        # 4. p99 < CI_SCALE_P99_MS deleted
        old = "    assert p99 < CI_SCALE_P99_MS, f\"p99={p99}; {b1_ci_scale_run['fingerprint']}\""
        assert old in src, "p99_deleted anchor missing"
        return src.replace(old, "    # mutated: p99 < CI_SCALE_P99_MS deleted", 1)
    if mutation == "committed_bare_expression":
        # 5. assert committed == served → bare expression
        old = (
            "    assert committed == served, (\n"
            "        f\"committed={committed} served={served}; "
            "{b1_ci_scale_run['fingerprint']}\"\n"
            "    )"
        )
        assert old in src, "committed_bare_expression anchor missing"
        return src.replace(
            old,
            "    committed == served  # bare expression; cannot fail",
            1,
        )
    if mutation == "under_if_false":
        # 6. qualifying assertion moved under if False
        old = "    assert p99 < CI_SCALE_P99_MS, f\"p99={p99}; {b1_ci_scale_run['fingerprint']}\""
        assert old in src, "under_if_false anchor missing"
        return src.replace(
            old,
            "    if False:\n"
            "        assert p99 < CI_SCALE_P99_MS, f\"p99={p99}; {b1_ci_scale_run['fingerprint']}\"",
            1,
        )
    if mutation == "in_nested_def":
        # 7. qualifying assertion moved into uncalled nested def
        old = (
            "    assert served_rate >= CI_SCALE_SUSTAINED_FLOOR, (\n"
            "        f\"served_rate={served_rate}; {b1_ci_scale_run['fingerprint']}\"\n"
            "    )"
        )
        assert old in src, "in_nested_def anchor missing"
        return src.replace(
            old,
            "    def _hidden():\n"
            "        assert served_rate >= CI_SCALE_SUSTAINED_FLOOR, (\n"
            "            f\"served_rate={served_rate}; {b1_ci_scale_run['fingerprint']}\"\n"
            "        )\n"
            "    # nested not called",
            1,
        )
    if mutation == "rate_floor_deleted":
        # 8. served_rate >= CI_SCALE_SUSTAINED_FLOOR deleted
        old = (
            "    assert served_rate >= CI_SCALE_SUSTAINED_FLOOR, (\n"
            "        f\"served_rate={served_rate}; {b1_ci_scale_run['fingerprint']}\"\n"
            "    )"
        )
        assert old in src, "rate_floor_deleted anchor missing"
        return src.replace(old, "    # mutated: rate floor deleted", 1)
    raise ValueError(mutation)


# Eight mutations: (id, which file, which inventory names must go missing)
B1_NEGATIVE_MUTATIONS: list[tuple[str, Path, frozenset[str]]] = [
    ("accounting_deleted", REF_TEST, frozenset({"served", "errors", "offered"})),
    ("platform_online_deleted", E2E_TEST, frozenset({"platform_online"})),
    ("committed_weakened", REF_TEST, frozenset({"committed", "served"})),
    ("p99_deleted", REF_TEST, frozenset({"p99", "CI_SCALE_P99_MS"})),
    ("committed_bare_expression", REF_TEST, frozenset({"committed", "served"})),
    ("under_if_false", REF_TEST, frozenset({"p99", "CI_SCALE_P99_MS"})),
    ("in_nested_def", REF_TEST, frozenset({"served_rate", "CI_SCALE_SUSTAINED_FLOOR"})),
    ("rate_floor_deleted", REF_TEST, frozenset({"served_rate", "CI_SCALE_SUSTAINED_FLOOR"})),
]


@pytest.mark.parametrize(
    "mutation_id,path,required_names",
    B1_NEGATIVE_MUTATIONS,
    ids=[m[0] for m in B1_NEGATIVE_MUTATIONS],
)
def test_fp_ig19_guard_rejects_required_mutations(mutation_id, path, required_names):
    """FP-IG-19: each of the eight mutations is genuinely red against the guard."""
    src = path.read_text(encoding="utf-8")
    # Healthy source must currently match.
    test_name = CI_SCALE_REF_TEST if path == REF_TEST else "test_b1_ingest_burst_profile"
    healthy = _nodes_for(path, test_name)
    # Find the inventory entry for this mutation's names on this path.
    eq_ok = True
    ops = frozenset({ast.Eq})
    for p, tn, names, rops, eok in B1_FAILURE_INVENTORY:
        if p == path and names == required_names:
            ops = rops
            eq_ok = eok
            break
    # For p99 / rate floor use ordering ops. The kind e2e p99 row is gone
    # (55ddeff made that comparison an observation), so only the CI-scale
    # reference p99 is normalised here.
    if required_names == frozenset({"p99", "CI_SCALE_P99_MS"}):
        ops, eq_ok = frozenset({ast.Lt}), False
    if required_names == frozenset({"served_rate", "CI_SCALE_SUSTAINED_FLOOR"}):
        ops, eq_ok = frozenset({ast.GtE}), False

    assert _inventory_match(healthy, required_names, ops, eq_ok) is not None, (
        f"precondition: healthy source missing {required_names}"
    )

    mutated = _mutate_source(src, mutation_id)
    nodes = _nodes_for_src(mutated, test_name)
    # committed_weakened: Eq replaced by GtE — equality-admitted inventory must miss.
    if mutation_id == "committed_weakened":
        assert (
            _inventory_match(nodes, required_names, frozenset({ast.Eq}), True) is None
        ), f"{mutation_id} still matched Eq inventory"
        return
    assert _inventory_match(nodes, required_names, ops, eq_ok) is None, (
        f"{mutation_id} still matched inventory {required_names}; "
        f"nodes={[ast.dump(_node_compare(n)) for n in nodes if _node_compare(n)]}"
    )


# Standalone error / served deletion controls (C5): each must be one-to-one
# red; the broader accounting assertion must not alias them.
_STANDALONE_DELETIONS: list[tuple[str, Path, str, frozenset[str]]] = [
    (
        "ref_errors_eq_0",
        REF_TEST,
        '    assert errors == 0, f"errors={errors}; {b1_ci_scale_run[\'fingerprint\']}"',
        frozenset({"errors"}),
    ),
    (
        "ref_served_eq_offered",
        REF_TEST,
        '    assert served == offered, f"served={served}; {b1_ci_scale_run[\'fingerprint\']}"',
        frozenset({"served", "offered"}),
    ),
    (
        "e2e_errors_eq_0",
        E2E_TEST,
        "    assert errors == 0",
        frozenset({"errors"}),
    ),
    (
        "e2e_served_eq_6000",
        E2E_TEST,
        "    assert served == 6000",
        frozenset({"served"}),
    ),
    (
        "e2e_sat_errors_eq_0",
        E2E_TEST,
        '    assert sat_errors == 0, f"saturation errors={sat_errors}"',
        frozenset({"sat_errors"}),
    ),
    (
        "e2e_sat_served_accounting",
        E2E_TEST,
        "    assert sat_served + sat_errors == issued",
        frozenset({"sat_served", "sat_errors", "issued"}),
    ),
]


@pytest.mark.parametrize(
    "mutation_id,path,anchor,required_names",
    _STANDALONE_DELETIONS,
    ids=[m[0] for m in _STANDALONE_DELETIONS],
)
def test_fp_ig19_guard_rejects_standalone_error_and_served_deletion(
    mutation_id: str, path: Path, anchor: str, required_names: frozenset[str]
):
    """C5: deleting a standalone errors/served assert is red even when a
    broader accounting assert still names the same identifiers.
    """
    src = path.read_text(encoding="utf-8")
    assert anchor in src, f"anchor for {mutation_id} missing in {path.name}"
    test_name = CI_SCALE_REF_TEST if path == REF_TEST else "test_b1_ingest_burst_profile"
    healthy = _nodes_for(path, test_name)
    assert (
        _inventory_match(healthy, required_names, frozenset({ast.Eq}), True) is not None
    ), f"precondition: healthy source missing exact {required_names}"

    mutated = src.replace(anchor, f"    # mutated: deleted {mutation_id}", 1)
    assert mutated != src
    nodes = _nodes_for_src(mutated, test_name)
    assert _inventory_match(nodes, required_names, frozenset({ast.Eq}), True) is None, (
        f"{mutation_id}: deleting standalone assert still matched via alias; "
        f"nodes={[ast.dump(_node_compare(n)) for n in nodes if _node_compare(n)]}"
    )


def test_e2e_b1_profile_module_registers_before_exec():
    """C1 regression: loading b1_e2e_profile must not raise on Python 3.12 dataclasses."""
    import importlib.util as ilu

    path = REPO_ROOT / "tests" / "e2e" / "b1_e2e_profile.py"
    spec = ilu.spec_from_file_location("b1_e2e_profile_collection_probe", path)
    assert spec and spec.loader
    mod = ilu.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    assert hasattr(mod, "PhaseResult")
    # And the e2e test module itself must be importable / collectable.
    e2e_test_path = REPO_ROOT / "tests" / "e2e" / "test_e2e_load.py"
    src = e2e_test_path.read_text(encoding="utf-8")
    assert "sys.modules[_spec.name] = b1" in src or 'sys.modules[_spec.name] = b1' in src
    # Execute the same load sequence the test module uses.
    spec2 = ilu.spec_from_file_location("b1_e2e_profile_from_test", path)
    assert spec2 and spec2.loader
    b = ilu.module_from_spec(spec2)
    sys.modules[spec2.name] = b
    spec2.loader.exec_module(b)
    assert b.BASE_TOTAL == 6000


def test_unhealthy_events_oracle_filters_and_fails_closed():
    """C7 unit controls: stale / malformed / unavailable event data."""
    # Load helpers from the e2e module without collecting the whole e2e suite.
    import importlib.util as ilu
    from datetime import datetime, timezone
    from types import SimpleNamespace

    path = REPO_ROOT / "tests" / "e2e" / "test_e2e_load.py"
    # Import only by exec after ensuring profile is loadable.
    spec = ilu.spec_from_file_location("e2e_load_c7", path)
    assert spec and spec.loader
    mod = ilu.module_from_spec(spec)
    sys.modules[spec.name] = mod
    # The module loads b1 at import — must succeed (C1).
    spec.loader.exec_module(mod)

    since = datetime(2026, 8, 11, 12, 0, 0, tzinfo=timezone.utc)
    pod = "dbagent-ingest-gateway-abc"

    # Stale event (before since) must be ignored.
    stale = {
        "items": [
            {
                "involvedObject": {"name": pod},
                "lastTimestamp": "2026-08-11T11:00:00Z",
                "message": "old",
            }
        ]
    }
    assert mod._unhealthy_events_since(since, pod_name=pod, events_payload=stale) == []

    # In-window event for the current pod is returned.
    fresh = {
        "items": [
            {
                "involvedObject": {"name": pod},
                "lastTimestamp": "2026-08-11T12:05:00Z",
                "message": "probe failed",
            },
            {
                "involvedObject": {"name": "other-pod"},
                "lastTimestamp": "2026-08-11T12:06:00Z",
                "message": "unrelated",
            },
        ]
    }
    hits = mod._unhealthy_events_since(since, pod_name=pod, events_payload=fresh)
    assert len(hits) == 1
    assert "probe failed" in hits[0]

    # series.lastObservedTime is an accepted timestamp source.
    series_fresh = {
        "items": [
            {
                "involvedObject": {"name": pod},
                "series": {"lastObservedTime": "2026-08-11T12:07:00Z"},
                "message": "via series",
            }
        ]
    }
    hits2 = mod._unhealthy_events_since(
        since, pod_name=pod, events_payload=series_fresh
    )
    assert len(hits2) == 1

    # Missing timestamp on a current-pod event → fail closed (C7).
    missing_ts = {
        "items": [
            {
                "involvedObject": {"name": pod},
                "message": "no ts",
            }
        ]
    }
    try:
        mod._unhealthy_events_since(since, pod_name=pod, events_payload=missing_ts)
        assert False, "expected RuntimeError for missing timestamp"
    except RuntimeError as exc:
        assert "timestamp" in str(exc).lower()

    # Malformed JSON / missing items → fail closed.
    try:
        mod._unhealthy_events_since(since, pod_name=pod, events_payload={"nope": []})
        assert False, "expected RuntimeError for missing items"
    except RuntimeError as exc:
        assert "items" in str(exc)

    # kubectl failure → fail closed.
    def _fail_run(*a, **k):
        return SimpleNamespace(returncode=1, stdout="", stderr="boom")

    try:
        mod._unhealthy_events_since(since, pod_name=pod, kubectl_runner=_fail_run)
        assert False, "expected RuntimeError for kubectl failure"
    except RuntimeError as exc:
        assert "kubectl" in str(exc).lower() or "failed" in str(exc).lower()

    # Fingerprint field names must be the design.md K set (C7).
    src = path.read_text(encoding="utf-8")
    for field in (
        "gw_cpu_seconds=",
        "gw_throttled_usec=",
        "gw_nr_throttled=",
        "gw_restarts=",
        "in_flight=",
    ):
        assert field in src, f"fingerprint missing {field}"
    # Retired field names must not appear as fingerprint keys.
    assert "cgroup_cpu_s=" not in src
    assert "nr_throttled_delta=" not in src


def test_bd_import_does_not_construct_client_or_start_server():
    import subprocess
    import sys
    script = """
import importlib.util, subprocess, sys, httpx
from pathlib import Path
def forbidden(*args, **kwargs):
    raise AssertionError("module import started a client or server")
subprocess.Popen = forbidden
httpx.AsyncClient = forbidden
path = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("bd_import_only", path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
assert callable(module.characterize_b1_instant_server)
"""
    result = subprocess.run([sys.executable, "-c", script, str(REF_TEST)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert not result.stdout


def _assert_b1_output_capture_ownership(reference_source, e2e_sources):
    """FP-IG-40 under GC-1's carrier change.

    The measured gateway is no longer a host child of the driver: it is a
    sibling container, so Docker's log store -- not an inherited stdout pipe --
    is what the driver reads. The hazard FP-IG-40 exists for is unchanged
    (an unread pipe fills and the workers block), and it is now structurally
    impossible on the live path: nothing in the live fixture calls Popen at
    all. What is pinned here is that the fixture reads the retained log through
    the Docker API into a regular file on the writable run mount, at window
    completion, and that the ``_b1_gateway_process`` helper -- still the
    tracked carrier for the host-child shape and its own unit evidence --
    keeps its regular-file sink.
    """
    tree = ast.parse(reference_source)
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_b1_gateway_process")
    fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == LIVE_RUN_IMPL)
    snapshot = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_snapshot_container_log")
    launches = [n for n in ast.walk(helper) if isinstance(n, ast.Call) and _call_func_name(n) == "Popen"]
    assert len(launches) == 1
    launch = launches[0]
    kwargs = {k.arg: ast.unparse(k.value) for k in launch.keywords}
    assert kwargs["stdout"] == "writer"
    assert kwargs["stderr"] == "subprocess.STDOUT"
    assert kwargs["start_new_session"] == "True"
    writer_scope = next(n for n in ast.walk(helper) if isinstance(n, ast.With) and any(isinstance(i.optional_vars, ast.Name) and i.optional_vars.id == "writer" for i in n.items))
    assert ast.unparse(writer_scope.items[0].context_expr) == "log_path.open('xb')"
    assert launch in list(ast.walk(writer_scope))

    # The live fixture owns no inherited pipe at all.
    assert not any(isinstance(n, ast.Call) and _call_func_name(n) == "Popen" for n in ast.walk(fixture))
    assert not any(isinstance(n, ast.Call) and _call_func_name(n) == "_b1_gateway_process" for n in ast.walk(fixture))
    # The snapshot helper writes the Docker-retained log to a regular file and
    # reports the exact prefix length the warning count is scoped to.
    assert any(isinstance(n, ast.Call) and _call_func_name(n) == "logs" for n in ast.walk(snapshot))
    assert any(
        isinstance(n, ast.With)
        and ast.unparse(n.items[0].context_expr) == "log_path.open('wb')"
        for n in ast.walk(snapshot)
    )
    assert any(
        isinstance(n, ast.Return) and n.value is not None
        and "stat().st_size" in ast.unparse(n.value)
        for n in ast.walk(snapshot)
    )
    # It is called from the window-completion hook, and its result is what
    # scopes the concurrency-warning count.
    window = next(n for n in ast.walk(fixture) if isinstance(n, ast.FunctionDef) and n.name == "_after_window")
    assert any(isinstance(n, ast.Call) and _call_func_name(n) == "_snapshot_container_log" for n in ast.walk(window))
    count = next(
        n for n in ast.walk(fixture)
        if isinstance(n, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "concurrency_limit_warnings" for t in n.targets)
    )
    assert "_b1_gateway_warning_count" in ast.unparse(count)
    assert "log_prefix_bytes" in ast.unparse(count)
    # The two measured siblings are owned by one ExitStack and the burst runs
    # inside it.
    owned = [n for n in ast.walk(fixture) if isinstance(n, ast.With) and any(isinstance(i.context_expr, ast.Call) and _call_func_name(i.context_expr) == "ExitStack" for i in n.items)]
    assert len(owned) == 1
    entered = [
        ast.unparse(n.args[0]) for n in ast.walk(owned[0])
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
        and n.func.attr == "enter_context" and n.args
    ]
    assert entered == ["postgres", "gateway"], entered
    assert any(isinstance(n, ast.Call) and _call_func_name(n) == "run_open_loop" for n in ast.walk(owned[0]))
    assert any(isinstance(n, ast.Call) and _call_func_name(n) == "get" for n in ast.walk(owned[0]))

    for source in e2e_sources:
        assert not any(isinstance(n, ast.Call) and _call_func_name(n) == "Popen" for n in ast.walk(ast.parse(source)))
    load_tree = ast.parse(e2e_sources[1])
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and ast.unparse(n.func) == "subprocess.run" for n in ast.walk(load_tree))
    events = next(n for n in load_tree.body if isinstance(n, ast.FunctionDef) and n.name == "_unhealthy_events_since")
    assert any(isinstance(n, ast.Assign) and ast.unparse(n.value) == "kubectl_runner or subprocess.run" for n in ast.walk(events))


def test_b1_output_capture_ownership():
    source = REF_TEST.read_text()
    e2e_sources = [p.read_text() for p in (E2E_PATH, E2E_TEST, E2E_TEST.parent / "conftest.py")]
    _assert_b1_output_capture_ownership(source, e2e_sources)
    for mutant in (
        source.replace("stdout=writer", "stdout=subprocess.PIPE", 1),
        source.replace('marks["log_prefix_bytes"] = _snapshot_container_log(gateway, log_path)',
                       'marks["log_prefix_bytes"] = 0', 1),
        source.replace("stack.enter_context(gateway)", "gateway.start()", 1),
        source.replace("payload = wrapped.logs(stdout=True, stderr=True)",
                       'payload = b""', 1),
        source.replace("return log_path.stat().st_size", "return 0", 1),
    ):
        with pytest.raises(AssertionError):
            _assert_b1_output_capture_ownership(mutant, e2e_sources)
    for index in range(3):
        mutants = e2e_sources.copy()
        mutants[index] += "\nproc = subprocess.Popen(['gateway'], stdout=subprocess.PIPE)\n"
        with pytest.raises(AssertionError):
            _assert_b1_output_capture_ownership(source, mutants)


def test_b1_e2e_finite_capture_drains_large_output():
    import signal
    import subprocess
    import sys
    from datetime import datetime, timezone

    module = _load(E2E_TEST, "be_e2e_finite_capture")
    captures = []
    marker = "FINITE-STDERR-MARKER"
    def runner(argv, **kwargs):
        assert argv[0] == "kubectl"
        assert kwargs == {"capture_output": True, "text": True, "check": False}
        result = subprocess.run(
            [sys.executable, "-c", "import sys; sys.stdout.write(' '*2097152 + '{\"items\": []}'); sys.stderr.write('FINITE-STDERR-MARKER')"],
            **kwargs, timeout=9,
        )
        captures.append(result)
        return result
    def watchdog(signum, frame):
        raise TimeoutError("finite capture exceeded outer 10-second watchdog")
    previous = signal.signal(signal.SIGALRM, watchdog)
    signal.setitimer(signal.ITIMER_REAL, 10)
    try:
        assert module._unhealthy_events_since(datetime.now(timezone.utc), pod_name="gateway", kubectl_runner=runner) == []
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    assert len(captures) == 1
    assert captures[0].returncode == 0
    assert captures[0].stdout == " " * 2097152 + '{"items": []}'
    assert captures[0].stderr == marker


# ---------------------------------------------------------------------------
# GC-1 — the two-tier harness surface, the placement fingerprint and the
# routed CPU basis (FP-GC1-1 / 3 / 4 / 6).
#
# Every literal below is declared here, independently of the module it pins:
# a pin derived from its own subject detects nothing.
# ---------------------------------------------------------------------------

CI_SCALE_BARS = {
    "CI_SCALE_BURST_RATE": 500,
    "CI_SCALE_BURST_SECONDS": 30,
    "CI_SCALE_TOTAL_REQUESTS": 15000,
    "CI_SCALE_P99_MS": 150.0,
    "CI_SCALE_SUSTAINED_FLOOR": 450,
    "CI_SCALE_MAX_IN_FLIGHT": 500,
    "CI_SCALE_PROLOGUE_REQUESTS": 75,
}
PRODUCT_BARS = {
    "PRODUCT_P99_MS": 150.0,
    "PRODUCT_SUSTAINED_FLOOR": 200,
    "PRODUCT_MAX_IN_FLIGHT": 1000,
    "PRODUCT_TOTAL_REQUESTS": 30000,
}
# Which profile constant each test-module bar literal must equal.
_BAR_TO_PROFILE_CONSTANT = {
    "CI_SCALE_P99_MS": "CI_SCALE_P99_MS",
    "CI_SCALE_SUSTAINED_FLOOR": "CI_SCALE_SUSTAINED_FLOOR",
    "CI_SCALE_MAX_IN_FLIGHT": "CI_SCALE_MAX_IN_FLIGHT",
    "CI_SCALE_TOTAL_REQUESTS": "CI_SCALE_TOTAL_REQUESTS",
    "PRODUCT_P99_MS": "P99_MS",
    "PRODUCT_SUSTAINED_FLOOR": "SUSTAINED_FLOOR",
    "PRODUCT_MAX_IN_FLIGHT": "MAX_IN_FLIGHT",
    "PRODUCT_TOTAL_REQUESTS": "TOTAL_REQUESTS",
}
GC1_ROLES = ("gateway", "postgres", "driver")
# Gating identity and effective affinity first; every cgroup/host diagnostic
# after. The order is the contract: a reader must be able to stop at
# `driver_allowed_cpus` and have seen everything that decided the verdict.
GC1_GATING_PLACEMENT_FIELDS = (
    "placement_profile",
    "placement_schema",
    "placement_run_id",
    "measurement_authority",
    "placement_ok",
    "gateway_allowed_cpus",
    "postgres_allowed_cpus",
    "driver_allowed_cpus",
)
# GC-3 (FP-GC3-5) split this inventory in two. The schema-2 line -- the
# product-local profile, and the ordinary CI-scale contract until a topology is
# ratified -- keeps exactly the GC-1/GC-2 sequence below. The schema-3 line has
# its own inventory further down: it carries the physical-topology claim in its
# GATING prefix and therefore does not repeat `gateway_thread_siblings_pct`
# among its diagnostics. One shared tuple could not say that.
GC3_PRODUCT_DIAGNOSTIC_PLACEMENT_FIELDS = (
    "gateway_quota_cpus",
    "gateway_cpu_period_us",
    "gateway_nr_periods",
    "gateway_nr_throttled",
    "gateway_throttled_usec",
    "postgres_quota_cpus",
    "postgres_cpu_period_us",
    "postgres_nr_periods",
    "postgres_nr_throttled",
    "postgres_throttled_usec",
    "driver_quota_cpus",
    "driver_cpu_period_us",
    "driver_nr_periods",
    "driver_nr_throttled",
    "driver_throttled_usec",
    "gateway_cpu_busy_usec",
    "gateway_nonrole_busy_cores_estimate",
    "gateway_cpu_cores_used",
    # GC-2 (FP-GC2-5): three appended reported-only attribution fields. They
    # sit after every existing diagnostic and before nothing: the gating
    # prefix is unchanged, and none of them can fail a B1 tier.
    "postgres_usage_usec",
    "gateway_thread_siblings_pct",
    "spectre_v2_pct",
)
GC1_PLACEMENT_FIELDS = GC1_GATING_PLACEMENT_FIELDS + GC3_PRODUCT_DIAGNOSTIC_PLACEMENT_FIELDS
GC1_PRODUCT_FIELDS = (
    "product_errors_eq_zero",
    "product_p99_lt_150_ms",
    "product_served_eq_offered",
)
GC1_RETIRED_FINGERPRINT_KEYS = ("cpu_cores_used",)
# The allocation is affinity cardinality, not a CPU quota.
#
# GC-3 (FP-GC3-4) retired the fixed `ci-scale` entry and the scalar
# `GC1_PLACEMENT_SCHEMA`. The CI-scale allocation is now decided per exact CPU
# model, so both are read from the tracked carrier entry by entry
# (`_gc1_cardinalities_by_cpu_model`, `_gc1_schemas_by_cpu_model` below) and
# compared with the Python declaration surface. The product-local entry and the
# product schema are unchanged, and the probe schema is a fixed 3.
GC1_AFFINITY_CARDINALITIES = {
    "product-exclusive": {"gateway": 4, "postgres": 3, "driver": 1},
}
GC1_PRODUCT_PLACEMENT_SCHEMA = 2
GC1_PROBE_PLACEMENT_SCHEMA = 3
GC1_SELECTED_PLACEMENT_SCHEMA = 3
GC1_PLACEMENT_MECHANISM = "sched-affinity"
GC1_DIAGNOSTIC_UNAVAILABLE = "unavailable"
# Docker bandwidth/cpuset controls, removed as the allocation primitive.
GC1_BANDWIDTH_CONTROLS = ("--cpus", "--cpu-period", "--cpu-quota", "--cpuset-cpus",
                          "cpu_period=", "cpu_quota=", "cpuset_cpus=")
GC1_MARKERS = ("b1_live", "b1_product", "b1_latency_basis", "b1_topology_probe")


def _gc3_carrier_models() -> "dict[str, dict]":
    """The tracked carrier's model map; empty while the carrier is absent.

    Reading it here is deliberately non-fatal: the two GC-3 decision tests
    below are the fail-closed carriers that REQUIRE the file, under the named
    reason `gc3_decision_missing`. Everything else compares declaration
    surfaces against whatever the carrier decided, and "nothing decided yet"
    must therefore mean "nothing declared", not "anything goes".
    """
    if not GC3_DECISION.is_file():
        return {}
    decision = json.loads(GC3_DECISION.read_text(encoding="utf-8"))
    models = (decision or {}).get("models") or {}
    return models if isinstance(models, dict) else {}


def _gc1_selected_models() -> "dict[str, dict]":
    return {
        model: entry for model, entry in _gc3_carrier_models().items()
        if isinstance(entry, dict) and entry.get("status") == "selected"
    }


def _gc1_cardinality_map_failures(test_assigns: "dict[str, ast.AST]") -> list[str]:
    """FP-GC3-4: the per-model declaration maps equal the carrier, exactly.

    This is the replacement for the retired scalar
    `GC1_AFFINITY_CARDINALITIES["ci-scale"]` / `GC1_PLACEMENT_SCHEMA` pins:
    one entry per `selected` model, each carrying that model's own
    topology-derived cardinality and schema 3, and no scalar default anywhere.
    """
    fails: list[str] = []
    selected = _gc1_selected_models()
    expectations = {
        "CI_SCALE_AFFINITY_CARDINALITIES_BY_CPU_MODEL": {
            model: entry.get("cardinality") for model, entry in selected.items()
        },
        "CI_SCALE_PLACEMENT_SCHEMAS_BY_CPU_MODEL": {
            model: GC1_SELECTED_PLACEMENT_SCHEMA for model in selected
        },
    }
    for name, expected in expectations.items():
        node = test_assigns.get(name)
        if node is None:
            fails.append(f"{name} is missing from the harness")
            continue
        declared = ast.literal_eval(node)
        if declared != expected:
            fails.append(f"{name} is {declared!r}, the carrier decides {expected!r}")
    for retired in ("CI_SCALE_AFFINITY_CARDINALITY", "B1_PLACEMENT_SCHEMA"):
        if retired in test_assigns:
            fails.append(f"the retired scalar {retired} survives")
    if ast.literal_eval(
        test_assigns["PRODUCT_AFFINITY_CARDINALITY"]
    ) != GC1_AFFINITY_CARDINALITIES["product-exclusive"]:
        fails.append("the product-local 4/3/1 cardinality moved")
    return fails
# The historical basis number 2.427 is VOID and no longer has a name here.
# The retired-owner walk below forbids both the literal and the three constant
# names that used to carry it inside any GC-* pin, so a definition could only
# serve to re-wire one: B1-LATENCY-BASIS-1 owns the replacement.
GC1_BASIS_OWNER = "B1-LATENCY-BASIS-1"
#: The single actual-state owner of the unqualified basis. Every GC-* handoff
#: pin routes to it instead of duplicating its scheduled failure.
GC1_BASIS_GATE = (
    "tests/delivery/test_delivery_sizing_ledger.py"
    "::test_sizing_basis_provenance_is_on_reference_and_from_a_serving_run"
)
# Top-level directories the FP-GC1-6 guard may open. The gitignored
# specification tree is deliberately absent: the guard must stay
# collectable in CI, where that tree does not exist.
GC1_TRACKED_CARRIER_ROOTS = frozenset({"deploy", "tests", "services", "libs", "scripts"})
GC1_PRESERVED_ORACLES = (
    "test_measured_cpu_cost_does_not_exceed_the_recorded_sizing_basis",
    "test_sizing_basis_provenance_is_on_reference_and_from_a_serving_run",
)


def _module_tuple(tree: ast.Module, name: str) -> tuple:
    node = next(
        n.value for n in tree.body
        if isinstance(n, ast.Assign) and len(n.targets) == 1
        and isinstance(n.targets[0], ast.Name) and n.targets[0].id == name
    )
    return ast.literal_eval(node)


def _decorator_markers(func: ast.AST) -> set[str]:
    out: set[str] = set()
    for dec in getattr(func, "decorator_list", []):
        node = dec.func if isinstance(dec, ast.Call) else dec
        text = ast.unparse(node)
        if text.startswith("pytest.mark."):
            out.add(text.split("pytest.mark.", 1)[1])
    return out


def _live_consumer_failures(src: str, *, where: str) -> list[str]:
    """The closed live-fixture/marker mapping, applied to one module.

    Every function that injects a live fixture carries ``b1_live``; product
    consumers also carry ``b1_product``; discovery consumers also carry
    ``b1_topology_probe``; and no function injects two live fixtures. Adding an
    unmarked live consumer -- in either module -- is a named failure, so the
    traced container-free selection cannot silently acquire live work.
    """
    tree = ast.parse(src)
    fails: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in node.args.args}
        markers = _decorator_markers(node)
        live = params & {CI_SCALE_FIXTURE, PRODUCT_FIXTURE, PROBE_FIXTURE}
        if not live:
            continue
        if not node.name.startswith("test"):
            # The fixture definitions themselves are the one admitted
            # exception: `def b1_topology_probe_run(...)` takes no live
            # fixture, so only a *consumer* reaches here.
            fails.append(f"{where}::{node.name}: non-test consumer of a live fixture")
            continue
        if "b1_live" not in markers:
            fails.append(f"{where}::{node.name}: live-fixture consumer without b1_live")
        if PRODUCT_FIXTURE in params and "b1_product" not in markers:
            fails.append(f"{where}::{node.name}: product-fixture consumer without b1_product")
        if PROBE_FIXTURE in params and "b1_topology_probe" not in markers:
            fails.append(
                f"{where}::{node.name}: probe-fixture consumer without b1_topology_probe"
            )
        if PROBE_FIXTURE in params and "b1_product" in markers:
            fails.append(f"{where}::{node.name}: probe node carries b1_product")
        if len(live) > 1:
            fails.append(f"{where}::{node.name}: injects more than one live fixture")
    return fails


def _live_marker_failures(src: str, probe_src: str | None = None) -> list[str]:
    """The dual-module map: the harness module, and the live-only probe module.

    The probe node deliberately does NOT live in the harness module: a second
    CI job collecting ``test_b1_ingest_burst.py`` would break FP-IG-26's
    one-producer invariant. Passing both sources here keeps one mapping for
    both files rather than two mappings that can disagree.
    """
    fails = _live_consumer_failures(src, where=REF_TEST.name)
    if probe_src is not None:
        fails.extend(_live_consumer_failures(probe_src, where=PROBE_TEST.name))
        if PROBE_FIXTURE not in probe_src:
            fails.append(f"{PROBE_TEST.name}: defines no {PROBE_FIXTURE} fixture")
    if PROBE_FIXTURE in src:
        fails.append(f"{REF_TEST.name}: defines or consumes the probe fixture")
    tree = ast.parse(src)
    witness = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name == "test_b1_instant_server_clears_open_loop_offer"), None
    )
    if witness is None:
        fails.append("test_b1_instant_server_clears_open_loop_offer: missing")
    elif "b1_live" not in _decorator_markers(witness):
        fails.append("test_b1_instant_server_clears_open_loop_offer: without b1_live")
    basis = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name == GC1_PRESERVED_ORACLES[0]), None
    )
    if basis is None:
        fails.append(f"{GC1_PRESERVED_ORACLES[0]}: missing")
    elif "b1_latency_basis" not in _decorator_markers(basis):
        fails.append(f"{GC1_PRESERVED_ORACLES[0]}: without b1_latency_basis")
    return fails


def _product_partition_failures(src: str) -> list[str]:
    """The recorded/gating partition inside the product node.

    The three product comparisons are recorded: the node may check that a
    serialized token *equals its own live comparison*, and may check the token
    is one of the two admitted words. It may not require any token to be
    ``met`` -- that would turn a recorded status back into a bar.
    """
    tree = ast.parse(src)
    fails: list[str] = []
    node = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
         and n.name == PRODUCT_REF_TEST), None
    )
    if node is None:
        return [f"{PRODUCT_REF_TEST}: missing"]
    for cmp_node in ast.walk(node):
        if not isinstance(cmp_node, ast.Compare):
            continue
        if not any(isinstance(op, ast.Eq) for op in cmp_node.ops):
            continue
        rendered = [ast.unparse(c) for c in cmp_node.comparators]
        if any(r in ("VERDICT_MET", "'met'", '"met"') for r in rendered):
            fails.append(f"{PRODUCT_REF_TEST}: truth-gates a recorded status: {ast.unparse(cmp_node)}")
    body = ast.get_source_segment(src, node) or ""
    for gating in (
        "assert served + errors == offered",
        "assert committed == served",
        'assert b1_product_run["placement_ok"] is True',
        "assert served_rate >= PRODUCT_SUSTAINED_FLOOR",
        "assert max_in_flight < PRODUCT_MAX_IN_FLIGHT",
        'assert b1_product_run["worker_set_ok"]',
    ):
        if gating not in body:
            fails.append(f"{PRODUCT_REF_TEST}: missing gating assertion {gating!r}")
    for recorded in ("token == live[field_name]", "token in (VERDICT_MET, VERDICT_MISSED)"):
        if recorded not in body:
            fails.append(f"{PRODUCT_REF_TEST}: missing record-consistency check {recorded!r}")
    return fails


def _verdict_evaluator_failures(src: str) -> list[str]:
    """The three comparisons themselves: names, order, operators, operands."""
    tree = ast.parse(src)
    fails: list[str] = []
    if _module_tuple(tree, "PRODUCT_VERDICT_FIELDS") != GC1_PRODUCT_FIELDS:
        fails.append("PRODUCT_VERDICT_FIELDS is not the closed ordered triple")
    fn = next(
        (n for n in tree.body
         if isinstance(n, ast.FunctionDef) and n.name == "_product_promise_verdicts"), None
    )
    if fn is None:
        return fails + ["_product_promise_verdicts: missing"]
    assigned: list[str] = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant):
                assigned.append(target.slice.value)
    if tuple(assigned) != GC1_PRODUCT_FIELDS:
        fails.append(f"_product_promise_verdicts assigns {tuple(assigned)}")
    body = ast.get_source_segment(src, fn) or ""
    for operand in ("result.errors == 0", "result.p99 < PRODUCT_P99_MS",
                    "result.served == result.offered"):
        if operand not in body:
            fails.append(f"_product_promise_verdicts lost the comparison {operand!r}")
    for literalized in ('= VERDICT_MET\n', '= "met"\n', "= 'met'\n"):
        if literalized in body:
            fails.append(f"_product_promise_verdicts literalizes a status: {literalized!r}")
    return fails


def test_b1_harness_surface_is_pinned_and_environment_independent_gc1():
    """FP-GC1-1/3: both immutable profiles, the marker map, the recorded partition."""
    profile_src = REF_PATH.read_text(encoding="utf-8")
    test_src = REF_TEST.read_text(encoding="utf-8")
    profile_assigns = _source_assigns(profile_src)
    test_assigns = _source_assigns(test_src)

    # The CI-scale profile constants live beside the untouched product ones.
    for name, expected in CI_SCALE_BARS.items():
        assert name in profile_assigns, f"b1_reference_profile.py missing {name}"
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    for name, expected in SHARED_CONSTANTS.items():
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    assert _eval_simple_constant(
        profile_assigns["CI_SCALE_TOTAL_REQUESTS"], profile_assigns
    ) == (
        _eval_simple_constant(profile_assigns["CI_SCALE_BURST_RATE"], profile_assigns)
        * _eval_simple_constant(profile_assigns["CI_SCALE_BURST_SECONDS"], profile_assigns)
    )
    # ... and the e2e copy is untouched by GC-1.
    assert "CI_SCALE_BURST_RATE" not in _module_assigns(E2E_PATH)

    # The test module's independent bar literals equal their profile counterparts.
    for name, expected in {**CI_SCALE_BARS, **PRODUCT_BARS}.items():
        if name not in _BAR_TO_PROFILE_CONSTANT:
            continue
        assert name in test_assigns, f"test_b1_ingest_burst.py missing {name}"
        node = test_assigns[name]
        assert isinstance(node, ast.Constant), f"{name} must be a numeric literal"
        assert node.value == expected, f"{name}={node.value}"
        counterpart = _BAR_TO_PROFILE_CONSTANT[name]
        assert _eval_simple_constant(profile_assigns[counterpart], profile_assigns) == expected, (
            f"{name} disagrees with b1_reference_profile.{counterpart}"
        )

    # Affinity cardinalities are literals in the test module, one per profile,
    # and the allocation carries no bandwidth control anywhere.
    tree = ast.parse(test_src)
    for profile, cardinalities in GC1_AFFINITY_CARDINALITIES.items():
        name = "PRODUCT_AFFINITY_CARDINALITY"
        assert ast.literal_eval(test_assigns[name]) == cardinalities, name
        assert sum(cardinalities.values()) == 8, profile
    # The CI-scale half is model-keyed and generated; it is checked against the
    # carrier, entry by entry, in test_gc3_reference_topology_scope_and_
    # decision_are_pinned rather than against a literal here.
    assert _gc1_cardinality_map_failures(test_assigns) == []
    assert ast.literal_eval(
        test_assigns["PRODUCT_PLACEMENT_SCHEMA"]
    ) == GC1_PRODUCT_PLACEMENT_SCHEMA
    assert ast.literal_eval(test_assigns["B1_PLACEMENT_MECHANISM"]) == GC1_PLACEMENT_MECHANISM
    assert _module_tuple(tree, "B1_ROLES") == GC1_ROLES
    for line in test_src.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            continue
        for control in GC1_BANDWIDTH_CONTROLS:
            assert control not in stripped, f"bandwidth control survives: {stripped[:80]}"

    # Closed live-fixture/marker mapping, and the registered marker set.
    assert _live_marker_failures(test_src) == []
    markers_toml = (REPO_ROOT / "services" / "gateway" / "pyproject.toml").read_text(encoding="utf-8")
    for marker in GC1_MARKERS:
        assert f'"{marker}:' in markers_toml, f"{marker} is not registered"

    # Recorded/gating partition and the evaluator behind it.
    assert _product_partition_failures(test_src) == []
    assert _verdict_evaluator_failures(test_src) == []

    # No profile knob comes from the environment; the driver semantics are kept.
    assert not _has_environ_read(REF_PATH)
    assert "getenv" not in test_src and "os.environ.get" not in test_src
    assert "E2E_B1_CONCURRENCY" not in test_src
    _raw_surface_checks(REF_PATH, profile_src)

    # Negative controls: one mutation at a time, each named.
    unmarked = test_src.replace(
        "@pytest.mark.b1_live\ndef test_b1_ci_scale_fingerprint_proves_reference_topology(",
        "def test_b1_ci_scale_fingerprint_proves_reference_topology(", 1)
    assert unmarked != test_src
    assert any("without b1_live" in f for f in _live_marker_failures(unmarked))
    unproducted = test_src.replace(
        "@pytest.mark.b1_live\n@pytest.mark.b1_product\ndef test_b1_product_exclusive_reference_profile(",
        "@pytest.mark.b1_live\ndef test_b1_product_exclusive_reference_profile(", 1)
    assert unproducted != test_src
    assert any("without b1_product" in f for f in _live_marker_failures(unproducted))
    unbasised = test_src.replace("@pytest.mark.b1_latency_basis\n", "", 1)
    assert unbasised != test_src
    assert any("without b1_latency_basis" in f for f in _live_marker_failures(unbasised))
    unwitnessed = test_src.replace(
        "@pytest.mark.b1_live\n@pytest.mark.parametrize(\"driver\", [b1, bd_e2e], "
        "ids=[\"reference\", \"e2e\"])\n@pytest.mark.asyncio\nasync def "
        "test_b1_instant_server_clears_open_loop_offer(",
        "@pytest.mark.parametrize(\"driver\", [b1, bd_e2e], ids=[\"reference\", \"e2e\"])\n"
        "@pytest.mark.asyncio\nasync def test_b1_instant_server_clears_open_loop_offer(", 1)
    assert unwitnessed != test_src
    assert any("instant_server" in f for f in _live_marker_failures(unwitnessed))
    smuggled = test_src + (
        "\n\ndef test_b1_smuggled_live_consumer(b1_ci_scale_run):\n"
        "    assert b1_ci_scale_run\n"
    )
    assert any("without b1_live" in f for f in _live_marker_failures(smuggled))

    truth_gated = test_src.replace(
        "        assert token == live[field_name], (",
        "        assert token == VERDICT_MET\n        assert token == live[field_name], (", 1)
    assert truth_gated != test_src
    assert any("truth-gates" in f for f in _product_partition_failures(truth_gated))
    ungated = test_src.replace("    assert committed == served, f\"committed={committed} "
                               "served={served}; {line}\"\n", "", 1)
    assert ungated != test_src
    assert any("missing gating assertion" in f for f in _product_partition_failures(ungated))
    for operand, replacement in (
        ("result.errors == 0", "False"),
        ("result.p99 < PRODUCT_P99_MS", "False"),
        ("result.served == result.offered", "False"),
    ):
        deleted = test_src.replace(operand, replacement, 1)
        assert deleted != test_src
        assert any("lost the comparison" in f for f in _verdict_evaluator_failures(deleted)), operand
    reordered = test_src.replace(
        'PRODUCT_VERDICT_FIELDS = (\n    "product_errors_eq_zero",\n'
        '    "product_p99_lt_150_ms",\n    "product_served_eq_offered",\n)',
        'PRODUCT_VERDICT_FIELDS = (\n    "product_p99_lt_150_ms",\n'
        '    "product_errors_eq_zero",\n    "product_served_eq_offered",\n)', 1)
    assert reordered != test_src
    assert any("closed ordered triple" in f for f in _verdict_evaluator_failures(reordered))


def _placement_surface_failures(src: str) -> list[str]:
    """Exact fingerprint field names, order and placement in the B1 line."""
    tree = ast.parse(src)
    fails: list[str] = []
    gating = _module_tuple(tree, "B1_GATING_PLACEMENT_FIELDS")
    diagnostics = _module_tuple(tree, "B1_DIAGNOSTIC_PLACEMENT_FIELDS")
    if gating != GC1_GATING_PLACEMENT_FIELDS:
        fails.append(f"B1_GATING_PLACEMENT_FIELDS drift: {gating}")
    if diagnostics != GC3_PRODUCT_DIAGNOSTIC_PLACEMENT_FIELDS:
        fails.append(f"B1_DIAGNOSTIC_PLACEMENT_FIELDS drift: {diagnostics}")
    if gating + diagnostics != GC1_PLACEMENT_FIELDS:
        fails.append("B1_PLACEMENT_FIELDS is not the two blocks in order")
    composition = next(
        (ast.unparse(n.value) for n in tree.body
         if isinstance(n, ast.Assign) and len(n.targets) == 1
         and isinstance(n.targets[0], ast.Name)
         and n.targets[0].id == "B1_PLACEMENT_FIELDS"), None
    )
    if composition != "B1_GATING_PLACEMENT_FIELDS + B1_DIAGNOSTIC_PLACEMENT_FIELDS":
        fails.append(f"B1_PLACEMENT_FIELDS is not gating-first: {composition}")

    fn = next(
        (n for n in tree.body
         if isinstance(n, ast.FunctionDef) and n.name == "_serialize_placement_fields"), None
    )
    if fn is None:
        return fails + ["_serialize_placement_fields: missing"]
    body = ast.get_source_segment(src, fn) or ""
    # Reconstruct the emission order from the serializer's own literals. The
    # per-role blocks are contiguous runs under `for role in B1_ROLES`, so each
    # expands role-major.
    emitted: list[str] = []
    for match in re.finditer(r'[f]?"(\{role\}_)?([a-z_0-9]+)=', body):
        emitted.append(("{role}_" if match.group(1) else "") + match.group(2))
    expanded: list[str] = []
    index = 0
    while index < len(emitted):
        if not emitted[index].startswith("{role}_"):
            expanded.append(emitted[index])
            index += 1
            continue
        run = []
        while index < len(emitted) and emitted[index].startswith("{role}_"):
            run.append(emitted[index][len("{role}_"):])
            index += 1
        for role in GC1_ROLES:
            expanded.extend(f"{role}_{suffix}" for suffix in run)
    # The five diagnostic keys per role are rendered by B1RoleDiagnostics, not
    # inline, so splice them in at their declared position.
    diag_fn = next(
        (n for n in ast.walk(tree)
         if isinstance(n, ast.FunctionDef) and n.name == "rendered"), None
    )
    if diag_fn is None:
        fails.append("B1RoleDiagnostics.rendered: missing")
    else:
        rendered_body = ast.get_source_segment(src, diag_fn) or ""
        per_role = [
            m.group(1) for m in re.finditer(r'f"\{self\.role\}_([a-z_0-9]+)"', rendered_body)
        ]
        anchor = expanded.index("gateway_cpu_busy_usec") if "gateway_cpu_busy_usec" in expanded \
            else len(expanded)
        spliced = [f"{role}_{suffix}" for role in GC1_ROLES for suffix in per_role]
        expanded = expanded[:anchor] + spliced + expanded[anchor:]
    if tuple(expanded) != GC1_PLACEMENT_FIELDS:
        fails.append(f"_serialize_placement_fields emits {tuple(expanded)}")

    live = next(
        (n for n in tree.body
         if isinstance(n, ast.FunctionDef) and n.name == LIVE_RUN_IMPL), None
    )
    if live is None:
        return fails + [f"{LIVE_RUN_IMPL}: missing"]
    assign = next(
        (n for n in ast.walk(live)
         if isinstance(n, ast.Assign)
         and any(isinstance(t, ast.Name) and t.id == "fingerprint_line" for t in n.targets)), None
    )
    if assign is None:
        return fails + ["fingerprint_line: missing"]
    line = ast.unparse(assign)
    if "{placement_fields}" not in line:
        fails.append("fingerprint_line carries no placement block")
    else:
        before = line.index("workers=")
        block = line.index("{placement_fields}")
        after = line.index("max_lateness_ms=")
        if not before < block < after:
            fails.append("placement block is not between workers= and the latency fields")
    if "{product_fields}" not in line:
        fails.append("fingerprint_line carries no product-verdict slot")
    elif not line.index("{product_fields}") < line.index("p99_leg_split="):
        fails.append("product verdicts are not immediately before p99_leg_split")
    for retired in GC1_RETIRED_FINGERPRINT_KEYS:
        if f",{retired}=" in line or f"'{retired}=" in line:
            fails.append(f"retired fingerprint key {retired!r} is still emitted")
    if "gateway_cpu_cores_used" not in ast.unparse(fn):
        fails.append("gateway_cpu_cores_used is not emitted")

    # Every reported diagnostic must have an `unavailable` fallback, and no
    # gating field may ever carry one.
    serializer = ast.unparse(fn)
    for name in ("gateway_cpu_busy_usec", "gateway_nonrole_busy_cores_estimate",
                 "gateway_cpu_cores_used"):
        if "DIAGNOSTIC_UNAVAILABLE" not in serializer:
            fails.append(f"{name} has no unavailable fallback")
            break
    diag_src = ast.get_source_segment(
        src,
        next(n for n in tree.body
             if isinstance(n, ast.FunctionDef) and n.name == "_role_diagnostics"),
    ) or ""
    if "DIAGNOSTIC_UNAVAILABLE" not in diag_src or "_try_diagnostic" not in diag_src:
        fails.append("_role_diagnostics has no fail-soft path")
    # A diagnostic failure must never reach placement_ok.
    if "placement_ok" in diag_src:
        fails.append("_role_diagnostics touches placement_ok")
    return fails


def test_b1_placement_fingerprint_surface_is_pinned():
    """FP-GC1-4: gating affinity first, diagnostics after, `unavailable` fallback."""
    src = REF_TEST.read_text(encoding="utf-8")
    assert len(GC1_PLACEMENT_FIELDS) == 29
    assert len(set(GC1_PLACEMENT_FIELDS)) == 29
    assert len(GC1_GATING_PLACEMENT_FIELDS) == 8
    for role in GC1_ROLES:
        assert f"{role}_allowed_cpus" in GC1_GATING_PLACEMENT_FIELDS
        for suffix in ("quota_cpus", "cpu_period_us", "nr_periods",
                       "nr_throttled", "throttled_usec"):
            assert f"{role}_{suffix}" in GC3_PRODUCT_DIAGNOSTIC_PLACEMENT_FIELDS
            assert f"{role}_{suffix}" not in GC1_GATING_PLACEMENT_FIELDS
    assert _placement_surface_failures(src) == []

    # Negative controls, one mutation at a time.
    dropped = src.replace('    "driver_throttled_usec",\n', "", 1)
    assert dropped != src
    assert any("DIAGNOSTIC_PLACEMENT_FIELDS drift" in f
               for f in _placement_surface_failures(dropped))
    ungated = src.replace('    "driver_allowed_cpus",\n', "", 1)
    assert ungated != src
    assert any("GATING_PLACEMENT_FIELDS drift" in f for f in _placement_surface_failures(ungated))
    # Moving a diagnostic into the gating prefix is red.
    reordered = src.replace(
        'B1_PLACEMENT_FIELDS = B1_GATING_PLACEMENT_FIELDS + B1_DIAGNOSTIC_PLACEMENT_FIELDS',
        'B1_PLACEMENT_FIELDS = B1_DIAGNOSTIC_PLACEMENT_FIELDS + B1_GATING_PLACEMENT_FIELDS', 1)
    assert reordered != src
    assert any("not gating-first" in f for f in _placement_surface_failures(reordered))
    renamed = src.replace('f"gateway_cpu_cores_used="', 'f"cpu_cores_used="', 1)
    if renamed != src:
        assert _placement_surface_failures(renamed) != []
    moved = src.replace('f"{placement_fields}"\n            f"max_lateness_ms=',
                        'f"max_lateness_ms=', 1)
    assert moved != src
    assert any("no placement block" in f or "not between" in f
               for f in _placement_surface_failures(moved))
    unslotted = src.replace('            f"{product_fields}"\n', "", 1)
    assert unslotted != src
    assert any("product-verdict slot" in f for f in _placement_surface_failures(unslotted))
    # Removing the fail-soft path, or letting a diagnostic reach placement_ok.
    hardened = src.replace("_try_diagnostic(", "_must_succeed(")
    assert hardened != src
    assert any("no fail-soft path" in f for f in _placement_surface_failures(hardened))
    gating_diag = src.replace(
        '        notes.append(f"{role} cpu.max: source was not readable")',
        '        notes.append(f"{role} cpu.max: source was not readable"); placement_ok = False', 1)
    assert gating_diag != src
    assert any("touches placement_ok" in f for f in _placement_surface_failures(gating_diag))


def test_gc1_preserves_and_routes_unqualified_cpu_basis():
    """FP-GC1-6 / FP-B1LB-7: the basis handoff is RESOLVED by schema and owner.

    GC-1 deferred the CPU basis; B1-LATENCY-BASIS-1 owns it. What this guard
    preserves is the handoff itself -- the named owner, the closed ledger
    carriers, and the two oracles that decide it -- NOT the void state. It no
    longer pins `observations == []` or the literal 2.427: those are exactly
    what the owning slice's collection replaces, and duplicating its scheduled
    empty-before-collection failure here would produce a second red for one
    fact. FP-IG-23's own actual-state gate is the single owner of that void.

    Reads only tracked carriers, deliberately: this guard must stay collectable
    in CI, where the gitignored design tree does not exist.
    """
    import yaml as _yaml

    values_path = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
    values = _yaml.safe_load(values_path.read_text(encoding="utf-8"))
    basis = values["ingestGateway"]["sizingBasis"]
    # The closed carriers the owning slice reads and writes, and nothing about
    # what they currently hold.
    assert set(basis) == {"cpuMsPerRequest", "signature", "collection", "observations"}
    assert set(basis["collection"]) == {"attempts"}
    assert isinstance(basis["observations"], list)
    assert isinstance(basis["collection"]["attempts"], list)

    thresholds = _yaml.safe_load(
        (REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml").read_text(encoding="utf-8")
    )
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    notes = b1_entry["notes"]
    assert GC1_BASIS_OWNER in notes, "B1 notes must route the basis to its owning slice"
    assert GC1_BASIS_GATE in notes, "B1 notes must name the actual-state gate"
    assert "collection.attempts" in notes

    # Both oracle carriers keep their names and their comparisons.
    ref_src = REF_TEST.read_text(encoding="utf-8")
    ledger_src = (
        REPO_ROOT / "tests" / "delivery" / "test_delivery_sizing_ledger.py"
    ).read_text(encoding="utf-8")
    assert f"def {GC1_PRESERVED_ORACLES[0]}(" in ref_src
    assert f"def {GC1_PRESERVED_ORACLES[1]}(" in ledger_src
    basis_fn = next(
        n for n in ast.parse(ref_src).body
        if isinstance(n, ast.FunctionDef) and n.name == GC1_PRESERVED_ORACLES[0]
    )
    body = ast.get_source_segment(ref_src, basis_fn) or ""
    assert "assert measured <= basis" in body
    assert 'values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"]' in body
    # It is routed out of both GC-1 targets rather than skipped or weakened.
    assert "b1_latency_basis" in _decorator_markers(basis_fn)
    for weakening in ("pytest.mark.skip", "pytest.mark.xfail", "pytest.skip("):
        assert weakening not in body, f"{GC1_PRESERVED_ORACLES[0]} must not {weakening}"

    # This guard reads no gitignored design carrier.
    guard_src = Path(__file__).read_text(encoding="utf-8")
    guard_fn = next(
        n for n in ast.parse(guard_src).body
        if isinstance(n, ast.FunctionDef) and n.name == "test_gc1_preserves_and_routes_unqualified_cpu_basis"
    )
    roots = set()
    for node in ast.walk(guard_fn):
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)):
            continue
        left = node.left
        while isinstance(left, ast.BinOp) and isinstance(left.op, ast.Div):
            left = left.left
        parent = node
        while isinstance(parent.left, ast.BinOp):
            parent = parent.left
        if isinstance(left, ast.Name) and left.id == "REPO_ROOT":
            assert isinstance(parent.right, ast.Constant), ast.unparse(node)
            roots.add(parent.right.value)
    assert roots, "guard opens no repository carrier at all"
    assert roots <= GC1_TRACKED_CARRIER_ROOTS, sorted(roots - GC1_TRACKED_CARRIER_ROOTS)


# ---------------------------------------------------------------------------
# GC-2 — the write-path slice's source and configuration boundary (FP-GC2-7).
#
# Every literal below is declared here, independently of the module it pins.
# The pin is structural: it says what this slice did and did not change. It
# infers no performance from source shape -- the hosted-runner CI record
# required by FP-GC2-4 remains the only performance acceptance evidence.
# ---------------------------------------------------------------------------

GC2_INGEST_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "ingest.py"
GC2_MAIN_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "main.py"
GC2_REPO_PATH = (
    REPO_ROOT / "libs" / "py" / "rca_common" / "rca_common" / "investigation_repo.py"
)
GC2_SESSION_PATH = (
    REPO_ROOT / "libs" / "py" / "rca_common" / "rca_common" / "db" / "session.py"
)
GC2_LAUNCHER_PATH = REPO_ROOT / "scripts" / "integration-test.sh"
GC2_VALUES_PATH = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"

GC2_FUSED_HELPER = "merge_existing_event_with_audit"
GC2_TXN = "_ingest_txn"
# The failure-producing comparisons the CI-scale bar is made of. Each must be
# a bare assert on a comparison in the named test, not a recorded verdict.
GC2_CI_SCALE_REQUIRED_ASSERTIONS = frozenset(
    {
        "offered == CI_SCALE_TOTAL_REQUESTS",
        "served + errors == offered",
        "errors == 0",
        "served == offered",
        "p99 < CI_SCALE_P99_MS",
        "committed == served",
        "served_rate >= CI_SCALE_SUSTAINED_FLOOR",
        "max_in_flight < CI_SCALE_MAX_IN_FLIGHT",
    }
)
GC2_FIXED_CI_SCALE_LITERALS = {
    "CI_SCALE_BURST_RATE": 500,
    "CI_SCALE_BURST_SECONDS": 30,
    "CI_SCALE_TOTAL_REQUESTS": 15000,
    "CI_SCALE_P99_MS": 150.0,
    "CI_SCALE_SUSTAINED_FLOOR": 450,
    "CI_SCALE_MAX_IN_FLIGHT": 500,
}
# Serve/pool/durability knobs this slice is forbidden to touch.
GC2_MAX_CONNECTIONS_PER_WORKER = 150
GC2_BACKLOG = 2048
GC2_GATEWAY_WORKERS = "4"
GC2_DURABILITY_TOKENS = ("synchronous_commit", "fsync", "full_page_writes")
# Deferred-audit machinery: ways of moving the audit row out of the merge's
# own transaction. GC-5 re-scoped two of the original tokens rather than
# weakening the rule. `batch` is retired because the slice's whole mechanism
# is a per-worker merge GROUP whose method is named for it -- the property
# that matters, one event row and one audit row inside the SAME committed
# transaction, is asserted structurally below and by FP-GC5-1's real-PostgreSQL
# owner. `asyncio` is retired from this scan and asserted on the coalescer
# module instead, which owns queueing and must contain no audit or insert
# symbol at all.
GC2_DEFERRED_AUDIT_TOKENS = (
    "BackgroundTask",
    "background_tasks",
    "run_in_executor",
    "ThreadPoolExecutor",
    "Queue(",
    "after_response",
    "defer",
)
#: GC-5's coalescer: queueing only. None of these may appear in it.
GC2_COALESCER_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "merge_commit.py"
GC2_COALESCER_FORBIDDEN = (
    "write_audit",
    "insert_alert_event",
    "audit",
    "alert_events",
    "audit_log",
    "INSERT",
)
GC2_BATCH_CALLBACK = "_execute_merge_batch"
GC2_BATCH_CLOSER = "_finish_merge_batch"
# CI-scale 2/1/1 and product 4/3/1, spelled as the launcher spells them.
# GC-1's launcher allocation, as GC-3 leaves it. The three ordinary CI-scale
# lines are RETIRED: that route no longer allocates roles at all -- it renders
# the exact host model's ratified topology over the two observed sibling pairs
# through `contract-selected`. The product-local 4/3/1 lines are unchanged, and
# the retired CI-scale literals are pinned ABSENT in `_gc3_scope_failures`.
GC2_LAUNCHER_AFFINITY_LINES = (
    'gateway_cpus="$(b1_canonical_cpu_list "${cpus[0]}" "${cpus[1]}" "${cpus[2]}" "${cpus[3]}")"',
    'postgres_cpus="$(b1_canonical_cpu_list "${cpus[4]}" "${cpus[5]}" "${cpus[6]}")"',
    'driver_cpus="$(b1_canonical_cpu_list "${cpus[7]}")"',
)
GC2_LAUNCHER_ROUTED_LINES = (
    'b1_run_driver driver-coverage.sh "${cpus[0]}"',
    'python3 "$B1_PROBE_PLANNER" route \\',
    'python3 "$B1_PROBE_PLANNER" route-fields --route "$B1_ROUTE_RECORD"',
    'python3 "$B1_PROBE_PLANNER" contract-selected \\',
    'b1_run_driver driver-live.sh "$driver_cpus"',
)
GC2_RAW_CLIENT_LIMIT = "client = build_httpx_client(max_connections=max_in_flight)"
# The GC-2 investigation's own numbers. Neither may become a sizing carrier
# value or a B1-LATENCY-BASIS-1 observation; the ledger's population and
# lifecycle stay with test_delivery_sizing_ledger.py and that later slice.
GC2_INVESTIGATION_CPU_MS = "5.271"
GC2_INVESTIGATION_RUN_ID = "35057395036"
GC2_SIZING_CARRIERS = (
    ("deploy", "charts", "dbagent", "values.yaml"),
    ("tests", "benchmark", "thresholds.yaml"),
    ("tests", "delivery", "test_delivery_sizing_ledger.py"),
    ("services", "gateway", "tests", "b1_reference_profile.py"),
    ("services", "gateway", "tests", "test_b1_ingest_burst.py"),
    ("scripts", "integration-test.sh"),
)
# GC-3 (FP-GC3-5): the same split, applied to GC-2's appended attribution tail.
# The product line still ends in all three; the schema-3 line ends in two,
# because its gateway sibling map moved into the gating prefix.
GC3_PRODUCT_DIAGNOSTIC_TAIL = (
    "postgres_usage_usec",
    "gateway_thread_siblings_pct",
    "spectre_v2_pct",
)
GC3_CI_SCALE_DIAGNOSTIC_TAIL = (
    "postgres_usage_usec",
    "spectre_v2_pct",
)
GC2_DIAGNOSTIC_SAFE_CHARACTERS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:+"
)


def _gc2_function(tree: ast.AST, name: str, *, cls: str | None = None) -> ast.AST:
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        if node.name != name:
            continue
        if cls is None:
            return node
        for parent in ast.walk(tree):
            if (
                isinstance(parent, ast.ClassDef)
                and parent.name == cls
                and node in parent.body
            ):
                return node
    raise AssertionError(f"{name} not found")


def _gc2_named_calls(node: ast.AST, name: str) -> list[ast.Call]:
    out = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        spelled = (
            func.id if isinstance(func, ast.Name)
            else (func.attr if isinstance(func, ast.Attribute) else None)
        )
        if spelled == name:
            out.append(child)
    return out


def test_gc2_write_path_scope_and_fixed_bar_are_pinned():
    """FP-GC2-7, re-scoped by GC-5: the fused call, its order, the fixed bar.

    GC-5 moved transaction ownership for the committed-hit branch out of
    ``_ingest_txn`` and into the per-worker group, exactly as its frozen
    deviation registers. This pin moves with it and weakens nothing: there is
    still exactly ONE fused call in the module, it is still the request's
    first database operation, the merged 200 body still follows one durable
    commit, the fallback still keeps its platform lookup, its advisory lock
    before the deciding read and its own commit, and no audit row is deferred
    outside the transaction that writes its event.
    """
    ingest_src = GC2_INGEST_PATH.read_text(encoding="utf-8")
    ingest_tree = ast.parse(ingest_src)
    txn = _gc2_function(ingest_tree, GC2_TXN, cls="IngestService")
    ingest_fn = _gc2_function(ingest_tree, "ingest", cls="IngestService")
    batch = _gc2_function(ingest_tree, GC2_BATCH_CALLBACK, cls="IngestService")
    closer = _gc2_function(ingest_tree, GC2_BATCH_CLOSER, cls="IngestService")

    # (1) Exactly one fused call in the whole module, inside the group
    # callback, and it is the request's FIRST database operation: the
    # coalescer is awaited before the individual transaction is dispatched,
    # and that transaction now begins at the platform lookup.
    module_fused = _gc2_named_calls(ingest_tree, GC2_FUSED_HELPER)
    assert len(module_fused) == 1, [c.lineno for c in module_fused]
    batch_fused = _gc2_named_calls(batch, GC2_FUSED_HELPER)
    assert len(batch_fused) == 1, [c.lineno for c in batch_fused]
    assert not _gc2_named_calls(txn, GC2_FUSED_HELPER), (
        "the fused statement is repeated on the fallback"
    )
    assert not _gc2_named_calls(ingest_fn, GC2_FUSED_HELPER), (
        "the fused statement must not run on the event loop"
    )
    platform_calls = _gc2_named_calls(txn, "get_platform")
    assert platform_calls, "the fallback lost its platform lookup"
    txn_db_calls = [
        call for call in ast.walk(txn)
        if isinstance(call, ast.Call)
        and isinstance(call.func, ast.Name)
        and call.func.id in {
            "get_platform", "acquire_correlation_lock", "find_open_by_fingerprint",
            "insert_alert_event", "write_audit", "create_investigation",
        }
    ]
    assert min(call.lineno for call in txn_db_calls) == min(
        call.lineno for call in platform_calls
    ), "the individual transaction no longer begins at the platform lookup"
    submits = [
        node for node in ast.walk(ingest_fn)
        if isinstance(node, ast.Call) and ast.unparse(node.func).endswith("submit")
    ]
    dispatches = [
        node for node in ast.walk(ingest_fn)
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) == "run_in_threadpool"
    ]
    assert len(submits) == 1 and len(dispatches) == 1
    assert submits[0].lineno < dispatches[0].lineno, (
        "the fused merge must be the first database operation of a request"
    )

    # (2) The merged 200 body is produced only for a group hit -- whose
    # transaction committed before the callback returned -- and it carries no
    # workflow id. The group performs exactly one outer commit.
    merged_branch = None
    for node in ast.walk(ingest_fn):
        if isinstance(node, ast.If) and "MergeHit" in ast.unparse(node.test):
            merged_branch = node
    assert merged_branch is not None, "the merged fast branch is gone"
    branch_returns = [n for n in ast.walk(merged_branch) if isinstance(n, ast.Return)]
    assert len(branch_returns) == 1
    returned = ast.unparse(branch_returns[0])
    assert returned.startswith("return (200,"), returned
    assert "'status': 'merged'" in returned, returned
    assert not _gc2_named_calls(merged_branch, "commit"), (
        "the event loop commits for a hit"
    )
    assert not _gc2_named_calls(merged_branch, "start_investigation"), (
        "a merge must start no workflow"
    )
    session_commits = [
        call for call in _gc2_named_calls(closer, "commit")
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "session"
    ]
    assert len(session_commits) == 1, [c.lineno for c in session_commits]
    closer_calls = _gc2_named_calls(batch, GC2_BATCH_CLOSER)
    assert len(closer_calls) == 1, [c.lineno for c in closer_calls]
    batch_returns = [n for n in ast.walk(batch) if isinstance(n, ast.Return)]
    assert batch_returns and all(
        node.lineno > closer_calls[0].lineno for node in batch_returns
    ), "an outcome is returned before the group's transaction was closed"
    # The under-lock merge branch of the fallback keeps its own single commit
    # before its own 200.
    under_lock = None
    for node in ast.walk(txn):
        if isinstance(node, ast.If) and "existing is not None" in ast.unparse(node.test):
            under_lock = node
    assert under_lock is not None, "the under-lock merge branch is gone"
    under_lock_commits = _gc2_named_calls(under_lock, "commit")
    under_lock_returns = [n for n in ast.walk(under_lock) if isinstance(n, ast.Return)]
    assert len(under_lock_commits) == 1 and len(under_lock_returns) == 1
    assert under_lock_commits[0].lineno < under_lock_returns[0].lineno
    assert ast.unparse(under_lock_returns[0]).rstrip().endswith("None)"), (
        "a merge must return no workflow id"
    )

    # (2) The fallback keeps run_in_threadpool, lock-before-deciding-read and
    # the workflow boundary.
    assert _gc2_named_calls(ingest_fn, "run_in_threadpool"), "off-loop dispatch is gone"
    lock_calls = _gc2_named_calls(txn, "acquire_correlation_lock")
    find_calls = _gc2_named_calls(txn, "find_open_by_fingerprint")
    assert len(lock_calls) == 1 and len(find_calls) == 1, (
        [c.lineno for c in lock_calls], [c.lineno for c in find_calls]
    )
    assert lock_calls[0].lineno < find_calls[0].lineno, (
        "the deciding correlation read must happen under the advisory lock"
    )
    starters = _gc2_named_calls(ingest_tree, "start_investigation")
    started_in_ingest = _gc2_named_calls(ingest_fn, "start_investigation")
    assert len(started_in_ingest) == 1 and len(starters) == 1
    assert not _gc2_named_calls(txn, "start_investigation")
    guard = next(
        node for node in ast.walk(ingest_fn)
        if isinstance(node, ast.If) and "investigation_id is not None" in ast.unparse(node.test)
    )
    assert _gc2_named_calls(guard, "start_investigation"), (
        "the workflow start lost its opened-branch guard"
    )
    # No deferred or off-transaction audit machinery appeared, and the audit
    # row still travels inside the transaction that writes its event: every
    # `write_audit` call in this module is inside the individual transaction
    # or its reject helper, before that transaction's own commit, and the
    # grouped hit's audit row is written by the fused statement itself.
    for token in GC2_DEFERRED_AUDIT_TOKENS:
        assert token not in ingest_src, f"deferred audit machinery: {token}"
    reject = _gc2_function(ingest_tree, "_reject", cls="IngestService")
    audit_owners = (txn, reject)
    for call in _gc2_named_calls(ingest_tree, "write_audit"):
        assert any(
            owner.lineno <= call.lineno <= (owner.end_lineno or call.lineno)
            for owner in audit_owners
        ), f"write_audit at line {call.lineno} is outside the individual transaction"
    assert not _gc2_named_calls(batch, "write_audit"), (
        "the group writes an audit row outside the fused statement"
    )
    coalescer_code = _gc4_prose_free(GC2_COALESCER_PATH.read_text(encoding="utf-8"))
    for token in GC2_COALESCER_FORBIDDEN:
        assert token not in coalescer_code, f"the coalescer carries {token!r}"
    for token in GC2_DEFERRED_AUDIT_TOKENS:
        assert token not in coalescer_code, f"deferred audit machinery: {token}"
    # One session scope per transaction owner: one for the group, one for the
    # individual transaction, and none anywhere else.
    for owner, label in ((txn, GC2_TXN), (batch, GC2_BATCH_CALLBACK)):
        session_scopes = [
            node for node in ast.walk(owner)
            if isinstance(node, ast.With)
            and "self._session_factory()" in ast.unparse(node)
        ]
        assert len(session_scopes) == 1, f"{label}: one transaction, one session scope"
    factories = [
        node for node in ast.walk(ingest_tree)
        if isinstance(node, ast.Attribute) and node.attr == "_session_factory"
    ]
    # One store in __init__, one use in each of the two transaction owners.
    assert len(factories) == 3, [node.lineno for node in factories]

    # (3) The CI-scale bar is unchanged and still failure-producing.
    test_src = REF_TEST.read_text(encoding="utf-8")
    test_assigns = _source_assigns(test_src)
    profile_assigns = _module_assigns(REF_PATH)
    for name, expected in GC2_FIXED_CI_SCALE_LITERALS.items():
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    for name in ("CI_SCALE_TOTAL_REQUESTS", "CI_SCALE_P99_MS",
                 "CI_SCALE_SUSTAINED_FLOOR", "CI_SCALE_MAX_IN_FLIGHT"):
        node = test_assigns[name]
        assert isinstance(node, ast.Constant), name
        assert node.value == GC2_FIXED_CI_SCALE_LITERALS[name], name
    ci_scale_test = _gc2_function(ast.parse(test_src), CI_SCALE_REF_TEST)
    observed = {
        ast.unparse(node.test) for node in ast.walk(ci_scale_test)
        if isinstance(node, ast.Assert)
    }
    missing = GC2_CI_SCALE_REQUIRED_ASSERTIONS - observed
    assert not missing, sorted(missing)
    for node in ast.walk(ci_scale_test):
        if isinstance(node, ast.Assert) and ast.unparse(node.test) in (
            GC2_CI_SCALE_REQUIRED_ASSERTIONS
        ):
            assert isinstance(node.test, ast.Compare), ast.unparse(node.test)
    body = ast.get_source_segment(test_src, ci_scale_test) or ""
    for weakening in ("pytest.mark.skip", "pytest.mark.xfail", "pytest.skip(",
                      "VERDICT_MET", "VERDICT_MISSED"):
        assert weakening not in body, f"{CI_SCALE_REF_TEST} must not {weakening}"

    # (4) Serve parameters, pool construction and durability are untouched.
    main_src = GC2_MAIN_PATH.read_text(encoding="utf-8")
    main_assigns = _source_assigns(main_src)
    assert ast.literal_eval(
        main_assigns["DEFAULT_MAX_CONNECTIONS_PER_WORKER"]
    ) == GC2_MAX_CONNECTIONS_PER_WORKER
    assert ast.literal_eval(main_assigns["BACKLOG"]) == GC2_BACKLOG
    assert f'"DBAGENT_GATEWAY_WORKERS", "{GC2_GATEWAY_WORKERS}"' in main_src
    assert "limit_concurrency=max_connections" in main_src
    engine_calls = _gc2_named_calls(ast.parse(main_src), "make_engine")
    assert len(engine_calls) == 1
    assert not engine_calls[0].keywords, "the gateway engine gained a pool keyword"
    assert len(engine_calls[0].args) == 1
    session_src = GC2_SESSION_PATH.read_text(encoding="utf-8")
    factory_defs = [
        node for node in ast.parse(session_src).body
        if isinstance(node, ast.FunctionDef) and node.name == "make_engine"
    ]
    assert len(factory_defs) == 1
    assert "create_engine(dsn, future=True, **kwargs)" in session_src, (
        "make_engine gained or lost a pool default"
    )
    for token in GC2_DURABILITY_TOKENS:
        assert token not in main_src, token
        assert token not in ingest_src, token
        assert token not in session_src, token
        assert token not in GC2_REPO_PATH.read_text(encoding="utf-8"), token

    # (5) The GC-1 launcher allocation and the raw client's limit are unchanged.
    launcher_src = GC2_LAUNCHER_PATH.read_text(encoding="utf-8")
    for line in GC2_LAUNCHER_AFFINITY_LINES:
        assert line in launcher_src, line
    for line in GC2_LAUNCHER_ROUTED_LINES:
        assert line in launcher_src, line
    profile_src = REF_PATH.read_text(encoding="utf-8")
    assert GC2_RAW_CLIENT_LIMIT in profile_src
    assert "MAX_IN_FLIGHT = BURST_RATE" in profile_src
    for profile, cardinalities in GC1_AFFINITY_CARDINALITIES.items():
        assert ast.literal_eval(test_assigns["PRODUCT_AFFINITY_CARDINALITY"]) == cardinalities
    assert _gc1_cardinality_map_failures(test_assigns) == []

    # (6) The chart basis is unchanged, and this slice's own investigation
    # numbers are in no tracked sizing carrier. Ledger emptiness is NOT
    # asserted: its population belongs to test_delivery_sizing_ledger.py and
    # to B1-LATENCY-BASIS-1.
    import yaml as _yaml

    values_text = GC2_VALUES_PATH.read_text(encoding="utf-8")
    values = _yaml.safe_load(values_text)
    basis = values["ingestGateway"]["sizingBasis"]
    # FP-B1LB-7: the basis VALUE is B1-LATENCY-BASIS-1's to move, so this pin
    # no longer requires 2.427 or an empty ledger. What stays GC-2's is its
    # own investigation numbers: they may never become a sizing observation,
    # however the ledger is populated.
    for observation in basis["observations"] or []:
        rendered = str(observation)
        assert GC2_INVESTIGATION_CPU_MS not in rendered, rendered
        assert GC2_INVESTIGATION_RUN_ID not in rendered, rendered
    for parts in GC2_SIZING_CARRIERS:
        carrier = REPO_ROOT.joinpath(*parts)
        assert carrier.is_file(), carrier
        text_ = carrier.read_text(encoding="utf-8")
        assert GC2_INVESTIGATION_CPU_MS not in text_, f"{parts[-1]} carries 5.271"
        assert GC2_INVESTIGATION_RUN_ID not in text_, f"{parts[-1]} carries the run id"
    thresholds = _yaml.safe_load(
        (REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml").read_text(encoding="utf-8")
    )
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    assert GC1_BASIS_OWNER in b1_entry["notes"]
    assert GC1_BASIS_GATE in b1_entry["notes"]

    # (7) The three GC-2 diagnostics are appended, reported-only, and escaped.
    assert GC3_PRODUCT_DIAGNOSTIC_PLACEMENT_FIELDS[-3:] == GC3_PRODUCT_DIAGNOSTIC_TAIL
    for field_name in GC3_PRODUCT_DIAGNOSTIC_TAIL:
        assert field_name not in GC1_GATING_PLACEMENT_FIELDS, field_name
    assert _placement_surface_failures(test_src) == []
    safe_node = _source_assigns(test_src)["B1_DIAGNOSTIC_SAFE_CHARACTERS"]
    assert isinstance(safe_node, ast.Call)
    assert set(ast.literal_eval(safe_node.args[0])) == set(GC2_DIAGNOSTIC_SAFE_CHARACTERS)
    serializer = ast.get_source_segment(
        test_src,
        _gc2_function(ast.parse(test_src), "_serialize_placement_fields"),
    ) or ""
    for field_name in GC3_PRODUCT_DIAGNOSTIC_TAIL:
        assert f'"{field_name}="' in serializer, field_name
        assert serializer.count(f'"{field_name}="') == 1, field_name
    assert serializer.count("_percent_encode_diagnostic(") == 2, serializer
    assert serializer.count("DIAGNOSTIC_UNAVAILABLE") >= 5

    # Negative controls: one mutation at a time, each named. Each proves the
    # pin above would notice, on the GC-5 shape rather than on the retired one.
    repeated = ingest_src.replace(
        "        with self._session_factory() as session:\n"
        "            platform = get_platform(session, event[\"platform_key\"])",
        "        with self._session_factory() as session:\n"
        "            existing_id = merge_existing_event_with_audit(\n"
        "                session,\n"
        "                event=event,\n"
        "                default_correlation_window_seconds=1800,\n"
        "            )\n"
        "            platform = get_platform(session, event[\"platform_key\"])", 1)
    assert repeated != ingest_src
    repeated_txn = _gc2_function(ast.parse(repeated), GC2_TXN, cls="IngestService")
    assert _gc2_named_calls(repeated_txn, GC2_FUSED_HELPER), (
        "the one-fused-call pin would not notice a second fused call on the fallback"
    )
    dropped_commit = ingest_src.replace(
        "            try:\n                session.commit()\n",
        "            try:\n                pass\n", 1)
    assert dropped_commit != ingest_src
    dropped_closer = _gc2_function(
        ast.parse(dropped_commit), GC2_BATCH_CLOSER, cls="IngestService"
    )
    assert not [
        call for call in _gc2_named_calls(dropped_closer, "commit")
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "session"
    ], "the one-outer-commit pin would not notice a dropped commit"
    early_return = ingest_src.replace(
        "            fatal = self._finish_merge_batch(session, outcomes, fatal)\n",
        "            return outcomes\n", 1)
    assert early_return != ingest_src
    early_batch = _gc2_function(
        ast.parse(early_return), GC2_BATCH_CALLBACK, cls="IngestService"
    )
    assert not _gc2_named_calls(early_batch, GC2_BATCH_CLOSER), (
        "the commit-before-outcome pin would not notice an early return"
    )
    unlocked = ingest_src.replace(
        "            acquire_correlation_lock(session, event[\"platform_key\"], "
        "event[\"fingerprint\"])\n", "", 1)
    assert unlocked != ingest_src
    assert not _gc2_named_calls(
        _gc2_function(ast.parse(unlocked), GC2_TXN, cls="IngestService"),
        "acquire_correlation_lock",
    ), "the lock-ordering pin would not notice a removed advisory lock"


# ---------------------------------------------------------------------------
# GC-3 — the closed candidate space, the discovery artifact and the decision
# carrier (FP-GC3-3 / 4 / 6).
#
# Every literal below is declared here, independently of the modules it pins.
# The two tests in this block are the slice's fail-closed carriers: while
# `tests/benchmark/b1_topology_decision.json` does not exist they BOTH fail
# with the named reason `gc3_decision_missing`. That is deliberate and it is
# the design's own statement of the probe head: no model has a decision until
# SOME EXACT CPU MODEL has two complete discovery artifacts of its own, from
# distinct GitHub runs at this exact SHA. There is no reference SKU here --
# the standard four-vCPU pool rotates, every model accumulates its evidence
# independently, and absence must never read as a skip, a default or a
# placeholder.
# ---------------------------------------------------------------------------

GC3_DECISION_MISSING_REASON = "gc3_decision_missing"
GC3_DECISION_INVALID_REASON = "gc3_decision_invalid"
GC3_UNRATIFIED_REASON_PREFIX = "topology_unratified_sku:"
GC3_MODEL_UNAVAILABLE_REASON = "topology_cpu_model_unavailable"
#: The tracked carrier at the exact path the driver container reads it at,
#: through the existing read-only source mount. It is the ONE file that joins
#: the host route to the live fingerprint: the host route record is never
#: copied into B1_RUN_DIR and the closed placement contract gains no cpuModel.
GC3_MOUNTED_CARRIER = "/workspace/tests/benchmark/b1_topology_decision.json"
GC3_WITNESS_TEST = "test_b1_ci_scale_fingerprint_proves_reference_topology"
GC3_RETIRED_WITNESS_TEST = "test_b1_ci_scale_fingerprint_proves_placement"
GC3_PROBE_PROFILE_NAME = "ci-scale-probe"
GC3_CONTRACT_SCHEMA = 3
GC3_SCHEMA2 = 2
# GC-3 rev 0.6: no fixed reference SKU. The decision is keyed by whatever
# exact canonical model string an artifact carries, and the two tests below pin
# that the selector holds no manufacturer, family or SKU literal at all.
# GC-3 rev 0.8 (FP-GC3-7): schema 3 adds the append-only supersession history.
# A model entry carries its CURRENT decision fields directly -- so routing has
# one unambiguous source -- plus `superseded`, an oldest-to-newest list of the
# full decisions it replaced, each naming the head that replaced it.
GC3_DECISION_SCHEMA = 3
#: The `decide` parser's exact option surface, in registration order.
GC3_DECIDE_OPTION_ORDER = ["--out", "--base", "--pair", "--supersede"]
#: The one Git-invoking helper, the two commands it runs, and the closed
#: fail-closed reason for anything other than a clean accept/reject.
GC3_ANCESTRY_HELPER = "verify_decision_ancestry"
GC3_ANCESTRY_UNAVAILABLE_REASON = "gc3_ancestry_unavailable"
GC3_GIT_EXISTENCE_TOKENS = ("cat-file", "-e", "^{{commit}}")
GC3_GIT_ANCESTRY_TOKENS = ("merge-base", "--is-ancestor")
#: Nothing on the benchmark-runtime path may spawn Git: `route` classifies the
#: host from the validated carrier alone, at a checkout of any depth.
GC3_ANCESTRY_FREE_FUNCTIONS = (
    "route_host", "validate_decision", "recompute_decision", "route_fields",
)
GC3_HISTORY_KEY = "superseded"
GC3_HISTORY_RECORD_KEYS = ["decision", "supersededByHeadSha"]
GC3_REFERENCE_LOGICAL_CPUS = 4
GC3_ARMS_PER_ARTIFACT = 28
GC3_ORIENTATIONS = (0, 1)
GC3_ROUNDS = (0, 1)
GC3_TOPOLOGY_IDS = (
    "driver-isolated",
    "gateway-core",
    "gateway-isolated",
    "gateway-split",
    "postgres-core",
    "postgres-isolated",
    "postgres-split",
)
# The abstract maps over the two sibling pairs (a, b) and (c, d). Relationships,
# never CPU ids: `{a, b}` is one physical core on a hosted four-vCPU guest and
# on the i7 replica alike, while the ids differ on both.
GC3_TOPOLOGY_MAPS = {
    "gateway-core": {"gateway": ("a", "b"), "postgres": ("c",), "driver": ("d",),
                     "unassigned": ()},
    "gateway-split": {"gateway": ("a", "c"), "postgres": ("b",), "driver": ("d",),
                      "unassigned": ()},
    "postgres-core": {"gateway": ("a",), "postgres": ("c", "d"), "driver": ("b",),
                      "unassigned": ()},
    "postgres-split": {"gateway": ("b",), "postgres": ("a", "c"), "driver": ("d",),
                       "unassigned": ()},
    "postgres-isolated": {"gateway": ("a",), "postgres": ("c",), "driver": ("b",),
                          "unassigned": ("d",)},
    "driver-isolated": {"gateway": ("a",), "postgres": ("b",), "driver": ("c",),
                        "unassigned": ("d",)},
    "gateway-isolated": {"gateway": ("c",), "postgres": ("a",), "driver": ("b",),
                         "unassigned": ("d",)},
}
GC3_VERDICT_FIELDS = (
    "offered_eq_15000",
    "served_plus_errors_eq_offered",
    "errors_eq_zero",
    "served_eq_offered",
    "p99_lt_150_ms",
    "committed_eq_served",
    "served_rate_gte_450",
    "max_in_flight_lt_500",
    "platform_online",
    "worker_set_stable",
)
GC3_INTEGRITY_VERDICT_FIELDS = (
    "offered_eq_15000",
    "served_plus_errors_eq_offered",
    "committed_eq_served",
    "platform_online",
    "worker_set_stable",
)
GC3_PERFORMANCE_VERDICT_FIELDS = (
    "errors_eq_zero",
    "served_eq_offered",
    "p99_lt_150_ms",
    "served_rate_gte_450",
    "max_in_flight_lt_500",
)
# The schema-3 CI-scale inventory. The physical-topology claim is GATING; the
# gateway sibling map appears here exactly once and therefore not among the
# diagnostics below.
GC3_CI_SCALE_GATING_PLACEMENT_FIELDS = (
    "placement_profile",
    "placement_schema",
    "placement_run_id",
    "measurement_authority",
    "reference_topology",
    "reference_cpus",
    "unassigned_cpus",
    "placement_ok",
    "gateway_allowed_cpus",
    "postgres_allowed_cpus",
    "driver_allowed_cpus",
    "gateway_thread_siblings_pct",
    "postgres_thread_siblings_pct",
    "driver_thread_siblings_pct",
)
GC3_CI_SCALE_DIAGNOSTIC_PLACEMENT_FIELDS = (
    "gateway_quota_cpus",
    "gateway_cpu_period_us",
    "gateway_nr_periods",
    "gateway_nr_throttled",
    "gateway_throttled_usec",
    "postgres_quota_cpus",
    "postgres_cpu_period_us",
    "postgres_nr_periods",
    "postgres_nr_throttled",
    "postgres_throttled_usec",
    "driver_quota_cpus",
    "driver_cpu_period_us",
    "driver_nr_periods",
    "driver_nr_throttled",
    "driver_throttled_usec",
    "gateway_cpu_busy_usec",
    "gateway_nonrole_busy_cores_estimate",
    "gateway_cpu_cores_used",
    "postgres_usage_usec",
    "spectre_v2_pct",
)
GC3_CI_SCALE_PLACEMENT_FIELDS = (
    GC3_CI_SCALE_GATING_PLACEMENT_FIELDS + GC3_CI_SCALE_DIAGNOSTIC_PLACEMENT_FIELDS
)
GC3_TOPOLOGY_ONLY_FIELDS = (
    "reference_topology",
    "reference_cpus",
    "unassigned_cpus",
    "postgres_thread_siblings_pct",
    "driver_thread_siblings_pct",
)
GC3_LAUNCHER = REPO_ROOT / "scripts" / "integration-test.sh"
GC3_CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GC3_DELIVERY_CI = REPO_ROOT / "tests" / "delivery" / "test_delivery_ci.py"
GC3_PRODUCER_REL = "services/gateway/tests/test_b1_ingest_burst.py"
GC3_PROBE_LIVE_REL = "services/gateway/tests/b1_topology_probe_live.py"
GC3_COVERAGE_SELECTION = (
    "-m 'not b1_live and not b1_product and not b1_latency_basis and not b1_topology_probe'"
)
GC3_LIVE_SELECTION = (
    "-m 'b1_live and not b1_product and not b1_latency_basis and not b1_topology_probe'"
)
GC3_PROBE_SELECTION = "-m b1_topology_probe"
GC3_PRODUCT_SELECTION = "-m b1_product"
# B1-LATENCY-BASIS-1 FP-B1LB-6: the fifth selection, declared beside the four
# GC-3 pinned above rather than derived from any of them. It is the ordinary
# CI-scale live selection WITHOUT `not b1_latency_basis`, so it adds exactly
# the FP-IG-18 oracle node -- and it must appear exactly once, only in the
# isolated target, while all four above stay byte-exact.
GC3_LATENCY_BASIS_SELECTION = "-m 'b1_live and not b1_product and not b1_topology_probe'"
GC3_PROBE_JOB = "b1-topology-probe"
# The GC-2 RCA's own diagnostics. Neither may become a sizing observation nor a
# selection threshold: mean CPU explains a result and cannot prove due-time
# p99, errors, completion or audit accounting.
GC3_RCA_POSTGRES_MS = "2.105"
GC3_RCA_GATEWAY_MS = "1.901"
GC3_RCA_RUN_ID = "35080052686"
GC3_SIZING_CARRIERS = (
    ("deploy", "charts", "dbagent", "values.yaml"),
    ("tests", "benchmark", "thresholds.yaml"),
    ("tests", "delivery", "test_delivery_sizing_ledger.py"),
    ("services", "gateway", "tests", "b1_reference_profile.py"),
    ("services", "gateway", "tests", "test_b1_ingest_burst.py"),
    ("services", "gateway", "tests", "b1_topology_probe.py"),
    ("services", "gateway", "tests", "b1_topology_probe_live.py"),
    ("scripts", "integration-test.sh"),
)
GC3_WEAKENINGS = (
    "pytest.mark.skip",
    "pytest.mark.xfail",
    "pytest.skip(",
    "--deselect",
    "continue-on-error",
    "|| true",
)
GC3_BANDWIDTH_CONTROLS = GC1_BANDWIDTH_CONTROLS

gc3 = _load(PROBE_HELPER, "gc3_topology_probe")


def _gc3_emitted_fields(src: str, name: str) -> tuple[str, ...]:
    """The field names one serializer emits, in emission order.

    Reconstructed from the function's own literals rather than from a tuple it
    could import: a pin derived from its subject detects nothing. Each
    ``for role in B1_ROLES`` loop expands role-major on its own, so two
    consecutive per-role blocks cannot be folded into one interleaved run.
    """
    tree = ast.parse(src)
    fn = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name), None
    )
    if fn is None:
        return ()
    rendered_fn = next(
        (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "rendered"),
        None,
    )
    per_role_diagnostics = (
        [m.group(1) for m in re.finditer(r'f"\{self\.role\}_([a-z_0-9]+)"',
                                         ast.get_source_segment(src, rendered_fn) or "")]
        if rendered_fn is not None else []
    )

    def literals(text: str) -> list[str]:
        return [m.group(2) for m in re.finditer(r'[f]?"(\{role\}_)?([a-z_0-9]+)=', text)]

    out: list[str] = []
    for stmt in fn.body:
        # The RAW source segment, never ast.unparse: unparse normalises string
        # quoting and the literals this reconstruction reads would vanish.
        text = ast.get_source_segment(src, stmt) or ""
        if isinstance(stmt, ast.For) and ast.unparse(stmt.iter) == "B1_ROLES":
            if "rendered()" in text:
                for role in GC1_ROLES:
                    out.extend(f"{role}_{suffix}" for suffix in per_role_diagnostics)
                continue
            suffixes = [m.group(1) for m in re.finditer(r'f"\{role\}_([a-z_0-9]+)=', text)]
            for role in GC1_ROLES:
                out.extend(f"{role}_{suffix}" for suffix in suffixes)
            continue
        out.extend(literals(text))
    return tuple(out)


def _gc3_topology_surface_failures(src: str) -> list[str]:
    """FP-GC3-5: the schema-3 inventory, and its separation from schema 2."""
    tree = ast.parse(src)
    fails: list[str] = []
    gating = _module_tuple(tree, "B1_TOPOLOGY_GATING_PLACEMENT_FIELDS")
    diagnostics = _module_tuple(tree, "B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS")
    if gating != GC3_CI_SCALE_GATING_PLACEMENT_FIELDS:
        fails.append(f"schema-3 gating inventory drift: {gating}")
    if diagnostics != GC3_CI_SCALE_DIAGNOSTIC_PLACEMENT_FIELDS:
        fails.append(f"schema-3 diagnostic inventory drift: {diagnostics}")
    composition = next(
        (ast.unparse(n.value) for n in tree.body
         if isinstance(n, ast.Assign) and len(n.targets) == 1
         and isinstance(n.targets[0], ast.Name)
         and n.targets[0].id == "B1_TOPOLOGY_PLACEMENT_FIELDS"), None
    )
    if composition != (
        "B1_TOPOLOGY_GATING_PLACEMENT_FIELDS + B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS"
    ):
        fails.append(f"schema-3 fields are not gating-first: {composition}")
    # No field is duplicated within the schema-3 line, and the topology claim is
    # gating rather than diagnostic.
    if len(set(GC3_CI_SCALE_PLACEMENT_FIELDS)) != len(GC3_CI_SCALE_PLACEMENT_FIELDS):
        fails.append("schema-3 line repeats a field")
    if "gateway_thread_siblings_pct" in diagnostics:
        fails.append("gateway_thread_siblings_pct is duplicated in the schema-3 diagnostics")
    for field in GC3_TOPOLOGY_ONLY_FIELDS:
        if field not in gating:
            fails.append(f"{field} is not gating under schema 3")
        if field in GC3_PRODUCT_DIAGNOSTIC_PLACEMENT_FIELDS or field in GC1_GATING_PLACEMENT_FIELDS:
            fails.append(f"{field} leaked into the schema-2 inventory")
    if diagnostics[-2:] != GC3_CI_SCALE_DIAGNOSTIC_TAIL:
        fails.append(f"schema-3 tail is {diagnostics[-2:]}")
    if GC3_PRODUCT_DIAGNOSTIC_PLACEMENT_FIELDS[-3:] != GC3_PRODUCT_DIAGNOSTIC_TAIL:
        fails.append("the schema-2 product tail changed")
    # The two serializers are separate functions, each emitting exactly its own
    # inventory in order. The schema-2 one is byte-unchanged from GC-1/GC-2.
    emitted = _gc3_emitted_fields(src, "_serialize_topology_placement_fields")
    if emitted != GC3_CI_SCALE_PLACEMENT_FIELDS:
        fails.append(f"_serialize_topology_placement_fields emits {emitted}")
    legacy = _gc3_emitted_fields(src, "_serialize_placement_fields")
    if legacy != GC1_PLACEMENT_FIELDS:
        fails.append(f"_serialize_placement_fields emits {legacy}")
    # The inventory is selected from the parsed contract, not shared.
    live = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == LIVE_RUN_IMPL), None
    )
    if live is None:
        return fails + [f"{LIVE_RUN_IMPL}: missing"]
    body = ast.get_source_segment(src, live) or ""
    if "if declaration.carries_topology:" not in body:
        fails.append("the serializer is not selected from the parsed contract")
    for clause in (
        "_serialize_topology_placement_fields(",
        "_serialize_placement_fields(",
        "siblings_before = _read_reference_sibling_groups(declaration)",
        "siblings_open = _read_reference_sibling_groups(declaration)",
        "siblings_close = _read_reference_sibling_groups(declaration)",
        "sibling_groups=siblings_open",
    ):
        if clause not in body:
            fails.append(f"{LIVE_RUN_IMPL} lost {clause!r}")
    return fails


def _gc3_candidate_space_failures() -> list[str]:
    """FP-GC3-1: seven classes, two orientations, two rounds, 28 unique arms."""
    fails: list[str] = []
    if tuple(sorted(gc3.TOPOLOGY_CLASSES)) != GC3_TOPOLOGY_IDS:
        fails.append(f"topology ids {tuple(sorted(gc3.TOPOLOGY_CLASSES))}")
        return fails
    if gc3.TOPOLOGY_IDS != GC3_TOPOLOGY_IDS:
        fails.append("TOPOLOGY_IDS is not the lexically sorted closed set")
    for topology, expected in GC3_TOPOLOGY_MAPS.items():
        got = gc3.TOPOLOGY_CLASSES[topology]
        if {k: tuple(v) for k, v in got.items()} != expected:
            fails.append(f"{topology} maps {got}, expected {expected}")
    if gc3.ARMS_PER_ARTIFACT != GC3_ARMS_PER_ARTIFACT:
        fails.append(f"arms per artifact {gc3.ARMS_PER_ARTIFACT}")
    if tuple(gc3.ORIENTATIONS) != GC3_ORIENTATIONS or tuple(gc3.ROUNDS) != GC3_ROUNDS:
        fails.append("orientations/rounds are not the closed pairs")
    # Two independent pairings, so the enumeration is a relationship rather than
    # a CPU-id literal: a hosted guest's (0,1)/(2,3) and an i7 replica's
    # (0,8)/(1,9) must produce the same 28 relationships.
    for pair0, pair1 in (((0, 1), (2, 3)), ((0, 8), (1, 9))):
        arms = gc3.enumerate_arms(pair0, pair1)
        if len(arms) != GC3_ARMS_PER_ARTIFACT:
            fails.append(f"{pair0}/{pair1}: {len(arms)} arms")
            continue
        keys = {(a["topology"], a["round"], a["orientation"]) for a in arms}
        if len(keys) != GC3_ARMS_PER_ARTIFACT:
            fails.append(f"{pair0}/{pair1}: {len(keys)} unique arms")
        # Round 1 reverses both orders, so no class owns only late arms.
        first_round = [a["topology"] for a in arms if a["round"] == 0]
        second_round = [a["topology"] for a in arms if a["round"] == 1]
        if first_round == second_round:
            fails.append("both rounds run in the same order")
        if [a["orientation"] for a in arms[:2]] != [0, 1]:
            fails.append("round 0 does not run orientation 0 then 1")
        if [a["orientation"] for a in arms[14:16]] != [1, 0]:
            fails.append("round 1 does not run orientation 1 then 0")
        reference = frozenset((*pair0, *pair1))
        for arm in arms:
            roles = {r: gc3.parse_cpu_list(arm["roles"][r]) for r in ("gateway", "postgres", "driver")}
            if len(roles["driver"]) != 1:
                fails.append(f"{arm['topology']}: driver holds {sorted(roles['driver'])}")
            if not 1 <= len(roles["gateway"]) <= 2 or not 1 <= len(roles["postgres"]) <= 2:
                fails.append(f"{arm['topology']}: role cardinality outside 1..2")
            union = roles["gateway"] | roles["postgres"] | roles["driver"]
            if len(union) != sum(len(v) for v in roles.values()):
                fails.append(f"{arm['topology']}: measured roles overlap")
            if not union <= reference:
                fails.append(f"{arm['topology']}: allocates outside the reference set")
            idle = reference - union
            if len(idle) > 1:
                fails.append(f"{arm['topology']}: {len(idle)} unassigned CPUs")
            rendered = gc3.format_cpu_list(idle) if idle else "none"
            if arm["unassignedCpus"] != rendered:
                fails.append(f"{arm['topology']}: unassignedCpus {arm['unassignedCpus']}")
    if tuple(gc3.VERDICT_FIELDS) != GC3_VERDICT_FIELDS:
        fails.append(f"verdict fields {tuple(gc3.VERDICT_FIELDS)}")
    if tuple(gc3.INTEGRITY_VERDICT_FIELDS) != GC3_INTEGRITY_VERDICT_FIELDS:
        fails.append("integrity verdict block drift")
    if tuple(gc3.PERFORMANCE_VERDICT_FIELDS) != GC3_PERFORMANCE_VERDICT_FIELDS:
        fails.append("performance verdict block drift")
    if set(GC3_INTEGRITY_VERDICT_FIELDS) & set(GC3_PERFORMANCE_VERDICT_FIELDS):
        fails.append("a verdict is both integrity and performance")
    if set(GC3_INTEGRITY_VERDICT_FIELDS) | set(GC3_PERFORMANCE_VERDICT_FIELDS) != set(
        GC3_VERDICT_FIELDS
    ):
        fails.append("the two verdict blocks do not partition the vocabulary")
    return fails


def _gc3_decide_parser_failures() -> list[str]:
    """FP-GC3-3/7: the `decide` subparser's own argument surface, as built.

    Rev 0.8: exactly required `--out`, REQUIRED `--base`, required two-value
    `--pair` and optional single-value `--supersede`; no positional path; and
    none of the forbidden override flags, read off the parser rather than off
    its source. `--base` is required because the tracked carrier already
    exists: omitting it could construct a one-model replacement that looked
    valid while discarding every other model and every history.
    """
    import argparse

    fails: list[str] = []
    parser = gc3.build_parser()
    subparsers = [
        action for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    ]
    if len(subparsers) != 1 or "decide" not in subparsers[0].choices:
        return ["the decide subparser is missing"]
    decide = subparsers[0].choices["decide"]
    actions = {
        action.dest: action for action in decide._actions if action.dest != "help"
    }
    options = {
        option for action in actions.values() for option in action.option_strings
    }
    if options != set(GC3_DECIDE_OPTION_ORDER):
        fails.append(f"the decide parser exposes {sorted(options)}")
    positionals = sorted(
        dest for dest, action in actions.items() if not action.option_strings
    )
    if positionals:
        fails.append(f"the decide parser takes the positional(s) {positionals}")
    out = actions.get("out")
    if out is None or not out.required:
        fails.append("--out is not required")
    pair = actions.get("pair")
    if pair is None or not pair.required or pair.nargs != 2:
        fails.append(f"--pair is {getattr(pair, 'nargs', None)!r}, required two values")
    base = actions.get("base")
    if base is None or not base.required:
        fails.append("--base is not the required complete carrier to merge into")
    supersede = actions.get("supersede")
    if (
        supersede is None
        or supersede.required
        or supersede.default is not None
        or supersede.nargs is not None
    ):
        fails.append("--supersede is not an optional single-value evidence head")
    for forbidden in ("--force", "--select", "--candidate", "--threshold", "--tie",
                      "--topology", "--model", "--cpu-model", "--status"):
        if forbidden in options:
            fails.append(f"the decide parser exposes {forbidden}")
    return fails


#: The minimal readability anchors the two downstream handoff notes keep. They
#: neither replace nor satisfy the structural head assertions below.
GC3_HANDOFF_ANCHORS = ("current evidence head", "superseded", "GC-3 alone")


def _gc3_handoff_provenance_failures(notes: str) -> list[str]:
    """FP-GC3-7: the carrier-derived provenance both downstream slices hand over.

    Neither GC-4 nor GC-5 may pin an evidence head, a status or an empty
    declaration map: they change product cost and hand over a head, and GC-3
    alone decides hostability. What they owe is that the tracked carrier is
    intact and fully recomputed, that every current and superseded decision
    carries its own recorded head, that the edge chain terminates at the
    current head with strict Git descent, and that the manifest's per-model row
    names those heads as full 40-lowercase-hex values in carrier order.
    """
    fails: list[str] = []
    decision = json.loads(GC3_DECISION.read_text(encoding="utf-8"))
    # The common full-carrier recomputer, so no prior entry can be dropped.
    gc3.validate_decision(decision)
    models = decision["models"]
    if not models:
        return ["the decision carrier has no model entry"]
    if gc3.recompute_decision(decision) != models:
        fails.append("the carrier is not what the selector derives from its own evidence")
    harness_assigns = _source_assigns(REF_TEST.read_text(encoding="utf-8"))
    selected = {
        model: entry for model, entry in models.items()
        if entry["status"] == gc3.DECISION_SELECTED
    }
    expected_cardinalities = {
        model: entry["cardinality"] for model, entry in selected.items()
    }
    expected_schemas = {model: GC1_SELECTED_PLACEMENT_SCHEMA for model in selected}
    if ast.literal_eval(
        harness_assigns["CI_SCALE_AFFINITY_CARDINALITIES_BY_CPU_MODEL"]
    ) != expected_cardinalities:
        fails.append("the harness cardinality map is not the carrier's selected entries")
    if ast.literal_eval(
        harness_assigns["CI_SCALE_PLACEMENT_SCHEMAS_BY_CPU_MODEL"]
    ) != expected_schemas:
        fails.append("the harness schema map is not the carrier's selected entries")
    edges = 0
    for model, entry in models.items():
        head = entry["evidenceHeadSha"]
        for wrapper in entry["artifacts"]:
            if wrapper["artifact"]["headSha"] != head:
                fails.append(f"{model}: a current artifact is not at {head}")
        history = entry[GC3_HISTORY_KEY]
        chain = []
        for index, record in enumerate(history):
            older = record["decision"]["evidenceHeadSha"]
            for wrapper in record["decision"]["artifacts"]:
                if wrapper["artifact"]["headSha"] != older:
                    fails.append(f"{model}: superseded[{index}] artifact is not at {older}")
            chain.append(older)
        chain.append(head)
        if history and history[-1]["supersededByHeadSha"] != head:
            fails.append(f"{model}: the history chain does not terminate at {head}")
        for older, newer in zip(chain, chain[1:]):
            edges += 1
            try:
                gc3.verify_decision_ancestry(older, newer)
            except gc3.TopologyProbeError as exc:
                fails.append(f"{model}: {older} -> {newer}: {exc}")
        row = _gc3_notes_row(notes, model)
        if head not in row:
            fails.append(f"{model}: the manifest row omits the current head {head}")
        offsets = []
        for older in chain[:-1]:
            if older not in row:
                fails.append(f"{model}: the manifest row omits superseded head {older}")
            else:
                offsets.append(row.index(older))
        if offsets != sorted(offsets):
            fails.append(f"{model}: the manifest lists superseded heads out of carrier order")
        if not history and "superseded: none" not in row:
            fails.append(f"{model}: the manifest row does not record superseded: none")
        if entry["status"] != gc3.DECISION_SELECTED:
            if f"topology_unratified_sku:{model}" not in notes:
                fails.append(f"{model}: the recorded reason is unpublished")
    if gc3.verify_carrier_ancestry(decision) != edges:
        fails.append("the carrier walker proves a different number of edges")
    for readability in GC3_HANDOFF_ANCHORS:
        if readability not in notes:
            fails.append(f"the manifest does not read as provenance: {readability!r}")
    return fails


def _gc3_notes_row(notes: str, model: str) -> str:
    """The manifest's per-model row, found by the EXACT model string.

    Structural, not lexical: the row is located by its own model key and then
    required to contain the carrier's full heads. An author-chosen phrase can
    neither satisfy nor replace that.
    """
    marker = f"`{model}` -- status "
    assert notes.count(marker) == 1, f"the manifest has no single row for {model!r}"
    start = notes.index(marker)
    rest = notes[start + len(marker):]
    ends = [rest.index(token) for token in ("\n`", "\nNo row in this revision") if token in rest]
    return notes[start:start + len(marker) + (min(ends) if ends else len(rest))]


def _gc3_git_output(*arguments: str) -> str:
    """One offline `git -C <repo> ...` read, or the named fail-closed reason.

    The jailed review-runner image runs as root over a host-owned read-only
    `/workspace`, where Git refuses with `dubious ownership` unless the
    reviewer first runs `git config --global --add safe.directory /workspace`.
    That is an environment result to configure and rerun -- never a waiver and
    never a non-gating test.
    """
    result = subprocess.run(
        ["git", "-C", str(REPO_ROOT), *arguments],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=False,
    )
    assert result.returncode == 0, (
        f"{GC3_ANCESTRY_UNAVAILABLE_REASON}: git {' '.join(arguments)} exited "
        f"{result.returncode} in {REPO_ROOT} ({result.stderr.strip()}). The ancestry "
        f"authorities are the functional CI checkout with fetch-depth: 0 and a "
        f"full-history host checkout; inside the review-runner image run "
        f"`git config --global --add safe.directory /workspace` first."
    )
    return result.stdout.strip()


def _gc3_require_commit_object(sha: str) -> None:
    """Every retained head is a commit in THIS checkout's object database."""
    assert re.fullmatch(r"[0-9a-f]{40}", sha), sha
    _gc3_git_output("cat-file", "-e", f"{sha}^{{commit}}")


def _gc3_supersession_failures() -> list[str]:
    """FP-GC3-7: the supersession lifecycle's own source surface.

    Three separable claims, each named:

    * the carrier is schema 3 and every entry closes over the current decision
      fields plus one append-only `superseded` list of full prior decisions;
    * the strict-descendant proof is LOCAL Git history -- two no-shell
      commands, a three-way exit mapping and a closed fail-closed reason --
      and it lives in exactly one helper; and
    * nothing on the benchmark-runtime path spawns Git, so `route` keeps
      working at a checkout of any depth while publication through the
      Git-backed delivery gate is the ancestry authority.
    """
    fails: list[str] = []
    source = PROBE_HELPER.read_text(encoding="utf-8")
    tree = ast.parse(source)
    functions = {
        node.name: node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    # --- the closed schema-3 entry and history shapes ----------------------
    if getattr(gc3, "DECISION_SCHEMA", None) != GC3_DECISION_SCHEMA:
        fails.append(f"decision schema {getattr(gc3, 'DECISION_SCHEMA', None)!r}")
    decision_keys = set(getattr(gc3, "DECISION_DECISION_KEYS", ()) or ())
    entry_keys = set(getattr(gc3, "DECISION_ENTRY_KEYS", ()) or ())
    if not decision_keys:
        fails.append("the closed decision-field inventory is missing")
    elif GC3_HISTORY_KEY in decision_keys:
        fails.append(f"a decision carries {GC3_HISTORY_KEY!r} and can nest a history")
    elif entry_keys != decision_keys | {GC3_HISTORY_KEY}:
        fails.append(f"a current entry is {sorted(entry_keys)}")
    history_keys = sorted(getattr(gc3, "DECISION_HISTORY_KEYS", ()) or ())
    if history_keys != GC3_HISTORY_RECORD_KEYS:
        fails.append(f"a history record is {history_keys}")

    # --- exactly one Git-invoking helper -----------------------------------
    spawners = sorted(
        name for name, node in functions.items()
        if any(
            isinstance(call.func, ast.Attribute)
            and isinstance(call.func.value, ast.Name)
            and call.func.value.id == "subprocess"
            for call in ast.walk(node) if isinstance(call, ast.Call)
        )
    )
    if spawners != [GC3_ANCESTRY_HELPER]:
        fails.append(f"the module spawns a process from {spawners}")
    if "shell=True" in source:
        fails.append("the selector runs a shell")
    helper_node = functions.get(GC3_ANCESTRY_HELPER)
    if helper_node is None:
        return fails + [f"{GC3_ANCESTRY_HELPER}: missing"]
    # Its CODE, with its own prose removed: the prose legitimately names
    # `fetch-depth` and "no fetch", and a substring scan over it would fire on
    # the sentence that forbids the thing.
    code = ast.Module(
        body=[
            statement for statement in helper_node.body
            if not (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            )
        ],
        type_ignores=[],
    )
    body = ast.unparse(code)
    for token in ("git", "-C", "str(REPO_ROOT)",
                  *GC3_GIT_EXISTENCE_TOKENS, *GC3_GIT_ANCESTRY_TOKENS):
        if token not in body:
            fails.append(f"{GC3_ANCESTRY_HELPER} lost {token!r}")
    # The three-way exit mapping: accept, reject, fail closed. Nothing else.
    if getattr(gc3, "DECISION_ANCESTRY_UNAVAILABLE_REASON", None) != (
        GC3_ANCESTRY_UNAVAILABLE_REASON
    ):
        fails.append("the fail-closed ancestry reason is not the named one")
    for clause in ("returncode == 0", "returncode == 1",
                   "DECISION_ANCESTRY_UNAVAILABLE_REASON"):
        if clause not in body:
            fails.append(f"{GC3_ANCESTRY_HELPER} lost the {clause!r} branch")
    if "named_head == pair_head" not in body:
        fails.append(f"{GC3_ANCESTRY_HELPER} accepts an equal head as a descendant")
    # No network fallback exists: the proof is the local object database.
    for network in ("fetch", "ls-remote", "clone", "http", "origin"):
        if network in body:
            fails.append(f"{GC3_ANCESTRY_HELPER} reaches for {network!r}")

    # --- the repository root has no caller or environment override ---------
    root = next(
        (node for node in tree.body
         if isinstance(node, ast.Assign)
         and any(isinstance(t, ast.Name) and t.id == "REPO_ROOT" for t in node.targets)),
        None,
    )
    if root is None:
        fails.append("REPO_ROOT is not a module constant")
    elif ast.unparse(root.value) != "Path(__file__).resolve().parents[3]":
        fails.append(f"REPO_ROOT is {ast.unparse(root.value)}")
    if "REPO_ROOT" in source.split("def build_parser", 1)[-1]:
        fails.append("REPO_ROOT is reachable from the CLI surface")

    # --- who may and may not call it ---------------------------------------
    def _calls(name: str) -> set:
        node = functions.get(name)
        if node is None:
            return set()
        return {
            ast.unparse(call.func) for call in ast.walk(node) if isinstance(call, ast.Call)
        }

    for runtime in GC3_ANCESTRY_FREE_FUNCTIONS:
        if runtime not in functions:
            fails.append(f"{runtime}: missing")
            continue
        called = _calls(runtime)
        if GC3_ANCESTRY_HELPER in called or "verify_carrier_ancestry" in called:
            fails.append(f"{runtime} spawns Git at benchmark runtime")
    # BOTH proofs, because they answer different questions: the walker
    # re-proves every edge already in the base, and the direct call proves the
    # new edge this invocation is about to add. Either one alone leaves half
    # the carrier unproved.
    builder = _calls("build_decision")
    for proof in (GC3_ANCESTRY_HELPER, "verify_carrier_ancestry"):
        if proof not in builder:
            fails.append(f"build_decision does not call {proof}")
    if "verify_carrier_ancestry" not in functions:
        fails.append("verify_carrier_ancestry: missing")
    elif GC3_ANCESTRY_HELPER not in _calls("verify_carrier_ancestry"):
        fails.append("verify_carrier_ancestry proves no edge")
    return fails


def _gc3_selector_failures() -> list[str]:
    """FP-GC3-3: eligibility, ranking and the absence of any override."""
    fails: list[str] = []
    # The decision CLI takes exactly two input paths and one output path.
    src = PROBE_HELPER.read_text(encoding="utf-8")
    tree = ast.parse(src)
    builder = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_parser"), None
    )
    if builder is None:
        return ["build_parser: missing"]
    body = ast.get_source_segment(src, builder) or ""
    decide_block = body.split('sub.add_parser("decide"', 1)
    if len(decide_block) != 2:
        return ["the decide subcommand is missing"]
    # GC-3 rev 0.8: exactly required `--out`, required `--base`, required
    # two-value `--pair`, and optional single-value `--supersede`, REGISTERED
    # IN THAT SOURCE ORDER. No positional path, and no other option: one
    # invocation admits one exact model and merges it into the complete
    # carrier it was given.
    decide_source = decide_block[1].split("\n\n", 1)[0]
    options = re.findall(r'decide\.add_argument\("([^"]+)"', decide_source)
    if options != GC3_DECIDE_OPTION_ORDER:
        fails.append(f"the decide CLI takes {options}")
    if any(not option.startswith("--") for option in options):
        fails.append("the decide CLI accepts a positional path")
    if 'decide.add_argument("--out", required=True)' not in decide_source:
        fails.append("--out is not required")
    if 'decide.add_argument("--pair", required=True, nargs=2' not in decide_source:
        fails.append("--pair is not a required two-value option")
    if 'decide.add_argument("--base", required=True)' not in decide_source:
        fails.append("--base is not the required complete carrier to merge into")
    if 'decide.add_argument("--supersede", default=None)' not in decide_source:
        fails.append("--supersede is not an optional single-value evidence head")
    for forbidden in ("candidate", "threshold", "tie", "topology=", "--force", "--select"):
        if forbidden in decide_block[1]:
            fails.append(f"the decide CLI exposes {forbidden!r}")
    # ...and the same claim about the BUILT parser, not its source text. The
    # substring scan above runs over everything after the `decide` marker,
    # which includes the routing subparsers defined below it; this reads the
    # decide parser's own `option_strings`, so it neither misses a flag added
    # through a loop nor fires on a later subcommand's legitimate option.
    fails.extend(_gc3_decide_parser_failures())
    fails.extend(_gc3_supersession_failures())
    # CPU diagnostics may not enter the ranking.
    score = ast.get_source_segment(
        src, next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "score_topology")
    ) or ""
    for operand in ("p99Ms", "maxInFlight", "servedRate"):
        if operand not in score:
            fails.append(f"the ranking lost {operand}")
    for diagnostic in ("postgresUsageUsec", "gatewayCpuCoresUsed", "cpu_ms", "usage_usec"):
        if diagnostic in score:
            fails.append(f"the ranking uses the CPU diagnostic {diagnostic}")
    # GC-3 rev 0.6: there is NO fixed reference SKU any more. Admission is
    # "both artifacts carry the same validated exact model", and the model
    # rules are closed text rules with no manufacturer, family or SKU literal.
    if hasattr(gc3, "REFERENCE_CPU_MODEL"):
        fails.append("the fixed REFERENCE_CPU_MODEL survives")
    admit = ast.get_source_segment(
        src, next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "admit_evidence")
    ) or ""
    if "models[0] != models[1]" not in admit:
        fails.append("admission no longer requires the two artifacts to share a model")
    for vendor in ("EPYC", "Xeon", "AMD", "Intel"):
        if vendor in src:
            fails.append(f"the selector carries the SKU literal {vendor!r}")
    if gc3.DECISION_SCHEMA != GC3_DECISION_SCHEMA:
        fails.append(f"decision schema {gc3.DECISION_SCHEMA}")
    if gc3.REFERENCE_LOGICAL_CPUS != GC3_REFERENCE_LOGICAL_CPUS:
        fails.append(f"reference logical CPUs {gc3.REFERENCE_LOGICAL_CPUS}")
    if gc3.CPU_MODEL_UNKNOWN != "unknown":
        fails.append(f"model sentinel {gc3.CPU_MODEL_UNKNOWN!r}")
    for illegal in ("unknown", "", "x" * 300, "two  spaces", " padded", 7, None):
        if gc3.is_decision_eligible_cpu_model(illegal):
            fails.append(f"the model rules admit {illegal!r}")
    if not gc3.is_decision_eligible_cpu_model("Some Exact Model 9000"):
        fails.append("the model rules are an allowlist rather than text rules")
    return fails


GC3_PROBE_NODE = "test_b1_ci_scale_topology_probe_record"


def _gc3_probe_partition_failures(src: str) -> list[str]:
    """FP-GC3-2: the recorded/gating partition inside the discovery node.

    The five INTEGRITY statuses are asserted directly -- a miss there means the
    measurement is undefined. The five PERFORMANCE statuses are recorded: the
    node may check that a token equals its own live comparison and that it is
    one of the two admitted words, and it may not require any of them to be
    ``met``. Truth-gating one would stop the sweep at the first expected miss
    and destroy the evidence the decision needs.
    """
    tree = ast.parse(src)
    fails: list[str] = []
    node = next(
        (n for n in ast.walk(tree)
         if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == GC3_PROBE_NODE),
        None,
    )
    if node is None:
        return [f"{GC3_PROBE_NODE}: missing"]
    body = ast.get_source_segment(src, node) or ""
    for performance in GC3_PERFORMANCE_VERDICT_FIELDS:
        if f'"{performance}"' in body or f"'{performance}'" in body:
            fails.append(f"{GC3_PROBE_NODE}: names the performance status {performance}")
    if "probe.PERFORMANCE_VERDICT_FIELDS" not in body:
        fails.append(f"{GC3_PROBE_NODE}: does not record the performance block")
    # A `== VERDICT_MET` assertion is admissible ONLY inside the loop over the
    # integrity block. Anywhere else it turns a recorded datum back into a bar.
    admitted: set[int] = set()
    for loop in ast.walk(node):
        if isinstance(loop, ast.For) and "INTEGRITY_VERDICT_FIELDS" in ast.unparse(loop.iter):
            admitted.update(
                id(n) for n in ast.walk(loop) if isinstance(n, ast.Assert)
            )
    gating = [
        n for n in ast.walk(node)
        if isinstance(n, ast.Assert) and id(n) in admitted
        and re.search(r"==\s*probe\.VERDICT_MET\b", ast.unparse(n.test))
    ]
    if not gating:
        fails.append(
            f"{GC3_PROBE_NODE}: the integrity block is iterated but never asserted met"
        )
    for assertion in ast.walk(node):
        if not isinstance(assertion, ast.Assert):
            continue
        rendered = ast.unparse(assertion.test)
        # `token in (VERDICT_MET, VERDICT_MISSED)` is the admitted-word check,
        # not a bar: it passes for either word. Only an EQUALITY against `met`
        # turns a datum back into a threshold.
        if not re.search(r"==\s*probe\.VERDICT_MET\b", rendered):
            continue
        if id(assertion) not in admitted:
            fails.append(f"{GC3_PROBE_NODE}: truth-gates a recorded status: {rendered}")
    # The two record-consistency checks the recorded half rests on.
    for recorded in ("token == live[field]", "token in (probe.VERDICT_MET, probe.VERDICT_MISSED)"):
        if recorded not in body:
            fails.append(f"{GC3_PROBE_NODE}: missing record-consistency check {recorded!r}")
    # ...and the preconditions that make a record admissible at all.
    for gating in (
        'assert run["placement_ok"] is True',
        "record = harness.build_probe_arm_record(run, context)",
        "harness.write_probe_arm_record(record)",
    ):
        if gating not in body:
            fails.append(f"{GC3_PROBE_NODE}: missing gating step {gating!r}")
    return fails


#: The shell text of one launcher target, delimited by top-level function
#: headers. ONE definition, in tests/functional/test_manifests.py, reached
#: through the `_manifests` seam this module already loads: three copies of
#: this body existed and would have drifted (review-followups-batch-20260920
#: W1). Delimiting on headers rather than on a comment between the targets is
#: the point: a comment can be reworded without changing anything the launcher
#: does, and a check that splits on one silently widens its region when that
#: happens.
_b1_target_region = _manifests._b1_target_region


def _gc3_route_surface_failures() -> list[str]:
    """FP-GC3-4/5: the routing CLI, the launcher flow and the mounted witness.

    Three independent legs, checked from the sources themselves:

    * the planner exposes exactly `route`, `route-fields` and
      `contract-selected` with the argument and output contracts §3.5 fixes,
      and none of them accepts a profile, model, topology, status, reason,
      role mapping or cardinality value;
    * the launcher reaches placement only through them -- unconditional
      coverage, then `route`, then one `route-fields` read, then
      `contract-selected` -- and spells no topology and no reason itself; and
    * the renamed live witness is the one that joins decision to fingerprint,
      through the mounted carrier and the model the MEASURED container reports.
    """
    fails: list[str] = []
    helper = PROBE_HELPER.read_text(encoding="utf-8")
    launcher = GC3_LAUNCHER.read_text(encoding="utf-8")
    harness = REF_TEST.read_text(encoding="utf-8")
    tree = ast.parse(helper)
    builder = next(
        (n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "build_parser"), None
    )
    if builder is None:
        return ["build_parser: missing"]
    body = ast.get_source_segment(helper, builder) or ""
    expected_options = {
        "route": ["--decision", "--out"],
        "route-fields": ["--route"],
        "contract-selected": ["--topology", "--pairs", "--run-id", "--out"],
    }
    variables = {
        "route": "route", "route-fields": "route_fields_parser",
        "contract-selected": "contract_selected",
    }
    for command, options in expected_options.items():
        block = body.split(f'sub.add_parser("{command}"', 1)
        if len(block) != 2:
            fails.append(f"the {command} subcommand is missing")
            continue
        variable = variables[command]
        observed = re.findall(rf'{variable}\.add_argument\("([^"]+)"', block[1])
        if observed != options:
            fails.append(f"the {command} CLI takes {observed}")
        if any(not option.startswith("--") for option in observed):
            fails.append(f"the {command} CLI accepts a positional argument")
    for forbidden in ("--profile", "--model", "--cpu-model", "--status", "--reason",
                      "--cardinality", "--roles", "--orientation"):
        if forbidden in body:
            fails.append(f"the routing CLI exposes {forbidden}")
    if 'contract_selected.add_argument("--pairs", required=True, nargs=2)' not in body:
        fails.append("contract-selected does not take exactly two observed pairs")
    # `contract-selected` renders the fixed orientation 0 and nothing else.
    renderer = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                    and n.name == "selected_contract")
    rendered = ast.get_source_segment(helper, renderer) or ""
    if "SELECTED_ORIENTATION" not in rendered:
        fails.append("contract-selected does not render the fixed orientation")
    parameters = {a.arg for a in renderer.args.args} | {a.arg for a in renderer.args.kwonlyargs}
    if parameters != {"topology", "pairs", "run_id"}:
        fails.append(f"selected_contract takes {sorted(parameters)}")
    for statement in ast.walk(renderer):
        if isinstance(statement, ast.Name) and statement.id == "orientation":
            fails.append("contract-selected reads an orientation from its caller")

    # The launcher: coverage before route, one closed read, no reason text and
    # no topology literal of its own.
    # The ORDINARY target only. B1-LATENCY-BASIS-1 appended a second selected
    # route after it (FP-B1LB-6), which runs the same planner calls; folding
    # the two together would make "exactly one route-fields read" and "the
    # carrier is read only by route" say something about both at once, which
    # is not what GC-3 pinned. The isolated target has its own pins. The region
    # therefore ends at the NEXT top-level target header, not at the comment
    # that happens to introduce it.
    b1_region = _b1_target_region(launcher, "b1")
    if not b1_region:
        return fails + ["the ordinary b1 target is missing"]
    for clause in (
        'b1_run_driver driver-coverage.sh "${cpus[0]}"',
        'python3 "$B1_PROBE_PLANNER" route \\',
        '--decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json" \\',
        'python3 "$B1_PROBE_PLANNER" route-fields --route "$B1_ROUTE_RECORD"',
        'python3 "$B1_PROBE_PLANNER" contract-selected \\',
        '--topology "$route_topology" \\',
        '--pairs "${sibling_pairs[0]}" "${sibling_pairs[1]}" \\',
        'b1_run_driver driver-live.sh "$driver_cpus"',
    ):
        if clause not in b1_region:
            fails.append(f"the ordinary b1 route lost {clause!r}")
    coverage_at = b1_region.find('b1_run_driver driver-coverage.sh')
    route_at = b1_region.find('"$B1_PROBE_PLANNER" route ')
    live_at = b1_region.find('b1_run_driver driver-live.sh')
    if not -1 < coverage_at < route_at < live_at:
        fails.append(
            f"the ordinary b1 phases are out of order ({coverage_at}/{route_at}/{live_at})"
        )
    if b1_region.count("route-fields") != 1:
        fails.append("the launcher reads route-fields more than once")
    for reason in (GC3_DECISION_MISSING_REASON, GC3_DECISION_INVALID_REASON,
                   GC3_UNRATIFIED_REASON_PREFIX, GC3_MODEL_UNAVAILABLE_REASON):
        if reason not in helper:
            fails.append(f"the planner no longer declares {reason!r}")
        if reason in launcher:
            fails.append(f"the launcher spells the route reason {reason!r}")
    if "b1_topology_decision.json" in b1_region.replace(
        '--decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json" \\', "", 1
    ):
        fails.append("the launcher reads the carrier outside route")

    # The renamed witness: exactly one, under the new name, and it is the one
    # that proves the mounted-carrier join.
    harness_tree = ast.parse(harness)
    witnesses = [
        n for n in ast.walk(harness_tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == GC3_WITNESS_TEST
    ]
    if len(witnesses) != 1:
        fails.append(f"{GC3_WITNESS_TEST}: {len(witnesses)} definitions")
        return fails
    if GC3_RETIRED_WITNESS_TEST + "(" in harness:
        fails.append(f"the retired {GC3_RETIRED_WITNESS_TEST} survives")
    witness_src = ast.get_source_segment(harness, witnesses[0]) or ""
    # EXACT assertion text, not a loose substring: every one of these names
    # appears elsewhere in the same function, so a substring pin would survive
    # the very weakening it is named for.
    for clause in (
        'assert B1_DECISION_CARRIER.is_file(), (',
        "    probe.validate_decision(carrier)",
        '    measured_model = probe.validate_cpu_model(_host_fingerprint()["cpu_model"])',
        '    entry = carrier["models"].get(measured_model)',
        '    assert entry["status"] == probe.DECISION_SELECTED, '
        '(measured_model, entry["status"])',
        '    assert entry["selected"] == topology, '
        '(measured_model, entry["selected"], topology)',
        '    assert entry["placementSchema"] == B1_TOPOLOGY_PLACEMENT_SCHEMA',
        '    assert CI_SCALE_AFFINITY_CARDINALITIES_BY_CPU_MODEL[measured_model] == cardinality',
        '    assert _parse_b1_env_field(line, "placement_schema") == '
        "str(B1_TOPOLOGY_PLACEMENT_SCHEMA)",
        '    topology = _parse_b1_env_field(line, "reference_topology")',
        "    assert topology in probe.TOPOLOGY_IDS, topology",
        "    assert topology == declaration.topology",
        '        rendered = _parse_b1_env_field(line, f"{role}_thread_siblings_pct")',
        "        assert rendered != DIAGNOSTIC_UNAVAILABLE, role",
        "    assert declaration.carries_topology",
    ):
        if clause not in witness_src:
            fails.append(f"{GC3_WITNESS_TEST} lost the exact clause {clause!r}")
    if "for role in B1_ROLES:" not in witness_src:
        fails.append(f"{GC3_WITNESS_TEST} does not gate every role sibling map")
    if f'B1_DECISION_CARRIER = Path("{GC3_MOUNTED_CARRIER}")' not in harness:
        fails.append("the mounted carrier path moved")
    # The host route record never reaches the run directory, and the closed
    # placement contract never gains a cpuModel key.
    if "B1_ROUTE_RECORD" in harness:
        fails.append("the harness reads the host route record")
    if "cpuModel" in ast.get_source_segment(
        helper, next(n for n in ast.parse(helper).body
                     if isinstance(n, ast.FunctionDef) and n.name == "selected_contract")
    ):
        fails.append("the closed placement contract carries a cpuModel key")
    return fails


def _gc3_scope_failures() -> list[str]:
    """FP-GC3-6: what this slice may not have moved, checked independently."""
    fails: list[str] = []
    launcher = GC3_LAUNCHER.read_text(encoding="utf-8")
    harness = REF_TEST.read_text(encoding="utf-8")
    probe_live = PROBE_TEST.read_text(encoding="utf-8")
    probe_helper = PROBE_HELPER.read_text(encoding="utf-8")
    workflow = yaml.safe_load(GC3_CI_YML.read_text(encoding="utf-8"))

    # (1) The three marker selections, exactly.
    for literal in (GC3_COVERAGE_SELECTION, GC3_LIVE_SELECTION, GC3_PROBE_SELECTION,
                    GC3_PRODUCT_SELECTION):
        if literal not in launcher:
            fails.append(f"marker selection missing: {literal}")
    if launcher.count(GC3_PROBE_SELECTION) != 1:
        fails.append("the probe selection appears more than once")

    # (2) FP-IG-26: exactly one collector of the frozen producer, and the probe
    # job collects only the live-only module.
    if GC3_PRODUCER_REL not in GC3_DELIVERY_CI.read_text(encoding="utf-8"):
        fails.append("test_delivery_ci.py no longer names the frozen producer")
    b1_region = launcher.split("\nb1() {", 1)[1].split("\nb1_product() {", 1)[0]
    if GC3_PRODUCER_REL not in b1_region:
        fails.append("the b1 target no longer collects the producer lexically")
    probe_region = launcher.split("\nb1_topology_probe() {", 1)
    if len(probe_region) != 2:
        fails.append("the b1_topology_probe target is missing")
    else:
        region = probe_region[1].split("\n}\n", 1)[0]
        if GC3_PRODUCER_REL in region:
            fails.append("the probe target collects the frozen producer")
        if GC3_PROBE_LIVE_REL not in region:
            fails.append("the probe target does not collect the live-only module")

    # (3) The probe job: conditional, independent, three steps, honest upload.
    jobs = workflow.get("jobs") or {}
    job = jobs.get(GC3_PROBE_JOB)
    if not isinstance(job, dict):
        fails.append("the probe job is missing from ci.yml")
    else:
        if "needs" in job:
            fails.append("the probe job has a needs edge")
        if job.get("timeout-minutes") != 75:
            fails.append(f"probe timeout {job.get('timeout-minutes')}")
        steps = job.get("steps") or []
        if len(steps) != 3:
            fails.append(f"probe job has {len(steps)} steps")
        else:
            if (steps[1].get("run") or "").strip() != (
                "bash scripts/integration-test.sh b1_topology_probe"
            ):
                fails.append("probe wrapper step drift")
            if steps[2].get("uses") != "actions/upload-artifact@v4":
                fails.append("probe upload step drift")
            if (steps[2].get("if") or "").strip() != "always()":
                fails.append("probe upload is not always()")
        for name, other in jobs.items():
            needs = other.get("needs")
            listed = [needs] if isinstance(needs, str) else list(needs or [])
            if GC3_PROBE_JOB in listed:
                fails.append(f"{name} waits on the probe job")

    # (4) The unchanged CI-scale bar, still failure-producing, still direct.
    ci_scale = _gc2_function(ast.parse(harness), CI_SCALE_REF_TEST)
    observed = {
        ast.unparse(node.test) for node in ast.walk(ci_scale) if isinstance(node, ast.Assert)
    }
    missing = GC2_CI_SCALE_REQUIRED_ASSERTIONS - observed
    if missing:
        fails.append(f"the CI-scale bar lost {sorted(missing)}")
    profile_assigns = _module_assigns(REF_PATH)
    for name, expected in GC2_FIXED_CI_SCALE_LITERALS.items():
        if _eval_simple_constant(profile_assigns[name], profile_assigns) != expected:
            fails.append(f"{name} moved")
    # The discovery profile copies the workload; it does not restate it.
    harness_assigns = _source_assigns(harness)
    probe_profile = harness_assigns.get("CI_SCALE_PROBE_PROFILE")
    if probe_profile is None:
        fails.append("CI_SCALE_PROBE_PROFILE is missing")
    else:
        rendered = ast.unparse(probe_profile)
        for field in ("rate", "seconds", "total_requests", "prologue_requests",
                      "max_in_flight", "p99_ms", "sustained_floor"):
            if f"{field}=CI_SCALE_PROFILE.{field}" not in rendered:
                fails.append(f"the probe profile does not copy {field} from CI_SCALE_PROFILE")

    # (5) Excluded knobs. This slice touches no product source at all.
    main_src = GC2_MAIN_PATH.read_text(encoding="utf-8")
    main_assigns = _source_assigns(main_src)
    if ast.literal_eval(
        main_assigns["DEFAULT_MAX_CONNECTIONS_PER_WORKER"]
    ) != GC2_MAX_CONNECTIONS_PER_WORKER:
        fails.append("limit_concurrency moved")
    if ast.literal_eval(main_assigns["BACKLOG"]) != GC2_BACKLOG:
        fails.append("BACKLOG moved")
    if f'"DBAGENT_GATEWAY_WORKERS", "{GC2_GATEWAY_WORKERS}"' not in main_src:
        fails.append("the worker count moved")
    if "limit_concurrency=max_connections" not in main_src:
        fails.append("the concurrency limiter moved")
    session_src = GC2_SESSION_PATH.read_text(encoding="utf-8")
    if "create_engine(dsn, future=True, **kwargs)" not in session_src:
        fails.append("make_engine gained or lost a pool default")
    for token in GC2_DURABILITY_TOKENS:
        for name, text in (("main", main_src), ("session", session_src),
                           ("ingest", GC2_INGEST_PATH.read_text(encoding="utf-8"))):
            if token in text:
                fails.append(f"{name} touches durability token {token}")
    if "MAX_IN_FLIGHT = BURST_RATE" not in REF_PATH.read_text(encoding="utf-8"):
        fails.append("MAX_IN_FLIGHT moved")
    if ast.literal_eval(harness_assigns["PRODUCT_AFFINITY_CARDINALITY"]) != (
        GC1_AFFINITY_CARDINALITIES["product-exclusive"]
    ):
        fails.append("the product-local 4/3/1 placement moved")
    if ast.literal_eval(harness_assigns["PRODUCT_PLACEMENT_SCHEMA"]) != GC3_SCHEMA2:
        fails.append("the product schema-2 contract moved")
    if 'b1_product() {' not in launcher or '"minimumHostLogicalCpus": 8,' not in launcher:
        fails.append("the product-local route moved")
    if 'if [ "${#cpus[@]}" -lt 8 ]; then' not in launcher:
        fails.append("the product-local host floor moved")
    product_region = launcher.split("\nb1_product() {", 1)[1].split("\nB1_CPU", 1)[0]
    if "b1_complete_sibling_pairs" in product_region:
        fails.append("the SMT-pair prerequisite leaked into b1_product")

    # (6) The ordinary b1 prerequisite: a named failure on a gating route,
    # never a skip and never four unrelated CPUs. GC-3 retired the 2/1/1
    # literals entirely -- their absence is asserted, not assumed.
    for clause in (
        'mapfile -t sibling_pairs < <(b1_complete_sibling_pairs "${cpus[@]}")',
        'if [ "${#sibling_pairs[@]}" -lt 2 ]; then',
        'if [ "${#cpus[@]}" -lt 4 ]; then',
    ):
        if clause not in b1_region and clause not in launcher:
            fails.append(f"the ordinary b1 route lost {clause!r}")
    for retired in (
        'gateway_cpus="$(b1_canonical_cpu_list "${cpus[0]}" "${cpus[1]}")"',
        'postgres_cpus="$(b1_canonical_cpu_list "${cpus[2]}")"',
        'driver_cpus="$(b1_canonical_cpu_list "${cpus[3]}")"',
    ):
        if retired in b1_region:
            fails.append(f"the retired ordinary 2/1/1 literal survives: {retired!r}")
    for escape_hatch in ("pytest.mark.skip", "--deselect", "|| true"):
        if escape_hatch in b1_region:
            fails.append(f"the ordinary b1 route carries {escape_hatch}")

    # (7) No escape hatch, no bandwidth control, in any carrier this slice adds.
    for label, text in (("launcher", launcher), ("probe live", probe_live),
                        ("probe helper", probe_helper)):
        for escape in GC3_WEAKENINGS:
            if escape in text:
                fails.append(f"{label} carries {escape}")
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            for control in GC3_BANDWIDTH_CONTROLS:
                if control in stripped:
                    fails.append(f"{label} reintroduces {control}")

    # (8) No profile, candidate, affinity or bar value from the environment or
    # from a caller argument. The only environment reads in the helper are the
    # GitHub run identity of the record.
    if "getenv" in harness or "os.environ.get" in harness:
        fails.append("the harness reads the environment")
    # The only environment reads in the helper are the GitHub run identity of
    # the record and the step-summary sink the route row is appended to. None
    # of them is a profile, candidate, affinity, model or bar value.
    env_reads = set(re.findall(r'os\.environ\.get\("([A-Z_]+)"', probe_helper))
    if not env_reads <= {"GITHUB_SHA", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT",
                         "GITHUB_STEP_SUMMARY"}:
        fails.append(f"the probe helper reads {sorted(env_reads)}")
    if "os.environ.get" in probe_live or "getenv" in probe_live:
        fails.append("the probe live module reads the environment")

    # (9) The sizing ledger carries none of this slice's RCA values. FP-B1LB-7:
    # the basis VALUE itself is B1-LATENCY-BASIS-1's to move, so it is no
    # longer pinned here; what GC-3 keeps is that no topology-probe arm and no
    # RCA diagnostic may become a sizing observation.
    for parts in GC3_SIZING_CARRIERS:
        carrier = REPO_ROOT.joinpath(*parts)
        if not carrier.is_file():
            fails.append(f"{parts[-1]} is missing")
            continue
        text = carrier.read_text(encoding="utf-8")
        for value in (GC3_RCA_POSTGRES_MS, GC3_RCA_GATEWAY_MS, GC3_RCA_RUN_ID):
            if value in text:
                fails.append(f"{parts[-1]} carries the diagnostic {value}")
    return fails


def test_gc3_reference_topology_decision_is_evidence_backed(tmp_path):
    """FP-GC3-3: every tracked model entry is the selector's own result, or nothing.

    RED BY DESIGN at the probe implementation head, with the named reason
    ``gc3_decision_missing``. A model earns an entry only from two complete
    discovery artifacts OF THAT EXACT MODEL, from distinct GitHub runs at one
    source SHA. This never skips, never defaults and never writes a
    placeholder: a selected topology that nothing measured is precisely the
    failure this slice exists to prevent, and one model's evidence is never
    allowed to decide another model's outcome.
    """
    assert _gc3_selector_failures() == []

    assert GC3_DECISION.is_file(), (
        f"{GC3_DECISION_MISSING_REASON}: "
        f"tests/benchmark/b1_topology_decision.json does not exist. Dispatch "
        f"ci.yml with b1_topology_probe=true at this head until some exact CPU "
        f"model has two complete artifacts from distinct runs, then generate "
        f"that model's entry with `b1_topology_probe.py decide --out ... "
        f"--pair <first> <second>`. Absence is never a skip, a default or a "
        f"placeholder."
    )

    raw = GC3_DECISION.read_text(encoding="utf-8")
    decision = json.loads(raw)
    # The carrier is canonical, so the recomputation below reads the same bytes
    # a reviewer does.
    assert gc3.canonical_json(decision) == raw
    assert decision["schema"] == gc3.DECISION_SCHEMA == GC3_DECISION_SCHEMA == 3
    assert decision["topologySetVersion"] == gc3.TOPOLOGY_SET_VERSION
    assert sorted(decision) == ["models", "schema", "topologySetVersion"]
    models = decision["models"]
    assert isinstance(models, dict) and models
    # Lexical key order, so two reviewers reading the file see one order.
    assert list(models) == sorted(models)

    # The whole carrier, validated and recomputed from its own embedded
    # evidence -- never trusted, and never read one entry at a time.
    gc3.validate_decision(decision)
    recomputed = gc3.recompute_decision(decision)
    assert sorted(recomputed) == sorted(models)

    for model, entry in models.items():
        assert gc3.validate_cpu_model(model) == model
        assert entry["status"] in (gc3.DECISION_SELECTED, gc3.DECISION_UNHOSTABLE)
        assert entry == recomputed[model], model
        embedded = entry["artifacts"]
        assert len(embedded) == 2, model
        runs = {wrapper["artifact"]["githubRunId"] for wrapper in embedded}
        assert len(runs) == 2, f"{model}: both artifacts come from run {sorted(runs)}"
        for wrapper in embedded:
            assert sorted(wrapper) == ["artifact", "sha256", "sourceUrl"]
            assert wrapper["sourceUrl"].startswith("https://github.com/"), wrapper["sourceUrl"]
            artifact = wrapper["artifact"]
            assert str(artifact["githubRunId"]) in wrapper["sourceUrl"]
            assert wrapper["sha256"] == hashlib.sha256(
                gc3.canonical_json(artifact).encode("utf-8")
            ).hexdigest(), model
            assert artifact["status"] == "complete"
            # The model key IS the artifacts' own model. No cross-model pair.
            assert artifact["cpuModel"] == model
            assert artifact["logicalCpuCount"] == GC3_REFERENCE_LOGICAL_CPUS
            assert artifact["githubJob"] == GC3_PROBE_JOB
            assert len(artifact["arms"]) == GC3_ARMS_PER_ARTIFACT
            assert artifact["headSha"] == entry["evidenceHeadSha"]
        if entry["status"] == gc3.DECISION_SELECTED:
            assert entry["selected"] in GC3_TOPOLOGY_IDS, model
            assert entry["selected"] in entry["ratifiable"]
            assert entry["cardinality"] == gc3.topology_cardinality(entry["selected"])
            assert entry["placementSchema"] == GC1_SELECTED_PLACEMENT_SCHEMA == 3
            assert set(entry["score"]) == {"maxP99Ms", "maxInFlight", "minServedRate"}
        else:
            for null_field in ("selected", "cardinality", "placementSchema", "score"):
                assert entry[null_field] is None, (model, null_field)
            assert entry["ratifiable"] == []

        # --- FP-GC3-7: the append-only history, and its ancestry ----------
        # Every replaced decision is a complete decision in its own right: two
        # embedded same-head artifacts of this exact model, recomputable on
        # its own, with no nested history. The edges form one chain that ends
        # at the current head, and every edge is a STRICT Git descent proved
        # offline from this checkout's own object database.
        history = entry[GC3_HISTORY_KEY]
        assert isinstance(history, list), model
        chain = []
        for index, record in enumerate(history):
            assert sorted(record) == GC3_HISTORY_RECORD_KEYS, (model, index)
            superseded = record["decision"]
            assert GC3_HISTORY_KEY not in superseded, (model, index)
            assert superseded["status"] in (
                gc3.DECISION_SELECTED, gc3.DECISION_UNHOSTABLE
            ), (model, index)
            assert superseded == recomputed[model][GC3_HISTORY_KEY][index]["decision"], (
                model, index
            )
            embedded_heads = {
                wrapper["artifact"]["headSha"] for wrapper in superseded["artifacts"]
            }
            assert embedded_heads == {superseded["evidenceHeadSha"]}, (model, index)
            for wrapper in superseded["artifacts"]:
                assert wrapper["sha256"] == hashlib.sha256(
                    gc3.canonical_json(wrapper["artifact"]).encode("utf-8")
                ).hexdigest(), (model, index)
                assert wrapper["artifact"]["cpuModel"] == model, (model, index)
            successor = (
                history[index + 1]["decision"]["evidenceHeadSha"]
                if index + 1 < len(history) else entry["evidenceHeadSha"]
            )
            assert record["supersededByHeadSha"] == successor, (model, index)
            chain.append(superseded["evidenceHeadSha"])
        chain.append(entry["evidenceHeadSha"])
        assert len(set(chain)) == len(chain), (model, chain)
        # Every head in the chain is a commit object in THIS checkout -- which
        # is why the functional job checks out full history -- and every edge
        # is re-proved here, not taken from a recorded parent-head string.
        for head in chain:
            _gc3_require_commit_object(head)
        for older, newer in zip(chain, chain[1:]):
            gc3.verify_decision_ancestry(older, newer)

    # The same proof over the whole carrier, through the module's own walker.
    assert gc3.verify_carrier_ancestry(decision) == sum(
        len(entry[GC3_HISTORY_KEY]) for entry in models.values()
    )
    # ...and the direction of that proof is not decorative: this checkout's own
    # parent commit is an ancestor of its head, the reverse is refused, and an
    # equal head is refused. A shallow checkout cannot see HEAD~1 at all, which
    # is exactly why `fetch-depth: 0` is pinned on the functional job.
    head = _gc3_git_output("rev-parse", "HEAD")
    parent = _gc3_git_output("rev-parse", "HEAD~1")
    gc3.verify_decision_ancestry(parent, head)
    for older, newer in ((head, parent), (head, head), (parent, parent)):
        with pytest.raises(gc3.TopologyProbeError):
            gc3.verify_decision_ancestry(older, newer)

    # A hand-written entry is not a decision: mutating any derived field makes
    # the carrier disagree with a fresh selector run over its own evidence.
    for model, entry in models.items():
        if entry["status"] != gc3.DECISION_SELECTED:
            continue
        forged = json.loads(json.dumps(decision))
        others = [t for t in GC3_TOPOLOGY_IDS if t != entry["selected"]]
        forged["models"][model]["selected"] = others[0]
        with pytest.raises(gc3.TopologyProbeError):
            gc3.validate_decision(forged)
        break

    # A hand-written HISTORY record is not provenance: a fabricated record
    # whose decision duplicates the current one produces a self-edge, and an
    # unknown key in a record is not a closed record at all. Both are refused
    # without a Git call.
    model, entry = next(iter(models.items()))
    fabricated = {key: value for key, value in entry.items() if key != GC3_HISTORY_KEY}
    self_edge = json.loads(json.dumps(decision))
    self_edge["models"][model][GC3_HISTORY_KEY] = [
        {"supersededByHeadSha": entry["evidenceHeadSha"], "decision": fabricated}
    ]
    with pytest.raises(gc3.TopologyProbeError):
        gc3.validate_decision(self_edge)
    widened = json.loads(json.dumps(decision))
    widened["models"][model][GC3_HISTORY_KEY] = [
        {
            "supersededByHeadSha": entry["evidenceHeadSha"],
            "decision": fabricated,
            "note": "hand written",
        }
    ]
    with pytest.raises(gc3.TopologyProbeError):
        gc3.validate_decision(widened)

    # FP-GC3-7: re-deriving a tracked entry from its own embedded pair, with
    # the tracked carrier as the required base and no --supersede, is
    # byte-idempotent -- and it is the precise two-scratch form, so the base is
    # read and never rewritten.
    pair = []
    for wrapper in entry["artifacts"]:
        artifact_path = tmp_path / f"artifact-{wrapper['artifact']['githubRunId']}.json"
        gc3.write_artifact(artifact_path, wrapper["artifact"])
        pair.append(str(artifact_path))
    scratch = tmp_path / "scratch.json"
    retry = tmp_path / "retry.json"
    assert gc3.main([
        "decide", "--out", str(scratch), "--base", str(GC3_DECISION), "--pair", *pair
    ]) == 0
    assert scratch.read_text(encoding="utf-8") == raw
    assert gc3.main([
        "decide", "--out", str(retry), "--base", str(scratch), "--pair", *pair
    ]) == 0
    assert retry.read_text(encoding="utf-8") == raw
    # An aliased base/output, and a supersession naming a head that is not this
    # model's current one, are both refused with nothing written.
    before = scratch.read_text(encoding="utf-8")
    assert gc3.main([
        "decide", "--out", str(scratch), "--base", str(scratch), "--pair", *pair
    ]) == 1
    assert scratch.read_text(encoding="utf-8") == before
    never = tmp_path / "never-written.json"
    assert gc3.main([
        "decide", "--out", str(never), "--base", str(GC3_DECISION), "--pair", *pair,
        "--supersede", head,
    ]) == 1
    assert not never.exists()


def test_gc3_reference_topology_scope_and_decision_are_pinned():
    """FP-GC3-3/4/6: the candidate space, the excluded knobs and the decision.

    Every clause the probe head can decide is checked BEFORE the carrier is
    required, so this test enforces the scope boundary even while it is red.
    The carrier assertion is the last of the head's checks and the first of the
    decision's: below it are the clauses that only a measured decision can
    settle -- the per-model declaration maps, the manifest note's per-model
    table and the mounted-carrier live witness's own model key.
    """
    assert _gc3_candidate_space_failures() == []
    assert _gc3_topology_surface_failures(REF_TEST.read_text(encoding="utf-8")) == []
    assert _live_marker_failures(
        REF_TEST.read_text(encoding="utf-8"), PROBE_TEST.read_text(encoding="utf-8")
    ) == []
    probe_src = PROBE_TEST.read_text(encoding="utf-8")
    assert _gc3_probe_partition_failures(probe_src) == []
    assert _gc3_scope_failures() == []
    assert _gc3_route_surface_failures() == []
    assert _gc1_cardinality_map_failures(
        _source_assigns(REF_TEST.read_text(encoding="utf-8"))
    ) == []

    # Negative control: truth-gating a recorded performance status is red.
    gated = probe_src.replace(
        "        assert token == live[field], (field, token, live[field])",
        "        assert token == probe.VERDICT_MET\n"
        "        assert token == live[field], (field, token, live[field])", 1)
    assert "VERDICT_MET" in gated
    assert gated != probe_src
    assert any("truth-gates" in f for f in _gc3_probe_partition_failures(gated))
    ungated = probe_src.replace(
        "        assert verdicts[field] == probe.VERDICT_MET, (", "        assert True, (", 1)
    assert ungated != probe_src
    assert _gc3_probe_partition_failures(ungated) != []
    unrecorded = probe_src.replace("        assert token == live[field], (field, token, live[field])",
                                   "        pass", 1)
    assert unrecorded != probe_src
    assert any("record-consistency" in f for f in _gc3_probe_partition_failures(unrecorded))
    unwritten = probe_src.replace("    harness.write_probe_arm_record(record)", "", 1)
    assert unwritten != probe_src
    assert any("gating step" in f for f in _gc3_probe_partition_failures(unwritten))

    # Both fail-closed carriers name the reason, and neither reaches for a skip.
    own_src = Path(__file__).read_text(encoding="utf-8")
    assert GC3_DECISION_MISSING_REASON == gc3.DECISION_MISSING_REASON == "gc3_decision_missing"
    assert GC3_DECISION_INVALID_REASON == gc3.DECISION_INVALID_REASON == "gc3_decision_invalid"
    for name in ("test_gc3_reference_topology_decision_is_evidence_backed",
                 "test_gc3_reference_topology_scope_and_decision_are_pinned"):
        node = next(
            n for n in ast.parse(own_src).body
            if isinstance(n, ast.FunctionDef) and n.name == name
        )
        # The carrier is REQUIRED, and its absence is reported under the named
        # reason. Checked structurally, not by substring: this very function
        # has to be able to name the weakenings it forbids.
        asserts = [n for n in ast.walk(node) if isinstance(n, ast.Assert)]
        required = [
            n for n in asserts if ast.unparse(n.test) == "GC3_DECISION.is_file()"
        ]
        assert len(required) == 1, f"{name}: the carrier is not required exactly once"
        assert required[0].msg is not None, f"{name}: the carrier failure is unnamed"
        assert "GC3_DECISION_MISSING_REASON" in ast.unparse(required[0].msg), name
        assert not node.decorator_list, f"{name}: carries a decorator"
        calls = {
            ast.unparse(n.func) for n in ast.walk(node) if isinstance(n, ast.Call)
        }
        for weakening in ("pytest.skip", "pytest.xfail", "pytest.importorskip"):
            assert weakening not in calls, f"{name} must not call {weakening}"
        # ...and it is a statement of the function body, never nested inside a
        # branch that could route around it.
        assert any(stmt is required[0] for stmt in node.body), (
            f"{name}: the carrier requirement is conditional"
        )

    assert GC3_DECISION.is_file(), (
        f"{GC3_DECISION_MISSING_REASON}: "
        f"tests/benchmark/b1_topology_decision.json does not exist, so no model "
        f"has a ratified topology and none may be applied to the ordinary B1 "
        f"route. Every scope clause above holds at this probe head; what "
        f"remains is the measurement."
    )

    decision = json.loads(GC3_DECISION.read_text(encoding="utf-8"))
    gc3.validate_decision(decision)
    harness = REF_TEST.read_text(encoding="utf-8")
    harness_assigns = _source_assigns(harness)
    thresholds = yaml.safe_load(
        (REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml").read_text(encoding="utf-8")
    )
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    notes = b1_entry["notes"]
    # The bar is never relabelled by any model's outcome.
    assert b1_entry["status"] == "covered"
    assert "the first four CPUs available to the launcher, split 2/1/1" not in notes
    assert "first two complete SMT sibling pairs available to the launcher" in notes

    selected = {
        model: entry for model, entry in decision["models"].items()
        if entry["status"] == gc3.DECISION_SELECTED
    }
    unhostable = {
        model: entry for model, entry in decision["models"].items()
        if entry["status"] == gc3.DECISION_UNHOSTABLE
    }
    # Declaration surface == carrier, model by model, with no scalar default.
    assert ast.literal_eval(
        harness_assigns["CI_SCALE_AFFINITY_CARDINALITIES_BY_CPU_MODEL"]
    ) == {model: entry["cardinality"] for model, entry in selected.items()}
    assert ast.literal_eval(
        harness_assigns["CI_SCALE_PLACEMENT_SCHEMAS_BY_CPU_MODEL"]
    ) == {model: GC1_SELECTED_PLACEMENT_SCHEMA for model in selected}
    for model, entry in selected.items():
        assert model in notes, model
        assert entry["selected"] in notes, model
        assert str(entry["cardinality"]["gateway"]) in notes
        for url in (w["sourceUrl"] for w in entry["artifacts"]):
            assert url in notes, url
    for model in unhostable:
        assert model in notes, model
        assert f"topology_unratified_sku:{model}" in notes or (
            "topology_unratified_sku:<model>" in notes
        ), model
    # FP-GC3-7: the per-model row names the exact CURRENT evidence head and
    # every superseded head oldest-to-newest, always as the full
    # 40-lowercase-hex value. A seven-character prefix is not provenance, and a
    # superseded head is explicitly historical rather than an active route.
    assert "current evidence head" in notes
    assert GC3_HISTORY_KEY in notes
    for model, entry in decision["models"].items():
        row = _gc3_notes_row(notes, model)
        assert entry["evidenceHeadSha"] in row, model
        heads = [
            record["decision"]["evidenceHeadSha"] for record in entry[GC3_HISTORY_KEY]
        ]
        for head in heads:
            assert head in row, (model, head)
        offsets = [row.index(head) for head in heads]
        assert offsets == sorted(offsets), (model, heads)
        if not heads:
            assert "superseded: none" in row, model
    # ...and the carrier's own schema is published, so a reader of the manifest
    # cannot take a schema-2 entry for a current one.
    assert f"schema {gc3.DECISION_SCHEMA}" in notes
    # The launcher never names a topology, whatever the carrier decided: the
    # ratified class reaches placement through route -> route-fields ->
    # contract-selected and nowhere else.
    launcher = GC3_LAUNCHER.read_text(encoding="utf-8")
    for topology in GC3_TOPOLOGY_IDS:
        assert f'"topology": "{topology}"' not in launcher, topology
        assert topology not in launcher, topology


# ---------------------------------------------------------------------------
# GC-4 — the scoped Psycopg 3 gateway engine, the fixed bars it may not move,
# and the head-scoped GC-3 handoff.
#
# Every literal below is declared here, independently of the module it pins,
# for the same reason the GC-2 and GC-3 blocks above declare theirs: the pin
# says what this slice did and did not change, and it infers no performance
# from source shape.
# ---------------------------------------------------------------------------

GC4_MAIN_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "main.py"
GC4_INGEST_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "ingest.py"
GC4_SESSION_PATH = (
    REPO_ROOT / "libs" / "py" / "rca_common" / "rca_common" / "db" / "session.py"
)
GC4_REPO_PATH = (
    REPO_ROOT / "libs" / "py" / "rca_common" / "rca_common" / "investigation_repo.py"
)
GC4_GATEWAY_PYPROJECT = REPO_ROOT / "services" / "gateway" / "pyproject.toml"
GC4_COMMON_PYPROJECT = REPO_ROOT / "libs" / "py" / "rca_common" / "pyproject.toml"
GC4_MIGRATIONS_DIR = REPO_ROOT / "libs" / "py" / "rca_common" / "migrations"
GC4_VALUES_PATH = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
GC4_DEPLOY_DIR = REPO_ROOT / "deploy"
GC4_THRESHOLDS = REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml"
GC4_CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GC4_LAUNCHER = REPO_ROOT / "scripts" / "integration-test.sh"

GC4_ENGINE_FACTORY = "make_gateway_engine"
GC4_LISTENER = "_pin_gateway_prepare_threshold"
GC4_THRESHOLD_CONSTANT = "GATEWAY_PREPARE_THRESHOLD"
GC4_PREPARE_THRESHOLD = 5
GC4_DIALECT = "postgresql+psycopg"
GC4_GATEWAY_DEPENDENCY = "psycopg[binary]>=3.2,<4"
GC4_COMMON_DEPENDENCY = "psycopg2-binary>=2.9,<3"
# Production modules that build a shared engine and are NOT the ingest gateway.
# Each keeps its DSN-selected Psycopg 2 behaviour: none of them may name the
# gateway's constructor, dialect, driver or threshold.
GC4_OTHER_ENGINE_MODULES = (
    ("services", "worker", "worker", "worker_main.py"),
    ("services", "worker", "scripts", "seed_playbooks.py"),
    ("services", "dashboard-api", "dashboard_api", "main.py"),
    ("services", "dashboard-api", "dashboard_api", "bootstrap_admin.py"),
    ("libs", "py", "rca_common", "rca_common", "db", "session.py"),
    ("libs", "py", "rca_common", "rca_common", "db", "__init__.py"),
)
# Every way of widening the engine, the pool or the connection that the
# gateway constructor is forbidden to use. `connect_args` is named explicitly
# so the one sanctioned new per-connection setting -- the connect-event
# listener -- is not confused with a smuggled engine argument.
GC4_FORBIDDEN_ENGINE_KEYWORDS = (
    "connect_args",
    "poolclass",
    "pool_size",
    "max_overflow",
    "pool_timeout",
    "pool_recycle",
    "pool_pre_ping",
    "pool_use_lifo",
    "isolation_level",
    "execution_options",
    "creator",
    "NullPool",
    "StaticPool",
    "QueuePool",
)
GC4_FORBIDDEN_SQL_TOKENS = (
    "PREPARE ",
    "EXECUTE ",
    "DEALLOCATE",
    "CREATE FUNCTION",
    "CREATE OR REPLACE FUNCTION",
    "plan_cache_mode",
    "force_generic_plan",
)
# The GC-2 statement, byte-unchanged. The digest is over the Python constant's
# own value, so an edit of a single character inside the SQL fails by name --
# and the bind inventory below fixes the typed binds the Psycopg dialect
# renders its casts from.
GC4_MERGE_SQL_SHA256 = (
    "2cc1897aab8247c562f5fdd5996b9e2be7fa54cd7d8f23443c4582e96cbcd3bb"
)
GC4_MERGE_BIND_INVENTORY = (
    ("platform_key", "Text"),
    ("fingerprint", "Text"),
    ("source", "Text"),
    ("severity", "Text"),
    ("event_id", "UUID"),
    ("event_id_text", "Text"),
    ("normalized", "JSONB"),
    ("non_terminal_statuses", "ARRAY"),
    ("statement_at", "TIMESTAMP"),
    ("default_correlation_window_seconds", "Integer"),
)
# Workload, capacity, durability and index values GC-4 is forbidden to touch.
GC4_FIXED_CI_SCALE_LITERALS = {
    "CI_SCALE_BURST_RATE": 500,
    "CI_SCALE_BURST_SECONDS": 30,
    "CI_SCALE_TOTAL_REQUESTS": 15000,
    "CI_SCALE_P99_MS": 150.0,
    "CI_SCALE_SUSTAINED_FLOOR": 450,
    "CI_SCALE_MAX_IN_FLIGHT": 500,
}
GC4_FIXED_PRODUCT_LITERALS = {
    "PRODUCT_P99_MS": 150.0,
    "PRODUCT_SUSTAINED_FLOOR": 200,
    "PRODUCT_MAX_IN_FLIGHT": 1000,
    "PRODUCT_TOTAL_REQUESTS": 30000,
}
GC4_MAX_CONNECTIONS_PER_WORKER = 150
GC4_BACKLOG = 2048
GC4_GATEWAY_WORKERS = "4"
GC4_THREADPOOL_BOUNDARY = "run_in_threadpool(self._ingest_txn, event)"
# The index PostgreSQL names `alert_events_fingerprint_received_at_idx`, as the
# migration spells it. Dropping it makes candidate selection O(n); it stays.
GC4_FINGERPRINT_INDEX = "CREATE INDEX ON alert_events (fingerprint, received_at);"
GC4_DURABILITY_TOKENS = ("synchronous_commit", "fsync", "full_page_writes")
# This slice's own diagnostic values. None may become a sizing-carrier value
# or a B1-LATENCY-BASIS-1 observation; they are evidence and nothing else.
GC4_RCA_DIAGNOSTICS = ("2.105", "1.901", "2.008")
GC4_SIZING_CARRIERS = (
    ("deploy", "charts", "dbagent", "values.yaml"),
    ("tests", "benchmark", "thresholds.yaml"),
    ("tests", "delivery", "test_delivery_sizing_ledger.py"),
    ("services", "gateway", "tests", "b1_reference_profile.py"),
    ("services", "gateway", "tests", "test_b1_ingest_burst.py"),
    ("scripts", "integration-test.sh"),
)
# The test-only wait sampler: its symbols may live only in the B1 harness.
GC4_SAMPLER_SYMBOLS = (
    "B1PostgresWaitSampler",
    "B1PostgresWaitSample",
    "classify_postgres_wait",
    "serialize_postgres_wait_histogram",
    "serialize_postgres_cost_fields",
    "postgres_wait_",
    "gc4-wait-sampler",
)
GC4_COST_FIELDS = (
    "postgres_cpu_us_per_req",
    "postgres_wait_scheduled",
    "postgres_wait_completed",
    "postgres_wait_failed",
    "postgres_wait_observations",
    "postgres_wait_events_pct",
)
# GC-3 rev 0.8 retires this slice's fixed evidence-head and fixed-status pins:
# the authoritative head of every current and superseded decision is DERIVED
# from the carrier by `_gc3_handoff_provenance_failures`, and GC-4 may not
# assert one. What remains here is what GC-4 itself changed, narrowly -- the
# fused statement's own plan+execute cost, not "the gateway's PostgreSQL cost",
# which would read as a whole-container claim this slice disclaims.
GC4_PRODUCT_COST_WORDING = "the fused statement's plan+execute cost per merge"
GC4_PRODUCT_SOURCE_DIRS = (
    ("services", "gateway", "gateway"),
    ("services", "worker", "worker"),
    ("services", "dashboard-api", "dashboard_api"),
    ("libs", "py", "rca_common", "rca_common"),
)


def _gc4_prose_free(src: str) -> str:
    """Source with comments and docstrings blanked; other literals untouched.

    The pins below forbid tokens that the prose explaining them legitimately
    names -- a scan that reads a comment finds the word in the sentence that
    says the word must not be in the code. String literals stay, because a
    SQL ``PREPARE`` smuggled in as a literal is exactly what is forbidden.
    """
    tree = ast.parse(src)
    docstring_lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = getattr(node, "body", None)
        if not body:
            continue
        first = body[0]
        if (
            isinstance(first, ast.Expr)
            and isinstance(first.value, ast.Constant)
            and isinstance(first.value.value, str)
        ):
            docstring_lines.update(
                range(first.lineno, (first.end_lineno or first.lineno) + 1)
            )
    lines = src.splitlines()
    for token in tokenize.generate_tokens(io.StringIO(src).readline):
        if token.type != tokenize.COMMENT:
            continue
        row, col = token.start
        lines[row - 1] = lines[row - 1][:col]
    return "\n".join(
        "" if index in docstring_lines else line
        for index, line in enumerate(lines, start=1)
    )


def _gc4_function(tree: ast.AST, name: str) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{name} not found")


def _gc4_product_sources() -> "list[tuple[str, str]]":
    """Every production Python module, with its prose removed."""
    out: list[tuple[str, str]] = []
    for parts in GC4_PRODUCT_SOURCE_DIRS:
        root = REPO_ROOT.joinpath(*parts)
        for path in sorted(root.rglob("*.py")):
            out.append((
                str(path.relative_to(REPO_ROOT)),
                _gc4_prose_free(path.read_text(encoding="utf-8")),
            ))
    return out


def test_gc4_gateway_driver_scope_is_pinned():
    """FP-GC4-2: Psycopg 3 and the fixed threshold are the gateway's alone.

    The one engine, the one call site, the one connect listener, the unchanged
    shared factory and the unchanged callers -- each read from its own source,
    none of them inferred from another.
    """
    main_src = GC4_MAIN_PATH.read_text(encoding="utf-8")
    main_code = _gc4_prose_free(main_src)
    main_tree = ast.parse(main_src)

    # (1) The dependency is the gateway package's alone, bounded, and does not
    # displace the common library's Psycopg 2.
    gateway_toml = GC4_GATEWAY_PYPROJECT.read_text(encoding="utf-8")
    assert gateway_toml.count(GC4_GATEWAY_DEPENDENCY) == 1, GC4_GATEWAY_DEPENDENCY
    common_toml = GC4_COMMON_PYPROJECT.read_text(encoding="utf-8")
    assert GC4_COMMON_DEPENDENCY in common_toml, "rca_common lost its Psycopg 2 pin"
    assert "psycopg[" not in common_toml, "Psycopg 3 moved into the common library"
    for parts in (
        ("services", "worker", "pyproject.toml"),
        ("services", "dashboard-api", "pyproject.toml"),
    ):
        text = REPO_ROOT.joinpath(*parts).read_text(encoding="utf-8")
        assert "psycopg[" not in text, f"{parts[-2]} acquired Psycopg 3"

    # (2) Exactly one engine constructor, with exactly one `make_engine` call
    # site inside it, one positional argument and no keyword at all -- which is
    # also what keeps the connection-budget AST count at one.
    factory = _gc4_function(main_tree, GC4_ENGINE_FACTORY)
    module_calls = _gc2_named_calls(main_tree, "make_engine")
    assert len(module_calls) == 1, "the gateway has more than one make_engine call site"
    assert module_calls[0] in _gc2_named_calls(factory, "make_engine")
    assert len(module_calls[0].args) == 1
    assert not module_calls[0].keywords, "the gateway engine gained a keyword"
    factory_src = ast.get_source_segment(main_src, factory) or ""
    assert "render_as_string(hide_password=False)" in factory_src, (
        "the shared `dsn: str` signature is not rendered back to a string"
    )
    assert "make_url(dsn)" in factory_src, "the DSN is not carried by a URL object"
    assert f'drivername="{GC4_DIALECT}"' in factory_src, GC4_DIALECT
    assert not _gc2_named_calls(factory, "replace"), "ad-hoc DSN string replacement"
    assert len(_gc2_named_calls(main_tree, GC4_ENGINE_FACTORY)) == 1, (
        "build_app is not the only caller of the gateway engine constructor"
    )
    build_app = _gc4_function(main_tree, "build_app")
    assert _gc2_named_calls(build_app, GC4_ENGINE_FACTORY), (
        "build_app does not build its engine through the gateway constructor"
    )
    assert not _gc2_named_calls(build_app, "make_engine")

    # (3) The one new per-connection setting is the connect-event listener.
    # No connect_args, no pool keyword, no engine keyword anywhere in main.
    listen = [
        call for call in _gc2_named_calls(factory, "listen")
        if ast.unparse(call.func).endswith("event.listen")
    ]
    assert len(listen) == 1, "the prepare-threshold hook is not one connect listener"
    rendered = ast.unparse(listen[0])
    assert "'connect'" in rendered, rendered
    assert GC4_LISTENER in rendered, rendered
    for keyword in GC4_FORBIDDEN_ENGINE_KEYWORDS:
        assert keyword not in main_code, f"the gateway engine gained {keyword}"
    for token in GC4_DURABILITY_TOKENS:
        assert token not in main_code, token

    # (4) The threshold is a fixed constant, set on the raw connection, with no
    # environment, YAML, chart, query-string or caller override.
    main_assigns = _source_assigns(main_src)
    threshold = main_assigns[GC4_THRESHOLD_CONSTANT]
    assert isinstance(threshold, ast.Constant), "the threshold is not a literal"
    assert threshold.value == GC4_PREPARE_THRESHOLD, threshold.value
    listener = _gc4_function(main_tree, GC4_LISTENER)
    listener_src = ast.get_source_segment(main_src, listener) or ""
    assert f"prepare_threshold = {GC4_THRESHOLD_CONSTANT}" in listener_src, listener_src
    env_reads = {
        ast.unparse(call.args[0])
        for call in ast.walk(main_tree)
        if isinstance(call, ast.Call)
        and ast.unparse(call.func) in ("os.environ.get", "os.getenv")
        and call.args
    }
    for name in env_reads:
        assert "PREPARE" not in name.upper(), name
        assert "PSYCOPG" not in name.upper(), name
        assert "DRIVER" not in name.upper(), name
    assert not _gc2_named_calls(factory, "load_config")
    assert len(factory.args.args) == 1, "the constructor gained a caller-facing knob"
    assert factory.args.kwonlyargs == [] and factory.args.defaults == []

    # (5) The shared factory and every other production caller are unchanged.
    session_src = GC4_SESSION_PATH.read_text(encoding="utf-8")
    assert "def make_engine(dsn: str, **kwargs) -> Engine:" in session_src
    assert "create_engine(dsn, future=True, **kwargs)" in session_src
    assert "expire_on_commit=False" in session_src
    for parts in GC4_OTHER_ENGINE_MODULES:
        path = REPO_ROOT.joinpath(*parts)
        text = _gc4_prose_free(path.read_text(encoding="utf-8"))
        assert "make_engine" in text, f"{parts[-1]} no longer uses the shared factory"
        for forbidden in (GC4_ENGINE_FACTORY, GC4_DIALECT, "prepare_threshold", "psycopg"):
            assert forbidden not in text, f"{parts[-1]} acquired {forbidden!r}"

    # (6) Migrations, deployment, chart and compose DSNs stay ordinary.
    for path in sorted(GC4_MIGRATIONS_DIR.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        text = _gc4_prose_free(path.read_text(encoding="utf-8"))
        assert "psycopg" not in text, f"{path.name} names a driver"
    for path in sorted(GC4_DEPLOY_DIR.rglob("*")):
        if not path.is_file() or path.suffix not in (".yaml", ".yml", ".tpl", ".env"):
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        assert GC4_DIALECT not in text, f"{path} names the gateway dialect"
        assert "prepare_threshold" not in text, f"{path} names the threshold"

    # (7) The connection-budget carrier is untouched and still says one.
    budget = _load(REPO_ROOT / "tests" / "delivery" / "connection_budget.py", "gc4_budget")
    assert budget.ENGINES_PER_PROCESS["ingest-gateway"] == 1
    assert budget.count_make_engine_calls("ingest-gateway") == 1
    assert budget.stock_engine_capacity() == 15


def test_gc4_fixed_bars_and_sizing_boundaries_are_pinned():
    """FP-GC4-6: the statement, the workload, the capacity and the ledger stand still."""
    # (1) The GC-2 statement is byte-unchanged and keeps its typed binds. The
    # digest is of the Python constant; the wire form legitimately differs
    # under the Psycopg dialect's bind casts, and is deliberately not pinned.
    import sys

    sys.path.insert(0, str(REPO_ROOT / "libs" / "py" / "rca_common"))
    try:
        from rca_common import investigation_repo as gc4_repo
    finally:
        sys.path.pop(0)
    sql = gc4_repo._MERGE_EXISTING_EVENT_WITH_AUDIT_SQL
    assert hashlib.sha256(sql.encode("utf-8")).hexdigest() == GC4_MERGE_SQL_SHA256, (
        "the GC-2 fused statement changed"
    )
    binds = gc4_repo._MERGE_EXISTING_EVENT_WITH_AUDIT_STMT._bindparams
    observed = {name: type(param.type).__name__ for name, param in binds.items()}
    assert observed == dict(GC4_MERGE_BIND_INVENTORY), observed
    # `(?<!:)` keeps the statement's own `::TYPE` casts out of the bind set.
    assert set(re.findall(r"(?<!:):([a-z_]+)", sql)) == {
        name for name, _ in GC4_MERGE_BIND_INVENTORY
    }
    helper = _gc4_function(
        ast.parse(GC4_REPO_PATH.read_text(encoding="utf-8")),
        "merge_existing_event_with_audit",
    )
    assert len(_gc2_named_calls(helper, "execute")) == 1, "a second product execute"
    assert not _gc2_named_calls(helper, "commit")

    # (2) No SQL-level preparation, stored form or driver-level retry anywhere
    # in product code.
    for relative, text in _gc4_product_sources():
        upper = text.upper()
        for token in GC4_FORBIDDEN_SQL_TOKENS:
            assert token.upper() not in upper, f"{relative} carries {token!r}"
    # ...and the gateway adds no driver-level retry of its own.
    gateway_code = _gc4_prose_free(GC4_MAIN_PATH.read_text(encoding="utf-8")).lower()
    for token in ("retry", "reconnect", "while true"):
        assert token not in gateway_code, token

    # (3) Workload, capacity, durability and threadpool boundary.
    profile_assigns = _module_assigns(REF_PATH)
    harness_src = REF_TEST.read_text(encoding="utf-8")
    harness_assigns = _source_assigns(harness_src)
    for name, expected in GC4_FIXED_CI_SCALE_LITERALS.items():
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    for name, expected in {
        **GC4_FIXED_CI_SCALE_LITERALS, **GC4_FIXED_PRODUCT_LITERALS,
    }.items():
        node = harness_assigns.get(name)
        if node is None:
            continue
        assert isinstance(node, ast.Constant) and node.value == expected, name
    assert "MAX_IN_FLIGHT = BURST_RATE" in REF_PATH.read_text(encoding="utf-8")
    main_src = GC4_MAIN_PATH.read_text(encoding="utf-8")
    main_assigns = _source_assigns(main_src)
    assert ast.literal_eval(
        main_assigns["DEFAULT_MAX_CONNECTIONS_PER_WORKER"]
    ) == GC4_MAX_CONNECTIONS_PER_WORKER
    assert ast.literal_eval(main_assigns["BACKLOG"]) == GC4_BACKLOG
    assert f'"DBAGENT_GATEWAY_WORKERS", "{GC4_GATEWAY_WORKERS}"' in main_src
    assert "limit_concurrency=max_connections" in main_src
    ingest_src = GC4_INGEST_PATH.read_text(encoding="utf-8")
    assert GC4_THREADPOOL_BOUNDARY in ingest_src, "the threadpool boundary moved"
    session_src = GC4_SESSION_PATH.read_text(encoding="utf-8")
    for token in GC4_DURABILITY_TOKENS:
        for label, text in (("main", main_src), ("session", session_src),
                            ("ingest", ingest_src),
                            ("repo", GC4_REPO_PATH.read_text(encoding="utf-8"))):
            assert token not in _gc4_prose_free(text), f"{label} touches {token}"
    assert ast.literal_eval(
        harness_assigns["PRODUCT_AFFINITY_CARDINALITY"]
    ) == GC1_AFFINITY_CARDINALITIES["product-exclusive"]

    # (4) The fingerprint index is load-bearing and still declared.
    migration = (GC4_MIGRATIONS_DIR / "versions" / "0001_initial_schema.py").read_text(
        encoding="utf-8"
    )
    assert GC4_FINGERPRINT_INDEX in migration, "the fingerprint index was dropped"

    # (5) The wait sampler is test-only: its symbols exist in the B1 harness
    # and in no product source, and it builds no product engine.
    for relative, text in _gc4_product_sources():
        for symbol in GC4_SAMPLER_SYMBOLS:
            assert symbol not in text, f"{relative} carries the test-only {symbol!r}"
    assert _module_tuple(ast.parse(harness_src), "B1_POSTGRES_COST_FIELDS") == GC4_COST_FIELDS
    sampler = _gc4_function(ast.parse(harness_src), "_open_postgres_wait_connection")
    sampler_src = ast.get_source_segment(harness_src, sampler) or ""
    assert "psycopg2.connect" in sampler_src, "the sampler does not own its connection"
    for forbidden in ("make_engine", "make_gateway_engine", "session_factory"):
        assert forbidden not in sampler_src, forbidden

    # ...and no cost field is a gating field, a verdict or a GC-3 record key.
    harness_tree = ast.parse(harness_src)
    gating = set(_module_tuple(harness_tree, "B1_GATING_PLACEMENT_FIELDS"))
    topology_gating = set(_module_tuple(harness_tree, "B1_TOPOLOGY_GATING_PLACEMENT_FIELDS"))
    product_verdicts = set(_module_tuple(harness_tree, "PRODUCT_VERDICT_FIELDS"))
    for field in GC4_COST_FIELDS:
        assert field not in gating, field
        assert field not in topology_gating, field
        assert field not in product_verdicts, field
        assert field not in gc3.VERDICT_FIELDS, field
        assert field not in gc3.RECORD_KEYS, field

    # (6) The prohibited diagnostics. FP-B1LB-7: the basis VALUE and the
    # emptiness of the ledger are B1-LATENCY-BASIS-1's to move, so neither is
    # pinned here any more -- and the blanket "no long integer in the sizing
    # block" rule is narrowed to THIS slice's own run id, because a qualified
    # ledger legitimately carries five real GitHub run identities.
    values = yaml.safe_load(GC4_VALUES_PATH.read_text(encoding="utf-8"))
    basis = values["ingestGateway"]["sizingBasis"]
    for parts in GC4_SIZING_CARRIERS:
        carrier = REPO_ROOT.joinpath(*parts)
        assert carrier.is_file(), parts[-1]
        text = carrier.read_text(encoding="utf-8")
        for value in GC4_RCA_DIAGNOSTICS:
            assert value not in text, f"{parts[-1]} carries the diagnostic {value}"
    rendered_basis = yaml.safe_dump(basis)
    for value in GC4_RCA_DIAGNOSTICS + (GC3_RCA_RUN_ID, GC2_INVESTIGATION_RUN_ID):
        assert value not in rendered_basis, f"the sizing block carries {value}"


def test_gc4_gc3_requalification_handoff_is_head_scoped():
    """FP-GC4-7: the current decision stays evidence for its own product head.

    GC-4 records no topology, relabels no SKU and claims no hostability. What
    it owes GC-3 is a tracked manifest whose per-model provenance is DERIVED
    from the carrier -- the exact current evidence head and every superseded
    head, oldest to newest, as full 40-lowercase-hex values -- rather than a
    head, a status or an empty declaration map this slice pinned by hand.
    """
    # (1)-(2)-(3) The carrier's own provenance, recomputed, head-proved and
    # published. GC-4 asserts no head and no status of its own.
    thresholds = yaml.safe_load(GC4_THRESHOLDS.read_text(encoding="utf-8"))
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    notes = b1_entry["notes"]
    assert b1_entry["status"] == "covered", "the bar was relabelled"
    assert _gc3_handoff_provenance_failures(notes) == []
    models = json.loads(GC3_DECISION.read_text(encoding="utf-8"))["models"]
    for model in models:
        assert model in notes, model
    # ...and the manifest still states what GC-4 itself changed, narrowly.
    assert GC4_PRODUCT_COST_WORDING in notes
    # The unchanged bar is still stated, and no GC-4 record may be read as it.
    assert "p99<150ms" in notes.replace(" ", "")
    assert CI_SCALE_REF_TEST in notes
    for claim in ("is hostable", "now hostable", "GC-4 selects", "selected by GC-4"):
        assert claim not in notes, claim

    # (4) The cost diagnostics are described as reported-only in the same
    # manifest, so a reader cannot take them for a bar or a selector input.
    for field in GC4_COST_FIELDS:
        assert field in notes, field
    assert "reported diagnostic" in notes

    # (5) No runner class is added and no job waits on a new one: the probe is
    # still the manual `ubuntu-latest` workflow-dispatch route.
    ci = yaml.safe_load(GC4_CI_YML.read_text(encoding="utf-8"))
    for name, job in ci["jobs"].items():
        assert job.get("runs-on") == "ubuntu-latest", (name, job.get("runs-on"))
    launcher = GC4_LAUNCHER.read_text(encoding="utf-8")
    for topology in GC3_TOPOLOGY_IDS:
        assert topology not in launcher, topology

    # (6) The only test that can establish the CI-scale bar is unchanged, and
    # no GC-4 node claims it.
    harness_src = REF_TEST.read_text(encoding="utf-8")
    ci_scale = _gc2_function(ast.parse(harness_src), CI_SCALE_REF_TEST)
    observed = {
        ast.unparse(node.test) for node in ast.walk(ci_scale) if isinstance(node, ast.Assert)
    }
    assert not GC2_CI_SCALE_REQUIRED_ASSERTIONS - observed
    gc4_node = _gc4_function(ast.parse(harness_src), "test_gc4_live_postgres_cost_record_is_complete")
    gc4_src = ast.get_source_segment(harness_src, gc4_node) or ""
    for forbidden in ("CI_SCALE_P99_MS", "PRODUCT_P99_MS", "hostable", "selected",
                      "VERDICT_MET", "b1_topology_decision"):
        assert forbidden not in gc4_src, forbidden


# ---------------------------------------------------------------------------
# GC-5 — the durable commit-shape slice's source and configuration boundary
# (FP-GC5-6 / FP-GC5-8 / FP-GC5-9 / FP-GC5-10).
#
# Every literal below is declared here, independently of the module it pins,
# for the same reason the GC-2, GC-3 and GC-4 blocks above declare theirs. The
# pins are structural: they say what this slice did and did not change, and
# they infer no performance from source shape -- the product-local record
# required by FP-GC5-7 remains the only mechanism evidence.
# ---------------------------------------------------------------------------

GC5_COALESCER_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "merge_commit.py"
GC5_INGEST_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "ingest.py"
GC5_MAIN_PATH = REPO_ROOT / "services" / "gateway" / "gateway" / "main.py"
GC5_SESSION_PATH = (
    REPO_ROOT / "libs" / "py" / "rca_common" / "rca_common" / "db" / "session.py"
)
GC5_REPO_PATH = (
    REPO_ROOT / "libs" / "py" / "rca_common" / "rca_common" / "investigation_repo.py"
)
GC5_CONFTEST = REPO_ROOT / "tests" / "functional" / "conftest.py"
GC5_THRESHOLDS = REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml"
GC5_CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"
GC5_LAUNCHER = REPO_ROOT / "scripts" / "integration-test.sh"
GC5_VALUES_PATH = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
GC5_MIGRATIONS_DIR = REPO_ROOT / "libs" / "py" / "rca_common" / "migrations"
GC5_PROBE_LIVE = REPO_ROOT / "services" / "gateway" / "tests" / "b1_topology_probe_live.py"
GC5_PROBE_HELPER = REPO_ROOT / "services" / "gateway" / "tests" / "b1_topology_probe.py"

#: The fixed batch shape, and the one production carrier that may declare it.
GC5_BATCH_SIZE = 8
GC5_MAX_WAIT_SECONDS = 0.010
GC5_BATCH_CONSTANTS = ("MERGE_COMMIT_BATCH_SIZE", "MERGE_COMMIT_MAX_WAIT_SECONDS")
GC5_COALESCER_CLASS = "MergeCommitCoalescer"
GC5_BATCH_CALLBACK = "_execute_merge_batch"
#: Durability settings and WAL surrogates no source or configuration may name.
#: `SET LOCAL synchronous_commit=off` is a knob change whatever its scope, and
#: an LSN poll is not a transaction-owned flush primitive; both are rejected.
GC5_DURABILITY_TOKENS = (
    "synchronous_commit",
    "fsync",
    "full_page_writes",
    "commit_delay",
    "commit_siblings",
    "wal_writer_delay",
    "wal_writer_flush_after",
    "wal_sync_method",
    "SET LOCAL",
    "SET SESSION",
    "pg_current_wal_insert_lsn",
    "pg_current_wal_flush_lsn",
    "pg_current_wal_lsn",
    "pg_wal_lsn_diff",
    "pg_switch_wal",
    "pg_walfile_name",
    "pg_stat_get_wal_senders",
    "synchronous_standby_names",
)
#: Ways of turning the fixed batch shape into a knob.
GC5_OVERRIDE_TOKENS = (
    "MERGE_COMMIT_BATCH",
    "MERGE_COMMIT_MAX_WAIT",
    "BATCH_SIZE",
    "COALESC",
    "batch_size",
    "max_wait",
)
GC5_POOL_KEYWORDS = (
    "connect_args",
    "poolclass",
    "pool_size",
    "max_overflow",
    "pool_timeout",
    "pool_recycle",
    "pool_pre_ping",
    "pool_use_lifo",
    "isolation_level",
    "execution_options",
    "creator",
    "NullPool",
    "StaticPool",
    "QueuePool",
)
GC5_RETRY_TOKENS = ("retry", "reconnect", "attempt_again", "backoff")
#: The GC-2 statement, byte-unchanged under GC-5 as well.
GC5_MERGE_SQL_SHA256 = (
    "2cc1897aab8247c562f5fdd5996b9e2be7fa54cd7d8f23443c4582e96cbcd3bb"
)
GC5_FUSED_HELPER = "merge_existing_event_with_audit"
GC5_TXN = "_ingest_txn"
GC5_THREADPOOL_BOUNDARY = "run_in_threadpool(self._ingest_txn, event)"
GC5_FINGERPRINT_INDEX = "CREATE INDEX ON alert_events (fingerprint, received_at);"
GC5_FIXED_CI_SCALE_LITERALS = {
    "CI_SCALE_BURST_RATE": 500,
    "CI_SCALE_BURST_SECONDS": 30,
    "CI_SCALE_TOTAL_REQUESTS": 15000,
    "CI_SCALE_P99_MS": 150.0,
    "CI_SCALE_SUSTAINED_FLOOR": 450,
    "CI_SCALE_MAX_IN_FLIGHT": 500,
}
GC5_FIXED_PRODUCT_LITERALS = {
    "PRODUCT_P99_MS": 150.0,
    "PRODUCT_SUSTAINED_FLOOR": 200,
    "PRODUCT_MAX_IN_FLIGHT": 1000,
    "PRODUCT_TOTAL_REQUESTS": 30000,
}
#: The product profile's own offer, as the profile module spells it.
GC5_FIXED_PRODUCT_PROFILE_LITERALS = {
    "BURST_RATE": 1000,
    "BURST_SECONDS": 30,
    "TOTAL_REQUESTS": 30000,
    "P99_MS": 150.0,
    "SUSTAINED_FLOOR": 200,
}
GC5_TIMEOUT_KEEP_ALIVE_S = 5
#: The AnyIO threadpool limiter: nothing in the repository may resize it, so
#: the effective capacity stays AnyIO's shipped default.
GC5_LIMITER_TOKENS = (
    "current_default_thread_limiter",
    "total_tokens",
    "CapacityLimiter",
    "RunVar",
)
GC5_B1_THRESHOLD = (
    "CI-scale gating: >= 450 req/s served, p99 < 150 ms, 0 errors at 500 req/s offered for\n"
    "30s with exclusive gateway/PG/driver affinity cardinalities=2/1/1; product recorded, "
    "non-gating:\nserved == offered, p99 < 150 ms, 0 errors at 1000 req/s offered for 30s "
    "with 4 gateway CPUs\nexclusive from PG/driver"
)
GC5_MAX_CONNECTIONS_PER_WORKER = 150
GC5_BACKLOG = 2048
GC5_GATEWAY_WORKERS = "4"
GC5_PREPARE_THRESHOLD = 5
#: The one GC-5 outcome and the diagnostic fields around it.
GC5_MAX_COMMITS_PER_SERVED = 0.60
GC5_RATIO_CONSTANT = "B1_COMMIT_SHAPE_MAX_COMMITS_PER_SERVED"
GC5_COMMIT_FIELDS = (
    "postgres_xact_commit_delta",
    "postgres_xact_rollback_delta",
    "postgres_xact_commits_per_served",
    "postgres_wal_records_delta",
    "postgres_wal_bytes_delta",
    "postgres_wal_write_delta",
    "postgres_wal_sync_delta",
    "postgres_wal_syncs_per_served",
)
GC5_STATS_SYMBOLS = (
    "B1PostgresCommitSnapshot",
    "B1PostgresStatsReader",
    "serialize_postgres_commit_fields",
    "postgres_commit_snapshot_failure",
    "postgres_xact_commits_per_served",
    "commit_shape_record_failures",
    "gc5-stats-reader",
)
GC5_SAMPLER_APPLICATION_NAME = "gc4-wait-sampler"
GC5_STATS_APPLICATION_NAME = "gc5-stats-reader"
GC5_MAINTENANCE_DATABASE = "postgres"
GC5_MAINTENANCE_ALTERNATE = "template1"
GC5_GATE_NODE = "test_gc5_commit_shape_reference_profile"
GC5_CONTEXT_NODE = "test_gc5_product_record_carries_commit_cost_and_lateness_context"
GC5_PRODUCT_MARKERS = {"b1_live", "b1_product"}
#: GC-3's authority, restated: GC-5 changes the product head and nothing about
#: the decision carrier or its routing. Rev 0.8 retires this slice's fixed
#: evidence-head and fixed-status pins in favour of the carrier-derived
#: provenance in `_gc3_handoff_provenance_failures`; what remains here is what
#: GC-5 itself changed, narrowly.
GC5_COMMIT_SHAPE_WORDING = "how many ingested events share one durable commit"
GC5_HOSTABILITY_CLAIMS = (
    "is hostable",
    "now hostable",
    "GC-5 selects",
    "selected by GC-5",
)
GC5_PRODUCT_SOURCE_DIRS = (
    ("services", "gateway", "gateway"),
    ("services", "worker", "worker"),
    ("services", "dashboard-api", "dashboard_api"),
    ("libs", "py", "rca_common", "rca_common"),
)


def _gc5_product_sources() -> "list[tuple[str, str]]":
    """Every production Python module, with its prose removed."""
    out: list[tuple[str, str]] = []
    for parts in GC5_PRODUCT_SOURCE_DIRS:
        root = REPO_ROOT.joinpath(*parts)
        for path in sorted(root.rglob("*.py")):
            if "__pycache__" in path.parts:
                continue
            out.append((
                str(path.relative_to(REPO_ROOT)),
                _gc4_prose_free(path.read_text(encoding="utf-8")),
            ))
    return out


def _gc5_configuration_files() -> "list[tuple[str, str]]":
    """Every shipped configuration carrier a durability knob could hide in."""
    out: list[tuple[str, str]] = []
    for root, suffixes in (
        (REPO_ROOT / "deploy", (".yaml", ".yml", ".tpl", ".env", ".conf")),
        (REPO_ROOT / ".github", (".yml", ".yaml")),
    ):
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            out.append((
                str(path.relative_to(REPO_ROOT)),
                path.read_text(encoding="utf-8", errors="replace"),
            ))
    for parts in (("scripts", "integration-test.sh"),
                  ("tests", "benchmark", "thresholds.yaml")):
        path = REPO_ROOT.joinpath(*parts)
        out.append((str(path.relative_to(REPO_ROOT)),
                    path.read_text(encoding="utf-8", errors="replace")))
    return out


def _gc5_method(tree: ast.AST, name: str, *, cls: str = "IngestService") -> ast.AST:
    return _gc2_function(tree, name, cls=cls)


def _gc5_other_benchmark_entries() -> "dict[str, tuple[str, str]]":
    """Every benchmark entry GC-5 did not touch, id -> (status, threshold)."""
    return {
        'B10': (
            'covered',
            'list/filter p99 < 200 ms',
        ),
        'B11': (
            'covered',
            '>= 1000 inserts/s combined without partition-routing degradation',
        ),
        'B12': (
            'covered',
            'p99 < 300 ms',
        ),
        'B13': (
            'covered',
            '< 1 s per round',
        ),
        'B14': (
            'covered',
            'prompt build < 200 ms; assembled context <= model budget with zero truncation of the latest round',
        ),
        'B2': (
            'covered',
            'p99 < 20 ms',
        ),
        'B3': (
            'covered',
            'dispatch p99 < 50 ms, no heartbeat misses',
        ),
        'B4': (
            'covered',
            'end-to-end p99 < 2 s, reassembly CPU < 1 core',
        ),
        'B5': (
            'covered',
            '< 100 ms',
        ),
        'B6': (
            'covered',
            '< 5 ms per command',
        ),
        'B7': (
            'covered',
            '< 10 ms round trip',
        ),
        'B8': (
            'covered',
            'round collection overhead (non-model) < 2 s',
        ),
        'B9': (
            'covered',
            '< 500 ms',
        ),
    }


def test_gc5_synchronous_durability_policy_is_pinned():
    """FP-GC5-6: stock synchronous durability, and no application-side fence.

    The selected mechanism groups transactions; it does not change what a
    COMMIT means. So: no durability setting is named at any scope in product
    code, in the benchmark harness or in any shipped configuration; no LSN
    poll or other flush surrogate exists; and the committed-hit path's only
    successful response fence is one ordinary outer ``commit()``.
    """
    ingest_src = GC5_INGEST_PATH.read_text(encoding="utf-8")
    ingest_code = _gc4_prose_free(ingest_src)
    ingest_tree = ast.parse(ingest_src)
    coalescer_src = GC5_COALESCER_PATH.read_text(encoding="utf-8")
    coalescer_code = _gc4_prose_free(coalescer_src)
    main_code = _gc4_prose_free(GC5_MAIN_PATH.read_text(encoding="utf-8"))
    session_code = _gc4_prose_free(GC5_SESSION_PATH.read_text(encoding="utf-8"))
    repo_code = _gc4_prose_free(GC5_REPO_PATH.read_text(encoding="utf-8"))
    harness_code = _gc4_prose_free(REF_TEST.read_text(encoding="utf-8"))
    profile_code = _gc4_prose_free(REF_PATH.read_text(encoding="utf-8"))
    conftest_code = _gc4_prose_free(GC5_CONFTEST.read_text(encoding="utf-8"))

    # (1) No durability setting and no WAL/LSN surrogate, in product code, in
    # the shared library, in the B1 harness or in its fixtures.
    for label, code in (
        ("ingest", ingest_code),
        ("merge_commit", coalescer_code),
        ("main", main_code),
        ("session", session_code),
        ("investigation_repo", repo_code),
        ("b1 harness", harness_code),
        ("b1 profile", profile_code),
        ("functional conftest", conftest_code),
    ):
        for token in GC5_DURABILITY_TOKENS:
            assert token not in code, f"{label} names {token!r}"
    for relative, code in _gc5_product_sources():
        for token in GC5_DURABILITY_TOKENS:
            assert token not in code, f"{relative} names {token!r}"

    # (2) ...and in no shipped configuration, workflow or launcher either.
    for relative, text in _gc5_configuration_files():
        for token in GC5_DURABILITY_TOKENS:
            if token in ("fsync", "SET LOCAL", "SET SESSION"):
                # `fsync` is a substring of nothing here, but keep the search
                # case-exact and scoped: a setting is written as `name=value`
                # or `-c name=value`.
                assert f"{token}=" not in text, f"{relative} sets {token}"
                assert f"{token} =" not in text, f"{relative} sets {token}"
                continue
            assert token not in text, f"{relative} names {token!r}"

    # (3) The PostgreSQL containers the benchmark and the functional tier
    # start carry no server-setting override beyond the GC-4 statement
    # tracking, so the effective policy is PostgreSQL 16's stock
    # synchronous_commit=on / fsync=on / full_page_writes=on.
    assert 'PostgresContainer(\n            "postgres:16-alpine"' in REF_TEST.read_text(
        encoding="utf-8"
    ), "the B1 PostgreSQL container declaration moved"
    conftest_src = GC5_CONFTEST.read_text(encoding="utf-8")
    command = _source_assigns(conftest_src)["PG_STAT_STATEMENTS_COMMAND"]
    rendered = ast.literal_eval(command) if isinstance(command, ast.Constant) else (
        "".join(
            ast.literal_eval(part) for part in command.values
        ) if isinstance(command, ast.JoinedStr) else ast.unparse(command)
    )
    for token in ("shared_preload_libraries", "track_planning", "track="):
        assert token in rendered, rendered
    for token in GC5_DURABILITY_TOKENS:
        assert token not in rendered, f"the planning fixture sets {token}"

    # (4) The committed-hit path's one successful fence: exactly one outer
    # `session.commit()`, in the group's own closing method, and every other
    # `commit()` in the batch path is a SAVEPOINT release on the savepoint
    # object -- never a second durable commit.
    batch = _gc5_method(ingest_tree, GC5_BATCH_CALLBACK)
    closer = _gc5_method(ingest_tree, "_finish_merge_batch")
    session_commits = [
        call for call in _gc2_named_calls(closer, "commit")
        if isinstance(call.func, ast.Attribute)
        and isinstance(call.func.value, ast.Name)
        and call.func.value.id == "session"
    ]
    assert len(session_commits) == 1, [c.lineno for c in session_commits]
    for call in _gc2_named_calls(batch, "commit"):
        assert isinstance(call.func, ast.Attribute), ast.unparse(call)
        assert isinstance(call.func.value, ast.Name), ast.unparse(call)
        assert call.func.value.id == "savepoint", (
            f"a non-savepoint commit inside the group: {ast.unparse(call)}"
        )
    # A hit is resolved only after that commit: the callback returns its
    # outcomes after the closing method ran, and the coalescer performs no
    # commit of its own at all.
    assert not [
        call for call in _gc2_named_calls(ast.parse(coalescer_src), "commit")
        if isinstance(call.func, ast.Attribute)
    ], "the coalescer performs a commit of its own"
    finish_calls = _gc2_named_calls(batch, "_finish_merge_batch")
    assert len(finish_calls) == 1, [c.lineno for c in finish_calls]
    returns = [node for node in ast.walk(batch) if isinstance(node, ast.Return)]
    assert returns and all(
        node.lineno > finish_calls[0].lineno for node in returns
    ), "the group returns an outcome before its transaction was closed"

    # (5) The group is not a durability policy of its own: no autocommit, no
    # begin/commit on a raw connection, no explicit transaction control beyond
    # savepoints in the product path.
    for forbidden in ("autocommit", "raw_connection", "engine.connect", "text("):
        assert forbidden not in ingest_code, f"ingest names {forbidden!r}"
        assert forbidden not in coalescer_code, f"merge_commit names {forbidden!r}"


def test_gc5_fixed_workload_pool_schema_and_sizing_boundaries():
    """FP-GC5-9: the shape changed; every frozen carrier stood still."""
    ingest_src = GC5_INGEST_PATH.read_text(encoding="utf-8")
    ingest_tree = ast.parse(ingest_src)
    coalescer_src = GC5_COALESCER_PATH.read_text(encoding="utf-8")
    coalescer_tree = ast.parse(coalescer_src)
    coalescer_code = _gc4_prose_free(coalescer_src)
    main_src = GC5_MAIN_PATH.read_text(encoding="utf-8")
    main_code = _gc4_prose_free(main_src)
    harness_src = REF_TEST.read_text(encoding="utf-8")

    # (1) The batch shape is exactly eight events and ten milliseconds, as two
    # literals in ONE production carrier, with no configuration read and no
    # caller-facing override anywhere.
    coalescer_assigns = _source_assigns(coalescer_src)
    for name, expected in zip(
        GC5_BATCH_CONSTANTS, (GC5_BATCH_SIZE, GC5_MAX_WAIT_SECONDS)
    ):
        node = coalescer_assigns[name]
        assert isinstance(node, ast.Constant), f"{name} is not a literal"
        assert node.value == expected, (name, node.value)
    assert not _has_environ_read(GC5_COALESCER_PATH), "the coalescer reads the environment"
    assert not _has_environ_read(GC5_INGEST_PATH), "ingest reads the environment"
    assert not _gc2_named_calls(coalescer_tree, "load_config")
    coalescer_class = _gc2_function(coalescer_tree, "__init__", cls=GC5_COALESCER_CLASS)
    argument_names = [arg.arg for arg in coalescer_class.args.args] + [
        arg.arg for arg in coalescer_class.args.kwonlyargs
    ]
    assert argument_names == ["self", "execute_batch"], argument_names
    assert coalescer_class.args.defaults == [] and coalescer_class.args.kw_defaults == []
    for name in GC5_BATCH_CONSTANTS:
        # The constants are read from the module, never taken as parameters.
        assert name not in argument_names
    for relative, code in _gc5_product_sources():
        if relative.endswith("merge_commit.py"):
            continue
        for token in GC5_OVERRIDE_TOKENS:
            assert token not in code, f"{relative} carries a batching knob {token!r}"
    for relative, text in _gc5_configuration_files():
        for token in GC5_OVERRIDE_TOKENS + ("merge_commit", "MergeCommitCoalescer"):
            assert token not in text, f"{relative} configures batching ({token!r})"
    env_reads = {
        ast.unparse(call.args[0])
        for call in ast.walk(ast.parse(main_src))
        if isinstance(call, ast.Call)
        and ast.unparse(call.func) in ("os.environ.get", "os.getenv")
        and call.args
    }
    for name in env_reads:
        for token in ("BATCH", "MERGE", "COALESC", "COMMIT"):
            assert token not in name.upper(), name

    # (2) No pool keyword, no retry loop and no second execution of a group.
    for label, code in (("main", main_code), ("merge_commit", coalescer_code),
                        ("ingest", _gc4_prose_free(ingest_src))):
        for keyword in GC5_POOL_KEYWORDS:
            assert keyword not in code, f"{label} gained {keyword}"
        for token in GC5_RETRY_TOKENS:
            assert token not in code.lower(), f"{label} gained {token}"
    # The bound callback is stored once and handed to the threadpool once; it
    # is never called directly (that would put database work on the loop) and
    # never called twice (that would be a retry of a group).
    references = [
        node for node in ast.walk(coalescer_tree)
        if isinstance(node, ast.Attribute) and node.attr == "_execute_batch"
    ]
    assert len(references) == 2, [ast.unparse(node) for node in references]
    direct_calls = [
        node for node in ast.walk(coalescer_tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "_execute_batch"
    ]
    assert direct_calls == [], [ast.unparse(node) for node in direct_calls]
    dispatched = [
        node for node in ast.walk(coalescer_tree)
        if isinstance(node, ast.Call)
        and ast.unparse(node.func) == "run_in_threadpool"
        and node.args
        and ast.unparse(node.args[0]) == "self._execute_batch"
    ]
    assert len(dispatched) == 1, [ast.unparse(node) for node in dispatched]
    engine_calls = _gc2_named_calls(ast.parse(main_src), "make_engine")
    assert len(engine_calls) == 1 and not engine_calls[0].keywords
    assert "create_engine(dsn, future=True, **kwargs)" in GC5_SESSION_PATH.read_text(
        encoding="utf-8"
    )

    # (3) Workload, serve parameters, workers, prepare threshold and the
    # threadpool boundary are untouched.
    profile_assigns = _module_assigns(REF_PATH)
    harness_assigns = _source_assigns(harness_src)
    for name, expected in GC5_FIXED_CI_SCALE_LITERALS.items():
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    for name, expected in {
        **GC5_FIXED_CI_SCALE_LITERALS, **GC5_FIXED_PRODUCT_LITERALS,
    }.items():
        node = harness_assigns.get(name)
        if node is None:
            continue
        assert isinstance(node, ast.Constant) and node.value == expected, name
    assert "MAX_IN_FLIGHT = BURST_RATE" in REF_PATH.read_text(encoding="utf-8")
    for name, expected in GC5_FIXED_PRODUCT_PROFILE_LITERALS.items():
        assert _eval_simple_constant(
            profile_assigns[name], profile_assigns
        ) == expected, name
    main_assigns = _source_assigns(main_src)
    assert ast.literal_eval(
        main_assigns["DEFAULT_MAX_CONNECTIONS_PER_WORKER"]
    ) == GC5_MAX_CONNECTIONS_PER_WORKER
    assert ast.literal_eval(main_assigns["BACKLOG"]) == GC5_BACKLOG
    assert ast.literal_eval(
        main_assigns["DEFAULT_TIMEOUT_KEEP_ALIVE_S"]
    ) == GC5_TIMEOUT_KEEP_ALIVE_S
    assert "timeout_keep_alive=timeout_keep_alive" in main_src
    assert "backlog=BACKLOG" in main_src
    # The threadpool the group and the fallback share is AnyIO's default: no
    # source resizes the limiter, and the dispatch is still the shared
    # `run_in_threadpool` boundary rather than an executor of our own.
    for relative, code in _gc5_product_sources():
        for token in GC5_LIMITER_TOKENS:
            assert token not in code, f"{relative} resizes the threadpool ({token})"
    # ...and the stock pool capacity the shared factory builds is unchanged.
    budget = _load(REPO_ROOT / "tests" / "delivery" / "connection_budget.py", "gc5_budget")
    assert budget.ENGINES_PER_PROCESS["ingest-gateway"] == 1
    assert budget.count_make_engine_calls("ingest-gateway") == 1
    assert budget.stock_engine_capacity() == 15
    assert ast.literal_eval(
        main_assigns["GATEWAY_PREPARE_THRESHOLD"]
    ) == GC5_PREPARE_THRESHOLD
    assert f'"DBAGENT_GATEWAY_WORKERS", "{GC5_GATEWAY_WORKERS}"' in main_src
    assert "limit_concurrency=max_connections" in main_src
    assert GC5_THREADPOOL_BOUNDARY in ingest_src, "the threadpool boundary moved"
    assert ast.literal_eval(
        harness_assigns["PRODUCT_AFFINITY_CARDINALITY"]
    ) == GC1_AFFINITY_CARDINALITIES["product-exclusive"]

    # (4) The statement, its binds, the index and the schema are unchanged,
    # and no migration was added.
    import sys

    sys.path.insert(0, str(REPO_ROOT / "libs" / "py" / "rca_common"))
    try:
        from rca_common import investigation_repo as gc5_repo
    finally:
        sys.path.pop(0)
    sql = gc5_repo._MERGE_EXISTING_EVENT_WITH_AUDIT_SQL
    assert hashlib.sha256(sql.encode("utf-8")).hexdigest() == GC5_MERGE_SQL_SHA256, (
        "the GC-2 fused statement changed"
    )
    helper = _gc4_function(ast.parse(GC5_REPO_PATH.read_text(encoding="utf-8")),
                           GC5_FUSED_HELPER)
    assert len(_gc2_named_calls(helper, "execute")) == 1, "a second product execute"
    assert not _gc2_named_calls(helper, "commit")
    migration = (GC5_MIGRATIONS_DIR / "versions" / "0001_initial_schema.py").read_text(
        encoding="utf-8"
    )
    assert GC5_FINGERPRINT_INDEX in migration, "the fingerprint index was dropped"
    versions = sorted(
        path.name for path in (GC5_MIGRATIONS_DIR / "versions").glob("*.py")
        if "__pycache__" not in path.parts
    )
    assert versions == [
        "0001_initial_schema.py",
        "0002_dashboard_m4.py",
        "0003_m6_list_indexes.py",
    ], versions

    # (5) Every ingest branch, response body, audit action and the advisory
    # lock remain reachable, and the fused statement runs once per request.
    ingest_fn = _gc5_method(ingest_tree, "ingest")
    txn = _gc5_method(ingest_tree, GC5_TXN)
    batch = _gc5_method(ingest_tree, GC5_BATCH_CALLBACK)
    assert len(_gc2_named_calls(ast.parse(ingest_src), GC5_FUSED_HELPER)) == 1
    assert len(_gc2_named_calls(batch, GC5_FUSED_HELPER)) == 1
    assert not _gc2_named_calls(txn, GC5_FUSED_HELPER), (
        "the fused statement is repeated on the fallback"
    )
    assert not _gc2_named_calls(ingest_fn, GC5_FUSED_HELPER)
    rendered_ingest = ast.unparse(ingest_fn)
    for reason in ("missing_platform_key", "missing_error_summary", "unknown_source"):
        assert reason in rendered_ingest, reason
    rendered_txn = ast.unparse(txn)
    for reason in ("unknown_platform_key", "platform_not_ready"):
        assert reason in rendered_txn, reason
    for action in ("event_merged", "event_received", "event_rejected"):
        assert f'action="{action}"' in ingest_src, action
    lock_calls = _gc2_named_calls(txn, "acquire_correlation_lock")
    find_calls = _gc2_named_calls(txn, "find_open_by_fingerprint")
    assert len(lock_calls) == 1 and len(find_calls) == 1
    assert lock_calls[0].lineno < find_calls[0].lineno, (
        "the deciding correlation read must happen under the advisory lock"
    )
    assert "'status': 'merged'" in ast.unparse(ingest_fn) or (
        '"status": "merged"' in ingest_src
    )
    starters = _gc2_named_calls(ast.parse(ingest_src), "start_investigation")
    assert len(starters) == 1
    assert _gc2_named_calls(ingest_fn, "start_investigation")
    assert not _gc2_named_calls(txn, "start_investigation")
    assert not _gc2_named_calls(batch, "start_investigation"), (
        "a workflow is started for a grouped hit"
    )

    # (6) The ledger owner and the runner classes. FP-B1LB-7: neither the
    # basis value nor the ledger's emptiness is pinned here any more; GC-5's
    # own claim is the transaction ratio, and its own diagnostics stay out of
    # the sizing block however that block is populated.
    values_text = GC5_VALUES_PATH.read_text(encoding="utf-8")
    values = yaml.safe_load(values_text)
    basis = values["ingestGateway"]["sizingBasis"]
    rendered_basis = yaml.safe_dump(basis)
    for field in GC5_COMMIT_FIELDS + (GC5_RATIO_CONSTANT,):
        assert field not in rendered_basis, f"the sizing block carries {field}"
    thresholds = yaml.safe_load(GC5_THRESHOLDS.read_text(encoding="utf-8"))
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    assert b1_entry["status"] == "covered", "the bar was relabelled"
    assert b1_entry["threshold"].split() == GC5_B1_THRESHOLD.split(), (
        "the B1 threshold string moved"
    )
    assert GC1_BASIS_OWNER in b1_entry["notes"]
    assert GC1_BASIS_GATE in b1_entry["notes"]
    assert "p99<150ms" in b1_entry["notes"].replace(" ", "")
    # Every other benchmark entry keeps its own threshold and status: this
    # slice appended prose to B1's notes and touched nothing else.
    assert {
        entry["id"]: (entry["status"], entry["threshold"])
        for entry in thresholds["benchmarks"]
        if entry["id"] != "B1"
    } == _gc5_other_benchmark_entries(), "another benchmark entry moved"
    ci = yaml.safe_load(GC5_CI_YML.read_text(encoding="utf-8"))
    for name, job in ci["jobs"].items():
        assert job.get("runs-on") == "ubuntu-latest", (name, job.get("runs-on"))
    launcher = GC5_LAUNCHER.read_text(encoding="utf-8")
    for line in GC2_LAUNCHER_AFFINITY_LINES:
        assert line in launcher, line
    for line in GC2_LAUNCHER_ROUTED_LINES:
        assert line in launcher, line
    for token in GC5_OVERRIDE_TOKENS:
        assert token not in launcher, f"the launcher configures batching ({token!r})"

    # (7) No dependency, endpoint, response field or request option was added.
    gateway_toml = (REPO_ROOT / "services" / "gateway" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert gateway_toml.count(GC4_GATEWAY_DEPENDENCY) == 1
    import tomllib

    declared = set(
        tomllib.loads(gateway_toml)["project"]["dependencies"]
    )
    assert declared == {
        "fastapi>=0.110,<1",
        "uvicorn[standard]>=0.27,<1",
        "temporalio>=1.7,<2",
        "rca-common",
        GC4_GATEWAY_DEPENDENCY,
    }, sorted(declared)
    app_src = (REPO_ROOT / "services" / "gateway" / "gateway" / "app.py").read_text(
        encoding="utf-8"
    )
    routes = re.findall(r'@app\.(get|post|put|delete)\("([^"]+)"\)', app_src)
    assert sorted(routes) == [("get", "/healthz"), ("post", "/api/v1/events")], routes
    for token in GC5_COMMIT_FIELDS + GC5_BATCH_CONSTANTS:
        assert token not in app_src, f"the HTTP surface gained {token}"
    for token in ("batch_id", "batch_size", "coalesc", "merge_group"):
        assert token not in _gc4_prose_free(app_src).lower(), token


def test_gc5_diagnostics_do_not_enter_gc3_verdicts_or_sizing():
    """FP-GC5-8/9: the eight new fields are diagnostics and nothing else.

    They live in the B1 harness, travel inside the existing fingerprint, and
    appear in no product source, no GC-3 verdict or ranking input, and no
    sizing observation.
    """
    harness_src = REF_TEST.read_text(encoding="utf-8")
    harness_tree = ast.parse(harness_src)

    # (1) The field inventory is exactly these eight, in this order, declared
    # once, in the harness.
    assert _module_tuple(harness_tree, "B1_POSTGRES_COMMIT_FIELDS") == GC5_COMMIT_FIELDS
    assert _module_tuple(harness_tree, "B1_POSTGRES_COST_FIELDS") == GC4_COST_FIELDS
    assert not set(GC5_COMMIT_FIELDS) & set(GC4_COST_FIELDS)

    # (2) The stats reader is test-only: neither its symbols nor the new field
    # names occur in any production source.
    for relative, code in _gc5_product_sources():
        for symbol in GC5_STATS_SYMBOLS + GC5_COMMIT_FIELDS:
            assert symbol not in code, f"{relative} carries the test-only {symbol!r}"

    # (3) It owns its own connection to a DIFFERENT database, and builds no
    # engine and no Session.
    for opener in ("_open_postgres_stats_connection", "_open_postgres_wait_connection"):
        node = _gc4_function(harness_tree, opener)
        source = ast.get_source_segment(harness_src, node) or ""
        assert "psycopg2.connect" in source, f"{opener} does not own its connection"
        assert "maintenance_dsn(" in source, f"{opener} is not on the maintenance database"
        for forbidden in ("make_engine", "make_gateway_engine", "session_factory"):
            assert forbidden not in source, (opener, forbidden)
    maintenance = _gc4_function(harness_tree, "maintenance_database_name")
    maintenance_src = ast.get_source_segment(harness_src, maintenance) or ""
    assert "B1_MAINTENANCE_DATABASE_ALTERNATE" in maintenance_src, (
        "the reader can be pointed at the measured database when it is `postgres`"
    )
    assigns = _source_assigns(harness_src)
    assert ast.literal_eval(assigns["B1_MAINTENANCE_DATABASE"]) == GC5_MAINTENANCE_DATABASE
    assert ast.literal_eval(
        assigns["B1_MAINTENANCE_DATABASE_ALTERNATE"]
    ) == GC5_MAINTENANCE_ALTERNATE
    assert ast.literal_eval(
        assigns["B1_STATS_READER_APPLICATION_NAME"]
    ) == GC5_STATS_APPLICATION_NAME
    assert ast.literal_eval(
        assigns["B1_WAIT_SAMPLER_APPLICATION_NAME"]
    ) == GC5_SAMPLER_APPLICATION_NAME
    wait_sql = ast.literal_eval(assigns["B1_WAIT_SAMPLE_SQL"]) if isinstance(
        assigns["B1_WAIT_SAMPLE_SQL"], ast.Constant
    ) else "".join(
        ast.literal_eval(part) for part in assigns["B1_WAIT_SAMPLE_SQL"].values
    )
    # The sampler kept its application-name exclusion and now names the
    # measured database instead of inheriting it from its own connection.
    assert "coalesce(application_name, '') <> %(application_name)s" in wait_sql
    assert "datname = %(target_database)s" in wait_sql
    assert "current_database()" not in wait_sql
    for statement_name in ("B1_DATABASE_STATS_SQL", "B1_WAL_STATS_SQL"):
        statement = assigns[statement_name]
        rendered = ast.literal_eval(statement) if isinstance(
            statement, ast.Constant
        ) else "".join(ast.literal_eval(part) for part in statement.values)
        assert "current_database()" not in rendered, statement_name
        for token in ("INSERT", "UPDATE", "DELETE", "pg_stat_reset"):
            assert token not in rendered.upper(), (statement_name, token)

    # (4) No new field is a gating field, a product verdict, a GC-3 verdict or
    # a GC-3 record key, and none enters the selector's ranking.
    gating = set(_module_tuple(harness_tree, "B1_GATING_PLACEMENT_FIELDS"))
    topology_gating = set(_module_tuple(harness_tree, "B1_TOPOLOGY_GATING_PLACEMENT_FIELDS"))
    # Both full inventories are concatenations in the harness, so they are
    # rebuilt here from their two declared halves.
    placement = gating | set(
        _module_tuple(harness_tree, "B1_DIAGNOSTIC_PLACEMENT_FIELDS")
    )
    topology_placement = topology_gating | set(
        _module_tuple(harness_tree, "B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS")
    )
    product_verdicts = set(_module_tuple(harness_tree, "PRODUCT_VERDICT_FIELDS"))
    probe_src = GC5_PROBE_HELPER.read_text(encoding="utf-8")
    for field in GC5_COMMIT_FIELDS:
        assert field not in gating, field
        assert field not in topology_gating, field
        assert field not in placement, field
        assert field not in topology_placement, field
        assert field not in product_verdicts, field
        assert field not in gc3.VERDICT_FIELDS, field
        assert field not in gc3.RECORD_KEYS, field
        assert field not in probe_src, f"the GC-3 helper names {field}"

    # (5) The decision carrier is untouched by them: no key and no value
    # outside an embedded fingerprint mentions a GC-5 field.
    def _walk_json(node, key=None):
        if isinstance(node, dict):
            for name, value in node.items():
                for field in GC5_COMMIT_FIELDS:
                    assert field not in name, (name, field)
                _walk_json(value, name)
        elif isinstance(node, list):
            for value in node:
                _walk_json(value, key)
        elif isinstance(node, str) and key != "fingerprint":
            for field in GC5_COMMIT_FIELDS:
                assert field not in node, (key, field)

    _walk_json(json.loads(GC3_DECISION.read_text(encoding="utf-8")))

    # (6) No sizing carrier records them, and the ratio bar is not a sizing
    # value: the chart, the profile module and the ledger never name them.
    for parts in GC4_SIZING_CARRIERS:
        carrier = REPO_ROOT.joinpath(*parts)
        assert carrier.is_file(), parts[-1]
        text = carrier.read_text(encoding="utf-8")
        if parts[-1] in ("thresholds.yaml", "test_b1_ingest_burst.py"):
            # The manifest describes them as reported diagnostics and the
            # harness produces them; both are checked below rather than here.
            continue
        for field in GC5_COMMIT_FIELDS + (GC5_RATIO_CONSTANT,):
            assert field not in text, f"{parts[-1]} carries {field}"
    values = yaml.safe_load(GC5_VALUES_PATH.read_text(encoding="utf-8"))
    basis = yaml.safe_dump(values["ingestGateway"]["sizingBasis"])
    for field in GC5_COMMIT_FIELDS:
        assert field not in basis, field

    # (7) The manifest describes them as diagnostics, once, and names the one
    # node that consumes the ratio.
    thresholds = yaml.safe_load(GC5_THRESHOLDS.read_text(encoding="utf-8"))
    notes = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")["notes"]
    for field in GC5_COMMIT_FIELDS:
        assert field in notes, field
    assert "reported diagnostic" in notes
    assert GC5_GATE_NODE in notes, "the manifest does not name the gate node"
    assert str(GC5_MAX_COMMITS_PER_SERVED) in notes

    # (8) Only the gate node consumes the ratio; the probe route does not.
    probe_live_src = GC5_PROBE_LIVE.read_text(encoding="utf-8")
    assert GC5_RATIO_CONSTANT not in probe_live_src, (
        "the GC-3 probe route gates the GC-5 ratio"
    )
    assert "assert_complete_commit_shape_record" not in probe_live_src, (
        "a GC-5 diagnostic can void a GC-3 arm"
    )
    assert "postgres_commit_snapshot_failure" in probe_live_src, (
        "the probe route does not record the GC-5 fields at all"
    )
    # The bar is COMPARED against in exactly two places: the live gate node
    # and the serializer unit test that pins its boundary. Anywhere else the
    # constant may only be named (the recorded-context node checks that the
    # gate still compares it), never used to decide a measured value.
    ratio_comparers = []
    for node in ast.walk(harness_tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for statement in ast.walk(node):
            if not isinstance(statement, ast.Assert):
                continue
            for compare in ast.walk(statement.test):
                if not isinstance(compare, ast.Compare):
                    continue
                operands = [compare.left, *compare.comparators]
                if any(
                    isinstance(operand, ast.Name)
                    and operand.id == GC5_RATIO_CONSTANT
                    for operand in operands
                ):
                    ratio_comparers.append(node.name)
    assert GC5_GATE_NODE in ratio_comparers, ratio_comparers
    assert set(ratio_comparers) == {
        GC5_GATE_NODE,
        "test_gc5_commit_shape_fields_serialize_honestly_and_only_ratio_gates",
    }, ratio_comparers

    # ...and the bar is inclusive: a record whose ratio is exactly 0.60
    # satisfies FP-GC5-7, so the gate compares with `<=`, never `<`.
    gate = _gc4_function(harness_tree, GC5_GATE_NODE)
    gate_comparisons = [
        node for node in ast.walk(gate)
        if isinstance(node, ast.Compare)
        and any(
            isinstance(operand, ast.Name) and operand.id == GC5_RATIO_CONSTANT
            for operand in [node.left, *node.comparators]
        )
    ]
    assert len(gate_comparisons) == 1, [ast.unparse(c) for c in gate_comparisons]
    comparison = gate_comparisons[0]
    assert [type(op) for op in comparison.ops] == [ast.LtE], ast.unparse(comparison)
    assert ast.unparse(comparison.left) == "ratio", ast.unparse(comparison)
    assert ast.unparse(comparison.comparators[0]) == GC5_RATIO_CONSTANT


def test_gc5_gc3_requalification_handoff_is_head_scoped():
    """FP-GC5-10: GC-5 hands over a head; GC-3 alone decides hostability.

    Rev 0.8: the head and the status are DERIVED from the carrier, current
    decision and ordered history alike, and re-proved through local Git. GC-5
    pins neither, and its prose naming a current-head outcome is not decision
    evidence until the selector has published that head as current.
    """
    harness_src = REF_TEST.read_text(encoding="utf-8")
    thresholds = yaml.safe_load(GC5_THRESHOLDS.read_text(encoding="utf-8"))
    notes = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")["notes"]

    # (1) The carrier is unedited, fully recomputed, head-proved and published:
    # every current and superseded head appears in that model's manifest row.
    assert _gc3_handoff_provenance_failures(notes) == []
    models = json.loads(GC3_DECISION.read_text(encoding="utf-8"))["models"]
    for model in models:
        assert model in notes, model

    # (2) The manifest states what GC-5 changed, narrowly, and claims no SKU.
    assert GC5_COMMIT_SHAPE_WORDING in notes
    for claim in GC5_HOSTABILITY_CLAIMS:
        assert claim not in notes, claim

    # (3) No GC-5 node touches the carrier, the selector or a hostability
    # claim, and none of them asserts the unchanged 150 ms bar.
    harness_tree = ast.parse(harness_src)
    for node_name in (GC5_GATE_NODE, GC5_CONTEXT_NODE):
        node = _gc4_function(harness_tree, node_name)
        source = ast.get_source_segment(harness_src, node) or ""
        for forbidden in (
            "CI_SCALE_P99_MS",
            "PRODUCT_P99_MS",
            "hostable",
            "selected",
            "b1_topology_decision",
            "B1_DECISION_CARRIER",
            "evaluate_verdicts",
        ):
            assert forbidden not in source, (node_name, forbidden)
        markers = _decorator_markers(node)
        assert markers == GC5_PRODUCT_MARKERS, (node_name, markers)
    # ...and the one test that can establish the CI-scale bar is unchanged.
    ci_scale = _gc2_function(harness_tree, CI_SCALE_REF_TEST)
    observed = {
        ast.unparse(node.test) for node in ast.walk(ci_scale) if isinstance(node, ast.Assert)
    }
    assert not GC2_CI_SCALE_REQUIRED_ASSERTIONS - observed

    # (4) The probe route still writes every arm, and the GC-5 fields cannot
    # stop it: the shared validator it calls owns no GC-5 rule.
    probe_live_src = GC5_PROBE_LIVE.read_text(encoding="utf-8")
    node = next(
        n for n in ast.walk(ast.parse(probe_live_src))
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_b1_ci_scale_topology_probe_record"
    )
    statements = node.body
    validator_at = next(
        i for i, stmt in enumerate(statements)
        if "assert_complete_postgres_cost_record" in ast.unparse(stmt)
    )
    write_at = next(
        i for i, stmt in enumerate(statements)
        if "write_probe_arm_record" in ast.unparse(stmt)
    )
    assert validator_at < write_at
    for stmt in statements[validator_at:write_at]:
        rendered = ast.unparse(stmt)
        for escape in ("return", "raise", "pytest.skip", "if "):
            assert escape not in rendered, rendered
    validator = _gc4_function(ast.parse(harness_src), "postgres_cost_record_failures")
    validator_src = ast.get_source_segment(harness_src, validator) or ""
    for forbidden in ("postgres_commit", "xact_commit", "wal_"):
        assert forbidden not in validator_src, forbidden


# ---------------------------------------------------------------------------
# B1-LATENCY-BASIS-1 — the isolated CPU-basis oracle, the resolved basis
# handoff, and this slice's fixed scope.
#
# Every literal below is declared here, independently of the files it pins.
# What this slice adds is ONE explicit target and ONE closed ledger schema; the
# thing it must never do is change the ordinary CI-scale gate, so the ordinary
# selections, the workload, the placement and the frozen knobs are all pinned
# byte for byte alongside the new surface.
# ---------------------------------------------------------------------------
B1LB_LEDGER_MODULE = REPO_ROOT / "tests" / "delivery" / "test_delivery_sizing_ledger.py"
B1LB_VALUES = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
B1LB_THRESHOLDS = REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml"
B1LB_TARGET = "b1_latency_basis"
B1LB_WRAPPER = "bash scripts/integration-test.sh b1_latency_basis"
B1LB_CONDITION = (
    "github.event_name == 'workflow_dispatch' && inputs.b1_latency_basis == true"
)
B1LB_LIVE_DRIVER = 'b1_run_driver driver-latency-basis.sh "$driver_cpus"'
B1LB_ORDINARY_LIVE_DRIVER = 'b1_run_driver driver-live.sh "$driver_cpus"'
B1LB_COVERAGE_DRIVER = 'b1_run_driver driver-coverage.sh "${cpus[0]}"'
#: The two fail-closed CLI preconditions, exactly as §3.6 fixes them.
B1LB_PREFLIGHT_CALL = (
    '"$REPO_ROOT/services/worker/.venv/bin/python" '
    '"$REPO_ROOT/tests/delivery/test_delivery_sizing_ledger.py" basis-oracle-preflight '
    '--values "$REPO_ROOT/deploy/charts/dbagent/values.yaml" '
    '--decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json"'
)
B1LB_ROUTE_CALL = (
    '"$REPO_ROOT/services/worker/.venv/bin/python" '
    '"$REPO_ROOT/tests/delivery/test_delivery_sizing_ledger.py" basis-oracle-route '
    '--values "$REPO_ROOT/deploy/charts/dbagent/values.yaml" '
    '--decision "$REPO_ROOT/tests/benchmark/b1_topology_decision.json" '
    '--route "$B1_ROUTE_RECORD"'
)
B1LB_UNOBSERVED_PREFIX = "basis_oracle_unobserved:"
B1LB_UNOBSERVED_EXIT = 3
#: The frozen surfaces this slice may not have moved (FP-B1LB-8).
B1LB_FROZEN_LAUNCHER_CLAUSES = (
    "-m 'not b1_live and not b1_product and not b1_latency_basis and not b1_topology_probe'",
    "-m 'b1_live and not b1_product and not b1_latency_basis and not b1_topology_probe'",
    "-m b1_product",
    "-m b1_topology_probe",
)
B1LB_ESCAPES = GC3_WEAKENINGS

b1lb = _load(B1LB_LEDGER_MODULE, "b1lb_sizing_ledger_profile")


#: One shell target's body, under the name this section's checks call it by.
#: The same single definition as `_b1_target_region` above; it was a third
#: verbatim copy of that body until review-followups-batch-20260920 W1.
_b1lb_region = _manifests._b1_target_region


def _b1lb_target_failures(launcher: str, workflow: dict) -> list[str]:
    """FP-B1LB-6/8: the isolated target exists, is isolated, and fails closed."""
    fails: list[str] = []

    def add(reason: str, detail: str = "") -> None:
        fails.append(f"{reason}{(' ' + detail) if detail else ''}")

    region = _b1lb_region(launcher, B1LB_TARGET)
    ordinary = _b1lb_region(launcher, "b1")
    if not region:
        add("latency_basis_target_missing")
        return fails
    if B1LB_LIVE_DRIVER not in region:
        add("latency_basis_target_missing", "no live driver line")
    if B1LB_COVERAGE_DRIVER not in region:
        add("latency_basis_target_missing", "no container-free coverage phase")
    if GC3_PRODUCER_REL not in region:
        add("latency_basis_target_missing", "collects no producer")

    # The selection: exactly once, only here, and the four GC-3 ones untouched.
    if region.count(GC3_LATENCY_BASIS_SELECTION) != 1:
        add("latency_basis_selection_missing",
            f"{region.count(GC3_LATENCY_BASIS_SELECTION)} in the isolated target")
    if launcher.count(GC3_LATENCY_BASIS_SELECTION) != 1:
        add("latency_basis_selection_missing",
            f"{launcher.count(GC3_LATENCY_BASIS_SELECTION)} in the whole script")
    if GC3_LATENCY_BASIS_SELECTION in ordinary:
        add("latency_basis_selection_leaked_to_ordinary_b1", "selection")
    if B1LB_LIVE_DRIVER in ordinary:
        add("latency_basis_selection_leaked_to_ordinary_b1", "driver line")
    # Ordinary `b1` never calls either fail-closed entry point: the merge gate
    # must not acquire a dependency on the sizing ledger's recorded state.
    for other in ("b1", "b1_product", "b1_topology_probe", "b1_topology_probe_arm"):
        if "basis-oracle-" in _b1lb_region(launcher, other):
            add("latency_basis_selection_leaked_to_ordinary_b1", f"entry point in {other}")
    for command in ("basis-oracle-preflight", "basis-oracle-route"):
        if launcher.count(command) != 1:
            add("latency_basis_selection_leaked_to_ordinary_b1",
                f"{launcher.count(command)} x {command}")
    for literal in B1LB_FROZEN_LAUNCHER_CLAUSES:
        if literal not in launcher:
            add("ordinary_selection_drift", literal)
    if launcher.count(GC3_LIVE_SELECTION) != 1 or GC3_LIVE_SELECTION not in ordinary:
        add("ordinary_selection_drift", "the ordinary CI-scale live selection moved")
    if launcher.count(GC3_COVERAGE_SELECTION) != 1:
        add("ordinary_selection_drift", "the container-free coverage selection moved")

    # Fail closed, in order: ledger before any container, identity after the
    # route and before pair discovery or a live fixture.
    if B1LB_PREFLIGHT_CALL not in region:
        add("latency_basis_preflight_missing")
    if B1LB_ROUTE_CALL not in region:
        add("latency_basis_route_check_missing")
    positions = {
        "preflight": region.find(B1LB_PREFLIGHT_CALL),
        "prepare": region.find("b1_prepare || return 1"),
        "route_fields": region.find('route-fields --route "$B1_ROUTE_RECORD"'),
        "route_check": region.find(B1LB_ROUTE_CALL),
        "pairs": region.find("b1_complete_sibling_pairs"),
        "live": region.find(B1LB_LIVE_DRIVER),
    }
    if any(value < 0 for value in positions.values()):
        add("latency_basis_precondition_order_drift", str(positions))
    elif not (
        positions["preflight"] < positions["prepare"] < positions["route_fields"]
        < positions["route_check"] < positions["pairs"] < positions["live"]
    ):
        add("latency_basis_precondition_order_drift", str(positions))

    # Same container ownership and the same verified cleanup as the ordinary
    # route: a second live B1 run may not leave containers or a run directory.
    # The exact post-live stanza, as one literal: "b1_cleanup appears
    # somewhere" would survive removing the one that matters, since every
    # early-return path calls it too.
    for clause in (
        B1LB_LIVE_DRIVER + "\n  rc=$?\n  b1_cleanup\n  trap - EXIT TERM INT\n",
        'if [ "$B1_CLEANUP_FAILED" -ne 0 ] || [ "$B1_RUN_DIR_FAILED" -ne 0 ]; then return 1; fi',
    ):
        if clause not in region:
            add("latency_basis_cleanup_missing", repr(clause[:48]))
    for escape in B1LB_ESCAPES:
        if escape in region:
            add("latency_basis_escape_hatch", escape)

    # Absent from `all` and from every default CI route.
    all_case = launcher.split("  all)", 1)[1].split(";;", 1)[0]
    if B1LB_TARGET in all_case:
        add("latency_basis_in_default_route", "all")
    jobs = (workflow.get("jobs") or {})
    for job_name, job in jobs.items():
        for index, step in enumerate((job.get("steps") or [])):
            body = (step.get("run") or "").strip()
            if B1LB_TARGET not in body:
                continue
            if job_name != "benchmark":
                add("latency_basis_in_default_route", f"{job_name}[{index}]")
                continue
            if body != B1LB_WRAPPER:
                add("latency_basis_in_default_route", f"body {body!r}")
            if (step.get("if") or "").strip() != B1LB_CONDITION:
                add("latency_basis_in_default_route", f"condition {step.get('if')!r}")
    return fails


def _b1lb_run_cli(*args, cwd=None) -> subprocess.CompletedProcess:
    import sys as _sys

    return subprocess.run(
        [_sys.executable, str(B1LB_LEDGER_MODULE), *args],
        capture_output=True, text=True, check=False,
    )


def _b1lb_values_file(tmp_path, ig: dict, name: str = "values.yaml"):
    path = tmp_path / name
    path.write_text(yaml.safe_dump({"ingestGateway": ig}), encoding="utf-8")
    return path


def test_b1_latency_basis_target_is_isolated_and_fail_closed(tmp_path):
    """FP-B1LB-6: one explicit target, isolated from the gate, failing closed.

    Two legs. The launcher/workflow surface says the target exists, carries the
    explicit selection exactly once, leaves the four GC-3 selections byte-exact,
    runs both preconditions in the fixed order and is absent from `all` and
    from every default CI route. The CLI leg then EXERCISES the preconditions
    and requires the documented `basis_oracle_unobserved:<reason>` on stderr
    with exit 3 -- not a skip, not a zero, and not an ordinary error.

    PB-C1: `ledger_unrecorded` is BY CONSTRUCTION the verdict for a carrier
    with no observations and no attempts, so directing it at the shipped
    `values.yaml` asserted that the coordinator had not recorded anything yet.
    That is unsatisfiable for every qualified ledger, whatever it measured, so
    the unrecorded leg now runs against an ephemeral empty carrier under
    tmp_path and the shipped carrier is no longer asserted empty. All three
    preflight verdicts stay failure-producing, as the named controls below.
    """
    launcher = GC3_LAUNCHER.read_text(encoding="utf-8")
    workflow = yaml.safe_load(GC3_CI_YML.read_text(encoding="utf-8"))
    assert _b1lb_target_failures(launcher, workflow) == []

    def _preflight(path):
        return _b1lb_run_cli(
            "basis-oracle-preflight",
            "--values", str(path),
            "--decision", str(GC3_DECISION),
        )

    # Control `qualified_preflight_returns_zero`. Preflight PASSES on a
    # qualified carrier, and the costs are not what it reads: two different
    # valid cost vectors give the same verdict. This is exactly why the
    # pre-correction `returncode == 3` on the shipped file could not survive
    # any recording, and it is decided without consulting a measured value.
    for label, costs in (("fixture", None), ("other", (2.0, 2.5, 3.0, 2.25, 2.75))):
        qualified = _b1lb_values_file(
            tmp_path, b1lb._filled_ledger(cpu_vals=costs), f"qualified-{label}.yaml"
        )
        result = _preflight(qualified)
        assert result.returncode == 0, (label, result)
        assert (result.stdout, result.stderr) == ("", ""), (label, result)

    # Control `empty_preflight_returns_ledger_unrecorded`. The exact exit and
    # the exact reason, on a carrier that is empty by construction: the
    # qualified builder with exactly `observations = []` and
    # `collection.attempts = []`, and nothing else changed.
    empty = b1lb._filled_ledger()
    empty["sizingBasis"]["observations"] = []
    empty["sizingBasis"]["collection"]["attempts"] = []
    result = _preflight(_b1lb_values_file(tmp_path, empty, "unrecorded.yaml"))
    assert result.returncode == B1LB_UNOBSERVED_EXIT, result
    assert result.stderr.strip() == f"{B1LB_UNOBSERVED_PREFIX}ledger_unrecorded", result.stderr
    assert result.stdout == "", result.stdout

    # Control `invalid_nonempty_preflight_returns_ledger_invalid`. A non-empty
    # but broken carrier is a DIFFERENT reason, so nothing invalid can reach
    # the unrecorded branch and be read as "not collected yet".
    broken = b1lb._filled_ledger(
        mutate=lambda ig: ig["sizingBasis"]["observations"][0].__setitem__("errors", 1)
    )
    result = _preflight(_b1lb_values_file(tmp_path, broken, "invalid.yaml"))
    assert result.returncode == B1LB_UNOBSERVED_EXIT, result
    assert result.stderr.strip() == f"{B1LB_UNOBSERVED_PREFIX}ledger_invalid", result.stderr
    assert result.stdout == "", result.stdout

    # Ordinary CLI misuse keeps an ordinary status and never looks unobserved.
    misuse = _b1lb_run_cli("basis-oracle-preflight", "--values", str(B1LB_VALUES))
    assert misuse.returncode not in (0, B1LB_UNOBSERVED_EXIT), misuse
    assert B1LB_UNOBSERVED_PREFIX not in misuse.stderr


def test_b1_latency_basis_preconditions_reject_every_unobservable_route(tmp_path):
    """FP-B1LB-6: each unobservable route reports ITS OWN reason, and exits 3.

    The qualified fixture is synthetic and never enters values.yaml; it exists
    only to reach the route branch, which an unrecorded ledger cannot.
    """
    qualified = b1lb._filled_ledger()
    values = _b1lb_values_file(tmp_path, qualified)
    signature = qualified["sizingBasis"]["signature"]

    def _preflight(path):
        return _b1lb_run_cli(
            "basis-oracle-preflight", "--values", str(path), "--decision", str(GC3_DECISION)
        )

    def _route(path, route_path):
        return _b1lb_run_cli(
            "basis-oracle-route", "--values", str(path), "--decision", str(GC3_DECISION),
            "--route", str(route_path),
        )

    assert _preflight(values).returncode == 0, _preflight(values)

    # An invalid, non-empty ledger is a DIFFERENT reason from an unrecorded one.
    broken = b1lb._filled_ledger(
        mutate=lambda ig: ig["sizingBasis"]["observations"][0].__setitem__("errors", 1)
    )
    broken_values = _b1lb_values_file(tmp_path, broken, "broken.yaml")
    result = _preflight(broken_values)
    assert result.returncode == B1LB_UNOBSERVED_EXIT, result
    assert result.stderr.strip() == f"{B1LB_UNOBSERVED_PREFIX}ledger_invalid", result.stderr

    def _write_route(name, record):
        path = tmp_path / name
        path.write_text(json.dumps(record), encoding="utf-8")
        return path

    decision = json.loads(GC3_DECISION.read_text(encoding="utf-8"))
    matching = gc3.route_host(GC3_DECISION, cpu_model=signature["cpuModel"])
    assert matching["disposition"] == gc3.ROUTE_GATING, matching
    ok = _route(values, _write_route("route-ok.json", matching))
    assert ok.returncode == 0, ok
    assert ok.stdout == "" and ok.stderr == "", ok

    # A recorded GC-3 route reports the canonical route reason, unchanged.
    unhostable = next(
        model for model, entry in decision["models"].items()
        if entry.get("status") == "unhostable"
    )
    recorded = gc3.route_host(GC3_DECISION, cpu_model=unhostable)
    assert recorded["disposition"] == gc3.ROUTE_RECORDED, recorded
    result = _route(values, _write_route("route-recorded.json", recorded))
    assert result.returncode == B1LB_UNOBSERVED_EXIT, result
    assert result.stderr.strip() == B1LB_UNOBSERVED_PREFIX + recorded["reason"], result.stderr

    # A gating route on another identity is a NAMED signature mismatch.
    other_topology = next(
        t for t in gc3.TOPOLOGY_IDS if t != signature["referenceTopology"]
    )
    for field, key, replacement, expected in (
        ("cpuModel", "cpuModel", "Other Vendor CPU @ 0.00GHz", "cpuModel"),
        ("topology", "topology", other_topology, "referenceTopology"),
    ):
        mutated = dict(matching)
        mutated[key] = replacement
        if key == "topology":
            # Keep the record VALID: only the identity may differ, or the CLI
            # would report an unusable route instead of a signature mismatch.
            mutated["cardinality"] = gc3.topology_cardinality(replacement)
        result = _route(values, _write_route(f"route-{field}.json", mutated))
        assert result.returncode == B1LB_UNOBSERVED_EXIT, (field, result)
        assert result.stderr.strip() == (
            f"{B1LB_UNOBSERVED_PREFIX}signature_mismatch:{expected}"
        ), (field, result.stderr)

    # The remaining two route-visible identity fields cannot be expressed by a
    # VALID route record on the current carrier -- the route schema pins
    # placementSchema and the decision head is read from that same carrier --
    # so they are proved on the pure comparison the CLI delegates to. Defence
    # in depth is exactly what they are for; they are not dropped.
    identity = b1lb.gc3_selected_identity(b1lb.load_gc3_decision(GC3_DECISION))
    assert b1lb.route_signature_mismatch(signature, matching, identity) == []
    assert b1lb.route_signature_mismatch(
        {**signature, "placementSchema": 2}, matching, identity
    ) == ["placementSchema"]
    assert b1lb.route_signature_mismatch(
        {**signature, "topologyDecisionHeadSha": "f" * 40}, matching, identity
    ) == ["topologyDecisionHeadSha"]
    assert b1lb.route_signature_mismatch(
        {**signature, "cpuModel": "x", "referenceTopology": "y"}, matching, identity
    ) == ["cpuModel", "referenceTopology"]

    # An unusable route record is an ordinary failure, never an unobserved one.
    garbage = tmp_path / "route-garbage.json"
    garbage.write_text("{not json", encoding="utf-8")
    result = _route(values, garbage)
    assert result.returncode not in (0, B1LB_UNOBSERVED_EXIT), result
    assert B1LB_UNOBSERVED_PREFIX not in result.stderr


def test_b1_latency_basis_target_mutations_are_rejected():
    """FP-B1LB-6/8: one mutation per named cause, each independently red."""
    launcher = GC3_LAUNCHER.read_text(encoding="utf-8")
    workflow = yaml.safe_load(GC3_CI_YML.read_text(encoding="utf-8"))
    assert _b1lb_target_failures(launcher, workflow) == [], "positive control"

    def _expect(name, *, mutate_launcher=None, mutate_workflow=None):
        import copy as _copy

        mutated_launcher = mutate_launcher(launcher) if mutate_launcher else launcher
        mutated_workflow = _copy.deepcopy(workflow)
        if mutate_workflow:
            mutate_workflow(mutated_workflow)
        if mutate_launcher:
            assert mutated_launcher != launcher, f"{name}: launcher mutation was a no-op"
        if mutate_workflow:
            assert mutated_workflow != workflow, f"{name}: workflow mutation was a no-op"
        fails = _b1lb_target_failures(mutated_launcher, mutated_workflow)
        assert any(f.split(" ", 1)[0] == name for f in fails), (name, fails)

    _expect(
        "latency_basis_target_missing",
        mutate_launcher=lambda src: src.replace("\n" + B1LB_TARGET + "() {\n", "\nb1_retired() {\n", 1),
    )
    _expect(
        "latency_basis_selection_missing",
        mutate_launcher=lambda src: src.replace(GC3_LATENCY_BASIS_SELECTION, "-m b1_live", 1),
    )
    _expect(
        "latency_basis_selection_leaked_to_ordinary_b1",
        mutate_launcher=lambda src: src.replace(
            GC3_LIVE_SELECTION, GC3_LATENCY_BASIS_SELECTION, 1
        ),
    )
    _expect(
        "ordinary_selection_drift",
        mutate_launcher=lambda src: src.replace(
            GC3_COVERAGE_SELECTION, "-m 'not b1_live and not b1_product'", 1
        ),
    )
    _expect(
        "latency_basis_selection_leaked_to_ordinary_b1",
        mutate_launcher=lambda src: src.replace(
            "  b1_prepare || return 1\n  b1_write_coverage_driver\n",
            "  " + B1LB_PREFLIGHT_CALL + "\n  b1_prepare || return 1\n"
            "  b1_write_coverage_driver\n", 1),
    )
    _expect(
        "latency_basis_preflight_missing",
        mutate_launcher=lambda src: src.replace(B1LB_PREFLIGHT_CALL, "true", 1),
    )
    _expect(
        "latency_basis_route_check_missing",
        mutate_launcher=lambda src: src.replace(B1LB_ROUTE_CALL, "true", 1),
    )
    _expect(
        "latency_basis_precondition_order_drift",
        mutate_launcher=lambda src: src.replace(
            "  " + B1LB_PREFLIGHT_CALL + "\n", "", 1
        ).replace(
            "  " + B1LB_LIVE_DRIVER + "\n",
            "  " + B1LB_PREFLIGHT_CALL + "\n  " + B1LB_LIVE_DRIVER + "\n", 1
        ),
    )
    _expect(
        "latency_basis_cleanup_missing",
        mutate_launcher=lambda src: src.replace(
            '  b1_run_driver driver-latency-basis.sh "$driver_cpus"\n  rc=$?\n  b1_cleanup\n',
            '  b1_run_driver driver-latency-basis.sh "$driver_cpus"\n  rc=$?\n', 1),
    )
    _expect(
        "latency_basis_escape_hatch",
        mutate_launcher=lambda src: src.replace(
            '  b1_run_driver driver-latency-basis.sh "$driver_cpus"\n',
            '  b1_run_driver driver-latency-basis.sh "$driver_cpus" || true\n', 1),
    )
    _expect(
        "latency_basis_in_default_route",
        mutate_workflow=lambda wf: wf["jobs"]["benchmark"]["steps"][-1].pop("if"),
    )
    _expect(
        "latency_basis_in_default_route",
        mutate_workflow=lambda wf: wf["jobs"]["e2e"]["steps"].append(
            {"run": B1LB_WRAPPER}
        ),
    )
    _expect(
        "latency_basis_in_default_route",
        mutate_launcher=lambda src: src.replace(
            '             run_step "B1 product promise (recorded, non-gating)" b1_product ;;',
            '             run_step "B1 product promise (recorded, non-gating)" b1_product\n'
            '             run_step "B1 CPU-basis oracle" b1_latency_basis ;;', 1),
    )


def test_gc1_gc2_gc3_gc4_gc5_basis_handoffs_route_to_the_qualified_ledger():
    """FP-B1LB-7: every stale empty/2.427 handoff pin is retired, once.

    The five earlier slices deferred the CPU basis to this one. Each of them
    used to hold the void in place by asserting `observations == []` or the
    literal 2.427 -- which would make the collection this slice exists to
    perform fail in five places at once, for one fact. They now route to
    FP-IG-23's single actual-state gate instead. This is checked from the
    SOURCE of those tests, so a reintroduced pin is caught even when the
    ledger happens to still be empty.
    """
    source = Path(__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    retired_owners = (
        "test_gc1_preserves_and_routes_unqualified_cpu_basis",
        "test_gc2_write_path_scope_and_fixed_bar_are_pinned",
        "test_gc3_reference_topology_scope_and_decision_are_pinned",
        "test_gc4_fixed_bars_and_sizing_boundaries_are_pinned",
        "test_gc5_fixed_workload_pool_schema_and_sizing_boundaries",
    )
    functions = {
        node.name: node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in retired_owners:
        assert name in functions, f"{name} is missing; the handoff owner moved"

    # Every assertion reachable from those owners, plus the helpers the GC-3
    # and GC-5 owners delegate to, must be free of the two retired pins.
    helper_names = ("_gc3_scope_failures", "_gc3_route_surface_failures")
    rendered: list[str] = []
    for name in retired_owners + helper_names:
        node = functions.get(name)
        assert node is not None, name
        for child in ast.walk(node):
            if isinstance(child, ast.Assert):
                rendered.append(ast.unparse(child.test))
            elif isinstance(child, ast.Compare):
                rendered.append(ast.unparse(child))
    for text in rendered:
        assert "2.427" not in text, f"a retired 2.427 pin survives: {text}"
        assert "GC1_BASIS_MS_PER_REQUEST" not in text, text
        assert "GC4_BASIS_MS_PER_REQUEST" not in text, text
        assert "GC5_BASIS_MS_PER_REQUEST" not in text, text
        assert "['observations'] == []" not in text, (
            f"a retired empty-ledger pin survives: {text}"
        )

    # ...and exactly one owner still rejects the void: the FP-IG-23 gate.
    ledger_src = B1LB_LEDGER_MODULE.read_text(encoding="utf-8")
    assert (
        "def test_sizing_basis_provenance_is_on_reference_and_from_a_serving_run(" in ledger_src
    )
    assert "want exactly five observations, got" in ledger_src

    # The handoff is ROUTED, not merely dropped: the owner and the gate are
    # both named in the manifest the five slices share.
    thresholds = yaml.safe_load(B1LB_THRESHOLDS.read_text(encoding="utf-8"))
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    assert GC1_BASIS_OWNER in b1_entry["notes"]
    assert GC1_BASIS_GATE in b1_entry["notes"]
    assert "2.427" not in b1_entry["notes"], "the notes state a basis number again"

    # The two FP-IG-18 carriers keep their names, markers and comparison.
    ref_src = REF_TEST.read_text(encoding="utf-8")
    basis_fn = next(
        n for n in ast.parse(ref_src).body
        if isinstance(n, ast.FunctionDef) and n.name == GC1_PRESERVED_ORACLES[0]
    )
    body = ast.get_source_segment(ref_src, basis_fn) or ""
    assert "assert measured <= basis" in body
    assert "b1_latency_basis" in _decorator_markers(basis_fn)


def test_prior_slice_sizing_exclusions_survive_qualified_ledger():
    """FP-B1LB-7/8: the older slices' real boundaries survive the migration.

    Retiring the empty/2.427 pins must not retire what those slices actually
    own: their own investigation numbers and run ids stay inadmissible as
    sizing observations, and a topology-probe arm or a product-local run can
    still never become one. Proved against a POPULATED synthetic ledger, which
    is exactly the state the retired pins could not express.
    """
    qualified = b1lb._filled_ledger()
    b1lb.validate_sizing_ledger(qualified, check_rendered_cpu=False)
    signature = qualified["sizingBasis"]["signature"]

    # (1) Ineligible authorities and profiles, on a ledger that is otherwise
    # complete: the probe arms and the product-local tier are not this
    # warrant's population, whatever they measured.
    for field, value in (
        ("measurementAuthority", "product-local-reference"),
        ("measurementAuthority", "local-replica"),
        ("profile", "product-exclusive"),
        ("profile", gc3.PROBE_PROFILE_NAME),
    ):
        candidate = b1lb._filled_ledger(
            mutate=lambda ig, f=field, v=value: ig["sizingBasis"]["observations"][0]
            .__setitem__(f, v)
        )
        with pytest.raises(AssertionError):
            b1lb.validate_sizing_ledger(candidate, check_rendered_cpu=False)

    # (2) A product-scale row cannot be re-encoded under the restated point.
    product_row = b1lb._filled_ledger(
        mutate=lambda ig: ig["sizingBasis"]["observations"][0].update(
            {"offered": 30000, "served": 30000, "committed": 30000, "servedRate": 999.0}
        )
    )
    with pytest.raises(AssertionError):
        b1lb.validate_sizing_ledger(product_row, check_rendered_cpu=False)

    # (3) The earlier slices' own diagnostic values and run ids are still
    # absent from every sizing carrier -- INCLUDING the synthetic fixtures in
    # the ledger module, which is where a convenient copy would land first.
    forbidden = (
        GC2_INVESTIGATION_CPU_MS, GC2_INVESTIGATION_RUN_ID,
        GC3_RCA_POSTGRES_MS, GC3_RCA_GATEWAY_MS, GC3_RCA_RUN_ID,
    ) + GC4_RCA_DIAGNOSTICS
    for parts in GC4_SIZING_CARRIERS:
        carrier = REPO_ROOT.joinpath(*parts)
        assert carrier.is_file(), parts[-1]
        text = carrier.read_text(encoding="utf-8")
        for value in forbidden:
            assert value not in text, f"{parts[-1]} carries {value}"

    # (4) The shipped ledger carries no synthetic fixture value either: the
    # fixtures are mutation operands, never recorded evidence.
    #
    # PB-C2/PB-C3: by EXACT field and EXACT identity token, after the carrier
    # has been validated -- never by searching dumped YAML. The dump search was
    # wrong in two ways, both provable on fabricated qualified input and
    # neither dependent on any measured value. `signature["cpuModel"] not in
    # rendered` cannot hold for ANY qualified ledger, because the signature
    # model IS GC-3's one selected model and every row repeats it; and
    # `"11/1" not in rendered` fires on any real GitHub identity that merely
    # CONTAINS a fixture identity as a proper substring. Exactness restores
    # what the pins were for: a fixture value, not a value spelled like one.
    # `FIXTURE_OTHER_TOPOLOGY` is deliberately not an operand -- its value is a
    # real GC-3 topology, so a legitimately selected ledger could carry it.
    def _fixture_leak_check(ig: dict) -> list[str]:
        """Which synthetic fixture operands this ledger carries, fail-closed.

        Validation runs FIRST and raises: an unrecorded or invalid carrier
        never receives the vacuous "nothing leaked" verdict a token scan would
        hand it. A sub-assertion construct of this test only.
        """
        sb = b1lb.require_ledger_shape(ig)
        if sb["observations"] == [] and sb["collection"]["attempts"] == []:
            raise AssertionError(
                "ledger_unrecorded: an empty carrier gets no leak verdict"
            )
        b1lb.validate_sizing_ledger(ig, check_rendered_cpu=False)
        carriers = [("signature", None, sb["signature"])]
        carriers += [("observations", i, r) for i, r in enumerate(sb["observations"])]
        carriers += [
            ("attempts", i, r) for i, r in enumerate(sb["collection"]["attempts"])
        ]
        leaks = []
        for field, token in (
            ("headSha", b1lb.FIXTURE_HEAD_SHA),
            ("image", b1lb.FIXTURE_IMAGE),
            ("cpuModel", b1lb.FIXTURE_OTHER_MODEL),
        ):
            for where, index, row in carriers:
                if field in row and row[field] == token:
                    leaks.append(
                        f"{where}.{field}" if index is None
                        else f"{where}[{index}].{field}"
                    )
        shipped_ids = {row["runId"] for row in sb["observations"]}
        shipped_ids |= {row["runId"] for row in sb["collection"]["attempts"]}
        leaks += [
            f"runId:{value}"
            for value in sorted(shipped_ids & set(b1lb.FIXTURE_RUN_IDS))
        ]
        return sorted(leaks)

    shipped_ig = yaml.safe_load(B1LB_VALUES.read_text(encoding="utf-8"))["ingestGateway"]
    assert _fixture_leak_check(shipped_ig) == []
    identity = b1lb.gc3_selected_identity(b1lb.load_gc3_decision(GC3_DECISION))
    assert shipped_ig["sizingBasis"]["signature"]["cpuModel"] == identity["cpuModel"], (
        "the shipped signature must name GC-3's one current selected model"
    )

    # Control `qualified_selected_model_is_expected`: the deleted assertion,
    # applied to a structurally valid ledger. It is red for EVERY qualified
    # ledger -- the fixture, like any recording, correctly carries the selected
    # model -- so it was unsatisfiable rather than strict.
    assert signature["cpuModel"] == identity["cpuModel"]
    assert signature["cpuModel"] in yaml.safe_dump(qualified["sizingBasis"]), (
        "the deleted `cpuModel not in rendered` assertion would have to hold here"
    )

    # Controls `synthetic_signature_exact_token_leak_is_rejected` and
    # `synthetic_run_id_exact_token_leak_is_rejected`: the untouched synthetic
    # ledger IS the leak, and every named operand it carries is named back.
    fixture_leaks = _fixture_leak_check(qualified)
    assert "signature.headSha" in fixture_leaks, fixture_leaks
    assert "signature.image" in fixture_leaks, fixture_leaks
    assert [f"runId:{value}" for value in b1lb.FIXTURE_RUN_IDS] == [
        leak for leak in fixture_leaks if leak.startswith("runId:")
    ], fixture_leaks

    # ...including the one operand a ledger can still carry while remaining
    # fully VALID: a discarded attempt for a model GC-3 never ratified. Exact
    # field equality finds it; validity alone would not.
    hidden = b1lb._filled_ledger(
        mutate=lambda ig: ig["sizingBasis"]["collection"]["attempts"].insert(
            1,
            {
                "runId": "12/1",
                "headSha": b1lb.FIXTURE_HEAD_SHA,
                "cpuModel": b1lb.FIXTURE_OTHER_MODEL,
                "decisionState": b1lb.STATE_UNHOSTABLE,
                "outcome": b1lb.OUTCOME_DISCARDED,
                "reason": (
                    f"{gc3.ROUTE_UNRATIFIED_REASON_PREFIX}{b1lb.FIXTURE_OTHER_MODEL}"
                ),
            },
        )
    )
    b1lb.validate_sizing_ledger(hidden, check_rendered_cpu=False)
    assert "attempts[1].cpuModel" in _fixture_leak_check(hidden)

    # Control `substring_collision_qualified_ledger_control`: a fully
    # production-shaped qualified ledger whose first identity contains the
    # fixture identity `11/1` ONLY as a proper substring. It validates; the
    # deleted substring scan is red on it; the exact-token check is green.
    # These identities, head and image are fabricated for this control, exist
    # nowhere but here, and are not any collected run.
    collision_ids = (
        "30000000011/1", "30000000123/1", "30000000456/1",
        "30000000789/1", "30000000999/1",
    )
    assert b1lb.FIXTURE_RUN_IDS[0] in collision_ids[0]
    assert b1lb.FIXTURE_RUN_IDS[0] != collision_ids[0]
    assert set(collision_ids).isdisjoint(b1lb.FIXTURE_RUN_IDS)
    production_signature = b1lb._fixture_signature(
        headSha="a" * 40, image="os-release:abcdef0123456789"
    )

    def _production_identities(ig):
        sb = ig["sizingBasis"]
        for row, run_id in zip(sb["observations"], collision_ids):
            row["runId"] = run_id
        for row, run_id in zip(sb["collection"]["attempts"], collision_ids):
            row["runId"] = run_id

    def _production_ledger(mutate=None):
        def _mutate(ig):
            _production_identities(ig)
            if mutate:
                mutate(ig)
        return b1lb._filled_ledger(signature=production_signature, mutate=_mutate)

    collision = _production_ledger()
    b1lb.validate_sizing_ledger(collision, check_rendered_cpu=False)
    assert b1lb.FIXTURE_RUN_IDS[0] in yaml.safe_dump(collision["sizingBasis"]), (
        "the deleted substring scan is red on a ledger holding no fixture identity"
    )
    assert _fixture_leak_check(collision) == []

    # Shared controls `fixture_leak_check_rejects_unrecorded` and
    # `fixture_leak_check_rejects_invalid`: validation FIRST, fail closed.
    # Both inputs below would score a clean `[]` under a token scan, so a check
    # that returned a verdict for either would certify nothing.
    unrecorded = _production_ledger()
    unrecorded["sizingBasis"]["observations"] = []
    unrecorded["sizingBasis"]["collection"]["attempts"] = []
    with pytest.raises(AssertionError, match="ledger_unrecorded"):
        _fixture_leak_check(unrecorded)
    invalid = _production_ledger(
        mutate=lambda ig: ig["sizingBasis"]["observations"][0].__setitem__("errors", 1)
    )
    with pytest.raises(AssertionError, match=r"observations\[0\]\.errors"):
        _fixture_leak_check(invalid)


def test_b1_latency_basis_scope_and_frozen_knobs_are_pinned():
    """FP-B1LB-8: sizing only. Every excluded surface is checked here.

    This slice adds one explicit target, one closed ledger schema and one
    manual CI step. It changes no workload, no concurrency, no pool, no
    durability setting, no write path, no topology decision, no public API and
    no product source at all -- and none of its own text claims hostability or
    predicts product capacity.
    """
    launcher = GC3_LAUNCHER.read_text(encoding="utf-8")
    harness = REF_TEST.read_text(encoding="utf-8")
    profile_src = REF_PATH.read_text(encoding="utf-8")
    main_src = GC2_MAIN_PATH.read_text(encoding="utf-8")
    session_src = GC2_SESSION_PATH.read_text(encoding="utf-8")
    ingest_src = GC2_INGEST_PATH.read_text(encoding="utf-8")

    # (1) The unchanged CI-scale bar and workload, from the profile module.
    profile_assigns = _module_assigns(REF_PATH)
    for name, expected in GC2_FIXED_CI_SCALE_LITERALS.items():
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    assert "MAX_IN_FLIGHT = BURST_RATE" in profile_src
    harness_assigns = _source_assigns(harness)
    for name, expected in (
        ("CI_SCALE_P99_MS", 150.0),
        ("CI_SCALE_SUSTAINED_FLOOR", 450),
        ("CI_SCALE_MAX_IN_FLIGHT", 500),
        ("CI_SCALE_TOTAL_REQUESTS", 15000),
    ):
        assert ast.literal_eval(harness_assigns[name]) == expected, name

    # (2) Concurrency, pools, threadpool, engine and durability.
    main_assigns = _source_assigns(main_src)
    assert ast.literal_eval(
        main_assigns["DEFAULT_MAX_CONNECTIONS_PER_WORKER"]
    ) == GC4_MAX_CONNECTIONS_PER_WORKER
    assert ast.literal_eval(main_assigns["BACKLOG"]) == GC4_BACKLOG
    assert f'"DBAGENT_GATEWAY_WORKERS", "{GC4_GATEWAY_WORKERS}"' in main_src
    assert "limit_concurrency=max_connections" in main_src
    assert GC4_THREADPOOL_BOUNDARY in ingest_src
    assert "create_engine(dsn, future=True, **kwargs)" in session_src
    for token in GC4_DURABILITY_TOKENS:
        for label, text in (("main", main_src), ("session", session_src),
                            ("ingest", ingest_src)):
            assert token not in text, f"{label} touches {token}"

    # (3) The GC-3 decision and placements: read, never decided, here.
    decision = json.loads(GC3_DECISION.read_text(encoding="utf-8"))
    selected = {
        model: entry for model, entry in decision["models"].items()
        if entry.get("status") == "selected"
    }
    assert len(selected) == 1, sorted(selected)
    assert _gc1_cardinality_map_failures(_source_assigns(harness)) == []
    assert ast.literal_eval(
        harness_assigns["PRODUCT_AFFINITY_CARDINALITY"]
    ) == GC1_AFFINITY_CARDINALITIES["product-exclusive"]

    # (4) This slice touches no product source: its whole footprint is tests,
    # the launcher, the workflow, the chart ledger and the manifest.
    for parts in (
        ("services", "gateway", "gateway", "ingest.py"),
        ("services", "gateway", "gateway", "main.py"),
        ("libs", "py", "rca_common", "rca_common", "investigation_repo.py"),
        ("libs", "py", "rca_common", "rca_common", "db", "session.py"),
    ):
        text = REPO_ROOT.joinpath(*parts).read_text(encoding="utf-8")
        for token in ("b1_latency_basis", "sizingBasis", "basis_oracle", "B1-LATENCY-BASIS-1"):
            assert token not in text, f"{parts[-1]} carries {token}"

    # (5) No claim beyond this slice's own FPs, in any text it owns. Naming
    # the product-local tier as INELIGIBLE is required content, so the
    # forbidden patterns are claim words, word-bounded: `unhostable` is GC-3's
    # recorded route state and is legitimate here, a hostability claim is not.
    for parts in (
        ("tests", "delivery", "test_delivery_sizing_ledger.py"),
        ("deploy", "charts", "dbagent", "values.yaml"),
    ):
        text = REPO_ROOT.joinpath(*parts).read_text(encoding="utf-8").lower()
        # A bare "product capacity" substring cannot tell an assertion from a
        # denial -- both carriers must DISCUSS the product tier to declare it
        # ineligible -- so the absence test is limited to the two words that
        # only ever appear in a claim, and the positive disclaimers below do
        # the rest of the work.
        for claim in (r"\bhostable\b", r"\bhostability\b"):
            assert re.search(claim, text) is None, f"{parts[-1]} claims {claim!r}"
    ledger_text = B1LB_LEDGER_MODULE.read_text(encoding="utf-8")
    disclaimer = "neither weakens the CI-scale bar nor claims product-scale capacity"
    assert disclaimer in " ".join(ledger_text.split())
    assert "INELIGIBLE" in ledger_text, (
        "the ledger module must say which tiers cannot be a sizing observation"
    )
    values_text = B1LB_VALUES.read_text(encoding="utf-8")
    assert "VOID as provenance" in values_text, (
        "the chart must still say the shipped basis certifies nothing"
    )
    thresholds_notes = next(
        e for e in yaml.safe_load(B1LB_THRESHOLDS.read_text(encoding="utf-8"))["benchmarks"]
        if e["id"] == "B1"
    )["notes"]
    assert disclaimer in " ".join(thresholds_notes.split())

    # (6) The launcher's frozen selections and the product-local route.
    for literal in B1LB_FROZEN_LAUNCHER_CLAUSES:
        assert literal in launcher, literal
    assert 'if [ "${#cpus[@]}" -lt 8 ]; then' in launcher
    assert '"minimumHostLogicalCpus": 8,' in launcher


# ---------------------------------------------------------------------------
# B1-HOST-NOISE (FP-B1HN-1..5) -- ten reported-only host-noise fields appended
# to the existing `B1 env=` line.
#
# The tuple below is INDEPENDENT of the harness: it is retyped here so that
# renaming, reordering, dropping or inserting a field in the producer turns
# these guards red rather than silently redefining what they check.
# ---------------------------------------------------------------------------

B1HN_FIELDS = (
    "host_steal_usec",
    "assigned_cpu_steal_usec",
    "host_psi_cpu_some_usec",
    "host_psi_cpu_full_usec",
    "host_psi_io_some_usec",
    "host_psi_io_full_usec",
    "host_psi_memory_some_usec",
    "host_psi_memory_full_usec",
    "assigned_cpu_freq_open_khz",
    "assigned_cpu_freq_close_khz",
)
#: The exact declared sources, and the two rejected fallbacks that would give
#: one field environment-dependent semantics.
B1HN_SOURCES = {
    "B1_HOST_PROC_STAT_PATH": "/proc/stat",
    "B1_HOST_PSI_ROOT": "/proc/pressure",
    "B1_HOST_CPU_SYSFS_ROOT": "/sys/devices/system/cpu",
    "B1_CPU_FREQUENCY_RELATIVE": "cpufreq/scaling_cur_freq",
}
B1HN_REJECTED_SOURCES = ("/proc/cpuinfo", "cpuinfo_cur_freq", "/sys/fs/cgroup/cpu.pressure")
#: The recorded sizing ledger this slice must leave exactly as it found it
#: (design S3.5: five observations, eleven attempts, the 1.585 basis and the
#: 317m/1585m resources derived from it).
B1HN_LEDGER_BASIS_MS_PER_REQUEST = 1.585
B1HN_LEDGER_OBSERVATIONS = 5
B1HN_LEDGER_ATTEMPTS = 11
B1HN_LEDGER_RESOURCES = {"requests": "317m", "limits": "1585m"}
B1HN_LEDGER_OBSERVATION_KEYS = (
    "committed", "cpuModel", "cpuMsPerRequest", "cpus", "errors", "headSha",
    "image", "maxInFlight", "measurementAuthority", "offered", "p99Ms",
    "placementOk", "placementSchema", "platformOnline", "profile",
    "referenceTopology", "runId", "served", "servedRate",
    "topologyDecisionHeadSha", "workerPidsPost", "workerPidsPre", "workers",
)
B1HN_OPEN_HOOK = "_at_window_open"
B1HN_CLOSE_HOOK = "_after_window"
B1HN_READER = "_read_host_noise_snapshot"
B1HN_SERIALIZER = "serialize_host_noise_fields"
B1HN_COMPAT_READER = "parse_host_noise_fields"
#: The value-blind CURRENT-emission check. The compat reader above defaults a
#: missing key to `unavailable`, so it can never prove that an arm emitted the
#: block; this one counts the literal `,<key>=` tokens in tail order.
B1HN_PRESENCE_CHECK = "_host_noise_current_line_failures"
B1HN_TUPLE = "B1_HOST_NOISE_FIELDS"
B1HN_GC5_TAIL_FIELD = "postgres_wal_syncs_per_served"
#: The B1 comparison and the knobs this slice may not move. Restated, not
#: imported: a pin that reads the value it is guarding proves nothing.
B1HN_FIXED_CI_SCALE_LITERALS = {
    "CI_SCALE_BURST_RATE": 500,
    "CI_SCALE_BURST_SECONDS": 30,
    "CI_SCALE_TOTAL_REQUESTS": 15000,
    "CI_SCALE_P99_MS": 150.0,
    "CI_SCALE_SUSTAINED_FLOOR": 450,
    "CI_SCALE_MAX_IN_FLIGHT": 500,
    "BURST_RATE": 1000,
    "INGEST_GATEWAY_WORKERS": 4,
}
B1HN_MASKING_TOKENS = (
    "continue-on-error",
    "pytest.mark.xfail",
    "pytest.mark.skip",
    "|| true",
)
#: Every carrier the slice declares it does not change.
B1HN_UNCHANGED_CARRIERS = (
    ("tests", "benchmark", "b1_topology_decision.json"),
    ("deploy", "charts", "dbagent", "values.yaml"),
    ("tests", "delivery", "test_delivery_sizing_ledger.py"),
    ("scripts", "integration-test.sh"),
    ("scripts", "b1-affinity-helper.py"),
    ("tests", "functional", "test_manifests.py"),
)


def _b1hn_harness_tree() -> "tuple[str, ast.Module]":
    src = REF_TEST.read_text(encoding="utf-8")
    return src, ast.parse(src)


def test_b1_host_noise_fields_are_diagnostic_only_and_sizing_neutral():
    """FP-B1HN-3/4 [function test]: reported-only, bar-neutral, sizing-neutral.

    One test owns all three faces of the same negative boundary -- no
    host-noise outcome consumer, no changed B1 comparison or knob, and no
    retry/skip/xfail/masking -- so a mutation in any of them makes the same
    contract red.
    """
    harness_src, harness_tree = _b1hn_harness_tree()

    # (1) The inventory is exactly these ten, in this order, declared once, in
    # the harness, and disjoint from every earlier reported tail.
    assert _module_tuple(harness_tree, B1HN_TUPLE) == B1HN_FIELDS
    assert harness_src.count(f"{B1HN_TUPLE} = (") == 1
    assert not set(B1HN_FIELDS) & set(GC5_COMMIT_FIELDS)
    assert not set(B1HN_FIELDS) & set(GC4_COST_FIELDS)

    # (2) The tail location: the one fingerprint constructor appends exactly
    # one comma and the serialized block AFTER the GC-5 fields, so schema 2
    # and schema 3 receive byte-identical suffixes and the historical 81-key
    # prefix does not move.
    fixture = _gc4_function(harness_tree, "_run_b1_reference")
    line_assign = next(
        node for node in ast.walk(fixture)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "fingerprint_line"
                for t in node.targets)
    )
    rendered = ast.get_source_segment(harness_src, line_assign) or ""
    assert rendered.count("host_noise_fields") == 1, rendered
    assert (
        'f"{postgres_commit_fields},"\n'
        '            f"{host_noise_fields}"' in rendered
    ), rendered
    assert rendered.index("postgres_cost_fields") < rendered.index("host_noise_fields")
    assert rendered.index("placement_fields") < rendered.index("host_noise_fields")
    for field in B1HN_FIELDS:
        # No field is spelled into the constructor beside a placement or
        # cgroup diagnostic; the whole block travels as one serialized value.
        assert field not in rendered, field

    # (3) No field is a gating field, a product verdict, a GC-3 verdict,
    # ranking operand or record key, and none reaches the probe helper.
    gating = set(_module_tuple(harness_tree, "B1_GATING_PLACEMENT_FIELDS"))
    topology_gating = set(
        _module_tuple(harness_tree, "B1_TOPOLOGY_GATING_PLACEMENT_FIELDS")
    )
    placement = gating | set(
        _module_tuple(harness_tree, "B1_DIAGNOSTIC_PLACEMENT_FIELDS")
    )
    topology_placement = topology_gating | set(
        _module_tuple(harness_tree, "B1_TOPOLOGY_DIAGNOSTIC_PLACEMENT_FIELDS")
    )
    product_verdicts = set(_module_tuple(harness_tree, "PRODUCT_VERDICT_FIELDS"))
    probe_src = PROBE_HELPER.read_text(encoding="utf-8")
    for field in B1HN_FIELDS:
        assert field not in gating, field
        assert field not in topology_gating, field
        assert field not in placement, field
        assert field not in topology_placement, field
        assert field not in product_verdicts, field
        assert field not in gc3.VERDICT_FIELDS, field
        assert field not in gc3.INTEGRITY_VERDICT_FIELDS, field
        assert field not in gc3.PERFORMANCE_VERDICT_FIELDS, field
        assert field not in gc3.RECORD_KEYS, field
        assert field not in probe_src, f"the GC-3 helper names {field}"
    assert B1HN_TUPLE not in probe_src

    # (4) No record validator, reference-profile assertion body or CPU-basis
    # oracle reads one. They may be PRINTED -- the whole fingerprint already
    # is -- but never compared.
    for consumer in (
        "commit_shape_record_failures",
        "postgres_cost_record_failures",
        "test_b1_ci_scale_reference_profile",
        "test_gc5_commit_shape_reference_profile",
        "test_measured_cpu_cost_does_not_exceed_the_recorded_sizing_basis",
        "sizing_identity_failures",
        "sizing_run_identity",
    ):
        node = _gc4_function(harness_tree, consumer)
        body = ast.get_source_segment(harness_src, node) or ""
        for field in B1HN_FIELDS + (B1HN_TUPLE, "host_noise"):
            assert field not in body, (consumer, field)

    # ...and no assertion ANYWHERE in the harness compares a host-noise value:
    # the only nodes that may name one are the host-noise tests themselves.
    comparers: set[str] = set()
    for node in harness_tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for statement in ast.walk(node):
            if not isinstance(statement, ast.Assert):
                continue
            rendered_assert = ast.unparse(statement.test)
            if any(field in rendered_assert for field in B1HN_FIELDS) or (
                "host_noise" in rendered_assert
            ):
                comparers.add(node.name)
    assert comparers <= {
        "test_b1_host_noise_parsers_compute_declared_window_deltas",
        "test_b1_host_noise_live_reader_observes_real_proc_stat",
        "test_b1_host_noise_frequency_reads_exact_assigned_service_cpu_paths",
        "test_b1_host_noise_fields_serialize_comma_safe_in_pinned_order",
        "test_b1_host_noise_snapshot_failures_are_field_local_and_nonfatal",
        "test_b1_host_noise_window_hooks_bracket_the_measured_loop",
        "test_b1_host_noise_legacy_fingerprint_defaults_only_new_keys",
        "test_b1_host_noise_snapshot_reads_declared_sources_at_window_boundaries",
        "test_b1_ci_scale_fingerprint_reports_host_noise_fields",
        # The two existing TAIL pins: both assert only that the block closes
        # the line, in its serialized form. Neither reads a value.
        "test_b1_fingerprint_line_reports_scoped_concurrency_warnings",
        GC5_CONTEXT_NODE,
    }, sorted(comparers)

    # (5) The B1 comparison and every fixed knob are exactly where they were.
    profile_assigns = _module_assigns(REF_PATH)
    harness_assigns = _source_assigns(harness_src)
    for name, expected in B1HN_FIXED_CI_SCALE_LITERALS.items():
        source = profile_assigns if name in profile_assigns else harness_assigns
        assert ast.literal_eval(source[name]) == expected, name
    # ...and the product ceiling is still exactly one second of offered load.
    assert ast.unparse(profile_assigns["MAX_IN_FLIGHT"]) == "BURST_RATE"
    reference = _gc4_function(harness_tree, "test_b1_ci_scale_reference_profile")
    body = ast.get_source_segment(harness_src, reference) or ""
    assert "p99 < CI_SCALE_P99_MS" in body
    assert "served_rate >= CI_SCALE_SUSTAINED_FLOOR" in body
    assert "errors == 0" in body

    # (6) No retry, skip, xfail, `continue-on-error` or exit masking entered
    # any B1 carrier, and the live node carries no new marker.
    for parts in (
        ("services", "gateway", "tests", "test_b1_ingest_burst.py"),
        ("services", "gateway", "tests", "b1_topology_probe_live.py"),
        ("scripts", "integration-test.sh"),
        (".github", "workflows", "ci.yml"),
    ):
        text = REPO_ROOT.joinpath(*parts).read_text(encoding="utf-8")
        for token in B1HN_MASKING_TOKENS:
            assert token not in text, (parts[-1], token)
    live = _gc4_function(
        harness_tree, "test_b1_ci_scale_fingerprint_reports_host_noise_fields"
    )
    assert _decorator_markers(live) == {"b1_live"}, _decorator_markers(live)
    live_body = ast.get_source_segment(harness_src, live) or ""
    for forbidden in ("pytest.skip", "pytest.xfail", "if ", "unavailable\"" ):
        assert forbidden not in live_body.replace(
            '("unavailable" if value == DIAGNOSTIC_UNAVAILABLE else "value")', ""
        ), forbidden

    # (7) Sizing neutrality: the ledger, the chart and the basis never gain a
    # host-noise column, and no recorded observation is rewritten.
    for parts in GC4_SIZING_CARRIERS:
        carrier = REPO_ROOT.joinpath(*parts)
        assert carrier.is_file(), parts[-1]
        text = carrier.read_text(encoding="utf-8")
        if parts[-1] in ("thresholds.yaml", "test_b1_ingest_burst.py"):
            continue  # the manifest describes them; the harness produces them
        for field in B1HN_FIELDS + (B1HN_TUPLE,):
            assert field not in text, f"{parts[-1]} carries {field}"
    values = yaml.safe_load(GC5_VALUES_PATH.read_text(encoding="utf-8"))
    sizing = yaml.safe_dump(values["ingestGateway"]["sizingBasis"])
    for field in B1HN_FIELDS:
        assert field not in sizing, field
    basis = values["ingestGateway"]["sizingBasis"]
    assert float(basis["cpuMsPerRequest"]) == B1HN_LEDGER_BASIS_MS_PER_REQUEST
    assert len(basis["observations"]) == B1HN_LEDGER_OBSERVATIONS
    assert len(basis["collection"]["attempts"]) == B1HN_LEDGER_ATTEMPTS
    resources = values["ingestGateway"]["resources"]
    assert resources["requests"]["cpu"] == B1HN_LEDGER_RESOURCES["requests"]
    assert resources["limits"]["cpu"] == B1HN_LEDGER_RESOURCES["limits"]
    # The row schema is closed: no observation or attempt gained a column.
    assert {frozenset(row) for row in basis["observations"]} == {
        frozenset(B1HN_LEDGER_OBSERVATION_KEYS)
    }
    for attempt in basis["collection"]["attempts"]:
        assert set(attempt) == {
            "runId", "headSha", "cpuModel", "decisionState", "outcome", "reason",
        }, attempt

    # (8) The carriers the slice declares unchanged carry no host-noise name
    # at all -- including every fingerprint embedded in the GC-3 decision.
    for parts in B1HN_UNCHANGED_CARRIERS:
        text = REPO_ROOT.joinpath(*parts).read_text(encoding="utf-8")
        for field in B1HN_FIELDS + (B1HN_TUPLE, B1HN_READER):
            assert field not in text, f"{parts[-1]} carries {field}"

    # (9) The manifest describes them as reported diagnostics, and its
    # threshold, status and sizing prose are untouched.
    thresholds = yaml.safe_load(GC5_THRESHOLDS.read_text(encoding="utf-8"))
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    # The YAML folds the threshold's line breaks into spaces; compare the
    # words, so the bar itself is pinned rather than its wrapping.
    assert " ".join(b1_entry["threshold"].split()) == " ".join(
        GC5_B1_THRESHOLD.split()
    )
    assert b1_entry["status"] == "covered"
    notes = b1_entry["notes"]
    for field in B1HN_FIELDS:
        assert field in notes, field
    for source in B1HN_SOURCES.values():
        assert source in notes, source
    assert "reported diagnostic" in notes
    assert "unavailable" in notes
    assert GC5_GATE_NODE in notes
    assert str(GC5_MAX_COMMITS_PER_SERVED) in notes
    assert GC1_BASIS_OWNER in notes


def test_b1_host_noise_sources_and_window_hooks_are_pinned():
    """FP-B1HN-1: the exact declared sources and the two window boundaries.

    It makes no assertion about ``--pid host``: that clause belongs to the
    launcher's socket census and is not evidence that these kernel-global
    files were read.
    """
    harness_src, harness_tree = _b1hn_harness_tree()
    assigns = _source_assigns(harness_src)

    # (1) Four fixed source constants, each a literal path, declared once.
    for name, expected in B1HN_SOURCES.items():
        node = assigns[name]
        assert isinstance(node, ast.Call), (name, ast.dump(node))
        assert _call_func_name(node) == "Path", name
        assert ast.literal_eval(node.args[0]) == expected, name
        assert harness_src.count(f"{name} = Path(") == 1, name

    # (2) No fallback to a source that would change the field's meaning with
    # the environment, and no cgroup-pressure substitute.
    reader = _gc4_function(harness_tree, B1HN_READER)
    frequency = _gc4_function(harness_tree, "_read_assigned_cpu_frequencies")
    values_fn = _gc4_function(harness_tree, "_host_noise_field_values")
    for node in (reader, frequency, values_fn):
        body = ast.get_source_segment(harness_src, node) or ""
        for rejected in B1HN_REJECTED_SOURCES:
            assert rejected not in body, (node.name, rejected)
        assert "avg10" not in body and "avg60" not in body and "avg300" not in body

    # (3) The reader takes the declared roots as its defaults, so a fixture
    # root can never become the live source by omission.
    defaults = {
        arg.arg: ast.unparse(default)
        for arg, default in zip(
            reader.args.kwonlyargs, reader.args.kw_defaults
        ) if default is not None
    }
    assert defaults["proc_stat_path"] == "B1_HOST_PROC_STAT_PATH"
    assert defaults["psi_root"] == "B1_HOST_PSI_ROOT"
    assert defaults["cpu_sysfs_root"] == "B1_HOST_CPU_SYSFS_ROOT"

    # (4) The CPU population is the opening witness's gateway-union-PostgreSQL
    # set: not a range, not a cardinality, not the driver's own affinity.
    fixture = _gc4_function(harness_tree, "_run_b1_reference")
    population = next(
        node for node in ast.walk(fixture)
        if isinstance(node, ast.Assign)
        and any(isinstance(t, ast.Name) and t.id == "assigned_service_cpus"
                for t in node.targets)
    )
    rendered = ast.unparse(population.value)
    assert rendered == (
        "frozenset(roles_open['gateway'].allowed_cpus | "
        "roles_open['postgres'].allowed_cpus)"
    ), rendered
    assert "driver" not in rendered
    assert "sched_getaffinity" not in rendered

    # (5) The opening hook fires before `t0`; the profile module registers it
    # as a keyword and takes the reading as the last pre-window work.
    profile_src = REF_PATH.read_text(encoding="utf-8")
    assert profile_src.count("on_window_open()") == 1
    assert profile_src.count("t0 = time.perf_counter()") == 1
    assert profile_src.index("on_window_open()") < profile_src.index(
        "t0 = time.perf_counter()"
    )
    assert profile_src.index("on_window_complete()") < profile_src.index(
        "= derive_leg_vectors("
    )
    run_call = next(
        node for node in ast.walk(fixture)
        if isinstance(node, ast.Call) and _call_func_name(node) == "run_open_loop"
    )
    hooks = {
        kw.arg: ast.unparse(kw.value) for kw in run_call.keywords
        if kw.arg in ("on_window_open", "on_window_complete", "on_prologue_complete")
    }
    assert hooks == {
        "on_prologue_complete": "_after_prologue",
        "on_window_open": B1HN_OPEN_HOOK,
        "on_window_complete": B1HN_CLOSE_HOOK,
    }, hooks

    # (6) The opening callback does the host read and nothing else; the
    # closing callback does it FIRST, before `wait_sampler.stop` and before
    # every later close diagnostic.
    opening = _gc4_function(harness_tree, B1HN_OPEN_HOOK)
    opening_calls = [
        _call_func_name(node) for node in ast.walk(opening)
        if isinstance(node, ast.Call)
    ]
    assert opening_calls.count(B1HN_READER) == 1, opening_calls
    assert set(opening_calls) <= {B1HN_READER, "setdefault"}, opening_calls
    closing = _gc4_function(harness_tree, B1HN_CLOSE_HOOK)
    closing_calls = [
        (node.lineno, _call_func_name(node)) for node in ast.walk(closing)
        if isinstance(node, ast.Call)
    ]
    read_at = min(line for line, name in closing_calls if name == B1HN_READER)
    stop_at = min(
        node.lineno for node in ast.walk(closing)
        if isinstance(node, ast.Attribute) and node.attr == "stop"
    )
    assert read_at < stop_at, "the closing host read follows wait_sampler.stop"
    others = [
        line for line, name in closing_calls
        if name not in (B1HN_READER, "setdefault")
    ]
    assert others and read_at < min(others), closing_calls
    # The established sampler-stop-before-CPU-after order survives.
    collect_at = min(
        line for line, name in closing_calls if name == "_collect_cpu_diagnostics"
    )
    assert stop_at < collect_at

    # (7) No new bind mount, optional-source mount or retry entered the
    # launcher; `--pid host` keeps its existing socket-census purpose and is
    # not claimed as the host-noise vantage.
    launcher = GC5_LAUNCHER.read_text(encoding="utf-8")
    for token in ("/proc/pressure", "cpufreq", "scaling_cur_freq", B1HN_READER):
        assert token not in launcher, token
    assert "--pid host" in launcher
    manifests = REPO_ROOT.joinpath("tests", "functional", "test_manifests.py").read_text(
        encoding="utf-8"
    )
    assert "host_noise" not in manifests
    assert "--pid" in manifests


def test_b1_host_noise_probe_observation_is_post_write_and_nongating():
    """FP-B1HN-3: the GC-3 arm observation is post-write and decides nothing."""
    src = PROBE_TEST.read_text(encoding="utf-8")
    tree = ast.parse(src)
    node = _gc4_function(tree, "test_b1_ci_scale_topology_probe_record")

    calls = [
        (element.lineno, _call_func_name(element))
        for element in ast.walk(node) if isinstance(element, ast.Call)
    ]
    write_at = min(line for line, name in calls if name == "write_probe_arm_record")
    observe_at = min(line for line, name in calls if name == B1HN_COMPAT_READER)
    assert write_at < observe_at, "the host-noise observation precedes the arm write"
    serialize_at = min(line for line, name in calls if name == B1HN_SERIALIZER)
    assert write_at < serialize_at
    presence_calls = [line for line, name in calls if name == B1HN_PRESENCE_CHECK]
    assert presence_calls, (
        f"the arm observation never calls {B1HN_PRESENCE_CHECK}: the "
        "backward-compatibility reader alone cannot prove current emission"
    )
    presence_at = min(presence_calls)
    assert write_at < presence_at, "the current-emission check precedes the arm write"
    assert observe_at <= presence_at <= serialize_at, (observe_at, presence_at, serialize_at)

    # It iterates only the closed host-noise inventory and reads only the
    # WRITTEN arm's fingerprint.
    statements = [
        element for element in ast.walk(node)
        if isinstance(element, (ast.Assign, ast.Assert, ast.Expr))
        and element.lineno >= observe_at
        and element.lineno <= serialize_at
    ]
    rendered = "\n".join(ast.unparse(element) for element in statements)
    assert B1HN_TUPLE in rendered, rendered
    assert "written['fingerprint']" in rendered, rendered
    for field in B1HN_FIELDS:
        assert field not in src, f"the probe route names {field} directly"

    # No availability-conditioned assertion, verdict mutation, rejection,
    # top-level artifact key or ranking operand was added.
    for element in ast.walk(node):
        if not isinstance(element, (ast.If, ast.IfExp)):
            continue
        rendered_test = ast.unparse(element.test)
        assert "host_noise" not in rendered_test, rendered_test
        assert B1HN_TUPLE not in rendered_test, rendered_test
    # EXACTLY two admitted assertions, in this order, and both value-blind:
    # the closed key inventory, and the current-emission presence check that
    # the backward-compatibility reader cannot satisfy. Requiring the second
    # one is what stops a constructor that dropped the block from observing as
    # ten defaulted `unavailable`s; forbidding any third keeps an availability
    # or value comparison -- the kind that could void an arm -- out.
    host_noise_asserts = sorted(
        (element.lineno, ast.unparse(element.test))
        for element in ast.walk(node)
        if isinstance(element, ast.Assert) and "host_noise" in ast.unparse(element.test)
    )
    assert [rendered for _, rendered in host_noise_asserts] == [
        f"tuple(host_noise) == harness.{B1HN_TUPLE}",
        f"harness.{B1HN_PRESENCE_CHECK}(written['fingerprint']) == []",
    ], host_noise_asserts
    assert "DIAGNOSTIC_UNAVAILABLE not in set(host_noise" not in src
    assert "assert_complete_host_noise_record" not in src
    for verdict_token in ("VERDICT_MET", "VERDICT_MISSED", "verdicts["):
        segment = src.split("host_noise = ", 1)[1].split("wait_fields = ", 1)[0]
        assert verdict_token not in segment, verdict_token


# ---------------------------------------------------------------------------
# e2e-b1-diagnostics slice — FP-E2EB1D-1 … FP-E2EB1D-9.
#
# Reported-only diagnostics on the e2e B1 baseline. Every literal below is
# declared here, independently of the module it pins: a pin derived from its
# own subject detects nothing.
# ---------------------------------------------------------------------------

import io as _io
import math as _math
from dataclasses import replace as _replace
from urllib.parse import quote as _quote

E2EBD_DIAG_PATH = REPO_ROOT / "tests" / "e2e" / "b1_e2e_diagnostics.py"
E2EBD_CI_YML = REPO_ROOT / ".github" / "workflows" / "ci.yml"

e2ediag = _load(E2EBD_DIAG_PATH, "b1_e2e_diagnostics_delivery")
# The namespace-package module object the two e2e carriers import from. Object
# identity against THIS module is what proves the imports are direct rather
# than copied: `ref` above is a separate by-path load of the same file.
import services.gateway.tests.b1_reference_profile as e2ebd_reference

#: The exact import contract of §3.1 — three helpers in the profile carrier,
#: six in the diagnostics module, no alias, no re-export, nine in total.
E2EBD_REFERENCE_MODULE = "services.gateway.tests.b1_reference_profile"
E2EBD_PROFILE_IMPORTS = ("derive_leg_vectors", "leg_p99s_of", "p99_leg_split_of")
E2EBD_DIAGNOSTIC_IMPORTS = (
    "counter_delta",
    "parse_proc_stat_steal_ticks",
    "parse_psi_total",
    "serialize_leg_triple",
    "serialize_status_histogram",
    "steal_ticks_to_usec",
)
#: Live readers of the reference harness. None of them may be imported or
#: called from either e2e carrier.
E2EBD_REFERENCE_LIVE_READERS = (
    "read_proc_net_tcp_tables",
    "established_serve_port_inodes",
    "read_pool_census_sample",
    "pid_cpu_seconds",
    "tree_cpu_seconds",
    "iter_live_descendants",
    "classify_tree",
    "wait_for_classified_workers",
)
E2EBD_DYNAMIC_IMPORT_TOKENS = ("importlib", "__import__", "eval(", "exec(")
E2EBD_LIVE_TEST_MODULE = "test_b1_ingest_burst"

#: The 33-field record, declared independently of the module under test.
E2EBD_PREFIX = "B1 e2e baseline diagnostics="
E2EBD_UNAVAILABLE = "unavailable"
E2EBD_ARTIFACT = "/tmp/rca-e2e/b1-baseline-diagnostics.txt"
E2EBD_FIELDS = (
    "schema",
    "offered", "served", "errors", "p99_ms",
    "p99_leg_split_ms", "leg_p99s_ms", "status_histogram",
    "max_in_flight",
    "gateway_pod", "gateway_cpu_usage_usec",
    "gateway_nr_throttled", "gateway_throttled_usec",
    "postgres_pod", "postgres_cpu_usage_usec",
    "postgres_nr_throttled", "postgres_throttled_usec",
    "kind_node", "runner_steal_usec",
    "runner_psi_cpu_some_usec", "runner_psi_cpu_full_usec",
    "runner_psi_io_some_usec", "runner_psi_io_full_usec",
    "runner_psi_memory_some_usec", "runner_psi_memory_full_usec",
    "pg_xact_commit_delta", "pg_wal_records_delta",
    "pg_wal_bytes_delta", "pg_wal_write_delta", "pg_wal_sync_delta",
    "pg_track_wal_io_timing", "pg_wal_write_time_ms_delta",
    "pg_wal_sync_time_ms_delta",
)
#: The retired procfs naming the schema must never carry again: these counters
#: are whole-runner-kernel scope, not node-container-cgroup scope.
E2EBD_RETIRED_FIELD_PREFIX = "node_"

#: Fixed source identities (design §3.3 / §3.4).
E2EBD_NAMESPACE = "dbagent"
E2EBD_RELEASE_SELECTOR = "app.kubernetes.io/instance=dbagent"
E2EBD_COMPONENT_LABEL = "app.kubernetes.io/component"
E2EBD_GATEWAY_COMPONENT = "ingest-gateway"
E2EBD_POSTGRES_COMPONENT = "postgresql"
E2EBD_KIND_CLUSTER = "rca-e2e"
E2EBD_KIND_NODE = "rca-e2e-control-plane"
E2EBD_COMMAND_TIMEOUT_S = 5.0
E2EBD_COMMANDS_PER_BOUNDARY = 6
E2EBD_TOTAL_COMMANDS = 12
E2EBD_RUN_KWARGS = {
    "capture_output": True,
    "text": True,
    "check": False,
    "timeout": E2EBD_COMMAND_TIMEOUT_S,
}

#: The exact psql invocation, re-typed here rather than read from the module.
E2EBD_PSQL_TOKENS = (
    "psql --no-psqlrc --tuples-only --no-align -F '|'",
    "-U dbagent -d postgres -h /var/run/postgresql",
    "current_setting('track_wal_io_timing')",
    "d.xact_commit, d.stats_reset",
    "w.wal_records, w.wal_bytes::bigint, w.wal_write, w.wal_sync",
    "w.wal_write_time, w.wal_sync_time, w.stats_reset",
    "FROM pg_stat_database AS d",
    "CROSS JOIN pg_stat_wal AS w",
    "WHERE d.datname = 'dbagent';",
)

#: Legacy e2e reporting that must stay byte-identical (design §3.7).
E2EBD_LEGACY_DIGESTS = {
    "_cgroup_cpu_stat": "52955a0f02fe8da188e24731243fa992f654a6b6f2a0ecdea1ce2c4bf872204a",
    "_fmt_diag": "1260598b30805846c53144a184ad5ebc72e9888ce66132aaebdffbcace3b6ecb",
    "_after_prologue": "c851d24f62481856455362484c2849e1479966c5f13db6d2be1dade3cb9cc13d",
}
E2EBD_LEGACY_PRINT_DIGESTS = (
    "0b6ed6a0538a693cfe420aa109c9ea1d8d770f1ccc94b27989231ab484b65ae0",
    "939c613f06ad6cb11b7520156e7b6a9c3382666d30b33bdb6ba1dfeb0f391471",
)
#: e2e-b1-kind-policy: the successor to the retired kind p99 oracle. The
#: comparison is unchanged and still evaluated; only its consumer moved from an
#: assertion to pytest's built-in `record_property` observation fixture.
E2EBD_OBSERVATION_KEY = "b1_kind_p99_lt_150_ms"
E2EBD_OBSERVATION_BYTES = (
    '    record_property("b1_kind_p99_lt_150_ms", p99 < P99_MS)'
)
#: New exact pin: the built-in property fixture cannot silently disappear or be
#: replaced by a same-named local.
E2EBD_OBSERVATION_SIGNATURE = (
    "def test_b1_ingest_burst_profile(ingest_url, dashboard_url, record_property):"
)
#: Any call that would turn p99 back into an outcome, by name.
E2EBD_P99_OUTCOME_CALLS = ("pytest.fail", "pytest.skip", "pytest.xfail", "pytest.exit")
E2EBD_WIRING_LINES = (
    "from tests.e2e.b1_e2e_diagnostics import B1E2EDiagnosticSession",
    "    diagnostics = B1E2EDiagnosticSession()",
    "            on_window_open=diagnostics.open,",
    "            on_window_complete=diagnostics.close,",
    "    diagnostics.emit(baseline)",
)
E2EBD_MASKING_TOKENS = (
    "pytest.skip",
    "pytest.xfail",
    "pytest.mark.skip",
    "pytest.mark.xfail",
    "continue-on-error",
    "flaky",
    "rerun",
)
E2EBD_SUCCESS_STEP_NAME = "Upload B1 diagnostics on success"
E2EBD_FAILURE_STEP_NAME = "Upload phase timing and pod logs on failure"
E2EBD_FAILURE_PATHS = ("/tmp/rca-e2e/**", "tests/e2e/*.log")


def _e2ebd_sources() -> "tuple[str, str, str]":
    """(profile, diagnostics, live e2e test) sources, read once per call."""
    return (
        E2E_PATH.read_text(encoding="utf-8"),
        E2EBD_DIAG_PATH.read_text(encoding="utf-8"),
        E2E_TEST.read_text(encoding="utf-8"),
    )


def _e2ebd_reference_imports(src: str) -> "list[tuple[str, str | None]]":
    """Every ``from <reference module> import ...`` binding in *src*."""
    out: "list[tuple[str, str | None]]" = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.ImportFrom) and node.module == E2EBD_REFERENCE_MODULE:
            if node.level:
                out.append(("<relative import>", None))
            for alias in node.names:
                out.append((alias.name, alias.asname))
    return out


def _e2ebd_function(tree: ast.AST, name: str) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"function {name!r} not found")


def _e2ebd_name_ids(node: ast.AST) -> "set[str]":
    """Bare `ast.Name` ids only.

    Deliberately NOT attribute names: the legacy print reads `baseline.p99`,
    which is not the measured local and must never be mistaken for it.
    """
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _e2ebd_is_exact_observation(node: ast.AST) -> bool:
    """One exact `record_property("b1_kind_p99_lt_150_ms", p99 < P99_MS)`.

    Every part is pinned: the statement is a bare expression, the callee is the
    built-in fixture by name, there are exactly two positional arguments and no
    keywords, the key is that exact string, and the second argument is exactly
    `p99 < P99_MS` -- one `Lt` over the two measured Names. `<=` is a different
    comparison and is rejected here, not silently recorded.
    """
    if not isinstance(node, ast.Expr) or not isinstance(node.value, ast.Call):
        return False
    call = node.value
    if not isinstance(call.func, ast.Name) or call.func.id != "record_property":
        return False
    if call.keywords or len(call.args) != 2:
        return False
    key, compare = call.args
    if not (isinstance(key, ast.Constant) and key.value == E2EBD_OBSERVATION_KEY):
        return False
    if not isinstance(compare, ast.Compare) or len(compare.ops) != 1:
        return False
    if not isinstance(compare.ops[0], ast.Lt):
        return False
    if not (isinstance(compare.left, ast.Name) and compare.left.id == "p99"):
        return False
    right = compare.comparators[0]
    return isinstance(right, ast.Name) and right.id == "P99_MS"


def _e2ebd_p99_outcome_failures(test_fn: ast.AST) -> "list[str]":
    """Reject every route that would make the kind p99 decide the job again."""
    fails: list[str] = []
    for node in ast.walk(test_fn):
        if isinstance(node, ast.Assert):
            names, label = _e2ebd_name_ids(node.test), "p99_outcome_assert"
        elif isinstance(node, (ast.If, ast.IfExp, ast.While)):
            names, label = _e2ebd_name_ids(node.test), "p99_outcome_branch"
        elif isinstance(node, (ast.Raise, ast.Return)):
            names, label = _e2ebd_name_ids(node), "p99_outcome_exit"
        elif isinstance(node, ast.Call) and ast.unparse(node.func) in E2EBD_P99_OUTCOME_CALLS:
            names, label = _e2ebd_name_ids(node), "p99_outcome_call"
        else:
            continue
        if names & {"p99", "P99_MS"}:
            fails.append(label)
    return fails


def _e2ebd_observation_failures(load_src: str, test_fn: ast.AST) -> "list[str]":
    """The kind p99 observation: exact, top-level, ordered, and consumed by nothing.

    The five-way order is `legacy print < diagnostics.emit < p99 binding <
    observation < first baseline correctness assert`, so every coherent
    completed baseline has already published its record and still evaluates the
    comparison even when a later retained clause is red.
    """
    fails: list[str] = []
    if load_src.count(E2EBD_OBSERVATION_SIGNATURE + "\n") != 1:
        fails.append("observation_signature")
    if load_src.count(E2EBD_OBSERVATION_BYTES + "\n") != 1:
        fails.append("observation_bytes")

    calls = [
        n for n in ast.walk(test_fn)
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Call)
        and getattr(n.value.func, "id", "") == "record_property"
    ]
    keyed = [
        n for n in calls
        if n.value.args
        and isinstance(n.value.args[0], ast.Constant)
        and n.value.args[0].value == E2EBD_OBSERVATION_KEY
    ]
    exact = [n for n in keyed if _e2ebd_is_exact_observation(n)]
    if not calls:
        fails.append("observation_missing")
    elif not keyed:
        fails.append("observation_key")
    elif not exact:
        fails.append("exact_observation_compare")
    elif len(calls) != 1:
        fails.append(f"observation_not_unique: {len(calls)} property calls")
    elif exact[0] not in test_fn.body:
        fails.append("observation_not_top_level")
    else:
        legacy = emit = binding = first_assert = None
        for index, stmt in enumerate(test_fn.body):
            text = ast.unparse(stmt)
            if legacy is None and "phase=baseline,max_lateness_ms=" in text:
                legacy = index
            if emit is None and "diagnostics.emit(baseline)" in text:
                emit = index
            if binding is None and text == "p99 = baseline.p99":
                binding = index
        observation = test_fn.body.index(exact[0])
        if emit is not None:
            first_assert = next(
                (
                    index for index, stmt in enumerate(test_fn.body)
                    if index > emit and isinstance(stmt, ast.Assert)
                ),
                None,
            )
        if None in (legacy, emit, binding, first_assert):
            fails.append(
                f"observation_order_anchor_missing: legacy={legacy} emit={emit} "
                f"binding={binding} first_assert={first_assert}"
            )
        elif not (legacy < emit < binding < observation < first_assert):
            fails.append(
                f"observation_order: legacy={legacy} emit={emit} binding={binding} "
                f"observation={observation} first_assert={first_assert}"
            )
    fails.extend(_e2ebd_p99_outcome_failures(test_fn))
    return fails


def _e2ebd_import_failures(profile_src: str, diag_src: str) -> "list[str]":
    """Nine direct pure bindings, no copy, no alias, no dynamic route."""
    fails: list[str] = []
    for label, src, expected in (
        ("profile", profile_src, E2EBD_PROFILE_IMPORTS),
        ("diagnostics", diag_src, E2EBD_DIAGNOSTIC_IMPORTS),
    ):
        bindings = _e2ebd_reference_imports(src)
        names = tuple(sorted(n for n, _a in bindings))
        if names != tuple(sorted(expected)):
            fails.append(f"{label}: reference import set {names} want {tuple(sorted(expected))}")
        if any(asname is not None for _n, asname in bindings):
            fails.append(f"{label}: a reference helper is imported under an alias")
        tree = ast.parse(src)
        defined = {
            n.name
            for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        }
        for name in E2EBD_PROFILE_IMPORTS + E2EBD_DIAGNOSTIC_IMPORTS:
            if name in defined:
                fails.append(f"{label}: {name} is redefined locally instead of imported")
        # A re-export of the OTHER carrier's helpers is a second copy route.
        other = (
            E2EBD_DIAGNOSTIC_IMPORTS if label == "profile" else E2EBD_PROFILE_IMPORTS
        )
        for name in other:
            if name in dict(bindings):
                fails.append(f"{label}: re-exports {name}, which it does not own")
        for token in E2EBD_DYNAMIC_IMPORT_TOKENS:
            if token in src:
                fails.append(f"{label}: dynamic import route {token!r}")
        if E2EBD_LIVE_TEST_MODULE in src:
            fails.append(f"{label}: imports the live reference test module")
        for reader in E2EBD_REFERENCE_LIVE_READERS:
            if reader in src:
                fails.append(f"{label}: names the reference live reader {reader}")
    # The nine bindings must be the reference module's own objects.
    for name in E2EBD_PROFILE_IMPORTS:
        if getattr(e2e, name, None) is not getattr(e2ebd_reference, name):
            fails.append(f"profile: {name} is not the reference object")
    for name in E2EBD_DIAGNOSTIC_IMPORTS:
        if getattr(e2ediag, name, None) is not getattr(e2ebd_reference, name):
            fails.append(f"diagnostics: {name} is not the reference object")
    # Each imported binding is pure over caller-supplied data.
    ref_tree = ast.parse(REF_PATH.read_text(encoding="utf-8"))
    ref_globals = {
        t.id
        for n in ref_tree.body
        if isinstance(n, ast.Assign)
        for t in n.targets
        if isinstance(t, ast.Name)
    }
    for name in E2EBD_PROFILE_IMPORTS + E2EBD_DIAGNOSTIC_IMPORTS:
        fn = _e2ebd_function(ref_tree, name)
        body = ast.unparse(fn)
        for token in ("open(", "Path(", "os.", "subprocess", "socket", "print("):
            if token in body:
                fails.append(f"{name}: imported helper performs I/O ({token})")
        for node in ast.walk(fn):
            if isinstance(node, ast.Global):
                fails.append(f"{name}: imported helper mutates module state")
            if isinstance(node, (ast.Assign, ast.AugAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name) and target.id in ref_globals:
                        fails.append(f"{name}: imported helper rebinds the global {target.id}")
    return fails


def test_e2e_b1_reference_diagnostic_imports_are_pure_and_direct():
    """FP-E2EB1D-1/2/3: the nine exact bindings, direct and pure."""
    profile_src, diag_src, _load_src = _e2ebd_sources()
    assert _e2ebd_import_failures(profile_src, diag_src) == []
    # All nine are exercised by their owners.
    n = 8
    latencies = [float(i) for i in range(n)]
    dispatch = [1000.0 + i / 200.0 + 0.001 for i in range(n)]
    attempt = [1000.0 + i / 200.0 + 0.002 for i in range(n)]
    legs = e2e.derive_leg_vectors(latencies, dispatch, attempt, due0=1000.0, rate=200.0)
    assert [len(v) for v in legs] == [n, n, n]
    assert len(e2e.p99_leg_split_of(latencies, *legs)) == 3
    assert len(e2e.leg_p99s_of(*legs)) == 3
    assert e2ediag.counter_delta(1, 4, label="x") == 3
    assert e2ediag.parse_proc_stat_steal_ticks("cpu 1 1 1 1 1 1 1 9 0 0\ncpu0 1 1 1 1 1 1 1 9 0 0\n")[0] == 9
    assert e2ediag.parse_psi_total("some avg10=0.00 total=1234\n", "some") == 1234
    assert e2ediag.serialize_leg_triple((1.0, 2.0, 3.0)) == "1.000/2.000/3.000"
    assert e2ediag.serialize_status_histogram([202, 202, 503]) == "202:2;503:1"
    assert e2ediag.steal_ticks_to_usec(500, clock_ticks=100) == 5_000_000

    # Negative controls: every forbidden route is red.
    copied = profile_src.replace(
        "from services.gateway.tests.b1_reference_profile import (\n"
        "    derive_leg_vectors,\n"
        "    leg_p99s_of,\n"
        "    p99_leg_split_of,\n"
        ")",
        "def derive_leg_vectors(*a, **k):\n    return [], [], []\n"
        "def leg_p99s_of(*a, **k):\n    return (0.0, 0.0, 0.0)\n"
        "def p99_leg_split_of(*a, **k):\n    return (0.0, 0.0, 0.0)",
        1,
    )
    assert copied != profile_src
    assert _e2ebd_import_failures(copied, diag_src) != []
    for mutant in (
        profile_src.replace("    derive_leg_vectors,\n", "    derive_leg_vectors as _d,\n", 1),
        profile_src + "\nimportlib.import_module('services.gateway.tests.b1_reference_profile')\n",
        profile_src + "\nfrom services.gateway.tests import test_b1_ingest_burst\n",
        profile_src + "\nread_proc_net_tcp_tables()\n",
    ):
        assert _e2ebd_import_failures(mutant, diag_src) != [], mutant[-90:]
    for mutant in (
        diag_src.replace("    counter_delta,\n", "", 1),
        diag_src + "\nfrom services.gateway.tests.b1_reference_profile import derive_leg_vectors\n",
        diag_src + "\nread_pool_census_sample(None)\n",
    ):
        assert _e2ebd_import_failures(profile_src, mutant) != []


class E2EBDStubTransport:
    """Counts and orders every request that actually reaches the transport."""

    def __init__(self, delay_s: float = 0.0, status: int = 202):
        self.delay_s = delay_s
        self.status = status
        self.payloads: list[bytes] = []
        self.times: list[float] = []

    async def post(self, url, *, content, headers):
        self.payloads.append(content)
        self.times.append(time.perf_counter())
        if self.delay_s:
            await asyncio.sleep(self.delay_s)
        return self.status, b'{"investigation_id":"x"}', None


#: Dispatch rate and in-flight cap `_e2ebd_run_baseline` drives the open loop
#: at. Declared here because the range checks below are expressed in slots.
E2EBD_STUB_RATE = 2000.0
E2EBD_STUB_MAX_IN_FLIGHT = 1000
#: Wall-clock width of the forced stall, in dispatch slots. Ten slots is far
#: outside the spread two unstalled runs show: over 440 measured runs an
#: unstalled `max_backlog` was 1 or 2 and a stalled one 9 or 10, so the
#: forcing can never be confused with ordinary jitter.
E2EBD_STALL_SLOTS = 10


class E2EBDStallingStubTransport(E2EBDStubTransport):
    """A stub that blocks the event loop once, inside the measured window.

    `time.sleep` rather than `asyncio.sleep` on purpose: the open-loop
    dispatcher's schedule is wall-clock, so only a blocking stall makes it
    fall a KNOWN number of slots behind and report a `max_backlog` that no
    unstalled run produces. Every count, code and latency slot is unaffected.
    """

    def __init__(self, *, stall_at: int, stall_slots: int = E2EBD_STALL_SLOTS, **kwargs):
        super().__init__(**kwargs)
        self.stall_slots = stall_slots
        self.stall_s = stall_slots / E2EBD_STUB_RATE
        self.stall_at = stall_at

    async def post(self, url, *, content, headers):
        if len(self.payloads) == self.stall_at:
            time.sleep(self.stall_s)
        return await super().post(url, content=content, headers=headers)


def _e2ebd_exec_profile(src: str, name: str):
    """Execute a (possibly mutated) copy of the e2e profile carrier."""
    # Compiled under a synthetic filename on purpose: a mutant must never be
    # attributed to the real carrier's line numbers by a coverage run.
    origin = f"<{name}>"
    module = type(sys)(name)
    module.__file__ = origin
    sys.modules[name] = module
    exec(compile(src, origin, "exec"), module.__dict__)
    return module


def test_e2e_b1_leg_vectors_match_reference_semantics():
    """FP-E2EB1D-1: exact reference vectors, summaries, histogram and peak."""
    rate = 200.0
    due0 = 1000.0
    n = 6
    # Deterministic stations: request 3 is the slow one, and requests 1 and 4
    # tie on total lateness so the smallest-index rule is exercised.
    slips = [0.001, 0.002, 0.003, 0.010, 0.002, 0.001]
    lags = [0.0005, 0.0010, 0.0005, 0.0200, 0.0010, 0.0005]
    durations = [0.004, 0.009, 0.004, 0.500, 0.009, 0.004]
    dispatch = [due0 + i / rate + slips[i] for i in range(n)]
    attempt = [dispatch[i] + lags[i] for i in range(n)]
    response = [attempt[i] + durations[i] for i in range(n)]
    latencies = [(response[i] - (due0 + i / rate)) * 1000.0 for i in range(n)]

    pre, lag, dur = e2e.derive_leg_vectors(
        latencies, dispatch, attempt, due0=due0, rate=rate
    )
    # Identity: the three raw legs sum to that request's due-time lateness.
    for i in range(n):
        assert abs((pre[i] + lag[i] + dur[i]) - latencies[i]) < ref.LEG_SUM_TOLERANCE_MS
        assert abs(pre[i] - slips[i] * 1000.0) < 1e-6
        assert abs(lag[i] - lags[i] * 1000.0) < 1e-6
        assert abs(dur[i] - durations[i] * 1000.0) < 1e-6

    result = e2e.PhaseResult(
        offered=n, served=n, errors=0, latencies_ms=latencies,
        t0=due0, t_last_complete=response[-1], due0=due0,
        max_in_flight=3, max_backlog=0, phase="baseline",
        status_codes=[202] * (n - 1) + [503],
        pre_dispatch_slip_ms=pre, start_lag_ms=lag, attempt_duration_ms=dur,
    )
    # Identity-aligned triple: the p99 request's own three legs.
    p99_index = ref.p99_index_of(latencies)
    assert p99_index == 3
    assert result.p99_leg_split == (pre[3], lag[3], dur[3])
    assert abs(sum(result.p99_leg_split) - result.p99) < ref.LEG_SUM_TOLERANCE_MS
    # Three INDEPENDENT nearest-rank statistics, never a decomposition.
    assert result.leg_p99s == (
        ref.nearest_rank_p99(pre), ref.nearest_rank_p99(lag), ref.nearest_rank_p99(dur)
    )
    assert result.leg_p99s == (pre[3], lag[3], dur[3])  # same request here
    # Tie: two identical totals select the smallest request index.
    tied = [5.0, 9.0, 9.0, 1.0]
    assert ref.p99_index_of(tied) == 1
    tied_result = e2e.PhaseResult(
        offered=4, served=4, errors=0, latencies_ms=tied,
        t0=0.0, t_last_complete=1.0, due0=0.0, max_in_flight=1, max_backlog=0,
        pre_dispatch_slip_ms=[0.0, 1.0, 2.0, 3.0],
        start_lag_ms=[0.0, 1.0, 2.0, 3.0],
        attempt_duration_ms=[0.0, 1.0, 2.0, 3.0],
    )
    assert tied_result.p99_leg_split == (1.0, 1.0, 1.0)

    values = e2ediag.build_e2e_b1_diagnostic_values(
        result, e2ediag.unavailable_snapshot("open"), e2ediag.unavailable_snapshot("close")
    )
    assert values["p99_leg_split_ms"] == e2ediag.serialize_leg_triple(result.p99_leg_split)
    assert values["leg_p99s_ms"] == e2ediag.serialize_leg_triple(result.leg_p99s)
    assert values["status_histogram"] == "202:5;503:1"
    assert values["max_in_flight"] == 3
    assert values["offered"] == n and values["served"] == n and values["errors"] == 0

    # A live baseline through the shipped generator carries the same shape,
    # and max_in_flight is still the existing dispatch peak — no new census.
    transport = E2EBDStubTransport(delay_s=0.01)
    measured = [(f'{{"m":{i}}}'.encode(), {}) for i in range(24)]
    live = asyncio.run(
        e2e.run_open_loop_baseline(
            endpoint="http://stub/events",
            requests=measured,
            transport=transport,
            rate=400,
            max_in_flight=1000,
            include_sync_warmup=False,
        )
    )
    assert len(live.pre_dispatch_slip_ms) == 24
    assert len(live.start_lag_ms) == 24
    assert len(live.attempt_duration_ms) == 24
    for i in range(24):
        total = (
            live.pre_dispatch_slip_ms[i] + live.start_lag_ms[i] + live.attempt_duration_ms[i]
        )
        assert abs(total - live.latencies_ms[i]) < ref.LEG_SUM_TOLERANCE_MS
        assert live.pre_dispatch_slip_ms[i] >= 0.0
        assert live.start_lag_ms[i] >= 0.0
        assert live.attempt_duration_ms[i] >= 0.0
    assert 0 < live.max_in_flight <= 24
    assert e2ediag.serialize_status_histogram(live.status_codes) == "202:24"


def _e2ebd_instrumentation_failures(src: str) -> "list[str]":
    """Structural placement of the two guards, reads, stores and allocations."""
    fails: list[str] = []
    tree = ast.parse(src)
    gen = _e2ebd_function(tree, "run_open_loop_baseline")
    one = next(
        (n for n in gen.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "_one"),
        None,
    )
    if one is None:
        return ["run_open_loop_baseline no longer defines _one"]
    allocations = [
        stmt
        for stmt in gen.body
        if isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id in ("dispatch_at", "attempt_at")
    ]
    if len(allocations) != 2:
        fails.append(f"{len(allocations)} top-level timestamp allocations, want 2")
    for stmt in allocations:
        if ast.unparse(stmt.value) != "[0.0] * n":
            fails.append(f"allocation is not a preallocated length-n vector: {ast.unparse(stmt)}")
        if gen.body.index(stmt) > gen.body.index(one):
            fails.append(f"{stmt.targets[0].id} is allocated after `_one` is defined")
    # Exactly two bounds guards, each holding exactly one read and one store.
    guards = [
        node
        for node in ast.walk(gen)
        if isinstance(node, ast.If) and ast.unparse(node.test) in ("0 <= idx < n", "0 <= i < n")
    ]
    if len(guards) != 2:
        fails.append(f"{len(guards)} bounds guards, want exactly 2")
    stores = [
        node
        for node in ast.walk(gen)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Subscript)
        and isinstance(node.targets[0].value, ast.Name)
        and node.targets[0].value.id in ("dispatch_at", "attempt_at")
    ]
    if len(stores) != 2:
        fails.append(f"{len(stores)} timestamp stores, want exactly 2")
    guarded = [node for guard in guards for node in ast.walk(guard)]
    for store in stores:
        if store not in guarded:
            fails.append(f"unguarded timestamp store: {ast.unparse(store)}")
        if ast.unparse(store.value) != "time.perf_counter()":
            fails.append(f"store value is not a monotonic read: {ast.unparse(store)}")
    for guard in guards:
        if len(guard.body) != 1 or guard.orelse:
            fails.append(f"bounds guard carries {len(guard.body)} statements: {ast.unparse(guard)}")
        body = ast.unparse(guard)
        for token in ("await", "sleep", "open(", "subprocess", "Lock", "create_task", "for "):
            if token in body:
                fails.append(f"bounds guard performs forbidden work ({token})")
    # The attempt guard is the FIRST statement of `_one`'s existing try.
    try_stmt = next((n for n in one.body if isinstance(n, ast.Try)), None)
    if try_stmt is None:
        fails.append("_one no longer wraps its body in try")
    else:
        first = try_stmt.body[0]
        if not (isinstance(first, ast.If) and ast.unparse(first.test) == "0 <= idx < n"):
            fails.append(f"_one's first statement is {ast.unparse(first)!r}")
    # The dispatch store sits immediately before the unchanged create_task.
    for parent in ast.walk(gen):
        body = getattr(parent, "body", None)
        if not isinstance(body, list):
            continue
        for index, stmt in enumerate(body):
            if isinstance(stmt, ast.Assign) and "asyncio.create_task(_one(i, *requests[i]))" in ast.unparse(stmt):
                previous = body[index - 1] if index else None
                if not (
                    isinstance(previous, ast.If)
                    and ast.unparse(previous.test) == "0 <= i < n"
                ):
                    fails.append("the dispatch store is not immediately before create_task")
    return fails


def _e2ebd_run_baseline(module, *, measured: int, prologue: int = 30, transport=None):
    """1 warmup + `prologue` prologue + `measured` requests through a stub."""
    transport = E2EBDStubTransport() if transport is None else transport
    marks: dict[str, object] = {}

    def _at_prologue_complete() -> None:
        marks["after_prologue_calls"] = len(transport.payloads)

    def _at_open() -> None:
        marks["open_calls"] = len(transport.payloads)
        marks["open_ts"] = time.perf_counter()

    def _at_complete() -> None:
        marks["close_calls"] = len(transport.payloads)
        marks["close_ts"] = time.perf_counter()

    result = asyncio.run(
        module.run_open_loop_baseline(
            endpoint="http://stub/events",
            requests=[(f'{{"m":{i}}}'.encode(), {}) for i in range(measured)],
            transport=transport,
            rate=E2EBD_STUB_RATE,
            max_in_flight=E2EBD_STUB_MAX_IN_FLIGHT,
            warmup=(b'{"w":1}', {}),
            prologue=[(f'{{"p":{i}}}'.encode(), {}) for i in range(prologue)],
            include_sync_warmup=True,
            on_prologue_complete=_at_prologue_complete,
            on_window_open=_at_open,
            on_window_complete=_at_complete,
        )
    )
    return result, transport, marks


def test_e2e_b1_window_hooks_preserve_warmup_and_prologue():
    """FP-E2EB1D-1/7: every unmeasured request still sends; the hooks bracket."""
    profile_src, _diag_src, _load_src = _e2ebd_sources()
    assert _e2ebd_instrumentation_failures(profile_src) == []

    measured = 40
    result, transport, marks = _e2ebd_run_baseline(e2e, measured=measured)
    assert len(transport.payloads) == 1 + 30 + measured
    assert marks["after_prologue_calls"] == 1 + 30
    # The open hook is the LAST pre-window operation: nothing measured has
    # been sent yet, and it runs before t0 exists.
    assert marks["open_calls"] == 1 + 30
    assert marks["open_ts"] <= result.t0
    # The close hook is the FIRST post-drain operation: every request is done
    # and `t_last_complete` is already fixed.
    assert marks["close_calls"] == 1 + 30 + measured
    assert marks["close_ts"] >= result.t_last_complete
    assert result.offered == measured and result.served == measured
    # No measured slot was polluted by a negative index: a pre-window write
    # that survived would make that request's start lag negative.
    assert len(result.start_lag_ms) == measured
    assert all(v >= 0.0 for v in result.start_lag_ms)
    assert all(v >= 0.0 for v in result.pre_dispatch_slip_ms)
    assert all(v >= 0.0 for v in result.attempt_duration_ms)

    # --- required red cases -------------------------------------------------
    # D1: allocate after warmup/prologue AND store unguarded. The closure's
    # free variable is unbound while warmup and prologue run, so those 31
    # requests never reach the transport.
    late = profile_src.replace(
        "    dispatch_at = [0.0] * n\n    attempt_at = [0.0] * n\n\n    async def _one(",
        "    async def _one(",
        1,
    ).replace(
        "        latencies = [0.0] * n\n",
        "        dispatch_at = [0.0] * n\n        attempt_at = [0.0] * n\n        latencies = [0.0] * n\n",
        1,
    ).replace(
        "            if 0 <= idx < n:\n                attempt_at[idx] = time.perf_counter()\n",
        "            attempt_at[idx] = time.perf_counter()\n",
        1,
    )
    assert late != profile_src
    assert _e2ebd_instrumentation_failures(late) != []
    d1 = _e2ebd_exec_profile(late, "b1_e2e_profile_d1_mutant")
    _r, d1_transport, _m = _e2ebd_run_baseline(d1, measured=measured)
    assert len(d1_transport.payloads) == measured, (
        "the D1 shape must lose warmup and prologue at the transport"
    )

    # Preallocated but unguarded: a negative index now indexes a measured
    # slot, and with a measured window shorter than the prologue the wrong
    # write is a hard IndexError that costs those requests their transport call.
    unguarded = profile_src.replace(
        "            if 0 <= idx < n:\n                attempt_at[idx] = time.perf_counter()\n",
        "            attempt_at[idx] = time.perf_counter()\n",
        1,
    )
    assert unguarded != profile_src
    assert _e2ebd_instrumentation_failures(unguarded) != []
    pu = _e2ebd_exec_profile(unguarded, "b1_e2e_profile_unguarded_mutant")
    _r2, pu_transport, _m2 = _e2ebd_run_baseline(pu, measured=12)
    assert len(pu_transport.payloads) < 1 + 30 + 12, (
        "an unguarded store must write a measured slot and be observable"
    )


def _e2ebd_frame(name: str, body: str) -> str:
    return f"#b1diag-begin:{name}\n{body}\n#b1diag-end:{name}\n"


def _e2ebd_cgroup_v2(usage: int, nr_throttled: int, throttled: int) -> str:
    return (
        _e2ebd_frame("proc_self_cgroup", "0::/")
        + _e2ebd_frame(
            "cpu_stat_v2",
            f"usage_usec {usage}\nuser_usec 1\nsystem_usec 1\n"
            f"nr_periods 9\nnr_throttled {nr_throttled}\nthrottled_usec {throttled}",
        )
        + _e2ebd_frame("cpuacct_usage_v1", "")
        + _e2ebd_frame("cpu_stat_v1", "")
    )


def _e2ebd_cgroup_v1(usage_ns: int, nr_throttled: int, throttled_ns: int) -> str:
    return (
        _e2ebd_frame("proc_self_cgroup", "3:cpuacct,cpu:/kubepods/podx")
        + _e2ebd_frame("cpu_stat_v2", "")
        + _e2ebd_frame("cpuacct_usage_v1", str(usage_ns))
        + _e2ebd_frame(
            "cpu_stat_v1",
            f"nr_periods 9\nnr_throttled {nr_throttled}\nthrottled_time {throttled_ns}",
        )
    )


def test_e2e_b1_cgroup_parsers_cover_v2_and_v1_units():
    """FP-E2EB1D-2: exact v2/v1 deltas; every defect is unavailable, not zero."""
    parse = e2ediag.parse_cgroup_cpu_frames
    frames = e2ediag.parse_frames

    before = parse(frames(_e2ebd_cgroup_v2(13_000_000, 2, 4_000)))
    after = parse(frames(_e2ebd_cgroup_v2(13_910_000, 5, 9_500)))
    assert before.cgroup_version == 2
    assert e2ediag.cgroup_cpu_delta(before, after, label="gateway") == (910_000, 3, 5_500)
    # A real zero survives as 0.
    assert e2ediag.cgroup_cpu_delta(before, before, label="gateway") == (0, 0, 0)

    # v1 nanoseconds are converted only AFTER the subtraction.
    v1_before = parse(frames(_e2ebd_cgroup_v1(13_000_000_999, 2, 4_000_999)))
    v1_after = parse(frames(_e2ebd_cgroup_v1(13_910_000_999, 5, 9_500_999)))
    assert v1_before.cgroup_version == 1
    assert e2ediag.cgroup_cpu_delta(v1_before, v1_after, label="postgres") == (910_000, 3, 5_500)

    # Every refusal path.
    for payload, why in (
        (_e2ebd_cgroup_v2(1, 1, 1).replace("nr_throttled 1\n", ""), "short v2 payload"),
        (_e2ebd_cgroup_v2(1, 1, 1) + _e2ebd_frame("cpu_stat_v2", "usage_usec 2"), "duplicate frame"),
        (_e2ebd_cgroup_v2(1, 1, 1).replace("usage_usec 1", "usage_usec -3"), "negative counter"),
        (_e2ebd_cgroup_v2(1, 1, 1).replace("usage_usec 1", "usage_usec x"), "malformed counter"),
        (_e2ebd_cgroup_v2(1, 1, 1).replace("#b1diag-end:cpu_stat_v2\n", ""), "unterminated frame"),
        (_e2ebd_cgroup_v2(1, 1, 1).replace(_e2ebd_frame("proc_self_cgroup", "0::/"),
                                           _e2ebd_frame("proc_self_cgroup", "")), "no /proc/self/cgroup"),
    ):
        with pytest.raises(Exception):
            parse(frames(payload))
    # Mixed v1/v2 is refused rather than silently preferred.
    mixed = (
        _e2ebd_frame("proc_self_cgroup", "0::/")
        + _e2ebd_frame("cpu_stat_v2", "usage_usec 1\nnr_throttled 0\nthrottled_usec 0")
        + _e2ebd_frame("cpuacct_usage_v1", "17")
        + _e2ebd_frame("cpu_stat_v1", "nr_throttled 0\nthrottled_time 0")
    )
    with pytest.raises(Exception):
        parse(frames(mixed))
    # A reset (decreasing counter) is a lost measurement, never a zero.
    reset = parse(frames(_e2ebd_cgroup_v2(1_000, 0, 0)))
    with pytest.raises(Exception):
        e2ediag.cgroup_cpu_delta(after, reset, label="gateway")
    # A cgroup version change inside the window is refused.
    with pytest.raises(Exception):
        e2ediag.cgroup_cpu_delta(before, v1_after, label="gateway")

    # At the record level the whole group is `unavailable`, never 0.
    target = e2ediag.PodTarget(
        name="dbagent-ingest-gateway-abc", uid="uid-1",
        node_name=E2EBD_KIND_NODE, container_id="containerd://1",
        container_name=E2EBD_GATEWAY_COMPONENT,
    )
    opening = e2ediag.BoundarySnapshot(label="open", gateway=target, gateway_cpu=after)
    closing = e2ediag.BoundarySnapshot(label="close", gateway=target, gateway_cpu=reset)
    values = e2ediag.build_e2e_b1_diagnostic_values(None, opening, closing)
    for name in (
        "gateway_pod", "gateway_cpu_usage_usec",
        "gateway_nr_throttled", "gateway_throttled_usec",
    ):
        assert values[name] == E2EBD_UNAVAILABLE, name


class E2EBDFakeRunner:
    """Records every argv and replays canned outputs, in order, once each."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []

    def __call__(self, argv, **kwargs):
        self.calls.append(list(argv))
        self.kwargs.append(dict(kwargs))
        for match, stdout, returncode in self.replies:
            if match(argv):
                return subprocess.CompletedProcess(argv, returncode, stdout, "")
        return subprocess.CompletedProcess(argv, 1, "", "no canned reply")


def _e2ebd_is_pod_query(argv) -> bool:
    return argv[:2] == ["kubectl", "-n"] and "get" in argv and "pods" in argv


def _e2ebd_is_exec(component):
    def match(argv):
        return "exec" in argv and component in argv
    return match


def _e2ebd_pod_json(
    *,
    gateway_name="dbagent-ingest-gateway-5f7",
    gateway_uid="uid-gw-1",
    postgres_name="dbagent-postgresql-0",
    postgres_uid="uid-pg-1",
    node=E2EBD_KIND_NODE,
    extra=(),
) -> str:
    def pod(name, uid, component, container):
        return {
            "metadata": {
                "name": name,
                "uid": uid,
                "labels": {
                    "app.kubernetes.io/instance": "dbagent",
                    E2EBD_COMPONENT_LABEL: component,
                },
            },
            "spec": {"nodeName": node},
            "status": {
                "phase": "Running",
                "containerStatuses": [
                    {"name": container, "ready": True, "containerID": f"containerd://{uid}"}
                ],
            },
        }

    # A plausible decoy is listed FIRST: same release, same container NAME,
    # Running and Ready -- but a different component. A first-item selector,
    # or one that matches the component label by prefix, takes this pod and
    # reports another tenant's cgroup as the gateway's.
    items = [
        {
            "metadata": {
                "name": "dbagent-ingest-gateway-canary",
                "uid": "uid-decoy",
                "labels": {
                    "app.kubernetes.io/instance": "dbagent",
                    E2EBD_COMPONENT_LABEL: "ingest-gateway-canary",
                },
            },
            "spec": {"nodeName": node},
            "status": {"phase": "Running",
                       "containerStatuses": [
                           {"name": E2EBD_GATEWAY_COMPONENT, "ready": True,
                            "containerID": "containerd://decoy"}
                       ]},
        },
        pod(gateway_name, gateway_uid, E2EBD_GATEWAY_COMPONENT, E2EBD_GATEWAY_COMPONENT),
        pod(postgres_name, postgres_uid, E2EBD_POSTGRES_COMPONENT, E2EBD_POSTGRES_COMPONENT),
    ]
    items.extend(extra)
    return json.dumps({"items": items})


class E2EBDClusterRunner:
    """A whole fake cluster: one canned reply per source, per boundary."""

    def __init__(
        self,
        *,
        pod_json=None,
        gateway=None,
        postgres=None,
        runner=None,
        kind_stdout=E2EBD_KIND_NODE + "\n",
        failing=(),
    ):
        self.pod_json = list(pod_json or [_e2ebd_pod_json()])
        self.gateway = list(gateway or [])
        self.postgres = list(postgres or [])
        self.runner = list(runner or [])
        self.kind_stdout = kind_stdout
        self.failing = set(failing)
        self.calls: list[list[str]] = []
        self.kwargs: list[dict] = []
        self.counts: dict[str, int] = {}

    def _next(self, key, series):
        index = self.counts.get(key, 0)
        self.counts[key] = index + 1
        if not series:
            return ""
        return series[min(index, len(series) - 1)]

    def __call__(self, argv, **kwargs):
        argv = list(argv)
        self.calls.append(argv)
        self.kwargs.append(dict(kwargs))
        if argv[0] == "kubectl" and "get" in argv and "pods" in argv:
            key = "pods"
            stdout = self._next(key, self.pod_json)
        elif argv[0] == "kubectl" and "exec" in argv and E2EBD_GATEWAY_COMPONENT in argv:
            key = "gateway"
            stdout = self._next(key, self.gateway)
        elif argv[0] == "kubectl" and "exec" in argv and E2EBD_POSTGRES_COMPONENT in argv:
            key = "postgres"
            stdout = self._next(key, self.postgres)
        elif argv[0] == "kind":
            key = "kind"
            stdout = self.kind_stdout
            self.counts[key] = self.counts.get(key, 0) + 1
        elif argv[0] == "docker":
            key = "runner"
            stdout = self._next(key, self.runner)
        else:
            return subprocess.CompletedProcess(argv, 127, "", "unknown command")
        if key in self.failing:
            return subprocess.CompletedProcess(argv, 1, "", f"{key} unavailable")
        return subprocess.CompletedProcess(argv, 0, stdout, "")


def _e2ebd_proc_stat(steal: int, per_cpu_steal: int = 0) -> str:
    return (
        f"cpu  100 0 100 900 0 0 0 {steal} 0 0\n"
        f"cpu0 50 0 50 450 0 0 0 {per_cpu_steal} 0 0\n"
        f"cpu1 50 0 50 450 0 0 0 {per_cpu_steal} 0 0\n"
        "intr 1 2 3\nctxt 999\n"
    )


def _e2ebd_psi(some_total: int, full_total: int | None, avg10: str = "0.00") -> str:
    text = f"some avg10={avg10} avg60=0.00 avg300=0.00 total={some_total}"
    if full_total is not None:
        text += f"\nfull avg10={avg10} avg60=0.00 avg300=0.00 total={full_total}"
    return text


def _e2ebd_runner_payload(
    *, steal: int, psi_base: int, clk: str = "100", per_cpu_steal: int = 0,
    avg10: str = "0.00", full: bool = True,
) -> str:
    return (
        _e2ebd_frame("proc_stat", _e2ebd_proc_stat(steal, per_cpu_steal))
        + _e2ebd_frame("psi_cpu", _e2ebd_psi(psi_base, psi_base + 1 if full else None, avg10))
        + _e2ebd_frame("psi_io", _e2ebd_psi(psi_base + 2, psi_base + 3 if full else None, avg10))
        + _e2ebd_frame("psi_memory", _e2ebd_psi(psi_base + 4, psi_base + 5 if full else None, avg10))
        + _e2ebd_frame("clk_tck", clk)
    )


def _e2ebd_pg_row(
    *, timing="on", xact=1000, db_reset="", records=10, wal_bytes=2048,
    writes=5, syncs=4, write_ms=1.5, sync_ms=2.5, wal_reset="",
) -> str:
    return (
        f"{timing}|{xact}|{db_reset}|{records}|{wal_bytes}|{writes}|{syncs}|"
        f"{write_ms}|{sync_ms}|{wal_reset}"
    )


def _e2ebd_postgres_payload(row: str, cgroup: str, *, label: str) -> str:
    stats = _e2ebd_frame("pg_stats", row)
    return stats + cgroup if label == "open" else cgroup + stats


def _e2ebd_healthy_runner(**overrides) -> E2EBDClusterRunner:
    gateway = [_e2ebd_cgroup_v2(13_000_000, 2, 4_000), _e2ebd_cgroup_v2(13_910_000, 5, 9_500)]
    postgres = [
        _e2ebd_postgres_payload(
            _e2ebd_pg_row(xact=1000, records=10, wal_bytes=2048, writes=5, syncs=4,
                          write_ms=1.5, sync_ms=2.5),
            _e2ebd_cgroup_v2(7_000_000, 0, 0), label="open",
        ),
        _e2ebd_postgres_payload(
            _e2ebd_pg_row(xact=1600, records=40, wal_bytes=6144, writes=9, syncs=7,
                          write_ms=4.0, sync_ms=9.0),
            _e2ebd_cgroup_v2(7_250_000, 0, 0), label="close",
        ),
    ]
    runner = [
        _e2ebd_runner_payload(steal=1_000, psi_base=100_000),
        _e2ebd_runner_payload(steal=1_500, psi_base=300_000),
    ]
    kwargs = dict(gateway=gateway, postgres=postgres, runner=runner)
    kwargs.update(overrides)
    return E2EBDClusterRunner(**kwargs)


def _e2ebd_values_from(runner) -> dict:
    opening = e2ediag.snapshot_e2e_b1_boundary("open", run=runner)
    closing = e2ediag.snapshot_e2e_b1_boundary("close", run=runner)
    return e2ediag.build_e2e_b1_diagnostic_values(None, opening, closing)


def test_e2e_b1_workload_sources_target_exact_pods_and_containers():
    """FP-E2EB1D-2: the two named application containers, never a substitute."""
    runner = _e2ebd_healthy_runner()
    values = _e2ebd_values_from(runner)

    # Numeric, not `unavailable` -- an always-unavailable reader fails here.
    assert values["gateway_pod"] == "dbagent-ingest-gateway-5f7@uid-gw-1"
    assert values["gateway_cpu_usage_usec"] == 910_000
    assert values["gateway_nr_throttled"] == 3
    assert values["gateway_throttled_usec"] == 5_500
    assert values["postgres_pod"] == "dbagent-postgresql-0@uid-pg-1"
    assert values["postgres_cpu_usage_usec"] == 250_000
    assert values["postgres_nr_throttled"] == 0
    assert values["postgres_throttled_usec"] == 0

    # Exact command shapes.
    pod_queries = [a for a in runner.calls if a[0] == "kubectl" and "pods" in a]
    assert len(pod_queries) == 4
    for argv in pod_queries:
        assert argv == [
            "kubectl", "-n", E2EBD_NAMESPACE, "get", "pods",
            "-l", E2EBD_RELEASE_SELECTOR, "-o", "json",
        ]
    execs = [a for a in runner.calls if a[0] == "kubectl" and "exec" in a]
    assert len(execs) == 4
    for argv in execs:
        assert argv[:4] == ["kubectl", "-n", E2EBD_NAMESPACE, "exec"]
        assert argv[4].startswith("pod/")
        assert argv[5] == "-c"
        assert argv[6] in (E2EBD_GATEWAY_COMPONENT, E2EBD_POSTGRES_COMPONENT)
        assert argv[7:10] == ["--", "/bin/sh", "-c"]
        script = argv[10]
        assert "/proc/self/cgroup" in script
        assert "/sys/fs/cgroup/cpu.stat" in script
        assert "/sys/fs/cgroup/cpuacct/cpuacct.usage" in script
    assert [a[4] for a in execs] == [
        "pod/dbagent-ingest-gateway-5f7", "pod/dbagent-postgresql-0",
        "pod/dbagent-ingest-gateway-5f7", "pod/dbagent-postgresql-0",
    ]
    # No local cgroup or procfs read: every command is a cluster/route command.
    assert {a[0] for a in runner.calls} == {"kubectl", "kind", "docker"}
    diag_src = E2EBD_DIAG_PATH.read_text(encoding="utf-8")
    for token in ("Path('/proc", 'Path("/proc', "Path('/sys", 'Path("/sys',
                  "open('/proc", 'open("/proc', "open('/sys", 'open("/sys'):
        assert token not in diag_src, token

    # First-item selection is red: the decoy pod is listed first.
    gateway_target, postgres_target = e2ediag.resolve_b1_pod_targets(_e2ebd_healthy_runner())
    assert gateway_target.name == "dbagent-ingest-gateway-5f7"
    assert gateway_target.container_name == E2EBD_GATEWAY_COMPONENT
    assert postgres_target.container_name == E2EBD_POSTGRES_COMPONENT
    assert "canary" not in (gateway_target.name + postgres_target.name)
    assert gateway_target.uid == "uid-gw-1" and gateway_target.container_id.endswith("uid-gw-1")

    # Two pods sharing one component label: no first-item guess.
    duplicate = json.loads(_e2ebd_pod_json())
    duplicate["items"].append(json.loads(_e2ebd_pod_json(gateway_name="dbagent-ingest-gateway-2nd",
                                                         gateway_uid="uid-gw-2"))["items"][1])
    dup_values = _e2ebd_values_from(
        _e2ebd_healthy_runner(pod_json=[json.dumps(duplicate)])
    )
    assert dup_values["gateway_pod"] == E2EBD_UNAVAILABLE
    assert dup_values["gateway_cpu_usage_usec"] == E2EBD_UNAVAILABLE

    # Identity churn between the exec and the re-resolution.
    churn = _e2ebd_healthy_runner(
        pod_json=[
            _e2ebd_pod_json(),
            _e2ebd_pod_json(gateway_uid="uid-gw-RESTARTED"),
        ]
    )
    churn_values = _e2ebd_values_from(churn)
    assert churn_values["gateway_pod"] == E2EBD_UNAVAILABLE
    assert churn_values["gateway_cpu_usage_usec"] == E2EBD_UNAVAILABLE

    # A non-Ready container, a non-Running pod and an empty runtime id are all
    # refused rather than guessed.
    for mutate in (
        lambda d: d["items"][1]["status"]["containerStatuses"][0].__setitem__("ready", False),
        lambda d: d["items"][1]["status"].__setitem__("phase", "Pending"),
        lambda d: d["items"][1]["status"]["containerStatuses"][0].__setitem__("containerID", ""),
        lambda d: d["items"][1]["metadata"].__setitem__("uid", ""),
        lambda d: d["items"][1]["status"]["containerStatuses"][0].__setitem__("name", "sidecar"),
    ):
        payload = json.loads(_e2ebd_pod_json())
        mutate(payload)
        broken = _e2ebd_values_from(_e2ebd_healthy_runner(pod_json=[json.dumps(payload)]))
        assert broken["gateway_pod"] == E2EBD_UNAVAILABLE
        assert broken["gateway_cpu_usage_usec"] == E2EBD_UNAVAILABLE
        # The PostgreSQL workload is a separate source and survives.
        assert broken["postgres_cpu_usage_usec"] == 250_000


def test_e2e_b1_runner_global_proc_source_is_labelled_and_exact():
    """FP-E2EB1D-3: whole-runner steal/PSI through the verified kind route."""
    runner = _e2ebd_healthy_runner()
    values = _e2ebd_values_from(runner)

    assert values["kind_node"] == E2EBD_KIND_NODE
    # 1500 - 1000 = 500 ticks at CLK_TCK=100 -> 5,000,000 microseconds.
    assert values["runner_steal_usec"] == 5_000_000
    for name in (
        "runner_psi_cpu_some_usec", "runner_psi_cpu_full_usec",
        "runner_psi_io_some_usec", "runner_psi_io_full_usec",
        "runner_psi_memory_some_usec", "runner_psi_memory_full_usec",
    ):
        assert values[name] == 200_000, name

    # Exact route commands, and nothing else.
    kind_calls = [a for a in runner.calls if a[0] == "kind"]
    docker_calls = [a for a in runner.calls if a[0] == "docker"]
    assert len(kind_calls) == 2 and len(docker_calls) == 2
    for argv in kind_calls:
        assert argv == ["kind", "get", "nodes", "--name", E2EBD_KIND_CLUSTER]
    for argv in docker_calls:
        assert argv[:3] == ["docker", "exec", E2EBD_KIND_NODE]
        assert argv[3:5] == ["/bin/sh", "-c"]
        script = argv[5]
        assert "/proc/stat" in script
        assert "/proc/pressure/cpu" in script
        assert "/proc/pressure/io" in script
        assert "/proc/pressure/memory" in script
        assert "getconf CLK_TCK" in script

    # The schema never claims node-container-cgroup scope.
    assert all(not name.startswith(E2EBD_RETIRED_FIELD_PREFIX) for name in E2EBD_FIELDS)
    assert e2ediag.B1_E2E_DIAGNOSTIC_FIELDS == E2EBD_FIELDS

    # Wrong / absent kind node: the route AND every runner field go dark.
    wrong = _e2ebd_values_from(_e2ebd_healthy_runner(kind_stdout="some-other-cluster-control-plane\n"))
    assert wrong["kind_node"] == E2EBD_UNAVAILABLE
    for name in E2EBD_FIELDS:
        if name.startswith("runner_"):
            assert wrong[name] == E2EBD_UNAVAILABLE, name
    # ... while the workload cgroups, a separate source, survive.
    assert wrong["gateway_cpu_usage_usec"] == 910_000

    # Two nodes returned by `kind get nodes` is not a route.
    two = _e2ebd_values_from(
        _e2ebd_healthy_runner(kind_stdout=f"{E2EBD_KIND_NODE}\nother-control-plane\n")
    )
    assert two["kind_node"] == E2EBD_UNAVAILABLE

    # Placement disagreement between the two workloads: no route at all.
    split_json = json.loads(_e2ebd_pod_json())
    split_json["items"][2]["spec"]["nodeName"] = "rca-e2e-worker"
    split = _e2ebd_values_from(_e2ebd_healthy_runner(pod_json=[json.dumps(split_json)]))
    assert split["kind_node"] == E2EBD_UNAVAILABLE
    assert split["runner_steal_usec"] == E2EBD_UNAVAILABLE

    # No local /proc fallback exists, even though it is equivalent today.
    diag_src = E2EBD_DIAG_PATH.read_text(encoding="utf-8")
    for token in ('"/proc/stat"', "'/proc/stat'", '"/proc/pressure', "'/proc/pressure"):
        assert token not in diag_src, token
    # PSI averages are never read: only `total=` has a closed-window meaning.
    assert "avg10" not in diag_src and "avg60" not in diag_src and "avg300" not in diag_src
    moving = _e2ebd_healthy_runner(
        runner=[
            _e2ebd_runner_payload(steal=1_000, psi_base=100_000, avg10="0.00"),
            _e2ebd_runner_payload(steal=1_000, psi_base=100_000, avg10="97.31"),
        ]
    )
    moved = _e2ebd_values_from(moving)
    assert moved["runner_steal_usec"] == 0          # a real zero
    assert moved["runner_psi_cpu_some_usec"] == 0   # averages moved; totals did not

    # The aggregate `cpu` row is the population, never the sum of per-CPU rows.
    per_cpu = _e2ebd_healthy_runner(
        runner=[
            _e2ebd_runner_payload(steal=1_000, psi_base=100_000, per_cpu_steal=10_000),
            _e2ebd_runner_payload(steal=1_500, psi_base=300_000, per_cpu_steal=90_000),
        ]
    )
    assert _e2ebd_values_from(per_cpu)["runner_steal_usec"] == 5_000_000

    # A missing `full` record affects only the three full fields.
    partial = _e2ebd_values_from(
        _e2ebd_healthy_runner(
            runner=[
                _e2ebd_runner_payload(steal=1_000, psi_base=100_000, full=False),
                _e2ebd_runner_payload(steal=1_500, psi_base=300_000, full=False),
            ]
        )
    )
    assert partial["runner_psi_cpu_some_usec"] == 200_000
    assert partial["runner_psi_cpu_full_usec"] == E2EBD_UNAVAILABLE
    assert partial["runner_steal_usec"] == 5_000_000

    # A malformed / missing CLK_TCK darkens only the steal field.
    for clk in ("", "0", "not-a-number"):
        bad_clk = _e2ebd_values_from(
            _e2ebd_healthy_runner(
                runner=[
                    _e2ebd_runner_payload(steal=1_000, psi_base=100_000, clk=clk),
                    _e2ebd_runner_payload(steal=1_500, psi_base=300_000, clk=clk),
                ]
            )
        )
        assert bad_clk["runner_steal_usec"] == E2EBD_UNAVAILABLE, clk
        assert bad_clk["runner_psi_io_some_usec"] == 200_000

    # A steal counter reset is a lost measurement, never a zero.
    reset = _e2ebd_values_from(
        _e2ebd_healthy_runner(
            runner=[
                _e2ebd_runner_payload(steal=9_000, psi_base=100_000),
                _e2ebd_runner_payload(steal=1_500, psi_base=300_000),
            ]
        )
    )
    assert reset["runner_steal_usec"] == E2EBD_UNAVAILABLE
    assert reset["runner_psi_cpu_some_usec"] == 200_000

    # The node exec itself failing leaves the verified route but no counters.
    failed = _e2ebd_values_from(_e2ebd_healthy_runner(failing={"runner"}))
    assert failed["kind_node"] == E2EBD_KIND_NODE
    assert failed["runner_steal_usec"] == E2EBD_UNAVAILABLE
    assert failed["runner_psi_memory_full_usec"] == E2EBD_UNAVAILABLE


def _e2ebd_pg_values(open_row: str, close_row: str) -> dict:
    """Two PostgreSQL boundary rows against otherwise-healthy sources."""
    runner = _e2ebd_healthy_runner(
        postgres=[
            _e2ebd_postgres_payload(open_row, _e2ebd_cgroup_v2(7_000_000, 0, 0), label="open"),
            _e2ebd_postgres_payload(close_row, _e2ebd_cgroup_v2(7_250_000, 0, 0), label="close"),
        ]
    )
    return _e2ebd_values_from(runner)


E2EBD_PG_FIELDS = (
    "pg_xact_commit_delta", "pg_wal_records_delta", "pg_wal_bytes_delta",
    "pg_wal_write_delta", "pg_wal_sync_delta", "pg_track_wal_io_timing",
    "pg_wal_write_time_ms_delta", "pg_wal_sync_time_ms_delta",
)


def test_e2e_b1_postgres_stats_parse_and_delta():
    """FP-E2EB1D-4: reset-safe PG/WAL/timing deltas, no in-window sampler."""
    runner = _e2ebd_healthy_runner()
    values = _e2ebd_values_from(runner)
    assert values["pg_xact_commit_delta"] == 600
    assert values["pg_wal_records_delta"] == 30
    assert values["pg_wal_bytes_delta"] == 4096
    assert values["pg_wal_write_delta"] == 4
    assert values["pg_wal_sync_delta"] == 3
    assert values["pg_track_wal_io_timing"] == "on"
    assert values["pg_wal_write_time_ms_delta"] == pytest.approx(2.5)
    assert values["pg_wal_sync_time_ms_delta"] == pytest.approx(6.5)

    # The literal invocation is pinned token by token, against literals typed
    # out here rather than read back from the module.
    postgres_exec = [
        a for a in runner.calls
        if a[0] == "kubectl" and "exec" in a and E2EBD_POSTGRES_COMPONENT in a
    ]
    assert len(postgres_exec) == 2
    for argv in postgres_exec:
        script = argv[10]
        for token in E2EBD_PSQL_TOKENS:
            assert token in script, token
        # The query connects to `postgres`, never to the measured database.
        assert "-d dbagent" not in script
        # One statement, no composition from a pod or environment value.
        assert script.count("psql ") == 1
        assert "$" not in script and "`" not in script
    # Open reads statistics FIRST, close reads them LAST.
    assert postgres_exec[0][10].index("pg_stats") < postgres_exec[0][10].index("cpu_stat_v2")
    assert postgres_exec[1][10].index("cpu_stat_v2") < postgres_exec[1][10].index("pg_stats")
    # No in-window sampler exists at all.
    diag_src = E2EBD_DIAG_PATH.read_text(encoding="utf-8")
    assert "pg_stat_activity" not in diag_src
    assert "wait_event" not in diag_src
    assert "Thread(" not in diag_src and "create_task" not in diag_src

    # An empty (SQL NULL) reset identity at BOTH boundaries is valid.
    both_empty = _e2ebd_pg_values(_e2ebd_pg_row(xact=10), _e2ebd_pg_row(xact=25))
    assert both_empty["pg_xact_commit_delta"] == 15
    # A populated, stable reset identity is equally valid.
    stamp = "2026-09-21 03:59:00+00"
    stable = _e2ebd_pg_values(
        _e2ebd_pg_row(xact=10, db_reset=stamp, wal_reset=stamp),
        _e2ebd_pg_row(xact=25, db_reset=stamp, wal_reset=stamp),
    )
    assert stable["pg_xact_commit_delta"] == 15
    assert stable["pg_wal_records_delta"] == 0

    # Empty -> timestamp, and a changed timestamp, invalidate their group only.
    later = "2026-09-21 04:10:00+00"
    for open_row, close_row, dark, lit in (
        (_e2ebd_pg_row(xact=10), _e2ebd_pg_row(xact=25, db_reset=stamp),
         "pg_xact_commit_delta", "pg_wal_records_delta"),
        (_e2ebd_pg_row(xact=10, db_reset=stamp), _e2ebd_pg_row(xact=25, db_reset=later),
         "pg_xact_commit_delta", "pg_wal_records_delta"),
        (_e2ebd_pg_row(xact=10, wal_reset=stamp), _e2ebd_pg_row(xact=25, wal_reset=later),
         "pg_wal_records_delta", "pg_xact_commit_delta"),
    ):
        grouped = _e2ebd_pg_values(open_row, close_row)
        assert grouped[dark] == E2EBD_UNAVAILABLE, dark
        assert grouped[lit] != E2EBD_UNAVAILABLE, lit
    # A WAL reset also darkens the timing fields it carries.
    wal_reset_values = _e2ebd_pg_values(
        _e2ebd_pg_row(wal_reset=stamp), _e2ebd_pg_row(wal_reset=later)
    )
    assert wal_reset_values["pg_wal_write_time_ms_delta"] == E2EBD_UNAVAILABLE

    # `off` timing is `unavailable`, never a zero.
    off = _e2ebd_pg_values(
        _e2ebd_pg_row(timing="off", write_ms=0.0, sync_ms=0.0),
        _e2ebd_pg_row(timing="off", write_ms=0.0, sync_ms=0.0),
    )
    assert off["pg_track_wal_io_timing"] == "off"
    assert off["pg_wal_write_time_ms_delta"] == E2EBD_UNAVAILABLE
    assert off["pg_wal_sync_time_ms_delta"] == E2EBD_UNAVAILABLE
    assert off["pg_xact_commit_delta"] == 0
    # A setting that changes mid-window darkens the setting and the timings.
    flipped = _e2ebd_pg_values(_e2ebd_pg_row(timing="on"), _e2ebd_pg_row(timing="off"))
    assert flipped["pg_track_wal_io_timing"] == E2EBD_UNAVAILABLE
    assert flipped["pg_wal_write_time_ms_delta"] == E2EBD_UNAVAILABLE

    # A whole SQL / row-shape failure darkens ALL PG-stat fields and nothing
    # else: the cgroup and runner sources are untouched.
    for broken_row in (
        "on|1|||||||",                       # nine columns
        "",                                  # zero rows
        _e2ebd_pg_row() + "\n" + _e2ebd_pg_row(),  # two rows
        _e2ebd_pg_row(xact="NaN"),           # non-counter
        _e2ebd_pg_row(timing="maybe"),       # not a boolean setting
        _e2ebd_pg_row(write_ms="-1.0"),      # negative timing
        _e2ebd_pg_row(db_reset="not-a-timestamp"),
    ):
        broken = _e2ebd_pg_values(broken_row, _e2ebd_pg_row(xact=2000))
        for name in E2EBD_PG_FIELDS:
            assert broken[name] == E2EBD_UNAVAILABLE, (name, broken_row)
        assert broken["gateway_cpu_usage_usec"] == 910_000
        assert broken["postgres_cpu_usage_usec"] == 250_000
        assert broken["runner_steal_usec"] == 5_000_000

    # A commit counter that goes backwards is a lost measurement.
    backwards = _e2ebd_pg_values(_e2ebd_pg_row(xact=9000), _e2ebd_pg_row(xact=10))
    assert backwards["pg_xact_commit_delta"] == E2EBD_UNAVAILABLE
    assert backwards["pg_wal_records_delta"] == 0


def _e2ebd_top_level_fields(line: str) -> "list[tuple[str, str]]":
    assert line.startswith(E2EBD_PREFIX), line[:60]
    body = line[len(E2EBD_PREFIX):]
    out = []
    for part in body.split(","):
        name, sep, value = part.partition("=")
        assert sep, part
        out.append((name, value))
    return out


def _e2ebd_statement_index(src: str, fn_name: str, needle: str) -> int:
    fn = _e2ebd_function(ast.parse(src), fn_name)
    for index, stmt in enumerate(fn.body):
        if needle in ast.unparse(stmt):
            return index
    raise AssertionError(f"{needle!r} not found at the top level of {fn_name}")


def test_e2e_b1_diagnostic_schema_is_canonical_and_comma_safe():
    """FP-E2EB1D-5: one exact 33-field line, before the kind p99 observation."""
    assert e2ediag.B1_E2E_DIAGNOSTIC_PREFIX == E2EBD_PREFIX
    assert e2ediag.B1_E2E_DIAGNOSTIC_UNAVAILABLE == E2EBD_UNAVAILABLE
    assert e2ediag.B1_E2E_DIAGNOSTIC_FIELDS == E2EBD_FIELDS
    assert len(E2EBD_FIELDS) == 33
    assert len(set(E2EBD_FIELDS)) == 33

    runner = _e2ebd_healthy_runner()
    opening = e2ediag.snapshot_e2e_b1_boundary("open", run=runner)
    closing = e2ediag.snapshot_e2e_b1_boundary("close", run=runner)
    result = e2e.PhaseResult(
        offered=6000, served=6000, errors=0,
        latencies_ms=[1.0] * 5939 + [1441.54] * 61,
        t0=0.0, t_last_complete=31.0, due0=0.0,
        max_in_flight=251, max_backlog=0, phase="baseline",
        status_codes=[202] * 6000,
        pre_dispatch_slip_ms=[0.1] * 6000,
        start_lag_ms=[1.2] * 6000,
        attempt_duration_ms=[1440.24] * 6000,
    )
    values = e2ediag.build_e2e_b1_diagnostic_values(result, opening, closing)
    line = e2ediag.serialize_e2e_b1_diagnostics(values)

    assert "\n" not in line and "\r" not in line
    fields = _e2ebd_top_level_fields(line)
    assert [name for name, _v in fields] == list(E2EBD_FIELDS)
    rendered = dict(fields)
    assert rendered["schema"] == "1"
    assert rendered["offered"] == "6000"
    assert rendered["p99_ms"] == "1441.540"
    assert rendered["p99_leg_split_ms"] == "0.100/1.200/1440.240"
    assert rendered["status_histogram"] == "202:6000"
    assert rendered["max_in_flight"] == "251"
    assert rendered["kind_node"] == E2EBD_KIND_NODE
    assert rendered["pg_wal_write_time_ms_delta"] == "2.500"

    # A hostile value cannot forge a top-level boundary.
    hostile = dict(values)
    hostile["gateway_pod"] = "pod,x=1\r\n100% 2026-09-21T03:59:00Z MainThread"
    hostile_line = e2ediag.serialize_e2e_b1_diagnostics(hostile)
    hostile_fields = _e2ebd_top_level_fields(hostile_line)
    assert [name for name, _v in hostile_fields] == list(E2EBD_FIELDS)
    encoded = dict(hostile_fields)["gateway_pod"]
    for token in ("%2C", "%3D", "%0D", "%0A", "%25", "%20"):
        assert token in encoded, token
    assert "," not in encoded and "=" not in encoded
    assert "\n" not in hostile_line and "\r" not in hostile_line
    assert encoded == _quote(
        hostile["gateway_pod"], safe="-._~:+/;@", encoding="utf-8"
    )

    # Missing, extra, reordered, empty, nonfinite and boolean members are red.
    for mutant in (
        {k: v for k, v in values.items() if k != "kind_node"},
        {**values, "node_steal_usec": 1},
        dict(reversed(list(values.items()))),
        {**values, "kind_node": ""},
        {**values, "p99_ms": float("inf")},
        {**values, "p99_ms": float("nan")},
        {**values, "offered": -1},
        {**values, "offered": True},
        {**values, "offered": None},
    ):
        with pytest.raises((ValueError, TypeError)):
            e2ediag.serialize_e2e_b1_diagnostics(mutant)
    # The old node_* naming can never be reintroduced through the field tuple.
    renamed = {
        ("node_steal_usec" if k == "runner_steal_usec" else k): v for k, v in values.items()
    }
    with pytest.raises(ValueError):
        e2ediag.serialize_e2e_b1_diagnostics(renamed)

    # Total source failure still yields a complete, well-formed line.
    blank = e2ediag.build_e2e_b1_diagnostic_values(
        None, e2ediag.unavailable_snapshot("open"), e2ediag.unavailable_snapshot("close")
    )
    blank_line = e2ediag.serialize_e2e_b1_diagnostics(blank)
    blank_fields = _e2ebd_top_level_fields(blank_line)
    assert [name for name, _v in blank_fields] == list(E2EBD_FIELDS)
    assert [v for n, v in blank_fields if n != "schema"] == [E2EBD_UNAVAILABLE] * 32
    assert blank_line == e2ediag.fallback_e2e_b1_diagnostic_line()

    # The record is printed BEFORE the p99 binding and its observation, and
    # AFTER the legacy baseline fingerprint print. The full five-way order is
    # legacy print < emit < p99 binding < observation < first correctness assert.
    load_src = E2E_TEST.read_text(encoding="utf-8")
    emit_at = _e2ebd_statement_index(load_src, "test_b1_ingest_burst_profile", "diagnostics.emit(baseline)")
    observation_at = _e2ebd_statement_index(
        load_src,
        "test_b1_ingest_burst_profile",
        "record_property('b1_kind_p99_lt_150_ms', p99 < P99_MS)",
    )
    binding_at = _e2ebd_statement_index(load_src, "test_b1_ingest_burst_profile", "p99 = baseline.p99")
    legacy_at = _e2ebd_statement_index(load_src, "test_b1_ingest_burst_profile", "phase=baseline,max_lateness_ms=")
    first_assert_at = _e2ebd_statement_index(
        load_src, "test_b1_ingest_burst_profile", "assert served + errors == 6000"
    )
    assert legacy_at < emit_at < binding_at < observation_at < first_assert_at


class E2EBDRaisingStream:
    def __init__(self, exc=OSError("stdout is gone")):
        self.exc = exc
        self.written: list[str] = []

    def write(self, text):
        raise self.exc

    def flush(self):
        raise self.exc


def _e2ebd_core(result) -> dict:
    """The part of a baseline result two separate executions must agree on.

    Counts and codes only. `max_backlog` and `max_in_flight` are deliberately
    absent: they are dispatcher peaks read off a real clock and a real task
    queue, so two honest runs of the same baseline differ every few dozen
    executions (CI 35568809898). `_e2ebd_peak_failures` checks those instead.
    The latency SAMPLES are absent for the same reason, and the two guards
    that stand in for them are `_e2ebd_boundary_1_handler_failures` (the
    handler cannot reach them) and `_e2ebd_p99_consistency_failures` (the
    summary a run reports is the percentile of that run's own samples).
    """
    return {
        "offered": result.offered,
        "served": result.served,
        "errors": result.errors,
        "status_codes": list(result.status_codes),
        "latency_count": len(result.latencies_ms),
    }


def _e2ebd_peak_failures(result, *, offered: int, rate: float) -> "list[str]":
    """Shape of the two dispatcher peaks, checked within ONE run.

    `max_in_flight` counts measured dispatches that have not completed, so
    `1 <= max_in_flight <= offered` holds by construction whatever the
    scheduler does. `max_backlog` counts schedule slots the dispatcher is
    behind; its only construction-guaranteed ceiling is the window it was
    measured in (measured here: a 20 ms stall inside a 12 ms window drives it
    to 39, well past `offered`, so `offered` is NOT a safe bound).
    """
    fails: list[str] = []
    backlog, in_flight = result.max_backlog, result.max_in_flight
    span_slots = _math.ceil(max(0.0, result.t_last_complete - result.due0) * rate)
    if type(backlog) is not int or not 0 <= backlog <= span_slots:
        fails.append(f"max_backlog={backlog!r} is not an int in 0..{span_slots}")
    if type(in_flight) is not int or not 1 <= in_flight <= offered:
        fails.append(f"max_in_flight={in_flight!r} is not an int in 1..{offered}")
    return fails


#: The three diagnostic keywords of the baseline's `PhaseResult(...)`. Every
#: OTHER keyword of that call names a measured value, and the set of locals
#: feeding them is read off the carrier itself rather than listed here, so a
#: renamed local is carried INTO the protected set instead of out of it.
E2EBD_LEG_KEYWORDS = ("pre_dispatch_slip_ms", "start_lag_ms", "attempt_duration_ms")
#: The measured keywords the guard refuses to accept as unprotected: each must
#: be present and built from at least one local, or the pin below is vacuous.
E2EBD_ORACLE_KEYWORDS = ("offered", "served", "errors", "latencies_ms", "status_codes")


def _e2ebd_bindings(node: ast.AST) -> "tuple[set[str], list[str]]":
    """Every name a subtree binds: plain `Name` stores, and any other form."""
    plain: set[str] = set()
    other: list[str] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store):
            plain.add(child.id)
        elif isinstance(child, ast.Name) and isinstance(child.ctx, ast.Del):
            other.append(f"del {child.id}")
        elif isinstance(child, (ast.Attribute, ast.Subscript)) and isinstance(
            child.ctx, (ast.Store, ast.Del)
        ):
            other.append(ast.unparse(child))
        elif isinstance(child, (ast.Import, ast.ImportFrom, ast.Global, ast.Nonlocal)):
            other.append(ast.unparse(child))
        elif isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            other.append(f"{type(child).__name__} {child.name}")
    return plain, other


def _e2ebd_boundary_1_handler_failures(src: str) -> "list[str]":
    """Structure of boundary 1's fail-soft handler in the e2e carrier.

    `_e2ebd_core` compares counts and codes, so a handler that RESCALED the
    latency samples -- every count, code and peak identical, p99 x 1000 --
    satisfied every check in this file (measured on this stub: a reported
    1261 ms against a 1.11 ms control). Cross-run equality of the values
    cannot close that: they are wall-clock and two honest runs differ, which
    is the flake beeec34 removed. What is checkable without a clock is that
    the handler cannot reach them at all -- it may rebind the three
    diagnostic leg vectors and nothing else, and may not so much as NAME any
    local the baseline's `return PhaseResult(...)` is built from.
    """
    fails: list[str] = []
    try:
        tree = ast.parse(src)
    except SyntaxError as exc:
        return [f"the e2e profile carrier no longer parses: {exc}"]
    generator = _e2ebd_function(tree, "run_open_loop_baseline")

    returns = [
        n for n in ast.walk(generator)
        if isinstance(n, ast.Return)
        and isinstance(n.value, ast.Call)
        and ast.unparse(n.value.func) == "PhaseResult"
    ]
    if len(returns) != 1:
        return [f"{len(returns)} `return PhaseResult(...)` in the baseline, want 1"]
    built = returns[0].value
    legs: set[str] = set()
    protected: set[str] = _e2ebd_name_ids(built.func)
    supplied = {k.arg for k in built.keywords}
    for keyword in built.keywords:
        if keyword.arg in E2EBD_LEG_KEYWORDS:
            legs |= _e2ebd_name_ids(keyword.value)
        else:
            protected |= _e2ebd_name_ids(keyword.value)
    protected -= legs
    if legs != set(E2EBD_LEG_KEYWORDS):
        fails.append(
            f"the diagnostic vectors are fed by {sorted(legs)}, "
            f"want {sorted(E2EBD_LEG_KEYWORDS)}"
        )
    for name in E2EBD_ORACLE_KEYWORDS:
        if name not in supplied:
            fails.append(f"the baseline no longer passes {name}= to PhaseResult")
    for keyword in built.keywords:
        if keyword.arg in E2EBD_ORACLE_KEYWORDS and not _e2ebd_name_ids(keyword.value):
            fails.append(f"{keyword.arg}= is built from no local this guard can protect")

    # The boundary-1 block is the try whose OWN body derives the leg vectors;
    # the generator's outer try/finally (the client close) also contains that
    # call, several levels down, and is not it.
    guarded = [
        n for n in ast.walk(generator)
        if isinstance(n, ast.Try)
        and any(
            isinstance(stmt, ast.Assign) and "derive_leg_vectors" in ast.unparse(stmt.value)
            for stmt in n.body
        )
    ]
    if len(guarded) != 1:
        fails.append(f"{len(guarded)} try blocks guard derive_leg_vectors directly, want 1")
        return fails
    block = guarded[0]
    if len(block.body) != 1:
        fails.append(
            f"boundary 1 guards {len(block.body)} statements; only the derivation is fail-soft"
        )
    if block.orelse or block.finalbody:
        fails.append("boundary 1 grew an else/finally clause")
    if len(block.handlers) != 1:
        fails.append(f"boundary 1 has {len(block.handlers)} handlers, want 1")
        return fails

    handler = block.handlers[0]
    caught = ast.unparse(handler.type) if handler.type is not None else "everything"
    if caught != "Exception":
        fails.append(f"boundary 1 catches {caught}, want Exception")
    if handler.name is not None:
        fails.append(f"boundary 1 binds the exception as {handler.name!r}")
    body = ast.Module(body=list(handler.body), type_ignores=[])
    bound, exotic = _e2ebd_bindings(body)
    stray = sorted(bound - legs)
    if stray:
        fails.append(
            f"boundary 1's handler binds {stray}; only {sorted(legs)} are its to write"
        )
    for form in exotic:
        fails.append(f"boundary 1's handler binds through {form!r}")
    reachable = sorted(_e2ebd_name_ids(body) & protected)
    if reachable:
        fails.append(f"boundary 1's handler names the measured {reachable}")
    calls = [ast.unparse(n.func) for n in ast.walk(body) if isinstance(n, ast.Call)]
    if calls:
        fails.append(
            f"boundary 1's handler calls {calls}; it may only rebind the three vectors"
        )
    return fails


def _e2ebd_p99_consistency_failures(result, *, label: str) -> "list[str]":
    """Within ONE run: each reported summary is a statistic of its own samples.

    Deterministic, and never a comparison between two runs: the samples are
    wall-clock, but the relation between a run's samples and the numbers it
    reports about them is arithmetic. Recomputed with the shipped reference
    helper, which no copy of the carrier can reach.
    """
    fails: list[str] = []
    samples = list(result.latencies_ms)
    expected = ref.nearest_rank_p99(samples)
    if result.p99 != expected:
        fails.append(
            f"{label}: p99={result.p99!r} is not the nearest-rank percentile "
            f"{expected!r} of its own {len(samples)} samples"
        )
    if samples and result.max_lateness_ms != max(samples):
        fails.append(
            f"{label}: max_lateness_ms={result.max_lateness_ms!r} is not the "
            f"largest of its own samples ({max(samples)!r})"
        )
    return fails


def _e2ebd_assert_boundary_1_preserved(faulted, control, *, offered: int) -> None:
    """Everything a boundary-1 diagnostic fault must leave untouched.

    Equality for what the fault cannot touch, shape for what the OS scheduler
    owns. Both peaks are produced before the guarded derivation runs, so
    fail-soft can only be observed to have left them well-formed -- requiring
    the faulted run to REPRODUCE them asserted that the scheduler is
    deterministic, which is the defect this split fixes. The latency samples
    are wall-clock too, so what is required of them is the same kind of
    within-run statement: the summaries each run reports are that run's own.
    """
    assert _e2ebd_core(faulted) == _e2ebd_core(control)
    assert _e2ebd_peak_failures(faulted, offered=offered, rate=E2EBD_STUB_RATE) == []
    assert _e2ebd_peak_failures(control, offered=offered, rate=E2EBD_STUB_RATE) == []
    assert _e2ebd_p99_consistency_failures(faulted, label="faulted") == []
    assert _e2ebd_p99_consistency_failures(control, label="control") == []


def test_e2e_b1_diagnostics_fail_soft_at_each_boundary():
    """FP-E2EB1D-1/2/3/4/7/8: four independent boundaries, none reaching the oracle."""
    measured = 24

    # --- boundary 1: the in-generator derivation wrapper -------------------
    control, _t, _m = _e2ebd_run_baseline(e2e, measured=measured, prologue=4)
    assert len(control.pre_dispatch_slip_ms) == measured
    control_line = e2ediag.serialize_e2e_b1_diagnostics(
        e2ediag.build_e2e_b1_diagnostic_values(
            control, e2ediag.unavailable_snapshot("open"), e2ediag.unavailable_snapshot("close")
        )
    )
    assert "p99_leg_split_ms=unavailable" not in control_line
    assert "leg_p99s_ms=unavailable" not in control_line

    def _raise(*args, **kwargs):
        raise RuntimeError("helper drift")

    original = e2e.derive_leg_vectors
    try:
        e2e.derive_leg_vectors = _raise
        degraded, _t2, _m2 = _e2ebd_run_baseline(e2e, measured=measured, prologue=4)
    finally:
        e2e.derive_leg_vectors = original
    _e2ebd_assert_boundary_1_preserved(degraded, control, offered=measured)
    assert _math.isfinite(degraded.p99) and _math.isfinite(control.p99)
    assert degraded.pre_dispatch_slip_ms == []
    assert degraded.start_lag_ms == []
    assert degraded.attempt_duration_ms == []
    degraded_values = e2ediag.build_e2e_b1_diagnostic_values(
        degraded, e2ediag.unavailable_snapshot("open"), e2ediag.unavailable_snapshot("close")
    )
    assert degraded_values["p99_leg_split_ms"] == E2EBD_UNAVAILABLE
    assert degraded_values["leg_p99s_ms"] == E2EBD_UNAVAILABLE
    assert degraded_values["p99_ms"] == degraded.p99
    assert degraded_values["status_histogram"] == "202:24"

    # Named red mutation: removing the wrapper lets the exception abort the
    # baseline, so the unchanged assertions are never reached.
    profile_src, diag_src, load_src = _e2ebd_sources()
    unwrapped = profile_src.replace(
        "        try:\n"
        "            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = derive_leg_vectors(",
        "        if True:\n"
        "            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = derive_leg_vectors(",
        1,
    ).replace(
        "        except Exception:  # noqa: BLE001 -- diagnostic only, never the oracle\n"
        "            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = [], [], []\n",
        "",
        1,
    )
    assert unwrapped != profile_src
    mutant = _e2ebd_exec_profile(unwrapped, "b1_e2e_profile_unwrapped_mutant")
    mutant.derive_leg_vectors = _raise
    with pytest.raises(RuntimeError):
        _e2ebd_run_baseline(mutant, measured=measured, prologue=4)

    # KeyboardInterrupt and SystemExit are never converted into output.
    for escalating in (KeyboardInterrupt, SystemExit):
        def _escalate(*args, **kwargs):
            raise escalating("stop")

        try:
            e2e.derive_leg_vectors = _escalate
            with pytest.raises(escalating):
                _e2ebd_run_baseline(e2e, measured=4, prologue=1)
        finally:
            e2e.derive_leg_vectors = original

    # --- boundary 2: each snapshot callback, independently ------------------
    def _raising_runner(argv, **kwargs):
        raise RuntimeError("kubectl exploded")

    for label in ("open", "close"):
        snapshot = e2ediag.safe_snapshot_e2e_b1_boundary(label, run=_raising_runner)
        assert snapshot.gateway is None and snapshot.runner is None
        assert snapshot.postgres_stats is None and snapshot.kind_node is None

    healthy = _e2ebd_healthy_runner()
    good_open = e2ediag.snapshot_e2e_b1_boundary("open", run=healthy)
    session = e2ediag.B1E2EDiagnosticSession(run=_raising_runner)
    session.open()
    session.close()
    out = _io.StringIO()
    line = session.emit(control, stdout=out, artifact_writer=lambda text: True)
    assert line.startswith(E2EBD_PREFIX)
    assert out.getvalue() == line + "\n"
    assert dict(_e2ebd_top_level_fields(line))["gateway_pod"] == E2EBD_UNAVAILABLE
    assert dict(_e2ebd_top_level_fields(line))["p99_ms"] != E2EBD_UNAVAILABLE

    # One failing boundary never erases the other, and a valid controlled
    # fixture must still be numeric -- an always-unavailable reader is red.
    half = e2ediag.B1E2EDiagnosticSession(run=_raising_runner)
    half._opening = good_open
    half.close()
    half_values = e2ediag.build_e2e_b1_diagnostic_values(control, half.opening, half.closing)
    assert half_values["gateway_pod"] == E2EBD_UNAVAILABLE
    both = _e2ebd_healthy_runner()
    full = e2ediag.B1E2EDiagnosticSession(run=both)
    full.open()
    full.close()
    full_values = e2ediag.build_e2e_b1_diagnostic_values(control, full.opening, full.closing)
    assert full_values["gateway_cpu_usage_usec"] == 910_000
    assert full_values["runner_steal_usec"] == 5_000_000
    assert full_values["pg_xact_commit_delta"] == 600

    # --- boundary 3: renderer and stdout ------------------------------------
    class Exploding:
        offered = 1

        def __getattr__(self, name):
            raise RuntimeError("result is poisoned")

    fallback_out = _io.StringIO()
    fallback_line = full.emit(
        Exploding(), stdout=fallback_out, artifact_writer=lambda text: True
    )
    assert fallback_line == e2ediag.fallback_e2e_b1_diagnostic_line()
    assert fallback_out.getvalue() == fallback_line + "\n"
    assert [n for n, _v in _e2ebd_top_level_fields(fallback_line)] == list(E2EBD_FIELDS)

    stdout_line = full.emit(
        control, stdout=E2EBDRaisingStream(), artifact_writer=lambda text: True
    )
    assert stdout_line.startswith(E2EBD_PREFIX)

    # --- boundary 4: the artifact writer ------------------------------------
    def _raising_writer(text):
        raise OSError("read-only filesystem")

    writer_out = _io.StringIO()
    writer_line = full.emit(control, stdout=writer_out, artifact_writer=_raising_writer)
    assert writer_out.getvalue() == writer_line + "\n"
    assert e2ediag.write_e2e_b1_diagnostic_artifact(
        writer_line, path=Path("/proc/definitely-not-writable/x.txt")
    ) is False


def test_e2e_b1_diagnostics_boundary_1_check_survives_dispatcher_jitter():
    """Regression for CI 35568809898.

    The boundary-1 case above runs the same baseline twice and requires the
    faulted run to reproduce the control's core result. `max_backlog` and
    `max_in_flight` are dispatcher peaks read off a real clock and a real task
    queue, so two honest runs differ every few dozen executions -- CI reported
    ``{'max_backlog': 1} != {'max_backlog': 2}`` with the other five items
    identical. Both peaks are computed BEFORE boundary 1's try/except can run,
    so fail-soft cannot change them; what the check must prove about them is
    their shape, and what it must prove by equality is the counts and codes.
    """
    measured = 24
    prologue = 4

    def _raise(*args, **kwargs):
        raise RuntimeError("helper drift")

    control, _t, _m = _e2ebd_run_baseline(e2e, measured=measured, prologue=prologue)

    # (a) The exact CI divergence, injected: a run identical to the control
    # except that the scheduler let each peak land one slot away. Both twins
    # are clamped into the band a real run of this shape can produce, so the
    # only thing under test is that a one-slot difference is not a fault.
    span_slots = _math.ceil(
        (control.t_last_complete - control.due0) * E2EBD_STUB_RATE
    )
    twins = [
        _replace(
            control,
            max_backlog=min(span_slots, control.max_backlog + 1),
            max_in_flight=min(measured, control.max_in_flight + 1),
        ),
        _replace(
            control,
            max_backlog=max(0, control.max_backlog - 1),
            max_in_flight=max(1, control.max_in_flight - 1),
        ),
    ]
    # Non-vacuous by construction: `max_in_flight` cannot be both 1 and
    # `measured`, so the clamps can never collapse BOTH twins onto the control.
    assert any(
        (t.max_backlog, t.max_in_flight)
        != (control.max_backlog, control.max_in_flight)
        for t in twins
    ), (control.max_backlog, control.max_in_flight, span_slots)
    for twin in twins:
        _e2ebd_assert_boundary_1_preserved(twin, control, offered=measured)

    # (b) The same divergence produced by the real dispatcher rather than by
    # construction: a blocking stall on the second measured request puts the
    # faulted run ten slots behind its schedule. The fault at boundary 1 is
    # the shipped one, so this is the boundary-1 case with the scheduling
    # difference forced instead of waited for.
    original = e2e.derive_leg_vectors
    try:
        e2e.derive_leg_vectors = _raise
        stalled, _t2, _m2 = _e2ebd_run_baseline(
            e2e,
            measured=measured,
            prologue=prologue,
            # 1 warmup + `prologue` prologue requests precede the window.
            transport=E2EBDStallingStubTransport(stall_at=1 + prologue + 1),
        )
    finally:
        e2e.derive_leg_vectors = original
    # The forcing is real, and bounded from BELOW only -- an upper bound, or a
    # comparison against the control's own peak, would put this test back on
    # the scheduler. `time.sleep` never returns early, so a longer stall can
    # only raise this number (measured: 9 or 10 over 200 runs, against 1 or 2
    # unstalled, so half the stall width is a bound with room to spare).
    assert stalled.max_backlog >= E2EBD_STALL_SLOTS // 2, stalled.max_backlog
    assert stalled.pre_dispatch_slip_ms == []
    _e2ebd_assert_boundary_1_preserved(stalled, control, offered=measured)

    # (c) It still discriminates. Every value boundary 1 must preserve is
    # checked, and a faulted run that changed one is red.
    for broken in (
        _replace(control, offered=measured - 1),
        _replace(control, served=control.served - 1),
        _replace(control, errors=control.errors + 1),
        _replace(control, status_codes=[503] + list(control.status_codes)[1:]),
        _replace(control, latencies_ms=list(control.latencies_ms)[:-1]),
    ):
        with pytest.raises(AssertionError):
            _e2ebd_assert_boundary_1_preserved(broken, control, offered=measured)

    # ... and so is a run whose peaks are no longer well-formed counters.
    for peaks in (
        {"max_backlog": -1},
        {"max_backlog": 2.0},
        {"max_backlog": True},
        {"max_in_flight": 0},
        {"max_in_flight": measured + 1},
        {"max_in_flight": None},
    ):
        with pytest.raises(AssertionError):
            _e2ebd_assert_boundary_1_preserved(
                _replace(control, **peaks), control, offered=measured
            )


def test_e2e_b1_boundary_1_cannot_reach_the_measured_values():
    """Regression for review-fix-e2ebd-flaky-test S1 (pre-existing at 8e5dbcf).

    The boundary-1 case projects a faulted run onto counts and codes, so a
    diagnostic fault that rescaled the latency samples, or rewrote the p99
    the run reports, satisfied every assertion this file made. Neither hole
    can be closed by comparing values across two runs -- they are wall-clock.
    Two guards close them without a clock: the handler is structurally unable
    to reach anything the result is built from, and within one run the
    summaries reported are statistics of that run's own samples.

    The two mutants below are complementary, which is why both guards are
    needed: rescaling the samples keeps the p99 self-consistent (only the
    structural pin sees it), and rewriting the p99 leaves the samples honest
    (only the within-run check sees it).
    """
    measured = 24
    prologue = 4
    profile_src, _diag_src, _load_src = _e2ebd_sources()
    assert _e2ebd_boundary_1_handler_failures(profile_src) == []

    # The shipped handler's body, verbatim and unique: each mutant is that
    # handler plus exactly one statement.
    anchor = "            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = [], [], []\n"
    assert profile_src.count(anchor) == 1

    def _raise(*args, **kwargs):
        raise RuntimeError("helper drift")

    control, _t, _m = _e2ebd_run_baseline(e2e, measured=measured, prologue=prologue)
    assert _e2ebd_p99_consistency_failures(control, label="control") == []

    for label, statement, named, samples_rewritten in (
        (
            "rescaled_samples",
            "            latencies = [value * 1000.0 for value in latencies]\n",
            "latencies",
            True,
        ),
        (
            "rewritten_p99",
            "            PhaseResult.p99 = property("
            "lambda self: nearest_rank_p99(self.latencies_ms) * 1000.0)\n",
            "PhaseResult",
            False,
        ),
    ):
        mutated = profile_src.replace(anchor, anchor + statement, 1)
        assert mutated != profile_src, label
        failures = _e2ebd_boundary_1_handler_failures(mutated)
        assert failures != [], label
        assert any(named in f for f in failures), (label, failures)

        module = _e2ebd_exec_profile(mutated, f"b1_e2e_profile_{label}_mutant")
        module.derive_leg_vectors = _raise
        faulted, _t2, _m2 = _e2ebd_run_baseline(
            module, measured=measured, prologue=prologue
        )
        assert faulted.pre_dispatch_slip_ms == [], label

        # Not cosmetic, and stated entirely within the faulted run: it reports
        # a p99 larger than the whole window it was measured in, which no
        # latency of that window can be (every sample is a completion inside
        # `due0 .. t_last_complete`). Nothing here asks the scheduler to
        # reproduce anything, so it cannot flake on a busy machine.
        span_ms = (faulted.t_last_complete - faulted.due0) * 1000.0
        assert faulted.p99 > span_ms, (label, faulted.p99, span_ms)
        assert (max(faulted.latencies_ms) > span_ms) is samples_rewritten, label

        # ... and every check that existed before still accepts it.
        assert _e2ebd_core(faulted) == _e2ebd_core(control), label
        assert _e2ebd_peak_failures(
            faulted, offered=measured, rate=E2EBD_STUB_RATE
        ) == [], label
        values = e2ediag.build_e2e_b1_diagnostic_values(
            faulted,
            e2ediag.unavailable_snapshot("open"),
            e2ediag.unavailable_snapshot("close"),
        )
        assert values["p99_ms"] == faulted.p99, label
        assert values["status_histogram"] == f"202:{measured}", label
        assert values["p99_leg_split_ms"] == E2EBD_UNAVAILABLE, label
        assert e2ediag.serialize_e2e_b1_diagnostics(values).startswith(E2EBD_PREFIX)

        consistency = _e2ebd_p99_consistency_failures(faulted, label=label)
        assert (consistency == []) is samples_rewritten, (label, consistency)
        if samples_rewritten:
            # Still accepted by everything that runs the two baselines: the
            # rescale is self-consistent, so the structural pin is the only
            # thing that sees it. That is the whole reason the pin exists.
            _e2ebd_assert_boundary_1_preserved(faulted, control, offered=measured)
        else:
            with pytest.raises(AssertionError):
                _e2ebd_assert_boundary_1_preserved(faulted, control, offered=measured)

    # The pin is not satisfied by accident: a handler that binds one more
    # name, catches more than `Exception`, keeps the exception alive, widens
    # what it guards, or calls anything at all is red.
    for widened in (
        profile_src.replace(anchor, anchor + "            codes = codes\n", 1),
        profile_src.replace(anchor, anchor + "            spare = 1\n", 1),
        profile_src.replace(anchor, anchor + "            del rate\n", 1),
        profile_src.replace(anchor, anchor + "            import math as _m\n", 1),
        profile_src.replace(anchor, anchor + "            latencies.clear()\n", 1),
        profile_src.replace(
            "        except Exception:  # noqa: BLE001 -- diagnostic only, never the oracle\n",
            "        except BaseException as exc:  # widened\n",
            1,
        ),
        profile_src.replace(
            "        try:\n"
            "            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = derive_leg_vectors(",
            "        try:\n"
            "            served = sum(1 for o in outcomes if o == 'served')\n"
            "            pre_dispatch_slip_ms, start_lag_ms, attempt_duration_ms = derive_leg_vectors(",
            1,
        ),
    ):
        assert widened != profile_src
        assert _e2ebd_boundary_1_handler_failures(widened) != []

    # A carrier that stopped building the result from locals cannot make the
    # protected set empty and pass vacuously.
    hollowed = profile_src.replace("            latencies_ms=latencies,\n", "", 1)
    assert hollowed != profile_src
    assert _e2ebd_boundary_1_handler_failures(hollowed) != []


def test_e2e_b1_diagnostic_module_has_no_popen_or_environment_read():
    """FP-E2EB1D-7/8: the new module is bounded, injectable and env-free.

    `test_b1_output_capture_ownership` keeps its fixed three-source list and
    the existing no-environment loop covers the two profile files, so neither
    of them sees `b1_e2e_diagnostics.py`. This test applies the same two
    shipped AST predicates to it directly.
    """
    diag_src = E2EBD_DIAG_PATH.read_text(encoding="utf-8")
    tree = ast.parse(diag_src)

    assert not _source_has_environ_read(diag_src)
    assert not any(
        isinstance(n, ast.Call) and _call_func_name(n) == "Popen" for n in ast.walk(tree)
    )
    # A Popen or an environment read in this module must be caught here.
    assert _source_has_environ_read(diag_src + "\nimport os\nX = os.environ.get('E2E')\n")
    popen_mutant = ast.parse(diag_src + "\nproc = subprocess.Popen(['kubectl'])\n")
    assert any(
        isinstance(n, ast.Call) and _call_func_name(n) == "Popen"
        for n in ast.walk(popen_mutant)
    )
    # Token scans run over prose-free source: a comment that explains why a
    # token is forbidden must not itself trip the scan.
    code = _gc4_prose_free(diag_src)
    for token in ("threading", "Thread(", "asyncio", "create_task", "signal.", "os.fork"):
        assert token not in code, token

    # Exactly one call site invokes the injected runner, and it is not in a
    # loop: there is no retry anywhere.
    runner_calls = [
        n for n in ast.walk(tree)
        if isinstance(n, ast.Call) and _call_func_name(n) == "run"
    ]
    assert len(runner_calls) == 1, [ast.unparse(n) for n in runner_calls]
    call = runner_calls[0]
    kwargs = {k.arg: ast.unparse(k.value) for k in call.keywords}
    assert kwargs == {
        "capture_output": "True",
        "text": "True",
        "check": "False",
        "timeout": "DIAGNOSTIC_COMMAND_TIMEOUT_S",
    }
    enclosing = _e2ebd_function(tree, "_run_command")
    assert call in list(ast.walk(enclosing))
    assert not any(isinstance(n, (ast.For, ast.While, ast.AsyncFor)) for n in ast.walk(enclosing))
    for token in ("retry", "retries", "backoff", "attempt_again", "reconnect", "time.sleep"):
        assert token not in code, token
    assert e2ediag.DIAGNOSTIC_COMMAND_TIMEOUT_S == E2EBD_COMMAND_TIMEOUT_S

    # Exactly twelve commands for a complete two-boundary collection, each
    # with the exact keyword set, and a bounded 60 s worst case inside the
    # pinned 420 s pytest_e2e phase budget.
    runner = _e2ebd_healthy_runner()
    session = e2ediag.B1E2EDiagnosticSession(run=runner)
    session.open()
    assert len(runner.calls) == E2EBD_COMMANDS_PER_BOUNDARY
    session.close()
    assert len(runner.calls) == E2EBD_TOTAL_COMMANDS
    assert all(kw == E2EBD_RUN_KWARGS for kw in runner.kwargs)
    assert E2EBD_TOTAL_COMMANDS * E2EBD_COMMAND_TIMEOUT_S == 60.0
    assert 60.0 < 420.0

    # A timeout is a missing source, not a retry and not an exception.
    def _timeout_runner(argv, **kwargs):
        raise subprocess.TimeoutExpired(list(argv), E2EBD_COMMAND_TIMEOUT_S)

    timed_out = e2ediag.snapshot_e2e_b1_boundary("open", run=_timeout_runner)
    assert timed_out.gateway is None and timed_out.runner is None
    # The module's own default is the real subprocess.run, injected once.
    constructor = _e2ebd_function(tree, "__init__")
    defaults = [ast.unparse(d) for d in constructor.args.kw_defaults if d is not None]
    assert "subprocess.run" in defaults


def _e2ebd_segment_digest(src: str, node: ast.AST) -> str:
    return hashlib.sha256(
        ast.get_source_segment(src, node, padded=True).encode("utf-8")
    ).hexdigest()


def _e2ebd_reported_only_failures(load_src: str, profile_src: str, ci_text: str) -> "list[str]":
    """Nothing diagnostic may touch the verdict, the legacy report or a knob."""
    fails: list[str] = []
    try:
        tree = ast.parse(load_src)
    except SyntaxError as exc:
        return [f"live e2e test no longer parses: {exc}"]
    test_fn = _e2ebd_function(tree, "test_b1_ingest_burst_profile")

    # 1. the exact five live wiring lines, once each
    for line in E2EBD_WIRING_LINES:
        if load_src.count(line + "\n") != 1:
            fails.append(f"wiring line drift: {line!r}")

    # 2. the kind p99 observation: exact bytes and signature, one top-level
    #    node, the five-way order, and no route back to the verdict. The
    #    canonical record is still published before the comparison on a
    #    completed PASS or FAIL; absence or nesting of the observation is a
    #    named policy failure here, not an accepted removal of an oracle.
    fails.extend(_e2ebd_observation_failures(load_src, test_fn))

    # 3. legacy readers and both legacy fingerprint prints, byte-identical
    for name, digest in E2EBD_LEGACY_DIGESTS.items():
        try:
            node = _e2ebd_function(tree, name)
        except AssertionError:
            fails.append(f"legacy reader {name} is gone")
            continue
        if _e2ebd_segment_digest(load_src, node) != digest:
            fails.append(f"legacy reader {name} changed")
    prints = [
        n for n in ast.walk(test_fn)
        if isinstance(n, ast.Expr)
        and isinstance(n.value, ast.Call)
        and getattr(n.value.func, "id", "") == "print"
    ]
    digests = tuple(_e2ebd_segment_digest(load_src, n) for n in prints)
    if digests != E2EBD_LEGACY_PRINT_DIGESTS:
        fails.append(f"the legacy `B1 env=` prints changed: {digests}")

    # 4. all eleven FP-IG-19 e2e FAILURE rows still match one-to-one
    nodes = _nodes_for_src(load_src, "test_b1_ingest_burst_profile")
    consumed: set[int] = set()
    rows = [r for r in B1_FAILURE_INVENTORY if r[0] == E2E_TEST and r[1] == "test_b1_ingest_burst_profile"]
    if len(rows) != 11:
        fails.append(f"{len(rows)} e2e inventory rows, want 11")
    for _path, _name, names, ops, eq_ok in rows:
        matched = _inventory_match(nodes, names, ops, eq_ok, consumed=consumed)
        if matched is None:
            fails.append(f"missing e2e assertion for {sorted(names)}")
        else:
            consumed.add(matched)

    # 5. no skip / xfail / retry / mask anywhere on the live surface
    code = _gc4_prose_free(load_src)
    for token in E2EBD_MASKING_TOKENS:
        if token in code:
            fails.append(f"masking token on the live e2e surface: {token}")

    # 6. no diagnostic value is ever read back into a branch or an assertion
    for node in ast.walk(test_fn):
        if isinstance(node, (ast.If, ast.While, ast.Assert, ast.IfExp, ast.Try)):
            text = ast.unparse(node)
            if "diagnostics" in text or "B1E2EDiagnosticSession" in text:
                fails.append(f"a diagnostic value conditions control flow: {text[:60]}")
    for node in ast.walk(test_fn):
        if isinstance(node, ast.Assign) and "diagnostics.emit" in ast.unparse(node):
            fails.append("the emitted record is bound to a name and can be read back")

    # 7. the generator call keeps every fixed argument; only the two callbacks
    #    are added
    calls = [
        n for n in ast.walk(test_fn)
        if isinstance(n, ast.Call) and "run_open_loop_baseline" in ast.unparse(n.func)
    ]
    if len(calls) != 1:
        fails.append(f"{len(calls)} baseline generator calls")
    else:
        kwargs = {k.arg: ast.unparse(k.value) for k in calls[0].keywords}
        expected = {
            "endpoint": "endpoint",
            "requests": "measured",
            "rate": "BASE_RATE",
            "max_in_flight": "MAX_IN_FLIGHT",
            "warmup": "warmup",
            "prologue": "prologue",
            "include_sync_warmup": "True",
            "on_prologue_complete": "_after_prologue",
            "on_window_open": "diagnostics.open",
            "on_window_complete": "diagnostics.close",
        }
        if kwargs != expected:
            fails.append(f"baseline call argument drift: {kwargs}")
    sat_calls = [
        n for n in ast.walk(test_fn)
        if isinstance(n, ast.Call) and "run_closed_loop_saturation" in ast.unparse(n.func)
    ]
    if len(sat_calls) != 1:
        fails.append("the saturation call changed")
    else:
        sat_kwargs = {k.arg: ast.unparse(k.value) for k in sat_calls[0].keywords}
        if sat_kwargs != {
            "endpoint": "endpoint",
            "request_factory": "factory",
            "clients": "SATURATION_CLIENTS",
            "duration_s": "BURST_SECONDS",
        }:
            fails.append(f"saturation call drift: {sat_kwargs}")

    # 8. the fixed profile constants, in both carriers
    load_assigns = _source_assigns(load_src)
    profile_assigns = _source_assigns(profile_src)
    for name, expected_value in (
        ("BASE_RATE", 200), ("BASE_SECONDS", 30), ("BASE_TOTAL", 6000),
        ("P99_MS", 150.0), ("MAX_IN_FLIGHT", 1000), ("SATURATION_CLIENTS", 150),
        ("PROLOGUE_REQUESTS", 30), ("BURST_SECONDS", 30),
    ):
        for label, assigns in (("test", load_assigns), ("profile", profile_assigns)):
            if name not in assigns:
                fails.append(f"{label}: {name} is gone")
                continue
            try:
                value = _eval_simple_constant(assigns[name], assigns)
            except AssertionError:
                continue  # a derived expression is evaluated by its own pin
            if value != expected_value:
                fails.append(f"{label}: {name}={value} want {expected_value}")

    # 9. the workflow: the byte-identical failure upload, the exact success
    #    upload, and no masking anywhere in the e2e job
    workflow = yaml.safe_load(ci_text)
    steps = (workflow.get("jobs") or {}).get("e2e", {}).get("steps") or []
    names = [s.get("name") or s.get("uses") for s in steps]
    if names.count(E2EBD_SUCCESS_STEP_NAME) != 1:
        fails.append("the success-only diagnostics upload is not present exactly once")
    if names.count(E2EBD_FAILURE_STEP_NAME) != 1:
        fails.append("the failure upload is not present exactly once")
    else:
        failure = steps[names.index(E2EBD_FAILURE_STEP_NAME)]
        if failure.get("if") != "failure()":
            fails.append("the failure upload condition changed")
        if failure.get("uses") != "actions/upload-artifact@v4":
            fails.append("the failure upload action changed")
        with_block = failure.get("with") or {}
        if with_block.get("name") != "e2e-failure-logs":
            fails.append("the failure artifact name changed")
        if tuple(str(with_block.get("path", "")).split()) != E2EBD_FAILURE_PATHS:
            fails.append(f"the failure upload paths changed: {with_block.get('path')!r}")
        if with_block.get("if-no-files-found") != "ignore":
            fails.append("the failure upload missing-file policy changed")
    if "            /tmp/rca-e2e/**\n            tests/e2e/*.log\n" not in ci_text:
        fails.append("the two failure-upload path lines are no longer byte-identical")
    for step in steps:
        if "continue-on-error" in step:
            fails.append("an e2e step masks its own outcome")
    if "continue-on-error" in ((workflow.get("jobs") or {}).get("e2e") or {}):
        fails.append("the e2e job masks its own outcome")
    run_steps = [s.get("run") for s in steps if s.get("run")]
    if "bash tests/e2e/run.sh" not in run_steps:
        fails.append("the e2e run command changed")
    return fails


def test_e2e_b1_diagnostics_are_reported_only_and_fixed():
    """FP-E2EB1D-8: the verdict, the legacy report and every knob stay fixed."""
    profile_src, _diag_src, load_src = _e2ebd_sources()
    ci_text = E2EBD_CI_YML.read_text(encoding="utf-8")
    assert _e2ebd_reported_only_failures(load_src, profile_src, ci_text) == []

    # run.sh and its pinned pytest command are untouched by this slice.
    run_sh = (REPO_ROOT / "tests" / "e2e" / "run.sh").read_text(encoding="utf-8")
    assert "python3 -m pytest tests/e2e -v --tb=short" in run_sh
    assert "tee" not in run_sh.split("python3 -m pytest tests/e2e")[1][:80]

    # --- the §3.7 mutation set: every one of these is red ------------------
    load_mutants = {
        "observation_weakened": load_src.replace(
            'record_property("b1_kind_p99_lt_150_ms", p99 < P99_MS)',
            'record_property("b1_kind_p99_lt_150_ms", p99 <= P99_MS)',
            1,
        ),
        "observation_deleted": load_src.replace(E2EBD_OBSERVATION_BYTES + "\n", "", 1),
        "observation_nested": load_src.replace(
            E2EBD_OBSERVATION_BYTES + "\n",
            "    if diagnostics is not None:\n    " + E2EBD_OBSERVATION_BYTES + "\n",
            1,
        ),
        "emit_moved_after_observation": load_src.replace(
            "    diagnostics.emit(baseline)\n", "", 1
        ).replace(
            E2EBD_OBSERVATION_BYTES + "\n",
            E2EBD_OBSERVATION_BYTES + "\n    diagnostics.emit(baseline)\n",
            1,
        ),
        "observation_signature_dropped": load_src.replace(
            E2EBD_OBSERVATION_SIGNATURE,
            "def test_b1_ingest_burst_profile(ingest_url, dashboard_url):",
            1,
        ),
        "p99_assertion_reintroduced": load_src.replace(
            E2EBD_OBSERVATION_BYTES + "\n",
            E2EBD_OBSERVATION_BYTES + '\n    assert p99 < P99_MS, f"baseline p99={p99}"\n',
            1,
        ),
        "record_bound_and_readable": load_src.replace(
            "    diagnostics.emit(baseline)\n", "    record = diagnostics.emit(baseline)\n", 1
        ),
        "diagnostic_conditions_the_run": load_src.replace(
            "    diagnostics.emit(baseline)\n",
            "    diagnostics.emit(baseline)\n    if diagnostics.opening.gateway is None:\n        return\n",
            1,
        ),
        "legacy_print_refed": load_src.replace(
            "f\"gw_cpu_seconds={_fmt_diag(gw_cpu_seconds)},\"",
            "f\"gw_cpu_seconds={_fmt_diag(None)},\"",
            1,
        ),
        "legacy_reader_changed": load_src.replace(
            '    empty = {"usage_usec": None, "throttled_usec": None, "nr_throttled": None}',
            '    empty = {"usage_usec": 0, "throttled_usec": 0, "nr_throttled": 0}',
            1,
        ),
        "skip_added": load_src.replace(
            "    diagnostics.emit(baseline)\n",
            "    diagnostics.emit(baseline)\n    pytest.skip('diagnostics only')\n",
            1,
        ),
        "max_in_flight_changed": load_src.replace("MAX_IN_FLIGHT = 1000", "MAX_IN_FLIGHT = 500", 1),
        "p99_constant_changed": load_src.replace("P99_MS = 150.0", "P99_MS = 1500.0", 1),
        "base_rate_changed": load_src.replace("BASE_RATE = 200", "BASE_RATE = 100", 1),
        "generator_rate_rebound": load_src.replace("            rate=BASE_RATE,", "            rate=100,", 1),
        "saturation_shortened": load_src.replace(
            "            duration_s=BURST_SECONDS,", "            duration_s=1,", 1
        ),
        "accounting_assertion_deleted": load_src.replace("    assert errors == 0\n", "", 1),
    }
    for case, mutant in load_mutants.items():
        assert mutant != load_src, case
        assert _e2ebd_reported_only_failures(mutant, profile_src, ci_text) != [], case

    profile_mutants = {
        "profile_max_in_flight": profile_src.replace("MAX_IN_FLIGHT = BURST_RATE", "MAX_IN_FLIGHT = 500", 1),
        "profile_p99": profile_src.replace("P99_MS = 150.0", "P99_MS = 1500.0", 1),
        "profile_base_seconds": profile_src.replace("BASE_SECONDS = 30", "BASE_SECONDS = 5", 1),
    }
    for case, mutant in profile_mutants.items():
        assert mutant != profile_src, case
        assert _e2ebd_reported_only_failures(load_src, mutant, ci_text) != [], case

    ci_mutants = {
        "failure_path_line_removed": ci_text.replace("            tests/e2e/*.log\n", "", 1),
        "failure_condition_widened": ci_text.replace(
            "      - name: Upload phase timing and pod logs on failure\n        if: failure()",
            "      - name: Upload phase timing and pod logs on failure\n        if: always()",
            1,
        ),
        "success_upload_removed": ci_text.replace(
            "      - name: Upload B1 diagnostics on success\n"
            "        if: success()\n"
            "        uses: actions/upload-artifact@v4\n"
            "        with:\n"
            "          name: e2e-b1-diagnostics\n"
            "          path: /tmp/rca-e2e/b1-baseline-diagnostics.txt\n"
            "          if-no-files-found: ignore\n",
            "",
            1,
        ),
        "e2e_step_masks_its_outcome": ci_text.replace(
            "      - name: Run e2e (1500s product budget inside 30m job)\n        run: bash tests/e2e/run.sh",
            "      - name: Run e2e (1500s product budget inside 30m job)\n        continue-on-error: true\n        run: bash tests/e2e/run.sh",
            1,
        ),
        "e2e_command_replaced": ci_text.replace(
            "        run: bash tests/e2e/run.sh", "        run: bash tests/e2e/run.sh || true", 1
        ),
    }
    for case, mutant in ci_mutants.items():
        assert mutant != ci_text, case
        assert _e2ebd_reported_only_failures(load_src, profile_src, mutant) != [], case

# ---------------------------------------------------------------------------
# e2e-b1-kind-policy -- the kind due-time p99 is observed, never a verdict.
#
# The slice's four delivery function tests. FP-E2EB1K-4 lives in
# tests/functional/test_manifests.py, beside the manifest it pins.
# ---------------------------------------------------------------------------

#: The eleven kind comparisons that still fail the nested job, in source order.
E2EBK_KIND_FAILURE_ROWS: tuple[frozenset[str], ...] = (
    frozenset({"platform_online"}),
    frozenset({"served", "errors"}),
    frozenset({"errors"}),
    frozenset({"served"}),
    frozenset({"committed", "served"}),
    frozenset({"sat_served", "sat_errors", "issued"}),
    frozenset({"sat_errors"}),
    frozenset({"restart_delta"}),
    frozenset({"unhealthy_count"}),
    frozenset({"sat_committed", "sat_served"}),
    frozenset({"audit_actions"}),
)
#: The reference gate this slice may not touch, in its own bytes.
E2EBK_REFERENCE_ORACLE = (
    "    assert p99 < CI_SCALE_P99_MS, f\"p99={p99}; {b1_ci_scale_run['fingerprint']}\""
)


def _e2ebk_load_src() -> str:
    return E2E_TEST.read_text(encoding="utf-8")


def _e2ebk_test_fn(src: str) -> ast.AST:
    return _e2ebd_function(ast.parse(src), "test_b1_ingest_burst_profile")


def _e2ebk_statement_lines(src: str, names: frozenset[str]) -> "tuple[int, int]":
    """The 1-based line span of the one top-level node that carries ``names``."""
    fn = _e2ebk_test_fn(src)
    for node in fn.body:
        cmp = _node_compare(node)
        if cmp is not None and _cmp_names(cmp) == names:
            return node.lineno, node.end_lineno
    raise AssertionError(f"no top-level comparison for {sorted(names)}")


def _e2ebk_delete_statement(src: str, names: frozenset[str]) -> str:
    start, end = _e2ebk_statement_lines(src, names)
    lines = src.split("\n")
    lines[start - 1:end] = [f"    # mutated: deleted {sorted(names)}"]
    return "\n".join(lines)


def _e2ebk_weaken_statement(src: str, names: frozenset[str]) -> str:
    start, end = _e2ebk_statement_lines(src, names)
    lines = src.split("\n")
    block = "\n".join(lines[start - 1:end])
    assert "==" in block, block
    lines[start - 1:end] = (block.replace("==", ">=", 1)).split("\n")
    return "\n".join(lines)


def test_e2e_kind_p99_is_observed_not_failure_producing():
    """FP-E2EB1K-1: the exact comparison is evaluated and recorded, and decides nothing.

    The Boolean goes into pytest's in-process ``TestReport.user_properties``;
    no shipped reporter persists it, so this exact-bytes/AST pin plus its
    mutants -- not a durable artifact field -- is what proves the comparison is
    still a live runtime consumer of ``p99`` rather than a dead local.
    """
    load_src = _e2ebk_load_src()
    profile_src = E2E_PATH.read_text(encoding="utf-8")
    ref_src = REF_TEST.read_text(encoding="utf-8")

    # (1) the new exact signature pin and the exact observation bytes, once each
    assert load_src.count(E2EBD_OBSERVATION_SIGNATURE + "\n") == 1
    assert load_src.count(E2EBD_OBSERVATION_BYTES + "\n") == 1
    assert E2EBD_OBSERVATION_KEY == "b1_kind_p99_lt_150_ms"

    # (2) the unchanged 150.0 policy constant, in BOTH carriers
    assert _eval_simple_constant(
        _source_assigns(load_src)["P99_MS"], _source_assigns(load_src)
    ) == 150.0
    assert _eval_simple_constant(
        _source_assigns(profile_src)["P99_MS"], _source_assigns(profile_src)
    ) == 150.0

    # (3) exactly one top-level observation node, in the five-way order, with
    #     no assertion / branch / raise / return / pytest-outcome consumer.
    test_fn = _e2ebk_test_fn(load_src)
    assert _e2ebd_observation_failures(load_src, test_fn) == []
    exact = [n for n in test_fn.body if _e2ebd_is_exact_observation(n)]
    assert len(exact) == 1
    assert [n for n in ast.walk(test_fn) if _e2ebd_is_exact_observation(n)] == exact
    assert _e2ebd_p99_outcome_failures(test_fn) == []
    # The retired oracle bytes are gone from the live kind test entirely.
    assert "assert p99 < P99_MS" not in load_src

    # (4) the isolated reference assertion and its constant are byte-identical.
    assert ref_src.count(E2EBK_REFERENCE_ORACLE + "\n") == 1
    assert _eval_simple_constant(
        _source_assigns(ref_src)["CI_SCALE_P99_MS"], _source_assigns(ref_src)
    ) == 150.0
    ref_nodes = _nodes_for(REF_TEST, CI_SCALE_REF_TEST)
    assert _inventory_match(
        ref_nodes, frozenset({"p99", "CI_SCALE_P99_MS"}), frozenset({ast.Lt}), False
    ) is not None

    # (4b) every rejection arm of the exact-observation predicate actually
    #      rejects: a near-miss shape must never be accepted as the pin.
    for variant in (
        'record_property(key="b1_kind_p99_lt_150_ms", value=p99 < P99_MS)',
        'record_property("b1_kind_p99_lt_150_ms")',
        'record_property("b1_kind_p99_lt_150_ms", p99 < P99_MS, extra)',
        'record_property("b1_kind_p99_observed", p99 < P99_MS)',
        'record_property(OBSERVATION_KEY, p99 < P99_MS)',
        'record_property("b1_kind_p99_lt_150_ms", p99)',
        'record_property("b1_kind_p99_lt_150_ms", 0 < p99 < P99_MS)',
        'record_property("b1_kind_p99_lt_150_ms", p99 <= P99_MS)',
        'record_property("b1_kind_p99_lt_150_ms", 1 < P99_MS)',
        'record_property("b1_kind_p99_lt_150_ms", p99 < 150.0)',
        'record_property("b1_kind_p99_lt_150_ms", p99 < baseline.P99_MS)',
        'other_property("b1_kind_p99_lt_150_ms", p99 < P99_MS)',
        'self.record_property("b1_kind_p99_lt_150_ms", p99 < P99_MS)',
        "p99 = baseline.p99",
    ):
        node = ast.parse(variant).body[0]
        assert not _e2ebd_is_exact_observation(node), variant
    assert _e2ebd_is_exact_observation(
        ast.parse('record_property("b1_kind_p99_lt_150_ms", p99 < P99_MS)').body[0]
    )

    # (5) every named successor mutation is red for its named reason.
    mutants = {
        "observation_weakened": (
            load_src.replace(
                'record_property("b1_kind_p99_lt_150_ms", p99 < P99_MS)',
                'record_property("b1_kind_p99_lt_150_ms", p99 <= P99_MS)',
                1,
            ),
            "exact_observation_compare",
        ),
        "observation_key_renamed": (
            load_src.replace(E2EBD_OBSERVATION_KEY, "b1_kind_p99_observed", 1),
            "observation_key",
        ),
        "observation_deleted": (
            load_src.replace(E2EBD_OBSERVATION_BYTES + "\n", "", 1),
            "observation_missing",
        ),
        "observation_nested": (
            load_src.replace(
                E2EBD_OBSERVATION_BYTES + "\n",
                "    if diagnostics is not None:\n    " + E2EBD_OBSERVATION_BYTES + "\n",
                1,
            ),
            "observation_not_top_level",
        ),
        "observation_moved_after_the_first_assert": (
            load_src.replace(E2EBD_OBSERVATION_BYTES + "\n", "", 1).replace(
                "    assert served == 6000\n",
                "    assert served == 6000\n" + E2EBD_OBSERVATION_BYTES + "\n",
                1,
            ),
            "observation_order",
        ),
        "emit_moved_after_observation": (
            load_src.replace("    diagnostics.emit(baseline)\n", "", 1).replace(
                E2EBD_OBSERVATION_BYTES + "\n",
                E2EBD_OBSERVATION_BYTES + "\n    diagnostics.emit(baseline)\n",
                1,
            ),
            "observation_order",
        ),
        "fixture_dropped_from_the_signature": (
            load_src.replace(
                E2EBD_OBSERVATION_SIGNATURE,
                "def test_b1_ingest_burst_profile(ingest_url, dashboard_url):",
                1,
            ),
            "observation_signature",
        ),
        "p99_assertion_reintroduced": (
            load_src.replace(
                E2EBD_OBSERVATION_BYTES + "\n",
                E2EBD_OBSERVATION_BYTES + '\n    assert p99 < P99_MS, f"baseline p99={p99}"\n',
                1,
            ),
            "p99_outcome_assert",
        ),
        "p99_early_return": (
            load_src.replace(
                E2EBD_OBSERVATION_BYTES + "\n",
                E2EBD_OBSERVATION_BYTES + "\n    if p99 >= P99_MS:\n        return\n",
                1,
            ),
            "p99_outcome_branch",
        ),
        "p99_raised": (
            load_src.replace(
                E2EBD_OBSERVATION_BYTES + "\n",
                E2EBD_OBSERVATION_BYTES
                + "\n    if True:\n        raise AssertionError(f'p99={p99}')\n",
                1,
            ),
            "p99_outcome_exit",
        ),
        "p99_pytest_fail": (
            load_src.replace(
                E2EBD_OBSERVATION_BYTES + "\n",
                E2EBD_OBSERVATION_BYTES + "\n    pytest.fail(f'p99={p99}')\n",
                1,
            ),
            "p99_outcome_call",
        ),
        "observation_duplicated": (
            load_src.replace(
                E2EBD_OBSERVATION_BYTES + "\n",
                E2EBD_OBSERVATION_BYTES + "\n" + E2EBD_OBSERVATION_BYTES + "\n",
                1,
            ),
            "observation_not_unique",
        ),
    }
    for case, (mutant, reason) in mutants.items():
        assert mutant != load_src, case
        fails = _e2ebd_observation_failures(mutant, _e2ebk_test_fn(mutant))
        assert any(f.startswith(reason) for f in fails), f"{case}: {fails}"

    # ... and the shipped policy guard rejects each of them as a whole.
    ci_text = E2EBD_CI_YML.read_text(encoding="utf-8")
    for case, (mutant, _reason) in mutants.items():
        assert _e2ebd_reported_only_failures(mutant, profile_src, ci_text) != [], case


def test_e2e_kind_correctness_clauses_remain_failure_producing():
    """FP-E2EB1K-2: eleven kind failure nodes, one-to-one, plus the ten-row matrices."""
    load_src = _e2ebk_load_src()

    # (1) the failure inventory carries exactly these eleven kind rows, and no
    #     p99 row: a non-failing observation may never be counted as a gate.
    rows = [
        r for r in B1_FAILURE_INVENTORY
        if r[0] == E2E_TEST and r[1] == "test_b1_ingest_burst_profile"
    ]
    assert len(rows) == 11
    assert tuple(r[2] for r in rows) == E2EBK_KIND_FAILURE_ROWS
    assert frozenset({"p99", "P99_MS"}) not in {r[2] for r in rows}
    assert len(B1_FAILURE_INVENTORY) == 19

    # (2) each row matches exactly one live node, one-to-one, through the seam.
    nodes = _nodes_for_src(load_src, "test_b1_ingest_burst_profile")
    consumed: set[int] = set()
    for _path, _name, names, ops, eq_ok in rows:
        matched = _inventory_match(nodes, names, ops, eq_ok, consumed=consumed)
        assert matched is not None, f"missing kind failure node for {sorted(names)}"
        consumed.add(matched)
    assert len(consumed) == 11
    # The removed p99 comparison is genuinely absent from the failure surface.
    assert _inventory_match(
        nodes, frozenset({"p99", "P99_MS"}), frozenset({ast.Lt}), False
    ) is None

    # (3) deleting or weakening ANY of the eleven is red for that row alone.
    for _path, _name, names, ops, eq_ok in rows:
        deleted = _e2ebk_delete_statement(load_src, names)
        assert deleted != load_src, sorted(names)
        assert _inventory_match(
            _nodes_for_src(deleted, "test_b1_ingest_burst_profile"), names, ops, eq_ok
        ) is None, f"deleting {sorted(names)} still matched"
        # every retained kind clause is an accounting/identity equality, so
        # weakening its operator is always a meaningful mutation here.
        assert ops == frozenset({ast.Eq}) and eq_ok, sorted(names)
        weakened = _e2ebk_weaken_statement(load_src, names)
        assert weakened != load_src, sorted(names)
        assert _inventory_match(
            _nodes_for_src(weakened, "test_b1_ingest_burst_profile"),
            names,
            frozenset({ast.Eq}),
            True,
        ) is None, f"weakening {sorted(names)} still matched Eq inventory"

    # ... and the locator those mutations use refuses to guess.
    with pytest.raises(AssertionError):
        _e2ebk_statement_lines(load_src, frozenset({"no_such_clause"}))

    # (4) the complete post-change final/superseded matrices, all ten rows.
    assert len(e2e.ACCEPTANCE_EXPECTED) == 10
    assert len(e2e.ACCEPTANCE_SUPERSEDED) == 10
    expected = {
        "healthy_1000": ("pass", "pass", "pass", "pass", "pass"),
        "round2_tail": ("pass", "pass", "fail", "fail", "fail"),
        "late_first_completion": ("pass", "pass", "pass", "fail", "fail"),
        "sustained_deficit_990": ("pass", "pass", "pass", "fail", "fail"),
        "sustained_deficit_400": ("fail", "fail", "fail", "fail", "fail"),
        "round3_997": ("pass", "pass", "pass", "fail", "pass"),
        "round4_repeated_ramp": ("pass", "pass", "pass", "pass", "pass"),
        "round5_constant_995": ("pass", "pass", "pass", "fail", "pass"),
        "round5_burst_credits": ("pass", "pass", "pass", "pass", "pass"),
        "round6_dispatch_hold": ("pass", "pass", "fail", "fail", "fail"),
    }
    for name, (final, f1, f2, f3, f4) in expected.items():
        matrix = e2e.run_acceptance_matrix(name)
        verdict, fails = e2e.run_acceptance_case(name)
        assert (verdict, matrix["final"]) == (final, final), f"{name}: {verdict} {fails}"
        assert e2e.ACCEPTANCE_EXPECTED[name] == final, name
        assert (matrix["form1"], matrix["form2"], matrix["form3"], matrix["form4"]) == (
            f1, f2, f3, f4
        ), f"{name}: {matrix}"
        assert e2e.ACCEPTANCE_SUPERSEDED[name] == (f1, f2, f3, f4), name

    # (5) the latency-only schedule now passes; the completion/error control
    #     is still red, and red for completion and errors rather than latency.
    latency_only, latency_fails = e2e.run_acceptance_case("sustained_deficit_990")
    assert (latency_only, latency_fails) == ("pass", [])
    assert not (e2e._acceptance_schedule("sustained_deficit_990").p99 < e2e.P99_MS)
    control, control_fails = e2e.run_acceptance_case("sustained_deficit_400")
    assert control == "fail"
    # served + errors still equals offered in this schedule: the control is red
    # for lost work and errors, which is exactly the class p99 must not hide.
    assert set(control_fails) == {"errors==0", "served==offered"}
    assert "p99<P99_MS" not in control_fails

    # (6) the base evaluator is the renamed correctness-only one, shared by the
    #     final oracle and all four superseded forms, so no stale call can
    #     re-introduce the removed p99 clause.
    profile_src = E2E_PATH.read_text(encoding="utf-8")
    assert "def evaluate_baseline_correctness_clauses(" in profile_src
    assert "evaluate_baseline_clauses" not in profile_src
    assert profile_src.count("evaluate_baseline_correctness_clauses(result)") == 5
    assert "p99<P99_MS" not in profile_src
    for form in ("evaluate_superseded_form1", "evaluate_superseded_form2",
                 "evaluate_superseded_form3", "evaluate_superseded_form4"):
        body = ast.unparse(_e2ebd_function(ast.parse(profile_src), form))
        assert "evaluate_baseline_correctness_clauses(result)" in body, form

    # (7) the classifier still counts every non-200/202 or transport result as
    #     an error, so "zero errors" keeps its meaning.
    for status, body, err, expected_outcome in CLASSIFIER_TABLE:
        assert e2e.classify_response(status, body, err) == expected_outcome


def test_e2e_kind_p99_record_route_is_exact_and_non_masking(tmp_path: Path):
    """FP-E2EB1K-3: a high, bar-missing p99 still reaches print, line, file and artifact."""
    profile_src, diag_src, load_src = _e2ebd_sources()
    ci_text = E2EBD_CI_YML.read_text(encoding="utf-8")

    # A coherent completed baseline whose p99 misses the 150 ms bar by an order
    # of magnitude -- the shape every recorded CI observation had.
    result = e2e.PhaseResult(
        offered=6000, served=6000, errors=0,
        latencies_ms=[1.0] * 5939 + [1389.75] * 61,
        t0=0.0, t_last_complete=31.0, due0=0.0,
        max_in_flight=251, max_backlog=0, phase="baseline",
        status_codes=[202] * 6000,
        pre_dispatch_slip_ms=[0.1] * 6000,
        start_lag_ms=[1.2] * 6000,
        attempt_duration_ms=[1388.45] * 6000,
    )
    assert result.p99 == 1389.75 and not (result.p99 < e2e.P99_MS)

    runner = _e2ebd_healthy_runner()
    session = e2ediag.B1E2EDiagnosticSession(run=runner)
    session.open()
    session.close()
    target = tmp_path / "rca-e2e" / "b1-baseline-diagnostics.txt"
    stream = io.StringIO()
    line = session.emit(
        result,
        stdout=stream,
        artifact_writer=lambda text: e2ediag.write_e2e_b1_diagnostic_artifact(text, path=target),
    )

    # (1) one canonical record: stdout bytes == file bytes, 33 fields in order.
    assert stream.getvalue() == line + "\n"
    assert target.read_text(encoding="utf-8") == line + "\n"
    fields = _e2ebd_top_level_fields(line)
    assert [name for name, _v in fields] == list(E2EBD_FIELDS)
    assert len(E2EBD_FIELDS) == 33
    # (2) the numeric p99 is the measured value, not a bar-derived verdict.
    assert dict(fields)["p99_ms"] == "1389.750"
    assert float(dict(fields)["p99_ms"]) == result.p99
    assert "150" not in dict(fields)["p99_ms"]
    for token in ("b1_kind_p99_lt_150_ms", "true", "false", "met", "missed"):
        assert token not in line, token
    # (3) the legacy print carries the same source expression, unchanged.
    assert E2EBD_LEGACY_PRINT_DIGESTS == (
        "0b6ed6a0538a693cfe420aa109c9ea1d8d770f1ccc94b27989231ab484b65ae0",
        "939c613f06ad6cb11b7520156e7b6a9c3382666d30b33bdb6ba1dfeb0f391471",
    )
    assert "p99_ms={baseline.p99:.1f}" in load_src
    # (4) the fixed file path lives under the failure-artifact root, and the
    #     success artifact publishes exactly that one file.
    assert str(e2ediag.B1_E2E_DIAGNOSTIC_ARTIFACT) == E2EBD_ARTIFACT
    workflow = yaml.safe_load(ci_text)
    steps = workflow["jobs"]["e2e"]["steps"]
    names = [s.get("name") or s.get("uses") for s in steps]
    success = steps[names.index(E2EBD_SUCCESS_STEP_NAME)]
    failure = steps[names.index(E2EBD_FAILURE_STEP_NAME)]
    assert success["if"] == "success()" and failure["if"] == "failure()"
    assert success["with"]["path"] == E2EBD_ARTIFACT
    assert tuple(str(failure["with"]["path"]).split()) == E2EBD_FAILURE_PATHS
    assert E2EBD_ARTIFACT.startswith(E2EBD_FAILURE_PATHS[0][: -len("**")])
    # (5) the shipped guard is green on the unmutated route.
    assert _e2ebd_reported_only_failures(load_src, profile_src, ci_text) == []

    # --- deletion / hard-coding / masking are red ---------------------------
    # p99_ms hard-coded in the diagnostics carrier: a direct data-flow proof.
    hard_coded_src = diag_src.replace(
        '        values["p99_ms"] = p99\n', '        values["p99_ms"] = 0.0\n', 1
    )
    assert hard_coded_src != diag_src
    hard_coded = _e2ebd_exec_profile(hard_coded_src, "b1_e2e_diagnostics_hardcoded_mutant")
    hard_values = hard_coded.build_e2e_b1_diagnostic_values(
        result, session.opening, session.closing
    )
    assert hard_values["p99_ms"] != result.p99

    # the file write removed from emit: stdout survives, the artifact does not.
    unwritten_src = diag_src.replace("            artifact_writer(line)\n", "            pass\n", 1)
    assert unwritten_src != diag_src
    unwritten = _e2ebd_exec_profile(unwritten_src, "b1_e2e_diagnostics_unwritten_mutant")
    gone = tmp_path / "gone" / "b1-baseline-diagnostics.txt"
    unwritten_session = unwritten.B1E2EDiagnosticSession(run=_e2ebd_healthy_runner())
    unwritten_session.open()
    unwritten_session.close()
    unwritten_session.emit(
        result,
        stdout=io.StringIO(),
        artifact_writer=lambda text: unwritten.write_e2e_b1_diagnostic_artifact(text, path=gone),
    )
    assert not gone.exists()

    # every remaining carrier mutation is red under the shipped policy guard.
    load_mutants = {
        "emit_deleted": load_src.replace("    diagnostics.emit(baseline)\n", "", 1),
        "legacy_print_hard_coded": load_src.replace(
            "p99_ms={baseline.p99:.1f}", "p99_ms=0.0", 1
        ),
        "kind_p99_constant_changed": load_src.replace("P99_MS = 150.0", "P99_MS = 1500.0", 1),
        "skip_added": load_src.replace(
            "    diagnostics.emit(baseline)\n",
            "    diagnostics.emit(baseline)\n    pytest.skip('diagnostics only')\n",
            1,
        ),
    }
    for case, mutant in load_mutants.items():
        assert mutant != load_src, case
        assert _e2ebd_reported_only_failures(mutant, profile_src, ci_text) != [], case
    assert _e2ebd_reported_only_failures(
        load_src, profile_src.replace("P99_MS = 150.0", "P99_MS = 1500.0", 1), ci_text
    ) != []
    ci_mutants = {
        "success_upload_removed": ci_text.replace(
            "      - name: Upload B1 diagnostics on success\n"
            "        if: success()\n"
            "        uses: actions/upload-artifact@v4\n"
            "        with:\n"
            "          name: e2e-b1-diagnostics\n"
            "          path: /tmp/rca-e2e/b1-baseline-diagnostics.txt\n"
            "          if-no-files-found: ignore\n",
            "",
            1,
        ),
        "failure_upload_path_removed": ci_text.replace(
            "            /tmp/rca-e2e/**\n", "", 1
        ),
        "e2e_job_masks_its_outcome": ci_text.replace(
            "      - name: Run e2e (1500s product budget inside 30m job)\n        run: bash tests/e2e/run.sh",
            "      - name: Run e2e (1500s product budget inside 30m job)\n        continue-on-error: true\n        run: bash tests/e2e/run.sh",
            1,
        ),
    }
    for case, mutant in ci_mutants.items():
        assert mutant != ci_text, case
        assert _e2ebd_reported_only_failures(load_src, profile_src, mutant) != [], case


def test_fp_ig19_policy_guard_rejects_failure_observation_reporting_and_collection_mutations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """FP-E2EB1K-5: 19 failure nodes, the observation, the report route, and reachability."""
    profile_src, _diag_src, load_src = _e2ebd_sources()
    ci_text = E2EBD_CI_YML.read_text(encoding="utf-8")

    # (1) nineteen failure rows, eight reference + eleven kind, one-to-one
    #     through the real `_nodes_for_src` / `_inventory_match` seam.
    assert len(B1_FAILURE_INVENTORY) == 19
    by_file: dict[tuple[str, str], list] = {}
    for row in B1_FAILURE_INVENTORY:
        by_file.setdefault((str(row[0]), row[1]), []).append(row)
    assert sorted(len(v) for v in by_file.values()) == [8, 11]
    for (path_str, test_name), rows in by_file.items():
        nodes = _nodes_for_src(Path(path_str).read_text(encoding="utf-8"), test_name)
        consumed: set[int] = set()
        for _p, _n, names, ops, eq_ok in rows:
            matched = _inventory_match(nodes, names, ops, eq_ok, consumed=consumed)
            assert matched is not None, f"{test_name}: missing {sorted(names)}"
            consumed.add(matched)
        assert len(consumed) == len(rows)

    # (2) the observation guard and the report route are green as shipped ...
    assert _e2ebd_observation_failures(load_src, _e2ebk_test_fn(load_src)) == []
    assert _e2ebd_reported_only_failures(load_src, profile_src, ci_text) == []

    # ... and every named failure / observation / reporting mutation is red.
    for names in E2EBK_KIND_FAILURE_ROWS:
        mutant = _e2ebk_delete_statement(load_src, names)
        assert _e2ebd_reported_only_failures(mutant, profile_src, ci_text) != [], sorted(names)
    for case, mutant in {
        "observation_deleted": load_src.replace(E2EBD_OBSERVATION_BYTES + "\n", "", 1),
        "observation_weakened": load_src.replace(
            "p99 < P99_MS)", "p99 <= P99_MS)", 1
        ),
        "observation_nested": load_src.replace(
            E2EBD_OBSERVATION_BYTES + "\n",
            "    if diagnostics is not None:\n    " + E2EBD_OBSERVATION_BYTES + "\n",
            1,
        ),
        "emit_moved_after_observation": load_src.replace(
            "    diagnostics.emit(baseline)\n", "", 1
        ).replace(
            E2EBD_OBSERVATION_BYTES + "\n",
            E2EBD_OBSERVATION_BYTES + "\n    diagnostics.emit(baseline)\n",
            1,
        ),
        "reporting_deleted": load_src.replace("    diagnostics.emit(baseline)\n", "", 1),
    }.items():
        assert mutant != load_src, case
        assert _e2ebd_reported_only_failures(mutant, profile_src, ci_text) != [], case

    # ... and the row-count guard is live too: an inventory that quietly loses
    # a kind row is named, rather than absorbed into a smaller expectation.
    short = [
        r for r in B1_FAILURE_INVENTORY
        if not (r[0] == E2E_TEST and r[2] == frozenset({"sat_errors"}))
    ]
    assert len(short) == 18
    monkeypatch.setitem(globals(), "B1_FAILURE_INVENTORY", short)
    assert "10 e2e inventory rows, want 11" in _e2ebd_reported_only_failures(
        load_src, profile_src, ci_text
    )
    monkeypatch.undo()
    assert _e2ebd_reported_only_failures(load_src, profile_src, ci_text) == []

    # (3) collection reachability: the nested diagnostic path is carried into
    #     the collection-suppression guard by the EXPLICIT constant, not by a
    #     remaining threshold link. Two sides, on the same three-link manifest.
    assert _manifests.B1_NESTED_DIAGNOSTIC_LINK == (
        "tests/e2e/test_e2e_load.py::test_b1_ingest_burst_profile"
    )
    scratch = tmp_path / "scratch_tree"
    manifest_text = (REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml").read_text(
        encoding="utf-8"
    )
    (scratch / "tests" / "benchmark").mkdir(parents=True)
    (scratch / "tests" / "benchmark" / "thresholds.yaml").write_text(
        manifest_text, encoding="utf-8"
    )
    bare = _manifests._covered_py_links(scratch)
    explicit = _manifests._collection_guard_links(scratch)
    assert _manifests.B1_NESTED_DIAGNOSTIC_LINK not in bare
    assert explicit == [*bare, _manifests.B1_NESTED_DIAGNOSTIC_LINK]
    b1_entry = next(
        e for e in yaml.safe_load(manifest_text)["benchmarks"] if e["id"] == "B1"
    )
    assert len(b1_entry["tests"]) == 3
    assert _manifests.B1_NESTED_DIAGNOSTIC_LINK in b1_entry["notes"]

    # materialise every chain directory with its real config files / conftests
    dirs = _manifests._chain_dirs(scratch, explicit) | _manifests._chain_dirs(scratch, bare)
    for directory in sorted(dirs):
        real = REPO_ROOT / directory.relative_to(scratch.resolve())
        directory.mkdir(parents=True, exist_ok=True)
        # Every chain directory must exist in the real repository: a scratch
        # tree missing one would prove nothing, loudly rather than silently.
        assert real.is_dir(), real
        for entry in real.iterdir():
            if entry.is_file() and (
                _manifests._is_config_shaped(entry.name) or entry.name == "conftest.py"
            ):
                (directory / entry.name).write_text(
                    entry.read_text(encoding="utf-8"), encoding="utf-8"
                )

    e2e_dir = (scratch / "tests" / "e2e").resolve()
    assert e2e_dir in _manifests._chain_dirs(scratch, explicit)
    assert e2e_dir not in _manifests._chain_dirs(scratch, bare)
    assert _manifests._pytest_collection_failures(scratch, explicit) == []
    assert _manifests._pytest_collection_failures(scratch, bare) == []

    conftest = scratch / "tests" / "e2e" / "conftest.py"
    assert conftest.is_file()
    conftest.write_text(
        conftest.read_text(encoding="utf-8") + '\ncollect_ignore = ["test_e2e_load.py"]\n',
        encoding="utf-8",
    )
    assert _manifests._pytest_collection_failures(scratch, explicit) == [
        "conftest_collection_hook"
    ]
    assert _manifests._pytest_collection_failures(scratch, bare) == []


#: The per-request schedule-path budget, declared here rather than measured
#: from either subject: two bounds guards, two monotonic reads and two
#: preallocated-vector stores for a measured request; one guard and nothing
#: else for a warmup or prologue request.
E2EBD_MEASURED_BUDGET = {
    "bounds_guards": 2,
    "monotonic_reads_in_guards": 2,
    "preallocated_stores_in_guards": 2,
    "allocations_before_one": 2,
    "forbidden_operations_in_guards": 0,
    "unmeasured_guard_evaluations": 1,
    "unmeasured_reads": 0,
    "unmeasured_stores": 0,
}
E2EBD_FORBIDDEN_HOT_PATH = (
    "await", "sleep", "open(", "subprocess", "Lock", "Event", "create_task",
    "gather", "for ", "while ", "[0.0]", "append", "dict(", "list(",
)


def _e2ebd_operation_budget(src: str, fn_name: str) -> dict:
    """The AST operation metric of one open-loop generator's schedule path."""
    tree = ast.parse(src)
    gen = _e2ebd_function(tree, fn_name)
    one = next(n for n in gen.body if isinstance(n, ast.AsyncFunctionDef) and n.name == "_one")
    one_index = gen.body.index(one)
    allocations = [
        index
        for index, stmt in enumerate(gen.body)
        if isinstance(stmt, ast.Assign)
        and len(stmt.targets) == 1
        and isinstance(stmt.targets[0], ast.Name)
        and stmt.targets[0].id in ("dispatch_at", "attempt_at")
        and ast.unparse(stmt.value) == "[0.0] * n"
    ]
    guards = [
        node
        for node in ast.walk(gen)
        if isinstance(node, ast.If) and ast.unparse(node.test) in ("0 <= idx < n", "0 <= i < n")
    ]
    reads = 0
    stores = 0
    forbidden = 0
    for guard in guards:
        body_text = "\n".join(ast.unparse(stmt) for stmt in guard.body)
        reads += body_text.count("time.perf_counter()")
        for stmt in guard.body:
            if (
                isinstance(stmt, ast.Assign)
                and len(stmt.targets) == 1
                and isinstance(stmt.targets[0], ast.Subscript)
                and isinstance(stmt.targets[0].value, ast.Name)
                and stmt.targets[0].value.id in ("dispatch_at", "attempt_at")
            ):
                stores += 1
        for token in E2EBD_FORBIDDEN_HOT_PATH:
            if token in body_text:
                forbidden += 1
        if guard.orelse:
            forbidden += 1
    # A warmup / prologue request (idx < 0) evaluates the `_one` guard only.
    attempt_guards = [g for g in guards if ast.unparse(g.test) == "0 <= idx < n"]
    return {
        "bounds_guards": len(guards),
        "monotonic_reads_in_guards": reads,
        "preallocated_stores_in_guards": stores,
        "allocations_before_one": sum(1 for index in allocations if index < one_index),
        "forbidden_operations_in_guards": forbidden,
        "unmeasured_guard_evaluations": len(attempt_guards),
        "unmeasured_reads": 0 if reads == len(guards) else reads,
        "unmeasured_stores": 0 if stores == len(guards) else stores,
    }


def test_e2e_b1_leg_instrumentation_operation_budget_matches_reference():
    """Benchmark (FP-E2EB1D-7): the e2e hot path equals the shipped reference.

    The reference carrier already passes the isolated gate at 500 offered/s --
    2.5x the e2e offer -- with exactly this placement, so operation-for-
    operation parity is the non-perturbation evidence. No live on/off run is
    part of the acceptance bar.
    """
    profile_src, _diag_src, _load_src = _e2ebd_sources()
    ref_src = REF_PATH.read_text(encoding="utf-8")

    e2e_budget = _e2ebd_operation_budget(profile_src, "run_open_loop_baseline")
    ref_budget = _e2ebd_operation_budget(ref_src, "run_open_loop")
    assert e2e_budget == E2EBD_MEASURED_BUDGET, e2e_budget
    assert ref_budget == E2EBD_MEASURED_BUDGET, ref_budget
    assert e2e_budget == ref_budget

    # The diagnostic work itself is entirely outside the schedule path.
    gen = _e2ebd_function(ast.parse(profile_src), "run_open_loop_baseline")
    dispatch_loop = next(
        n for n in ast.walk(gen)
        if isinstance(n, ast.For) and "asyncio.create_task(_one(i, *requests[i]))" in ast.unparse(n)
    )
    loop_text = ast.unparse(dispatch_loop)
    for token in ("derive_leg_vectors", "on_window_open", "on_window_complete", "subprocess"):
        assert token not in loop_text, token

    # Red for both D1 shapes.
    late = profile_src.replace(
        "    dispatch_at = [0.0] * n\n    attempt_at = [0.0] * n\n\n    async def _one(",
        "    async def _one(",
        1,
    ).replace(
        "        latencies = [0.0] * n\n",
        "        dispatch_at = [0.0] * n\n        attempt_at = [0.0] * n\n        latencies = [0.0] * n\n",
        1,
    )
    assert _e2ebd_operation_budget(late, "run_open_loop_baseline") != E2EBD_MEASURED_BUDGET
    unguarded = profile_src.replace(
        "            if 0 <= idx < n:\n                attempt_at[idx] = time.perf_counter()\n",
        "            attempt_at[idx] = time.perf_counter()\n",
        1,
    )
    assert _e2ebd_operation_budget(unguarded, "run_open_loop_baseline") != E2EBD_MEASURED_BUDGET
    # An added await, per-request allocation or sampler task inside a guard is
    # over budget too.
    for injected in (
        "            if 0 <= idx < n:\n                await asyncio.sleep(0)\n                attempt_at[idx] = time.perf_counter()\n",
        "            if 0 <= idx < n:\n                attempt_at[idx] = time.perf_counter()\n                samples = [0.0] * n\n",
        "            if 0 <= idx < n:\n                asyncio.create_task(_one(0, raw, headers))\n                attempt_at[idx] = time.perf_counter()\n",
    ):
        mutant = profile_src.replace(
            "            if 0 <= idx < n:\n                attempt_at[idx] = time.perf_counter()\n",
            injected,
            1,
        )
        assert mutant != profile_src
        budget = _e2ebd_operation_budget(mutant, "run_open_loop_baseline")
        assert budget["forbidden_operations_in_guards"] > 0, injected
        assert budget != E2EBD_MEASURED_BUDGET


def test_e2e_b1_every_source_failure_is_group_local_and_unavailable():
    """FP-E2EB1D-2/3/4/5/8 (§3.8): one dark source never darkens another."""
    # A failing command, a malformed payload and an unparseable JSON document
    # each darken exactly their own group.
    for failing, dark, lit in (
        ({"gateway"}, "gateway_cpu_usage_usec", "postgres_cpu_usage_usec"),
        ({"postgres"}, "postgres_cpu_usage_usec", "gateway_cpu_usage_usec"),
        ({"kind"}, "kind_node", "gateway_cpu_usage_usec"),
        ({"runner"}, "runner_steal_usec", "pg_xact_commit_delta"),
    ):
        values = _e2ebd_values_from(_e2ebd_healthy_runner(failing=failing))
        assert values[dark] == E2EBD_UNAVAILABLE, (failing, dark)
        assert values[lit] != E2EBD_UNAVAILABLE, (failing, lit)
    # The whole pod query failing darkens every cluster-sourced field, and the
    # record is still complete.
    blind = _e2ebd_values_from(_e2ebd_healthy_runner(failing={"pods"}))
    for name in E2EBD_FIELDS:
        if name != "schema":
            assert blind[name] == E2EBD_UNAVAILABLE, name
    assert len(e2ediag.serialize_e2e_b1_diagnostics(blind).split(",")) == 33

    # Structurally impossible pod payloads are refused, never guessed at.
    for payload in ("not json at all", "[]", '{"items": {}}', '{"items": [3]}',
                    '{"items": [{"metadata": {"labels": 7}}]}'):
        gateway, postgres = e2ediag.resolve_b1_pod_targets(
            _e2ebd_healthy_runner(pod_json=[payload])
        )
        assert gateway is None and postgres is None, payload

    # Malformed exec output is an unavailable, never a zero.
    garbled = _e2ebd_values_from(
        _e2ebd_healthy_runner(
            gateway=["#b1diag-begin:cpu_stat_v2\nusage_usec 1\n"],  # unterminated
            postgres=["not framed at all"],
        )
    )
    assert garbled["gateway_cpu_usage_usec"] == E2EBD_UNAVAILABLE
    assert garbled["postgres_cpu_usage_usec"] == E2EBD_UNAVAILABLE
    assert garbled["pg_xact_commit_delta"] == E2EBD_UNAVAILABLE
    assert garbled["runner_steal_usec"] == 5_000_000
    # A v1 payload missing half of itself, and a non-mapping frame set.
    for frames in ({"proc_stat": "cpu 1"}, "not a mapping"):
        with pytest.raises(Exception):
            e2ediag.parse_cgroup_cpu_frames(frames)
    with pytest.raises(Exception):
        e2ediag.parse_runner_frames("not a mapping")
    with pytest.raises(Exception):
        e2ediag.parse_runner_frames({"psi_cpu": "some total=1"})
    with pytest.raises(Exception):
        e2ediag.parse_frames(None)
    with pytest.raises(Exception):
        e2ediag.parse_postgres_stats_row(None)
    for body in ("17", "nr_throttled 1\nthrottled_time 2"):
        broken = (
            _e2ebd_frame("proc_self_cgroup", "0::/")
            + _e2ebd_frame("cpu_stat_v2", "")
            + _e2ebd_frame("cpuacct_usage_v1", body if body == "17" else "")
            + _e2ebd_frame("cpu_stat_v1", "" if body == "17" else body)
        )
        with pytest.raises(Exception):
            e2ediag.parse_cgroup_cpu_frames(e2ediag.parse_frames(broken))
    bad_usage = (
        _e2ebd_frame("proc_self_cgroup", "0::/")
        + _e2ebd_frame("cpu_stat_v2", "")
        + _e2ebd_frame("cpuacct_usage_v1", "not-a-number")
        + _e2ebd_frame("cpu_stat_v1", "nr_throttled 1\nthrottled_time 2")
    )
    with pytest.raises(Exception):
        e2ediag.parse_cgroup_cpu_frames(e2ediag.parse_frames(bad_usage))
    incomplete_v1 = (
        _e2ebd_frame("proc_self_cgroup", "0::/")
        + _e2ebd_frame("cpu_stat_v2", "")
        + _e2ebd_frame("cpuacct_usage_v1", "17")
        + _e2ebd_frame("cpu_stat_v1", "nr_periods 3")
    )
    with pytest.raises(Exception):
        e2ediag.parse_cgroup_cpu_frames(e2ediag.parse_frames(incomplete_v1))
    with pytest.raises(Exception):
        e2ediag.parse_frames("#b1diag-end:cpu_stat_v2\n")
    with pytest.raises(Exception):
        e2ediag.parse_frames("#b1diag-begin:a\n#b1diag-begin:b\n")

    # A stable identity whose counters are missing keeps the group dark.
    target = e2ediag.PodTarget(
        name="p", uid="u", node_name=E2EBD_KIND_NODE,
        container_id="c", container_name=E2EBD_GATEWAY_COMPONENT,
    )
    half = e2ediag.build_e2e_b1_diagnostic_values(
        None,
        e2ediag.BoundarySnapshot(label="open", gateway=target),
        e2ediag.BoundarySnapshot(label="close", gateway=target),
    )
    assert half["gateway_pod"] == E2EBD_UNAVAILABLE

    # An unknown boundary label is a programming error, not a silent reading.
    with pytest.raises(ValueError):
        e2ediag.snapshot_e2e_b1_boundary("midpoint", run=_e2ebd_healthy_runner())

    # Incoherent leg vectors render `unavailable`, never a fabricated triple.
    snapshot = e2ediag.unavailable_snapshot("open")
    for vectors in (
        ([], [], []),
        ([1.0], [1.0, 2.0], [1.0]),
        ([float("nan")], [1.0], [1.0]),
        ([float("inf")], [1.0], [1.0]),
    ):
        result = e2e.PhaseResult(
            offered=1, served=1, errors=0, latencies_ms=[1.0],
            t0=0.0, t_last_complete=1.0, due0=0.0, max_in_flight=1, max_backlog=0,
            pre_dispatch_slip_ms=vectors[0],
            start_lag_ms=vectors[1],
            attempt_duration_ms=vectors[2],
        )
        values = e2ediag.build_e2e_b1_diagnostic_values(result, snapshot, snapshot)
        assert values["p99_leg_split_ms"] == E2EBD_UNAVAILABLE, vectors
        assert values["leg_p99s_ms"] == E2EBD_UNAVAILABLE, vectors
    empty = e2e.PhaseResult(
        offered=0, served=0, errors=0, latencies_ms=[], t0=0.0,
        t_last_complete=0.0, due0=0.0, max_in_flight=0, max_backlog=0,
    )
    empty_values = e2ediag.build_e2e_b1_diagnostic_values(empty, snapshot, snapshot)
    assert empty_values["p99_ms"] == E2EBD_UNAVAILABLE   # inf is not a reading
    assert empty_values["status_histogram"] == E2EBD_UNAVAILABLE
    assert empty_values["offered"] == 0                  # a real zero
    # An extra member is refused outright rather than silently dropped.
    with pytest.raises(ValueError):
        e2ediag.serialize_e2e_b1_diagnostics({**empty_values, "extra": 1})
    # A concise stderr note is best-effort and never raises.
    e2ediag._note("b1-e2e-diagnostics: delivery-tier probe")
