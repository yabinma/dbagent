"""FP-IG-8/13/14/15/19 and UT-IG-7: B1 harness surface, classifiers, generators."""
from __future__ import annotations

import ast
import asyncio
import hashlib
import importlib.util
import json
import re
import time
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

# Exact twenty-node inventory. Each entry: (test_file, test_name, required_names,
# required_op_types or None, equality_admitted).
# Equality is admitted ONLY for B1 accounting clauses.
B1_INVENTORY: list[tuple[Path, str, frozenset[str], frozenset[type] | None, bool]] = [
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
    # --- FP-IG-9 e2e: twelve clauses ---
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"platform_online"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"served", "errors"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"errors"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"served"}), frozenset({ast.Eq}), True),
    (E2E_TEST, "test_b1_ingest_burst_profile", frozenset({"p99", "P99_MS"}), frozenset({ast.Lt}), False),
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
    so twenty inventory entries require twenty distinct assertions.
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
    """FP-IG-19: exact twenty-node inventory via the shared seam (one-to-one)."""
    assert len(B1_INVENTORY) == 20, f"inventory size {len(B1_INVENTORY)}"
    cache: dict[tuple[str, str], list[ast.AST]] = {}
    consumed_by_key: dict[tuple[str, str], set[int]] = {}
    for path, test_name, names, ops, eq_ok in B1_INVENTORY:
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
    for p, tn, names, rops, eok in B1_INVENTORY:
        if p == path and names == required_names:
            ops = rops
            eq_ok = eok
            break
    # For p99 / rate floor use ordering ops.
    if required_names in (frozenset({"p99", "P99_MS"}), frozenset({"p99", "CI_SCALE_P99_MS"})):
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
GC1_BASIS_MS_PER_REQUEST = 2.427
GC1_BASIS_OWNER = "B1-LATENCY-BASIS-1"
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
    """FP-GC1-6: the stale 2.427 basis stays visible, unchanged and routed.

    Reads only tracked carriers, deliberately: this guard must stay collectable
    in CI, where the gitignored design tree does not exist.
    """
    import yaml as _yaml

    values_path = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
    values = _yaml.safe_load(values_path.read_text(encoding="utf-8"))
    basis = values["ingestGateway"]["sizingBasis"]
    assert float(basis["cpuMsPerRequest"]) == GC1_BASIS_MS_PER_REQUEST
    assert basis["observations"] == []
    assert "cpuMsPerRequest: 2.427" in values_path.read_text(encoding="utf-8")

    thresholds = _yaml.safe_load(
        (REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml").read_text(encoding="utf-8")
    )
    b1_entry = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")
    notes = b1_entry["notes"]
    assert GC1_BASIS_OWNER in notes, "B1 notes must route the basis to its owning slice"
    assert "cpuMsPerRequest=2.427" in notes
    assert "five consecutive" in notes

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
GC2_DEFERRED_AUDIT_TOKENS = (
    "BackgroundTask",
    "background_tasks",
    "create_task",
    "run_in_executor",
    "ThreadPoolExecutor",
    "Queue(",
    "asyncio",
    "after_response",
    "batch",
    "defer",
)
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
    """FP-GC2-7: the fused call order, the fixed bar, and the untouched knobs."""
    ingest_src = GC2_INGEST_PATH.read_text(encoding="utf-8")
    ingest_tree = ast.parse(ingest_src)
    txn = _gc2_function(ingest_tree, GC2_TXN, cls="IngestService")
    ingest_fn = _gc2_function(ingest_tree, "ingest", cls="IngestService")

    # (1) Exactly one fused call, first, before the platform lookup; the merged
    # return is preceded by exactly one commit inside its own branch.
    fused = _gc2_named_calls(txn, GC2_FUSED_HELPER)
    assert len(fused) == 1, [c.lineno for c in fused]
    platform_calls = _gc2_named_calls(txn, "get_platform")
    assert platform_calls, "the fallback lost its platform lookup"
    assert fused[0].lineno < min(c.lineno for c in platform_calls), (
        "the fused merge must be the first database operation"
    )
    assert len(_gc2_named_calls(ingest_tree, GC2_FUSED_HELPER)) == 1
    assert not _gc2_named_calls(ingest_fn, GC2_FUSED_HELPER), (
        "the fused statement must not run on the event loop"
    )

    merged_branch = None
    for node in ast.walk(txn):
        if isinstance(node, ast.If) and "existing_id is not None" in ast.unparse(node.test):
            merged_branch = node
    assert merged_branch is not None, "the merged fast branch is gone"
    branch_commits = _gc2_named_calls(merged_branch, "commit")
    branch_returns = [n for n in ast.walk(merged_branch) if isinstance(n, ast.Return)]
    assert len(branch_commits) == 1, [c.lineno for c in branch_commits]
    assert len(branch_returns) == 1
    assert branch_commits[0].lineno < branch_returns[0].lineno, (
        "a 2xx must not be produced before the durable commit"
    )
    returned = ast.unparse(branch_returns[0])
    assert returned.startswith("return (200,"), returned
    assert "'status': 'merged'" in returned, returned
    assert returned.rstrip().endswith("None)"), (
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
    # No deferred, batched or off-transaction audit machinery appeared.
    for token in GC2_DEFERRED_AUDIT_TOKENS:
        assert token not in ingest_src, f"deferred audit machinery: {token}"
    session_scopes = [
        node for node in ast.walk(txn)
        if isinstance(node, ast.With)
        and "self._session_factory()" in ast.unparse(node)
    ]
    assert len(session_scopes) == 1, "one request, one session scope"

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
    assert float(basis["cpuMsPerRequest"]) == GC1_BASIS_MS_PER_REQUEST == 2.427
    assert "cpuMsPerRequest: 2.427" in values_text
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
    assert "cpuMsPerRequest=2.427" in b1_entry["notes"]

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

    # Negative controls: one mutation at a time, each named.
    unordered = ingest_src.replace(
        "            existing_id = merge_existing_event_with_audit(",
        "            platform = get_platform(session, event['platform_key'])\n"
        "            existing_id = merge_existing_event_with_audit(", 1)
    assert unordered != ingest_src
    mutated = ast.parse(unordered)
    mutated_txn = _gc2_function(mutated, GC2_TXN, cls="IngestService")
    assert _gc2_named_calls(mutated_txn, GC2_FUSED_HELPER)[0].lineno > min(
        c.lineno for c in _gc2_named_calls(mutated_txn, "get_platform")
    ), "the ordering pin would not notice a reordered platform lookup"
    late_commit = ingest_src.replace(
        "            if existing_id is not None:\n                session.commit()\n",
        "            if existing_id is not None:\n", 1)
    assert late_commit != ingest_src
    late_branch = None
    for node in ast.walk(_gc2_function(ast.parse(late_commit), GC2_TXN, cls="IngestService")):
        if isinstance(node, ast.If) and "existing_id is not None" in ast.unparse(node.test):
            late_branch = node
    assert late_branch is not None
    assert not _gc2_named_calls(late_branch, "commit"), (
        "the commit-before-return pin would not notice a dropped commit"
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
GC3_DECISION_SCHEMA = 2
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
    """FP-GC3-3: the `decide` subparser's own argument surface, as built.

    Exactly required `--out`, required two-value `--pair` and optional
    `--base`; no positional path; and none of the forbidden override flags,
    read off the parser rather than off its source.
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
    if options != {"--out", "--base", "--pair"}:
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
    if base is None or base.required or base.default is not None:
        fails.append("--base is not an optional carrier to merge into")
    for forbidden in ("--force", "--select", "--candidate", "--threshold", "--tie",
                      "--topology", "--model", "--cpu-model", "--status"):
        if forbidden in options:
            fails.append(f"the decide parser exposes {forbidden}")
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
    # GC-3 rev 0.6: exactly required `--out`, required two-value `--pair`, and
    # optional `--base`. No positional path, and no other option: one
    # invocation admits one exact model and merges it into the carrier.
    decide_source = decide_block[1].split("\n\n", 1)[0]
    options = re.findall(r'decide\.add_argument\("([^"]+)"', decide_source)
    if options != ["--out", "--base", "--pair"]:
        fails.append(f"the decide CLI takes {options}")
    if any(not option.startswith("--") for option in options):
        fails.append("the decide CLI accepts a positional path")
    if 'decide.add_argument("--out", required=True)' not in decide_source:
        fails.append("--out is not required")
    if 'decide.add_argument("--pair", required=True, nargs=2' not in decide_source:
        fails.append("--pair is not a required two-value option")
    if 'decide.add_argument("--base", default=None)' not in decide_source:
        fails.append("--base is not an optional carrier to merge into")
    for forbidden in ("candidate", "threshold", "tie", "topology=", "--force", "--select"):
        if forbidden in decide_block[1]:
            fails.append(f"the decide CLI exposes {forbidden!r}")
    # ...and the same claim about the BUILT parser, not its source text. The
    # substring scan above runs over everything after the `decide` marker,
    # which includes the routing subparsers defined below it; this reads the
    # decide parser's own `option_strings`, so it neither misses a flag added
    # through a loop nor fires on a later subcommand's legitimate option.
    fails.extend(_gc3_decide_parser_failures())
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
    region = launcher.split("\nb1() {", 1)
    if len(region) != 2:
        return fails + ["the ordinary b1 target is missing"]
    b1_region = region[1].split("\n# The product promise", 1)[0]
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

    # (9) The sizing ledger is untouched and carries none of the RCA values.
    values_text = GC2_VALUES_PATH.read_text(encoding="utf-8")
    if "cpuMsPerRequest: 2.427" not in values_text:
        fails.append("cpuMsPerRequest moved")
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


def test_gc3_reference_topology_decision_is_evidence_backed():
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
    assert decision["schema"] == gc3.DECISION_SCHEMA == 2
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
    # The launcher never names a topology, whatever the carrier decided: the
    # ratified class reaches placement through route -> route-fields ->
    # contract-selected and nowhere else.
    launcher = GC3_LAUNCHER.read_text(encoding="utf-8")
    for topology in GC3_TOPOLOGY_IDS:
        assert f'"topology": "{topology}"' not in launcher, topology
        assert topology not in launcher, topology
