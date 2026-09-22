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


PRODUCT_REF_TEST = "test_b1_product_exclusive_reference_profile"
PRODUCT_FIXTURE = "b1_product_run"
LIVE_RUN_IMPL = "_run_b1_reference"

# Exact nineteen-node FAILURE inventory. Each entry: (test_file, test_name,
# required_names, required_op_types or None, equality_admitted).
# Equality is admitted ONLY for B1 accounting clauses.
#
# bench-on-demand (FP-BOD-3/8): the isolated half is the PRODUCT node, the only
# live B1 node left. Its `errors == 0` and `served == offered` are now real
# gates, so they are inventory rows; `product_p99_lt_150_ms` is NOT, because a
# truthful `missed` leaves the node green, and the kind due-time p99 is not
# either -- that comparison, its recorded observation and the module behind it
# are deleted. Admitting a non-failing node here would count it as a gate.
B1_FAILURE_INVENTORY: list[tuple[Path, str, frozenset[str], frozenset[type] | None, bool]] = [
    # --- FP-GC1-3 / FP-BOD-3 product reference: 7 B1 clauses + max_in_flight = 8 ---
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"platform_online"}), frozenset({ast.Eq}), True),
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"served", "errors", "offered"}), frozenset({ast.Eq}), True),
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"errors"}), frozenset({ast.Eq}), True),
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"served", "offered"}), frozenset({ast.Eq}), True),
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"offered", "PRODUCT_TOTAL_REQUESTS"}), frozenset({ast.Eq}), True),
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"committed", "served"}), frozenset({ast.Eq}), True),
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"served_rate", "PRODUCT_SUSTAINED_FLOOR"}), frozenset({ast.GtE}), False),
    (REF_TEST, PRODUCT_REF_TEST, frozenset({"max_in_flight", "PRODUCT_MAX_IN_FLIGHT"}), frozenset({ast.Lt}), False),
    # --- FP-IG-9 e2e: eleven failure clauses ---
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
    """Apply one of the required negative mutations (design.md FP-IG-19).

    Replacements target complete multi-line statement blocks so the mutated
    source remains parseable (the guard is AST-based). bench-on-demand
    (FP-BOD-3) re-pointed every isolated-tier anchor at the product node: it is
    the only live B1 node left, and the two p99 mutations went with the
    CI-scale bar, because the product run records its p99 instead of gating on
    it and there is no failure-producing latency comparison left to delete.
    """
    if mutation == "accounting_deleted":
        # 1. served + errors == offered deleted (product multi-line assert)
        old = (
            "    assert served + errors == offered, (\n"
            "        f\"served+errors!=offered {served}+{errors}!={offered}; {line}\"\n"
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
        old = '    assert committed == served, f"committed={committed} served={served}; {line}"'
        assert old in src, "committed_weakened anchor missing"
        return src.replace(
            old,
            '    assert committed >= served, f"committed={committed} served={served}; {line}"',
            1,
        )
    if mutation == "errors_gate_deleted":
        # 4. FP-BOD-3: the errors bar deleted outright.
        old = '    assert errors == 0, f"errors={errors}; {line}"'
        assert old in src, "errors_gate_deleted anchor missing"
        return src.replace(old, "    # mutated: errors == 0 deleted", 1)
    if mutation == "committed_bare_expression":
        # 5. assert committed == served → bare expression
        old = '    assert committed == served, f"committed={committed} served={served}; {line}"'
        assert old in src, "committed_bare_expression anchor missing"
        return src.replace(
            old, "    committed == served  # bare expression; cannot fail", 1
        )
    if mutation == "shortfall_gate_under_if_false":
        # 6. FP-BOD-3: the shortfall bar moved under a dead branch.
        old = '    assert served == offered, f"served={served} offered={offered}; {line}"'
        assert old in src, "shortfall_gate_under_if_false anchor missing"
        return src.replace(
            old,
            "    if False:\n"
            '        assert served == offered, f"served={served} offered={offered}; {line}"',
            1,
        )
    if mutation == "in_nested_def":
        # 7. qualifying assertion moved into uncalled nested def
        old = (
            '    assert served_rate >= PRODUCT_SUSTAINED_FLOOR, f"served_rate={served_rate}; {line}"'
        )
        assert old in src, "in_nested_def anchor missing"
        return src.replace(
            old,
            "    def _hidden():\n"
            '        assert served_rate >= PRODUCT_SUSTAINED_FLOOR, f"served_rate={served_rate}; {line}"\n'
            "    # nested not called",
            1,
        )
    if mutation == "rate_floor_deleted":
        # 8. served_rate >= PRODUCT_SUSTAINED_FLOOR deleted
        old = (
            '    assert served_rate >= PRODUCT_SUSTAINED_FLOOR, f"served_rate={served_rate}; {line}"'
        )
        assert old in src, "rate_floor_deleted anchor missing"
        return src.replace(old, "    # mutated: rate floor deleted", 1)
    raise ValueError(mutation)


# Eight mutations: (id, which file, which inventory names must go missing)
B1_NEGATIVE_MUTATIONS: list[tuple[str, Path, frozenset[str]]] = [
    ("accounting_deleted", REF_TEST, frozenset({"served", "errors", "offered"})),
    ("platform_online_deleted", E2E_TEST, frozenset({"platform_online"})),
    ("committed_weakened", REF_TEST, frozenset({"committed", "served"})),
    ("errors_gate_deleted", REF_TEST, frozenset({"errors"})),
    ("committed_bare_expression", REF_TEST, frozenset({"committed", "served"})),
    ("shortfall_gate_under_if_false", REF_TEST, frozenset({"served", "offered"})),
    ("in_nested_def", REF_TEST, frozenset({"served_rate", "PRODUCT_SUSTAINED_FLOOR"})),
    ("rate_floor_deleted", REF_TEST, frozenset({"served_rate", "PRODUCT_SUSTAINED_FLOOR"})),
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
    test_name = PRODUCT_REF_TEST if path == REF_TEST else "test_b1_ingest_burst_profile"
    healthy = _nodes_for(path, test_name)
    # Find the inventory entry for this mutation's names on this path.
    eq_ok = True
    ops = frozenset({ast.Eq})
    for p, tn, names, rops, eok in B1_FAILURE_INVENTORY:
        if p == path and names == required_names:
            ops = rops
            eq_ok = eok
            break
    # The rate floor is an ordering comparison; every other required name set
    # here is an accounting or identity equality.
    if required_names == frozenset({"served_rate", "PRODUCT_SUSTAINED_FLOOR"}):
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
        "product_errors_eq_0",
        REF_TEST,
        '    assert errors == 0, f"errors={errors}; {line}"',
        frozenset({"errors"}),
    ),
    (
        "product_served_eq_offered",
        REF_TEST,
        '    assert served == offered, f"served={served} offered={offered}; {line}"',
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
    test_name = PRODUCT_REF_TEST if path == REF_TEST else "test_b1_ingest_burst_profile"
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

    # bench-on-demand FP-BOD-8: the kind burst's two `B1 env=...tier=e2e...`
    # prints and the cgroup sampling that filled them are deleted with the p99
    # tape, so there is no fingerprint left here to pin. What this node owns is
    # the Unhealthy-event oracle above, which still fails the job (clause 9),
    # and the restart and audit readings the other clauses consume. None of
    # those field names may come back as a fingerprint key.
    src = path.read_text(encoding="utf-8")
    for retired in (
        "gw_cpu_seconds=",
        "gw_throttled_usec=",
        "gw_nr_throttled=",
        "gw_restarts=",
        "f\"in_flight=",
        "cgroup_cpu_s=",
        "nr_throttled_delta=",
        "tier=e2e",
    ):
        assert retired not in src, f"retired fingerprint key {retired!r} is back"
    # The readings the eleven clauses do consume are still taken.
    assert "_gateway_restart_count()" in src
    assert "_count_ingest_audit_rows(" in src
    assert "_unhealthy_events_since(" in src


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

#: Which profile constant each test-module bar literal must equal. FP-BOD-2
#: deleted the CI-scale bars with the route that measured them, so the product
#: bars are the whole map.
PRODUCT_BARS = {
    "PRODUCT_P99_MS": 150.0,
    "PRODUCT_SUSTAINED_FLOOR": 200,
    "PRODUCT_MAX_IN_FLIGHT": 1000,
    "PRODUCT_TOTAL_REQUESTS": 30000,
}
_BAR_TO_PROFILE_CONSTANT = {
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
# bench-on-demand FP-BOD-2: the per-exact-cpuModel CI-scale maps are deleted
# with the carrier that decided them. The product-local entry and the product
# schema are the whole surface, and they are unchanged.
GC1_AFFINITY_CARDINALITIES = {
    "product-exclusive": {"gateway": 4, "postgres": 3, "driver": 1},
}
GC1_PRODUCT_PLACEMENT_SCHEMA = 2
GC1_PLACEMENT_MECHANISM = "sched-affinity"
GC1_DIAGNOSTIC_UNAVAILABLE = "unavailable"
# Docker bandwidth/cpuset controls, removed as the allocation primitive.
GC1_BANDWIDTH_CONTROLS = ("--cpus", "--cpu-period", "--cpu-quota", "--cpuset-cpus",
                          "cpu_period=", "cpu_quota=", "cpuset_cpus=")
GC1_MARKERS = ("b1_live", "b1_product")


def _gc1_cardinality_map_failures(test_assigns: "dict[str, ast.AST]") -> list[str]:
    """FP-BOD-2: one declared cardinality, and no route back to the others.

    The per-exact-cpuModel CI-scale maps and the scalar defaults they replaced
    are both deleted. What must remain is the product-local 4/3/1 and nothing
    that could act as a fallback for another profile.
    """
    fails: list[str] = []
    for retired in (
        "CI_SCALE_AFFINITY_CARDINALITIES_BY_CPU_MODEL",
        "CI_SCALE_PLACEMENT_SCHEMAS_BY_CPU_MODEL",
        "CI_SCALE_AFFINITY_CARDINALITY",
        "B1_PLACEMENT_SCHEMA",
    ):
        if retired in test_assigns:
            fails.append(f"the retired declaration {retired} survives")
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

    Every function that injects a live fixture carries ``b1_live``, and --
    since FP-BOD-2 left the product profile as the only one -- also
    ``b1_product``. Adding an unmarked live consumer is a named failure, so the
    container-free selection cannot silently acquire live work.
    """
    tree = ast.parse(src)
    fails: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        params = {a.arg for a in node.args.args}
        markers = _decorator_markers(node)
        live = params & {PRODUCT_FIXTURE}
        if not live:
            continue
        if not node.name.startswith("test"):
            # The fixture definition itself is the one admitted exception:
            # `def b1_product_run(...)` takes no live fixture, so only a
            # *consumer* reaches here.
            fails.append(f"{where}::{node.name}: non-test consumer of a live fixture")
            continue
        if "b1_live" not in markers:
            fails.append(f"{where}::{node.name}: live-fixture consumer without b1_live")
        if "b1_product" not in markers:
            fails.append(f"{where}::{node.name}: product-fixture consumer without b1_product")
    return fails


def _live_marker_failures(src: str) -> list[str]:
    """The live-fixture/marker map of the one harness module left.

    FP-BOD-2 deleted the discovery module, its fixture and the CPU-basis
    oracle, so there is one live fixture, ``b1_product_run``, and one place it
    can be consumed from. A live node that arrives without both markers would
    be collected by the container-free selection, which is what this catches.
    """
    fails = _live_consumer_failures(src, where=REF_TEST.name)
    for retired in ("b1_ci_scale_run", "b1_topology_probe_run"):
        if retired in src:
            fails.append(f"{REF_TEST.name}: the retired live fixture {retired} survives")
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
    return fails


def _product_partition_failures(src: str) -> list[str]:
    """The recorded/gating partition inside the product node.

    FP-BOD-3 moved two of the three product comparisons across that line:
    ``errors == 0`` and ``served == offered`` are failure-producing asserts and
    are required below. The p99 stays recorded: the node may check that its
    serialized token *equals its own live comparison*, and may check the token
    is one of the two admitted words, but it may not require it -- or the loop
    variable that reaches every token -- to be ``met``. That rule is what stops
    a recorded status being turned back into a bar; it never applied to the two
    equalities, whose comparators are ``0`` and ``offered``.
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
        if not any(r in ("VERDICT_MET", "'met'", '"met"') for r in rendered):
            continue
        # Only the RECORDED token may not be required `met`: the p99 field by
        # name, and the loop variable that reaches every token in turn.
        left = ast.unparse(cmp_node.left)
        if left in ("token", "product_p99_lt_150_ms", '"product_p99_lt_150_ms"',
                    "_parse_b1_env_field(line, 'product_p99_lt_150_ms')") or (
            "product_p99_lt_150_ms" in left
        ):
            fails.append(f"{PRODUCT_REF_TEST}: truth-gates a recorded status: {ast.unparse(cmp_node)}")
    body = ast.get_source_segment(src, node) or ""
    for gating in (
        "assert served + errors == offered",
        "assert committed == served",
        'assert b1_product_run["placement_ok"] is True',
        "assert served_rate >= PRODUCT_SUSTAINED_FLOOR",
        "assert max_in_flight < PRODUCT_MAX_IN_FLIGHT",
        'assert b1_product_run["worker_set_ok"]',
        # FP-BOD-3: the two release bars.
        "assert errors == 0",
        "assert served == offered",
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

    # FP-BOD-2: the CI-scale profile constants are deleted with their route,
    # and no copy of them may survive in either carrier.
    for retired in (
        "CI_SCALE_BURST_RATE", "CI_SCALE_BURST_SECONDS", "CI_SCALE_TOTAL_REQUESTS",
        "CI_SCALE_P99_MS", "CI_SCALE_SUSTAINED_FLOOR", "CI_SCALE_MAX_IN_FLIGHT",
        "CI_SCALE_PROLOGUE_REQUESTS",
    ):
        assert retired not in profile_assigns, f"b1_reference_profile.py still binds {retired}"
        assert retired not in test_assigns, f"test_b1_ingest_burst.py still binds {retired}"
        assert retired not in _module_assigns(E2E_PATH), f"the e2e copy binds {retired}"
    # The product profile constants are untouched.
    for name, expected in SHARED_CONSTANTS.items():
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    assert _eval_simple_constant(
        profile_assigns["TOTAL_REQUESTS"], profile_assigns
    ) == (
        _eval_simple_constant(profile_assigns["BURST_RATE"], profile_assigns)
        * _eval_simple_constant(profile_assigns["BURST_SECONDS"], profile_assigns)
    )

    # The test module's independent bar literals equal their profile counterparts.
    for name, expected in PRODUCT_BARS.items():
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
    # FP-BOD-2: the per-model CI-scale maps are gone with the carrier.
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
        "@pytest.mark.b1_live\n@pytest.mark.b1_product\ndef test_b1_product_exclusive_reference_profile(",
        "@pytest.mark.b1_product\ndef test_b1_product_exclusive_reference_profile(", 1)
    assert unmarked != test_src
    assert any("without b1_live" in f for f in _live_marker_failures(unmarked))
    unproducted = test_src.replace(
        "@pytest.mark.b1_live\n@pytest.mark.b1_product\ndef test_b1_product_exclusive_reference_profile(",
        "@pytest.mark.b1_live\ndef test_b1_product_exclusive_reference_profile(", 1)
    assert unproducted != test_src
    assert any("without b1_product" in f for f in _live_marker_failures(unproducted))
    unwitnessed = test_src.replace(
        "@pytest.mark.b1_live\n@pytest.mark.parametrize(\"driver\", [b1, bd_e2e], "
        "ids=[\"reference\", \"e2e\"])\n@pytest.mark.asyncio\nasync def "
        "test_b1_instant_server_clears_open_loop_offer(",
        "@pytest.mark.parametrize(\"driver\", [b1, bd_e2e], ids=[\"reference\", \"e2e\"])\n"
        "@pytest.mark.asyncio\nasync def test_b1_instant_server_clears_open_loop_offer(", 1)
    assert unwitnessed != test_src
    assert any("instant_server" in f for f in _live_marker_failures(unwitnessed))
    smuggled = test_src + (
        "\n\ndef test_b1_smuggled_live_consumer(b1_product_run):\n"
        "    assert b1_product_run\n"
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
# The failure-producing comparisons the B1 bar is made of. Each must be a bare
# assert on a comparison in the named test, not a recorded verdict.
# bench-on-demand (FP-BOD-2/3) deleted the CI-scale bar with its route; the
# product bar took its place, and `errors == 0` / `served == offered` are
# failure-producing there too. The p99 is deliberately NOT in this set: the
# product node records it.
GC2_PRODUCT_REQUIRED_ASSERTIONS = frozenset(
    {
        "offered == PRODUCT_TOTAL_REQUESTS",
        "served + errors == offered",
        "errors == 0",
        "served == offered",
        "committed == served",
        "served_rate >= PRODUCT_SUSTAINED_FLOOR",
        "max_in_flight < PRODUCT_MAX_IN_FLIGHT",
    }
)
GC2_FIXED_PRODUCT_LITERALS = {
    "BURST_RATE": 1000,
    "BURST_SECONDS": 30,
    "TOTAL_REQUESTS": 30000,
    "P99_MS": 150.0,
    "SUSTAINED_FLOOR": 200,
    "MAX_IN_FLIGHT": 1000,
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
# Product 4/3/1, spelled as the launcher spells it. FP-BOD-2 deleted every
# CI-scale allocation line with the route that used it; these three are the
# whole allocation the launcher performs.
GC2_LAUNCHER_AFFINITY_LINES = (
    'gateway_cpus="$(b1_canonical_cpu_list "${cpus[0]}" "${cpus[1]}" "${cpus[2]}" "${cpus[3]}")"',
    'postgres_cpus="$(b1_canonical_cpu_list "${cpus[4]}" "${cpus[5]}" "${cpus[6]}")"',
    'driver_cpus="$(b1_canonical_cpu_list "${cpus[7]}")"',
)
# FP-BOD-2: the routed CI-scale lines are deleted with the target that ran
# them. What the launcher runs now is the product driver, and nothing else.
GC2_LAUNCHER_ROUTED_LINES = (
    'b1_run_driver driver-product.sh "$driver_cpus"',
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

    # (3) The B1 bar is unchanged and still failure-producing.
    test_src = REF_TEST.read_text(encoding="utf-8")
    test_assigns = _source_assigns(test_src)
    profile_assigns = _module_assigns(REF_PATH)
    for name, expected in GC2_FIXED_PRODUCT_LITERALS.items():
        assert _eval_simple_constant(profile_assigns[name], profile_assigns) == expected, name
    for name in ("PRODUCT_TOTAL_REQUESTS", "PRODUCT_P99_MS",
                 "PRODUCT_SUSTAINED_FLOOR", "PRODUCT_MAX_IN_FLIGHT"):
        node = test_assigns[name]
        assert isinstance(node, ast.Constant), name
    product_test = _gc2_function(ast.parse(test_src), PRODUCT_REF_TEST)
    observed = {
        ast.unparse(node.test) for node in ast.walk(product_test)
        if isinstance(node, ast.Assert)
    }
    missing = GC2_PRODUCT_REQUIRED_ASSERTIONS - observed
    assert not missing, sorted(missing)
    for node in ast.walk(product_test):
        if isinstance(node, ast.Assert) and ast.unparse(node.test) in (
            GC2_PRODUCT_REQUIRED_ASSERTIONS
        ):
            assert isinstance(node.test, ast.Compare), ast.unparse(node.test)
    body = ast.get_source_segment(test_src, product_test) or ""
    for weakening in ("pytest.mark.skip", "pytest.mark.xfail", "pytest.skip("):
        assert weakening not in body, f"{PRODUCT_REF_TEST} must not {weakening}"

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
    for name, expected in GC4_FIXED_PRODUCT_LITERALS.items():
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
    product_verdicts = set(_module_tuple(harness_tree, "PRODUCT_VERDICT_FIELDS"))
    for field in GC4_COST_FIELDS:
        assert field not in gating, field
        assert field not in product_verdicts, field

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
    for value in GC4_RCA_DIAGNOSTICS + (GC2_INVESTIGATION_RUN_ID,):
        assert value not in rendered_basis, f"the sizing block carries {value}"


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
    "product on-demand: served == offered and 0 errors at 1000 req/s offered for 30s on "
    "the product-exclusive placement (gateway 4, PostgreSQL 3, driver 1), each role's CPU "
    "set exclusive of the others; p99 < 150 ms is printed as met or missed and is not the "
    "bar"
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
    for name, expected in GC5_FIXED_PRODUCT_LITERALS.items():
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

    # (4) No new field is a gating field or a product verdict. FP-BOD-2
    # deleted the GC-3 verdict, record-key and ranking surfaces entirely, so
    # this test keeps only the half that still has a subject: the SIZING half
    # below, and the placement/verdict partition here.
    gating = set(_module_tuple(harness_tree, "B1_GATING_PLACEMENT_FIELDS"))
    # The full inventory is a concatenation in the harness, so it is rebuilt
    # here from its two declared halves.
    placement = gating | set(
        _module_tuple(harness_tree, "B1_DIAGNOSTIC_PLACEMENT_FIELDS")
    )
    product_verdicts = set(_module_tuple(harness_tree, "PRODUCT_VERDICT_FIELDS"))
    for field in GC5_COMMIT_FIELDS:
        assert field not in gating, field
        assert field not in placement, field
        assert field not in product_verdicts, field

    # (5) No sizing carrier records them, and the ratio bar is not a sizing
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

    # (6) The manifest describes them as diagnostics, once, and names the one
    # node that consumes the ratio.
    thresholds = yaml.safe_load(GC5_THRESHOLDS.read_text(encoding="utf-8"))
    notes = next(e for e in thresholds["benchmarks"] if e["id"] == "B1")["notes"]
    for field in GC5_COMMIT_FIELDS:
        assert field in notes, field
    assert "reported diagnostic" in notes
    assert GC5_GATE_NODE in notes, "the manifest does not name the gate node"
    assert str(GC5_MAX_COMMITS_PER_SERVED) in notes

    # (7) The bar is COMPARED against in exactly two places: the live gate node
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


B1LB_LEDGER_MODULE = REPO_ROOT / "tests" / "delivery" / "test_delivery_sizing_ledger.py"
B1LB_VALUES = REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml"
B1LB_THRESHOLDS = REPO_ROOT / "tests" / "benchmark" / "thresholds.yaml"

b1lb = _load(B1LB_LEDGER_MODULE, "b1lb_sizing_ledger_profile")

#: One shell target's body, under the name this file's checks call it by: the
#: ONE definition, imported rather than copied. Three verbatim copies of it
#: existed until review-followups-batch-20260920 W1, and FP-BOD-2 deleted the
#: third (`_b1lb_region`) with the latency-basis target it was written for.
_b1_target_region = _manifests._b1_target_region


def test_b1_launcher_region_splitter_is_one_shared_definition():
    """The splitter name IS the manifests function, not a copy of it.

    `_b1_target_region` is an alias of
    tests/functional/test_manifests.py::_b1_target_region. Three verbatim
    copies of that body existed until review-followups-batch-20260920 W1, and
    a copy drifts silently because each one is reached by a different set of
    tests. Identity (`is`), never equality of behaviour: two independent
    bodies that agree today are exactly the state this pin exists to reject.
    The source leg catches the other shape of the same regression -- a copy
    defined ABOVE the alias, which the alias then shadows, so the identity
    leg alone would not see it.
    """
    assert _b1_target_region is _manifests._b1_target_region

    own_src = Path(__file__).read_text(encoding="utf-8")
    copied = sorted(
        node.name
        for node in ast.walk(ast.parse(own_src))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "_b1_target_region"
    )
    assert copied == [], f"the splitter body was copied back into this file: {copied}"


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
    # bench-on-demand FP-BOD-2/9: the GC-1 unqualified-basis route and the GC-3
    # scope pin were retired with the CI-scale route and the topology carrier,
    # and the two GC-3 helpers they delegated to went with them. The three
    # surviving owners are the whole list.
    retired_owners = (
        "test_gc2_write_path_scope_and_fixed_bar_are_pinned",
        "test_gc4_fixed_bars_and_sizing_boundaries_are_pinned",
        "test_gc5_fixed_workload_pool_schema_and_sizing_boundaries",
    )
    functions = {
        node.name: node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for name in retired_owners:
        assert name in functions, f"{name} is missing; the handoff owner moved"

    # Every assertion reachable from those owners must be free of the two
    # retired pins.
    rendered: list[str] = []
    for name in retired_owners:
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
    # The owner and the gate are named in the manifest the slices share. They
    # cite the B1-LATENCY-BASIS-1 SLICE and its provenance test, not the
    # deleted `b1_latency_basis` target, so FP-BOD-9 keeps both.
    assert GC1_BASIS_OWNER in b1_entry["notes"]
    assert GC1_BASIS_GATE in b1_entry["notes"]
    assert "2.427" not in b1_entry["notes"], "the notes state a basis number again"

    # FP-BOD-9: the live FP-IG-18 oracle is deleted, not re-homed. Nothing in
    # the harness re-measures the basis, and the static ledger gate above is
    # what a silent edit of 1.585 or of 317m/1585m still has to get past.
    ref_src = REF_TEST.read_text(encoding="utf-8")
    for retired in (
        "test_measured_cpu_cost_does_not_exceed_the_recorded_sizing_basis",
        "b1_latency_basis",
        "assert measured <= basis",
    ):
        assert retired not in ref_src, f"the retired CPU-basis oracle survives: {retired}"


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
        ("profile", "ci-scale-probe"),
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
    # FP-BOD-9: the shipped signature keeps the recorded model as HISTORY. The
    # carrier that used to decide it is deleted, so this is a literal now --
    # which is the point: nothing may quietly re-derive it.
    assert shipped_ig["sizingBasis"]["signature"]["cpuModel"] == (
        "AMD EPYC 7763 64-Core Processor"
    )

    # Control `qualified_selected_model_is_expected`: the deleted assertion,
    # applied to a structurally valid ledger. It is red for EVERY qualified
    # ledger -- the fixture, like any recording, carries its own signature
    # model -- so it was unsatisfiable rather than strict.
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
                    f"{b1lb.ROUTE_UNRATIFIED_REASON_PREFIX}{b1lb.FIXTURE_OTHER_MODEL}"
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
B1HN_FIXED_PRODUCT_LITERALS = {
    "PRODUCT_P99_MS": 150.0,
    "PRODUCT_SUSTAINED_FLOOR": 200,
    "PRODUCT_MAX_IN_FLIGHT": 1000,
    "PRODUCT_TOTAL_REQUESTS": 30000,
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

    # (3) No field is a gating field or a product verdict. FP-BOD-2 deleted
    # the GC-3 verdict, ranking-operand and record-key surfaces along with the
    # probe helper, so the product line is the only line these ten reach.
    gating = set(_module_tuple(harness_tree, "B1_GATING_PLACEMENT_FIELDS"))
    placement = gating | set(
        _module_tuple(harness_tree, "B1_DIAGNOSTIC_PLACEMENT_FIELDS")
    )
    product_verdicts = set(_module_tuple(harness_tree, "PRODUCT_VERDICT_FIELDS"))
    for field in B1HN_FIELDS:
        assert field not in gating, field
        assert field not in placement, field
        assert field not in product_verdicts, field

    # (4) No record validator, reference-profile assertion body or CPU-basis
    # oracle reads one. They may be PRINTED -- the whole fingerprint already
    # is -- but never compared.
    for consumer in (
        "commit_shape_record_failures",
        "postgres_cost_record_failures",
        PRODUCT_REF_TEST,
        "test_gc5_commit_shape_reference_profile",
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
        "test_b1_host_noise_snapshot_reads_declared_sources_at_window_boundaries",
        "test_b1_product_fingerprint_reports_host_noise_fields",
        # The two existing TAIL pins: both assert only that the block closes
        # the line, in its serialized form. Neither reads a value.
        "test_b1_fingerprint_line_reports_scoped_concurrency_warnings",
        GC5_CONTEXT_NODE,
    }, sorted(comparers)

    # (5) The B1 comparison and every fixed knob are exactly where they were.
    profile_assigns = _module_assigns(REF_PATH)
    harness_assigns = _source_assigns(harness_src)
    for name, expected in B1HN_FIXED_PRODUCT_LITERALS.items():
        source = profile_assigns if name in profile_assigns else harness_assigns
        assert ast.literal_eval(source[name]) == expected, name
    # ...and the product ceiling is still exactly one second of offered load.
    assert ast.unparse(profile_assigns["MAX_IN_FLIGHT"]) == "BURST_RATE"
    reference = _gc4_function(harness_tree, PRODUCT_REF_TEST)
    body = ast.get_source_segment(harness_src, reference) or ""
    assert "served_rate >= PRODUCT_SUSTAINED_FLOOR" in body
    assert "errors == 0" in body
    assert "served == offered" in body

    # (6) No retry, skip, xfail, `continue-on-error` or exit masking entered
    # any B1 carrier, and the live node carries no new marker.
    for parts in (
        ("services", "gateway", "tests", "test_b1_ingest_burst.py"),
        ("scripts", "integration-test.sh"),
        (".github", "workflows", "ci.yml"),
    ):
        text = REPO_ROOT.joinpath(*parts).read_text(encoding="utf-8")
        for token in B1HN_MASKING_TOKENS:
            assert token not in text, (parts[-1], token)
    live = _gc4_function(
        harness_tree, "test_b1_product_fingerprint_reports_host_noise_fields"
    )
    assert _decorator_markers(live) == {"b1_live", "b1_product"}, _decorator_markers(live)
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



# ---------------------------------------------------------------------------
# bench-on-demand -- the two new function tests (FP-BOD-3, FP-BOD-8).
#
# Both read the shipped sources with `ast`, for the same reason every pin in
# this file does: a string match on `assert errors == 0` is satisfied by a
# comment or an assertion message, and a live gate is an `ast.Assert` whose
# test is a comparison of two real operands.
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
#: The e2e step that must survive the diagnostics deletion, and the artifact
#: name that must not.
E2EBK_FAILURE_STEP_NAME = "Upload phase timing and pod logs on failure"
E2EBK_SUCCESS_ARTIFACT = "e2e-b1-diagnostics"
E2EBK_DIAGNOSTIC_MODULE = REPO_ROOT / "tests" / "e2e" / "b1_e2e_diagnostics.py"


def _bod_function(tree: ast.AST, name: str) -> ast.AST:
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    raise AssertionError(f"{name} not found")


def _bod_statement_lines(src: str, names: frozenset[str]) -> "tuple[int, int]":
    """The 1-based line span of the one top-level node that carries ``names``."""
    fn = _bod_function(ast.parse(src), "test_b1_ingest_burst_profile")
    for node in fn.body:
        cmp = _node_compare(node)
        if cmp is not None and _cmp_names(cmp) == names:
            return node.lineno, node.end_lineno
    raise AssertionError(f"no top-level comparison for {sorted(names)}")


def _bod_delete_statement(src: str, names: frozenset[str]) -> str:
    start, end = _bod_statement_lines(src, names)
    lines = src.split("\n")
    lines[start - 1:end] = [f"    # mutated: deleted {sorted(names)}"]
    return "\n".join(lines)


def _bod_weaken_statement(src: str, names: frozenset[str]) -> str:
    start, end = _bod_statement_lines(src, names)
    lines = src.split("\n")
    block = "\n".join(lines[start - 1:end])
    assert "==" in block, block
    lines[start - 1:end] = (block.replace("==", ">=", 1)).split("\n")
    return "\n".join(lines)


def test_b1_product_run_fails_on_errors_and_shortfall_and_not_on_p99():
    """FP-BOD-3 [function test]: the two release bars are real asserts.

    Named for two failures, and it takes both to go green.

    The first is a product run that records a shortfall as `missed` and stays
    green. That is what the node did before this slice, and it is what the
    release record cannot tolerate: a committed block whose tokens say `met`
    has to mean the run really served its whole offer with no errors. So
    ``errors == 0`` and ``served == offered`` must be live ``assert``
    statements inside the node -- proved through this file's own AST walk,
    which returns only an ``ast.Assert``/``ast.If`` test, so the
    ``VERDICT_MET if errors == 0 else ...`` conditional already in the token
    dictionary cannot satisfy it and neither can a comment or an assertion
    message.

    The second is the opposite regression: the node starting to FAIL on the
    p99. The slice's whole point is that the latency comparison is recorded,
    not gating, so no assert in the node may compare `p99` with
    `PRODUCT_P99_MS`, and none may require the p99 token to be `met`.
    """
    src = REF_TEST.read_text(encoding="utf-8")
    nodes = _nodes_for(REF_TEST, PRODUCT_REF_TEST)

    # (1) The two bars are live, one-to-one, and each is an equality.
    for names in (frozenset({"errors"}), frozenset({"served", "offered"})):
        assert _inventory_match(nodes, names, frozenset({ast.Eq}), True) is not None, (
            f"the product node has no live `assert` for {sorted(names)}"
        )

    # ...and each of them is genuinely load-bearing: deleting it, or weakening
    # its operator, takes it out of the failure surface.
    fn = _bod_function(ast.parse(src), PRODUCT_REF_TEST)
    for anchor, names in (
        ('    assert errors == 0, f"errors={errors}; {line}"', frozenset({"errors"})),
        (
            '    assert served == offered, f"served={served} offered={offered}; {line}"',
            frozenset({"served", "offered"}),
        ),
    ):
        assert anchor in src, anchor
        deleted = src.replace(anchor, "    # mutated: deleted", 1)
        assert _inventory_match(
            _nodes_for_src(deleted, PRODUCT_REF_TEST), names, frozenset({ast.Eq}), True
        ) is None, f"deleting {sorted(names)} still matched"
        weakened = src.replace(anchor, anchor.replace("==", ">=", 1), 1)
        assert weakened != src
        assert _inventory_match(
            _nodes_for_src(weakened, PRODUCT_REF_TEST), names, frozenset({ast.Eq}), True
        ) is None, f"weakening {sorted(names)} still matched the Eq inventory"

    # (2) The p99 is NOT a bar. No assert in the node compares it with the
    # constant, and none requires its token to be `met`.
    for statement in ast.walk(fn):
        if not isinstance(statement, ast.Assert):
            continue
        rendered = ast.unparse(statement.test)
        assert "PRODUCT_P99_MS" not in rendered, (
            f"the product node gates on the p99 again: {rendered}"
        )
    assert _product_partition_failures(src) == []
    truth_gated = src.replace(
        "        assert token == live[field_name], (",
        "        assert token == VERDICT_MET\n        assert token == live[field_name], (",
        1,
    )
    assert truth_gated != src
    assert any("truth-gates" in f for f in _product_partition_failures(truth_gated))

    # (3) ...and the partition helper notices a deleted bar as well, so the
    # two checks above are not the only thing standing between the release
    # record and a run that did not serve its offer.
    for anchor in (
        '    assert errors == 0, f"errors={errors}; {line}"',
        '    assert served == offered, f"served={served} offered={offered}; {line}"',
    ):
        ungated = src.replace(anchor, "", 1)
        assert ungated != src
        assert any(
            "missing gating assertion" in f for f in _product_partition_failures(ungated)
        ), anchor


def test_e2e_kind_burst_keeps_eleven_clauses_without_p99_machinery():
    """FP-BOD-8 [function test]: eleven clauses stay; the tape goes.

    Named for three failures.

    The first is a cleanup that drops a correctness assert while removing the
    p99 hook. The eleven comparisons below are matched one-to-one against live
    nodes, and each one is separately proved load-bearing by deleting it and
    by weakening its operator.

    The second is the success-only diagnostic upload surviving. That artifact
    existed to carry the 33-field diagnostic file the slice deletes; leaving
    the step would upload a path nothing writes.

    The third is the opposite mistake: removing the FAILURE log upload along
    with it. That step is not this slice's to touch, and an e2e job that fails
    without its pod logs is materially worse to debug.

    Searching for the absence of the string `p99` is not this test: the
    saturation path may still mention latency in a comment, and the eleven
    asserts are the thing the test is for.
    """
    load_src = E2E_TEST.read_text(encoding="utf-8")

    # (1) The failure inventory carries exactly these eleven kind rows, and no
    # p99 row: a non-failing observation may never be counted as a gate.
    rows = [
        r for r in B1_FAILURE_INVENTORY
        if r[0] == E2E_TEST and r[1] == "test_b1_ingest_burst_profile"
    ]
    assert len(rows) == 11
    assert tuple(r[2] for r in rows) == E2EBK_KIND_FAILURE_ROWS
    assert frozenset({"p99", "P99_MS"}) not in {r[2] for r in rows}

    # (2) Each row matches exactly one live node, one-to-one, through the seam.
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

    # (3) Deleting or weakening ANY of the eleven is red for that row alone.
    for _path, _name, names, ops, eq_ok in rows:
        deleted = _bod_delete_statement(load_src, names)
        assert deleted != load_src, sorted(names)
        assert _inventory_match(
            _nodes_for_src(deleted, "test_b1_ingest_burst_profile"), names, ops, eq_ok
        ) is None, f"deleting {sorted(names)} still matched"
        assert ops == frozenset({ast.Eq}) and eq_ok, sorted(names)
        weakened = _bod_weaken_statement(load_src, names)
        assert weakened != load_src, sorted(names)
        assert _inventory_match(
            _nodes_for_src(weakened, "test_b1_ingest_burst_profile"),
            names,
            frozenset({ast.Eq}),
            True,
        ) is None, f"weakening {sorted(names)} still matched Eq inventory"

    # ... and the locator those mutations use refuses to guess.
    with pytest.raises(AssertionError):
        _bod_statement_lines(load_src, frozenset({"no_such_clause"}))

    # (4) The p99 machinery is gone from the function and from the tree: no
    # recorded observation, no diagnostic session, no module.
    fn = _bod_function(ast.parse(load_src), "test_b1_ingest_burst_profile")
    called = {
        (node.func.id if isinstance(node.func, ast.Name) else
         node.func.attr if isinstance(node.func, ast.Attribute) else "")
        for node in ast.walk(fn) if isinstance(node, ast.Call)
    }
    assert "record_property" not in called, "the kind p99 observation is back"
    named = {node.id for node in ast.walk(fn) if isinstance(node, ast.Name)}
    assert "B1E2EDiagnosticSession" not in named, "the diagnostic session is back"
    assert "record_property" not in {a.arg for a in fn.args.args}, (
        "the node still takes the record_property fixture"
    )
    assert "b1_e2e_diagnostics" not in load_src
    assert not E2EBK_DIAGNOSTIC_MODULE.exists(), "the diagnostic module is back"

    # (5) The workflow: the success-only upload is gone, the failure upload
    # stays, by exact step name.
    workflow_text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    assert E2EBK_SUCCESS_ARTIFACT not in workflow_text, (
        "the success-only B1 diagnostics artifact is back"
    )
    workflow = yaml.safe_load(workflow_text)
    e2e_steps = workflow["jobs"]["e2e"]["steps"]
    names = [step.get("name") for step in e2e_steps]
    assert E2EBK_FAILURE_STEP_NAME in names, (
        "the failure log upload was removed with the success artifact"
    )
    failure = next(s for s in e2e_steps if s.get("name") == E2EBK_FAILURE_STEP_NAME)
    assert failure.get("if") == "failure()", failure
    assert "/tmp/rca-e2e/**" in str(failure["with"]["path"]).split()

    # (6) Kind resources are untouched: this slice changed no pod request or
    # limit, including the bundled PostgreSQL's 500m CPU ceiling, which the
    # e2e deployment throttles against on every run and which the slice
    # explicitly leaves out of scope.
    chart = yaml.safe_load(
        (REPO_ROOT / "deploy" / "charts" / "dbagent" / "values.yaml").read_text(
            encoding="utf-8"
        )
    )
    postgres = chart["postgresql"]["resources"]
    assert postgres["limits"]["cpu"] == "500m", postgres
    assert postgres["requests"]["cpu"] == "50m", postgres
