"""FP-IG-8/13/14/15/19 and UT-IG-7: B1 harness surface, classifiers, generators."""
from __future__ import annotations

import ast
import asyncio
import importlib.util
import time
from pathlib import Path

import pytest

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


# Exact twenty-node inventory. Each entry: (test_file, test_name, required_names,
# required_op_types or None, equality_admitted).
# Equality is admitted ONLY for B1 accounting clauses.
B1_INVENTORY: list[tuple[Path, str, frozenset[str], frozenset[type] | None, bool]] = [
    # --- FP-IG-7 reference: 7 B1 clauses + max_in_flight harness = 8 ---
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"platform_online"}), frozenset({ast.Eq}), True),
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"served", "errors", "offered"}), frozenset({ast.Eq}), True),
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"errors"}), frozenset({ast.Eq}), True),
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"served", "offered"}), frozenset({ast.Eq}), True),
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"p99", "P99_MS"}), frozenset({ast.Lt}), False),
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"committed", "served"}), frozenset({ast.Eq}), True),
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"served_rate", "SUSTAINED_FLOOR"}), frozenset({ast.GtE}), False),
    (REF_TEST, "test_b1_ingest_burst_reference_profile", frozenset({"max_in_flight", "MAX_IN_FLIGHT"}), frozenset({ast.Lt}), False),
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
            "{b1_reference_run['fingerprint']}\"\n"
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
            "{b1_reference_run['fingerprint']}\"\n"
            "    )"
        )
        assert old in src, "committed_weakened anchor missing"
        return src.replace(
            old,
            "    assert committed >= served, (\n"
            "        f\"committed={committed} served={served}; "
            "{b1_reference_run['fingerprint']}\"\n"
            "    )",
            1,
        )
    if mutation == "p99_deleted":
        # 4. p99 < P99_MS deleted
        old = "    assert p99 < P99_MS, f\"p99={p99}; {b1_reference_run['fingerprint']}\""
        assert old in src, "p99_deleted anchor missing"
        return src.replace(old, "    # mutated: p99 < P99_MS deleted", 1)
    if mutation == "committed_bare_expression":
        # 5. assert committed == served → bare expression
        old = (
            "    assert committed == served, (\n"
            "        f\"committed={committed} served={served}; "
            "{b1_reference_run['fingerprint']}\"\n"
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
        old = "    assert p99 < P99_MS, f\"p99={p99}; {b1_reference_run['fingerprint']}\""
        assert old in src, "under_if_false anchor missing"
        return src.replace(
            old,
            "    if False:\n"
            "        assert p99 < P99_MS, f\"p99={p99}; {b1_reference_run['fingerprint']}\"",
            1,
        )
    if mutation == "in_nested_def":
        # 7. qualifying assertion moved into uncalled nested def
        old = (
            "    assert served_rate >= SUSTAINED_FLOOR, (\n"
            "        f\"served_rate={served_rate}; {b1_reference_run['fingerprint']}\"\n"
            "    )"
        )
        assert old in src, "in_nested_def anchor missing"
        return src.replace(
            old,
            "    def _hidden():\n"
            "        assert served_rate >= SUSTAINED_FLOOR, (\n"
            "            f\"served_rate={served_rate}; {b1_reference_run['fingerprint']}\"\n"
            "        )\n"
            "    # nested not called",
            1,
        )
    if mutation == "rate_floor_deleted":
        # 8. served_rate >= SUSTAINED_FLOOR deleted
        old = (
            "    assert served_rate >= SUSTAINED_FLOOR, (\n"
            "        f\"served_rate={served_rate}; {b1_reference_run['fingerprint']}\"\n"
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
    ("p99_deleted", REF_TEST, frozenset({"p99", "P99_MS"})),
    ("committed_bare_expression", REF_TEST, frozenset({"committed", "served"})),
    ("under_if_false", REF_TEST, frozenset({"p99", "P99_MS"})),
    ("in_nested_def", REF_TEST, frozenset({"served_rate", "SUSTAINED_FLOOR"})),
    ("rate_floor_deleted", REF_TEST, frozenset({"served_rate", "SUSTAINED_FLOOR"})),
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
    test_name = (
        "test_b1_ingest_burst_reference_profile"
        if path == REF_TEST
        else "test_b1_ingest_burst_profile"
    )
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
    if required_names == frozenset({"p99", "P99_MS"}):
        ops, eq_ok = frozenset({ast.Lt}), False
    if required_names == frozenset({"served_rate", "SUSTAINED_FLOOR"}):
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
        '    assert errors == 0, f"errors={errors}; {b1_reference_run[\'fingerprint\']}"',
        frozenset({"errors"}),
    ),
    (
        "ref_served_eq_offered",
        REF_TEST,
        '    assert served == offered, f"served={served}; {b1_reference_run[\'fingerprint\']}"',
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
    test_name = (
        "test_b1_ingest_burst_reference_profile"
        if path == REF_TEST
        else "test_b1_ingest_burst_profile"
    )
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
    tree = ast.parse(reference_source)
    helper = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_b1_gateway_process")
    fixture = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "b1_reference_run")
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
    owned = [n for n in ast.walk(fixture) if isinstance(n, ast.With) and any(isinstance(i.context_expr, ast.Call) and _call_func_name(i.context_expr) == "_b1_gateway_process" and isinstance(i.optional_vars, ast.Name) and i.optional_vars.id == "proc" for i in n.items)]
    assert len(owned) == 1
    call = owned[0].items[0].context_expr
    assert {k.arg: ast.unparse(k.value) for k in call.keywords} == {"env": "env", "log_path": "log_path"}
    assert "_PROFILE_PATH" in ast.unparse(call.args[0])
    assert not any(isinstance(n, ast.Call) and _call_func_name(n) == "Popen" for n in ast.walk(fixture))
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
        source.replace("with _b1_gateway_process(", "with subprocess.Popen(", 1),
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
