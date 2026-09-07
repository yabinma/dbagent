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
    tree = ast.parse(path.read_text(encoding="utf-8"))
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
    tree = ast.parse(path.read_text(encoding="utf-8"))
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


def _client_call_from_source(src: str) -> ast.Call:
    """Find the AsyncClient / Client construction Call node."""
    tree = ast.parse(src)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = None
        if isinstance(node.func, ast.Attribute):
            name = node.func.attr
        elif isinstance(node.func, ast.Name):
            name = node.func.id
        if name in {"AsyncClient", "Client"}:
            return node
    raise AssertionError("no AsyncClient/Client construction found")


def _call_kwargs(call: ast.Call) -> dict[str, ast.AST]:
    return {kw.arg: kw.value for kw in call.keywords if kw.arg is not None}


def _nested_call_kwargs(node: ast.AST, *, expected_names: set[str]) -> dict[str, ast.AST]:
    """Resolve a nested ``Limits(...)`` / ``Timeout(...)`` call's keyword args."""
    assert isinstance(node, ast.Call), f"expected Call, got {type(node)}"
    name = None
    if isinstance(node.func, ast.Attribute):
        name = node.func.attr
    elif isinstance(node.func, ast.Name):
        name = node.func.id
    assert name in expected_names, f"expected one of {expected_names}, got {name}"
    return _call_kwargs(node)


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


# Every nested HTTPX control that FP-IG-13 requires (design.md §11.3.3 H).
_HTTPX_PINNED_OUTER = {
    "trust_env": False,
    "http2": False,
    "http1": True,
    "follow_redirects": False,
}
_LIMITS_KEYS = ("max_connections", "max_keepalive_connections", "keepalive_expiry")
_TIMEOUT_KEYS = ("connect", "read", "write", "pool")


def _assert_httpx_fully_pinned(path: Path, src: str) -> None:
    """Parse and pin every nested HTTPX argument (FP-IG-13 / C4)."""
    call = _client_call_from_source(src)
    kwargs = _call_kwargs(call)

    for key, expected in _HTTPX_PINNED_OUTER.items():
        assert key in kwargs, f"{path.name}: AsyncClient missing {key}="
        assert isinstance(kwargs[key], ast.Constant) and kwargs[key].value is expected, (
            f"{path.name}: {key}={ast.dump(kwargs[key])} want {expected}"
        )

    assert "limits" in kwargs, f"{path.name}: AsyncClient missing limits="
    assert "timeout" in kwargs, f"{path.name}: AsyncClient missing timeout="
    # No proxy / SSL-context / event-hook arguments (design.md FP-IG-13).
    for forbidden in ("proxies", "proxy", "verify", "cert", "event_hooks", "mounts"):
        assert forbidden not in kwargs, f"{path.name}: forbidden client arg {forbidden}"

    limits = _nested_call_kwargs(kwargs["limits"], expected_names={"Limits"})
    for key in _LIMITS_KEYS:
        assert key in limits, f"{path.name}: Limits missing {key}="
    # Capacity must be the *parameter* ``max_connections`` (phase capacity),
    # not a weakened literal. Both keys bind that same name.
    assert _const_or_name(limits["keepalive_expiry"]) == ("name", "KEEPALIVE_EXPIRY"), (
        f"{path.name}: keepalive_expiry must be KEEPALIVE_EXPIRY"
    )
    mc = _const_or_name(limits["max_connections"])
    mk = _const_or_name(limits["max_keepalive_connections"])
    assert mc == ("name", "max_connections"), (
        f"{path.name}: max_connections must be the capacity parameter, got {mc}"
    )
    assert mk == ("name", "max_connections"), (
        f"{path.name}: max_keepalive_connections must be the capacity parameter, got {mk}"
    )

    assert "transport" in kwargs, f"{path.name}: missing transport="
    transport = _nested_call_kwargs(
        kwargs["transport"], expected_names={"B1ReservationTransport"}
    )
    assert set(transport) == {"limits", "trust_env", "http1", "http2", "retries"}
    assert ast.dump(transport["limits"]) == ast.dump(kwargs["limits"])
    for key, expected in {"trust_env": False, "http1": True, "http2": False, "retries": 0}.items():
        assert isinstance(transport[key], ast.Constant)
        assert transport[key].value is expected
    tree = ast.parse(src)
    classes = {n.name: n for n in tree.body if isinstance(n, ast.ClassDef)}
    pool_class = classes["B1ReservationPool"]
    transport_class = classes["B1ReservationTransport"]
    assert [ast.unparse(b) for b in pool_class.bases] == ["httpcore.AsyncConnectionPool"]
    assert [ast.unparse(b) for b in transport_class.bases] == ["httpx.AsyncHTTPTransport"]
    assert [n.name for n in pool_class.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))] == ["_assign_requests_to_connections"]
    init = next(n for n in transport_class.body if isinstance(n, ast.FunctionDef) and n.name == "__init__")
    expected_init = ast.parse("""
def __init__(self, *, limits, trust_env, http1, http2, retries):
    super().__init__(limits=limits, trust_env=trust_env, http1=http1, http2=http2, retries=retries)
    pool = self._pool
    self._pool = B1ReservationPool(
        ssl_context=pool._ssl_context,
        max_connections=pool._max_connections,
        max_keepalive_connections=pool._max_keepalive_connections,
        keepalive_expiry=pool._keepalive_expiry,
        http1=pool._http1, http2=pool._http2, retries=pool._retries,
    )
""").body[0]
    assert ast.dump(init) == ast.dump(expected_init), f"{path.name}: transport/pool construction drift"

    timeout = _nested_call_kwargs(kwargs["timeout"], expected_names={"Timeout"})
    for key in _TIMEOUT_KEYS:
        assert key in timeout, f"{path.name}: Timeout missing {key}="
        assert _const_or_name(timeout[key]) == ("name", "CLIENT_TIMEOUT"), (
            f"{path.name}: timeout.{key} must be CLIENT_TIMEOUT"
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
    """FP-IG-13: constants, no env reads, full HTTPX pin on every harness surface."""
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
        _assert_httpx_fully_pinned(path, text)
        _assert_phase_capacity_bindings(path, text)

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


# Omission fixtures: dropping any one nested control must make the pin red.
_OMISSION_TARGETS: list[tuple[str, str]] = [
    ("keepalive_expiry", "keepalive_expiry=KEEPALIVE_EXPIRY"),
    ("max_keepalive_connections", "max_keepalive_connections=max_connections"),
    ("max_connections", "max_connections=max_connections"),
    ("connect", "connect=CLIENT_TIMEOUT"),
    ("read", "read=CLIENT_TIMEOUT"),
    ("write", "write=CLIENT_TIMEOUT"),
    ("pool", "pool=CLIENT_TIMEOUT"),
    ("http1", "http1=True"),
]


@pytest.mark.parametrize("target,anchor", _OMISSION_TARGETS, ids=[t[0] for t in _OMISSION_TARGETS])
def test_fp_ig13_guard_rejects_httpx_control_omission(target: str, anchor: str):
    """FP-IG-13 negative: omitting any nested HTTPX control is red (C4)."""
    src = REF_PATH.read_text(encoding="utf-8")
    assert anchor in src, f"anchor for {target} missing from reference profile"
    # Drop the keyword argument (and its trailing comma if present).
    mutated = src.replace(f"            {anchor},\n", "", 1)
    if mutated == src:
        mutated = src.replace(f"        {anchor},\n", "", 1)
    assert mutated != src, f"failed to omit {target}"
    try:
        _assert_httpx_fully_pinned(REF_PATH, mutated)
    except AssertionError:
        return  # expected red
    raise AssertionError(f"omitting {target} still passed the HTTPX pin")


# Value-changing mutations: retain the argument name but weaken the bound value.
# Each must make the pin go red (C4 remaining gap / FP-IG-13).
_VALUE_MUTATIONS: list[tuple[str, str, str]] = [
    # (id, old_snippet, new_snippet)
    ("client_timeout_literal", "CLIENT_TIMEOUT = float(BURST_SECONDS)", "CLIENT_TIMEOUT = 0.001"),
    (
        "keepalive_expiry_literal",
        "KEEPALIVE_EXPIRY = float(BURST_SECONDS)",
        "KEEPALIVE_EXPIRY = 0.001",
    ),
    (
        "max_connections_literal_1",
        "max_connections=max_connections,\n"
        "            max_keepalive_connections=max_connections,",
        "max_connections=1,\n"
        "            max_keepalive_connections=1,",
    ),
    (
        "max_keepalive_only_literal",
        "max_keepalive_connections=max_connections,",
        "max_keepalive_connections=1,",
    ),
    (
        "connect_timeout_literal",
        "connect=CLIENT_TIMEOUT,",
        "connect=0.001,",
    ),
    (
        "read_timeout_literal",
        "read=CLIENT_TIMEOUT,",
        "read=0.001,",
    ),
    (
        "write_timeout_literal",
        "write=CLIENT_TIMEOUT,",
        "write=0.001,",
    ),
    (
        "pool_timeout_literal",
        "pool=CLIENT_TIMEOUT,",
        "pool=0.001,",
    ),
    (
        "keepalive_expiry_arg_literal",
        "keepalive_expiry=KEEPALIVE_EXPIRY,",
        "keepalive_expiry=0.001,",
    ),
    (
        "http1_false",
        "http1=True,",
        "http1=False,",
    ),
]


@pytest.mark.parametrize(
    "mutation_id,old,new",
    _VALUE_MUTATIONS,
    ids=[m[0] for m in _VALUE_MUTATIONS],
)
def test_fp_ig13_guard_rejects_httpx_value_weakening(mutation_id: str, old: str, new: str):
    """FP-IG-13 negative: value-changing mutations on every nested pin are red (C4)."""
    src = REF_PATH.read_text(encoding="utf-8")
    assert old in src, f"anchor for {mutation_id} missing from reference profile"
    mutated = src.replace(old, new, 1)
    assert mutated != src, f"failed to apply {mutation_id}"
    tree_assigns: dict[str, ast.AST] = {}
    tree = ast.parse(mutated)
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            t = node.targets[0]
            if isinstance(t, ast.Name):
                tree_assigns[t.id] = node.value
    try:
        # Full surface: assignment inventory + nested HTTPX + phase capacity.
        _assert_timeout_constants_pinned(REF_PATH, tree_assigns)
        _assert_httpx_fully_pinned(REF_PATH, mutated)
        _assert_phase_capacity_bindings(REF_PATH, mutated)
    except AssertionError:
        return  # expected red
    raise AssertionError(f"value mutation {mutation_id} still passed the HTTPX pin")


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


_BD_CONSTRUCTION_MUTATIONS = [
    ("plain_transport", "transport=B1ReservationTransport(", "transport=httpx.AsyncHTTPTransport("),
    ("plain_pool", "self._pool = B1ReservationPool(", "self._pool = httpcore.AsyncConnectionPool("),
    ("unequal_inner_limits", "                max_connections=max_connections,", "                max_connections=1,"),
    ("transport_environment", "            trust_env=False,", "            trust_env=True,"),
    ("transport_http2", "            http2=False,", "            http2=True,"),
] + [
    ("pool_" + key, key + "=pool._" + key + ",", key + "=" + value + ",")
    for key, value in (
        ("max_connections", "1"), ("max_keepalive_connections", "1"),
        ("keepalive_expiry", "0.001"), ("http1", "False"),
        ("http2", "True"), ("retries", "1"),
    )
] + [
    ("pool_ssl_context_" + name, "ssl_context=pool._ssl_context,", "ssl_context=" + value + ",")
    for name, value in (
        ("none", "None"), ("new", "ssl.SSLContext()"),
        ("unrelated", "other._ssl_context"),
    )
]


@pytest.mark.parametrize("path", [REF_PATH, E2E_PATH], ids=["reference", "e2e"])
@pytest.mark.parametrize("name,old,new", _BD_CONSTRUCTION_MUTATIONS, ids=[m[0] for m in _BD_CONSTRUCTION_MUTATIONS])
def test_bd_construction_mutations(path, name, old, new):
    source = path.read_text()
    assert old in source, name
    with pytest.raises(AssertionError):
        _assert_httpx_fully_pinned(path, source.replace(old, new, 1))


@pytest.mark.parametrize("path", [REF_PATH, E2E_PATH])
def test_bd_omitted_transport(path):
    tree = ast.parse(path.read_text())
    call = next(n for n in ast.walk(tree) if isinstance(n, ast.Call) and _call_func_name(n) == "AsyncClient")
    call.keywords = [k for k in call.keywords if k.arg != "transport"]
    with pytest.raises(AssertionError):
        _assert_httpx_fully_pinned(path, ast.unparse(tree))


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
