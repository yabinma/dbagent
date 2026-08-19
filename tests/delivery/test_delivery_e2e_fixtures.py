"""FP-M6-15/17: the e2e fixtures must be installable and usable as written.

Two classes of defect this tier catches before a 25-minute cluster run does:

* a seeded admin password the dashboard-api's own policy rejects, which makes
  `run.sh` phase 4 fail deterministically at change-password (code review round
  4, C2);
* a `run.sh` phase table whose declared budgets no longer describe a feasible
  run against the approved 1500 s gate (code review round 4, W1).
"""
from __future__ import annotations

import ast
import importlib.util
import json
import os
import re
import shutil
import signal
import subprocess
import textwrap
from pathlib import Path

import pytest
import yaml

from delivery_helpers import REPO_ROOT

from rca_common.config import DashboardConfig

E2E = REPO_ROOT / "tests" / "e2e"
RUN_SH = E2E / "run.sh"
E2E_VALUES = E2E / "values-dbagent.yaml"

# design.md §11.1.3, "run.sh phases and their budget caps (total 1480 s, 20 s
# reserve under the 1500 s gate)".  Order matters: adjacency is what the table
# describes.
APPROVED_PHASE_BUDGETS = [
    ("preflight", 20),
    ("build_and_cluster", 500),
    ("kind_load", 130),
    ("helm_dbagent", 180),
    ("deploy_presto", 150),
    ("helm_dbagent_probe", 60),
    ("pytest_e2e", 420),
    ("teardown", 20),
]
APPROVED_PHASE_TOTAL = 1480
RUN_SH_GATE = 1500

_PHASE_RE = re.compile(r'^\s*phase\s+"([a-z0-9_]+)"\s+(\d+)\s', re.MULTILINE)
_PASS_RE = re.compile(r'^PASS\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


def _bash_function_definition_count(text: str, name: str) -> int:
    """Count bash function definitions of *name* in *text*.

    ``[ \\t\\r\\n]*\\{`` also matches brace-on-next-line bash style
    (``function foo\\n{\\n...\\n}``), which a same-line-only form misses.

    This is a small, deliberately over-approximating heuristic, not a bash
    grammar (see rounds 3-5 of review.md for why we stopped reimplementing
    one). It does not see a comment inserted between the name and the brace,
    or a function defined via ``eval``, and it can false-positive on a bare
    call immediately followed by an unrelated ``{ ... }`` group command
    (fails closed: red, not a missed defect). A redefinition mid-script is
    not a plausible accident, so these are accepted, named boundaries
    rather than gaps to keep chasing — the same call this project's
    manifest-honesty checker makes for general control-flow/reachability
    (design.md §11.1.3, clause (L)).
    """
    return len(re.findall(
        rf"^[ \t]*(?:function[ \t]+)?{re.escape(name)}[ \t]*(?:\([ \t]*\))?[ \t\r\n]*\{{",
        text, re.M))


def _declared_phases() -> list[tuple[str, int]]:
    return [(name, int(budget)) for name, budget in _PHASE_RE.findall(
        RUN_SH.read_text(encoding="utf-8")
    )]


def _effective_password_min_length() -> int:
    """The bar the deployed dashboard-api will actually enforce for e2e."""
    values = yaml.safe_load(E2E_VALUES.read_text(encoding="utf-8")) or {}
    dashboard = ((values.get("config") or {}).get("dashboard") or {})
    if "password_min_length" in dashboard:
        return int(dashboard["password_min_length"])
    return DashboardConfig().password_min_length


def _e2e_passwords() -> dict[str, str]:
    """Every place the e2e suite spells the admin password."""
    found: dict[str, str] = {}

    values = yaml.safe_load(E2E_VALUES.read_text(encoding="utf-8")) or {}
    seeded = ((values.get("secrets") or {}).get("data") or {}).get(
        "ADMIN_INITIAL_PASSWORD"
    )
    assert seeded, "tests/e2e/values-dbagent.yaml must seed ADMIN_INITIAL_PASSWORD"
    found[str(E2E_VALUES.relative_to(REPO_ROOT))] = str(seeded)

    run_sh = RUN_SH.read_text(encoding="utf-8")
    literals = _PASS_RE.findall(run_sh)
    assert literals, "run.sh must bind PASS for its dashboard-api calls"
    for index, literal in enumerate(literals):
        found[f"tests/e2e/run.sh#PASS[{index}]"] = literal

    for module in ("test_e2e_scenarios.py", "test_e2e_smoke.py"):
        text = (E2E / module).read_text(encoding="utf-8")
        match = re.search(
            r'ADMIN_PASS\s*=\s*os\.environ\.get\(\s*"E2E_ADMIN_PASS"\s*,\s*"([^"]+)"',
            text,
        )
        assert match, f"{module} must default E2E_ADMIN_PASS"
        found[f"tests/e2e/{module}"] = match.group(1)

    return found


def _scenarios_module():
    """The e2e scenario module, imported without a cluster.

    Its waiter is pure HTTP plumbing, so it can — and, after code review round
    5 C2, must — be proved here rather than only inside a 25-minute kind run.
    """
    spec = importlib.util.spec_from_file_location(
        "e2e_scenarios_under_test", E2E / "test_e2e_scenarios.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, payload: dict, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self) -> dict:
        return self._payload


def _stub_list(monkeypatch, module, pages):
    """Serve `pages` (one per GET) from the case-list endpoint."""
    calls: list[dict] = []
    served = list(pages)

    def fake_get(url, **kwargs):
        calls.append(dict(kwargs.get("params") or {}))
        payload = served.pop(0) if served else served_last(pages)
        return _FakeResponse(payload)

    def served_last(all_pages):
        return all_pages[-1]

    monkeypatch.setattr(module.httpx, "get", fake_get)
    monkeypatch.setattr(module.time, "sleep", lambda _s: None)
    return calls


TARGET = "11111111-1111-1111-1111-111111111111"
OTHER = "22222222-2222-2222-2222-222222222222"


def test_wait_case_never_accepts_an_unrelated_case_in_the_wanted_status(monkeypatch):
    """C2: a stale/other case in a terminal status, ahead of the target."""
    module = _scenarios_module()
    _stub_list(
        monkeypatch,
        module,
        [{"items": [{"investigation_id": OTHER, "status": "RESOLVED"}], "next_cursor": None}],
    )
    with pytest.raises(AssertionError) as excinfo:
        module._wait_case(
            "http://dash",
            "tok",
            investigation_id=TARGET,
            statuses={"RESOLVED"},
            timeout=0.2,
        )
    message = str(excinfo.value)
    assert TARGET in message
    assert OTHER not in message


def test_wait_case_requires_the_target_id_and_the_status_together(monkeypatch):
    module = _scenarios_module()
    _stub_list(
        monkeypatch,
        module,
        [
            {
                "items": [
                    {"investigation_id": OTHER, "status": "RESOLVED"},
                    {"investigation_id": TARGET, "status": "INVESTIGATING"},
                ],
                "next_cursor": None,
            },
            {
                "items": [
                    {"investigation_id": OTHER, "status": "RESOLVED"},
                    {"investigation_id": TARGET, "status": "RESOLVED"},
                ],
                "next_cursor": None,
            },
        ],
    )
    found = module._wait_case(
        "http://dash",
        "tok",
        investigation_id=TARGET,
        statuses={"RESOLVED"},
        timeout=30,
    )
    assert found["investigation_id"] == TARGET
    assert found["status"] == "RESOLVED"


def test_wait_case_pages_past_a_full_first_page(monkeypatch):
    """B1's burst can push a scenario's case off the first page."""
    module = _scenarios_module()
    calls = _stub_list(
        monkeypatch,
        module,
        [
            {
                "items": [{"investigation_id": OTHER, "status": "RESOLVED"}],
                "next_cursor": "cursor-1",
            },
            {
                "items": [{"investigation_id": TARGET, "status": "CLOSED_SUMMARY"}],
                "next_cursor": None,
            },
        ],
    )
    found = module._wait_case(
        "http://dash",
        "tok",
        investigation_id=TARGET,
        statuses={"CLOSED_SUMMARY"},
        timeout=30,
    )
    assert found["investigation_id"] == TARGET
    assert calls[1].get("cursor") == "cursor-1"


def test_wait_case_refuses_to_run_without_an_investigation_id(monkeypatch):
    module = _scenarios_module()
    _stub_list(monkeypatch, module, [{"items": [], "next_cursor": None}])
    for missing in (None, "", "None"):
        with pytest.raises(AssertionError):
            module._wait_case(
                "http://dash", "tok", investigation_id=missing, timeout=0.2
            )


def test_approve_pending_posts_approved_and_fails_closed(monkeypatch):
    """C2/W1: decision domain is enforced; silent failures hide a stuck
    AWAITING_APPROVAL and green E1/E4 without remediation."""
    import httpx

    module = _scenarios_module()
    posts: list[dict] = []

    class _Resp:
        def __init__(self, status_code: int, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = json.dumps(payload) if not isinstance(payload, str) else payload

        def json(self):
            return self._payload

    def fake_get(url, **kwargs):
        params = kwargs.get("params") or {}
        assert "approvals" in url
        assert "pending" in str(params)
        assert str(params.get("investigation_id")) == "inv-1"
        return _Resp(
            200,
            {
                "items": [
                    {
                        "approval_id": "ap-1",
                        "investigation_id": "inv-1",
                        "decision": None,
                    }
                ]
            },
        )

    def fake_post(url, **kwargs):
        posts.append({"url": url, "json": kwargs.get("json")})
        return _Resp(200, {"ok": True})

    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", fake_post)

    # Valid decision domain (default + each accepted value).
    for decision in ("approved", "denied", "need_more"):
        posts.clear()
        module._approve_pending(
            "http://dash", "tok", "inv-1", decision=decision
        )
        assert posts, f"decision POST never fired for {decision!r}"
        assert posts[0]["json"]["decision"] == decision
        assert "ap-1" in posts[0]["url"]

    # FP-AP-3: a server that ignores investigation_id (returns another
    # investigation's pending approval) must fail the all-items-match
    # assertion. This is red whenever any other investigation holds a
    # pending approval; the client-side filter that hid G1 is refused.
    def ignore_filter_get(url, **kwargs):
        return _Resp(
            200,
            {
                "items": [
                    {
                        "approval_id": "ap-other",
                        "investigation_id": "inv-OTHER",
                        "decision": None,
                    }
                ]
            },
        )

    monkeypatch.setattr(httpx, "get", ignore_filter_get)
    with pytest.raises(AssertionError, match="other investigations"):
        module._approve_pending("http://dash", "tok", "inv-1")

    # Invalid decision is rejected before any HTTP call.
    posts.clear()
    with pytest.raises(AssertionError, match="decision must be one of"):
        module._approve_pending(
            "http://dash", "tok", "inv-1", decision="maybe"
        )
    assert posts == [], "invalid decision must not POST"

    # Missing pending approval must fail, not silently return.
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *a, **k: _Resp(200, {"items": []}),
    )
    with pytest.raises(AssertionError, match="no pending approval"):
        module._approve_pending("http://dash", "tok", "inv-1")

    # Invalid GET status must fail closed.
    monkeypatch.setattr(
        httpx,
        "get",
        lambda *a, **k: _Resp(500, "boom"),
    )
    with pytest.raises(AssertionError, match="GET /approvals"):
        module._approve_pending("http://dash", "tok", "inv-1")

    # POST failure must fail closed (round 7, W1).
    monkeypatch.setattr(httpx, "get", fake_get)

    def fail_post(url, **kwargs):
        posts.append({"url": url, "json": kwargs.get("json")})
        return _Resp(500, "nope")

    posts.clear()
    monkeypatch.setattr(httpx, "post", fail_post)
    with pytest.raises(AssertionError, match="POST decision"):
        module._approve_pending("http://dash", "tok", "inv-1")


def test_approve_pending_mixed_page_does_not_post(monkeypatch):
    """Mixed page (target + foreign) must not be decided.

    Lives in its own function so ``assert posts == []`` cannot be
    shadowed by the other-only case's ``match="other investigations"``
    prose assertion. The shipped helper raises before POSTing; a helper
    that filters client-side POSTs the target. Swallowing AssertionError
    lets the behavioural discriminator run either way.
    """
    import httpx

    module = _scenarios_module()
    posts: list[dict] = []

    class _Resp:
        def __init__(self, status_code: int, payload):
            self.status_code = status_code
            self._payload = payload
            self.text = json.dumps(payload) if not isinstance(payload, str) else payload

        def json(self):
            return self._payload

    def mixed_page_get(url, **kwargs):
        return _Resp(
            200,
            {
                "items": [
                    {
                        "approval_id": "ap-other",
                        "investigation_id": "inv-OTHER",
                        "decision": None,
                    },
                    {
                        "approval_id": "ap-1",
                        "investigation_id": "inv-1",
                        "decision": None,
                    },
                ]
            },
        )

    def fake_post(url, **kwargs):
        posts.append({"url": url, "json": kwargs.get("json")})
        return _Resp(200, {"ok": True})

    monkeypatch.setattr(httpx, "get", mixed_page_get)
    monkeypatch.setattr(httpx, "post", fake_post)

    try:
        module._approve_pending("http://dash", "tok", "inv-1")
    except AssertionError:
        pass
    assert posts == [], "a page containing foreign items must not be decided"


def test_e2e_scenarios_contain_no_status_only_case_selection():
    """The predicate shape C2 flagged must not come back in any scenario."""
    source = (E2E / "test_e2e_scenarios.py").read_text(encoding="utf-8")
    assert "predicate=" not in source, (
        "case selection must go through _wait_case(investigation_id=...), not a "
        "predicate that can match on status alone"
    )
    for scenario_status in ("RESOLVED", "CLOSED_SUMMARY"):
        assert f'it.get("status") in {{"{scenario_status}"' not in source


def _scenario_source(name: str) -> str:
    import ast

    source = (E2E / "test_e2e_scenarios.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    node = next(
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    )
    return ast.get_source_segment(source, node) or ""


def test_e1_reads_the_pre_snapshot_row_the_design_names():
    """C4: `remediation_executions.pre_snapshot` non-empty is the bar; the
    case-detail projection does not carry that column."""
    body = _scenario_source("test_e1_worker_oom_to_resolved")
    assert "presto.adjust_memory_config" in body
    assert "pre_snapshot" in body and "_psql(" in body
    assert 'if ex.get("pre_snapshot") is not None' not in body


def test_e1_requires_failed_memory_query_before_the_alert():
    """C2/C3: FINISHED must not stand in for a memory-limit fault; the exact
    Presto error name is required (not a generic "exceeded")."""
    body = _scenario_source("test_e1_worker_oom_to_resolved")
    assert 'state == "FAILED"' in body
    assert "TERMINAL_QUERY_STATES | {\"GONE\"}" not in body
    assert "_is_presto_local_memory_limit_failure" in body
    assert "EXCEEDED_LOCAL_MEMORY_LIMIT" in body or "PRESTO_LOCAL_MEMORY_LIMIT_ERROR" in body


def test_e1_waits_for_worker_discovery_after_restart():
    """E1 must gate the trip query on current worker IPs in /v1/node."""
    body = _scenario_source("test_e1_worker_oom_to_resolved")
    restart_pos = body.find("_restart_and_wait(WORKER_WORKLOAD)")
    wait_pos = body.find("_wait_presto_workers_discovered")
    query_pos = body.find("_presto_query(")
    assert restart_pos != -1, "E1 must restart workers after starve patch"
    assert wait_pos != -1, "E1 must wait for coordinator worker discovery"
    assert query_pos != -1, "E1 must submit the heavy query"
    assert restart_pos < wait_pos < query_pos, (
        "_wait_presto_workers_discovered must run after worker restart "
        "and before _presto_query"
    )


def _fake_worker_pod_list_json(ips: set[str]) -> str:
    """Build kubectl pod-list JSON for _worker_pod_ips unit fakes."""
    return json.dumps(
        {
            "items": [
                {
                    "metadata": {},
                    "status": {
                        "phase": "Running",
                        "podIP": ip,
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                }
                for ip in sorted(ips)
            ]
        }
    )


def _stats_nodes(hosts: set[str]) -> list[dict]:
    """Presto 0.298 HeartbeatFailureDetector.Stats JSON (uri only)."""
    return [{"uri": f"http://{host}:8080/v1/status"} for host in sorted(hosts)]


def _fake_presto_node_get(
    node_hosts: set[str],
    failed_hosts: set[str] | None = None,
):
    """Route httpx.get to /v1/node and /v1/node/failed fakes."""
    failed = failed_hosts if failed_hosts is not None else set()

    def fake_get(url: str, **_k):
        if url.endswith("/v1/node/failed"):
            return _FakeResponse(_stats_nodes(failed))
        if url.endswith("/v1/node"):
            return _FakeResponse(_stats_nodes(node_hosts))
        raise AssertionError(f"unexpected GET {url!r}")

    return fake_get


def test_wait_presto_workers_discovered_accepts_matching_ips(monkeypatch):
    """Matching live worker URIs must return success, not only time out."""
    mod = _scenarios_module()
    current_ips = {"10.244.0.25", "10.244.0.26"}

    class _FakeProc:
        stdout = _fake_worker_pod_list_json(current_ips)

    monkeypatch.setattr(mod, "_kubectl_ok", lambda *_a, **_k: _FakeProc())
    monkeypatch.setattr(
        mod.httpx,
        "get",
        _fake_presto_node_get(current_ips),
    )
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    mod._wait_presto_workers_discovered("http://presto.example", timeout=10.0)


def test_wait_presto_workers_discovered_ignores_failed_stale_uris(monkeypatch):
    """CI E1: stale stats in /v1/node but /v1/node/failed must not block."""
    mod = _scenarios_module()
    current_ips = {"10.244.0.27", "10.244.0.28"}
    stale_ips = {"10.244.0.23", "10.244.0.24"}
    node_hosts = stale_ips | current_ips

    class _FakeProc:
        stdout = _fake_worker_pod_list_json(current_ips)

    monkeypatch.setattr(mod, "_kubectl_ok", lambda *_a, **_k: _FakeProc())
    monkeypatch.setattr(
        mod.httpx,
        "get",
        _fake_presto_node_get(node_hosts, failed_hosts=stale_ips),
    )
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    mod._wait_presto_workers_discovered("http://presto.example", timeout=10.0)


def test_wait_presto_workers_discovered_rejects_warming_workers_in_failed(
    monkeypatch,
):
    """Workers in both /v1/node and /v1/node/failed during warmup must time out."""
    mod = _scenarios_module()
    current_ips = {"10.244.0.27", "10.244.0.28"}

    class _FakeProc:
        stdout = _fake_worker_pod_list_json(current_ips)

    monkeypatch.setattr(mod, "_kubectl_ok", lambda *_a, **_k: _FakeProc())
    monkeypatch.setattr(
        mod.httpx,
        "get",
        _fake_presto_node_get(current_ips, failed_hosts=current_ips),
    )
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    clock = {"t": 1000.0}

    def fake_time() -> float:
        clock["t"] += 5.0
        return clock["t"]

    monkeypatch.setattr(mod.time, "time", fake_time)

    with pytest.raises(AssertionError, match=r"(?s)worker discovery.*10\.244\.0\.2[78]"):
        mod._wait_presto_workers_discovered(
            "http://presto.example", timeout=10.0
        )


def test_wait_presto_workers_discovered_rejects_still_active_stale_uris(
    monkeypatch,
):
    """Stale hosts still active (not in /v1/node/failed) must time out."""
    mod = _scenarios_module()
    current_ips = {"10.244.0.27", "10.244.0.28"}
    stale_ips = {"10.244.0.23", "10.244.0.24"}
    node_hosts = stale_ips | current_ips

    class _FakeProc:
        stdout = _fake_worker_pod_list_json(current_ips)

    monkeypatch.setattr(mod, "_kubectl_ok", lambda *_a, **_k: _FakeProc())
    monkeypatch.setattr(
        mod.httpx,
        "get",
        _fake_presto_node_get(node_hosts, failed_hosts=set()),
    )
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    clock = {"t": 1000.0}

    def fake_time() -> float:
        clock["t"] += 5.0
        return clock["t"]

    monkeypatch.setattr(mod.time, "time", fake_time)

    with pytest.raises(AssertionError, match=r"(?s)worker discovery.*10\.244\.0\.2[34]"):
        mod._wait_presto_workers_discovered(
            "http://presto.example", timeout=10.0
        )


def test_wait_presto_workers_discovered_rejects_terminating_pod_ips(monkeypatch):
    """Terminating previous-generation pod IPs must not count as current."""
    mod = _scenarios_module()
    current_ips = {"10.244.0.25", "10.244.0.26"}
    terminating_ip = "10.244.0.23"
    kubectl_json = {
        "items": [
            {
                "metadata": {"deletionTimestamp": "2026-08-18T16:45:10Z"},
                "status": {
                    "phase": "Running",
                    "podIP": terminating_ip,
                    "conditions": [{"type": "Ready", "status": "True"}],
                },
            },
            *[
                {
                    "metadata": {},
                    "status": {
                        "phase": "Running",
                        "podIP": ip,
                        "conditions": [{"type": "Ready", "status": "True"}],
                    },
                }
                for ip in sorted(current_ips)
            ],
        ]
    }
    node_hosts = {terminating_ip, *current_ips}

    class _FakeProc:
        stdout = json.dumps(kubectl_json)

    monkeypatch.setattr(mod, "_kubectl_ok", lambda *_a, **_k: _FakeProc())
    monkeypatch.setattr(
        mod.httpx,
        "get",
        _fake_presto_node_get(node_hosts),
    )
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    clock = {"t": 1000.0}

    def fake_time() -> float:
        clock["t"] += 5.0
        return clock["t"]

    monkeypatch.setattr(mod.time, "time", fake_time)

    with pytest.raises(AssertionError, match=r"(?s)worker discovery.*10\.244\.0\.23"):
        mod._wait_presto_workers_discovered(
            "http://presto.example", timeout=10.0
        )


def test_wait_presto_workers_discovered_retries_httpx_connection_error(
    monkeypatch,
):
    """Transient /v1/node connect failures must retry until success."""
    import httpx

    mod = _scenarios_module()
    current_ips = {"10.244.0.25", "10.244.0.26"}

    class _FakeProc:
        stdout = _fake_worker_pod_list_json(current_ips)

    calls = {"n": 0}
    router = _fake_presto_node_get(current_ips)

    def fake_get(url: str, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectError("connection refused")
        return router(url)

    monkeypatch.setattr(mod, "_kubectl_ok", lambda *_a, **_k: _FakeProc())
    monkeypatch.setattr(mod.httpx, "get", fake_get)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)

    mod._wait_presto_workers_discovered("http://presto.example", timeout=10.0)
    assert calls["n"] == 3, (
        "helper must retry after a transient connect error "
        "(1 failed + /v1/node + /v1/node/failed)"
    )


def test_e1_memory_error_predicate_rejects_unrelated_limits():
    """Round 7 C2: execution-time exceeded is not a memory fault."""
    import importlib.util
    from pathlib import Path

    path = Path(__file__).resolve().parents[1] / "e2e" / "test_e2e_scenarios.py"
    spec = importlib.util.spec_from_file_location("_e2e_scen_c2", path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)

    # Unrelated FAILED payloads must not satisfy the memory-fault predicate.
    unrelated = [
        {"state": "FAILED", "error": "execution time exceeded"},
        {
            "state": "FAILED",
            "errorCode": {"name": "EXCEEDED_TIME_LIMIT"},
        },
        {
            "state": "FAILED",
            "failureInfo": {"errorCode": {"name": "EXCEEDED_TIME_LIMIT"}},
        },
        {"state": "FAILED", "error": "CPU limit exceeded"},
        # Global memory is a different Presto code; E1 starves local per-node.
        {"state": "FAILED", "errorCode": {"name": "EXCEEDED_GLOBAL_MEMORY_LIMIT"}},
        {"state": "FINISHED"},
    ]
    for payload in unrelated:
        assert not mod._is_presto_local_memory_limit_failure(payload), payload

    memory_ok = [
        {
            "state": "FAILED",
            "errorCode": {"name": "EXCEEDED_LOCAL_MEMORY_LIMIT"},
        },
        {
            "state": "FAILED",
            "failureInfo": {
                "errorCode": {"name": "EXCEEDED_LOCAL_MEMORY_LIMIT"},
            },
        },
        {
            "state": "FAILED",
            "message": "Query exceeded per-node memory limit: EXCEEDED_LOCAL_MEMORY_LIMIT",
        },
    ]
    for payload in memory_ok:
        assert mod._is_presto_local_memory_limit_failure(payload), payload


def test_wait_query_terminal_expired_deadline_names_timeout_and_last_state(
    monkeypatch,
):
    """G-1: an already-expired deadline must not return ``{}`` silently.

    Today the while-loop never runs, so the helper returns its initial
    ``last = {}`` and E1 renders that as ``state=''``. After the fix it
    must signal a timeout that carries the last observed state.
    """
    mod = _scenarios_module()
    monkeypatch.setattr(mod.time, "time", lambda: 10.0)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        mod.httpx,
        "get",
        lambda *_a, **_k: _FakeResponse(
            {"queryId": "q-stuck", "state": "RUNNING"}
        ),
    )
    with pytest.raises(AssertionError, match=r"(?s)timed out.*RUNNING"):
        result = mod._wait_query_terminal(
            "http://presto.example", "q-stuck", deadline=0.0
        )
        pytest.fail(
            f"expired wait returned silently instead of signalling timeout: "
            f"{result!r}"
        )


def test_wait_query_terminal_404_is_gone_even_after_deadline(monkeypatch):
    """G-1 blast radius: the 404 → GONE sentinel must survive an expired wait."""
    mod = _scenarios_module()
    monkeypatch.setattr(mod.time, "time", lambda: 10.0)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(
        mod.httpx,
        "get",
        lambda *_a, **_k: _FakeResponse({}, status_code=404),
    )
    got = mod._wait_query_terminal(
        "http://presto.example", "q-gone", deadline=0.0
    )
    assert got == {"queryId": "q-gone", "state": "GONE"}


def test_presto_query_exhausted_follow_loop_names_timeout_not_empty_state(
    monkeypatch,
):
    """G-1 / C1: a nextUri loop that consumes the whole budget must not report
    ``state=''``, and must not grant extra runtime past the original timeout.

    The follow loop and the terminal wait share one deadline. When nextUri
    never terminates, the authoritative read still happens once (so E1 does
    not render ``state=''``), but a later FAILED transition must not make
    the wait succeed — that would let E1 pass a query that missed the bar.
    The default 180s timeout is not under test here — a 1s budget plus a
    stubbed clock keeps this docker-free and fast.
    """
    import inspect

    mod = _scenarios_module()
    assert inspect.signature(mod._presto_query).parameters["timeout"].default == 180.0
    assert not hasattr(mod, "TERMINAL_WAIT_FLOOR_S"), (
        "a terminal-wait floor grants extra query runtime past the 180s bar"
    )

    clock = {"t": 1000.0}
    query_gets = {"n": 0}

    def fake_time() -> float:
        return clock["t"]

    def fake_sleep(seconds: float) -> None:
        clock["t"] += float(seconds)

    def fake_post(_url, **_kwargs):
        return _FakeResponse(
            {
                "id": "q-slow",
                "nextUri": "http://presto.example/v1/statement/q-slow/1",
            }
        )

    def fake_get(url, **_kwargs):
        url = str(url)
        if "/v1/query/" in url:
            query_gets["n"] += 1
            if query_gets["n"] == 1:
                return _FakeResponse({"queryId": "q-slow", "state": "RUNNING"})
            # Post-deadline FAILED: extra polling past the bar would return
            # this and E1 would treat the query as having failed in time.
            return _FakeResponse(
                {
                    "queryId": "q-slow",
                    "state": "FAILED",
                    "errorCode": {"name": "EXCEEDED_LOCAL_MEMORY_LIMIT"},
                }
            )
        # nextUri never terminates; consume the follow-loop budget on first GET.
        clock["t"] += 2.0
        return _FakeResponse(
            {"id": "q-slow", "nextUri": "http://presto.example/v1/statement/q-slow/2"}
        )

    monkeypatch.setattr(mod.time, "time", fake_time)
    monkeypatch.setattr(mod.time, "sleep", fake_sleep)
    monkeypatch.setattr(mod.httpx, "post", fake_post)
    monkeypatch.setattr(mod.httpx, "get", fake_get)

    with pytest.raises(AssertionError, match=r"timed out") as ei:
        result = mod._presto_query(
            "http://presto.example", "SELECT 1", timeout=1.0
        )
        pytest.fail(
            f"post-deadline FAILED must not make the wait succeed: state="
            f"{str(result.get('state') or '')!r} result={result!r}"
        )
    message = str(ei.value).lower()
    assert "running" in message, str(ei.value)
    # Distinguish a dispatch-loop exhaustion from a slow terminal wait.
    assert "nexturi" in message or "follow" in message or "exhausted" in message, (
        str(ei.value)
    )
    assert query_gets["n"] == 1, (
        "a post-deadline transition must not be observed: only the mandatory "
        f"authoritative GET is allowed, got {query_gets['n']}"
    )


def test_e1_still_requires_failed_state_and_does_not_extend_query_timeout():
    """G-1 guard: the diagnostic fix must not turn E1 green by relaxing the bar."""
    body = _scenario_source("test_e1_worker_oom_to_resolved")
    assert 'state == "FAILED"' in body
    assert "timeout=" not in body.split("_presto_query", 1)[1][:400]
    source = (E2E / "test_e2e_scenarios.py").read_text(encoding="utf-8")
    assert "timeout: float = 180.0" in source
    assert "TERMINAL_WAIT_FLOOR_S" not in source


def test_wait_query_terminal_does_not_get_again_after_deadline(monkeypatch):
    """C1: the mandatory first GET is the last GET once the deadline has passed."""
    mod = _scenarios_module()
    clock = {"t": 10.0}
    gets = {"n": 0}

    def fake_time() -> float:
        return clock["t"]

    def fake_sleep(seconds: float) -> None:
        clock["t"] += float(seconds)

    def fake_get(_url, **_kwargs):
        gets["n"] += 1
        if gets["n"] == 1:
            return _FakeResponse({"queryId": "q-stuck", "state": "RUNNING"})
        return _FakeResponse({"queryId": "q-stuck", "state": "FAILED"})

    monkeypatch.setattr(mod.time, "time", fake_time)
    monkeypatch.setattr(mod.time, "sleep", fake_sleep)
    monkeypatch.setattr(mod.httpx, "get", fake_get)

    with pytest.raises(AssertionError, match=r"(?s)timed out.*RUNNING"):
        result = mod._wait_query_terminal(
            "http://presto.example", "q-stuck", deadline=10.5
        )
        pytest.fail(
            f"subsequent GET past the deadline returned {result!r}"
        )
    assert gets["n"] == 1, gets["n"]


_MEMORY_LIMIT_FAILED = {
    "queryId": "q-late",
    "state": "FAILED",
    "errorCode": {"name": "EXCEEDED_LOCAL_MEMORY_LIMIT"},
}


def test_wait_query_terminal_first_get_failed_after_deadline_is_timeout(
    monkeypatch,
):
    """C1: the mandatory first GET is not a license to accept a late terminal.

    A GET whose observation lands at or after the original deadline must
    raise the diagnostic timeout (carrying the observed FAILED state), even
    when that payload is the exact E1 memory-limit failure. Returning it as
    success lets ``state == "FAILED"`` pass after the wait has expired.
    """
    mod = _scenarios_module()
    clock = {"t": 1000.0}
    gets = {"n": 0}

    def fake_time() -> float:
        return clock["t"]

    def fake_get(_url, **_kwargs):
        gets["n"] += 1
        # The GET itself is what crosses the deadline — not a later poll.
        clock["t"] = 1010.0
        return _FakeResponse(dict(_MEMORY_LIMIT_FAILED))

    monkeypatch.setattr(mod.time, "time", fake_time)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(mod.httpx, "get", fake_get)

    with pytest.raises(AssertionError, match=r"(?s)timed out.*FAILED") as ei:
        result = mod._wait_query_terminal(
            "http://presto.example", "q-late", deadline=1001.0
        )
        pytest.fail(
            f"post-deadline FAILED from the mandatory first GET must not "
            f"succeed the wait: {result!r}"
        )
    assert gets["n"] == 1, (
        f"only the mandatory first GET is allowed, got {gets['n']}"
    )
    message = str(ei.value)
    assert "EXCEEDED_LOCAL_MEMORY_LIMIT" in message, message


def test_wait_query_terminal_on_time_memory_failed_is_success(monkeypatch):
    """C1 blast radius: an in-budget memory-limit FAILED is still a result."""
    mod = _scenarios_module()
    clock = {"t": 1000.0}

    def fake_time() -> float:
        return clock["t"]

    def fake_get(_url, **_kwargs):
        return _FakeResponse(dict(_MEMORY_LIMIT_FAILED))

    monkeypatch.setattr(mod.time, "time", fake_time)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(mod.httpx, "get", fake_get)

    got = mod._wait_query_terminal(
        "http://presto.example", "q-late", deadline=1001.0
    )
    assert got.get("state") == "FAILED", got
    assert got.get("errorCode", {}).get("name") == "EXCEEDED_LOCAL_MEMORY_LIMIT"


def test_presto_query_mandatory_get_failed_after_deadline_is_timeout(
    monkeypatch,
):
    """C1 through ``_presto_query``: nextUri expires, first query GET is FAILED.

    Reviewer trace: deadline 1001.0, nextUri finishes at 1002.0, the
    mandatory ``/v1/query`` GET returns the memory-limit FAILED payload at
    1010.0. That must time out (with the observed state), not make E1's
    ``state == "FAILED"`` assertion pass eight seconds late.
    """
    import inspect

    mod = _scenarios_module()
    assert inspect.signature(mod._presto_query).parameters["timeout"].default == 180.0

    clock = {"t": 1000.0}
    query_gets = {"n": 0}

    def fake_time() -> float:
        return clock["t"]

    def fake_post(_url, **_kwargs):
        return _FakeResponse(
            {
                "id": "q-late",
                "nextUri": "http://presto.example/v1/statement/q-late/1",
            }
        )

    def fake_get(url, **_kwargs):
        url = str(url)
        if "/v1/query/" in url:
            query_gets["n"] += 1
            clock["t"] = 1010.0
            payload = dict(_MEMORY_LIMIT_FAILED)
            payload["queryId"] = "q-late"
            return _FakeResponse(payload)
        # nextUri consumes the 1s budget: 1000.0 → 1002.0, past deadline 1001.0.
        clock["t"] = 1002.0
        return _FakeResponse(
            {"id": "q-late", "nextUri": "http://presto.example/v1/statement/q-late/2"}
        )

    monkeypatch.setattr(mod.time, "time", fake_time)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(mod.httpx, "post", fake_post)
    monkeypatch.setattr(mod.httpx, "get", fake_get)

    with pytest.raises(AssertionError, match=r"(?s)timed out.*FAILED") as ei:
        result = mod._presto_query(
            "http://presto.example", "SELECT 1", timeout=1.0
        )
        pytest.fail(
            f"post-deadline FAILED from the mandatory first GET must not "
            f"succeed _presto_query: state="
            f"{str(result.get('state') or '')!r} result={result!r}"
        )
    assert query_gets["n"] == 1, query_gets["n"]
    message = str(ei.value)
    assert "EXCEEDED_LOCAL_MEMORY_LIMIT" in message, message
    lower = message.lower()
    assert "nexturi" in lower or "follow" in lower or "exhausted" in lower, message


def test_presto_query_records_follow_exit_when_wait_returns_finished(monkeypatch):
    """W3: a successful terminal wait must still carry the nextUri exit reason.

    If the wait returns FINISHED and E1 then rejects it, the follow-loop
    exit is the diagnostic that distinguishes 'query completed' from
    'client lost the stream'. Recording it only on the raise path hides
    that from the failure E1 actually emits.
    """
    mod = _scenarios_module()
    clock = {"t": 1000.0}

    def fake_time() -> float:
        return clock["t"]

    def fake_post(_url, **_kwargs):
        return _FakeResponse({"id": "q-done"})

    def fake_get(url, **_kwargs):
        assert "/v1/query/" in str(url)
        return _FakeResponse({"queryId": "q-done", "state": "FINISHED"})

    monkeypatch.setattr(mod.time, "time", fake_time)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(mod.httpx, "post", fake_post)
    monkeypatch.setattr(mod.httpx, "get", fake_get)

    result = mod._presto_query("http://presto.example", "SELECT 1", timeout=1.0)
    assert result.get("state") == "FINISHED", result
    reason = result.get("_e2e_nexturi_follow_exit")
    assert reason, (
        f"follow_exit must be attached on a successful wait, got {result!r}"
    )
    assert "nexturi" in str(reason).lower() or reason == "no-nextUri", reason


def test_e2_never_skips_its_sentinel_assertions():
    """C3: a non-200 iterations response used to skip the whole check."""
    body = _scenario_source("test_e2_broken_catalog_redacted")
    assert "if er.status_code == 200" not in body
    for surface in (
        "_evidence_payload(",
        "_llm_calls(",
        "_audit_entries(",
        "_wait_notification_for(",
    ):
        assert surface in body, f"E2 must inspect {surface}"
    # Notification redaction is non-vacuous: both placeholder and raw marker.
    assert "***REDACTED***" in body
    assert "redacted_any" in body or "REDACTED" in body


def test_e2_values_configure_an_outbound_webhook():
    """C4: send_notifications must not run against an empty target list."""
    values = yaml.safe_load(E2E_VALUES.read_text(encoding="utf-8")) or {}
    hooks = (
        ((values.get("config") or {}).get("notifications") or {}).get(
            "outbound_webhooks"
        )
        or []
    )
    assert hooks, "tests/e2e/values-dbagent.yaml must configure outbound_webhooks"
    assert any("webhook-capture" in str(h.get("url") or "") for h in hooks), hooks


def test_e3_requires_the_exact_tool_name_and_its_payload():
    """C5: matching the word "queued" also matched canned RCA prose."""
    body = _scenario_source("_e3_assert_case")
    assert 'ref.get("tool_name") == "presto_list_queries"' in body
    assert "_evidence_payload(" in body
    assert '"queued" in evidence_blob' not in body


def test_e4_does_not_accept_a_naturally_finished_query_as_a_kill():
    """C6: a query that completed on its own is not a successful kill."""
    import ast

    body = _scenario_source("test_e4_runaway_query_killed")
    # String *literals* only: an explanatory comment naming the state it
    # rejects is not an accepted state.
    literals = {
        node.value
        for node in ast.walk(ast.parse(body))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    }
    assert "FINISHED" not in literals, (
        "E4 must not accept FINISHED as a kill outcome; the design requires the "
        "query gone or cancelled/failed"
    )
    assert 'ex.get("playbook_id") == "presto.kill_query"' in body
    assert "_audit_entries(" in body


def test_e2e_admin_password_satisfies_the_apis_own_minimum_length():
    """C2: `run.sh` phase 4 posts this value to /auth/change-password, which
    rejects anything shorter than the API's `password_min_length`."""
    minimum = _effective_password_min_length()
    for where, password in _e2e_passwords().items():
        assert len(password) >= minimum, (
            f"{where} seeds a {len(password)}-character admin password; "
            f"dashboard-api requires at least {minimum} "
            "(POST /api/v1/auth/change-password would 400)"
        )


def test_e2e_admin_password_is_one_value_everywhere():
    """A password that differs between the chart values and the clients logs in
    nowhere; every subsequent authenticated call inherits the same value."""
    passwords = _e2e_passwords()
    distinct = set(passwords.values())
    assert len(distinct) == 1, (
        f"the e2e admin password must be one value; found {sorted(distinct)} "
        f"across {sorted(passwords)}"
    )


def test_run_sh_phase_budgets_match_the_approved_phase_table():
    """W1: the phase table is normative (design.md §11.1.3); a phase budget is
    not an implementation choice."""
    assert _declared_phases() == APPROVED_PHASE_BUDGETS


def test_run_sh_phase_budgets_leave_the_approved_reserve():
    declared = _declared_phases()
    total = sum(budget for _name, budget in declared)
    assert total == APPROVED_PHASE_TOTAL, (
        f"declared phase budgets total {total}s; the approved allocation is "
        f"{APPROVED_PHASE_TOTAL}s"
    )
    assert total < RUN_SH_GATE
    run_sh = RUN_SH.read_text(encoding="utf-8")
    assert f"BUDGET={RUN_SH_GATE}" in run_sh, (
        f"run.sh must fail above the approved {RUN_SH_GATE}s gate"
    )


# --- C3: inline smoke snippets must read env vars the dashboard pod actually has. ---


def test_e2e_smoke_inline_env_lookups_exist_in_rendered_dashboard_pod():
    """Review C3: catch DBAGENT_PG_DSN vs PG_DSN drift without a cluster run.

    Parses os.environ['...'] lookups in the helm-upgrade smoke commands of
    test_e2e_smoke.py and asserts each name is present in the rendered
    dashboard-api pod (explicit env or envFrom Secret keys).
    """
    from delivery_helpers import CHARTS, helm_template, parse_manifests

    smoke = (E2E / "test_e2e_smoke.py").read_text(encoding="utf-8")
    # Inline kubectl exec python snippets use os.environ['KEY'].
    looked_up = sorted(set(re.findall(r"os\.environ\[['\"]([A-Z0-9_]+)['\"]\]", smoke)))
    assert looked_up, "test_e2e_smoke.py has no os.environ['...'] lookups to validate"
    # The defect: smoke used DBAGENT_PG_DSN while the pod only has PG_DSN.
    assert "DBAGENT_PG_DSN" not in looked_up, (
        "smoke must not read DBAGENT_PG_DSN; dashboard-api Secret key is PG_DSN"
    )
    assert "PG_DSN" in looked_up, "expected at least one PG_DSN lookup in smoke"

    rendered = helm_template(
        CHARTS / "dbagent",
        values=[str(E2E_VALUES)],
    )
    docs = parse_manifests(rendered)

    dash = next(
        d
        for d in docs
        if d.get("kind") == "Deployment"
        and "dashboard-api" in (d.get("metadata") or {}).get("name", "")
    )
    container = dash["spec"]["template"]["spec"]["containers"][0]
    explicit_env = {
        e["name"] for e in (container.get("env") or []) if e.get("name")
    }
    # envFrom secretRef: keys come from the app Secret stringData.
    secret_names = {
        ref["secretRef"]["name"]
        for ref in (container.get("envFrom") or [])
        if (ref.get("secretRef") or {}).get("name")
    }
    secret_keys: set[str] = set()
    for d in docs:
        if d.get("kind") != "Secret":
            continue
        name = (d.get("metadata") or {}).get("name") or ""
        if name not in secret_names:
            continue
        secret_keys.update((d.get("stringData") or {}).keys())
        secret_keys.update((d.get("data") or {}).keys())

    available = explicit_env | secret_keys
    missing = [k for k in looked_up if k not in available]
    assert not missing, (
        f"smoke looks up {looked_up} but dashboard-api pod only provides "
        f"explicit={sorted(explicit_env)} secret_keys={sorted(secret_keys)}; "
        f"missing={missing}"
    )


# --- e2e fixture QoS + failure diagnostics (first real-CI e2e run). ---
#
# Presto e2e manifests had no resources: block, so those pods were BestEffort
# QoS and were first starved under node pressure on a 4-vCPU ubuntu-latest
# runner — cascading into E1–E4 failures. Product pods already declare
# resources; Presto and the other non-chart fixtures (mock-llm,
# webhook-capture) must match that pattern. B1 ingest errors are a separate
# defect and are out of scope for this guard.


_K8S_CPU_RE = re.compile(
    r"^(?P<num>\d+(?:\.\d+)?)(?P<unit>m)?$"
)
_K8S_MEM_RE = re.compile(
    r"^(?P<num>\d+(?:\.\d+)?)(?P<unit>Ei|Pi|Ti|Gi|Mi|Ki|E|P|T|G|M|K|)$"
)
_JVM_XMX_RE = re.compile(r"-Xmx(?P<num>\d+(?:\.\d+)?)(?P<unit>[kKmMgG])\b")

# Binary (1024) for Ki/Mi/Gi…; decimal (1000) for K/M/G… — Kubernetes rules.
_MEM_UNIT_BYTES = {
    "Ki": 1024,
    "Mi": 1024**2,
    "Gi": 1024**3,
    "Ti": 1024**4,
    "Pi": 1024**5,
    "Ei": 1024**6,
    "K": 1000,
    "M": 1000**2,
    "G": 1000**3,
    "T": 1000**4,
    "P": 1000**5,
    "E": 1000**6,
    "": 1,
}
# HotSpot -Xmx units are binary powers of 1024.
_JVM_UNIT_BYTES = {
    "k": 1024,
    "K": 1024,
    "m": 1024**2,
    "M": 1024**2,
    "g": 1024**3,
    "G": 1024**3,
}

EXPECTED_PRESTO_DEPLOYMENTS = frozenset({"presto-coordinator", "presto-worker"})
# Fixtures applied by run.sh that are not chart-managed; same BestEffort risk.
EXPECTED_E2E_AUX_DEPLOYMENTS = frozenset({"mock-llm", "webhook-capture"})
MIN_CPU_MILLICORES = 100  # modest floor so the pod is Burstable, not BestEffort
MEM_HEADROOM_OVER_XMX = 1.5


def _parse_cpu_millicores(raw: str) -> int:
    text = str(raw).strip()
    m = _K8S_CPU_RE.fullmatch(text)
    assert m, f"unparseable CPU quantity: {raw!r}"
    num = float(m.group("num"))
    if m.group("unit") == "m":
        return int(num)
    return int(num * 1000)


def _parse_memory_bytes(raw: str) -> int:
    text = str(raw).strip()
    m = _K8S_MEM_RE.fullmatch(text)
    assert m, f"unparseable memory quantity: {raw!r}"
    num = float(m.group("num"))
    unit = m.group("unit") or ""
    return int(num * _MEM_UNIT_BYTES[unit])


def _parse_jvm_xmx_bytes(jvm_config: str) -> int:
    m = _JVM_XMX_RE.search(jvm_config)
    assert m, f"jvm.config missing -Xmx: {jvm_config!r}"
    num = float(m.group("num"))
    return int(num * _JVM_UNIT_BYTES[m.group("unit")])


def _presto_xmx_bytes() -> int:
    """Derive the memory floor from the real jvm.config, not a hardcoded size."""
    sizes: set[int] = set()
    for path in sorted((E2E / "presto").glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if not doc or doc.get("kind") != "ConfigMap":
                continue
            data = doc.get("data") or {}
            jvm = data.get("jvm.config")
            if jvm:
                sizes.add(_parse_jvm_xmx_bytes(jvm))
    assert sizes, "expected jvm.config with -Xmx under tests/e2e/presto/"
    assert len(sizes) == 1, f"inconsistent -Xmx across Presto configmaps: {sizes}"
    return next(iter(sizes))


def _deployments_in(*relative_dirs: str) -> list[tuple[Path, dict]]:
    out: list[tuple[Path, dict]] = []
    for rel in relative_dirs:
        root = E2E / rel
        paths = sorted(root.glob("*.yaml")) if root.is_dir() else [root]
        for path in paths:
            if not path.is_file():
                continue
            for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                if not doc or doc.get("kind") != "Deployment":
                    continue
                out.append((path, doc))
    return out


def _presto_deployments() -> list[tuple[Path, dict]]:
    """Load Deployment docs from the e2e Presto manifests."""
    return _deployments_in("presto")


def test_presto_e2e_deployments_declare_cpu_and_memory_resources():
    """Regression: Presto e2e pods must not be BestEffort QoS.

    A container with no resource requests is BestEffort — first starved or
    evicted under node pressure on a 4-vCPU kind node. Coordinator/worker must
    declare a real CPU request floor and a memory request/limit sized from the
    configured -Xmx (not merely a unit-suffixed string). limits.cpu is optional
    so the JVM can burst free cores during startup/rollout.
    """
    deployments = _presto_deployments()
    names = {
        (doc.get("metadata") or {}).get("name")
        for _, doc in deployments
        if (doc.get("metadata") or {}).get("name")
    }
    assert EXPECTED_PRESTO_DEPLOYMENTS <= names, (
        f"expected Presto Deployments {sorted(EXPECTED_PRESTO_DEPLOYMENTS)}, "
        f"found {sorted(names)}"
    )

    xmx = _presto_xmx_bytes()
    mem_floor = int(xmx * MEM_HEADROOM_OVER_XMX)

    for path, doc in deployments:
        name = (doc.get("metadata") or {}).get("name") or path.name
        if name not in EXPECTED_PRESTO_DEPLOYMENTS:
            continue
        containers = (
            ((doc.get("spec") or {}).get("template") or {})
            .get("spec") or {}
        ).get("containers") or []
        assert containers, f"{path.name}: Deployment {name!r} has no containers"
        for container in containers:
            cname = container.get("name") or "<unnamed>"
            resources = container.get("resources") or {}
            requests = resources.get("requests") or {}
            limits = resources.get("limits") or {}

            assert "cpu" in requests, (
                f"{path.name} container {cname!r} missing resources.requests.cpu "
                f"(BestEffort QoS under CI node pressure)"
            )
            assert "memory" in requests, (
                f"{path.name} container {cname!r} missing resources.requests.memory "
                f"(BestEffort QoS under CI node pressure)"
            )
            assert "memory" in limits, (
                f"{path.name} container {cname!r} missing resources.limits.memory"
            )

            cpu_m = _parse_cpu_millicores(requests["cpu"])
            assert cpu_m >= MIN_CPU_MILLICORES, (
                f"{path.name} container {cname!r}: requests.cpu={requests['cpu']!r} "
                f"({cpu_m}m) below floor {MIN_CPU_MILLICORES}m"
            )

            mem_req = _parse_memory_bytes(requests["memory"])
            mem_lim = _parse_memory_bytes(limits["memory"])
            assert mem_req >= mem_floor, (
                f"{path.name} container {cname!r}: requests.memory={requests['memory']!r} "
                f"({mem_req} B) below -Xmx*{MEM_HEADROOM_OVER_XMX} floor "
                f"({mem_floor} B from -Xmx={xmx} B)"
            )
            assert mem_lim >= mem_req, (
                f"{path.name} container {cname!r}: limits.memory={limits['memory']!r} "
                f"({mem_lim} B) < requests.memory={requests['memory']!r} ({mem_req} B)"
            )


def test_presto_worker_deployment_has_http_readiness_probe():
    """E1 regression: worker rollout must not pass before Presto listens.

    Without an HTTP readiness probe mirroring the coordinator, kubectl rollout
    status returns while workers are merely Running and the coordinator may
    schedule onto stale discovery IPs from the previous generation.
    """
    deployments = _presto_deployments()
    worker_docs = [
        (path, doc)
        for path, doc in deployments
        if (doc.get("metadata") or {}).get("name") == "presto-worker"
    ]
    assert worker_docs, "presto-worker Deployment not found in e2e manifests"
    for path, doc in worker_docs:
        containers = (
            ((doc.get("spec") or {}).get("template") or {})
            .get("spec") or {}
        ).get("containers") or []
        assert containers, f"{path.name}: presto-worker has no containers"
        presto = next((c for c in containers if c.get("name") == "presto"), containers[0])
        readiness = presto.get("readinessProbe") or {}
        http_get = readiness.get("httpGet") or {}
        assert http_get.get("path") == "/v1/info", (
            f"{path.name}: presto-worker readinessProbe.httpGet.path must be "
            f"/v1/info (mirror coordinator); got {http_get!r}"
        )
        assert http_get.get("port") == 8080, (
            f"{path.name}: presto-worker readinessProbe.httpGet.port must be "
            f"8080; got {http_get!r}"
        )
        liveness = presto.get("livenessProbe") or {}
        live_http = liveness.get("httpGet") or {}
        assert live_http.get("path") == "/v1/info", (
            f"{path.name}: presto-worker livenessProbe.httpGet.path must be "
            f"/v1/info (mirror coordinator); got {live_http!r}"
        )
        assert live_http.get("port") == 8080, (
            f"{path.name}: presto-worker livenessProbe.httpGet.port must be "
            f"8080; got {live_http!r}"
        )


def test_e2e_aux_deployments_declare_resource_requests():
    """Regression: mock-llm and webhook-capture must not be BestEffort either.

    Both are applied by run.sh into the same namespace; mock-llm backs every
    investigation LLM call (E4's path). Same QoS rule as Presto: requests
    required so the kubelet does not rank them first for starvation.
    """
    deployments = _deployments_in("mockllm", "webhook-capture")
    names = {
        (doc.get("metadata") or {}).get("name")
        for _, doc in deployments
        if (doc.get("metadata") or {}).get("name")
    }
    assert EXPECTED_E2E_AUX_DEPLOYMENTS <= names, (
        f"expected aux Deployments {sorted(EXPECTED_E2E_AUX_DEPLOYMENTS)}, "
        f"found {sorted(names)}"
    )
    for path, doc in deployments:
        name = (doc.get("metadata") or {}).get("name") or path.name
        if name not in EXPECTED_E2E_AUX_DEPLOYMENTS:
            continue
        containers = (
            ((doc.get("spec") or {}).get("template") or {})
            .get("spec") or {}
        ).get("containers") or []
        assert containers, f"{path.name}: Deployment {name!r} has no containers"
        for container in containers:
            cname = container.get("name") or "<unnamed>"
            requests = (container.get("resources") or {}).get("requests") or {}
            assert "cpu" in requests, (
                f"{path.name} container {cname!r} missing resources.requests.cpu"
            )
            assert "memory" in requests, (
                f"{path.name} container {cname!r} missing resources.requests.memory"
            )
            assert _parse_cpu_millicores(requests["cpu"]) >= 1
            assert _parse_memory_bytes(requests["memory"]) >= 1


def test_run_sh_failure_path_collects_pod_logs_and_events(tmp_path: Path):
    """Regression: phase failure must actually collect cluster diagnostics.

    The CI upload packs /tmp/rca-e2e/**, but run.sh historically only wrote
    phases.txt — the first real-CI e2e failure had no kubectl describe/logs/
    events. Static text matching of run.sh is forgeable (echo hints, dead
    branches, later redefinitions); this test instead runs bash on the real
    functions with a stub kubectl on PATH and asserts observed behaviour.
    """
    # W3: dynamic execution cannot see past the sourcing guard (~line 75-77).
    # A redefinition of collect_failure_diagnostics / phase / check_budget after
    # the guard would be invisible to the runtime check; count definitions in
    # the file so each name exists exactly once (bash uses the last definition).
    # Checked first so a duplicate definition fails with a clear uniqueness
    # message rather than an opaque runtime symptom.
    run_sh_text = RUN_SH.read_text(encoding="utf-8")
    for fn in (
        "collect_failure_diagnostics",
        "phase",
        "check_budget",
        "start_live_log_sidecar",
        "stop_live_log_sidecar",
        "_stop_pid_until_gone",
    ):
        count = _bash_function_definition_count(run_sh_text, fn)
        assert count == 1, (
            f"run.sh must define {fn} exactly once, found {count}"
        )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kubectl_log = tmp_path / "kubectl-argv.log"
    # Marker files prove the shim ran (immune to string-only forgeries).
    marker_dir = tmp_path / "kubectl-markers"
    marker_dir.mkdir()

    # Single synthetic pod name shared by the kubectl shim and expected_artifacts
    # so renaming stays consistent (and the tr name-mangling stays intentional).
    FAKE_POD = "fake-pod-0"

    # Stub kubectl: log argv, emit a fake pod name for the logs loop, exit 0.
    # PATH is overridden only in the subprocess env — never the real process.
    kubectl_shim = bin_dir / "kubectl"
    kubectl_shim.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            # Log argv (one invocation per line) for assertion.
            printf '%s\\n' "$*" >>"{kubectl_log}"
            # Touch a marker so presence of a real call is filesystem-observable.
            : >"{marker_dir}/called"
            # The collector iterates `kubectl get pods -n dbagent -o name`.
            # Return one synthetic pod so the per-pod logs branch is exercised.
            if [[ " $* " == *" get pods "* && " $* " == *" -o name "* ]]; then
              echo "pod/{FAKE_POD}"
            fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    kubectl_shim.chmod(0o755)

    diag_dir = Path("/tmp/rca-e2e/diagnostics")
    # Isolate from any prior e2e debris so emptiness is meaningful.
    if diag_dir.exists():
        shutil.rmtree(diag_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    # Source run.sh (top-level guard returns after function defs), then force
    # phase() down its failure branch with a command that exits non-zero.
    script = textwrap.dedent(
        f"""\
        set -euo pipefail
        # shellcheck disable=SC1091
        source "{RUN_SH}"
        phase "forced_failure" 5 false
        """
    )
    # start_new_session=True puts bash in its own process group so a timeout can
    # kill the whole tree.  Without it, subprocess's timeout SIGKILLs only bash
    # and orphans its grandchildren -- and if the sourcing guard ever regresses,
    # those grandchildren are a real `docker build` and `kind create cluster`.
    proc = subprocess.Popen(
        ["bash", "-c", script],
        env=env,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        stdout, stderr = proc.communicate()
        raise AssertionError(
            "sourcing run.sh must return at its sourcing guard within seconds; "
            "it did not, so the guard is gone and the real e2e pipeline started "
            f"(process group killed). stdout so far:\n{stdout}"
        ) from None
    result = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)

    assert result.returncode == 1, (
        "phase() must exit 1 on a failing command; "
        f"got rc={result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    # W2: sourcing must stop at the guard and run only the forced phase.
    # Without this, a deleted guard can pass in CI (kind missing → preflight
    # fails → collector fires from the wrong phase) or hang on a dev box.
    phases_seen = re.findall(r"^==> phase: (\S+)", result.stdout, re.M)
    assert phases_seen == ["forced_failure"], (
        "sourcing run.sh must stop at the sourcing guard and run only the "
        f"forced failure; phases observed: {phases_seen}"
    )
    assert (marker_dir / "called").is_file(), (
        "collect_failure_diagnostics must invoke kubectl on phase failure "
        f"(no marker written under {marker_dir})"
    )
    assert diag_dir.is_dir() and any(diag_dir.iterdir()), (
        "diagnostics directory must be non-empty after phase failure "
        f"({diag_dir})"
    )
    # W1: assert named artifact files were written, not merely that the dir is
    # non-empty / that argv text contains keywords (redirect drops pass those).
    produced = {q.name for q in diag_dir.iterdir()}
    # tr '/:' '--' mangling of "pod/<FAKE_POD>" → logs-pod-<FAKE_POD>*.txt
    expected_artifacts = {
        "nodes-wide.txt", "describe-nodes.txt", "pods-wide.txt", "events.txt",
        "describe-dbagent-pods.txt",
        f"logs-pod-{FAKE_POD}.txt", f"logs-pod-{FAKE_POD}-previous.txt",
    }
    assert expected_artifacts <= produced, (
        f"missing diagnostics artifacts: {sorted(expected_artifacts - produced)}; "
        f"produced={sorted(produced)}"
    )

    assert kubectl_log.is_file() and kubectl_log.stat().st_size > 0, (
        "kubectl shim must have recorded at least one invocation"
    )
    lines = [
        line for line in kubectl_log.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    joined = "\n".join(lines)
    assert re.search(r"\bget events\b", joined), (
        f"expected kubectl get events; recorded invocations:\n{joined}"
    )
    assert re.search(r"\bdescribe\b", joined), (
        f"expected kubectl describe; recorded invocations:\n{joined}"
    )
    assert re.search(r"\blogs\b", joined), (
        f"expected kubectl logs; recorded invocations:\n{joined}"
    )
    for line in lines:
        assert "--request-timeout" in line, (
            "every kubectl invocation must carry --request-timeout; "
            f"got: {line!r}"
        )


def test_run_sh_captures_pod_logs_before_scenario_teardown(tmp_path: Path):
    """G-2 / W1: failure-window logs must be captured while the failing pods still exist.

    ``collect_failure_diagnostics`` runs once after the whole pytest session.
    Each scenario's ``finally`` restarts Presto, so a post-session sweep
    cannot see the coordinator that served the failure. A live sidecar
    (started before ``pytest_e2e``, stopped on EXIT) follows each pod UID
    with ``kubectl logs -f`` so a line emitted immediately before removal
    is still captured; the end-of-run sweep stays as a complement.
    """
    run_sh_text = RUN_SH.read_text(encoding="utf-8")
    for fn in (
        "start_live_log_sidecar",
        "stop_live_log_sidecar",
        "_stop_pid_until_gone",
        "collect_failure_diagnostics",
        "phase",
        "check_budget",
    ):
        count = _bash_function_definition_count(run_sh_text, fn)
        assert count == 1, (
            f"run.sh must define {fn} exactly once, found {count}"
        )

    # Executable path: after the sourcing guard, the sidecar must start
    # before pytest_e2e. Must not sit *between* the hygiene gate and the
    # phase line — that span is pinned empty of kubectl by A10(v).
    guard = "if [[ \"${BASH_SOURCE[0]}\" != \"${0}\" ]]; then"
    assert guard in run_sh_text
    after_guard = run_sh_text.split(guard, 1)[1]
    pytest_idx = after_guard.find('phase "pytest_e2e"')
    assert pytest_idx != -1, "missing phase pytest_e2e after the sourcing guard"
    before_pytest = after_guard[:pytest_idx]
    assert re.search(r"^start_live_log_sidecar\b", before_pytest, re.M), (
        "start_live_log_sidecar must be invoked after the sourcing guard and "
        "before phase pytest_e2e so snapshots cover the session, not only "
        "the post-session sweep"
    )
    between = _hygiene_gate_to_pytest_e2e_span(run_sh_text)
    assert "start_live_log_sidecar" not in between, (
        "sidecar start must not sit between the A10(v) hygiene gate and "
        'phase "pytest_e2e"'
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kubectl_log = tmp_path / "kubectl-argv.log"
    state_file = tmp_path / "pod-generation"
    state_file.write_text("old", encoding="utf-8")
    OLD_POD = "presto-coordinator-old"
    NEW_POD = "presto-coordinator-new"
    OLD_UID = "uid-old-1"
    NEW_UID = "uid-new-2"
    DECISIVE = "DECISIVE-FAILURE-LINE-BEFORE-REMOVAL"

    kubectl_shim = bin_dir / "kubectl"
    kubectl_shim.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env bash
            printf '%s\\n' "$*" >>"{kubectl_log}"
            gen=$(cat "{state_file}" 2>/dev/null || echo old)
            if [[ " $* " == *" get pods "* && " $* " == *" -o name "* ]]; then
              if [[ "$gen" == "new" ]]; then
                echo "pod/{NEW_POD}"
              else
                echo "pod/{OLD_POD}"
              fi
              exit 0
            fi
            if [[ " $* " == *" get pods "* ]]; then
              if [[ "$gen" == "new" ]]; then
                printf '%s\\t%s\\n' "{NEW_POD}" "{NEW_UID}"
              else
                printf '%s\\t%s\\n' "{OLD_POD}" "{OLD_UID}"
              fi
              exit 0
            fi
            if [[ " $* " == *" logs "* ]]; then
              following=0
              [[ " $* " == *" -f "* ]] && following=1
              old_pod=0
              if [[ " $* " == *" {OLD_POD} "* || " $* " == *" pod/{OLD_POD} "* ]]; then
                old_pod=1
              fi
              if (( following && old_pod )); then
                # Stream current logs, then on pod death emit the line that
                # only exists immediately before removal (W1).
                echo "old-coordinator log line"
                while true; do
                  gen=$(cat "{state_file}" 2>/dev/null || echo old)
                  if [[ "$gen" != "old" ]]; then
                    echo "{DECISIVE}"
                    exit 0
                  fi
                  sleep 0.05
                done
              fi
              if (( old_pod )); then
                echo "old-coordinator log line"
              else
                echo "new-coordinator log line"
              fi
            fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    kubectl_shim.chmod(0o755)

    diag_dir = Path("/tmp/rca-e2e/diagnostics")
    live_dir = diag_dir / "live"
    if diag_dir.exists():
        shutil.rmtree(diag_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["LIVE_LOG_POLL_S"] = "0.05"

    script = textwrap.dedent(
        f"""\
        set -euo pipefail
        source "{RUN_SH}"
        start_live_log_sidecar
        # Wait until the OLD pod is being followed, then replace it
        # immediately — the decisive failure line is emitted by the
        # follower only as the pod disappears, not before.
        deadline=$(( SECONDS + 10 ))
        while (( SECONDS < deadline )); do
          if grep -rqs "old-coordinator log line" "{live_dir}" 2>/dev/null; then
            break
          fi
          sleep 0.05
        done
        echo new >"{state_file}"
        deadline=$(( SECONDS + 10 ))
        while (( SECONDS < deadline )); do
          if grep -rqs "{DECISIVE}" "{live_dir}" 2>/dev/null; then
            break
          fi
          sleep 0.05
        done
        stop_live_log_sidecar
        collect_failure_diagnostics
        """
    )
    proc = subprocess.Popen(
        ["bash", "-c", script],
        env=env,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        stdout, stderr = proc.communicate()
        raise AssertionError(
            "live-log sidecar test hung; process group killed. "
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from None
    assert proc.returncode == 0, (
        f"sidecar + collect must succeed; rc={proc.returncode}\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}"
    )

    live_files = list(live_dir.rglob("*.txt")) if live_dir.is_dir() else []
    live_blob = "\n".join(
        p.read_text(encoding="utf-8", errors="replace") for p in live_files
    )
    assert "old-coordinator log line" in live_blob, (
        "live sidecar must capture the pre-teardown coordinator; "
        f"live files={sorted(str(p) for p in live_files)} stdout:\n{stdout}"
    )
    assert DECISIVE in live_blob, (
        "live sidecar must capture a line emitted immediately before pod "
        "removal, not only a snapshot taken while waiting for the old pod; "
        f"live files={sorted(str(p) for p in live_files)} stdout:\n{stdout}"
    )

    run_sh_text = RUN_SH.read_text(encoding="utf-8")
    assert "sidecar.pid" not in run_sh_text, (
        "stop_live_log_sidecar must not trust a PID file (W2)"
    )
    assert re.search(r"logs\s+-f\b", run_sh_text) or "logs -f" in run_sh_text, (
        "sidecar must follow per-pod with kubectl logs -f (W1)"
    )

    # End-of-run sweep sees only the replacement pod — proving the two
    # capture points are distinct, and that relying on the sweep alone
    # would have lost the failure window.
    sweep_old = diag_dir / f"logs-pod-{OLD_POD}.txt"
    sweep_new = diag_dir / f"logs-pod-{NEW_POD}.txt"
    assert sweep_new.is_file(), (
        f"end-of-run sweep must still collect the live pods; "
        f"produced={sorted(p.name for p in diag_dir.iterdir())}"
    )
    assert "new-coordinator log line" in sweep_new.read_text(encoding="utf-8")
    assert not sweep_old.is_file() or "old-coordinator log line" not in (
        sweep_old.read_text(encoding="utf-8")
    )


def test_stop_live_log_sidecar_ignores_stale_pid_file_and_reaps_until_gone(
    tmp_path: Path,
):
    """W2: a planted sidecar.pid must not be signalled; stop must wait until gone.

    The current shell already holds LIVE_LOG_SIDECAR_PID. Trusting a pid
    file lets stop_live_log_sidecar kill an unrelated process. kill(1)
    succeeding is also not the same as the process having exited — a
    SIGTERM-ignoring child must be SIGKILL'd and polled until absent.

    The stubborn child signals readiness (a file) only after installing
    SIG_IGN, and this test waits for that file before calling stop. Without
    that handshake the SIGTERM can land before SIG_IGN and the test would
    exercise ordinary termination instead of SIGKILL escalation (W1).
    """
    run_sh_text = RUN_SH.read_text(encoding="utf-8")
    assert "sidecar.pid" not in run_sh_text
    assert "_stop_pid_until_gone" in run_sh_text
    assert run_sh_text.count("LIVE_LOG_SIDECAR_PID") >= 2

    diag_dir = Path("/tmp/rca-e2e/diagnostics")
    live_dir = diag_dir / "live"
    if diag_dir.exists():
        shutil.rmtree(diag_dir)
    live_dir.mkdir(parents=True)

    marker = tmp_path / "w2-out.txt"
    ready = tmp_path / "stubborn-ready"
    script = textwrap.dedent(
        f"""\
        set -euo pipefail
        source "{RUN_SH}"

        sleep 60 &
        victim=$!
        echo "$victim" >"{live_dir}/sidecar.pid"
        LIVE_LOG_SIDECAR_PID=""
        stop_live_log_sidecar
        if ! kill -0 "$victim" 2>/dev/null; then
          echo PLANTED_PID_KILLED >"{marker}"
          exit 1
        fi
        kill -KILL "$victim" 2>/dev/null || true
        wait "$victim" 2>/dev/null || true
        echo PLANTED_PID_SURVIVED >>"{marker}"

        python3 -c 'import signal, time, pathlib; signal.signal(signal.SIGTERM, signal.SIG_IGN); pathlib.Path(r"{ready}").write_text("ready"); time.sleep(60)' &
        stubborn=$!
        for _ in $(seq 1 100); do
          if [[ -f "{ready}" ]]; then
            break
          fi
          sleep 0.05
        done
        if [[ ! -f "{ready}" ]]; then
          echo STUBBORN_NEVER_READY >>"{marker}"
          kill -KILL "$stubborn" 2>/dev/null || true
          wait "$stubborn" 2>/dev/null || true
          exit 1
        fi
        LIVE_LOG_SIDECAR_PID=$stubborn
        stop_live_log_sidecar
        if kill -0 "$stubborn" 2>/dev/null; then
          echo STUBBORN_STILL_ALIVE >>"{marker}"
          kill -KILL "$stubborn" 2>/dev/null || true
          wait "$stubborn" 2>/dev/null || true
          exit 1
        fi
        echo STUBBORN_GONE >>"{marker}"
        """
    )
    proc = subprocess.Popen(
        ["bash", "-c", script],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        stdout, stderr = proc.communicate()
        raise AssertionError(
            "W2 sidecar stop test hung; process group killed. "
            f"stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from None
    assert proc.returncode == 0, (
        f"W2 stop path must succeed; rc={proc.returncode}\n"
        f"stdout:\n{stdout}\nstderr:\n{stderr}\n"
        f"marker={marker.read_text() if marker.is_file() else '<missing>'}"
    )
    text = marker.read_text(encoding="utf-8") if marker.is_file() else ""
    assert "PLANTED_PID_SURVIVED" in text, text
    assert "PLANTED_PID_KILLED" not in text, text
    assert "STUBBORN_NEVER_READY" not in text, text
    assert "STUBBORN_GONE" in text, text
    assert "STUBBORN_STILL_ALIVE" not in text, text
    assert ready.is_file(), "stubborn child must have installed SIG_IGN before stop"



# Product workloads that must satisfy FP-IG-1/2 under every shipped overlay
# (design.md FP-IG-3; review C8). Sizing (FP-IG-4) stays ingest-gateway only.
_PRODUCT_WORKLOADS = (
    "ingest-gateway",
    "temporal-worker",
    "probe-gateway",
    "dashboard-api",
    "dashboard-web",
)
_PROBE_KEYS = ("timeoutSeconds", "periodSeconds", "failureThreshold", "successThreshold")


def _shed_before_kill(t_r, p_r, F_r, t_l, p_l, F_l) -> bool:
    """FP-IG-2 five conditions (same predicate as test_delivery_charts)."""
    if not (t_r < t_l):
        return False
    if not (p_r * F_r + t_r < (F_l - 1) * p_l):
        return False
    if not ((F_l - 1) * p_l >= 90):
        return False
    if not (t_l >= 5):
        return False
    if not (t_r <= p_r and t_l <= p_l):
        return False
    return True


def test_shipped_values_overlays_do_not_weaken_probe_or_sizing_defaults():
    """FP-IG-3: every product workload under both overlays satisfies FP-IG-1/2/4."""
    import math

    from delivery_helpers import CHARTS, helm_template, parse_manifests

    dbagent = CHARTS / "dbagent"
    overlays = [
        REPO_ROOT / "tests/e2e/values-dbagent.yaml",
        dbagent / "values-dev.yaml",
    ]
    values = yaml.safe_load((dbagent / "values.yaml").read_text(encoding="utf-8"))
    basis = float(values["ingestGateway"]["sizingBasis"]["cpuMsPerRequest"])

    def millicores(v):
        s = str(v)
        return int(s[:-1]) if s.endswith("m") else int(float(s) * 1000)

    for overlay in overlays:
        out = helm_template(dbagent, values=[str(overlay)])
        docs = parse_manifests(out)
        # Index every product Deployment by short workload name.
        by_workload: dict[str, dict] = {}
        for d in docs:
            if d.get("kind") != "Deployment":
                continue
            name = d["metadata"]["name"]
            short = next((w for w in _PRODUCT_WORKLOADS if w in name), None)
            if short is None:
                continue
            by_workload[short] = d

        # Every product workload must be present and checked (review C8).
        for w in _PRODUCT_WORKLOADS:
            assert w in by_workload, (
                f"{overlay}: missing Deployment for product workload {w}"
            )
            dep = by_workload[w]
            containers = dep["spec"]["template"]["spec"]["containers"]
            assert containers, f"{overlay} {w}: no containers"
            c = containers[0]
            for kind in ("livenessProbe", "readinessProbe"):
                assert kind in c, f"{overlay} {w}: missing {kind}"
                probe = c[kind]
                for k in _PROBE_KEYS:
                    assert k in probe, f"{overlay} {w} {kind} missing {k}"
                    assert probe[k] is not None
            r, l = c["readinessProbe"], c["livenessProbe"]
            ok = _shed_before_kill(
                r["timeoutSeconds"],
                r["periodSeconds"],
                r["failureThreshold"],
                l["timeoutSeconds"],
                l["periodSeconds"],
                l["failureThreshold"],
            )
            assert ok, (
                f"{overlay} {w} fails FP-IG-2 shed-before-kill: "
                f"readiness={r} liveness={l}"
            )

        # Sizing (FP-IG-4) is specific to ingest-gateway only.
        gw = by_workload["ingest-gateway"]["spec"]["template"]["spec"]["containers"][0]
        res = gw["resources"]
        assert millicores(res["requests"]["cpu"]) == math.ceil(basis * 200)
        assert millicores(res["limits"]["cpu"]) >= 5 * millicores(res["requests"]["cpu"])


# ---------------------------------------------------------------------------
# W1 — E3 cleanup observation failures must reach the aggregate
# ---------------------------------------------------------------------------


def _load_e2e_scenarios_module():
    """Load test_e2e_scenarios.py without collecting the e2e suite."""
    path = E2E / "test_e2e_scenarios.py"
    name = "e2e_scenarios_w1_cleanup"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    # Register before exec so dataclasses / relative patterns work if any.
    import sys

    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def test_e3_observation_helpers_propagate_errors(monkeypatch):
    """W1: observation failure is not treated as successful absence."""
    mod = _load_e2e_scenarios_module()

    def boom(*_a, **_k):
        raise RuntimeError("observation unavailable")

    monkeypatch.setattr(mod, "_kubectl_ok", boom)
    with pytest.raises(RuntimeError, match="observation unavailable"):
        mod._e3_cm_key_present()
    with pytest.raises(RuntimeError, match="observation unavailable"):
        mod._e3_mount_present()


def test_e3_cleanup_aggregates_every_step_failure(monkeypatch):
    """W1: every removal/restart/verification is attempted; all failures aggregate."""
    mod = _load_e2e_scenarios_module()
    attempts: list[str] = []

    def boom_mount(*, present):
        attempts.append(f"patch_mount:{present}")
        raise RuntimeError("mount patch failed")

    def boom_cm():
        attempts.append("remove_cm_key")
        raise RuntimeError("cm remove failed")

    def boom_restart(workload, timeout="180s"):
        attempts.append(f"restart:{workload}")
        raise RuntimeError("restart failed")

    def boom_cm_present():
        attempts.append("verify_cm")
        raise RuntimeError("observation unavailable")

    def boom_mount_present():
        attempts.append("verify_mount")
        raise RuntimeError("observation unavailable")

    monkeypatch.setattr(mod, "_patch_coordinator_rg_mount", boom_mount)
    monkeypatch.setattr(mod, "_e3_remove_cm_key", boom_cm)
    monkeypatch.setattr(mod, "_restart_and_wait", boom_restart)
    monkeypatch.setattr(mod, "_e3_cm_key_present", boom_cm_present)
    monkeypatch.setattr(mod, "_e3_mount_present", boom_mount_present)

    with pytest.raises(RuntimeError, match="E3 cleanup failed") as ei:
        mod._e3_cleanup_fault()
    msg = str(ei.value)
    # Every step attempted.
    assert attempts == [
        "patch_mount:False",
        "remove_cm_key",
        f"restart:{mod.COORDINATOR_WORKLOAD}",
        "verify_cm",
        "verify_mount",
    ], attempts
    # Every failure reaches the aggregate message.
    for fragment in (
        "remove mount",
        "remove cm key",
        "restart coordinator",
        "verify cm key absent",
        "verify mount absent",
        "mount patch failed",
        "cm remove failed",
        "restart failed",
        "observation unavailable",
    ):
        assert fragment in msg, f"missing {fragment!r} in {msg!r}"


def test_e3_cleanup_false_only_after_successful_absent_read(monkeypatch):
    """W1: successful observation of absence is quiet; residual state fails."""
    mod = _load_e2e_scenarios_module()

    monkeypatch.setattr(mod, "_patch_coordinator_rg_mount", lambda **_k: None)
    monkeypatch.setattr(mod, "_e3_remove_cm_key", lambda: None)
    monkeypatch.setattr(mod, "_restart_and_wait", lambda *_a, **_k: None)
    # Successful reads prove absence → cleanup succeeds.
    monkeypatch.setattr(mod, "_e3_cm_key_present", lambda: False)
    monkeypatch.setattr(mod, "_e3_mount_present", lambda: False)
    mod._e3_cleanup_fault()  # must not raise

    # Residual key after "cleanup" must surface.
    monkeypatch.setattr(mod, "_e3_cm_key_present", lambda: True)
    monkeypatch.setattr(mod, "_e3_mount_present", lambda: False)
    with pytest.raises(RuntimeError, match="still present"):
        mod._e3_cleanup_fault()


def test_e3_cleanup_removes_cm_key_that_was_added_by_merge_patch(monkeypatch):
    """H-A: apply cannot delete a field that patch never recorded.

    `_put_configmap_key` adds the key with merge-patch, which does not write
    ``kubectl.kubernetes.io/last-applied-configuration``. ``kubectl apply``
    therefore leaves the live field in place. Red before the fix: cleanup
    raises 'still present' — the production E3 failure.
    """
    from subprocess import CompletedProcess

    mod = _load_e2e_scenarios_module()
    key = mod.RESOURCE_GROUPS_PROPERTIES_KEY
    cm = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": mod.COORDINATOR_CONFIGMAP, "namespace": "dbagent"},
        "data": {"config.properties": "coordinator=true\n"},
    }

    def kubectl_ok(*args):
        if args[:3] == ("get", "configmap", mod.COORDINATOR_CONFIGMAP):
            return CompletedProcess(args, 0, json.dumps(cm), "")
        if args[:3] == ("patch", "configmap", mod.COORDINATOR_CONFIGMAP):
            payload = json.loads(args[args.index("-p") + 1])
            data = cm.setdefault("data", {})
            for field, value in (payload.get("data") or {}).items():
                if value is None:
                    data.pop(field, None)
                else:
                    data[field] = value
            return CompletedProcess(args, 0, "", "")
        raise AssertionError(f"unexpected kubectl: {args}")

    def apply_does_not_delete(cmd, **_kwargs):
        # Three-way merge with no last-applied-configuration annotation:
        # apply succeeds and does not remove a live data key.
        return CompletedProcess(cmd, 0, "configmap/configured\n", "")

    monkeypatch.setattr(mod, "_kubectl_ok", kubectl_ok)
    monkeypatch.setattr(mod.subprocess, "run", apply_does_not_delete)
    monkeypatch.setattr(mod, "_patch_coordinator_rg_mount", lambda **_k: None)
    monkeypatch.setattr(mod, "_restart_and_wait", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "_e3_mount_present", lambda: False)

    mod._put_configmap_key(
        mod.COORDINATOR_CONFIGMAP,
        key,
        "resource-groups.configuration-manager=file\n",
    )
    assert mod._e3_cm_key_present() is True, "precondition: patch must add the key"

    mod._e3_cleanup_fault()
    assert mod._e3_cm_key_present() is False


def test_e1_restores_starved_memory_in_finally():
    """H-B: E1 must restore query.max-memory-per-node on every exit path.

    Red before the fix: the starve has no try/finally, so a failure at the
    heavy-query assertion leaves the cluster at 1MB for E2/E3/E4.
    """
    body = _scenario_source("test_e1_worker_oom_to_resolved")
    tree = ast.parse(body)
    found = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or not node.finalbody:
            continue
        for stmt in ast.walk(ast.Module(body=node.finalbody, type_ignores=[])):
            if (
                isinstance(stmt, ast.Call)
                and isinstance(stmt.func, ast.Name)
                and stmt.func.id == "_e1_cleanup_fault"
            ):
                found = True
    assert found, (
        "test_e1_worker_oom_to_resolved must restore the starved memory "
        "config in a finally block via _e1_cleanup_fault"
    )
    assert "STARVED_MEMORY" in body
    assert "_e1_cleanup_fault" in body


def test_e1_captures_original_memory_before_mutating():
    """C1: `before` must be assigned before `_patch_configmap_property`
    mutates — not from that helper's return value.

    The helper applies the patch, then reads/asserts. If a post-patch
    observation fails, it raises without returning, leaving `before is
    None` and skipping finally's cleanup (starved=True, cleanup_calls=[]).
    """
    body = _scenario_source("test_e1_worker_oom_to_resolved")
    tree = ast.parse(body)
    captured_before_patch = False
    assigned_from_patch = False
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try) or not node.finalbody:
            continue
        finally_calls_cleanup = any(
            isinstance(stmt, ast.Call)
            and isinstance(stmt.func, ast.Name)
            and stmt.func.id == "_e1_cleanup_fault"
            for stmt in ast.walk(ast.Module(body=node.finalbody, type_ignores=[]))
        )
        if not finally_calls_cleanup:
            continue
        before_lineno = None
        patch_lineno = None
        for inner in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(inner, ast.Assign):
                targets = [
                    t.id for t in inner.targets if isinstance(t, ast.Name)
                ]
                if "before" not in targets:
                    continue
                if before_lineno is None:
                    before_lineno = inner.lineno
                if (
                    isinstance(inner.value, ast.Call)
                    and isinstance(inner.value.func, ast.Name)
                    and inner.value.func.id == "_patch_configmap_property"
                ):
                    assigned_from_patch = True
            if (
                isinstance(inner, ast.Call)
                and isinstance(inner.func, ast.Name)
                and inner.func.id == "_patch_configmap_property"
                and patch_lineno is None
            ):
                patch_lineno = inner.lineno
        if (
            before_lineno is not None
            and patch_lineno is not None
            and before_lineno < patch_lineno
        ):
            captured_before_patch = True
    assert not assigned_from_patch, (
        "test_e1_worker_oom_to_resolved assigns `before` from "
        "_patch_configmap_property(); a post-patch exception then skips "
        "finally cleanup because `before` is still None"
    )
    assert captured_before_patch, (
        "test_e1_worker_oom_to_resolved must capture the original memory "
        "config into `before` before calling _patch_configmap_property"
    )


def test_e1_cleanup_runs_when_patch_helper_raises_after_mutating(monkeypatch):
    """C1: patch is applied, then the helper raises; cleanup must still run.

    Red before the fix: `before = _patch_configmap_property(...)` never
    assigns when the helper raises, so finally sees `before is None`.
    """
    mod = _load_e2e_scenarios_module()
    starved = {"applied": False}
    cleanup_calls: list[str] = []

    monkeypatch.setattr(mod, "_login", lambda *_a, **_k: "tok")
    monkeypatch.setattr(
        mod,
        "_platform_config",
        lambda *_a, **_k: {
            "remediation": {"settle_seconds": 15},
            "remediation_targets": {
                "namespace": "dbagent",
                "worker_configmap": mod.WORKER_CONFIGMAP,
                "config_file_key": "config.properties",
            },
        },
    )
    monkeypatch.setattr(
        mod,
        "_configmap_data",
        lambda *_a, **_k: {
            "config.properties": f"{mod.MEMORY_PROP}=256MB\nother.prop=keep\n"
        },
    )

    def fake_patch(configmap, file_key, prop, value):
        starved["applied"] = True
        starved["value"] = value
        raise AssertionError(f"{prop}={value!r} after patch")

    def fake_cleanup(restore_to):
        cleanup_calls.append(restore_to)

    monkeypatch.setattr(mod, "_patch_configmap_property", fake_patch)
    monkeypatch.setattr(mod, "_e1_cleanup_fault", fake_cleanup)

    with pytest.raises(AssertionError, match="after patch"):
        mod.test_e1_worker_oom_to_resolved(
            "http://dash", "http://ingest", "http://presto"
        )

    assert starved["applied"] is True
    assert starved["value"] == mod.STARVED_MEMORY
    assert cleanup_calls == ["256MB"], (
        f"starved=True cleanup_calls={cleanup_calls!r} — a post-patch "
        "exception skipped finally's _e1_cleanup_fault"
    )


def test_e1_cleanup_fault_restores_captured_value_and_aggregates(monkeypatch):
    """H-B: cleanup matches _e3_cleanup_fault's state-observed shape."""
    mod = _load_e2e_scenarios_module()
    patched: list[tuple] = []
    restarts: list[str] = []
    mounted = {mod.MEMORY_PROP: mod.STARVED_MEMORY}

    def fake_patch(configmap, file_key, prop, value):
        patched.append((configmap, file_key, prop, value))
        mounted[prop] = value
        return {prop: "256MB"}

    def fake_mounted(_workload, _path, prop):
        return mounted.get(prop)

    monkeypatch.setattr(mod, "_patch_configmap_property", fake_patch)
    monkeypatch.setattr(
        mod,
        "_restart_and_wait",
        lambda workload, timeout="120s": restarts.append(workload),
    )
    monkeypatch.setattr(mod, "_mounted_property", fake_mounted)

    mod._e1_cleanup_fault("256MB")
    assert patched == [
        (mod.WORKER_CONFIGMAP, "config.properties", mod.MEMORY_PROP, "256MB")
    ]
    assert restarts == [mod.WORKER_WORKLOAD]
    assert mounted[mod.MEMORY_PROP] == "256MB"

    # Residual starve after a no-op restore must surface.
    monkeypatch.setattr(mod, "_patch_configmap_property", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "_restart_and_wait", lambda *_a, **_k: None)
    monkeypatch.setattr(mod, "_mounted_property", lambda *_a, **_k: mod.STARVED_MEMORY)
    with pytest.raises(RuntimeError, match="E1 cleanup failed"):
        mod._e1_cleanup_fault("256MB")

    # Every step is attempted; failures aggregate.
    attempts: list[str] = []

    def boom_patch(*_a, **_k):
        attempts.append("patch")
        raise RuntimeError("patch failed")

    def boom_restart(*_a, **_k):
        attempts.append("restart")
        raise RuntimeError("restart failed")

    def boom_mounted(*_a, **_k):
        attempts.append("verify")
        raise RuntimeError("observation unavailable")

    monkeypatch.setattr(mod, "_patch_configmap_property", boom_patch)
    monkeypatch.setattr(mod, "_restart_and_wait", boom_restart)
    monkeypatch.setattr(mod, "_mounted_property", boom_mounted)
    with pytest.raises(RuntimeError, match="E1 cleanup failed") as ei:
        mod._e1_cleanup_fault("256MB")
    msg = str(ei.value)
    assert attempts == ["patch", "restart", "verify"], attempts
    for fragment in ("restore", "restart", "verify", "patch failed", "restart failed"):
        assert fragment in msg, f"missing {fragment!r} in {msg!r}"


# ---------------------------------------------------------------------------
# D-A / D-B — e2e readiness barrier + failure diagnostics (fix.md)
# ---------------------------------------------------------------------------

CONFTEST = E2E / "conftest.py"
_FIRST_COLLECTED_E2E = (
    "tests/e2e/test_e2e_connection_budget.py::test_live_connection_supply_exceeds_configured_demand"
)


def _load_e2e_conftest():
    """Import tests/e2e/conftest.py without collecting the e2e suite."""
    spec = importlib.util.spec_from_file_location(
        "e2e_conftest_under_test", CONFTEST
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _load_e2e_load():
    """Import tests/e2e/test_e2e_load.py without collecting the e2e suite."""
    spec = importlib.util.spec_from_file_location(
        "e2e_load_under_test", E2E / "test_e2e_load.py"
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _session_autouse_fixture_nodes(
    source: str,
) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    tree = ast.parse(source)
    nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for dec in node.decorator_list:
            call = dec if isinstance(dec, ast.Call) else None
            func = call.func if call is not None else dec
            is_fixture = (
                (isinstance(func, ast.Attribute) and func.attr == "fixture")
                or (isinstance(func, ast.Name) and func.id == "fixture")
            )
            if not is_fixture:
                continue
            kwargs = {}
            if call is not None:
                for kw in call.keywords:
                    if kw.arg and isinstance(kw.value, ast.Constant):
                        kwargs[kw.arg] = kw.value.value
            if kwargs.get("scope") == "session" and kwargs.get("autouse") is True:
                nodes.append(node)
    return nodes


def _session_autouse_fixture_names(source: str) -> list[str]:
    return [node.name for node in _session_autouse_fixture_nodes(source)]


def _names_called_by(fn: ast.AST) -> set[str]:
    return {
        c.func.id
        for c in ast.walk(fn)
        if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
    }


def _assert_session_autouse_calls_wait_for_platform_online(source: str) -> None:
    """W1: the autouse fixture must actually invoke the barrier helper.

    A session-autouse fixture whose body is `return None` still has the
    right decorator; without this check the D-A guard is fail-open.
    """
    fixtures = _session_autouse_fixture_nodes(source)
    assert fixtures, (
        "tests/e2e/conftest.py must define a session-scoped autouse fixture "
        "that blocks until the platform is online; without it B1 is the first "
        f"collected test ({_FIRST_COLLECTED_E2E}) and races the probe"
    )
    called: set[str] = set()
    for fn in fixtures:
        called |= _names_called_by(fn)
    assert "wait_for_platform_online" in called, (
        "the session-autouse fixture must actually call the barrier; a no-op "
        "autouse fixture leaves B1 racing the probe"
    )


# Reviewer's exact W1 mutant (review.md): fixture body replaced with `return None`.
# Used as a negative fixture so the guard stays red if the linkage check is dropped.
_W1_DISABLED_BARRIER_MUTANT = textwrap.dedent(
    """\
    import pytest

    def wait_for_platform_online(dashboard_url: str) -> None:
        raise AssertionError("platform did not reach 'online'; last observed status='pending'")

    @pytest.fixture(scope="session", autouse=True)
    def wait_until_platform_online(dashboard_url: str) -> None:
        return None  # MUTANT: barrier disabled
    """
)


def _conftest_with_return_none_barrier() -> str:
    """Apply the reviewer's exact mutation to the real conftest source."""
    source = CONFTEST.read_text(encoding="utf-8")
    needle = "    wait_for_platform_online(dashboard_url)\n"
    mutant = "    return None  # MUTANT: barrier disabled\n"
    assert needle in source, (
        "could not apply the W1 return-None mutant; the autouse fixture "
        "no longer calls wait_for_platform_online(dashboard_url)"
    )
    return source.replace(needle, mutant, 1)


def _first_collected_e2e_nodeid() -> str:
    """Pytest default collection: test_*.py alphabetical, then def order."""
    files = sorted(p for p in E2E.glob("test_*.py") if p.is_file())
    assert files, "tests/e2e must contain test_*.py files"
    tree = ast.parse(files[0].read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith(
            "test_"
        ):
            return f"tests/e2e/{files[0].name}::{node.name}"
    raise AssertionError(f"no test_ functions in {files[0]}")


def _hygiene_gate_to_pytest_e2e_span(run_sh: str) -> str:
    lines = run_sh.splitlines()
    gate = [i for i, ln in enumerate(lines) if ln.strip() == "env_hygiene_gate"]
    assert len(gate) == 1, f"expected one bare env_hygiene_gate call, found {len(gate)}"
    phase = [
        i
        for i, ln in enumerate(lines)
        if ln.lstrip().startswith('phase "pytest_e2e"')
    ]
    assert phase, 'missing phase "pytest_e2e"'
    start, end = gate[0] + 1, phase[0]
    assert start <= end, "hygiene gate must precede phase pytest_e2e"
    return "\n".join(lines[start:end])


def _platform_dashboard_stub(items: list[dict]):
    """Tiny dashboard stand-in: login + GET /api/v1/platforms."""
    from contextlib import contextmanager
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    @contextmanager
    def _serve():
        class _Dash(BaseHTTPRequestHandler):
            def _send(self, payload, code=200):
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if self.path.rstrip("/").endswith("/auth/login"):
                    self._send({"access_token": "stub-token"})
                    return
                self.send_error(404)

            def do_GET(self):
                path = self.path.split("?", 1)[0].rstrip("/")
                if path.endswith("/platforms"):
                    self._send({"items": items})
                    return
                self.send_error(404)

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Dash)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()

    return _serve()


def _dashboard_stub_no_get_by_key(items: list[dict], requested: list[str] | None = None):
    """Dashboard stand-in matching the shipped route table.

    GET /api/v1/platforms            → 200 {"items": ...}
    GET /api/v1/platforms/{key}      → 405 (PATCH occupies that path)
    POST /api/v1/auth/login          → 200 {"access_token": ...}
    """
    from contextlib import contextmanager
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    log = requested if requested is not None else []

    @contextmanager
    def _serve():
        class _Dash(BaseHTTPRequestHandler):
            def _send(self, payload, code=200, extra_headers=None):
                raw = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                for key, value in extra_headers or ():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                path = self.path.split("?", 1)[0]
                log.append(f"POST {path}")
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                if path.rstrip("/").endswith("/auth/login"):
                    self._send({"access_token": "stub-token"})
                    return
                self.send_error(404)

            def do_GET(self):
                path = self.path.split("?", 1)[0]
                log.append(f"GET {path}")
                stripped = path.rstrip("/")
                if stripped.endswith("/platforms"):
                    self._send({"items": items})
                    return
                if "/platforms/" in stripped:
                    # Same 405 FastAPI returns when PATCH owns this path.
                    self.send_response(405)
                    self.send_header("Allow", "PATCH")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                self.send_error(404)

            def log_message(self, *_args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), _Dash)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_address[1]}"
        finally:
            server.shutdown()
            server.server_close()

    return _serve()


def _shorten_barrier_defaults(mod, monkeypatch, *, deadline_s=0.05, poll_s=0.0):
    """So the session-autouse fixture (no explicit deadline) can be driven in-process."""
    kw = getattr(mod.wait_for_platform_online, "__kwdefaults__", None)
    assert isinstance(kw, dict) and "deadline_s" in kw, (
        "wait_for_platform_online must expose keyword defaults so the autouse "
        "fixture's call can be bounded without a cluster"
    )
    monkeypatch.setitem(kw, "deadline_s", deadline_s)
    if "poll_s" in kw:
        monkeypatch.setitem(kw, "poll_s", poll_s)
    monkeypatch.setattr(mod, "PLATFORM_ONLINE_DEADLINE_S", deadline_s)
    monkeypatch.setattr(mod, "PLATFORM_ONLINE_POLL_S", poll_s)


def test_e2e_conftest_session_autouse_barrier_blocks_on_platform_online(monkeypatch):
    """D-A: order-independent readiness barrier, red at 2276405.

    Alphabetical collection currently puts
    test_e2e_connection_budget.py::test_live_connection_supply_exceeds_configured_demand
    first (ahead of test_e2e_load.py::test_b1_ingest_burst_profile) and the E0
    online check last. A session-scoped autouse fixture in conftest.py is what
    actually runs before whichever test is collected first. A test that only
    asserted "E0 passes" would have been green on the failing run and is
    worthless here.
    """
    source = CONFTEST.read_text(encoding="utf-8")
    fixtures = _session_autouse_fixture_names(source)
    assert fixtures, (
        "tests/e2e/conftest.py must define a session-scoped autouse fixture "
        "that blocks until the platform is online; without it B1 is the first "
        f"collected test ({_FIRST_COLLECTED_E2E}) and races the probe"
    )
    _assert_session_autouse_calls_wait_for_platform_online(source)

    first = _first_collected_e2e_nodeid()
    assert first == _FIRST_COLLECTED_E2E, (
        f"alphabetically-first e2e test is {first}; the barrier must still "
        "run first because it is session-autouse in conftest, not a per-file fix"
    )

    # The fixture (or a helper it calls) must poll for status 'online' and
    # bound the wait. Source-shape only would miss a no-op autouse fixture.
    lowered = source.lower()
    assert "online" in lowered
    assert any(
        token in lowered
        for token in ("deadline", "timeout", "monotonic", "time.time")
    ), "barrier must bound the wait; an unbounded poll hangs the 420s pytest_e2e phase"

    mod = _load_e2e_conftest()
    wait = getattr(mod, "wait_for_platform_online", None)
    assert callable(wait), (
        "conftest must expose wait_for_platform_online so the barrier can be "
        "exercised without a cluster"
    )

    polls = {"n": 0}

    class _Resp:
        def __init__(self, payload, status_code=200):
            self.status_code = status_code
            self._payload = payload
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

    def fake_post(url, **_kwargs):
        assert "login" in url
        return _Resp({"access_token": "tok"})

    def fake_get_then_online(url, **_kwargs):
        assert "platforms" in url
        polls["n"] += 1
        status = "online" if polls["n"] >= 3 else "enrolling"
        return _Resp({"items": [{"platform_key": "presto-e2e", "status": status}]})

    monkeypatch.setattr(mod.httpx, "post", fake_post)
    monkeypatch.setattr(mod.httpx, "get", fake_get_then_online)
    monkeypatch.setattr(mod.time, "sleep", lambda _s: None)
    wait("http://dash.example", deadline_s=30, poll_s=0)
    assert polls["n"] >= 3, "barrier must poll until status is online, not sample once"

    def always_pending(url, **_kwargs):
        return _Resp({"items": [{"platform_key": "presto-e2e", "status": "pending"}]})

    monkeypatch.setattr(mod.httpx, "get", always_pending)
    with pytest.raises(AssertionError, match="pending") as excinfo:
        wait("http://dash.example", deadline_s=0.01, poll_s=0)
    message = str(excinfo.value)
    assert "online" in message.lower()
    assert "pending" in message
    assert "presto-e2e" in message, (
        "failure must name the platform the barrier was waiting for; got "
        f"{message!r}"
    )


def test_e2e_autouse_fixture_blocks_on_stub_that_never_reports_online(monkeypatch):
    """W1 runtime: drive the helper *and* the autouse fixture against a stub.

    A fixture body of `return None` leaves the helper red and the fixture
    call green — that is the mutant review.md proved the old guard missed.
    """
    source = CONFTEST.read_text(encoding="utf-8")
    _assert_session_autouse_calls_wait_for_platform_online(source)
    fixtures = _session_autouse_fixture_names(source)
    mod = _load_e2e_conftest()
    wait = mod.wait_for_platform_online
    fixture_fn = getattr(mod, fixtures[0])
    # pytest 8+ refuses to call FixtureFunctionDefinition directly.
    fixture_body = getattr(fixture_fn, "__wrapped__", None) or getattr(
        fixture_fn, "_fixture_function", fixture_fn
    )

    never_online = [{"platform_key": "presto-e2e", "status": "enrolling"}]
    with _platform_dashboard_stub(never_online) as dash_url:
        with pytest.raises(AssertionError) as never_exc:
            wait(dash_url, deadline_s=0.05, poll_s=0)
        never_msg = str(never_exc.value)
        assert "online" in never_msg.lower()
        assert "presto-e2e" in never_msg
        assert "enrolling" in never_msg

        _shorten_barrier_defaults(mod, monkeypatch)
        with pytest.raises(AssertionError) as fixture_exc:
            fixture_body(dash_url)
        fixture_msg = str(fixture_exc.value)
        assert "online" in fixture_msg.lower()
        assert "presto-e2e" in fixture_msg


def test_da_guard_rejects_return_none_autouse_barrier_mutant():
    """W1 negative fixture: the reviewer's exact `return None` body is red.

    The previous guard stayed green against this mutant (review.md, 0.04s)
    because it only checked that *some* session-autouse fixture existed.
    """
    with pytest.raises(AssertionError, match="must actually call the barrier"):
        _assert_session_autouse_calls_wait_for_platform_online(
            _W1_DISABLED_BARRIER_MUTANT
        )
    with pytest.raises(AssertionError, match="must actually call the barrier"):
        _assert_session_autouse_calls_wait_for_platform_online(
            _conftest_with_return_none_barrier()
        )


def test_e2e_barrier_requires_the_specific_platform_not_any_online():
    """W2: B1's precondition is platform 'presto-e2e', not any online row.

    The shared-waiter anti-pattern (CLAUDE.md) is returning as soon as any
    entry in /api/v1/platforms is online. A leaked platform from a prior
    KEEP_CLUSTER=1 run would let the barrier pass while B1 still fails
    FP-IG-19 against /api/v1/platforms/presto-e2e.
    """
    mod = _load_e2e_conftest()
    wait = mod.wait_for_platform_online

    other_online = [
        {"platform_key": "other-platform", "status": "online"},
        {"platform_key": "presto-e2e", "status": "enrolling"},
    ]
    with _platform_dashboard_stub(other_online) as dash_url:
        with pytest.raises(AssertionError) as excinfo:
            wait(dash_url, deadline_s=0.05, poll_s=0)
    wrong = str(excinfo.value)
    assert "presto-e2e" in wrong, (
        "failure must name the required platform; got " f"{wrong!r}"
    )
    assert "enrolling" in wrong, (
        "failure must report what the required platform actually showed; "
        f"got {wrong!r}"
    )
    assert "online" in wrong.lower()

    required_online = [
        {"platform_key": "other-platform", "status": "pending"},
        {"platform_key": "presto-e2e", "status": "online"},
    ]
    with _platform_dashboard_stub(required_online) as dash_url:
        wait(dash_url, deadline_s=1, poll_s=0)

    only_other = [{"platform_key": "other-platform", "status": "online"}]
    with _platform_dashboard_stub(only_other) as dash_url:
        with pytest.raises(AssertionError) as missing:
            wait(dash_url, deadline_s=0.05, poll_s=0)
    missing_msg = str(missing.value)
    assert "presto-e2e" in missing_msg
    assert "other-platform" in missing_msg or "missing" in missing_msg.lower() or "not in" in missing_msg.lower()


def test_b1_platform_online_true_against_real_route_table():
    """F3: B1's check must pass when the list endpoint reports the platform online.

    GET /api/v1/platforms/{key} is not a route (405; PATCH occupies it). Driving
    `_platform_online` against a stub that 405s that path and serves the real
    list endpoint is the defect: at 698fff1 the helper returns False and B1
    refuses to measure. A test that only asserts False-when-offline is green
    today and is worthless.
    """
    requested: list[str] = []
    online = [{"platform_key": "presto-e2e", "status": "ONLINE"}]
    load = _load_e2e_load()
    with _dashboard_stub_no_get_by_key(online, requested) as dash_url:
        result = load._platform_online(dash_url, "stub-token")
    assert result is True, (
        "_platform_online must return True when GET /api/v1/platforms lists "
        f"presto-e2e as online; got {result!r}. requested={requested!r}"
    )
    assert any(path.endswith("/platforms") for path in requested), (
        "_platform_online must query GET /api/v1/platforms; requested="
        f"{requested!r}"
    )


def test_b1_platform_online_false_when_listed_status_is_not_online():
    """F3 companion: reading the list must not weaken B1's fail-closed check."""
    load = _load_e2e_load()
    enrolling = [{"platform_key": "presto-e2e", "status": "enrolling"}]
    with _dashboard_stub_no_get_by_key(enrolling) as dash_url:
        assert load._platform_online(dash_url, "stub-token") is False
    missing = [{"platform_key": "other-platform", "status": "online"}]
    with _dashboard_stub_no_get_by_key(missing) as dash_url:
        assert load._platform_online(dash_url, "stub-token") is False


def test_b1_and_barrier_share_list_lookup_against_real_routes():
    """F3: B1 and the session barrier must not drift onto different platform URLs."""
    requested: list[str] = []
    online = [{"platform_key": "presto-e2e", "status": "online"}]
    load = _load_e2e_load()
    barrier = _load_e2e_conftest()
    with _dashboard_stub_no_get_by_key(online, requested) as dash_url:
        assert load._platform_online(dash_url, "stub-token") is True
        barrier.wait_for_platform_online(dash_url, deadline_s=1, poll_s=0)
    get_paths = [p.split(" ", 1)[1].rstrip("/") for p in requested if p.startswith("GET ")]
    assert all(not path.split("/")[-1] == "presto-e2e" for path in get_paths), (
        "neither helper may GET /api/v1/platforms/{key}; requested="
        f"{requested!r}"
    )


def test_run_sh_failure_diagnostics_platform_status(tmp_path: Path):
    """Failure path dumps platform status; not between A10(v) and pytest_e2e.

    The pre-existing collect_failure_diagnostics() already gathers pod logs
    and events. The only extra dump that is not a duplicate is the dashboard
    API platform-status snapshot. Named-service kubectl logs were a false
    finding (D-B withdrawn) and must not come back.
    """
    run_sh = RUN_SH.read_text(encoding="utf-8")
    between = _hygiene_gate_to_pytest_e2e_span(run_sh)
    for needle in (
        "kubectl get pods",
        "kubectl describe",
        "kubectl logs",
        "/api/v1/platforms",
        "collect_failure_diagnostics",
    ):
        assert needle not in between, (
            f"{needle!r} must not sit between the A10(v) hygiene gate and "
            f'phase "pytest_e2e" (negative fixture 26); found in:\n{between}'
        )

    assert "collect_failure_diagnostics()" in run_sh
    assert "/api/v1/platforms" in run_sh, (
        "failure path must dump platform status as the dashboard API reports it"
    )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    kubectl_shim = bin_dir / "kubectl"
    kubectl_shim.write_text(
        textwrap.dedent(
            """\
            #!/usr/bin/env bash
            if [[ " $* " == *" get pods "* && " $* " == *" -o name "* ]]; then
              echo "pod/fake-pod-0"
            fi
            exit 0
            """
        ),
        encoding="utf-8",
    )
    kubectl_shim.chmod(0o755)

    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    class _Dash(BaseHTTPRequestHandler):
        def _send(self, payload):
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_POST(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            if self.path.rstrip("/").endswith("/auth/login"):
                self._send({"access_token": "diag-token"})
                return
            self.send_error(404)

        def do_GET(self):
            if "/platforms" in self.path:
                self._send(
                    {
                        "items": [
                            {"platform_key": "presto-e2e", "status": "enrolling"}
                        ]
                    }
                )
                return
            self.send_error(404)

        def log_message(self, *_args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Dash)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    dash_url = f"http://127.0.0.1:{server.server_address[1]}"

    diag_dir = Path("/tmp/rca-e2e/diagnostics")
    if diag_dir.exists():
        shutil.rmtree(diag_dir)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}{os.pathsep}{env.get('PATH', '')}"
    env["E2E_DASHBOARD_URL"] = dash_url
    env["E2E_ADMIN_USER"] = "admin"
    env["E2E_ADMIN_PASS"] = "admin-e2e-password"

    script = textwrap.dedent(
        f"""\
        set -euo pipefail
        source "{RUN_SH}"
        phase "forced_failure" 5 false
        """
    )
    proc = subprocess.Popen(
        ["bash", "-c", script],
        env=env,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = proc.communicate(timeout=30)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
        stdout, stderr = proc.communicate()
        raise AssertionError(
            f"platform-status collector hung. stdout:\n{stdout}\nstderr:\n{stderr}"
        ) from None
    finally:
        server.shutdown()
        server.server_close()

    assert proc.returncode == 1, (
        f"phase() must exit 1; rc={proc.returncode}\n{stdout}\n{stderr}"
    )
    combined = stdout + "\n" + stderr

    status_file = diag_dir / "platform-status.txt"
    assert status_file.is_file(), (
        "failure path must write the platform status the API reported "
        f"(missing {status_file})"
    )
    status_text = status_file.read_text(encoding="utf-8")
    assert "presto-e2e" in status_text
    assert "enrolling" in status_text
    # Job log must carry the status too — artifacts alone were not enough
    # to diagnose E2/E3/E4 on the failing run.
    assert "enrolling" in combined or "presto-e2e" in combined


def test_marker_failure_message_surfaces_remediation_and_execution_diagnostics():
    """E1 marker assertion must carry remediation_finished.detail and execution rows."""
    module = _scenarios_module()
    by_action = {
        "remediation_finished": [
            {
                "detail": {
                    "ok": False,
                    "failed_step": 3,
                    "op": "k8s_patch_configmap",
                    "error": "configmap conflict",
                }
            }
        ],
        "remediation_started": [{}],
        "remediation_proposed": [{}],
    }
    execution_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    exec_diagnostics = [
        {
            "execution_id": execution_id,
            "status": "failed",
            "verification_result": '{"error": "configmap conflict"}',
        }
    ]

    # Weak red-before: action names alone omit the fields E1 already had.
    old_msg = (
        f"missing remediation/verification audit markers; actions={sorted(by_action)}"
    )
    assert "configmap conflict" not in old_msg
    assert "k8s_patch_configmap" not in old_msg
    assert execution_id not in old_msg

    msg = module._marker_failure_message(by_action, exec_diagnostics)
    assert "configmap conflict" in msg
    assert "failed_step=3" in msg or "failed_step: 3" in msg
    assert "k8s_patch_configmap" in msg
    assert execution_id in msg
    assert "status='failed'" in msg
    assert "verification_result=" in msg
    assert '{"error": "configmap conflict"}' in msg
    assert "playbook failed" in msg.lower()


def test_marker_failure_message_omits_detail_when_no_remediation_finished():
    """No remediation_finished entries must not crash or fabricate detail clauses."""
    module = _scenarios_module()
    by_action = {"remediation_started": [{}]}
    msg = module._marker_failure_message(by_action, [])
    assert "missing remediation/verification audit markers" in msg
    assert "remediation_finished.detail=" not in msg
    assert "playbook failed" not in msg.lower()


def test_marker_failure_message_omits_detail_when_none():
    """detail is None must skip the detail clause without crashing."""
    module = _scenarios_module()
    by_action = {"remediation_finished": [{"detail": None}]}
    msg = module._marker_failure_message(by_action, [])
    assert "missing remediation/verification audit markers" in msg
    assert "remediation_finished.detail=" not in msg


def test_marker_failure_message_skips_playbook_failed_when_ok_truthy():
    """detail.ok truthy must not emit playbook-failed diagnostics."""
    module = _scenarios_module()
    by_action = {"remediation_finished": [{"detail": {"ok": True}}]}
    msg = module._marker_failure_message(by_action, [])
    assert "remediation_finished.detail=" in msg
    assert "playbook failed" not in msg.lower()


def test_marker_failure_message_ok_false_without_error():
    """ok falsey with error absent must still name playbook failed."""
    module = _scenarios_module()
    by_action = {
        "remediation_finished": [{"detail": {"ok": False, "failed_step": 2}}],
    }
    msg = module._marker_failure_message(by_action, [])
    assert "playbook failed" in msg.lower()
    assert "error=" not in msg
    assert "failed_step=2" in msg or "failed_step: 2" in msg


def test_marker_failure_message_degrades_on_diagnostic_lookup_failure():
    """A failed diagnostics lookup must not replace the marker assertion."""
    module = _scenarios_module()
    by_action = {
        "remediation_finished": [{"detail": {"ok": False, "error": "step blew up"}}],
    }
    exec_diagnostics = [
        {
            "execution_id": "exec-bad",
            "lookup_error": "connection refused",
        }
    ]

    msg = module._marker_failure_message(by_action, exec_diagnostics)
    assert "missing remediation/verification audit markers" in msg
    assert "connection refused" in msg


def test_marker_failure_message_survives_non_dict_remediation_detail():
    """A non-dict remediation_finished.detail must not mask the marker assert."""
    module = _scenarios_module()
    by_action = {
        "remediation_finished": [{"detail": "unexpected serialized blob"}],
    }
    msg = module._marker_failure_message(by_action, [])
    assert "missing remediation/verification audit markers" in msg
    assert "unexpected serialized blob" in msg
    assert "unexpected type" in msg


def test_parse_psql_exec_row_matches_real_psql_tsv_output():
    """Collection path must parse tab-separated psql -At -F $'\\t' rows."""
    module = _scenarios_module()
    # Measured against PostgreSQL 16 psql -At -F $'\t':
    # SELECT 'failed', '{"error":"boom"}'  ->  failed<TAB>{"error":"boom"}
    status, vr = module._parse_psql_exec_row('failed\t{"error":"boom"}')
    assert status == "failed"
    assert vr == '{"error":"boom"}'
    # SELECT 'failed', ''  ->  failed<TAB>  (trailing tab; do not strip it)
    status, vr = module._parse_psql_exec_row("failed\t")
    assert status == "failed"
    assert vr == ""
    # Default psql -At uses '|' — must not be parsed as two columns here.
    status, vr = module._parse_psql_exec_row('failed|{"error":"boom"}')
    assert status == 'failed|{"error":"boom"}'
    assert vr == ""
    # 0-row SELECT: stdout empty after rstrip -> both columns empty.
    status, vr = module._parse_psql_exec_row("")
    assert status == ""
    assert vr == ""
    status, vr = module._parse_psql_exec_row("\n")
    assert status == ""
    assert vr == ""


def test_psql_tsv_separator_constant_is_tab():
    """Producer and parser must share an explicit tab field separator."""
    module = _scenarios_module()
    assert module._PSQL_TSV_SEP == "\t"


def test_e1_marker_assertion_and_settle_bounds_not_weakened():
    """Guard: richer failure messages must not turn E1 green by relaxing the bar."""
    body = _scenario_source("test_e1_worker_oom_to_resolved")
    assert "assert start and end" in body
    assert 'by_action["verification_run"]' in body
    assert "_marker_failure_message" in body
    assert "_psql_tsv_row" in body
    assert "_parse_psql_exec_row" in body
    assert "window >= 15.0" in body
    assert "window < 60.0" in body
    assert 'status") == "RESOLVED"' in body
    end_assign_lines = [
        line.strip()
        for line in body.splitlines()
        if "end =" in line and "end = None" not in line
    ]
    assert len(end_assign_lines) == 1, (
        f"end must be assigned only from verification_run; found {end_assign_lines!r}"
    )
    assert "verification_run" in end_assign_lines[0]
    diag_block = body.split("if not (start and end):", 1)[1].split(
        "assert start and end", 1
    )[0]
    assert 'ex["execution_id"]' in diag_block
    assert diag_block.index("try:") < diag_block.index('ex["execution_id"]')
