"""FP-M6-15/17: the e2e fixtures must be installable and usable as written.

Two classes of defect this tier catches before a 25-minute cluster run does:

* a seeded admin password the dashboard-api's own policy rejects, which makes
  `run.sh` phase 4 fail deterministically at change-password (code review round
  4, C2);
* a `run.sh` phase table whose declared budgets no longer describe a feasible
  run against the approved 1500 s gate (code review round 4, W1).
"""
from __future__ import annotations

import importlib.util
import json
import re
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
        assert "approvals" in url and "pending" in str(kwargs.get("params") or {})
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
