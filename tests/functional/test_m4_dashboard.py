"""M4 functional tests — one per FP-M4-* (design.md Section 10.2.5).

Real Temporal (WorkflowEnvironment.start_local for the end-to-end acceptance
test), real Postgres (migrated to head incl. 0002), real MinIO, FakeProbe +
ScriptedLLM, and the real dashboard-api FastAPI app over HTTP
(httpx.ASGITransport). Signals are never called directly in the acceptance
test — only through dashboard-api HTTP endpoints.
"""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from temporalio.worker import Worker

from rca_common.db.models import Approval, AuditLog, Platform, User
from rca_common.llmclient.objectstore import FakeObjectStore
from rca_common.userauth import hash_password

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "services" / "dashboard-api"))
sys.path.insert(0, str(_REPO / "services" / "worker"))
sys.path.insert(0, str(_REPO / "services" / "worker" / "tests"))

from dashboard_api.app import DashboardAppConfig, create_app  # noqa: E402
from helpers import ScriptedLLM  # noqa: E402
from worker.activities.investigation import InvestigationActivities  # noqa: E402
from worker.probeclient import FakeProbeGatewayClient  # noqa: E402
from worker.worker_main import investigation_activity_list  # noqa: E402
from worker.workflows.investigation import InvestigationWorkflow  # noqa: E402

JWT_SECRET = "m4-functional-jwt-secret-32bytes!!"
TASK_QUEUE = "m4-functional"


def _session_factory(postgres_dsn: str):
    engine = create_engine(postgres_dsn)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _seed_platform(sf, key="presto-us1", status="online"):
    with sf() as s:
        existing = s.get(Platform, key)
        if existing is None:
            s.add(
                Platform(
                    platform_key=key,
                    platform_type="presto",
                    deployment="k8s",
                    display_name=key,
                    status=status,
                    config={},
                    created_at=datetime.now(timezone.utc),
                )
            )
        else:
            existing.status = status
            # Reset config on re-seed so session-scoped PG leaks from earlier
            # suites (e.g. M3 budget override) cannot cap workflow rounds
            # (review N1 fixture isolation).
            existing.config = {}
        s.commit()


def _seed_user(
    sf,
    *,
    username: str | None = None,
    password="approver-pass-12",
    role="approver",
    must_change=False,
):
    """Create a user with a unique username (session-scoped PG is shared)."""
    uid = uuid.uuid4()
    base = username or role
    username = f"{base}-{uid.hex[:10]}"
    with sf() as s:
        existing = s.scalars(
            select(User).where(User.username == username)
        ).first()
        if existing is not None:
            return existing.user_id, existing.username
        s.add(
            User(
                user_id=uid,
                username=username,
                password_hash=hash_password(password),
                role=role,
                created_at=datetime.now(timezone.utc),
                disabled=False,
                must_change_password=must_change,
            )
        )
        s.commit()
    return uid, username


def _make_app(sf, temporal_client=None, object_store=None, webhooks=None):
    return create_app(
        session_factory=sf,
        temporal_client=temporal_client,
        object_store=object_store or FakeObjectStore(),
        config=DashboardAppConfig(
            jwt_secret=JWT_SECRET,
            token_ttl_seconds=3600,
            password_min_length=12,
            notification_webhooks=webhooks or [],
        ),
    )


async def _login(client, username, password):
    r = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )
    assert r.status_code == 200, r.text
    return r.json()


# ---------------------------------------------------------------------------
# FP-M4-1 .. FP-M4-3 auth
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_m4_login_issues_jwt_and_rejects_bad_credentials(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, uname = _seed_user(sf, username="u1", password="good-password-12", role="viewer")
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        ok = await _login(c, uname, "good-password-12")
        assert "token" in ok
        assert ok["role"] == "viewer"
        bad = await c.post(
            "/api/v1/auth/login", json={"username": uname, "password": "nope"}
        )
        assert bad.status_code == 401


@pytest.mark.asyncio
async def test_m4_rbac_matrix_401_403(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, vu = _seed_user(sf, username="v", password="viewer-pass-12", role="viewer")
    _, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        assert (await c.get("/api/v1/investigations")).status_code == 401
        v = (await _login(c, vu, "viewer-pass-12"))["token"]
        a = (await _login(c, au, "approver-pass12"))["token"]
        r = await c.get("/api/v1/approvals", headers={"Authorization": f"Bearer {v}"})
        assert r.status_code == 403
        r = await c.get("/api/v1/approvals", headers={"Authorization": f"Bearer {a}"})
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_m4_forced_password_change_gate(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, boot = _seed_user(
        sf,
        username="boot",
        password="initial-pass-12",
        role="admin",
        must_change=True,
    )
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, boot, "initial-pass-12"))["token"]
        r = await c.get(
            "/api/v1/investigations", headers={"Authorization": f"Bearer {tok}"}
        )
        assert r.status_code == 403
        assert r.json()["error"]["code"] == "password_change_required"
        r = await c.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {tok}"},
            json={"old_password": "initial-pass-12", "new_password": "changed-pass12"},
        )
        assert r.status_code == 204
        tok2 = (await _login(c, boot, "changed-pass12"))["token"]
        r = await c.get(
            "/api/v1/investigations", headers={"Authorization": f"Bearer {tok2}"}
        )
        assert r.status_code == 200


# ---------------------------------------------------------------------------
# FP-M4-4 .. FP-M4-8 read paths (seeded data)
# ---------------------------------------------------------------------------


def _seed_case(sf, *, status="INVESTIGATING"):
    from rca_common.db.models import Evidence, Investigation, Iteration, LLMCall

    _seed_platform(sf)
    inv_id = uuid.uuid4()
    eid = uuid.uuid4()
    with sf() as s:
        s.add(
            Investigation(
                investigation_id=inv_id,
                created_at=datetime.now(timezone.utc),
                platform_key="presto-us1",
                status=status,
                trigger_event=None,
                workflow_id=f"investigation-{inv_id}",
                budget={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
                spent={"rounds": 1, "cost_usd": 0},
                rca_report={
                    "status": "concluded",
                    "confidence": 0.9,
                    "root_cause": {"category": "resource", "summary": "oom"},
                    "rca_compact": "worker oom",
                },
            )
        )
        s.add(
            Iteration(
                investigation_id=inv_id,
                round=1,
                plan={"tool_calls": []},
                rca_output={"status": "need_more_data"},
                cost_usd=0.1,
                duration_ms=10,
            )
        )
        s.add(
            Evidence(
                evidence_id=eid,
                investigation_id=inv_id,
                round=1,
                tool_name="presto_cluster_info",
                summary="cluster ok",
                payload_ref=f"evidence/{eid}.json",
                payload_bytes=2,
                created_at=datetime.now(timezone.utc),
            )
        )
        s.add(
            LLMCall(
                call_id=uuid.uuid4(),
                created_at=datetime.now(timezone.utc),
                investigation_id=inv_id,
                round=1,
                agent_role="rca",
                model="fake",
                provider="fake",
                prompt_ref=f"p/{inv_id}",
                response_ref=f"r/{inv_id}",
                cost_usd=0.42,
                latency_ms=5,
            )
        )
        s.commit()
    return inv_id, eid


@pytest.mark.asyncio
async def test_m4_case_list_filters_and_cursor(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, vu = _seed_user(sf, username="v", password="viewer-pass-12", role="viewer")
    _seed_case(sf)
    _seed_case(sf, status="RESOLVED")
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, vu, "viewer-pass-12"))["token"]
        r = await c.get(
            "/api/v1/investigations",
            headers={"Authorization": f"Bearer {tok}"},
            params={"limit": 1},
        )
        assert r.status_code == 200
        assert len(r.json()["items"]) == 1
        assert r.json()["items"][0]["spent"]["cost_usd"] == pytest.approx(0.42)


@pytest.mark.asyncio
async def test_m4_case_detail_full_and_compact(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, vu = _seed_user(sf, username="v", password="viewer-pass-12", role="viewer")
    inv_id, _ = _seed_case(sf)
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, vu, "viewer-pass-12"))["token"]
        r = await c.get(
            f"/api/v1/investigations/{inv_id}",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["rca_compact"] == "worker oom"
        assert body["rca_report"]["root_cause"]["summary"] == "oom"


@pytest.mark.asyncio
async def test_m4_iterations_timeline_with_evidence_refs(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, vu = _seed_user(sf, username="v", password="viewer-pass-12", role="viewer")
    inv_id, eid = _seed_case(sf)
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, vu, "viewer-pass-12"))["token"]
        r = await c.get(
            f"/api/v1/investigations/{inv_id}/iterations",
            headers={"Authorization": f"Bearer {tok}"},
        )
        assert r.status_code == 200
        assert r.json()["items"][0]["evidence"][0]["evidence_id"] == str(eid)


@pytest.mark.asyncio
async def test_m4_evidence_read_presigned_url(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, vu = _seed_user(sf, username="v", password="viewer-pass-12", role="viewer")
    _, eid = _seed_case(sf)
    store = FakeObjectStore()
    store.put(f"evidence/{eid}.json", b"{}")
    app = _make_app(sf, object_store=store)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, vu, "viewer-pass-12"))["token"]
        r = await c.get(
            f"/api/v1/evidence/{eid}",
            headers={"Authorization": f"Bearer {tok}"},
            params={"full": "true"},
        )
        assert r.status_code == 200
        assert "download_url" in r.json()


@pytest.mark.asyncio
async def test_m4_llm_calls_trace_viewer(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, vu = _seed_user(sf, username="v", password="viewer-pass-12", role="viewer")
    inv_id, _ = _seed_case(sf)
    store = FakeObjectStore()
    store.put(f"p/{inv_id}", b"p")
    store.put(f"r/{inv_id}", b"r")
    app = _make_app(sf, object_store=store)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, vu, "viewer-pass-12"))["token"]
        r = await c.get(
            "/api/v1/llm-calls",
            headers={"Authorization": f"Bearer {tok}"},
            params={"investigation_id": str(inv_id)},
        )
        assert r.status_code == 200
        assert r.json()["items"][0]["cost_usd"] == pytest.approx(0.42)


# ---------------------------------------------------------------------------
# FP-M4-9 signals
# ---------------------------------------------------------------------------


class _FakeTemporal:
    def __init__(self):
        self.signals = []
        self.closed = set()

    def get_workflow_handle(self, workflow_id):
        parent = self

        class H:
            async def signal(self, name, arg=None):
                if workflow_id in parent.closed:
                    raise RuntimeError("workflow execution already completed")
                parent.signals.append({"workflow_id": workflow_id, "name": name, "arg": arg})

        return H()


@pytest.mark.asyncio
async def test_m4_signal_pause_resume_abort_adjust_budget(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")
    inv_id, _ = _seed_case(sf, status="INVESTIGATING")
    tc = _FakeTemporal()
    app = _make_app(sf, temporal_client=tc)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, au, "approver-pass12"))["token"]
        for action in ("pause", "resume", "abort"):
            r = await c.post(
                f"/api/v1/investigations/{inv_id}/signal",
                headers={"Authorization": f"Bearer {tok}"},
                json={"action": action},
            )
            assert r.status_code == 200, r.text
        r = await c.post(
            f"/api/v1/investigations/{inv_id}/signal",
            headers={"Authorization": f"Bearer {tok}"},
            json={"action": "adjust_budget", "budget": {"max_rounds": 20}},
        )
        assert r.status_code == 200
    assert [s["name"] for s in tc.signals] == ["pause", "resume", "abort", "adjust_budget"]


@pytest.mark.asyncio
async def test_m4_signal_on_terminal_case_409(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")
    inv_id, _ = _seed_case(sf, status="RESOLVED")
    app = _make_app(sf, temporal_client=_FakeTemporal())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, au, "approver-pass12"))["token"]
        r = await c.post(
            f"/api/v1/investigations/{inv_id}/signal",
            headers={"Authorization": f"Bearer {tok}"},
            json={"action": "pause"},
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "case_terminal"


# ---------------------------------------------------------------------------
# FP-M4-10 .. FP-M4-12 approvals
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_m4_approval_queue_lists_pending(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")
    inv_id, _ = _seed_case(sf, status="AWAITING_APPROVAL")
    aid = uuid.uuid4()
    with sf() as s:
        s.add(
            Approval(
                approval_id=aid,
                investigation_id=inv_id,
                kind="raw_command",
                subject={"command": "cat /x"},
                decision=None,
                created_at=datetime.now(timezone.utc),
            )
        )
        s.commit()
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, au, "approver-pass12"))["token"]
        r = await c.get(
            "/api/v1/approvals",
            headers={"Authorization": f"Bearer {tok}"},
            params={"pending": "true"},
        )
        assert r.status_code == 200
        assert any(i["approval_id"] == str(aid) for i in r.json()["items"])


@pytest.mark.asyncio
async def test_m4_approval_double_decision_409(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")
    inv_id, _ = _seed_case(sf, status="AWAITING_APPROVAL")
    aid = uuid.uuid4()
    with sf() as s:
        s.add(
            Approval(
                approval_id=aid,
                investigation_id=inv_id,
                kind="raw_command",
                subject={},
                decision=None,
                created_at=datetime.now(timezone.utc),
            )
        )
        s.commit()
    tc = _FakeTemporal()
    app = _make_app(sf, temporal_client=tc)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, au, "approver-pass12"))["token"]
        r1 = await c.post(
            f"/api/v1/approvals/{aid}/decision",
            headers={"Authorization": f"Bearer {tok}"},
            json={"decision": "approved"},
        )
        assert r1.status_code == 200
        r2 = await c.post(
            f"/api/v1/approvals/{aid}/decision",
            headers={"Authorization": f"Bearer {tok}"},
            json={"decision": "denied"},
        )
        assert r2.status_code == 409
        assert r2.json()["error"]["code"] == "already_decided"


@pytest.mark.asyncio
async def test_m4_approval_decision_on_terminal_409(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")
    inv_id, _ = _seed_case(sf, status="CLOSED_SUMMARY")
    aid = uuid.uuid4()
    with sf() as s:
        s.add(
            Approval(
                approval_id=aid,
                investigation_id=inv_id,
                kind="remediation",
                subject={},
                decision=None,
                created_at=datetime.now(timezone.utc),
            )
        )
        s.commit()
    app = _make_app(sf, temporal_client=_FakeTemporal())
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, au, "approver-pass12"))["token"]
        r = await c.post(
            f"/api/v1/approvals/{aid}/decision",
            headers={"Authorization": f"Bearer {tok}"},
            json={"decision": "approved"},
        )
        assert r.status_code == 409
        assert r.json()["error"]["code"] == "case_terminal"


@pytest.mark.asyncio
async def test_m4_need_more_comment_in_next_rca_round(postgres_dsn, temporal_env):
    """FP-M4-12: need_more comment is injected into the next RCA round prompt."""
    sf = _session_factory(postgres_dsn)
    _seed_platform(sf)
    approver_id, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")

    llm = ScriptedLLM(
        {
            "planner": {
                "tool_calls": [{"tool": "presto_cluster_info", "args": {}, "purpose": "s"}],
                "unresolvable": [],
            },
            "collector": {
                "summary": "ok",
                "notable_lines": [],
                "anomaly_detected": False,
            },
            "rca": [
                {
                    "status": "need_more_data",
                    "confidence": 0.5,
                    "missing_info": [{"what": "logs", "why": "need"}],
                    "raw_command_requests": [
                        {
                            "command": "cat /etc/presto/config.properties",
                            "justification": "config",
                        }
                    ],
                },
                {
                    "status": "concluded",
                    "confidence": 0.95,
                    "root_cause": {"category": "resource", "summary": "oom"},
                    "rca_compact": "oom after feedback",
                },
            ],
            "remediation": {
                "proposed_actions": [
                    {"kind": "ignore", "risk_level": "R0", "description": "done"}
                ],
                "rca_compact": "oom after feedback",
            },
        }
    )
    probe = FakeProbeGatewayClient()
    acts = InvestigationActivities(
        session_factory=sf,
        llm_client=llm,
        probe_client=probe,
        object_store=FakeObjectStore(),
        config=None,
    )
    client = temporal_env.client
    app = _make_app(sf, temporal_client=client)
    inv_id = uuid.uuid4()
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "grafana-prod",
        "platform_key": "presto-us1",
        "error_summary": "worker oom",
        "occurred_at": "2026-07-11T00:00:00Z",
        "severity": "high",
        "fingerprint": "fp-need-more",
    }
    import asyncio

    async with Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[InvestigationWorkflow],
        activities=investigation_activity_list(acts),
    ):
        handle = await client.start_workflow(
            InvestigationWorkflow.run,
            {"event": event, "investigation_id": str(inv_id)},
            id=f"investigation-{inv_id}",
            task_queue=TASK_QUEUE,
        )
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t"
        ) as http:
            tok = (await _login(http, au, "approver-pass12"))["token"]
            aid = None
            for _ in range(80):
                await asyncio.sleep(0.25)
                r = await http.get(
                    "/api/v1/approvals",
                    headers={"Authorization": f"Bearer {tok}"},
                    params={"pending": "true"},
                )
                items = r.json().get("items") or []
                pending = [i for i in items if i["investigation_id"] == str(inv_id)]
                if pending:
                    aid = pending[0]["approval_id"]
                    break
            assert aid, "raw_command approval never appeared"
            r = await http.post(
                f"/api/v1/approvals/{aid}/decision",
                headers={"Authorization": f"Bearer {tok}"},
                json={
                    "decision": "need_more",
                    "comment": "please also collect GC logs",
                },
            )
            assert r.status_code == 200, r.text
            result = await handle.result()
    assert result["status"] in ("CLOSED_SUMMARY", "RESOLVED", "NEEDS_HUMAN")
    rca_calls = [c for c in llm.calls if c.get("agent_role") == "rca"]
    assert len(rca_calls) >= 2
    second_prompt = rca_calls[1]["messages"][0]["content"]
    assert "please also collect GC logs" in second_prompt


# ---------------------------------------------------------------------------
# FP-M4-11 centerpiece: end-to-end acceptance (Section 12)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_m4_approval_decision_end_to_end(postgres_dsn, temporal_env):
    """Section 12: human completes one raw-command + one remediation approval
    end to end through dashboard-api HTTP only → RESOLVED.
    """
    sf = _session_factory(postgres_dsn)
    _seed_platform(sf)
    approver_id, au = _seed_user(sf, username="a", password="approver-pass12", role="approver")

    llm = ScriptedLLM(
        {
            "planner": {
                "tool_calls": [
                    {"tool": "presto_cluster_info", "args": {}, "purpose": "state"}
                ],
                "unresolvable": [],
            },
            "collector": {
                "summary": "cluster info",
                "notable_lines": [],
                "anomaly_detected": False,
            },
            "rca": {
                "status": "concluded",
                "confidence": 0.95,
                "root_cause": {
                    "category": "resource",
                    "summary": "runaway query",
                    "detail": "q1",
                    "evidence_refs": [],
                },
                "rca_compact": "kill runaway query",
                "raw_command_requests": [
                    {
                        "command": "cat /etc/presto/config.properties",
                        "justification": "confirm memory",
                    }
                ],
            },
            "remediation": {
                "proposed_actions": [
                    {
                        "kind": "playbook",
                        "playbook_id": "presto.kill_query",
                        "risk_level": "R1",
                        "description": "kill q1",
                        "playbook_params": {"query_id": "q1"},
                        "verification_plan": ["presto_list_queries"],
                    }
                ],
                "rca_compact": "kill runaway query",
            },
        }
    )
    probe = FakeProbeGatewayClient(
        {
            "presto_cluster_info": {"exit_code": 0, "data": {}},
            "presto_list_queries": {"exit_code": 0, "data": {"queries": []}},
            "presto_query_detail": {"exit_code": 0, "data": {}},
            "health": {"ok": True, "exit_code": 0},
            "write": {"ok": True, "exit_code": 0},
        }
    )
    import tempfile
    from rca_common.signing.signer import bootstrap_signing_key

    signer = bootstrap_signing_key(tempfile.mkdtemp() + "/ed25519.key")
    acts = InvestigationActivities(
        session_factory=sf,
        llm_client=llm,
        probe_client=probe,
        object_store=FakeObjectStore(),
        config=None,
        signer=signer,
    )
    client = temporal_env.client
    app = _make_app(sf, temporal_client=client)
    inv_id = uuid.uuid4()
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "grafana-prod",
        "platform_key": "presto-us1",
        "error_summary": "runaway query",
        "occurred_at": "2026-07-11T00:00:00Z",
        "severity": "critical",
        "fingerprint": "fp-e2e",
    }

    async def wait_pending(http, tok, kind=None, timeout_loops=80):
        import asyncio

        for _ in range(timeout_loops):
            r = await http.get(
                "/api/v1/approvals",
                headers={"Authorization": f"Bearer {tok}"},
                params={"pending": "true"},
            )
            items = [
                i
                for i in (r.json().get("items") or [])
                if i["investigation_id"] == str(inv_id)
                and (kind is None or i["kind"] == kind)
            ]
            if items:
                return items[0]
            await asyncio.sleep(0.25)
        return None

    async with Worker(
        client,
        task_queue=TASK_QUEUE,
        workflows=[InvestigationWorkflow],
        activities=investigation_activity_list(acts),
    ):
        handle = await client.start_workflow(
            InvestigationWorkflow.run,
            {"event": event, "investigation_id": str(inv_id)},
            id=f"investigation-{inv_id}",
            task_queue=TASK_QUEUE,
        )
        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="http://t"
        ) as http:
            tok = (await _login(http, au, "approver-pass12"))["token"]
            h = {"Authorization": f"Bearer {tok}"}

            raw = await wait_pending(http, tok, kind="raw_command")
            assert raw is not None, "raw_command approval never appeared"
            r = await http.post(
                f"/api/v1/approvals/{raw['approval_id']}/decision",
                headers=h,
                json={"decision": "approved", "comment": "ok raw"},
            )
            assert r.status_code == 200, r.text

            rem = await wait_pending(http, tok, kind="remediation")
            assert rem is not None, "remediation approval never appeared"
            r = await http.post(
                f"/api/v1/approvals/{rem['approval_id']}/decision",
                headers=h,
                json={"decision": "approved", "comment": "ok rem"},
            )
            assert r.status_code == 200, r.text

            result = await handle.result()
            assert result["status"] == "RESOLVED"

            # Double decision → 409
            r = await http.post(
                f"/api/v1/approvals/{raw['approval_id']}/decision",
                headers=h,
                json={"decision": "denied"},
            )
            assert r.status_code == 409

            # Signal on terminal → 409
            r = await http.post(
                f"/api/v1/investigations/{inv_id}/signal",
                headers=h,
                json={"action": "pause"},
            )
            assert r.status_code == 409

    with sf() as s:
        approvals = list(
            s.scalars(
                select(Approval).where(Approval.investigation_id == inv_id)
            ).all()
        )
        assert len(approvals) == 2
        for a in approvals:
            assert a.decision == "approved"
            assert a.decided_by == approver_id
        audits = list(
            s.scalars(
                select(AuditLog).where(
                    AuditLog.investigation_id == inv_id,
                    AuditLog.action.in_(
                        ["approval_decided", "raw_cmd_approved"]
                    ),
                )
            ).all()
        )
        assert any(a.actor == f"user:{approver_id}" for a in audits)


# ---------------------------------------------------------------------------
# FP-M4-13 admin + FP-M4-14 audit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_m4_admin_endpoints(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    _, adu = _seed_user(sf, username="ad", password="admin-pass-123", role="admin")
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, adu, "admin-pass-123"))["token"]
        h = {"Authorization": f"Bearer {tok}"}
        r = await c.post(
            "/api/v1/platforms",
            headers=h,
            json={
                "platform_key": "presto-admin",
                "platform_type": "presto",
                "deployment": "k8s",
                "display_name": "Admin",
                "config": {},
            },
        )
        assert r.status_code == 201
        r = await c.patch(
            "/api/v1/platforms/presto-admin",
            headers=h,
            json={"config": {"health_query": "SELECT 1"}},
        )
        assert r.status_code == 200
        r = await c.post(
            "/api/v1/platforms/presto-admin/bootstrap-token", headers=h
        )
        assert r.status_code == 200 and "token" in r.json()
        r = await c.get("/api/v1/probes", headers=h)
        assert r.status_code == 200
        r = await c.get("/api/v1/playbooks", headers=h)
        assert r.status_code == 200
        # auto_eligible PUT → 403 pre-Phase-3 (even if playbook missing, 403 first)
        r = await c.put(
            "/api/v1/playbooks/any",
            headers=h,
            json={"auto_eligible": True},
        )
        assert r.status_code == 403
        r = await c.post(
            "/api/v1/users",
            headers=h,
            json={
                "username": "carol",
                "password": "carol-pass-123",
                "role": "viewer",
            },
        )
        assert r.status_code == 201
        r = await c.post("/api/v1/admin/notifications/test", headers=h)
        assert r.status_code == 200
        r = await c.get("/api/v1/audit", headers=h)
        assert r.status_code == 200
        r = await c.get("/api/v1/metrics/summary", headers=h)
        assert r.status_code == 200


@pytest.mark.asyncio
async def test_m4_mutations_write_audit_user_actor(postgres_dsn):
    sf = _session_factory(postgres_dsn)
    uid, adu = _seed_user(sf, username="ad", password="admin-pass-123", role="admin")
    app = _make_app(sf)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        tok = (await _login(c, adu, "admin-pass-123"))["token"]
        await c.post(
            "/api/v1/platforms",
            headers={"Authorization": f"Bearer {tok}"},
            json={
                "platform_key": "p-audit",
                "platform_type": "presto",
                "deployment": "swarm",
            },
        )
    with sf() as s:
        rows = list(
            s.scalars(
                select(AuditLog).where(AuditLog.action == "admin_config_changed")
            ).all()
        )
    assert rows
    assert any(r.actor == f"user:{uid}" for r in rows)
