"""Investigations / evidence / approvals / admin unit tests (FP-M4-4..14)."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from rca_common.db.models import (
    Approval,
    AuditLog,
    Evidence,
    Investigation,
    Iteration,
    LLMCall,
    Platform,
    Playbook,
)
from dashboard_helpers import login, seed_user


def _seed_platform(sf, key="presto-us1"):
    with sf() as s:
        if s.get(Platform, key) is None:
            s.add(
                Platform(
                    platform_key=key,
                    platform_type="presto",
                    deployment="k8s",
                    display_name=key,
                    status="online",
                    config={},
                    created_at=datetime.now(timezone.utc),
                )
            )
            s.commit()


def _seed_inv(
    sf,
    *,
    status="INVESTIGATING",
    platform_key="presto-us1",
    cost=0.25,
    rounds=2,
    rca=None,
):
    inv_id = uuid.uuid4()
    wf = f"investigation-{inv_id}"
    with sf() as s:
        s.add(
            Investigation(
                investigation_id=inv_id,
                created_at=datetime.now(timezone.utc),
                platform_key=platform_key,
                status=status,
                trigger_event=None,
                workflow_id=wf,
                budget={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
                spent={"rounds": rounds, "cost_usd": 0},
                rca_report=rca
                or {
                    "status": "concluded",
                    "confidence": 0.9,
                    "root_cause": {"category": "resource", "summary": "oom"},
                    "rca_compact": "worker oom",
                },
            )
        )
        if cost:
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
                    input_tokens=10,
                    output_tokens=20,
                    cost_usd=cost,
                    latency_ms=5,
                )
            )
        s.commit()
    return inv_id, wf


@pytest.mark.asyncio
async def test_case_list_filters_and_cursor(client, session_factory):
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    _seed_platform(session_factory)
    for i in range(3):
        _seed_inv(session_factory, status="INVESTIGATING" if i < 2 else "RESOLVED")
    tok = await login(client, "v", "viewer-pass-12")
    r = await client.get(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {tok}"},
        params={"limit": 2},
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 2
    assert body["items"][0]["spent"]["cost_usd"] == pytest.approx(0.25)
    # status filter
    r = await client.get(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {tok}"},
        params=[("status", "RESOLVED")],
    )
    assert r.status_code == 200
    assert all(i["status"] == "RESOLVED" for i in r.json()["items"])


@pytest.mark.asyncio
async def test_case_detail_full_and_compact(client, session_factory):
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    _seed_platform(session_factory)
    inv_id, _ = _seed_inv(session_factory)
    tok = await login(client, "v", "viewer-pass-12")
    r = await client.get(
        f"/api/v1/investigations/{inv_id}",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["rca_report"]["root_cause"]["summary"] == "oom"
    assert body["rca_compact"] == "worker oom"
    assert "related_events" in body
    assert "executions" in body


@pytest.mark.asyncio
async def test_iterations_timeline_with_evidence_refs(client, session_factory, object_store):
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    _seed_platform(session_factory)
    inv_id, _ = _seed_inv(session_factory)
    eid = uuid.uuid4()
    with session_factory() as s:
        s.add(
            Iteration(
                investigation_id=inv_id,
                round=1,
                plan={"tool_calls": []},
                rca_output={"status": "need_more_data"},
                cost_usd=0.1,
                duration_ms=12,
            )
        )
        s.add(
            Evidence(
                evidence_id=eid,
                investigation_id=inv_id,
                round=1,
                tool_name="presto_cluster_info",
                summary="ok",
                payload_ref=f"evidence/{eid}.json",
                payload_bytes=10,
                created_at=datetime.now(timezone.utc),
            )
        )
        s.commit()
    object_store.put(f"evidence/{eid}.json", b'{"x":1}')
    tok = await login(client, "v", "viewer-pass-12")
    r = await client.get(
        f"/api/v1/investigations/{inv_id}/iterations",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert items[0]["round"] == 1
    assert items[0]["evidence"][0]["evidence_id"] == str(eid)


@pytest.mark.asyncio
async def test_evidence_read_presigned_url(client, session_factory, object_store):
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    eid = uuid.uuid4()
    object_store.put("e/1.json", b"{}")
    with session_factory() as s:
        s.add(
            Evidence(
                evidence_id=eid,
                investigation_id=uuid.uuid4(),
                round=1,
                tool_name="t",
                summary="sum",
                payload_ref="e/1.json",
                created_at=datetime.now(timezone.utc),
            )
        )
        s.commit()
    tok = await login(client, "v", "viewer-pass-12")
    r = await client.get(
        f"/api/v1/evidence/{eid}",
        headers={"Authorization": f"Bearer {tok}"},
    )
    assert r.status_code == 200
    assert "download_url" not in r.json() or r.json().get("download_url") is None
    r = await client.get(
        f"/api/v1/evidence/{eid}",
        headers={"Authorization": f"Bearer {tok}"},
        params={"full": "true"},
    )
    assert r.status_code == 200
    assert "fake-s3.local" in r.json()["download_url"]


@pytest.mark.asyncio
async def test_llm_calls_trace_viewer(client, session_factory, object_store):
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    _seed_platform(session_factory)
    inv_id, _ = _seed_inv(session_factory, cost=0.5)
    object_store.put(f"p/{inv_id}", b"prompt")
    object_store.put(f"r/{inv_id}", b"resp")
    tok = await login(client, "v", "viewer-pass-12")
    r = await client.get(
        "/api/v1/llm-calls",
        headers={"Authorization": f"Bearer {tok}"},
        params={"investigation_id": str(inv_id)},
    )
    assert r.status_code == 200
    item = r.json()["items"][0]
    assert item["cost_usd"] == pytest.approx(0.5)
    assert "fake-s3.local" in (item["prompt_url"] or "")


@pytest.mark.asyncio
async def test_signal_pause_resume_abort_adjust_budget(client, session_factory, temporal_client):
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    inv_id, wf = _seed_inv(session_factory, status="INVESTIGATING")
    tok = await login(client, "a", "approver-pass12")
    for action, extra in [
        ("pause", {}),
        ("resume", {}),
        ("adjust_budget", {"budget": {"max_rounds": 20}}),
        ("abort", {}),
    ]:
        r = await client.post(
            f"/api/v1/investigations/{inv_id}/signal",
            headers={"Authorization": f"Bearer {tok}"},
            json={"action": action, **extra},
        )
        assert r.status_code == 200, r.text
    names = [s["name"] for s in temporal_client.signals]
    assert names == ["pause", "resume", "adjust_budget", "abort"]
    # audit rows
    with session_factory() as s:
        actions = [a.action for a in s.scalars(select(AuditLog)).all()]
    assert "case_paused" in actions
    assert "case_resumed" in actions
    assert "budget_adjusted" in actions
    assert "case_aborted" in actions


@pytest.mark.asyncio
async def test_signal_on_terminal_case_409(client, session_factory, temporal_client):
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    inv_id, _ = _seed_inv(session_factory, status="RESOLVED")
    tok = await login(client, "a", "approver-pass12")
    r = await client.post(
        f"/api/v1/investigations/{inv_id}/signal",
        headers={"Authorization": f"Bearer {tok}"},
        json={"action": "pause"},
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "case_terminal"
    assert temporal_client.signals == []


@pytest.mark.asyncio
async def test_approval_queue_and_decision(client, session_factory, temporal_client):
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    inv_id, wf = _seed_inv(session_factory, status="AWAITING_APPROVAL")
    aid = uuid.uuid4()
    with session_factory() as s:
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
    tok = await login(client, "a", "approver-pass12")
    r = await client.get(
        "/api/v1/approvals",
        headers={"Authorization": f"Bearer {tok}"},
        params={"pending": "true"},
    )
    assert r.status_code == 200
    assert any(i["approval_id"] == str(aid) for i in r.json()["items"])

    r = await client.post(
        f"/api/v1/approvals/{aid}/decision",
        headers={"Authorization": f"Bearer {tok}"},
        json={"decision": "approved", "comment": "ok"},
    )
    assert r.status_code == 200
    assert temporal_client.signals[-1]["name"] == "approval_decided"
    assert temporal_client.signals[-1]["arg"]["approval_id"] == str(aid)

    # double decision 409
    r = await client.post(
        f"/api/v1/approvals/{aid}/decision",
        headers={"Authorization": f"Bearer {tok}"},
        json={"decision": "denied"},
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "already_decided"

    with session_factory() as s:
        actors = [a.actor for a in s.scalars(select(AuditLog)).all()]
    assert any(a.startswith("user:") for a in actors)


@pytest.mark.asyncio
async def test_approval_decision_on_terminal_409(client, session_factory):
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    inv_id, _ = _seed_inv(session_factory, status="CLOSED_SUMMARY")
    aid = uuid.uuid4()
    with session_factory() as s:
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
    tok = await login(client, "a", "approver-pass12")
    r = await client.post(
        f"/api/v1/approvals/{aid}/decision",
        headers={"Authorization": f"Bearer {tok}"},
        json={"decision": "approved"},
    )
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "case_terminal"


@pytest.mark.asyncio
async def test_need_more_requires_comment(client, session_factory):
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    inv_id, _ = _seed_inv(session_factory, status="AWAITING_APPROVAL")
    aid = uuid.uuid4()
    with session_factory() as s:
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
    tok = await login(client, "a", "approver-pass12")
    r = await client.post(
        f"/api/v1/approvals/{aid}/decision",
        headers={"Authorization": f"Bearer {tok}"},
        json={"decision": "need_more", "comment": ""},
    )
    assert r.status_code == 400


@pytest.mark.asyncio
async def test_admin_endpoints(client, session_factory):
    seed_user(session_factory, username="ad", password="admin-pass-123", role="admin")
    tok = await login(client, "ad", "admin-pass-123")
    h = {"Authorization": f"Bearer {tok}"}

    r = await client.post(
        "/api/v1/platforms",
        headers=h,
        json={
            "platform_key": "presto-new",
            "platform_type": "presto",
            "deployment": "k8s",
            "display_name": "New",
            "config": {},
        },
    )
    assert r.status_code == 201

    r = await client.patch(
        "/api/v1/platforms/presto-new",
        headers=h,
        json={"config": {"correlation_window": 900}},
    )
    assert r.status_code == 200

    r = await client.post("/api/v1/platforms/presto-new/bootstrap-token", headers=h)
    assert r.status_code == 200
    assert "token" in r.json()
    assert "expires_at" in r.json()

    r = await client.get("/api/v1/platforms", headers=h)
    assert r.status_code == 200
    assert any(p["platform_key"] == "presto-new" for p in r.json()["items"])

    r = await client.get("/api/v1/probes", headers=h)
    assert r.status_code == 200

    with session_factory() as s:
        s.add(
            Playbook(
                playbook_id="presto.kill_query",
                platform_type="presto",
                risk_level="R1",
                params_schema={},
                steps=[],
                verification={},
                auto_eligible=False,
            )
        )
        s.commit()
    r = await client.get("/api/v1/playbooks", headers=h)
    assert r.status_code == 200
    r = await client.get("/api/v1/playbooks/presto.kill_query", headers=h)
    assert r.status_code == 200
    r = await client.put(
        "/api/v1/playbooks/presto.kill_query",
        headers=h,
        json={"auto_eligible": True},
    )
    assert r.status_code == 403

    r = await client.post(
        "/api/v1/users",
        headers=h,
        json={"username": "bob", "password": "bob-password-12", "role": "viewer"},
    )
    assert r.status_code == 201
    bob_id = r.json()["user_id"]
    r = await client.patch(
        f"/api/v1/users/{bob_id}",
        headers=h,
        json={"disabled": True},
    )
    assert r.status_code == 200
    r = await client.get("/api/v1/users", headers=h)
    assert r.status_code == 200

    r = await client.post("/api/v1/admin/notifications/test", headers=h)
    assert r.status_code == 200
    assert "results" in r.json()

    r = await client.get("/api/v1/audit", headers=h)
    assert r.status_code == 200
    assert len(r.json()["items"]) >= 1

    r = await client.get("/api/v1/metrics/summary", headers=h, params={"window": "7d"})
    assert r.status_code == 200
    assert "open_cases" in r.json()


@pytest.mark.asyncio
async def test_mutations_write_audit_user_actor(client, session_factory):
    uid = seed_user(session_factory, username="ad", password="admin-pass-123", role="admin")
    tok = await login(client, "ad", "admin-pass-123")
    await client.post(
        "/api/v1/platforms",
        headers={"Authorization": f"Bearer {tok}"},
        json={"platform_key": "p1", "platform_type": "presto", "deployment": "swarm"},
    )
    with session_factory() as s:
        rows = list(s.scalars(select(AuditLog).where(AuditLog.action == "admin_config_changed")).all())
    assert rows
    assert all(r.actor == f"user:{uid}" for r in rows)


@pytest.mark.asyncio
async def test_bootstrap_admin_idempotent(session_factory):
    from dashboard_api.bootstrap_admin import bootstrap_admin

    r1 = bootstrap_admin(session_factory, username="root", password="root-password-12")
    r2 = bootstrap_admin(session_factory, username="root", password="root-password-12")
    assert r1 == "created"
    assert r2 == "exists"


@pytest.mark.asyncio
async def test_create_app_requires_jwt_secret(session_factory, temporal_client, object_store):
    from dashboard_api.app import DashboardAppConfig, create_app

    with pytest.raises(ValueError):
        create_app(
            session_factory=session_factory,
            temporal_client=temporal_client,
            object_store=object_store,
            config=DashboardAppConfig(jwt_secret=""),
        )
