"""Investigations / evidence / approvals / admin unit tests (FP-M4-4..14)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

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


_APPROVAL_ITEM_FIELDS = frozenset(
    {
        "approval_id",
        "investigation_id",
        "kind",
        "subject",
        "decision",
        "comment",
        "created_at",
        "age_seconds",
        "investigation_link",
    }
)


def _seed_pending_approvals_across_investigations(
    sf,
    n: int,
    *,
    start: datetime,
) -> list[tuple[uuid.UUID, uuid.UUID]]:
    """Seed n investigations, each with one pending approval. Target-last
    callers pass a start so created_at[i] = start + i seconds (oldest-first
    puts index n-1 beyond any 50/100 page when n > 100)."""
    rows: list[tuple[uuid.UUID, uuid.UUID]] = []
    with sf() as s:
        for i in range(n):
            inv_id = uuid.uuid4()
            aid = uuid.uuid4()
            created = start + timedelta(seconds=i)
            s.add(
                Investigation(
                    investigation_id=inv_id,
                    created_at=created,
                    platform_key="presto-us1",
                    status="AWAITING_APPROVAL",
                    trigger_event=None,
                    workflow_id=f"investigation-{inv_id}",
                    budget={
                        "max_rounds": 15,
                        "max_cost_usd": 10.0,
                        "max_wall_seconds": 1800,
                    },
                    spent={"rounds": 1, "cost_usd": 0},
                    rca_report={"status": "concluded", "rca_compact": f"seed-{i}"},
                )
            )
            s.add(
                Approval(
                    approval_id=aid,
                    investigation_id=inv_id,
                    kind="raw_command",
                    subject={"i": i},
                    decision=None,
                    created_at=created,
                )
            )
            rows.append((inv_id, aid))
        s.commit()
    return rows


def test_sum_llm_costs_batch_empty_missing_and_mixed(session_factory):
    """sum_llm_costs_batch: empty list, ids with no rows, mixed costs (W2)."""
    from dashboard_api.services import sum_llm_costs_batch

    _seed_platform(session_factory)
    inv_with, _ = _seed_inv(session_factory, cost=0.4)
    inv_zero, _ = _seed_inv(session_factory, cost=0)
    inv_extra = uuid.uuid4()  # never inserted

    with session_factory() as session:
        assert sum_llm_costs_batch(session, []) == {}
        # id with no llm_calls rows is absent from the map (caller uses .get(..., 0.0))
        costs = sum_llm_costs_batch(session, [inv_with, inv_zero, inv_extra])
        assert costs[inv_with] == pytest.approx(0.4)
        assert inv_zero not in costs or costs[inv_zero] == pytest.approx(0.0)
        assert inv_extra not in costs


@pytest.mark.asyncio
async def test_case_list_category_filter_and_cursor(client, session_factory):
    """category= is a SQL predicate; filtered page + next_cursor stay consistent."""
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    _seed_platform(session_factory)
    # two resource, one capacity
    _seed_inv(
        session_factory,
        status="RESOLVED",
        rca={
            "status": "concluded",
            "root_cause": {"category": "resource", "summary": "oom"},
            "rca_compact": "oom",
        },
    )
    _seed_inv(
        session_factory,
        status="RESOLVED",
        rca={
            "status": "concluded",
            "root_cause": {"category": "resource", "summary": "oom2"},
            "rca_compact": "oom2",
        },
    )
    _seed_inv(
        session_factory,
        status="RESOLVED",
        rca={
            "status": "concluded",
            "root_cause": {"category": "capacity", "summary": "queue"},
            "rca_compact": "queue",
        },
    )
    # row with rca_report but no root_cause — must not match category filter
    _seed_inv(
        session_factory,
        status="RESOLVED",
        rca={"status": "concluded", "rca_compact": "bare"},
    )
    tok = await login(client, "v", "viewer-pass-12")
    r = await client.get(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {tok}"},
        params={"category": "resource", "limit": 1},
    )
    assert r.status_code == 200
    body = r.json()
    assert len(body["items"]) == 1
    # next_cursor present when more resource rows remain
    assert body.get("next_cursor"), body
    r2 = await client.get(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {tok}"},
        params={"category": "resource", "limit": 1, "cursor": body["next_cursor"]},
    )
    assert r2.status_code == 200
    body2 = r2.json()
    assert len(body2["items"]) == 1
    assert body2["items"][0]["investigation_id"] != body["items"][0]["investigation_id"]
    # capacity-only page
    r3 = await client.get(
        "/api/v1/investigations",
        headers={"Authorization": f"Bearer {tok}"},
        params={"category": "capacity", "limit": 10},
    )
    assert r3.status_code == 200
    assert len(r3.json()["items"]) == 1


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


def test_list_approvals_filter_logic(session_factory):
    """UT-AP-1: list_approvals WHERE investigation_id, pending interplay,
    unknown id, and filter-before-LIMIT.

    Against the unfixed service this is red: investigation_id is not a
    parameter, so a call with it TypeErrors (or, if ignored, the
    limit=2 read of a target seated after older foreign rows is empty).
    Weak forms refused: a fixture with fewer foreign rows than `limit`
    would pass a post-LIMIT Python filter; asserting "returns approvals"
    passes today at any N.
    """
    from dashboard_api.services import list_approvals

    _seed_platform(session_factory)
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    # 10 older pending for other investigations, then 5 pending for the
    # target. If the filter is applied after LIMIT, limit=2 returns the
    # two oldest foreign rows and the target set is empty.
    others = _seed_pending_approvals_across_investigations(
        session_factory, 10, start=start
    )
    target_inv = uuid.uuid4()
    target_aids = []
    with session_factory() as s:
        s.add(
            Investigation(
                investigation_id=target_inv,
                created_at=start + timedelta(seconds=100),
                platform_key="presto-us1",
                status="AWAITING_APPROVAL",
                trigger_event=None,
                workflow_id=f"investigation-{target_inv}",
                budget={
                    "max_rounds": 15,
                    "max_cost_usd": 10.0,
                    "max_wall_seconds": 1800,
                },
                spent={"rounds": 1, "cost_usd": 0},
                rca_report={"status": "concluded", "rca_compact": "target"},
            )
        )
        for j in range(5):
            aid = uuid.uuid4()
            s.add(
                Approval(
                    approval_id=aid,
                    investigation_id=target_inv,
                    kind="raw_command",
                    subject={"j": j},
                    decision=None,
                    created_at=start + timedelta(seconds=100 + j),
                )
            )
            target_aids.append(aid)
        decided_aid = uuid.uuid4()
        s.add(
            Approval(
                approval_id=decided_aid,
                investigation_id=target_inv,
                kind="remediation",
                subject={"decided": True},
                decision="approved",
                comment="already decided",
                created_at=start + timedelta(seconds=200),
            )
        )
        s.commit()

    with session_factory() as session:
        filtered = list_approvals(
            session, pending=True, limit=2, investigation_id=target_inv
        )
        assert len(filtered["items"]) == 2
        assert {i["investigation_id"] for i in filtered["items"]} == {str(target_inv)}
        assert {i["approval_id"] for i in filtered["items"]} <= {
            str(a) for a in target_aids
        }

        unknown = list_approvals(
            session, pending=True, investigation_id=uuid.uuid4()
        )
        assert unknown == {"items": []}

        pending_only = list_approvals(
            session, pending=True, investigation_id=target_inv, limit=50
        )
        pending_ids = {i["approval_id"] for i in pending_only["items"]}
        assert str(decided_aid) not in pending_ids
        assert pending_ids == {str(a) for a in target_aids}

        including_decided = list_approvals(
            session, pending=False, investigation_id=target_inv, limit=50
        )
        all_ids = {i["approval_id"] for i in including_decided["items"]}
        assert str(decided_aid) in all_ids
        assert {str(a) for a in target_aids} <= all_ids

        no_filter = list_approvals(session, pending=True, limit=50)
        assert {i["investigation_id"] for i in no_filter["items"]} >= {
            str(inv) for inv, _ in others
        }


@pytest.mark.asyncio
async def test_get_approvals_route_investigation_id_parameter(client, session_factory):
    """UT-AP-2: route passes investigation_id through; malformed UUID → 422;
    absent parameter → unfiltered call.

    Against the unfixed route this is red: the parameter is undeclared, so
    FastAPI ignores it (filtered call returns the unfiltered page) and a
    malformed value is also ignored (200, not 422). Weak form refused:
    asserting 200 on a well-formed id without checking item ids.
    """
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    start = datetime(2026, 2, 1, tzinfo=timezone.utc)
    seeded = _seed_pending_approvals_across_investigations(
        session_factory, 3, start=start
    )
    tok = await login(client, "a", "approver-pass12")
    headers = {"Authorization": f"Bearer {tok}"}

    target_inv, target_aid = seeded[-1]
    r = await client.get(
        "/api/v1/approvals",
        headers=headers,
        params={"pending": "true", "investigation_id": str(target_inv)},
    )
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert items
    assert all(i["investigation_id"] == str(target_inv) for i in items)
    assert any(i["approval_id"] == str(target_aid) for i in items)

    r = await client.get(
        "/api/v1/approvals",
        headers=headers,
        params={"pending": "true", "investigation_id": "not-a-uuid"},
    )
    assert r.status_code == 422

    r = await client.get(
        "/api/v1/approvals",
        headers=headers,
        params={"pending": "true"},
    )
    assert r.status_code == 200
    unfiltered_ids = {i["investigation_id"] for i in r.json()["items"]}
    assert {str(inv) for inv, _ in seeded} <= unfiltered_ids


@pytest.mark.asyncio
async def test_a_caller_holding_an_investigation_id_reaches_its_approval_past_the_page_cap(
    client, session_factory
):
    """FP-AP-1: 120 pending approvals across 120 investigations, target last.

    Control: the unfiltered default read must NOT contain the target —
    otherwise the fixture is too small to exhibit the defect (a future
    default-page raise that exceeds N must fail this control loudly).
    Behaviour: `investigation_id=<target>` returns exactly the target's
    approval(s), every item carrying that id.

    Against the unfixed route: red. The parameter is undeclared, FastAPI
    ignores it, the response is the unfiltered oldest-first page of 50,
    and the target is absent.

    Weak forms refused: N < 50 (passes today, which is why three green
    runs never caught G1); asserting "the endpoint returns approvals"
    (passes today at any N); asserting the filtered call is non-empty
    without the id-match (passes against a filter-ignoring server
    whenever any approval exists).
    """
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    start = datetime(2026, 3, 1, tzinfo=timezone.utc)
    seeded = _seed_pending_approvals_across_investigations(
        session_factory, 120, start=start
    )
    target_inv, target_aid = seeded[-1]
    tok = await login(client, "a", "approver-pass12")
    headers = {"Authorization": f"Bearer {tok}"}

    control = await client.get(
        "/api/v1/approvals",
        headers=headers,
        params={"pending": "true"},
    )
    assert control.status_code == 200, control.text
    control_items = control.json()["items"]
    assert len(control_items) == 50
    control_ids = {i["investigation_id"] for i in control_items}
    assert str(target_inv) not in control_ids, (
        "unfiltered default page already contains the newest target — "
        "fixture is too small to exhibit the page-cap defect"
    )
    assert str(target_aid) not in {i["approval_id"] for i in control_items}

    filtered = await client.get(
        "/api/v1/approvals",
        headers=headers,
        params={"pending": "true", "investigation_id": str(target_inv)},
    )
    assert filtered.status_code == 200, filtered.text
    items = filtered.json()["items"]
    assert items, "filtered read returned no approvals for the target"
    assert all(i["investigation_id"] == str(target_inv) for i in items)
    assert {i["approval_id"] for i in items} == {str(target_aid)}


@pytest.mark.asyncio
async def test_approvals_list_contract_without_the_filter_is_unchanged(
    client, session_factory
):
    """FP-AP-2 pinning test — deliberately green against the unfixed code.

    Pins the unfiltered contract: `items` envelope, item field set,
    oldest-first by created_at, default page of 50, cap limit=500 → 100.
    This is not evidence for FP-AP-1. The weak form it forecloses is a
    fix that flips the sort to newest-first so the test's approval lands
    on page one, reordering the product's approval queue to serve a test.
    """
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed_platform(session_factory)
    start = datetime(2026, 4, 1, tzinfo=timezone.utc)
    seeded = _seed_pending_approvals_across_investigations(
        session_factory, 120, start=start
    )
    tok = await login(client, "a", "approver-pass12")
    headers = {"Authorization": f"Bearer {tok}"}

    default_page = await client.get("/api/v1/approvals", headers=headers)
    assert default_page.status_code == 200, default_page.text
    body = default_page.json()
    assert set(body.keys()) == {"items"}
    items = body["items"]
    assert len(items) == 50
    assert _APPROVAL_ITEM_FIELDS <= set(items[0].keys())

    created = [i["created_at"] for i in items]
    assert created == sorted(created), "unfiltered list must stay oldest-first"
    expected_oldest = [str(aid) for _, aid in seeded[:50]]
    assert [i["approval_id"] for i in items] == expected_oldest

    capped = await client.get(
        "/api/v1/approvals",
        headers=headers,
        params={"limit": 500},
    )
    assert capped.status_code == 200, capped.text
    capped_items = capped.json()["items"]
    assert len(capped_items) == 100
    assert [i["approval_id"] for i in capped_items] == [
        str(aid) for _, aid in seeded[:100]
    ]
    assert [i["created_at"] for i in capped_items] == sorted(
        i["created_at"] for i in capped_items
    )


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
