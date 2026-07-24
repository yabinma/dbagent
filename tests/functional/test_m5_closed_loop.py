"""M5 functional tests (design.md Section 9.5.5 FP-M5-1..13).

Uses real InvestigationWorkflow + InvestigationActivities, ephemeral PG
(migrated + seeded playbooks), FakeProbeGatewayClient, ScriptedLLM, and a
mock webhook receiver. Temporal time-skipping for settle timer (FP-M5-8).
"""
from __future__ import annotations

import base64
import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from rca_common.db.models import Platform, Playbook, RemediationExecution, AuditLog
from rca_common.db.session import make_session_factory
from rca_common.llmclient.objectstore import FakeObjectStore
from rca_common.signing.signer import bootstrap_signing_key, canonical_step_hash

import sys

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "services" / "worker"))
sys.path.insert(0, str(_REPO / "services" / "worker" / "tests"))
sys.path.insert(0, str(_REPO / "services" / "worker" / "scripts"))
sys.path.insert(0, str(_REPO / "libs" / "py" / "rca_common"))

from worker.activities.investigation import InvestigationActivities  # noqa: E402
from worker.playbooks import PLAYBOOK_STEPS, PLAYBOOK_CATALOG  # noqa: E402
from worker.probeclient import FakeProbeGatewayClient, HTTPProbeGatewayClient  # noqa: E402
from worker.worker_main import investigation_activity_list  # noqa: E402
from worker.workflows.investigation import InvestigationWorkflow  # noqa: E402
from helpers import ScriptedLLM  # noqa: E402
from seed_playbooks import seed_playbooks  # noqa: E402

TASK_QUEUE = "m5-functional"


class _WebhookHandler(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode())
        except Exception:  # noqa: BLE001
            payload = {"raw": body.decode(errors="replace")}
        type(self).received.append(payload)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        return


@pytest.fixture
def webhook_receiver():
    _WebhookHandler.received = []
    server = HTTPServer(("127.0.0.1", 0), _WebhookHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/hook"
    server.shutdown()


def _seed_platform(session_factory, key="presto-us1", deployment="k8s", config=None):
    from datetime import datetime, timezone

    with session_factory() as session:
        existing = session.get(Platform, key)
        if existing is None:
            session.add(
                Platform(
                    platform_key=key,
                    platform_type="presto",
                    deployment=deployment,
                    display_name=key,
                    status="online",
                    config=config
                    or {
                        "remediation_targets": {
                            "namespace": "presto",
                            "worker_configmap": "presto-worker-config",
                            "worker_workload_kind": "deployment",
                            "worker_workload_name": "presto-worker",
                        },
                        "remediation": {"settle_seconds": 0},
                    },
                    created_at=datetime.now(timezone.utc),
                )
            )
        else:
            existing.deployment = deployment
            if config is not None:
                existing.config = config
        session.commit()


def _make_config(webhook_url: str, key_path: str):
    from rca_common.config import parse_config

    return parse_config(
        {
            "signing": {"key_path": key_path},
            "notifications": {
                "outbound_webhooks": [
                    {
                        "name": "slack",
                        "url": webhook_url,
                        "format": "slack",
                        "events": [
                            "approval_requested",
                            "case_needs_human",
                            "case_resolved",
                            "case_rejected",
                        ],
                        "min_severity": "low",
                    },
                    {
                        "name": "generic",
                        "url": webhook_url,
                        "format": "generic",
                        "events": [
                            "approval_requested",
                            "case_resolved",
                        ],
                        "min_severity": "low",
                    },
                ]
            },
            "probe_gateway": {"url": "http://127.0.0.1:9"},
        }
    )


def _llm_playbook(playbook_id="presto.kill_query", params=None):
    return ScriptedLLM(
        {
            "planner": {
                "tool_calls": [
                    {"tool": "presto_cluster_info", "args": {}, "purpose": "state"}
                ],
                "unresolvable": [],
            },
            "collector": {
                "summary": "cluster ok",
                "notable_lines": [],
                "anomaly_detected": False,
            },
            "rca": {
                "status": "concluded",
                "confidence": 0.95,
                "root_cause": {
                    "category": "resource",
                    "summary": "runaway query",
                    "detail": "q",
                    "evidence_refs": [],
                },
                "rca_compact": "runaway query",
            },
            "remediation": {
                "proposed_actions": [
                    {
                        "kind": "playbook",
                        "playbook_id": playbook_id,
                        "risk_level": "R1",
                        "description": "kill query",
                        "playbook_params": params or {"query_id": "2024_q1"},
                        "verification_plan": ["presto_list_queries"],
                        "settle_seconds": 0,
                        "rollback_note": "re-submit query",
                    }
                ],
                "rca_compact": "runaway query digest",
            },
        }
    )


# ---------------------------------------------------------------------------
# FP-M5 unit-style functional points (Python side)
# ---------------------------------------------------------------------------


def test_m5_five_playbooks_primitive_sequences():
    """FP-M5-3: each playbook drives correct ordered primitives per deployment."""
    params = {
        "query_id": "q",
        "worker_id": "w1",
        "patches": [{"key": "query.max-memory", "value": "50GB"}],
        "memory_params": {"query.max-memory": "50GB"},
        "config_key": "query.max-memory",
        "config_value": "50GB",
    }
    expected_ops = {
        "presto.kill_query": {
            "k8s": ["presto_kill_query"],
            "swarm": ["presto_kill_query"],
        },
        "presto.update_config_restart_workers": {
            "k8s": ["k8s_patch_configmap", "k8s_rollout_restart"],
            "swarm": ["swarm_update_service_env", "swarm_restart_service"],
        },
        "presto.restart_coordinator": {
            "k8s": ["k8s_rollout_restart"],
            "swarm": ["swarm_restart_service"],
        },
        "presto.restart_worker": {
            "k8s": ["k8s_delete_pod"],
            "swarm": ["swarm_restart_service"],
        },
        "presto.adjust_memory_config": {
            "k8s": ["k8s_patch_configmap", "k8s_rollout_restart"],
            "swarm": ["swarm_update_service_env", "swarm_restart_service"],
        },
    }
    for pid, by_dep in expected_ops.items():
        for dep, ops in by_dep.items():
            steps = PLAYBOOK_STEPS[pid](dep, params, {})
            assert [s["op"] for s in steps] == ops


def test_m5_adjust_memory_config_whitelist_rejects_offlist():
    """FP-M5-4 worker-side whitelist."""
    with pytest.raises(ValueError, match="whitelist"):
        PLAYBOOK_STEPS["presto.adjust_memory_config"](
            "k8s",
            {"patches": [{"key": "not.allowed", "value": "1"}]},
            {},
        )


def test_m5_adjust_memory_config_empty_params_raises():
    """C1: empty params must fail closed (no fabricated query.max-memory=20GB)."""
    with pytest.raises(ValueError, match="requires memory params"):
        PLAYBOOK_STEPS["presto.adjust_memory_config"]("k8s", {}, {})


def test_m5_seed_playbooks_idempotent(postgres_dsn):
    """FP-M5-11.

    Session-scoped PG is shared: earlier suites may already have partial
    catalog rows via execute_playbook auto-seed (and those rows are FK-
    referenced by remediation_executions, so we cannot DELETE). Idempotency
    is: first seed covers all 5 (insert and/or update), second seed updates
    all 5 with zero inserts, and exactly 5 catalog rows exist afterward.
    """
    from sqlalchemy import select

    engine = __import__("sqlalchemy").create_engine(postgres_dsn)
    factory = make_session_factory(engine)
    with factory() as session:
        c1 = seed_playbooks(session)
        c2 = seed_playbooks(session)
    assert c1["inserted"] + c1["updated"] == 5
    assert c2["inserted"] == 0
    assert c2["updated"] == 5
    with factory() as session:
        rows = list(session.scalars(select(Playbook)))
        assert len(rows) == 5


@pytest.mark.asyncio
async def test_m5_notifications_slack_and_generic_filtered_and_retried(webhook_receiver):
    """FP-M5-10."""
    from rca_common.notifications import send_to_webhooks

    results = await send_to_webhooks(
        [
            {
                "name": "slack",
                "url": webhook_receiver,
                "format": "slack",
                "events": ["case_resolved"],
                "min_severity": "low",
            },
            {
                "name": "skip",
                "url": webhook_receiver,
                "format": "generic",
                "events": ["case_rejected"],
                "min_severity": "low",
            },
        ],
        "case_resolved",
        {
            "investigation_id": "i1",
            "platform_key": "p1",
            "severity": "high",
            "summary": "done",
        },
    )
    assert results[0]["ok"] is True
    assert results[1].get("skipped") is True
    assert any(
        (isinstance(p, dict) and ("blocks" in p or p.get("event") == "case_resolved"))
        for p in _WebhookHandler.received
    )


@pytest.mark.asyncio
async def test_m5_execute_write_http_contract():
    """FP-M5-12: HTTPProbeGatewayClient → probe-gateway kind=write body shape.

    Uses an in-process HTTP handler that mirrors dispatch's request decode.
    """
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    captured = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n))
            captured.update(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"task_id": body.get("task_id"), "exit_code": 0, "data": {"ok": True}}).encode()
            )

        def log_message(self, *a):
            return

    srv = HTTPServer(("127.0.0.1", 0), H)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        client = HTTPProbeGatewayClient(f"http://127.0.0.1:{port}")
        r = await client.execute_write(
            "p1",
            playbook_id="presto.kill_query",
            step_index=0,
            op="presto_kill_query",
            params={"query_id": "q"},
            execution_id="e1",
            signature_b64=base64.b64encode(b"s" * 64).decode(),
        )
        assert r.exit_code == 0
        assert captured["kind"] == "write"
        assert captured["op"] == "presto_kill_query"
        assert captured["control_plane_signature"]
        await client.aclose()
    finally:
        srv.shutdown()


# ---------------------------------------------------------------------------
# FP-M5-5..9,13 — closed-loop against real Temporal + Activities
# ---------------------------------------------------------------------------


async def _run_closed_loop(
    postgres_dsn,
    tmp_path,
    webhook_url,
    *,
    playbook_id="presto.kill_query",
    params=None,
    force_verify_fail=False,
    write_fail=False,
    auto_approve=True,
    settle_seconds=0,
):
    engine = __import__("sqlalchemy").create_engine(postgres_dsn)
    factory = make_session_factory(engine)
    _seed_platform(factory)
    with factory() as session:
        seed_playbooks(session)

    key_path = str(tmp_path / "ed25519.key")
    signer = bootstrap_signing_key(key_path)
    config = _make_config(webhook_url, key_path)

    probe_script = {
        "presto_cluster_info": {"exit_code": 0, "data": {"activeWorkers": 3}},
        "presto_nodes": {"exit_code": 0, "data": {"nodes": [{"nodeId": "n1"}]}},
        "presto_list_queries": {"exit_code": 0, "data": {"queries": []}},
        "presto_query_detail": {"exit_code": 0, "data": {"queryId": "2024_q1"}},
        "presto_config": {"exit_code": 0, "data": {"content": "query.max-memory=50GB\n"}},
        "presto_jmx": {"exit_code": 0, "data": {"heap": "ok"}},
        "k8s_pods": {"exit_code": 0, "data": {"pods": []}},
        "health": {"ok": True, "exit_code": 0},
        "write": {"ok": not write_fail, "exit_code": 1 if write_fail else 0, "error": "fail" if write_fail else None},
    }
    probe = FakeProbeGatewayClient(probe_script)
    llm = _llm_playbook(playbook_id, params)
    if force_verify_fail:
        # force via action flag injected after plan_remediation by wrapping LLM
        pass

    acts = InvestigationActivities(
        session_factory=factory,
        llm_client=llm,
        probe_client=probe,
        object_store=FakeObjectStore(),
        config=config,
        signer=signer,
        dashboard_base_url="http://dashboard.local",
    )

    event = {
        "source": "grafana",
        "platform_key": "presto-us1",
        "error_summary": "query stuck",
        "occurred_at": "2026-07-24T00:00:00Z",
        "severity": "high",
        "event_id": str(uuid.uuid4()),
    }
    inv = str(uuid.uuid4())

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=investigation_activity_list(acts),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {
                    "event": event,
                    "investigation_id": inv,
                    "settle_seconds": settle_seconds,
                },
                id=f"m5-{inv}",
                task_queue=TASK_QUEUE,
            )
            # Wait until approval is requested then approve.
            import asyncio

            for _ in range(200):
                desc = await handle.describe()
                # query status
                try:
                    st = await handle.query(InvestigationWorkflow.get_status)
                except Exception:  # noqa: BLE001
                    st = {}
                if (st or {}).get("status") == "AWAITING_APPROVAL" or (
                    st or {}
                ).get("awaiting_approval_id"):
                    break
                await asyncio.sleep(0.05)
            else:
                # Still try approve with a dummy if status query shape differs
                pass

            # Fetch approval_id from DB
            from sqlalchemy import select
            from rca_common.db.models import Approval

            approval_id = None
            for _ in range(100):
                with factory() as session:
                    row = session.scalars(
                        select(Approval)
                        .where(Approval.investigation_id == uuid.UUID(inv))
                        .order_by(Approval.created_at.desc())
                    ).first()
                    if row is not None:
                        approval_id = str(row.approval_id)
                        break
                await asyncio.sleep(0.05)

            if approval_id and auto_approve:
                action = {
                    "kind": "playbook",
                    "playbook_id": playbook_id,
                    "playbook_params": params or {"query_id": "2024_q1"},
                    "verification_plan": ["presto_list_queries"],
                    "settle_seconds": settle_seconds,
                    "_force_verify_fail": force_verify_fail,
                }
                # If force_verify_fail, we need the activity to see it — patch via
                # re-reading is hard; inject by updating proposed action is not
                # possible post-hoc. Instead set probe health fail:
                if force_verify_fail:
                    probe.script["health"] = {"ok": False, "exit_code": 1, "error": "canary fail"}
                await handle.signal(
                    InvestigationWorkflow.approval_decided,
                    {
                        "approval_id": approval_id,
                        "decision": "approved",
                        "comment": "ok",
                        "decided_by": str(uuid.uuid4()),
                    },
                )
            result = await handle.result()
            return result, probe, factory, inv, signer


@pytest.mark.asyncio
async def test_m5_closed_loop_e2e(postgres_dsn, tmp_path, webhook_receiver):
    """FP-M5-13 Section 12 acceptance."""
    result, probe, factory, inv, signer = await _run_closed_loop(
        postgres_dsn, tmp_path, webhook_receiver, settle_seconds=0
    )
    assert result.get("status") == "RESOLVED" or result.get("rca_report")

    with factory() as session:
        from sqlalchemy import select

        rows = list(
            session.scalars(
                select(RemediationExecution).where(
                    RemediationExecution.investigation_id == uuid.UUID(inv)
                )
            )
        )
        assert rows, "expected remediation_executions row"
        row = rows[0]
        assert row.status == "succeeded"
        assert row.pre_snapshot is not None
        assert row.verification_result is not None

        audits = list(
            session.scalars(
                select(AuditLog).where(AuditLog.investigation_id == uuid.UUID(inv))
            )
        )
        actions = {a.action for a in audits}
        assert "notification_sent" in actions
        assert "remediation_started" in actions
        assert "verification_run" in actions

    # Signed write dispatch recorded
    writes = [c for c in probe.calls if c["kind"] == "write"]
    assert writes, "expected signed write dispatch"
    w = writes[0]
    digest = canonical_step_hash(
        w["execution_id"], w["playbook_id"], w["step_index"], w["op"], w["params"]
    )
    import nacl.signing

    nacl.signing.VerifyKey(signer.public_key_bytes()).verify(
        digest, base64.b64decode(w["signature_b64"])
    )

    # Notifications: approval_requested + case_resolved (slack and/or generic)
    events = []
    for p in _WebhookHandler.received:
        if isinstance(p, dict):
            if p.get("event"):
                events.append(p["event"])
            elif p.get("blocks"):
                # slack — event is in header text
                title = p["blocks"][0]["text"]["text"]
                if "approval_requested" in title:
                    events.append("approval_requested")
                if "case_resolved" in title:
                    events.append("case_resolved")
    assert "approval_requested" in events
    assert "case_resolved" in events


@pytest.mark.asyncio
async def test_m5_pre_snapshot_captured_per_playbook(postgres_dsn, tmp_path, webhook_receiver):
    """FP-M5-5."""
    result, probe, factory, inv, _ = await _run_closed_loop(
        postgres_dsn, tmp_path, webhook_receiver
    )
    with factory() as session:
        from sqlalchemy import select

        row = session.scalars(
            select(RemediationExecution).where(
                RemediationExecution.investigation_id == uuid.UUID(inv)
            )
        ).first()
        assert row is not None
        assert row.pre_snapshot
        tools = [c["tool"] for c in probe.calls if c.get("kind") == "tool"]
        assert "presto_query_detail" in tools or "presto_list_queries" in tools


@pytest.mark.asyncio
async def test_m5_remediation_execution_row_lifecycle(postgres_dsn, tmp_path, webhook_receiver):
    """FP-M5-6."""
    _, _, factory, inv, _ = await _run_closed_loop(postgres_dsn, tmp_path, webhook_receiver)
    with factory() as session:
        from sqlalchemy import select

        row = session.scalars(
            select(RemediationExecution).where(
                RemediationExecution.investigation_id == uuid.UUID(inv)
            )
        ).first()
        assert row is not None
        assert row.mode == "approved"
        assert row.status == "succeeded"
        assert row.started_at is not None
        assert row.finished_at is not None
        pb = session.get(Playbook, row.playbook_id)
        assert pb is not None
        assert int((pb.maturity or {}).get("approved_runs") or 0) >= 1
        assert int((pb.maturity or {}).get("success") or 0) >= 1


@pytest.mark.asyncio
async def test_m5_verify_fix_union_and_canary(postgres_dsn, tmp_path, webhook_receiver):
    """FP-M5-7 pass path."""
    result, probe, factory, inv, _ = await _run_closed_loop(
        postgres_dsn, tmp_path, webhook_receiver
    )
    assert result.get("status") == "RESOLVED" or "RESOLVED" in str(result)
    health_calls = [c for c in probe.calls if c.get("kind") == "health"]
    assert health_calls, "expected canary health check"
    with factory() as session:
        from sqlalchemy import select

        row = session.scalars(
            select(RemediationExecution).where(
                RemediationExecution.investigation_id == uuid.UUID(inv)
            )
        ).first()
        assert row.verification_result and row.verification_result.get("ok") is True


@pytest.mark.asyncio
async def test_m5_verify_fix_fails_to_needs_human(postgres_dsn, tmp_path, webhook_receiver):
    """FP-M5-7 fail path."""
    result, _, _, _, _ = await _run_closed_loop(
        postgres_dsn, tmp_path, webhook_receiver, force_verify_fail=True
    )
    assert result.get("status") == "NEEDS_HUMAN" or "NEEDS_HUMAN" in str(result)


@pytest.mark.asyncio
async def test_m5_step_failure_halts_needs_human_with_rollback_note(
    postgres_dsn, tmp_path, webhook_receiver
):
    """FP-M5-9."""
    result, probe, factory, inv, _ = await _run_closed_loop(
        postgres_dsn, tmp_path, webhook_receiver, write_fail=True
    )
    assert result.get("status") == "NEEDS_HUMAN" or "NEEDS_HUMAN" in str(result)
    with factory() as session:
        from sqlalchemy import select

        row = session.scalars(
            select(RemediationExecution).where(
                RemediationExecution.investigation_id == uuid.UUID(inv)
            )
        ).first()
        assert row is not None
        assert row.status == "failed"
        assert row.verification_result
        assert "rollback" in json.dumps(row.verification_result).lower()


@pytest.mark.asyncio
async def test_m5_settle_window_timer(postgres_dsn, tmp_path, webhook_receiver):
    """FP-M5-8: durable settle timer (time-skipping advances it)."""
    # settle_seconds=2 is enough for time-skipping env to exercise sleep.
    result, _, _, _, _ = await _run_closed_loop(
        postgres_dsn, tmp_path, webhook_receiver, settle_seconds=2
    )
    assert result.get("status") == "RESOLVED" or "RESOLVED" in str(result)


@pytest.mark.asyncio
async def test_m5_settle_window_default_for_restart_playbook(
    postgres_dsn, tmp_path, webhook_receiver
):
    """FP-M5-8 / C2: no explicit settle_seconds → 120s default for restart playbooks.

    Time-skipping advances the durable timer; asserts the default path (not
    the masked action/platform override that previously always yielded 0).
    """
    from worker.playbooks import resolve_action_settle_seconds

    # Pure default resolution (guards the dead-code regression).
    assert (
        resolve_action_settle_seconds(
            {"playbook_id": "presto.restart_coordinator"},
            remediation_config={},
            input_override=None,
        )
        == 120
    )

    engine = __import__("sqlalchemy").create_engine(postgres_dsn)
    factory = make_session_factory(engine)
    # Platform without remediation.settle_seconds so playbook default applies.
    _seed_platform(
        factory,
        config={
            "remediation_targets": {
                "namespace": "presto",
                "worker_configmap": "presto-worker-config",
                "worker_workload_kind": "deployment",
                "worker_workload_name": "presto-worker",
                "coordinator_workload_kind": "deployment",
                "coordinator_workload_name": "presto-coordinator",
            },
        },
    )
    with factory() as session:
        seed_playbooks(session)

    key_path = str(tmp_path / "ed25519-default-settle.key")
    signer = bootstrap_signing_key(key_path)
    config = _make_config(webhook_receiver, key_path)
    probe = FakeProbeGatewayClient(
        {
            "presto_cluster_info": {"exit_code": 0, "data": {"activeWorkers": 3}},
            "presto_nodes": {"exit_code": 0, "data": {"nodes": [{"nodeId": "n1"}]}},
            "k8s_pods": {"exit_code": 0, "data": {"pods": []}},
            "health": {"ok": True, "exit_code": 0},
            "write": {"ok": True, "exit_code": 0},
        }
    )
    # Scripted remediation omits settle_seconds → workflow uses playbook default.
    llm = ScriptedLLM(
        {
            "planner": {
                "tool_calls": [
                    {"tool": "presto_cluster_info", "args": {}, "purpose": "state"}
                ],
                "unresolvable": [],
            },
            "collector": {
                "summary": "cluster ok",
                "notable_lines": [],
                "anomaly_detected": False,
            },
            "rca": {
                "status": "concluded",
                "confidence": 0.95,
                "root_cause": {
                    "category": "resource",
                    "summary": "gc hang",
                    "detail": "c",
                    "evidence_refs": [],
                },
                "rca_compact": "coordinator gc",
            },
            "remediation": {
                "proposed_actions": [
                    {
                        "kind": "playbook",
                        "playbook_id": "presto.restart_coordinator",
                        "risk_level": "R2",
                        "description": "restart coordinator",
                        "playbook_params": {},
                        "verification_plan": ["presto_cluster_info"],
                        "rollback_note": "manual",
                        # no settle_seconds
                    }
                ],
                "rca_compact": "coordinator gc",
            },
        }
    )
    acts = InvestigationActivities(
        session_factory=factory,
        llm_client=llm,
        probe_client=probe,
        object_store=FakeObjectStore(),
        config=config,
        signer=signer,
    )
    inv = str(uuid.uuid4())
    event = {
        "source": "grafana",
        "platform_key": "presto-us1",
        "error_summary": "gc hang",
        "occurred_at": "2026-07-24T00:00:00Z",
        "severity": "high",
        "event_id": str(uuid.uuid4()),
    }
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=investigation_activity_list(acts),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": event, "investigation_id": inv},
                id=f"m5-settle-default-{inv}",
                task_queue=TASK_QUEUE,
            )
            import asyncio
            from sqlalchemy import select
            from rca_common.db.models import Approval

            approval_id = None
            for _ in range(100):
                with factory() as session:
                    row = session.scalars(
                        select(Approval)
                        .where(Approval.investigation_id == uuid.UUID(inv))
                        .order_by(Approval.created_at.desc())
                    ).first()
                    if row is not None:
                        approval_id = str(row.approval_id)
                        break
                await asyncio.sleep(0.05)
            assert approval_id
            await handle.signal(
                InvestigationWorkflow.approval_decided,
                {
                    "approval_id": approval_id,
                    "decision": "approved",
                    "comment": "ok",
                    "decided_by": str(uuid.uuid4()),
                },
            )
            result = await handle.result()
    assert result.get("status") == "RESOLVED"


@pytest.mark.asyncio
async def test_m5_case_rejected_notification(postgres_dsn, tmp_path, webhook_receiver):
    """FP-M5-10 / W2: platform_not_ready → reject_case + case_rejected notification."""
    engine = __import__("sqlalchemy").create_engine(postgres_dsn)
    factory = make_session_factory(engine)
    from datetime import datetime, timezone

    with factory() as session:
        existing = session.get(Platform, "presto-offline")
        if existing is None:
            session.add(
                Platform(
                    platform_key="presto-offline",
                    platform_type="presto",
                    deployment="k8s",
                    display_name="offline",
                    status="offline",
                    config={},
                    created_at=datetime.now(timezone.utc),
                )
            )
        else:
            existing.status = "offline"
        session.commit()

    key_path = str(tmp_path / "ed25519-reject.key")
    signer = bootstrap_signing_key(key_path)
    config = _make_config(webhook_receiver, key_path)
    acts = InvestigationActivities(
        session_factory=factory,
        llm_client=ScriptedLLM({}),
        probe_client=FakeProbeGatewayClient(),
        object_store=FakeObjectStore(),
        config=config,
        signer=signer,
    )
    inv = str(uuid.uuid4())
    event = {
        "source": "grafana",
        "platform_key": "presto-offline",
        "error_summary": "should reject",
        "occurred_at": "2026-07-24T00:00:00Z",
        "severity": "high",
        "event_id": str(uuid.uuid4()),
    }
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=investigation_activity_list(acts),
        ):
            result = await env.client.execute_workflow(
                InvestigationWorkflow.run,
                {"event": event, "investigation_id": inv},
                id=f"m5-reject-{inv}",
                task_queue=TASK_QUEUE,
            )
    assert result.get("status") == "REJECTED"
    assert result.get("reason") == "platform_not_ready"
    events = []
    for p in _WebhookHandler.received:
        if isinstance(p, dict):
            if p.get("event") == "case_rejected":
                events.append("case_rejected")
            elif p.get("blocks"):
                title = p["blocks"][0]["text"]["text"]
                if "case_rejected" in title:
                    events.append("case_rejected")
    assert "case_rejected" in events


def test_m5_write_dispatch_signature_gate_unit():
    """FP-M5-2: re-assert writeops gate semantics (Python hash + Go gate covered in Go tests)."""
    from rca_common.signing.signer import bootstrap_signing_key
    import tempfile
    import os

    with tempfile.TemporaryDirectory() as d:
        key = os.path.join(d, "k")
        signer = bootstrap_signing_key(key)
        h1 = canonical_step_hash("e", "pb", 0, "op", {"a": 1})
        h2 = canonical_step_hash("e", "pb", 0, "op", {"a": 2})
        assert h1 != h2
        sig = signer.sign(h1)
        import nacl.signing

        nacl.signing.VerifyKey(signer.public_key_bytes()).verify(h1, sig)
        with pytest.raises(Exception):
            nacl.signing.VerifyKey(signer.public_key_bytes()).verify(h2, sig)


def test_b7_sign_verify_roundtrip_under_10ms(tmp_path):
    """B7: ed25519 sign+verify + canonical JSON < 10ms."""
    import time

    signer = bootstrap_signing_key(str(tmp_path / "k"))
    params = {"query_id": "q", "nested": {"b": 2, "a": 1}}
    # warm
    for _ in range(5):
        h = canonical_step_hash("e", "pb", 0, "presto_kill_query", params)
        sig = signer.sign(h)
        import nacl.signing

        nacl.signing.VerifyKey(signer.public_key_bytes()).verify(h, sig)
    start = time.perf_counter()
    for _ in range(50):
        h = canonical_step_hash("e", "pb", 0, "presto_kill_query", params)
        sig = signer.sign(h)
        nacl.signing.VerifyKey(signer.public_key_bytes()).verify(h, sig)
    elapsed_ms = (time.perf_counter() - start) / 50 * 1000
    assert elapsed_ms < 10.0, f"B7 round trip {elapsed_ms:.3f}ms >= 10ms"
