"""M3 functional tests (design.md Section 12 / 14.3 F1–F7, F16 + Section 13).

Wires real InvestigationWorkflow + InvestigationActivities against:
- ephemeral Postgres (migrated)
- ephemeral MinIO
- Temporal time-skipping env (unit-like) OR real local Temporal for a
  subset — here we use WorkflowEnvironment.start_time_skipping for speed
  with real Activities (not mocked), matching Section 14.3's "real
  internal components + mocked externals" bar (LLM + probe mocked).

Acceptance: injected faults (Section 13 scenarios via canned LLM/probe
fixtures) converge to a concluded RCAReport within budget.
"""
from __future__ import annotations

import json
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from rca_common.db.models import Platform
from rca_common.db.session import make_session_factory
from rca_common.fingerprint import compute_fingerprint
from rca_common.llmclient.objectstore import FakeObjectStore

import sys

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO / "services" / "gateway"))
sys.path.insert(0, str(_REPO / "services" / "worker"))
sys.path.insert(0, str(_REPO / "services" / "worker" / "tests"))

from gateway.ingest import IngestService  # noqa: E402
from worker.activities.investigation import InvestigationActivities  # noqa: E402
from worker.probeclient import FakeProbeGatewayClient  # noqa: E402
from worker.worker_main import investigation_activity_list  # noqa: E402
from worker.workflows.investigation import InvestigationWorkflow  # noqa: E402
from helpers import ScriptedLLM  # noqa: E402

TASK_QUEUE = "m3-functional"


def _seed_platform(session_factory, key="presto-us1", status="online", config=None):
    from datetime import datetime, timezone

    with session_factory() as session:
        existing = session.get(Platform, key)
        if existing is not None:
            existing.status = status
            if config is not None:
                existing.config = config
        else:
            session.add(
                Platform(
                    platform_key=key,
                    platform_type="presto",
                    deployment="k8s",
                    display_name=key,
                    status=status,
                    config=config or {},
                    created_at=datetime.now(timezone.utc),
                )
            )
        session.commit()


def _scenario_scripts(scenario: str) -> dict:
    """Canned multi-role LLM outputs for Section 13 fault scenarios."""
    concluded = {
        "worker_oom": {
            "status": "concluded",
            "confidence": 0.93,
            "root_cause": {
                "category": "resource",
                "summary": "Worker OOM due to undersized memory config",
                "detail": "Large query exceeded worker heap",
                "evidence_refs": [],
            },
            "rca_compact": "Worker OOM; propose presto.adjust_memory_config",
        },
        "coordinator_gc": {
            "status": "concluded",
            "confidence": 0.91,
            "root_cause": {
                "category": "resource",
                "summary": "Coordinator full-GC hang",
                "detail": "jmm thread dump shows GC",
                "evidence_refs": [],
            },
            "rca_compact": "Coordinator GC hang; propose presto.restart_coordinator",
        },
        "broken_catalog": {
            "status": "concluded",
            "confidence": 0.9,
            "root_cause": {
                "category": "configuration",
                "summary": "Broken hive catalog password property",
                "detail": "catalog config invalid",
                "evidence_refs": [],
            },
            "rca_compact": "Bad catalog config (secrets redacted in evidence)",
        },
        "worker_network": {
            "status": "concluded",
            "confidence": 0.9,
            "root_cause": {
                "category": "external_dependency",
                "summary": "Single worker network isolation",
                "detail": "failed node detected",
                "evidence_refs": [],
            },
            "rca_compact": "Failed worker; propose presto.restart_worker",
        },
        "queue_saturation": {
            "status": "concluded",
            "confidence": 0.9,
            "root_cause": {
                "category": "capacity",
                "summary": "Query queue saturation at concurrency limit",
                "detail": "queued > threshold",
                "evidence_refs": [],
            },
            "rca_compact": "Capacity: raise concurrency limit",
        },
        "runaway_query": {
            "status": "concluded",
            "confidence": 0.94,
            "root_cause": {
                "category": "resource",
                "summary": "Runaway query exhausting memory pool",
                "detail": "query_id=20260711_q1",
                "evidence_refs": [],
            },
            "rca_compact": "Kill runaway query 20260711_q1",
        },
    }[scenario]

    playbook = {
        "worker_oom": "presto.adjust_memory_config",
        "coordinator_gc": "presto.restart_coordinator",
        "broken_catalog": None,  # manual
        "worker_network": "presto.restart_worker",
        "queue_saturation": None,
        "runaway_query": "presto.kill_query",
    }[scenario]

    if playbook:
        remediation = {
            "proposed_actions": [
                {
                    "kind": "playbook",
                    "playbook_id": playbook,
                    "risk_level": "R1" if playbook == "presto.kill_query" else "R2",
                    "description": f"run {playbook}",
                    "playbook_params": {"query_id": "20260711_q1"} if playbook == "presto.kill_query" else {},
                    "verification_plan": ["presto_cluster_info"],
                    "description_compact": f"Apply {playbook}",
                }
            ],
            "rca_compact": concluded["rca_compact"],
        }
    else:
        remediation = {
            "proposed_actions": [
                {
                    "kind": "manual_recommendation",
                    "risk_level": "R0",
                    "description": "operator action required",
                    "description_compact": "manual fix",
                }
            ],
            "rca_compact": concluded["rca_compact"],
        }

    return {
        "planner": {
            "tool_calls": [
                {"tool": "presto_cluster_info", "args": {}, "purpose": "cluster"},
                {"tool": "presto_nodes", "args": {}, "purpose": "nodes"},
                {"tool": "presto_list_queries", "args": {}, "purpose": "queries"},
            ],
            "unresolvable": [],
        },
        "collector": {
            "summary": f"fixture summary for {scenario}",
            "notable_lines": ["anomaly"],
            "anomaly_detected": True,
        },
        "rca": concluded,
        "remediation": remediation,
    }


def _probe_script(scenario: str) -> dict:
    return {
        "presto_cluster_info": {"exit_code": 0, "data": {"activeWorkers": 3, "scenario": scenario}},
        "presto_nodes": {
            "exit_code": 0,
            "data": {
                "nodes": [{"id": "w1", "state": "failed" if scenario == "worker_network" else "active"}]
            },
        },
        "presto_list_queries": {
            "exit_code": 0,
            "data": {
                "queries": [
                    {"queryId": "20260711_q1", "state": "RUNNING", "memory": "huge"}
                ]
            },
        },
        "presto_config": {
            "exit_code": 0,
            "redacted": True,
            "data": {"hive.password": "***REDACTED***"},
        },
        "jvm_thread_dump": {"exit_code": 0, "data": {"dump": "Full GC"}},
        "presto_jmx": {"exit_code": 0, "data": {"heap": {"used": 0.95}}},
    }


def _pending_approval_id(session_factory) -> str | None:
    """Latest undecided approval id (mirrors dashboard list_approvals pending).

    Required by the M4 awaited-approval-id gate on InvestigationWorkflow:
    signals without a matching approval_id are ignored, so functional auto-
    approve must pass the real row id exactly as production does.
    """
    with session_factory() as session:
        row = session.execute(
            text(
                "SELECT approval_id FROM approvals "
                "WHERE decision IS NULL "
                "ORDER BY created_at DESC LIMIT 1"
            )
        ).fetchone()
    return str(row[0]) if row else None


async def _signal_approval(
    handle,
    session_factory,
    *,
    decision: str,
    comment: str,
) -> bool:
    """Signal approval_decided with the pending approval's id. Returns True if sent."""
    approval_id = _pending_approval_id(session_factory)
    if not approval_id:
        return False
    await handle.signal(
        InvestigationWorkflow.approval_decided,
        {"approval_id": approval_id, "decision": decision, "comment": comment},
    )
    return True


async def _run_investigation(session_factory, scenario: str, auto_approve: bool = True):
    llm = ScriptedLLM(_scenario_scripts(scenario))
    probe = FakeProbeGatewayClient(_probe_script(scenario))
    store = FakeObjectStore()
    acts = InvestigationActivities(
        session_factory=session_factory,
        llm_client=llm,
        probe_client=probe,
        object_store=store,
        config=None,
    )
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "manual",
        "platform_key": "presto-us1",
        "error_summary": f"fault:{scenario}",
        "occurred_at": "2026-07-11T00:00:00Z",
        "severity": "high",
        "fingerprint": compute_fingerprint("presto-us1", f"fault:{scenario}"),
    }
    inv_id = str(uuid.uuid4())

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=investigation_activity_list(acts),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": event, "investigation_id": inv_id},
                id=f"m3-{scenario}-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            if auto_approve:
                # Approve any pending approvals as they appear (with matching id).
                for _ in range(100):
                    status = await handle.query(InvestigationWorkflow.get_status)
                    if status["status"] in ("RESOLVED", "CLOSED_SUMMARY", "NEEDS_HUMAN", "REJECTED"):
                        break
                    if status["status"] == "AWAITING_APPROVAL":
                        await _signal_approval(
                            handle,
                            session_factory,
                            decision="approved",
                            comment="functional auto",
                        )
                    await env.sleep(timedelta(milliseconds=50))
            result = await handle.result()
    return result, llm, probe


@pytest.fixture
def m3_session_factory(postgres_dsn):
    engine = create_engine(postgres_dsn)
    factory = make_session_factory(engine)
    _seed_platform(factory)
    return factory


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scenario",
    [
        "worker_oom",
        "coordinator_gc",
        "broken_catalog",
        "worker_network",
        "queue_saturation",
        "runaway_query",
    ],
)
async def test_section13_fault_converges_to_concluded(m3_session_factory, scenario):
    """M3 acceptance: each Section 13 injected fault yields concluded RCA within budget."""
    result, llm, probe = await _run_investigation(m3_session_factory, scenario)
    assert result["status"] in ("RESOLVED", "CLOSED_SUMMARY")
    report = result.get("rca_report") or {}
    assert report.get("status") == "concluded"
    assert float(report.get("confidence") or 0) >= 0.85
    assert any(c.get("agent_role") == "rca" for c in llm.calls)
    assert probe.calls  # collector hit the fake probe


@pytest.mark.asyncio
async def test_f3_multi_round_loop(m3_session_factory):
    scripts = _scenario_scripts("worker_oom")
    scripts["rca"] = [
        {
            "status": "need_more_data",
            "confidence": 0.4,
            "missing_info": [{"what": "thread dump", "why": "confirm GC", "suggested_tools": ["jvm_thread_dump"]}],
        },
        {
            "status": "concluded",
            "confidence": 0.92,
            "root_cause": {"category": "resource", "summary": "oom"},
            "rca_compact": "oom after follow-up",
        },
    ]
    scripts["planner"] = {
        "tool_calls": [{"tool": "presto_cluster_info", "args": {}, "purpose": "s"}],
        "unresolvable": [],
    }
    scripts["remediation"] = {
        "proposed_actions": [
            {"kind": "ignore", "risk_level": "R0", "description": "done"}
        ],
        "rca_compact": "oom after follow-up",
    }
    llm = ScriptedLLM(scripts)
    probe = FakeProbeGatewayClient(_probe_script("worker_oom"))
    acts = InvestigationActivities(
        session_factory=m3_session_factory,
        llm_client=llm,
        probe_client=probe,
        object_store=FakeObjectStore(),
    )
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "manual",
        "platform_key": "presto-us1",
        "error_summary": "multi-round",
        "occurred_at": "2026-07-11T00:00:00Z",
        "fingerprint": compute_fingerprint("presto-us1", "multi-round"),
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
                {"event": event, "investigation_id": str(uuid.uuid4())},
                id=f"m3-multi-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
    assert result["status"] == "CLOSED_SUMMARY"
    assert result["rca_report"]["status"] == "concluded"
    # Two analyze rounds.
    assert sum(1 for c in llm.calls if c["agent_role"] == "rca") == 2


@pytest.mark.asyncio
async def test_f1_ingest_merge_and_reject(m3_session_factory, postgres_dsn):
    """F1: open + merge + platform_not_ready without Temporal start."""
    starter_calls = []

    class Starter:
        async def start_investigation(self, event, investigation_id):
            starter_calls.append(investigation_id)
            return f"investigation-{investigation_id}"

    svc = IngestService(
        m3_session_factory,
        budget_defaults={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        known_sources={"grafana-prod": "sec", "manual": "sec"},
        correlation_window_seconds=1800,
        workflow_starter=Starter(),
    )
    raw = {
        "source": "grafana-prod",
        "platform_key": "presto-us1",
        "error_summary": "Worker OOM killed",
        "occurred_at": "2026-07-11T00:00:00Z",
        "severity": "critical",
    }
    code, body = await svc.ingest(raw)
    assert code == 202
    inv = body["investigation_id"]
    assert len(starter_calls) == 1

    code2, body2 = await svc.ingest(raw)
    assert code2 == 200
    assert body2["status"] == "merged"
    assert body2["investigation_id"] == inv
    assert len(starter_calls) == 1  # no new workflow

    # Offline platform rejects.
    with m3_session_factory() as session:
        session.execute(
            text("UPDATE platforms SET status='offline' WHERE platform_key='presto-us1'")
        )
        session.commit()
    code3, body3 = await svc.ingest({**raw, "error_summary": "other"})
    assert body3["status"] == "rejected"
    assert body3["reason"] == "platform_not_ready"


# Audit actions that M3 code paths can emit (design.md Section 4.3 enum).
# Out of M3 reach (F16 partial note): notification_sent (M5/F13);
# credentials_detected / credentials_verified / credentials_test_failed (M2).
_M3_AUDIT_ACTIONS = {
    "event_received",
    "event_merged",
    "event_rejected",
    "case_opened",
    "round_started",
    "task_dispatched",
    "tool_executed",
    "raw_cmd_requested",
    "raw_cmd_approved",
    "raw_cmd_denied",
    "rca_produced",
    "budget_exceeded",
    "remediation_proposed",
    "approval_requested",
    "approval_decided",
    "remediation_started",
    "remediation_finished",
    "verification_run",
    "case_closed",
}

_ACTOR_RE = __import__("re").compile(
    r"^(system|agent:[A-Za-z0-9_-]+|user:[^\s]+|probe:[^\s]+)$"
)


@pytest.mark.asyncio
async def test_f16_audit_actions_emitted(m3_session_factory, postgres_dsn):
    """F16: every M3-emittable audit action is emitted at its trigger; actors valid.

    Walks multiple M3 paths (happy playbook, ingest merge/reject, cost budget,
    raw-command approve + deny) and asserts the closed M3 subset of the audit
    enum plus actor-field convention (system / agent:<role> / user:<id> /
    probe:<id>). Out-of-reach enums are documented as partial in checkpoints.yaml.
    """
    seen: dict[str, set[str]] = {}  # action -> set of actors

    def _collect():
        with m3_session_factory() as session:
            rows = session.execute(text("SELECT action, actor FROM audit_log")).fetchall()
        for action, actor in rows:
            seen.setdefault(action, set()).add(actor)

    # --- path 1: happy playbook → RESOLVED (core investigation + remediation) ---
    result, _, _ = await _run_investigation(
        m3_session_factory, "runaway_query", auto_approve=True
    )
    assert result["status"] == "RESOLVED"
    _collect()

    # --- path 2: ingest open + merge + platform_not_ready reject ---
    starter_calls: list = []

    class Starter:
        async def start_investigation(self, event, investigation_id):
            starter_calls.append(investigation_id)
            return f"investigation-{investigation_id}"

    svc = IngestService(
        m3_session_factory,
        budget_defaults={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        known_sources={"grafana-prod": "sec", "manual": "sec"},
        correlation_window_seconds=1800,
        workflow_starter=Starter(),
    )
    raw = {
        "source": "grafana-prod",
        "platform_key": "presto-us1",
        "error_summary": "F16 audit storm",
        "occurred_at": "2026-07-11T00:00:00Z",
        "severity": "critical",
    }
    await svc.ingest(raw)
    await svc.ingest(raw)  # merge
    with m3_session_factory() as session:
        session.execute(
            text("UPDATE platforms SET status='offline' WHERE platform_key='presto-us1'")
        )
        session.commit()
    await svc.ingest({**raw, "error_summary": "F16 other fingerprint"})
    with m3_session_factory() as session:
        session.execute(
            text("UPDATE platforms SET status='online' WHERE platform_key='presto-us1'")
        )
        session.commit()
    _collect()

    # --- path 3: cost budget → budget_exceeded ---
    scripts = _scenario_scripts("worker_oom")
    scripts["rca"] = {
        "status": "need_more_data",
        "confidence": 0.3,
        "missing_info": [{"what": "more", "why": "need"}],
    }
    # Force an already-spent investigation via a pre-seeded llm_calls row is
    # heavier than needed; use a tiny max_cost_usd platform override + a
    # ScriptedLLM that records spend via the real activity get_spend path.
    # Simpler: drive workflow unit-style with InvestigationActivities and
    # a budget that trips after the first model calls accumulate — or set
    # platform budget max_cost_usd extremely low and let create_case pick it up.
    with m3_session_factory() as session:
        session.execute(
            text(
                "UPDATE platforms SET config = CAST(:cfg AS jsonb) WHERE platform_key='presto-us1'"
            ),
            {
                "cfg": json.dumps(
                    {
                        "budget": {
                            "max_rounds": 10,
                            "max_cost_usd": 0.0,
                            "max_wall_seconds": 3600,
                        }
                    }
                )
            },
        )
        session.commit()
    llm = ScriptedLLM(scripts)
    acts = InvestigationActivities(
        session_factory=m3_session_factory,
        llm_client=llm,
        probe_client=FakeProbeGatewayClient(_probe_script("worker_oom")),
        object_store=FakeObjectStore(),
    )
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "manual",
        "platform_key": "presto-us1",
        "error_summary": "f16-budget",
        "occurred_at": "2026-07-11T00:00:00Z",
        "fingerprint": compute_fingerprint("presto-us1", "f16-budget"),
    }
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=investigation_activity_list(acts),
        ):
            budget_result = await env.client.execute_workflow(
                InvestigationWorkflow.run,
                {"event": event, "investigation_id": str(uuid.uuid4())},
                id=f"m3-f16-budget-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
    assert budget_result["status"] == "NEEDS_HUMAN"
    assert budget_result["reason"] == "cost_budget"
    # reset platform budget for remaining paths
    with m3_session_factory() as session:
        session.execute(
            text(
                "UPDATE platforms SET config = CAST(:cfg AS jsonb) WHERE platform_key='presto-us1'"
            ),
            {"cfg": json.dumps({})},
        )
        session.commit()
    _collect()

    # --- path 4: raw-command approve + deny (raw_cmd_* + approval_*) ---
    scripts = _scenario_scripts("worker_oom")
    scripts["rca"] = {
        "status": "concluded",
        "confidence": 0.95,
        "root_cause": {"category": "resource", "summary": "oom"},
        "rca_compact": "oom",
        "raw_command_requests": [
            {"command": "cat /etc/presto/config.properties", "purpose": "read config"},
        ],
    }
    scripts["remediation"] = {
        "proposed_actions": [
            {"kind": "ignore", "risk_level": "R0", "description": "n/a"}
        ],
        "rca_compact": "oom",
    }
    llm = ScriptedLLM(scripts)
    acts = InvestigationActivities(
        session_factory=m3_session_factory,
        llm_client=llm,
        probe_client=FakeProbeGatewayClient(_probe_script("worker_oom")),
        object_store=FakeObjectStore(),
    )
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "manual",
        "platform_key": "presto-us1",
        "error_summary": "f16-rawcmd-approve",
        "occurred_at": "2026-07-11T00:00:00Z",
        "fingerprint": compute_fingerprint("presto-us1", "f16-rawcmd-approve"),
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
                {"event": event, "investigation_id": str(uuid.uuid4())},
                id=f"m3-f16-raw-ok-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            for _ in range(100):
                status = await handle.query(InvestigationWorkflow.get_status)
                if status["status"] in ("RESOLVED", "CLOSED_SUMMARY", "NEEDS_HUMAN"):
                    break
                if status["status"] == "AWAITING_APPROVAL":
                    await _signal_approval(
                        handle,
                        m3_session_factory,
                        decision="approved",
                        comment="f16 raw ok",
                    )
                await env.sleep(timedelta(milliseconds=50))
            await handle.result()
    _collect()

    # Deny path for raw_cmd_denied.
    scripts = _scenario_scripts("worker_oom")
    scripts["rca"] = {
        "status": "concluded",
        "confidence": 0.95,
        "root_cause": {"category": "resource", "summary": "oom"},
        "rca_compact": "oom",
        "raw_command_requests": [
            {"command": "cat /etc/presto/node.properties", "purpose": "read node"},
        ],
    }
    scripts["remediation"] = {
        "proposed_actions": [
            {"kind": "ignore", "risk_level": "R0", "description": "n/a"}
        ],
        "rca_compact": "oom",
    }
    llm = ScriptedLLM(scripts)
    acts = InvestigationActivities(
        session_factory=m3_session_factory,
        llm_client=llm,
        probe_client=FakeProbeGatewayClient(_probe_script("worker_oom")),
        object_store=FakeObjectStore(),
    )
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "manual",
        "platform_key": "presto-us1",
        "error_summary": "f16-rawcmd-deny",
        "occurred_at": "2026-07-11T00:00:00Z",
        "fingerprint": compute_fingerprint("presto-us1", "f16-rawcmd-deny"),
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
                {"event": event, "investigation_id": str(uuid.uuid4())},
                id=f"m3-f16-raw-deny-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            for _ in range(100):
                status = await handle.query(InvestigationWorkflow.get_status)
                if status["status"] in ("RESOLVED", "CLOSED_SUMMARY", "NEEDS_HUMAN"):
                    break
                if status["status"] == "AWAITING_APPROVAL":
                    await _signal_approval(
                        handle,
                        m3_session_factory,
                        decision="denied",
                        comment="f16 raw deny",
                    )
                await env.sleep(timedelta(milliseconds=50))
            await handle.result()
    _collect()

    # --- assertions ---
    missing = _M3_AUDIT_ACTIONS - set(seen)
    assert not missing, f"F16 missing M3 audit actions: {sorted(missing)}; have {sorted(seen)}"

    # Actor field correctness for every emitted row we care about.
    for action, actors in seen.items():
        for actor in actors:
            assert _ACTOR_RE.match(actor), (
                f"F16 actor {actor!r} for action {action!r} does not match "
                f"system|agent:<role>|user:<id>|probe:<id>"
            )

    # Spot-check role-specific actors that M3 code assigns (Section 14.3).
    assert "system" in seen.get("case_opened", set())
    assert any(a.startswith("agent:collector") for a in seen.get("round_started", set()))
    assert any(a.startswith("agent:collector") for a in seen.get("task_dispatched", set()))
    assert any(a.startswith("agent:collector") for a in seen.get("tool_executed", set()))
    assert any(a.startswith("agent:rca") for a in seen.get("rca_produced", set()))
    assert any(a.startswith("agent:remediation") for a in seen.get("remediation_proposed", set()))
    assert "system" in seen.get("case_closed", set())
    assert "system" in seen.get("event_received", set())
    assert "system" in seen.get("approval_requested", set())


@pytest.mark.asyncio
async def test_f4_platform_budget_override(m3_session_factory):
    """Per-platform budget override: max_rounds=1 forces NEEDS_HUMAN/round_budget when not concluding."""
    with m3_session_factory() as session:
        session.execute(
            text(
                "UPDATE platforms SET config = CAST(:cfg AS jsonb) WHERE platform_key='presto-us1'"
            ),
            {"cfg": json.dumps({"budget": {"max_rounds": 1, "max_cost_usd": 100.0, "max_wall_seconds": 3600}})},
        )
        session.commit()

    scripts = _scenario_scripts("worker_oom")
    scripts["rca"] = {
        "status": "need_more_data",
        "confidence": 0.3,
        "missing_info": [{"what": "more", "why": "need"}],
    }
    llm = ScriptedLLM(scripts)
    acts = InvestigationActivities(
        session_factory=m3_session_factory,
        llm_client=llm,
        probe_client=FakeProbeGatewayClient(_probe_script("worker_oom")),
        object_store=FakeObjectStore(),
    )
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "manual",
        "platform_key": "presto-us1",
        "error_summary": "budget-test",
        "occurred_at": "2026-07-11T00:00:00Z",
        "fingerprint": compute_fingerprint("presto-us1", "budget-test"),
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
                {"event": event, "investigation_id": str(uuid.uuid4())},
                id=f"m3-budget-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "round_budget"
