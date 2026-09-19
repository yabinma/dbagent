"""Unit-tier InvestigationWorkflow tests (design.md Section 14.2).

All Activities are real InvestigationActivities bound to fakes (ScriptedLLM,
FakeProbeGatewayClient, in-memory sqlite is NOT used — we use a lightweight
session factory backed by the real models via a dict-store session OR
SQLAlchemy sqlite where JSONB isn't available).

For workflow unit tests we mock Activities at the Temporal level with
simple async functions that mirror the state machine contract — this
matches Section 14.2 ("All Activities mocked; Temporal's time-skipping
WorkflowEnvironment") and keeps the tests focused on every state-machine
transition, budget dimension, confidence threshold, approval timeout, and
round exhaustion.
"""
from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

import pytest
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from worker.workflows.investigation import InvestigationWorkflow

TASK_QUEUE = "test-investigation"


def _event(**overrides) -> dict[str, Any]:
    base = {
        "event_id": str(uuid.uuid4()),
        "source": "grafana-prod",
        "platform_key": "presto-us1",
        "error_summary": "worker oom",
        "occurred_at": "2026-07-11T00:00:00Z",
        "severity": "high",
        "fingerprint": "abc",
    }
    base.update(overrides)
    return base


class ActivityScript:
    """Configurable activity doubles for InvestigationWorkflow."""

    def __init__(self):
        self.budget = {"max_rounds": 5, "max_cost_usd": 10.0, "max_wall_seconds": 1800}
        self.spend = 0.0
        self.plans = [
            {"tool_calls": [{"tool": "presto_cluster_info", "args": {}, "purpose": "state"}], "unresolvable": []}
        ]
        # list of reports per round; last may be concluded
        self.reports = [
            {
                "status": "concluded",
                "confidence": 0.95,
                "root_cause": {"category": "resource", "summary": "oom"},
                "rca_compact": "oom on worker",
                "proposed_actions": [],
            }
        ]
        self.remediation = {
            "proposed_actions": [
                {
                    "kind": "ignore",
                    "risk_level": "R0",
                    "description": "transient",
                }
            ],
            "rca_compact": "oom on worker",
        }
        self.verify_ok = True
        self.playbook_ok = True
        self.raw_validate_ok = True
        self.collect_calls = 0
        self.analyze_calls = 0
        self.approvals: list[dict] = []
        self.closed: list[str] = []
        self.notifications: list[dict] = []
        self.rejected = False
        self.reject_reason: str | None = None
        self.remediation_config: dict = {}
        self.settle_slept: list[int] = []

    def bind(self):
        script = self

        @activity.defn(name="create_case")
        async def create_case(payload: dict) -> dict:
            out = {
                "investigation_id": payload.get("investigation_id") or str(uuid.uuid4()),
                "platform_key": payload["event"]["platform_key"],
                "budget": dict(script.budget),
                "confidence_threshold": 0.85,
                "max_calls_per_round": 8,
                "deployment": "k8s",
                "remediation": dict(script.remediation_config or {}),
                "rejected": bool(script.rejected),
                "reject_reason": script.reject_reason,
            }
            return out

        @activity.defn(name="get_spend")
        async def get_spend(payload: dict) -> float:
            return float(script.spend)

        @activity.defn(name="plan_initial")
        async def plan_initial(payload: dict) -> dict:
            return script.plans[0]

        @activity.defn(name="plan_next")
        async def plan_next(payload: dict) -> dict:
            return script.plans[min(len(script.plans) - 1, 0)]

        @activity.defn(name="collect")
        async def collect(payload: dict) -> list:
            script.collect_calls += 1
            return [
                {
                    "evidence_id": str(uuid.uuid4()),
                    "tool_name": "presto_cluster_info",
                    "round": payload["round"],
                    "summary": "cluster ok",
                    "payload": {"nodes": 3},
                }
            ]

        @activity.defn(name="analyze")
        async def analyze(payload: dict) -> dict:
            script.analyze_calls += 1
            idx = min(script.analyze_calls - 1, len(script.reports) - 1)
            return dict(script.reports[idx])

        @activity.defn(name="record_iteration")
        async def record_iteration(payload: dict) -> None:
            return None

        @activity.defn(name="static_validate_raw_command")
        async def static_validate_raw_command(payload: dict) -> dict:
            return {"ok": script.raw_validate_ok, "reason": "", "command": payload.get("command")}

        @activity.defn(name="run_raw_command")
        async def run_raw_command(payload: dict) -> list:
            return [
                {
                    "evidence_id": str(uuid.uuid4()),
                    "tool_name": "raw_command",
                    "round": payload.get("round"),
                    "summary": "raw out",
                    "payload": {"ok": True},
                }
            ]

        @activity.defn(name="create_approval")
        async def create_approval(payload: dict) -> dict:
            aid = str(uuid.uuid4())
            script.approvals.append({"id": aid, **payload})
            return {"approval_id": aid, "kind": payload["kind"]}

        @activity.defn(name="record_approval_decision")
        async def record_approval_decision(payload: dict) -> None:
            return None

        @activity.defn(name="plan_remediation")
        async def plan_remediation(payload: dict) -> dict:
            return dict(script.remediation)

        @activity.defn(name="execute_playbook")
        async def execute_playbook(payload: dict) -> dict:
            return {"ok": script.playbook_ok, "playbook_id": payload.get("action", {}).get("playbook_id")}

        @activity.defn(name="verify_fix")
        async def verify_fix(payload: dict) -> dict:
            if payload.get("force_fail"):
                return {"ok": False, "plan": payload.get("verification_plan")}
            return {"ok": script.verify_ok, "plan": payload.get("verification_plan")}

        @activity.defn(name="send_notifications")
        async def send_notifications(payload: dict) -> dict:
            script.notifications.append(payload)
            return {"ok": True, "results": []}

        @activity.defn(name="close_with_summary")
        async def close_with_summary(payload: dict) -> dict:
            script.closed.append("CLOSED_SUMMARY")
            return {"status": "CLOSED_SUMMARY"}

        @activity.defn(name="close_resolved")
        async def close_resolved(payload: dict) -> dict:
            script.closed.append("RESOLVED")
            return {"status": "RESOLVED"}

        @activity.defn(name="to_needs_human")
        async def to_needs_human(payload: dict) -> dict:
            script.closed.append(f"NEEDS_HUMAN:{payload.get('reason')}")
            return {"status": "NEEDS_HUMAN", "reason": payload.get("reason")}

        @activity.defn(name="reject_case")
        async def reject_case(payload: dict) -> dict:
            script.closed.append("REJECTED")
            return {"status": "REJECTED", "reason": payload.get("reason")}

        return [
            create_case,
            get_spend,
            plan_initial,
            plan_next,
            collect,
            analyze,
            record_iteration,
            static_validate_raw_command,
            run_raw_command,
            create_approval,
            record_approval_decision,
            plan_remediation,
            execute_playbook,
            verify_fix,
            send_notifications,
            close_with_summary,
            close_resolved,
            to_needs_human,
            reject_case,
        ]


async def _run(script: ActivityScript, event=None, investigation_id=None, signals=None):
    event = event or _event()
    inv = investigation_id or str(uuid.uuid4())
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": event, "investigation_id": inv},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            if signals:
                for sig in signals:
                    await sig(handle)
            result = await handle.result()
            status = await handle.query(InvestigationWorkflow.get_status)
            return result, status


@pytest.mark.asyncio
async def test_happy_path_ignore_closes_summary():
    script = ActivityScript()
    result, status = await _run(script)
    assert result["status"] == "CLOSED_SUMMARY"
    assert status["status"] == "CLOSED_SUMMARY"
    assert script.analyze_calls == 1


@pytest.mark.asyncio
async def test_happy_path_playbook_resolved():
    script = ActivityScript()
    script.remediation = {
        "proposed_actions": [
            {
                "kind": "playbook",
                "playbook_id": "presto.kill_query",
                "risk_level": "R1",
                "description": "kill runaway",
                "playbook_params": {"query_id": "q1"},
                "verification_plan": ["presto_list_queries"],
            }
        ],
        "rca_compact": "runaway query",
    }
    # Auto-approve via signal shortly after start: use a concurrent signal task.
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )

            # Poll until an approval is requested, then approve.
            for _ in range(50):
                await env.sleep(timedelta(seconds=1))
                if script.approvals:
                    await handle.signal(
                        InvestigationWorkflow.approval_decided,
                        {
                            "approval_id": script.approvals[-1]["id"],
                            "decision": "approved",
                        },
                    )
                    break
            result = await handle.result()
    assert result["status"] == "RESOLVED"


@pytest.mark.asyncio
async def test_round_budget_exhaustion():
    script = ActivityScript()
    script.budget = {"max_rounds": 2, "max_cost_usd": 100.0, "max_wall_seconds": 3600}
    script.reports = [
        {"status": "need_more_data", "confidence": 0.4, "missing_info": [{"what": "logs", "why": "need"}]},
        {"status": "need_more_data", "confidence": 0.5, "missing_info": [{"what": "jmx", "why": "need"}]},
    ]
    result, _ = await _run(script)
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "round_budget"


@pytest.mark.asyncio
async def test_cost_budget():
    script = ActivityScript()
    script.budget = {"max_rounds": 10, "max_cost_usd": 0.5, "max_wall_seconds": 3600}
    script.spend = 1.0
    result, _ = await _run(script)
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "cost_budget"


@pytest.mark.asyncio
async def test_time_budget():
    script = ActivityScript()
    script.budget = {"max_rounds": 10, "max_cost_usd": 100.0, "max_wall_seconds": 0}
    result, _ = await _run(script)
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "time_budget"


@pytest.mark.asyncio
async def test_inconclusive_no_path():
    script = ActivityScript()
    script.reports = [{"status": "inconclusive", "confidence": 0.2, "missing_info": []}]
    result, _ = await _run(script)
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "inconclusive"


@pytest.mark.asyncio
async def test_confidence_threshold_blocks_early_conclude():
    script = ActivityScript()
    script.budget = {"max_rounds": 3, "max_cost_usd": 100.0, "max_wall_seconds": 3600}
    script.reports = [
        {"status": "concluded", "confidence": 0.5, "missing_info": [{"what": "x", "why": "y"}]},
        {"status": "concluded", "confidence": 0.5, "missing_info": [{"what": "x", "why": "y"}]},
        {"status": "concluded", "confidence": 0.5, "missing_info": [{"what": "x", "why": "y"}]},
    ]
    result, _ = await _run(script)
    # Never reaches threshold → round budget
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "round_budget"


@pytest.mark.asyncio
async def test_multi_round_need_more_data_then_conclude():
    script = ActivityScript()
    script.budget = {"max_rounds": 5, "max_cost_usd": 100.0, "max_wall_seconds": 3600}
    script.reports = [
        {"status": "need_more_data", "confidence": 0.4, "missing_info": [{"what": "logs", "why": "oom"}]},
        {
            "status": "concluded",
            "confidence": 0.92,
            "root_cause": {"category": "resource", "summary": "oom"},
            "rca_compact": "oom",
        },
    ]
    result, _ = await _run(script)
    assert result["status"] == "CLOSED_SUMMARY"
    assert script.analyze_calls == 2
    assert script.collect_calls == 2


@pytest.mark.asyncio
async def test_raw_command_validator_reject_skips_approval():
    script = ActivityScript()
    script.raw_validate_ok = False
    script.reports = [
        {
            "status": "concluded",
            "confidence": 0.95,
            "raw_command_requests": [
                {"command": "rm -rf /", "justification": "no", "expected_evidence": "x"}
            ],
            "rca_compact": "x",
        }
    ]
    result, _ = await _run(script)
    assert result["status"] == "CLOSED_SUMMARY"
    assert script.approvals == []


@pytest.mark.asyncio
async def test_raw_command_approval_timeout_denied():
    script = ActivityScript()
    script.reports = [
        {
            "status": "concluded",
            "confidence": 0.95,
            "raw_command_requests": [
                {
                    "command": "cat /etc/presto/config.properties",
                    "justification": "need config",
                    "expected_evidence": "props",
                }
            ],
            "rca_compact": "x",
        }
    ]
    # Do not send approval signal → 24h timeout (time-skipping advances).
    result, _ = await _run(script)
    assert result["status"] == "CLOSED_SUMMARY"
    assert len(script.approvals) == 1


@pytest.mark.asyncio
async def test_verification_failed_needs_human():
    script = ActivityScript()
    script.verify_ok = False
    script.remediation = {
        "proposed_actions": [
            {
                "kind": "playbook",
                "playbook_id": "presto.restart_coordinator",
                "risk_level": "R2",
                "description": "restart",
                "verification_plan": ["presto_cluster_info"],
            }
        ]
    }
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            for _ in range(50):
                await env.sleep(timedelta(seconds=1))
                if script.approvals:
                    await handle.signal(
                        InvestigationWorkflow.approval_decided,
                        {"approval_id": script.approvals[-1]["id"], "decision": "approved"},
                    )
                    break
            result = await handle.result()
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "verification_failed"


@pytest.mark.asyncio
async def test_deny_remediation_closes_with_summary_if_no_approved_playbooks():
    """Denying the only playbook: close_with_summary → CLOSED_SUMMARY (design.md v1.8).

    Section 5.1/5.2 `executed_any` gate: RESOLVED only when at least one
    playbook was approved+executed+verified; deny of every playbook is
    CLOSED_SUMMARY (never misreport as RESOLVED).
    """
    script = ActivityScript()
    script.remediation = {
        "proposed_actions": [
            {
                "kind": "playbook",
                "playbook_id": "presto.restart_worker",
                "risk_level": "R2",
                "description": "restart worker",
            }
        ]
    }
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            for _ in range(50):
                await env.sleep(timedelta(seconds=1))
                if script.approvals:
                    await handle.signal(
                        InvestigationWorkflow.approval_decided,
                        {"approval_id": script.approvals[-1]["id"], "decision": "denied"},
                    )
                    break
            result = await handle.result()
    assert result["status"] == "CLOSED_SUMMARY"


@pytest.mark.asyncio
async def test_abort_signal():
    script = ActivityScript()
    script.reports = [
        {"status": "need_more_data", "confidence": 0.4, "missing_info": [{"what": "x", "why": "y"}]},
        {"status": "need_more_data", "confidence": 0.4, "missing_info": [{"what": "x", "why": "y"}]},
    ]
    script.budget = {"max_rounds": 10, "max_cost_usd": 100.0, "max_wall_seconds": 3600}

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            await handle.signal(InvestigationWorkflow.abort)
            result = await handle.result()
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "aborted"


@pytest.mark.asyncio
async def test_pause_resume_signal():
    """F6: pause freezes the round loop; resume lets it complete."""
    script = ActivityScript()
    script.reports = [
        {
            "status": "need_more_data",
            "confidence": 0.4,
            "missing_info": [{"what": "x", "why": "y"}],
        },
        {
            "status": "concluded",
            "confidence": 0.95,
            "rca_compact": "done after resume",
        },
    ]
    script.budget = {"max_rounds": 10, "max_cost_usd": 100.0, "max_wall_seconds": 3600}
    script.remediation = {
        "proposed_actions": [{"kind": "ignore", "risk_level": "R0", "description": "n/a"}],
        "rca_compact": "done after resume",
    }

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            await handle.signal(InvestigationWorkflow.pause)
            # Give the workflow a chance to observe pause and block in _wait_if_paused.
            await env.sleep(timedelta(seconds=1))
            status = await handle.query(InvestigationWorkflow.get_status)
            assert status["paused"] is True
            assert status["status"] not in ("RESOLVED", "CLOSED_SUMMARY", "NEEDS_HUMAN")
            await handle.signal(InvestigationWorkflow.resume)
            result = await handle.result()
    assert result["status"] == "CLOSED_SUMMARY"


@pytest.mark.asyncio
async def test_adjust_budget_signal():
    """F6: adjust_budget tightens max_cost_usd mid-flight → cost_budget NEEDS_HUMAN.

    The signal handler stores an override that is applied at the top of the
    next round (design.md Section 5.1 control signals). We use the cost
    dimension because it is re-checked every round against the live override.
    """
    script = ActivityScript()
    script.spend = 0.0
    script.reports = [
        {
            "status": "need_more_data",
            "confidence": 0.3,
            "missing_info": [{"what": "more", "why": "need"}],
        }
        for _ in range(10)
    ]
    script.budget = {"max_rounds": 15, "max_cost_usd": 100.0, "max_wall_seconds": 3600}

    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            # Raise reported spend and collapse the cost budget so the next
            # pre-round get_spend check trips cost_budget.
            script.spend = 5.0
            await handle.signal(
                InvestigationWorkflow.adjust_budget,
                {"max_cost_usd": 1.0},
            )
            # Nudge time so the workflow processes the signal and continues.
            for _ in range(20):
                await env.sleep(timedelta(seconds=1))
                status = await handle.query(InvestigationWorkflow.get_status)
                if status["status"] in ("NEEDS_HUMAN", "RESOLVED", "CLOSED_SUMMARY"):
                    break
            result = await handle.result()
    assert result["status"] == "NEEDS_HUMAN"
    assert result["reason"] == "cost_budget"


@pytest.mark.asyncio
async def test_b13_round_loop_overhead_under_1s():
    """B13: workflow round-loop overhead with 0-cost activities < 1s/round."""
    script = ActivityScript()
    script.budget = {"max_rounds": 5, "max_cost_usd": 100.0, "max_wall_seconds": 3600}
    script.reports = [
        {"status": "need_more_data", "confidence": 0.4, "missing_info": [{"what": "a", "why": "b"}]}
        for _ in range(4)
    ] + [
        {
            "status": "concluded",
            "confidence": 0.95,
            "rca_compact": "done",
        }
    ]
    import time

    t0 = time.perf_counter()
    result, _ = await _run(script)
    elapsed = time.perf_counter() - t0
    rounds = script.analyze_calls
    per_round = elapsed / max(rounds, 1)
    assert result["status"] == "CLOSED_SUMMARY"
    assert per_round < 1.0, f"B13 FAILED: {per_round:.3f}s per round (budget 1s)"


@pytest.mark.asyncio
async def test_m4_awaited_approval_id_guard_ignores_mismatched_signal():
    """M4 Section 10.2.3: mismatched approval_id must not unblock the wait.

    A late/duplicate signal for a *previous* approval must not corrupt the
    current gate. Only a matching approval_id applies.
    """
    script = ActivityScript()
    script.reports = [
        {
            "status": "concluded",
            "confidence": 0.95,
            "raw_command_requests": [
                {"command": "cat /etc/presto/config.properties", "justification": "need"}
            ],
            "rca_compact": "oom",
        }
    ]
    script.remediation = {
        "proposed_actions": [{"kind": "ignore", "risk_level": "R0", "description": "done"}],
        "rca_compact": "oom",
    }
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            # Wait until approval is created.
            for _ in range(50):
                await env.sleep(timedelta(seconds=1))
                if script.approvals:
                    break
            assert script.approvals, "expected a raw_command approval"
            real_id = script.approvals[-1]["id"]
            # Mismatched id — must be ignored by the guard.
            await handle.signal(
                InvestigationWorkflow.approval_decided,
                {"approval_id": str(uuid.uuid4()), "decision": "approved"},
            )
            await env.sleep(timedelta(seconds=2))
            status = await handle.query(InvestigationWorkflow.get_status)
            assert status["status"] == "AWAITING_APPROVAL"
            # Matching id — unblocks.
            await handle.signal(
                InvestigationWorkflow.approval_decided,
                {"approval_id": real_id, "decision": "approved"},
            )
            result = await handle.result()
    assert result["status"] == "CLOSED_SUMMARY"


@pytest.mark.asyncio
async def test_platform_not_ready_rejects_and_notifies():
    """W2 / FP-M5-10: REJECTED path fires case_rejected after reject_case."""
    script = ActivityScript()
    script.rejected = True
    script.reject_reason = "platform_not_ready"
    result, status = await _run(script)
    assert result["status"] == "REJECTED"
    assert result.get("reason") == "platform_not_ready"
    assert status["status"] == "REJECTED"
    assert "REJECTED" in script.closed
    events = [n.get("event") for n in script.notifications]
    assert "case_rejected" in events


@pytest.mark.asyncio
async def test_restart_playbook_default_settle_resolves():
    """C2 / FP-M5-8: restart playbook without settle_seconds still reaches RESOLVED.

    Default settle is 120s; time-skipping advances the durable timer. Regression
    guard for the dead-code ternary that always yielded 0.
    """
    script = ActivityScript()
    script.remediation = {
        "proposed_actions": [
            {
                "kind": "playbook",
                "playbook_id": "presto.restart_coordinator",
                "risk_level": "R2",
                "description": "restart coordinator",
                "verification_plan": ["presto_cluster_info"],
                # intentionally omit settle_seconds → playbook default 120
            }
        ],
        "rca_compact": "gc hang",
    }
    async with await WorkflowEnvironment.start_time_skipping() as env:
        async with Worker(
            env.client,
            task_queue=TASK_QUEUE,
            workflows=[InvestigationWorkflow],
            activities=script.bind(),
        ):
            handle = await env.client.start_workflow(
                InvestigationWorkflow.run,
                {"event": _event(), "investigation_id": str(uuid.uuid4())},
                id=f"inv-{uuid.uuid4()}",
                task_queue=TASK_QUEUE,
            )
            for _ in range(50):
                await env.sleep(timedelta(seconds=1))
                if script.approvals:
                    await handle.signal(
                        InvestigationWorkflow.approval_decided,
                        {
                            "approval_id": script.approvals[-1]["id"],
                            "decision": "approved",
                        },
                    )
                    break
            result = await handle.result()
    assert result["status"] == "RESOLVED"
    events = [n.get("event") for n in script.notifications]
    assert "case_resolved" in events
