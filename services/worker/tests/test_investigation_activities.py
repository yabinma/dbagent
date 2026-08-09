"""Unit tests for InvestigationActivities with faked LLM/probe/PG."""
from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from worker.activities.investigation import InvestigationActivities
from worker.probeclient import FakeProbeGatewayClient

from helpers import ScriptedLLM


class _SessionCtx:
    def __init__(self, session):
        self._session = session

    def __enter__(self):
        return self._session

    def __exit__(self, *args):
        return False


def _fake_inv(**kwargs):
    inv = MagicMock()
    inv.investigation_id = kwargs.get("investigation_id", uuid.uuid4())
    inv.status = kwargs.get("status", "OPEN")
    inv.budget = kwargs.get("budget", {"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800})
    inv.spent = kwargs.get("spent", {"rounds": 0, "cost_usd": 0})
    inv.rca_report = None
    inv.closed_at = None
    return inv


def _session_factory(session=None, inv=None):
    session = session or MagicMock()
    inv = inv if inv is not None else _fake_inv()
    session.get = MagicMock(return_value=None)
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=inv)))
    session.execute = MagicMock(return_value=MagicMock(scalar_one=MagicMock(return_value=0)))
    return lambda: _SessionCtx(session)


@pytest.fixture
def acts(tmp_path):
    llm = ScriptedLLM(
        {
            "planner": {
                "tool_calls": [
                    {"tool": "presto_cluster_info", "args": {}, "purpose": "state"},
                    {"tool": "presto_nodes", "args": {}, "purpose": "nodes"},
                ],
                "unresolvable": [],
            },
            "collector": {
                "summary": "cluster healthy summary",
                "notable_lines": ["line1"],
                "anomaly_detected": False,
            },
            "rca": {
                "status": "concluded",
                "confidence": 0.95,
                "root_cause": {"category": "resource", "summary": "oom"},
                "rca_compact": "oom",
            },
            "remediation": {
                "proposed_actions": [
                    {
                        "kind": "playbook",
                        "playbook_id": "presto.adjust_memory_config",
                        "risk_level": "R2",
                        "description": "raise memory",
                    }
                ],
                "rca_compact": "oom digest",
            },
        }
    )
    probe = FakeProbeGatewayClient(
        {
            "presto_cluster_info": {"exit_code": 0, "data": {"activeWorkers": 3}},
            "presto_nodes": {"exit_code": 0, "data": {"nodes": [{"nodeId": "n1"}]}},
            "presto_list_queries": {"exit_code": 0, "data": {"queries": []}},
            "presto_query_detail": {"exit_code": 0, "data": {"queryId": "q"}},
            "health": {"ok": True, "exit_code": 0},
            "write": {"ok": True, "exit_code": 0},
        }
    )
    from rca_common.llmclient.objectstore import FakeObjectStore
    from rca_common.signing.signer import bootstrap_signing_key

    key_path = str(tmp_path / "ed25519.key")
    signer = bootstrap_signing_key(key_path)

    return InvestigationActivities(
        session_factory=_session_factory(),
        llm_client=llm,
        probe_client=probe,
        object_store=FakeObjectStore(),
        config=None,
        signer=signer,
    ), llm, probe


@pytest.mark.asyncio
async def test_plan_initial_enforces_max_calls(acts):
    activities, llm, _ = acts
    llm.scripts["planner"] = {
        "tool_calls": [
            {"tool": f"t{i}", "args": {}, "purpose": "p"} for i in range(20)
        ],
        "unresolvable": [],
    }
    plan = await activities.plan_initial(
        {
            "event": {"error_summary": "x", "platform_key": "p"},
            "investigation_id": str(uuid.uuid4()),
            "max_calls_per_round": 3,
        }
    )
    assert len(plan["tool_calls"]) == 3


@pytest.mark.asyncio
async def test_collect_dispatches_tools_and_summaries(acts):
    activities, _, probe = acts
    inv = str(uuid.uuid4())
    evidence = await activities.collect(
        {
            "plan": {
                "tool_calls": [
                    {"tool": "presto_cluster_info", "args": {}, "purpose": "s"},
                    {"tool": "presto_nodes", "args": {}, "purpose": "n"},
                ],
                "unresolvable": [],
            },
            "investigation_id": inv,
            "platform_key": "presto-us1",
            "round": 1,
            "max_calls_per_round": 8,
        }
    )
    assert len(evidence) == 2
    assert all(e["summary"] for e in evidence)
    assert len(probe.calls) == 2


@pytest.mark.asyncio
async def test_b8_collect_overhead_under_2s_at_parallelism_8(acts):
    """B8: evidence-summary collect path non-model overhead < 2 s at max_calls=8.

    FakeProbeGatewayClient + ScriptedLLM (mocked model, fixed latency) so the
    measured wall time is the non-model collection overhead the threshold
    describes (design.md Section 14.4).
    """
    import time

    activities, _, probe = acts
    inv = str(uuid.uuid4())
    tool_calls = [
        {"tool": f"presto_cluster_info", "args": {"i": i}, "purpose": f"p{i}"}
        for i in range(8)
    ]
    t0 = time.perf_counter()
    evidence = await activities.collect(
        {
            "plan": {"tool_calls": tool_calls, "unresolvable": []},
            "investigation_id": inv,
            "platform_key": "presto-us1",
            "round": 1,
            "max_calls_per_round": 8,
        }
    )
    elapsed = time.perf_counter() - t0
    assert len(evidence) == 8
    assert len(probe.calls) == 8
    assert elapsed < 2.0, f"B8 FAILED: collect overhead {elapsed:.3f}s (budget < 2s)"


@pytest.mark.asyncio
async def test_analyze_produces_rca_report(acts):
    activities, _, _ = acts
    report = await activities.analyze(
        {
            "event": {"error_summary": "oom", "platform_key": "p"},
            "evidence": [
                {
                    "evidence_id": "e1",
                    "tool_name": "presto_cluster_info",
                    "round": 1,
                    "summary": "workers=3",
                    "payload": {"activeWorkers": 3},
                }
            ],
            "reports": [],
            "round": 1,
            "budget": {"max_rounds": 15},
            "spent_usd": 0.1,
            "investigation_id": str(uuid.uuid4()),
        }
    )
    assert report["status"] == "concluded"
    assert report["confidence"] >= 0.9
    assert "_context_metrics" not in report or report.get("_context_metrics") is not None


@pytest.mark.asyncio
async def test_static_validate_raw_command(acts):
    activities, _, _ = acts
    ok = await activities.static_validate_raw_command(
        {"command": "cat /etc/presto/config.properties", "investigation_id": str(uuid.uuid4())}
    )
    assert ok["ok"] is True
    bad = await activities.static_validate_raw_command(
        {"command": "rm -rf /", "investigation_id": str(uuid.uuid4())}
    )
    assert bad["ok"] is False


@pytest.mark.asyncio
async def test_plan_remediation(acts):
    activities, _, _ = acts
    out = await activities.plan_remediation(
        {
            "investigation_id": str(uuid.uuid4()),
            "rca_report": {"status": "concluded", "confidence": 0.9},
        }
    )
    assert out["proposed_actions"]


@pytest.mark.asyncio
async def test_get_spend_from_trace_store(acts):
    activities, llm, _ = acts
    inv = uuid.uuid4()
    await llm.generate(
        agent_role="rca",
        model="m",
        max_tokens=10,
        messages=[],
        investigation_id=inv,
    )
    spent = await activities.get_spend({"investigation_id": str(inv)})
    assert spent == pytest.approx(0.01)


@pytest.mark.asyncio
async def test_execute_playbook_and_verify(acts):
    activities, _, _ = acts
    inv = str(uuid.uuid4())
    r = await activities.execute_playbook(
        {
            "investigation_id": inv,
            "action": {"playbook_id": "presto.kill_query", "playbook_params": {"query_id": "q"}},
        }
    )
    assert r["ok"] is True
    # FP-M6-27: complete wiring required (platform_key + probe + playbook_id).
    v = await activities.verify_fix(
        {
            "investigation_id": inv,
            "platform_key": "presto-test",
            "playbook_id": "presto.kill_query",
            "verification_plan": ["presto_list_queries"],
        }
    )
    assert v["ok"] is True
    v2 = await activities.verify_fix(
        {
            "investigation_id": inv,
            "platform_key": "presto-test",
            "playbook_id": "presto.kill_query",
            "verification_plan": [],
            "force_fail": True,
        }
    )
    assert v2["ok"] is False


@pytest.mark.asyncio
async def test_verify_fix_fails_closed_on_missing_wiring(acts):
    """FP-M6-27 / S1: missing platform_key / probe / playbook_id → ok=False wiring check."""
    activities, _, _ = acts
    inv = str(uuid.uuid4())
    # No platform_key, no playbook_id.
    v = await activities.verify_fix(
        {"investigation_id": inv, "verification_plan": ["presto_list_queries"]}
    )
    assert v["ok"] is False
    assert any(c.get("name") == "wiring" and c.get("ok") is False for c in v.get("checks") or [])
    assert "playbook_id" in (v["checks"][0].get("error") or "")


@pytest.mark.asyncio
async def test_close_paths(acts):
    activities, _, _ = acts
    inv = str(uuid.uuid4())
    assert (await activities.close_with_summary({"investigation_id": inv, "rca_report": {}}))[
        "status"
    ] == "CLOSED_SUMMARY"
    assert (await activities.close_resolved({"investigation_id": inv, "rca_report": {}}))[
        "status"
    ] == "RESOLVED"
    assert (await activities.to_needs_human({"investigation_id": inv, "reason": "cost_budget"}))[
        "status"
    ] == "NEEDS_HUMAN"
    assert (await activities.reject_case({"investigation_id": inv, "reason": "platform_not_ready"}))[
        "status"
    ] == "REJECTED"


@pytest.mark.asyncio
async def test_create_case(acts):
    activities, _, _ = acts
    # Need session to support Investigation query + add
    session = MagicMock()
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))
    activities._session_factory = lambda: _SessionCtx(session)
    event = {
        "event_id": str(uuid.uuid4()),
        "platform_key": "presto-us1",
        "error_summary": "oom",
    }
    case = await activities.create_case(
        {"event": event, "investigation_id": str(uuid.uuid4()), "workflow_id": "wf-1"}
    )
    assert case["platform_key"] == "presto-us1"
    assert "budget" in case
    assert session.add.called or session.commit.called


@pytest.mark.asyncio
async def test_create_case_promotes_existing_received(acts):
    activities, _, _ = acts
    existing = _fake_inv(status="RECEIVED")
    platform = MagicMock()
    platform.config = {"budget": {"max_rounds": 2}}
    session = MagicMock()
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=existing)))
    session.get = MagicMock(return_value=platform)
    activities._session_factory = lambda: _SessionCtx(session)
    case = await activities.create_case(
        {
            "event": {"event_id": str(uuid.uuid4()), "platform_key": "presto-us1", "error_summary": "x"},
            "investigation_id": str(existing.investigation_id),
            "workflow_id": "wf-1",
        }
    )
    assert existing.status == "OPEN"
    assert case["budget"]["max_rounds"] == 2


@pytest.mark.asyncio
async def test_collect_control_tool_path(acts):
    activities, _, probe = acts
    inv = str(uuid.uuid4())
    evidence = await activities.collect(
        {
            "plan": {
                "tool_calls": [
                    {"tool": "fetch_source", "args": {"file_path": "a.java", "ref": "0.298"}, "purpose": "code"},
                    {"tool": "read_evidence", "args": {"evidence_id": str(uuid.uuid4())}, "purpose": "hist"},
                ],
                "unresolvable": [],
            },
            "investigation_id": inv,
            "platform_key": "presto-us1",
            "round": 2,
        }
    )
    assert len(evidence) == 2
    assert evidence[0]["executed_by"] == "control-plane"
    assert probe.calls == []  # control tools do not hit probe


@pytest.mark.asyncio
async def test_run_raw_command_and_approval_flow(acts):
    activities, _, probe = acts
    inv = str(uuid.uuid4())
    approval = await activities.create_approval_activity(
        {
            "investigation_id": inv,
            "kind": "raw_command",
            "subject": {"command": "cat /x"},
        }
    )
    assert "approval_id" in approval
    await activities.record_approval_decision(
        {
            "investigation_id": inv,
            "approval_id": approval["approval_id"],
            "decision": "approved",
            "kind": "raw_command",
        }
    )
    await activities.record_approval_decision(
        {
            "investigation_id": inv,
            "approval_id": approval["approval_id"],
            "decision": "denied",
            "kind": "raw_command",
            "comment": "timeout",
        }
    )
    ev = await activities.run_raw_command(
        {
            "investigation_id": inv,
            "platform_key": "presto-us1",
            "command": "cat /etc/presto/config.properties",
            "round": 1,
        }
    )
    assert ev[0]["tool_name"] == "raw_command"
    assert any(c["kind"] == "raw_command" for c in probe.calls)


@pytest.mark.asyncio
async def test_record_iteration_bumps_spent(acts):
    activities, _, _ = acts
    inv = _fake_inv(spent={"rounds": 0, "cost_usd": 0})
    session = MagicMock()
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=inv)))
    activities._session_factory = lambda: _SessionCtx(session)
    await activities.record_iteration(
        {
            "investigation_id": str(inv.investigation_id),
            "round": 1,
            "plan": {"tool_calls": []},
            "report": {"status": "concluded"},
            "cost_usd": 0.5,
        }
    )
    assert inv.spent["rounds"] == 1
    assert inv.spent["cost_usd"] == 0.5
    assert inv.status == "INVESTIGATING"


@pytest.mark.asyncio
async def test_plan_next_mode(acts):
    activities, llm, _ = acts
    plan = await activities.plan_next(
        {
            "event": {"error_summary": "x"},
            "investigation_id": str(uuid.uuid4()),
            "missing_info": [{"what": "logs", "why": "oom"}],
            "evidence_summaries": [{"evidence_id": "e1", "summary": "s"}],
            "max_calls_per_round": 4,
            "round": 1,
        }
    )
    assert "tool_calls" in plan
    assert llm.calls[-1]["agent_role"] == "planner"


@pytest.mark.asyncio
async def test_get_spend_without_trace_store():
    class NoTrace:
        pass

    acts = InvestigationActivities(
        session_factory=_session_factory(),
        llm_client=NoTrace(),
        probe_client=FakeProbeGatewayClient(),
        object_store=None,
    )
    spent = await acts.get_spend({"investigation_id": str(uuid.uuid4())})
    assert spent == 0.0


@pytest.mark.asyncio
async def test_summarize_falls_back_on_llm_error(acts):
    activities, llm, _ = acts
    llm.fail_roles.add("collector")
    evidence = await activities.collect(
        {
            "plan": {
                "tool_calls": [{"tool": "presto_cluster_info", "args": {}, "purpose": "s"}],
                "unresolvable": [],
            },
            "investigation_id": str(uuid.uuid4()),
            "platform_key": "p",
            "round": 1,
        }
    )
    assert evidence[0]["summary"]  # fallback head bytes


@pytest.mark.asyncio
async def test_m4_record_approval_decision_skips_audit_on_human_path(acts):
    """M4: when decide_approval raises already-decided and is_timeout is false,
    system-actor audits must not be written (human actor already recorded).
    """
    activities, _, _ = acts
    inv = str(uuid.uuid4())
    session = MagicMock()
    # decide_approval path is invoked via import inside the activity; patch it.
    import rca_common.investigation_repo as repo

    calls = {"decide": 0, "audits": 0}
    original_write = None

    def fake_decide(*args, **kwargs):
        calls["decide"] += 1
        raise ValueError("approval already decided")

    from rca_common import audit as audit_mod

    real_write = audit_mod.write_audit

    def counting_write(*args, **kwargs):
        calls["audits"] += 1
        return real_write(*args, **kwargs) if False else MagicMock()

    activities._session_factory = lambda: _SessionCtx(session)
    import worker.activities.investigation as inv_mod

    # Patch decide_approval used inside the activity
    monkey = pytest.MonkeyPatch()
    monkey.setattr(
        "rca_common.investigation_repo.decide_approval",
        fake_decide,
    )
    # Also patch write_audit where the activity module imported it
    monkey.setattr(inv_mod, "write_audit", counting_write)
    try:
        await activities.record_approval_decision(
            {
                "investigation_id": inv,
                "approval_id": str(uuid.uuid4()),
                "decision": "approved",
                "kind": "raw_command",
                "is_timeout": False,
            }
        )
        assert calls["decide"] == 1
        assert calls["audits"] == 0
        # Timeout path still audits even if already decided.
        calls["audits"] = 0
        await activities.record_approval_decision(
            {
                "investigation_id": inv,
                "approval_id": str(uuid.uuid4()),
                "decision": "denied",
                "kind": "raw_command",
                "comment": "timeout",
                "is_timeout": True,
            }
        )
        assert calls["audits"] >= 1
    finally:
        monkey.undo()


@pytest.mark.asyncio
async def test_m4_analyze_forwards_approver_feedback(acts):
    activities, llm, _ = acts
    report = await activities.analyze(
        {
            "event": {"error_summary": "oom", "platform_key": "presto-us1"},
            "evidence": [],
            "reports": [],
            "round": 2,
            "budget": {"max_rounds": 15},
            "spent_usd": 0.1,
            "investigation_id": str(uuid.uuid4()),
            "approver_feedback": ["collect GC logs please"],
        }
    )
    assert report["status"] == "concluded"
    # Prompt must have included the feedback block.
    prompt = llm.calls[-1]["messages"][0]["content"]
    assert "Approver feedback from prior rounds:" in prompt
    assert "collect GC logs please" in prompt
