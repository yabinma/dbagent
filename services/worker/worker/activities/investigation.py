"""Investigation Activities (design.md Section 5.2 implementation contract).

All four agent roles + case lifecycle helpers live here as methods on
``InvestigationActivities``, bound to shared deps (LLM client, PG session
factory, probe-gateway client, object store) at worker start-up.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from temporalio import activity

from rca_common.audit import actor_agent, actor_system, write_audit
from rca_common.investigation_repo import (
    create_approval,
    get_evidence,
    get_platform,
    insert_evidence,
    open_case_from_event,
    record_iteration as repo_record_iteration,
    update_investigation_status,
)
from rca_common.rawcmd import static_validate

from worker.agents.schemas import (
    CONTROL_TOOLS,
    DEFAULT_TOOL_CATALOG,
    MVP_PLAYBOOKS,
    RISK_DEFS,
    load_schema,
)
from worker.agents.templates import load_prompt, render
from worker.context_assembly import assemble_rca_context
from worker.control_tools import FakeSourceStore, run_control_tool


class InvestigationActivities:
    def __init__(
        self,
        *,
        session_factory,
        llm_client,
        probe_client,
        object_store=None,
        config=None,
        source_store=None,
        model_overrides: dict[str, dict[str, Any]] | None = None,
    ):
        self._session_factory = session_factory
        self._llm = llm_client
        self._probe = probe_client
        self._object_store = object_store
        self._config = config
        self._source_store = source_store or FakeSourceStore()
        self._model_overrides = model_overrides or {}

    # ------------------------------------------------------------------ helpers
    def _model_for(self, role: str) -> tuple[str, int]:
        if self._config is not None and role in getattr(self._config, "models", {}):
            route = self._config.models[role]
            return route.model, route.max_tokens
        defaults = {
            "planner": ("ollama/qwen2.5:14b", 2000),
            "collector": ("ollama/qwen2.5:14b", 2000),
            "rca": ("bedrock/anthropic.claude-fable-5", 8000),
            "remediation": ("bedrock/anthropic.claude-fable-5", 4000),
        }
        override = self._model_overrides.get(role)
        if override:
            return override.get("model", defaults[role][0]), int(override.get("max_tokens", defaults[role][1]))
        return defaults.get(role, ("ollama/qwen2.5:14b", 2000))

    def _budget_defaults(self) -> dict[str, Any]:
        if self._config is not None:
            return {
                "max_rounds": self._config.budget_defaults.max_rounds,
                "max_cost_usd": self._config.budget_defaults.max_cost_usd,
                "max_wall_seconds": self._config.budget_defaults.max_wall_seconds,
            }
        return {"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800}

    def _max_calls(self) -> int:
        if self._config is not None:
            return int(self._config.max_calls_per_round)
        return 8

    def _confidence_threshold(self) -> float:
        if self._config is not None:
            return float(self._config.rca_confidence_threshold)
        return 0.85

    def _put_payload(self, key: str, data: bytes) -> str:
        if self._object_store is None:
            return key
        self._object_store.put(key, data)
        return key

    # ------------------------------------------------------------------ activities
    @activity.defn(name="create_case")
    async def create_case(self, payload: dict[str, Any]) -> dict[str, Any]:
        """OPEN the case (+ audit). Returns case summary for the workflow."""
        event = payload["event"]
        investigation_id = uuid.UUID(str(payload.get("investigation_id") or uuid.uuid4()))
        workflow_id = payload.get("workflow_id") or f"investigation-{investigation_id}"
        with self._session_factory() as session:
            platform = get_platform(session, event["platform_key"])
            budget = dict(self._budget_defaults())
            if platform is not None and platform.config:
                from rca_common.investigation_repo import merge_platform_budget

                budget = merge_platform_budget(budget, platform.config)
            # If ingest already created a RECEIVED row, promote it to OPEN.
            from sqlalchemy import select
            from rca_common.db.models import Investigation

            existing = session.scalars(
                select(Investigation)
                .where(Investigation.investigation_id == investigation_id)
                .order_by(Investigation.created_at.desc())
                .limit(1)
            ).first()
            if existing is not None:
                existing.status = "OPEN"
                existing.budget = budget
                write_audit(
                    session,
                    action="case_opened",
                    actor=actor_system(),
                    investigation_id=investigation_id,
                    detail={"platform_key": event["platform_key"], "workflow_id": workflow_id},
                )
            else:
                open_case_from_event(
                    session,
                    event=event,
                    workflow_id=workflow_id,
                    budget=budget,
                    investigation_id=investigation_id,
                )
            session.commit()
        return {
            "investigation_id": str(investigation_id),
            "platform_key": event["platform_key"],
            "budget": budget,
            "confidence_threshold": self._confidence_threshold(),
            "max_calls_per_round": self._max_calls(),
        }

    @activity.defn(name="get_spend")
    async def get_spend(self, payload: dict[str, Any]) -> float:
        """Pre-round cost check (Section 5.2 / 7). Uses builtin llm_calls sum."""
        investigation_id = payload["investigation_id"]
        # Prefer the LLMClient's trace store when available.
        trace_store = getattr(self._llm, "_trace_store", None)
        if trace_store is not None:
            return float(trace_store.get_spend(investigation_id))
        with self._session_factory() as session:
            from sqlalchemy import func, select
            from rca_common.db.models import LLMCall

            stmt = select(func.coalesce(func.sum(LLMCall.cost_usd), 0)).where(
                LLMCall.investigation_id == uuid.UUID(str(investigation_id))
            )
            return float(session.execute(stmt).scalar_one())

    @activity.defn(name="plan_initial")
    async def plan_initial(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._plan(payload, mode="initial")

    @activity.defn(name="plan_next")
    async def plan_next(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._plan(payload, mode="next")

    async def _plan(self, payload: dict[str, Any], *, mode: str) -> dict[str, Any]:
        event = payload.get("event") or {}
        max_calls = int(payload.get("max_calls_per_round") or self._max_calls())
        if mode == "initial":
            mode_body = (
                f"Alert: {json.dumps(event, default=str)}\n"
                "Produce the first collection plan: choose 3-8 tool calls that most quickly "
                "narrow the fault domain. Prioritize: error context (relevant logs, failed "
                "query details), overall cluster state, resource snapshot."
            )
        else:
            mode_body = (
                f"Existing evidence summaries: {json.dumps(payload.get('evidence_summaries') or [], default=str)}\n"
                f"Gaps requested by the RCA agent: {json.dumps(payload.get('missing_info') or [], default=str)}\n"
                "Map each gap to concrete tool calls. If the catalog cannot satisfy a gap, "
                'list it under "unresolvable" with the reason.'
            )
        template = load_prompt("planner.txt")
        prompt = render(
            template,
            {
                "platform_type": payload.get("platform_type", "presto"),
                "engine_version": payload.get("engine_version", "0.298"),
                "deployment": payload.get("deployment", "k8s"),
                "tool_catalog": json.dumps(payload.get("tool_catalog") or DEFAULT_TOOL_CATALOG),
                "mode": mode,
                "mode_body": mode_body,
                "max_calls_per_round": str(max_calls),
            },
        )
        model, max_tokens = self._model_for("planner")
        result = await self._llm.generate(
            agent_role="planner",
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            investigation_id=payload.get("investigation_id"),
            round=payload.get("round"),
            output_schema=load_schema("plan"),
        )
        plan = result.parsed
        # Enforce max_calls_per_round server-side (F3).
        calls = list(plan.get("tool_calls") or [])
        if len(calls) > max_calls:
            plan = {**plan, "tool_calls": calls[:max_calls]}
        return plan

    @activity.defn(name="collect")
    async def collect(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        """Plan → probe-gateway / control-tool calls + evidence summaries."""
        plan = payload["plan"]
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
        platform_key = payload["platform_key"]
        round_num = int(payload["round"])
        max_calls = int(payload.get("max_calls_per_round") or self._max_calls())
        tool_calls = list(plan.get("tool_calls") or [])[:max_calls]
        evidence_out: list[dict[str, Any]] = []

        with self._session_factory() as session:
            write_audit(
                session,
                action="round_started",
                actor=actor_agent("collector"),
                investigation_id=investigation_id,
                detail={"round": round_num, "n_tools": len(tool_calls)},
            )
            session.commit()

        for call in tool_calls:
            tool = call.get("tool") or ""
            args = call.get("args") or {}
            task_id = f"{investigation_id}:{round_num}:{tool}:{uuid.uuid4().hex[:8]}"
            with self._session_factory() as session:
                write_audit(
                    session,
                    action="task_dispatched",
                    actor=actor_agent("collector"),
                    investigation_id=investigation_id,
                    detail={"tool": tool, "args": args, "task_id": task_id},
                )
                session.commit()

            if tool in CONTROL_TOOLS:
                def _lookup(eid):
                    try:
                        with self._session_factory() as s:
                            return get_evidence(s, eid)
                    except Exception:
                        return None

                class _OSAdapter:
                    def __init__(self, store):
                        self._store = store

                    def get_bytes(self, key: str) -> bytes:
                        if self._store is None:
                            return b""
                        if hasattr(self._store, "get"):
                            return self._store.get(key)
                        return b""

                result_data = await run_control_tool(
                    tool,
                    args,
                    source_store=self._source_store,
                    evidence_lookup=_lookup,
                    object_store=_OSAdapter(self._object_store),
                )
                raw = json.dumps(result_data).encode()
                exit_code = int(result_data.get("exit_code", 0))
                redacted = False
                executed_by = "control-plane"
                data_payload = result_data.get("data")
            else:
                result = await self._probe.execute_tool(
                    platform_key,
                    tool=tool,
                    args=args,
                    task_id=task_id,
                )
                raw = result.raw_bytes
                exit_code = result.exit_code
                redacted = result.redacted
                executed_by = result.probe_id or "probe"
                data_payload = result.data

            summary = await self._summarize_evidence(tool, args, raw, investigation_id, round_num)
            evidence_id = uuid.uuid4()
            payload_ref = f"evidence/{investigation_id}/{evidence_id}.json"
            self._put_payload(payload_ref, raw)

            with self._session_factory() as session:
                insert_evidence(
                    session,
                    evidence_id=evidence_id,
                    investigation_id=investigation_id,
                    round_num=round_num,
                    tool_name=tool,
                    args=args,
                    exit_code=exit_code,
                    summary=summary,
                    payload_ref=payload_ref,
                    payload_bytes=len(raw),
                    redacted=redacted,
                    executed_by=executed_by,
                )
                write_audit(
                    session,
                    action="tool_executed",
                    actor=actor_agent("collector"),
                    investigation_id=investigation_id,
                    detail={
                        "tool": tool,
                        "evidence_id": str(evidence_id),
                        "exit_code": exit_code,
                        "executed_by": executed_by,
                    },
                )
                session.commit()

            evidence_out.append(
                {
                    "evidence_id": str(evidence_id),
                    "tool_name": tool,
                    "args": args,
                    "round": round_num,
                    "summary": summary,
                    "payload": data_payload,
                    "payload_ref": payload_ref,
                    "exit_code": exit_code,
                    "redacted": redacted,
                    "executed_by": executed_by,
                }
            )
        return evidence_out

    async def _summarize_evidence(
        self,
        tool: str,
        args: dict[str, Any],
        raw: bytes,
        investigation_id: uuid.UUID,
        round_num: int,
    ) -> str:
        head = raw[:65536].decode("utf-8", errors="replace")
        template = load_prompt("collector_summary.txt")
        prompt = render(
            template,
            {
                "tool": tool,
                "args": json.dumps(args, default=str),
                "payload_head_64kb": head,
            },
        )
        model, max_tokens = self._model_for("collector")
        try:
            result = await self._llm.generate(
                agent_role="collector",
                model=model,
                max_tokens=max_tokens,
                messages=[{"role": "user", "content": prompt}],
                investigation_id=investigation_id,
                round=round_num,
                output_schema=load_schema("evidence_summary"),
            )
            parsed = result.parsed or {}
            summary = parsed.get("summary") or head[:500]
            notables = parsed.get("notable_lines") or []
            if notables:
                summary = summary + "\n" + "\n".join(notables[:10])
            return summary[:4000]
        except Exception:
            # Summary is best-effort; never fail the collect path on it.
            return head[:500]

    @activity.defn(name="analyze")
    async def analyze(self, payload: dict[str, Any]) -> dict[str, Any]:
        event = payload["event"]
        evidence = payload.get("evidence") or []
        reports = payload.get("reports") or []
        round_num = int(payload["round"])
        budget = payload.get("budget") or self._budget_defaults()
        spent = float(payload.get("spent_usd") or 0.0)
        assembled = assemble_rca_context(
            event=event,
            evidence=evidence,
            reports=reports,
            round_num=round_num,
            max_rounds=int(budget.get("max_rounds", 15)),
            spent_usd=spent,
            platform_type=payload.get("platform_type", "presto"),
            engine_version=payload.get("engine_version", "0.298"),
            approver_feedback=payload.get("approver_feedback") or [],
        )
        template = load_prompt("rca.txt")
        prompt = render(template, assembled["variables"])
        model, max_tokens = self._model_for("rca")
        result = await self._llm.generate(
            agent_role="rca",
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            investigation_id=payload.get("investigation_id"),
            round=round_num,
            output_schema=load_schema("rca_report"),
        )
        report = result.parsed
        with self._session_factory() as session:
            write_audit(
                session,
                action="rca_produced",
                actor=actor_agent("rca"),
                investigation_id=payload.get("investigation_id"),
                detail={
                    "status": report.get("status"),
                    "confidence": report.get("confidence"),
                    "round": round_num,
                    "context_build_ms": assembled["metrics"]["build_ms"],
                },
            )
            session.commit()
        report["_context_metrics"] = assembled["metrics"]
        return report

    @activity.defn(name="record_iteration")
    async def record_iteration(self, payload: dict[str, Any]) -> None:
        with self._session_factory() as session:
            repo_record_iteration(
                session,
                investigation_id=uuid.UUID(str(payload["investigation_id"])),
                round_num=int(payload["round"]),
                plan=payload.get("plan") or {},
                rca_output=payload.get("report"),
                cost_usd=payload.get("cost_usd"),
                duration_ms=payload.get("duration_ms"),
            )
            # Bump spent.rounds
            from sqlalchemy import select
            from rca_common.db.models import Investigation

            inv = session.scalars(
                select(Investigation)
                .where(Investigation.investigation_id == uuid.UUID(str(payload["investigation_id"])))
                .order_by(Investigation.created_at.desc())
                .limit(1)
            ).first()
            if inv is not None:
                spent = dict(inv.spent or {})
                spent["rounds"] = int(spent.get("rounds") or 0) + 1
                if payload.get("cost_usd") is not None:
                    spent["cost_usd"] = float(spent.get("cost_usd") or 0) + float(payload["cost_usd"])
                inv.spent = spent
                inv.status = "INVESTIGATING"
            session.commit()

    @activity.defn(name="static_validate_raw_command")
    async def static_validate_raw_command(self, payload: dict[str, Any]) -> dict[str, Any]:
        command = payload.get("command") or ""
        result = static_validate(command)
        investigation_id = payload.get("investigation_id")
        with self._session_factory() as session:
            write_audit(
                session,
                action="raw_cmd_requested",
                actor=actor_agent("rca"),
                investigation_id=investigation_id,
                detail={"command": command, "ok": result.ok, "reason": result.reason},
            )
            session.commit()
        return {"ok": result.ok, "reason": result.reason, "command": command}

    @activity.defn(name="run_raw_command")
    async def run_raw_command(self, payload: dict[str, Any]) -> list[dict[str, Any]]:
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
        platform_key = payload["platform_key"]
        command = payload["command"]
        round_num = int(payload.get("round") or 0)
        result = await self._probe.execute_raw_command(platform_key, command=command)
        evidence_id = uuid.uuid4()
        payload_ref = f"evidence/{investigation_id}/{evidence_id}.json"
        self._put_payload(payload_ref, result.raw_bytes)
        summary = f"raw_command output (exit={result.exit_code})"
        with self._session_factory() as session:
            insert_evidence(
                session,
                evidence_id=evidence_id,
                investigation_id=investigation_id,
                round_num=round_num,
                tool_name="raw_command",
                args={"command": command},
                exit_code=result.exit_code,
                summary=summary,
                payload_ref=payload_ref,
                payload_bytes=len(result.raw_bytes),
                redacted=result.redacted,
                executed_by=result.probe_id or "probe",
            )
            write_audit(
                session,
                action="tool_executed",
                actor=actor_agent("collector"),
                investigation_id=investigation_id,
                detail={"tool": "raw_command", "evidence_id": str(evidence_id)},
            )
            session.commit()
        return [
            {
                "evidence_id": str(evidence_id),
                "tool_name": "raw_command",
                "args": {"command": command},
                "round": round_num,
                "summary": summary,
                "payload": result.data,
                "payload_ref": payload_ref,
                "exit_code": result.exit_code,
            }
        ]

    @activity.defn(name="create_approval")
    async def create_approval_activity(self, payload: dict[str, Any]) -> dict[str, Any]:
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
        kind = payload["kind"]
        subject = payload.get("subject") or {}
        with self._session_factory() as session:
            row = create_approval(
                session,
                investigation_id=investigation_id,
                kind=kind,
                subject=subject,
            )
            write_audit(
                session,
                action="approval_requested",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"approval_id": str(row.approval_id), "kind": kind},
            )
            update_investigation_status(session, investigation_id, "AWAITING_APPROVAL")
            session.commit()
            approval_id = str(row.approval_id)
        return {"approval_id": approval_id, "kind": kind}

    @activity.defn(name="record_approval_decision")
    async def record_approval_decision(self, payload: dict[str, Any]) -> None:
        """Persist decision + audits.

        M4 (Section 10.2.3): when the human already decided via dashboard-api,
        ``decide_approval`` reports already-decided — skip decision write *and*
        the system-actor audits so the human ``user:<id>`` actor is preserved.
        The timeout path (``is_timeout=True`` or no prior decision) remains the
        sole system-side decider.
        """
        with self._session_factory() as session:
            from rca_common.investigation_repo import decide_approval

            already_decided = False
            try:
                decide_approval(
                    session,
                    payload["approval_id"],
                    decision=payload.get("decision") or "denied",
                    comment=payload.get("comment"),
                )
            except KeyError:
                # Unknown approval — still attempt audit for observability.
                pass
            except ValueError:
                # Already decided (human path via dashboard-api).
                already_decided = True

            if already_decided and not payload.get("is_timeout"):
                # Human was the decider: decision + user-actor audits already
                # written by dashboard-api. Do not double-audit as system.
                session.commit()
                return

            action = (
                "raw_cmd_approved"
                if payload.get("decision") == "approved" and payload.get("kind") == "raw_command"
                else None
            )
            if payload.get("decision") == "denied" and payload.get("kind") == "raw_command":
                action = "raw_cmd_denied"
            write_audit(
                session,
                action="approval_decided",
                actor=actor_system(),
                investigation_id=payload.get("investigation_id"),
                detail={
                    "approval_id": payload.get("approval_id"),
                    "decision": payload.get("decision"),
                    "comment": payload.get("comment"),
                    "kind": payload.get("kind"),
                },
            )
            if action:
                write_audit(
                    session,
                    action=action,
                    actor=actor_system(),
                    investigation_id=payload.get("investigation_id"),
                    detail={"approval_id": payload.get("approval_id")},
                )
            session.commit()

    @activity.defn(name="plan_remediation")
    async def plan_remediation(self, payload: dict[str, Any]) -> dict[str, Any]:
        rca_report = payload.get("rca_report") or {}
        template = load_prompt("remediation.txt")
        prompt = render(
            template,
            {
                "rca_report": json.dumps(rca_report, default=str),
                "playbooks": json.dumps(MVP_PLAYBOOKS),
                "write_ops": json.dumps(
                    [
                        "k8s_patch_configmap",
                        "k8s_rollout_restart",
                        "k8s_delete_pod",
                        "swarm_update_service_env",
                        "swarm_restart_service",
                        "presto_kill_query",
                    ]
                ),
                "health_query": payload.get("health_query") or "SELECT 1",
                "risk_defs": RISK_DEFS,
            },
        )
        model, max_tokens = self._model_for("remediation")
        result = await self._llm.generate(
            agent_role="remediation",
            model=model,
            max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
            investigation_id=payload.get("investigation_id"),
            output_schema=load_schema("remediation"),
        )
        out = result.parsed
        with self._session_factory() as session:
            write_audit(
                session,
                action="remediation_proposed",
                actor=actor_agent("remediation"),
                investigation_id=payload.get("investigation_id"),
                detail={"n_actions": len(out.get("proposed_actions") or [])},
            )
            session.commit()
        return out

    @activity.defn(name="execute_playbook")
    async def execute_playbook(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Dispatch signed write steps via probe-gateway (M5 deepens op execution).

        M3 implements the Activity contract and audit trail so the state
        machine can reach RESOLVED; the probe write-channel gate (M2) verifies
        signatures. Full k8s/swarm primitive execution remains M5.
        """
        investigation_id = payload.get("investigation_id")
        action = payload.get("action") or {}
        with self._session_factory() as session:
            write_audit(
                session,
                action="remediation_started",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"playbook_id": action.get("playbook_id"), "params": action.get("playbook_params")},
            )
            update_investigation_status(
                session, uuid.UUID(str(investigation_id)), "EXECUTING"
            )
            session.commit()
        # M3: treat playbook dispatch as successful when the action is well-formed.
        # A fake probe client may also record the call for assertions.
        ok = bool(action.get("playbook_id"))
        with self._session_factory() as session:
            write_audit(
                session,
                action="remediation_finished",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"playbook_id": action.get("playbook_id"), "ok": ok},
            )
            session.commit()
        return {"ok": ok, "playbook_id": action.get("playbook_id"), "pre_snapshot": {}}

    @activity.defn(name="verify_fix")
    async def verify_fix(self, payload: dict[str, Any]) -> dict[str, Any]:
        plan = payload.get("verification_plan") or []
        # M3: verification succeeds when the plan is present (or empty defaults).
        # Functional tests can force failure via payload["force_fail"].
        ok = not bool(payload.get("force_fail"))
        with self._session_factory() as session:
            write_audit(
                session,
                action="verification_run",
                actor=actor_system(),
                investigation_id=payload.get("investigation_id"),
                detail={"plan": plan, "ok": ok},
            )
            if ok:
                update_investigation_status(
                    session, uuid.UUID(str(payload["investigation_id"])), "VERIFYING"
                )
            session.commit()
        return {"ok": ok, "plan": plan}

    @activity.defn(name="close_with_summary")
    async def close_with_summary(self, payload: dict[str, Any]) -> dict[str, Any]:
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
        with self._session_factory() as session:
            update_investigation_status(
                session,
                investigation_id,
                "CLOSED_SUMMARY",
                rca_report=payload.get("rca_report"),
                close=True,
            )
            write_audit(
                session,
                action="case_closed",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"status": "CLOSED_SUMMARY", "reason": payload.get("reason")},
            )
            session.commit()
        return {"status": "CLOSED_SUMMARY"}

    @activity.defn(name="close_resolved")
    async def close_resolved(self, payload: dict[str, Any]) -> dict[str, Any]:
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
        with self._session_factory() as session:
            update_investigation_status(
                session,
                investigation_id,
                "RESOLVED",
                rca_report=payload.get("rca_report"),
                close=True,
            )
            write_audit(
                session,
                action="case_closed",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"status": "RESOLVED"},
            )
            session.commit()
        return {"status": "RESOLVED"}

    @activity.defn(name="to_needs_human")
    async def to_needs_human(self, payload: dict[str, Any]) -> dict[str, Any]:
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
        reason = payload.get("reason") or "unknown"
        with self._session_factory() as session:
            if reason in ("time_budget", "cost_budget", "round_budget"):
                write_audit(
                    session,
                    action="budget_exceeded",
                    actor=actor_system(),
                    investigation_id=investigation_id,
                    detail={"reason": reason},
                )
            update_investigation_status(
                session,
                investigation_id,
                "NEEDS_HUMAN",
                rca_report=payload.get("rca_report"),
                close=True,
            )
            write_audit(
                session,
                action="case_closed",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"status": "NEEDS_HUMAN", "reason": reason},
            )
            session.commit()
        return {"status": "NEEDS_HUMAN", "reason": reason}

    @activity.defn(name="reject_case")
    async def reject_case(self, payload: dict[str, Any]) -> dict[str, Any]:
        investigation_id = uuid.UUID(str(payload["investigation_id"]))
        with self._session_factory() as session:
            update_investigation_status(
                session, investigation_id, "REJECTED", close=True
            )
            write_audit(
                session,
                action="case_closed",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"status": "REJECTED", "reason": payload.get("reason")},
            )
            session.commit()
        return {"status": "REJECTED", "reason": payload.get("reason")}
