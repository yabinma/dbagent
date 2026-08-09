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
        signer=None,
        dashboard_base_url: str = "",
    ):
        self._session_factory = session_factory
        self._llm = llm_client
        self._probe = probe_client
        self._object_store = object_store
        self._config = config
        self._source_store = source_store or FakeSourceStore()
        self._model_overrides = model_overrides or {}
        if signer is None:
            # Fail closed unless explicitly allowed (review W1). Production
            # mounts a persistent key via worker_main; tests pass a real
            # signer or set config.signing.allow_ephemeral=true.
            allow_ephemeral = False
            if config is not None:
                signing = getattr(config, "signing", None)
                allow_ephemeral = bool(getattr(signing, "allow_ephemeral", False))
            if allow_ephemeral:
                import nacl.signing
                from rca_common.signing.signer import MountedEd25519Signer

                signer = MountedEd25519Signer(nacl.signing.SigningKey.generate())
            # else leave None — execute_playbook fails closed with "signer not configured"
        self._signer = signer
        self._dashboard_base_url = dashboard_base_url

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
        deployment = "k8s"
        remediation: dict[str, Any] = {}
        rejected = False
        reject_reason: str | None = None
        if platform is not None:
            deployment = getattr(platform, "deployment", None) or deployment
            if platform.config:
                remediation = dict((platform.config or {}).get("remediation") or {})
            # RECEIVED → REJECTED when platform is not ONLINE (Section 5.1 / 8.3).
            # Gateway already rejects most cases; this is defense in depth for
            # direct workflow starts and races (FP-M5-10 case_rejected).
            status = (getattr(platform, "status", None) or "").lower()
            if status and status != "online":
                rejected = True
                reject_reason = "platform_not_ready"
        return {
            "investigation_id": str(investigation_id),
            "platform_key": event["platform_key"],
            "budget": budget,
            "confidence_threshold": self._confidence_threshold(),
            "max_calls_per_round": self._max_calls(),
            "deployment": deployment,
            "remediation": remediation,
            "rejected": rejected,
            "reject_reason": reject_reason,
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
        """Real closed-loop playbook execution (design.md Section 9.5.3).

        Resolves ordered steps from ``worker.playbooks.PLAYBOOK_STEPS``, signs
        each step (D14) at execution time, dispatches via probe-gateway
        ``kind=write``, captures pre-snapshot, and manages
        ``remediation_executions`` lifecycle + maturity counters.
        """
        import base64

        from rca_common.db.models import Playbook, RemediationExecution
        from rca_common.signing.signer import canonical_step_hash
        from worker.playbooks import (
            PLAYBOOK_STEPS,
            PRE_SNAPSHOT_TOOLS,
            resolve_locators,
            resolve_runtime_tool,
        )

        investigation_id = payload.get("investigation_id")
        action = payload.get("action") or {}
        playbook_id = action.get("playbook_id")
        params = dict(action.get("playbook_params") or action.get("params") or {})
        approved_by = payload.get("approved_by")
        execution_id = uuid.UUID(str(payload.get("execution_id") or uuid.uuid4()))

        # Resolve platform deployment + locators.
        platform_key = payload.get("platform_key")
        deployment = payload.get("deployment") or "k8s"
        platform_config: dict[str, Any] = {}
        with self._session_factory() as session:
            inv = None
            try:
                from rca_common.db.models import Investigation

                inv = session.get(Investigation, uuid.UUID(str(investigation_id)))
            except Exception:  # noqa: BLE001
                inv = None
            if inv is not None:
                platform_key = platform_key or getattr(inv, "platform_key", None)
                plat = get_platform(session, platform_key) if platform_key else None
                if plat is not None:
                    deployment = payload.get("deployment") or getattr(plat, "deployment", None) or deployment
                    platform_config = dict(plat.config or {})
            write_audit(
                session,
                action="remediation_started",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"playbook_id": playbook_id, "params": params, "execution_id": str(execution_id)},
            )
            update_investigation_status(
                session, uuid.UUID(str(investigation_id)), "EXECUTING"
            )
            # Ensure playbook catalog row exists (FK) — seed on the fly if missing
            # so M3 fixtures and dashboard catalog stay consistent without a
            # hard dependency on the install-time seed job in every test.
            if playbook_id:
                pb = session.get(Playbook, playbook_id)
                if pb is None:
                    from worker.playbooks import PLAYBOOK_CATALOG

                    entry = next(
                        (e for e in PLAYBOOK_CATALOG if e["playbook_id"] == playbook_id),
                        None,
                    )
                    pb = Playbook(
                        playbook_id=playbook_id,
                        platform_type=(entry or {}).get("platform_type") or "presto",
                        risk_level=(entry or {}).get("risk_level") or "R2",
                        params_schema=(entry or {}).get("params_schema") or {},
                        steps=(entry or {}).get("steps") or {},
                        verification=(entry or {}).get("verification") or {},
                        auto_eligible=False,
                        maturity={"approved_runs": 0, "success": 0, "rollbacks": 0},
                    )
                    session.add(pb)
                    session.flush()
                mat = dict(pb.maturity or {"approved_runs": 0, "success": 0, "rollbacks": 0})
                mat["approved_runs"] = int(mat.get("approved_runs") or 0) + 1
                pb.maturity = mat
                session.add(pb)
            # Insert remediation_executions row (running).
            row = RemediationExecution(
                execution_id=execution_id,
                investigation_id=uuid.UUID(str(investigation_id)),
                playbook_id=playbook_id,
                params=params,
                mode="approved",
                approved_by=uuid.UUID(str(approved_by)) if approved_by else None,
                status="running",
                pre_snapshot=None,
                verification_result=None,
                started_at=datetime.now(timezone.utc),
                finished_at=None,
            )
            session.merge(row)
            session.commit()

        if not playbook_id or playbook_id not in PLAYBOOK_STEPS:
            with self._session_factory() as session:
                self._finish_execution(
                    session,
                    execution_id,
                    status="failed",
                    verification_result={"rollback_note": action.get("rollback_note"), "error": "unknown playbook"},
                )
                write_audit(
                    session,
                    action="remediation_finished",
                    actor=actor_system(),
                    investigation_id=investigation_id,
                    detail={"playbook_id": playbook_id, "ok": False, "error": "unknown playbook"},
                )
                session.commit()
            return {"ok": False, "playbook_id": playbook_id, "execution_id": str(execution_id), "pre_snapshot": {}}

        locators = resolve_locators(deployment, platform_config)
        try:
            steps = PLAYBOOK_STEPS[playbook_id](deployment, params, locators)
        except Exception as exc:  # noqa: BLE001
            with self._session_factory() as session:
                self._finish_execution(
                    session,
                    execution_id,
                    status="failed",
                    verification_result={
                        "rollback_note": action.get("rollback_note"),
                        "error": str(exc),
                    },
                )
                write_audit(
                    session,
                    action="remediation_finished",
                    actor=actor_system(),
                    investigation_id=investigation_id,
                    detail={"playbook_id": playbook_id, "ok": False, "error": str(exc)},
                )
                session.commit()
            return {
                "ok": False,
                "playbook_id": playbook_id,
                "execution_id": str(execution_id),
                "pre_snapshot": {},
                "error": str(exc),
            }

        # Pre-snapshot via read-only Toolpack (kind=tool).
        pre_snapshot: dict[str, Any] = {}
        if platform_key and self._probe is not None:
            for entry in PRE_SNAPSHOT_TOOLS.get(playbook_id, []):
                tool = resolve_runtime_tool(entry["tool"], deployment)
                args = dict(entry.get("args") or {})
                for k in entry.get("args_from") or []:
                    if k in params:
                        args[k] = params[k]
                try:
                    res = await self._probe.execute_tool(platform_key, tool=tool, args=args)
                    pre_snapshot[tool] = res.data
                except Exception as exc:  # noqa: BLE001
                    pre_snapshot[tool] = {"error": str(exc)}
        with self._session_factory() as session:
            row = session.get(RemediationExecution, execution_id)
            if row is not None:
                row.pre_snapshot = pre_snapshot
                session.add(row)
                session.commit()

        # Per-step sign + dispatch.
        if self._signer is None:
            with self._session_factory() as session:
                self._finish_execution(
                    session,
                    execution_id,
                    status="failed",
                    verification_result={
                        "rollback_note": action.get("rollback_note"),
                        "error": "signer not configured",
                    },
                    pre_snapshot=pre_snapshot,
                )
                write_audit(
                    session,
                    action="remediation_finished",
                    actor=actor_system(),
                    investigation_id=investigation_id,
                    detail={"playbook_id": playbook_id, "ok": False, "error": "no signer"},
                )
                session.commit()
            return {
                "ok": False,
                "playbook_id": playbook_id,
                "execution_id": str(execution_id),
                "pre_snapshot": pre_snapshot,
                "error": "signer not configured",
            }

        for idx, step in enumerate(steps):
            op = step["op"]
            step_params = step.get("params") or {}
            digest = canonical_step_hash(
                str(execution_id), playbook_id, idx, op, step_params
            )
            sig = self._signer.sign(digest)
            sig_b64 = base64.b64encode(sig).decode("ascii")
            try:
                result = await self._probe.execute_write(
                    platform_key or "",
                    playbook_id=playbook_id,
                    step_index=idx,
                    op=op,
                    params=step_params,
                    execution_id=str(execution_id),
                    signature_b64=sig_b64,
                )
            except Exception as exc:  # noqa: BLE001
                result_ok = False
                err = str(exc)
            else:
                result_ok = result.exit_code == 0 and not result.error
                if isinstance(result.data, dict) and result.data.get("ok") is False:
                    result_ok = False
                err = result.error or (result.data.get("error") if isinstance(result.data, dict) else None)

            if not result_ok:
                rollback_note = action.get("rollback_note") or (
                    f"step {idx} ({op}) failed; manual rollback may be required"
                )
                with self._session_factory() as session:
                    self._finish_execution(
                        session,
                        execution_id,
                        status="failed",
                        verification_result={
                            "rollback_note": rollback_note,
                            "failed_step": {"index": idx, "op": op, "error": err},
                        },
                        pre_snapshot=pre_snapshot,
                    )
                    write_audit(
                        session,
                        action="remediation_finished",
                        actor=actor_system(),
                        investigation_id=investigation_id,
                        detail={
                            "playbook_id": playbook_id,
                            "ok": False,
                            "failed_step": idx,
                            "op": op,
                            "error": err,
                            "rollback_note": rollback_note,
                        },
                    )
                    session.commit()
                return {
                    "ok": False,
                    "playbook_id": playbook_id,
                    "execution_id": str(execution_id),
                    "pre_snapshot": pre_snapshot,
                    "failed_step": idx,
                    "error": err,
                    "rollback_note": rollback_note,
                }

        with self._session_factory() as session:
            # Leave status=running until verify_fix finalizes succeeded/failed.
            write_audit(
                session,
                action="remediation_finished",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"playbook_id": playbook_id, "ok": True, "steps": len(steps)},
            )
            session.commit()
        return {
            "ok": True,
            "playbook_id": playbook_id,
            "execution_id": str(execution_id),
            "pre_snapshot": pre_snapshot,
            "steps": len(steps),
        }

    def _finish_execution(
        self,
        session,
        execution_id: uuid.UUID,
        *,
        status: str,
        verification_result: dict[str, Any] | None = None,
        pre_snapshot: dict[str, Any] | None = None,
    ) -> None:
        from rca_common.db.models import RemediationExecution

        row = session.get(RemediationExecution, execution_id)
        if row is None:
            return
        row.status = status
        row.finished_at = datetime.now(timezone.utc)
        if verification_result is not None:
            row.verification_result = verification_result
        if pre_snapshot is not None and row.pre_snapshot is None:
            row.pre_snapshot = pre_snapshot
        session.add(row)

    @activity.defn(name="verify_fix")
    async def verify_fix(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Real verify_fix: playbook defaults ∪ RCA plan ∪ canary (Section 9.5.3)."""
        from rca_common.db.models import Playbook, RemediationExecution
        from worker.verification import run_verification

        plan = payload.get("verification_plan") or []
        investigation_id = payload.get("investigation_id")
        execution_id = payload.get("execution_id")
        playbook_id = payload.get("playbook_id") or (payload.get("action") or {}).get("playbook_id")
        params = dict(
            payload.get("params")
            or (payload.get("action") or {}).get("playbook_params")
            or {}
        )
        # Functional/unit tests can still force failure.
        if payload.get("force_fail"):
            ok = False
            result = {"ok": False, "checks": [{"name": "force_fail", "ok": False}]}
        else:
            platform_key = payload.get("platform_key")
            health_query = payload.get("health_query")
            with self._session_factory() as session:
                if not platform_key:
                    try:
                        from rca_common.db.models import Investigation

                        inv = session.get(Investigation, uuid.UUID(str(investigation_id)))
                        if inv is not None:
                            platform_key = inv.platform_key
                            plat = get_platform(session, platform_key)
                            if plat is not None and plat.config:
                                health_query = health_query or (plat.config or {}).get("health_query")
                    except Exception:  # noqa: BLE001
                        pass
            if platform_key and self._probe is not None and playbook_id:
                result = await run_verification(
                    self._probe,
                    platform_key,
                    playbook_id=playbook_id,
                    params=params,
                    verification_plan=plan,
                    health_query=health_query,
                )
                ok = bool(result.get("ok"))
            else:
                # FP-M6-27 / S1: fail closed when required wiring is missing so
                # a regression cannot produce a silent RESOLVED.
                missing: list[str] = []
                if not platform_key:
                    missing.append("platform_key")
                if self._probe is None:
                    missing.append("probe")
                if not playbook_id:
                    missing.append("playbook_id")
                err_msg = "missing wiring: " + ", ".join(missing) if missing else "missing wiring"
                ok = False
                result = {
                    "ok": False,
                    "checks": [{"name": "wiring", "ok": False, "error": err_msg}],
                    "plan": plan,
                }

        with self._session_factory() as session:
            write_audit(
                session,
                action="verification_run",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"plan": plan, "ok": ok, "result": result},
            )
            if execution_id:
                try:
                    eid = uuid.UUID(str(execution_id))
                except Exception:  # noqa: BLE001
                    eid = None
                if eid is not None:
                    row = session.get(RemediationExecution, eid)
                    if row is not None:
                        row.verification_result = result
                        row.status = "succeeded" if ok else "failed"
                        row.finished_at = datetime.now(timezone.utc)
                        session.add(row)
                        if ok and row.playbook_id:
                            pb = session.get(Playbook, row.playbook_id)
                            if pb is not None:
                                mat = dict(pb.maturity or {})
                                mat["success"] = int(mat.get("success") or 0) + 1
                                pb.maturity = mat
                                session.add(pb)
            if ok:
                update_investigation_status(
                    session, uuid.UUID(str(payload["investigation_id"])), "VERIFYING"
                )
            session.commit()
        return {"ok": ok, "plan": plan, **result}

    @activity.defn(name="send_notifications")
    async def send_notifications(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Isolated notification Activity (Section 10.1 / 9.5.3). Never fails the run."""
        from rca_common.notifications import send_to_webhooks

        event = payload.get("event") or "case_resolved"
        notif_payload = dict(payload.get("payload") or payload)
        webhooks: list[Any] = []
        if self._config is not None and getattr(self._config, "notifications", None):
            webhooks = list(self._config.notifications.outbound_webhooks or [])
        if payload.get("webhooks"):
            webhooks = list(payload["webhooks"])
        # Inject dashboard deep link if missing.
        if not notif_payload.get("dashboard_url") and self._dashboard_base_url:
            inv = notif_payload.get("investigation_id")
            notif_payload["dashboard_url"] = (
                f"{self._dashboard_base_url.rstrip('/')}/cases/{inv}" if inv else self._dashboard_base_url
            )
        try:
            results = await send_to_webhooks(webhooks, event, notif_payload)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc), "results": []}

        with self._session_factory() as session:
            for r in results:
                if r.get("ok"):
                    write_audit(
                        session,
                        action="notification_sent",
                        actor=actor_system(),
                        investigation_id=notif_payload.get("investigation_id"),
                        detail={
                            "event": event,
                            "webhook": r.get("name"),
                            "status_code": r.get("status_code"),
                        },
                    )
            session.commit()
        return {"ok": True, "results": results}

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
