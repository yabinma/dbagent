"""InvestigationWorkflow — implementation contract from design.md Section 5.2.

Runs the collect→analyze loop under three-dimensional budget control
(rounds / cost / wall time), handles raw-command and remediation approvals
via Signals, and terminates in one of the Section 5.1 terminal states.
"""
from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

with workflow.unsafe.imports_passed_through():
    # Deterministic pure helpers (no I/O); sandbox-safe for replay.
    from worker.playbooks import resolve_action_settle_seconds


_DEFAULT_RETRY = RetryPolicy(maximum_attempts=3)
_NO_RETRY = RetryPolicy(maximum_attempts=1)


@workflow.defn
class InvestigationWorkflow:
    def __init__(self) -> None:
        self._paused = False
        self._aborted = False
        self._budget_override: dict[str, Any] | None = None
        self._approval_decision: dict[str, Any] | None = None
        # M4 (Section 10.2.3): only apply a signal that matches the gate we are
        # currently waiting on — stops a re-delivered first decision from
        # corrupting a subsequent approval wait.
        self._awaiting_approval_id: str | None = None
        self._status = "RECEIVED"
        self._last_report: dict[str, Any] | None = None
        self._terminal_reason: str | None = None
        self._platform_key: str | None = None
        self._severity: str | None = None

    # ---- signals (Section 5.1 / Appendix D.2 / F6) ------------------------
    @workflow.signal
    def pause(self) -> None:
        if self._status not in _TERMINAL:
            self._paused = True

    @workflow.signal
    def resume(self) -> None:
        self._paused = False

    @workflow.signal
    def abort(self) -> None:
        if self._status not in _TERMINAL:
            self._aborted = True

    @workflow.signal
    def adjust_budget(self, budget: dict[str, Any]) -> None:
        if self._status not in _TERMINAL:
            self._budget_override = dict(budget or {})

    @workflow.signal
    def approval_decided(self, decision: dict[str, Any]) -> None:
        """``{approval_id, decision, comment?}`` from dashboard (M4) or tests.

        M4 awaited-approval-id guard: ignore signals whose approval_id does not
        match the gate currently being awaited (duplicate/late delivery).
        """
        payload = dict(decision or {})
        signal_id = str(payload.get("approval_id") or "")
        if self._awaiting_approval_id is not None and signal_id:
            if signal_id != str(self._awaiting_approval_id):
                return
        self._approval_decision = payload

    @workflow.query
    def get_status(self) -> dict[str, Any]:
        return {
            "status": self._status,
            "paused": self._paused,
            "aborted": self._aborted,
            "terminal_reason": self._terminal_reason,
            "last_report": self._last_report,
        }

    # ---- main ------------------------------------------------------------
    @workflow.run
    async def run(self, input: dict[str, Any]) -> dict[str, Any]:
        event = input["event"]
        investigation_id = input.get("investigation_id")
        workflow_id = workflow.info().workflow_id

        case = await workflow.execute_activity(
            "create_case",
            {
                "event": event,
                "investigation_id": investigation_id,
                "workflow_id": workflow_id,
            },
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=_DEFAULT_RETRY,
        )
        investigation_id = case["investigation_id"]
        budget = dict(case["budget"])
        if self._budget_override:
            budget.update(self._budget_override)
        threshold = float(case.get("confidence_threshold") or 0.85)
        max_calls = int(case.get("max_calls_per_round") or 8)
        self._status = "OPEN"
        self._platform_key = case.get("platform_key") or event.get("platform_key")
        self._severity = event.get("severity") or "unknown"

        # Defense in depth: gateway rejects non-ONLINE platforms before start,
        # but if create_case still reports rejection, terminate as REJECTED and
        # fire case_rejected (FP-M5-10 / Section 9.5.3).
        if case.get("rejected"):
            reason = case.get("reject_reason") or "platform_not_ready"
            result = await workflow.execute_activity(
                "reject_case",
                {
                    "investigation_id": investigation_id,
                    "reason": reason,
                },
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=_DEFAULT_RETRY,
            )
            self._status = "REJECTED"
            self._terminal_reason = reason
            await self._notify(
                "case_rejected",
                {
                    "investigation_id": investigation_id,
                    "platform_key": case.get("platform_key") or event.get("platform_key"),
                    "severity": event.get("severity"),
                    "reason": reason,
                    "summary": f"rejected: {reason}",
                },
            )
            return result

        ctx: dict[str, Any] = {
            "event": event,
            "evidence": [],
            "reports": [],
            "investigation_id": investigation_id,
            "platform_key": case["platform_key"],
            # M4 need_more / denied comments for the next RCA round (Section 10.2.3)
            "approver_feedback": [],
            # Optional platform overrides for settle window (M5).
            "deployment": case.get("deployment") or input.get("deployment"),
            # Full remediation config block for settle_seconds() (FP-M5-8).
            "remediation": dict(case.get("remediation") or {}),
            # Explicit workflow-input override only when the caller set it
            # (None means "use playbook / platform defaults").
            "settle_seconds_override": (
                input["settle_seconds"] if "settle_seconds" in input else None
            ),
        }

        plan = await workflow.execute_activity(
            "plan_initial",
            {
                "event": event,
                "investigation_id": investigation_id,
                "max_calls_per_round": max_calls,
                "round": 0,
            },
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_DEFAULT_RETRY,
        )

        deadline = workflow.now() + timedelta(seconds=int(budget.get("max_wall_seconds", 1800)))
        max_rounds = int(budget.get("max_rounds", 15))
        max_cost = float(budget.get("max_cost_usd", 10.0))

        self._status = "INVESTIGATING"
        concluded = False

        for round_num in range(1, max_rounds + 1):
            await self._wait_if_paused()
            if self._aborted:
                return await self._needs_human(ctx, "aborted")

            if workflow.now() >= deadline:
                return await self._needs_human(ctx, "time_budget")

            spent = await workflow.execute_activity(
                "get_spend",
                {"investigation_id": investigation_id},
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=_DEFAULT_RETRY,
            )
            if float(spent) >= max_cost:
                return await self._needs_human(ctx, "cost_budget")

            if self._budget_override:
                budget.update(self._budget_override)
                max_rounds = int(budget.get("max_rounds", max_rounds))
                max_cost = float(budget.get("max_cost_usd", max_cost))
                if "max_wall_seconds" in self._budget_override:
                    deadline = workflow.now() + timedelta(
                        seconds=int(self._budget_override["max_wall_seconds"])
                    )
                self._budget_override = None

            new_evidence = await workflow.execute_activity(
                "collect",
                {
                    "plan": plan,
                    "investigation_id": investigation_id,
                    "platform_key": ctx["platform_key"],
                    "round": round_num,
                    "max_calls_per_round": max_calls,
                },
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_DEFAULT_RETRY,
            )
            ctx["evidence"].extend(new_evidence or [])

            report = await workflow.execute_activity(
                "analyze",
                {
                    "event": event,
                    "evidence": ctx["evidence"],
                    "reports": ctx["reports"],
                    "round": round_num,
                    "budget": budget,
                    "spent_usd": float(spent),
                    "investigation_id": investigation_id,
                    "approver_feedback": list(ctx.get("approver_feedback") or []),
                },
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_DEFAULT_RETRY,
            )
            # Strip internal metrics before persisting as the report of record.
            metrics = report.pop("_context_metrics", None)
            ctx["reports"].append(report)
            self._last_report = report

            await workflow.execute_activity(
                "record_iteration",
                {
                    "investigation_id": investigation_id,
                    "round": round_num,
                    "plan": plan,
                    "report": report,
                    "cost_usd": None,
                    "duration_ms": int(metrics["build_ms"]) if metrics else None,
                },
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=_DEFAULT_RETRY,
            )

            # Raw-command gate (Section 8.2 / F5)
            for req in report.get("raw_command_requests") or []:
                validation = await workflow.execute_activity(
                    "static_validate_raw_command",
                    {
                        "command": req.get("command"),
                        "investigation_id": investigation_id,
                    },
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=_DEFAULT_RETRY,
                )
                if not validation.get("ok"):
                    continue
                decision = await self._request_approval(
                    "raw_command",
                    req,
                    investigation_id,
                    timeout=timedelta(hours=24),
                )
                # need_more / commented deny feed the next RCA round (Section 10.2.3)
                if (
                    decision.get("decision") in ("need_more", "denied")
                    and (decision.get("comment") or "").strip()
                ):
                    ctx.setdefault("approver_feedback", []).append(
                        str(decision["comment"]).strip()
                    )
                if decision.get("decision") == "approved":
                    extra = await workflow.execute_activity(
                        "run_raw_command",
                        {
                            "investigation_id": investigation_id,
                            "platform_key": ctx["platform_key"],
                            "command": req.get("command"),
                            "round": round_num,
                        },
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=_DEFAULT_RETRY,
                    )
                    ctx["evidence"].extend(extra or [])

            if report.get("status") == "concluded" and float(report.get("confidence") or 0) >= threshold:
                concluded = True
                break
            if report.get("status") == "inconclusive" and not report.get("missing_info"):
                return await self._needs_human(ctx, "inconclusive")

            plan = await workflow.execute_activity(
                "plan_next",
                {
                    "event": event,
                    "investigation_id": investigation_id,
                    "max_calls_per_round": max_calls,
                    "round": round_num,
                    "missing_info": report.get("missing_info") or [],
                    "evidence_summaries": [
                        {"evidence_id": e.get("evidence_id"), "summary": e.get("summary")}
                        for e in ctx["evidence"]
                    ],
                },
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_DEFAULT_RETRY,
            )
        else:
            # for-else: loop exhausted without break
            if not concluded:
                return await self._needs_human(ctx, "round_budget")

        # Remediation planning
        remediation = await workflow.execute_activity(
            "plan_remediation",
            {
                "investigation_id": investigation_id,
                "rca_report": self._last_report,
            },
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_DEFAULT_RETRY,
        )
        actions = list(remediation.get("proposed_actions") or [])
        if self._last_report is not None and remediation.get("rca_compact"):
            self._last_report = {**self._last_report, "rca_compact": remediation["rca_compact"]}

        if not actions or all(
            a.get("kind") in ("ignore", "manual_recommendation", "code_fix_recommendation")
            for a in actions
        ):
            result = await workflow.execute_activity(
                "close_with_summary",
                {
                    "investigation_id": investigation_id,
                    "rca_report": self._last_report,
                    "actions": actions,
                    "reason": "summary_only",
                },
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=_DEFAULT_RETRY,
            )
            self._status = "CLOSED_SUMMARY"
            return {**result, "rca_report": self._last_report}

        # RESOLVED only if at least one playbook was approved+executed+verified
        # (design.md v1.8 Section 5.1/5.2 `executed_any` gate). Deny/timeout of
        # every playbook closes via close_with_summary → CLOSED_SUMMARY.
        executed_any = False
        applied_playbooks: list[str] = []
        for action in [a for a in actions if a.get("kind") == "playbook"]:
            decision = await self._request_approval(
                "remediation",
                action,
                investigation_id,
                timeout=timedelta(days=7),
            )
            if decision.get("decision") != "approved":
                continue
            playbook_result = await workflow.execute_activity(
                "execute_playbook",
                {
                    "investigation_id": investigation_id,
                    "action": action,
                    "platform_key": ctx.get("platform_key"),
                    "deployment": ctx.get("deployment"),
                    "approved_by": decision.get("decided_by"),
                },
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_NO_RETRY,
            )
            if not playbook_result.get("ok"):
                return await self._needs_human(ctx, "playbook_failed")
            # Settle wait window as a durable Temporal timer (Section 9.5.3 / FP-M5-8).
            # Defaults: 120 s for restart playbooks, 0 s for kill_query (see
            # worker.playbooks.resolve_action_settle_seconds).
            settle = resolve_action_settle_seconds(
                action,
                remediation_config=ctx.get("remediation") or {},
                input_override=ctx.get("settle_seconds_override"),
            )
            if settle > 0:
                await workflow.sleep(timedelta(seconds=settle))
            verified = await workflow.execute_activity(
                "verify_fix",
                {
                    "investigation_id": investigation_id,
                    "verification_plan": action.get("verification_plan") or [],
                    "force_fail": action.get("_force_verify_fail", False),
                    "execution_id": playbook_result.get("execution_id"),
                    "playbook_id": action.get("playbook_id"),
                    "action": action,
                    "platform_key": ctx.get("platform_key"),
                    "params": action.get("playbook_params") or {},
                },
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_DEFAULT_RETRY,
            )
            if not verified.get("ok"):
                return await self._needs_human(ctx, "verification_failed")
            executed_any = True
            if action.get("playbook_id"):
                applied_playbooks.append(action["playbook_id"])

        if executed_any:
            result = await workflow.execute_activity(
                "close_resolved",
                {
                    "investigation_id": investigation_id,
                    "rca_report": self._last_report,
                },
                start_to_close_timeout=timedelta(seconds=60),
                retry_policy=_DEFAULT_RETRY,
            )
            self._status = "RESOLVED"
            await self._notify(
                "case_resolved",
                {
                    "investigation_id": investigation_id,
                    "platform_key": ctx.get("platform_key"),
                    "severity": (ctx.get("event") or {}).get("severity"),
                    "rca_compact": (self._last_report or {}).get("rca_compact"),
                    "summary": (self._last_report or {}).get("rca_compact"),
                    "playbooks": applied_playbooks,
                },
            )
            return {**result, "rca_report": self._last_report}

        result = await workflow.execute_activity(
            "close_with_summary",
            {
                "investigation_id": investigation_id,
                "rca_report": self._last_report,
                "actions": actions,
                "reason": "remediation_denied",
            },
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=_DEFAULT_RETRY,
        )
        self._status = "CLOSED_SUMMARY"
        return {**result, "rca_report": self._last_report}

    async def _wait_if_paused(self) -> None:
        while self._paused and not self._aborted:
            await workflow.wait_condition(lambda: (not self._paused) or self._aborted)

    async def _request_approval(
        self,
        kind: str,
        subject: dict[str, Any],
        investigation_id: str,
        *,
        timeout: timedelta,
    ) -> dict[str, Any]:
        self._approval_decision = None
        approval = await workflow.execute_activity(
            "create_approval",
            {
                "investigation_id": investigation_id,
                "kind": kind,
                "subject": subject,
            },
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=_DEFAULT_RETRY,
        )
        approval_id = str(approval["approval_id"])
        self._awaiting_approval_id = approval_id
        self._status = "AWAITING_APPROVAL"
        # Non-blocking notification (Section 9.5.3); failures are swallowed.
        await self._notify(
            "approval_requested",
            {
                "investigation_id": investigation_id,
                "platform_key": self._platform_key,
                "severity": self._severity,
                "summary": f"{kind} approval requested",
                "digest": subject.get("playbook_id") or subject.get("command") or kind,
                "approval_kind": kind,
            },
        )
        try:
            # Gate on matching approval_id so a late/duplicate signal for a
            # *prior* approval that landed during create_approval (when
            # _awaiting_approval_id was still None) cannot satisfy this wait.
            await workflow.wait_condition(
                lambda: self._approval_decision is not None
                and str(self._approval_decision.get("approval_id") or "")
                == approval_id,
                timeout=timeout,
            )
            decision = dict(self._approval_decision or {})
            # Human path (dashboard already wrote decision + user-actor audits).
            is_timeout = False
        except asyncio.TimeoutError:
            decision = {
                "approval_id": approval["approval_id"],
                "decision": "denied",
                "comment": "timeout",
            }
            is_timeout = True
        decision.setdefault("approval_id", approval["approval_id"])
        self._awaiting_approval_id = None
        await workflow.execute_activity(
            "record_approval_decision",
            {
                "investigation_id": investigation_id,
                "approval_id": decision.get("approval_id"),
                "decision": decision.get("decision"),
                "comment": decision.get("comment"),
                "kind": kind,
                # M4: only the timeout path is the "decider"; human path skips
                # re-writing decision/audits so user:<id> actor is preserved.
                "is_timeout": is_timeout,
            },
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_DEFAULT_RETRY,
        )
        self._status = "INVESTIGATING"
        return decision

    async def _needs_human(self, ctx: dict[str, Any], reason: str) -> dict[str, Any]:
        result = await workflow.execute_activity(
            "to_needs_human",
            {
                "investigation_id": ctx["investigation_id"],
                "reason": reason,
                "rca_report": self._last_report,
            },
            start_to_close_timeout=timedelta(seconds=60),
            retry_policy=_DEFAULT_RETRY,
        )
        self._status = "NEEDS_HUMAN"
        self._terminal_reason = reason
        await self._notify(
            "case_needs_human",
            {
                "investigation_id": ctx.get("investigation_id"),
                "platform_key": ctx.get("platform_key"),
                "severity": (ctx.get("event") or {}).get("severity"),
                "reason": reason,
                "rca_compact": (self._last_report or {}).get("rca_compact"),
                "summary": f"needs human: {reason}",
            },
        )
        return {**result, "rca_report": self._last_report}

    async def _notify(self, event: str, payload: dict[str, Any]) -> None:
        """Schedule send_notifications; never fail the main flow (Section 10.1)."""
        try:
            await workflow.execute_activity(
                "send_notifications",
                {"event": event, "payload": payload},
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=3),
            )
        except Exception:  # noqa: BLE001 — never block the main flow
            pass


_TERMINAL = frozenset({"REJECTED", "NEEDS_HUMAN", "CLOSED_SUMMARY", "RESOLVED"})
