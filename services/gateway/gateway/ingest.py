"""Webhook ingest + fingerprint correlation (design.md Section 4.1, §11.3).

Responses:
- ``202 {investigation_id}`` opened
- ``200 {status: merged, investigation_id}`` correlated into open case
- ``200 {status: rejected, reason}`` platform not ready / unknown platform

FP-IG-5: the database transaction runs off the event loop via
``run_in_threadpool``. FP-IG-16: open-path correlation uses a transaction-
scoped advisory lock with a lock-free merge fast path.

FP-GC2-1/2/3: that lock-free fast path is one parameterized data-modifying
statement (``merge_existing_event_with_audit``) which selects the same
candidate as ``find_open_by_fingerprint`` and inserts both the merged event
and its ``event_merged`` audit row; a miss writes nothing and continues on
the unchanged reject / advisory-lock / deciding-re-read / open path.

FP-GC5-1/2/3: that one statement now runs inside a per-worker group. Up to
``MERGE_COMMIT_BATCH_SIZE`` candidates collected for at most
``MERGE_COMMIT_MAX_WAIT_SECONDS`` share one outer transaction, each inside its
own savepoint, and one stock-durability outer commit fences every 2xx in the
group. A candidate whose statement finds no committed case leaves the group
without a write and continues on the unchanged individual reject /
advisory-lock / deciding-re-read / open transaction.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Protocol, Sequence

from starlette.concurrency import run_in_threadpool

from gateway.merge_commit import MergeCommitCoalescer, MergeHit, MergeMiss
from rca_common.audit import actor_system, write_audit
from rca_common.fingerprint import compute_fingerprint
from rca_common.investigation_repo import (
    acquire_correlation_lock,
    create_investigation,
    find_open_by_fingerprint,
    get_platform,
    insert_alert_event,
    merge_existing_event_with_audit,
    merge_platform_budget,
)


class WorkflowStarter(Protocol):
    async def start_investigation(self, event: dict[str, Any], investigation_id: uuid.UUID) -> str:
        """Start InvestigationWorkflow; return workflow_id."""


class IngestService:
    def __init__(
        self,
        session_factory,
        *,
        budget_defaults: dict[str, Any],
        correlation_window_seconds: int = 1800,
        known_sources: dict[str, str] | None = None,
        workflow_starter: WorkflowStarter | None = None,
    ):
        self._session_factory = session_factory
        self._budget_defaults = budget_defaults
        self._correlation_window_seconds = correlation_window_seconds
        self._known_sources = known_sources or {}
        self._workflow_starter = workflow_starter
        # FP-GC5-1: exactly one FIFO coalescer per service, and so exactly one
        # per independently spawned uvicorn worker. It owns no engine, Session
        # or connection; this bound callback owns database execution.
        self._merge_coalescer = MergeCommitCoalescer(self._execute_merge_batch)

    def normalize_payload(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Build a Section 4.1 AlertEvent from a webhook JSON body."""
        event_id = raw.get("event_id") or str(uuid.uuid4())
        occurred_at = raw.get("occurred_at") or datetime.now(timezone.utc).isoformat()
        platform_key = raw.get("platform_key") or ""
        error_summary = raw.get("error_summary") or ""
        fingerprint = raw.get("fingerprint") or compute_fingerprint(platform_key, error_summary)
        event = {
            "event_id": str(event_id),
            "source": raw.get("source") or "",
            "platform_key": platform_key,
            "error_summary": error_summary,
            "error_detail": raw.get("error_detail"),
            "occurred_at": occurred_at,
            "reporter": raw.get("reporter"),
            "severity": raw.get("severity") or "unknown",
            "labels": raw.get("labels") or {},
            "fingerprint": fingerprint,
        }
        return event

    async def ingest(self, raw: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        event = self.normalize_payload(raw)
        if not event["platform_key"]:
            return 200, {"status": "rejected", "reason": "missing_platform_key"}
        if not event["error_summary"]:
            return 200, {"status": "rejected", "reason": "missing_error_summary"}
        if event["source"] and self._known_sources and event["source"] not in self._known_sources:
            return 200, {"status": "rejected", "reason": "unknown_source"}

        # FP-GC5-1/3: the dominant request is offered to this worker's one
        # coalescer. A hit's outer transaction has already committed durably
        # when the group resolves; a miss has written nothing and takes the
        # unchanged individual transaction below, exactly once.
        outcome = await self._merge_coalescer.submit(event)
        if isinstance(outcome, MergeHit):
            return 200, {
                "status": "merged",
                "investigation_id": str(outcome.investigation_id),
            }

        status, payload, investigation_id = await run_in_threadpool(self._ingest_txn, event)
        if investigation_id is not None and self._workflow_starter is not None:
            await self._workflow_starter.start_investigation(event, investigation_id)
        return status, payload

    async def close(self) -> None:
        """FP-GC5-5: stop admission and resolve every accepted merge item."""
        await self._merge_coalescer.close()

    def _execute_merge_batch(self, events: Sequence[dict[str, Any]]) -> list[Any]:
        """One group of candidates, one Session, at most one durable commit.

        FP-GC5-1/2: each candidate runs the unchanged fused statement once
        inside its own savepoint, in FIFO order. A statement failure whose
        savepoint rollback leaves the outer transaction usable belongs to that
        one request; a failed savepoint recovery, an unusable outer
        transaction or a failed outer commit fails every unresolved member of
        the group and is never retried. Plain synchronous method: the drainer
        reaches it only through ``run_in_threadpool``.
        """
        outcomes: list[Any] = [None] * len(events)
        fatal: BaseException | None = None
        with self._session_factory() as session:
            for index, event in enumerate(events):
                if fatal is not None:
                    break
                savepoint = session.begin_nested()
                try:
                    existing_id = merge_existing_event_with_audit(
                        session,
                        event=event,
                        default_correlation_window_seconds=self._correlation_window_seconds,
                    )
                except BaseException as exc:  # noqa: BLE001 — one request's own failure
                    outcomes[index] = exc
                    fatal = self._recover_savepoint(session, savepoint, exc)
                else:
                    savepoint.commit()
                    outcomes[index] = (
                        MergeHit(existing_id) if existing_id is not None else MergeMiss()
                    )
            fatal = self._finish_merge_batch(session, outcomes, fatal)
        if fatal is not None:
            # Members that already carry their own failure keep it; every
            # unresolved member fails with the group.
            outcomes = [
                outcome if isinstance(outcome, BaseException) else fatal
                for outcome in outcomes
            ]
        return outcomes

    @staticmethod
    def _recover_savepoint(session, savepoint, exc: BaseException):
        """Roll one candidate back; return a group-fatal failure or ``None``.

        A successful rollback to savepoint that leaves the outer transaction
        active is the proof that the surrounding transaction is still usable,
        so unrelated hits keep their isolation. Losing that proof is the only
        thing that widens one request's failure to the whole group.
        """
        try:
            savepoint.rollback()
        except BaseException as recovery_error:  # noqa: BLE001 — group-fatal
            return recovery_error
        if not session.is_active:
            return exc
        return None

    @staticmethod
    def _finish_merge_batch(session, outcomes: list[Any], fatal: BaseException | None):
        """Close the shared transaction: one commit, or an explicit rollback."""
        if fatal is not None:
            _rollback_quietly(session)
            return fatal
        if any(isinstance(outcome, MergeHit) for outcome in outcomes):
            try:
                session.commit()
            except BaseException as commit_error:  # noqa: BLE001 — group-fatal
                _rollback_quietly(session)
                return commit_error
            return None
        # No hit: the read-only outer transaction is rolled back explicitly,
        # so a group of misses never manufactures a committed transaction.
        session.rollback()
        return None

    def _ingest_txn(
        self, event: dict[str, Any]
    ) -> tuple[int, dict[str, Any], uuid.UUID | None]:
        """Synchronous DB transaction; invoked via run_in_threadpool (FP-IG-5).

        FP-GC5-3: reached only after the shared group transaction ended with a
        miss for this event. The fused statement is not repeated here: another
        request may have opened a case since, and the deciding re-read under
        the advisory lock below is the authoritative race resolver.
        """
        with self._session_factory() as session:
            platform = get_platform(session, event["platform_key"])
            if platform is None:
                self._reject(session, event, "unknown_platform_key")
                session.commit()
                return 200, {"status": "rejected", "reason": "unknown_platform_key"}, None
            if (platform.status or "").lower() != "online":
                self._reject(session, event, "platform_not_ready")
                session.commit()
                return 200, {"status": "rejected", "reason": "platform_not_ready"}, None

            # Per-platform correlation window override.
            window = self._correlation_window_seconds
            cfg = platform.config or {}
            if "correlation_window_seconds" in cfg:
                window = int(cfg["correlation_window_seconds"])
            elif "correlation_window" in cfg:
                window = int(cfg["correlation_window"])

            # Open path: advisory lock then re-read under the lock. The
            # lock-free read-and-merge already happened above as one
            # statement, so no second pre-lock lookup is emitted here.
            acquire_correlation_lock(session, event["platform_key"], event["fingerprint"])
            existing = find_open_by_fingerprint(
                session,
                fingerprint=event["fingerprint"],
                platform_key=event["platform_key"],
                correlation_window_seconds=window,
            )
            if existing is not None:
                insert_alert_event(
                    session,
                    event_id=uuid.UUID(event["event_id"]),
                    fingerprint=event["fingerprint"],
                    source=event["source"],
                    platform_key=event["platform_key"],
                    severity=event["severity"],
                    payload_ref=None,
                    normalized=event,
                    disposition="merged",
                    investigation_id=existing.investigation_id,
                )
                write_audit(
                    session,
                    action="event_merged",
                    actor=actor_system(),
                    investigation_id=existing.investigation_id,
                    detail={"event_id": event["event_id"], "fingerprint": event["fingerprint"]},
                )
                session.commit()
                return 200, {
                    "status": "merged",
                    "investigation_id": str(existing.investigation_id),
                }, None

            investigation_id = uuid.uuid4()
            budget = merge_platform_budget(
                {
                    "max_rounds": self._budget_defaults.get("max_rounds", 15),
                    "max_cost_usd": self._budget_defaults.get("max_cost_usd", 10.0),
                    "max_wall_seconds": self._budget_defaults.get("max_wall_seconds", 1800),
                },
                platform.config,
            )
            workflow_id = f"investigation-{investigation_id}"
            insert_alert_event(
                session,
                event_id=uuid.UUID(event["event_id"]),
                fingerprint=event["fingerprint"],
                source=event["source"],
                platform_key=event["platform_key"],
                severity=event["severity"],
                payload_ref=None,
                normalized=event,
                disposition="opened",
                investigation_id=investigation_id,
            )
            write_audit(
                session,
                action="event_received",
                actor=actor_system(),
                investigation_id=investigation_id,
                detail={"event_id": event["event_id"], "fingerprint": event["fingerprint"]},
            )
            create_investigation(
                session,
                investigation_id=investigation_id,
                platform_key=event["platform_key"],
                status="RECEIVED",
                trigger_event=uuid.UUID(event["event_id"]),
                workflow_id=workflow_id,
                budget=budget,
            )
            session.commit()
            return 202, {"investigation_id": str(investigation_id)}, investigation_id

    def _reject(self, session, event: dict[str, Any], reason: str) -> None:
        insert_alert_event(
            session,
            event_id=uuid.UUID(event["event_id"]),
            fingerprint=event["fingerprint"],
            source=event.get("source"),
            platform_key=event.get("platform_key"),
            severity=event.get("severity"),
            payload_ref=None,
            normalized=event,
            disposition="rejected",
            investigation_id=None,
            reject_reason=reason,
        )
        write_audit(
            session,
            action="event_rejected",
            actor=actor_system(),
            investigation_id=None,
            detail={"event_id": event["event_id"], "reason": reason},
        )


def _rollback_quietly(session) -> None:
    """Best-effort outer rollback after a failure that already decided the group."""
    try:
        session.rollback()
    except BaseException:  # noqa: BLE001 — the group has already failed
        pass
