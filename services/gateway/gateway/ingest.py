"""Webhook ingest + fingerprint correlation (design.md Section 4.1).

Responses:
- ``202 {investigation_id}`` opened
- ``200 {status: merged, investigation_id}`` correlated into open case
- ``200 {status: rejected, reason}`` platform not ready / unknown platform
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Protocol

from rca_common.audit import actor_system, write_audit
from rca_common.fingerprint import compute_fingerprint
from rca_common.investigation_repo import (
    find_open_by_fingerprint,
    get_platform,
    insert_alert_event,
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

        with self._session_factory() as session:
            platform = get_platform(session, event["platform_key"])
            if platform is None:
                self._reject(session, event, "unknown_platform_key")
                session.commit()
                return 200, {"status": "rejected", "reason": "unknown_platform_key"}
            if (platform.status or "").lower() != "online":
                self._reject(session, event, "platform_not_ready")
                session.commit()
                return 200, {"status": "rejected", "reason": "platform_not_ready"}

            # Per-platform correlation window override.
            window = self._correlation_window_seconds
            cfg = platform.config or {}
            if "correlation_window_seconds" in cfg:
                window = int(cfg["correlation_window_seconds"])
            elif "correlation_window" in cfg:
                window = int(cfg["correlation_window"])

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
                }

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
            # Persist a RECEIVED investigation row so correlation can find it
            # even before the workflow's create_case activity runs.
            from rca_common.investigation_repo import create_investigation

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

        if self._workflow_starter is not None:
            await self._workflow_starter.start_investigation(event, investigation_id)

        return 202, {"investigation_id": str(investigation_id)}

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
