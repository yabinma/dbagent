"""Persistence helpers for investigations, evidence, iterations, and
approvals (design.md Section 4.3 / 5.2). Used by temporal-worker Activities
and the ingest-gateway correlation path.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from rca_common.audit import actor_system, write_audit
from rca_common.db.models import (
    AlertEventRow,
    Approval,
    Evidence,
    Investigation,
    Iteration,
    Platform,
)

# Non-terminal investigation statuses that still accept correlation merges
# (design.md Section 4.1 / 5.1).
NON_TERMINAL_STATUSES = frozenset(
    {
        "RECEIVED",
        "OPEN",
        "INVESTIGATING",
        "AWAITING_APPROVAL",
        "EXECUTING",
        "VERIFYING",
    }
)

TERMINAL_STATUSES = frozenset(
    {
        "REJECTED",
        "NEEDS_HUMAN",
        "CLOSED_SUMMARY",
        "RESOLVED",
    }
)


def get_platform(session: Session, platform_key: str) -> Platform | None:
    return session.get(Platform, platform_key)


def find_open_by_fingerprint(
    session: Session,
    *,
    fingerprint: str,
    platform_key: str,
    correlation_window_seconds: int,
    now: datetime | None = None,
) -> Investigation | None:
    """Return the most recent non-terminal investigation whose trigger
    (or a related event) shares ``fingerprint`` inside the correlation window.
    """
    now = now or datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=correlation_window_seconds)

    # Prefer matching via alert_events (covers both opened + merged rows).
    stmt = (
        select(AlertEventRow)
        .where(
            AlertEventRow.fingerprint == fingerprint,
            AlertEventRow.platform_key == platform_key,
            AlertEventRow.investigation_id.is_not(None),
            AlertEventRow.received_at >= window_start,
        )
        .order_by(AlertEventRow.received_at.desc())
    )
    for event in session.scalars(stmt):
        inv = _latest_investigation(session, event.investigation_id)
        if inv is not None and inv.status in NON_TERMINAL_STATUSES:
            return inv
    return None


def _latest_investigation(session: Session, investigation_id: uuid.UUID) -> Investigation | None:
    stmt = (
        select(Investigation)
        .where(Investigation.investigation_id == investigation_id)
        .order_by(Investigation.created_at.desc())
        .limit(1)
    )
    return session.scalars(stmt).first()


def create_investigation(
    session: Session,
    *,
    investigation_id: uuid.UUID,
    platform_key: str,
    status: str,
    trigger_event: uuid.UUID | None,
    workflow_id: str,
    budget: dict[str, Any],
    spent: dict[str, Any] | None = None,
) -> Investigation:
    inv = Investigation(
        investigation_id=investigation_id,
        created_at=datetime.now(timezone.utc),
        platform_key=platform_key,
        status=status,
        trigger_event=trigger_event,
        workflow_id=workflow_id,
        budget=budget,
        spent=spent or {"rounds": 0, "cost_usd": 0},
    )
    session.add(inv)
    return inv


def update_investigation_status(
    session: Session,
    investigation_id: uuid.UUID,
    status: str,
    *,
    rca_report: dict[str, Any] | None = None,
    spent: dict[str, Any] | None = None,
    close: bool = False,
) -> None:
    inv = _latest_investigation(session, investigation_id)
    if inv is None:
        raise KeyError(f"investigation {investigation_id} not found")
    inv.status = status
    if rca_report is not None:
        inv.rca_report = rca_report
    if spent is not None:
        inv.spent = spent
    if close or status in TERMINAL_STATUSES:
        inv.closed_at = datetime.now(timezone.utc)


def insert_alert_event(
    session: Session,
    *,
    event_id: uuid.UUID,
    fingerprint: str,
    source: str | None,
    platform_key: str | None,
    severity: str | None,
    payload_ref: str | None,
    normalized: dict[str, Any],
    disposition: str,
    investigation_id: uuid.UUID | None,
    reject_reason: str | None = None,
) -> AlertEventRow:
    row = AlertEventRow(
        event_id=event_id,
        fingerprint=fingerprint,
        source=source,
        platform_key=platform_key,
        severity=severity,
        payload_ref=payload_ref,
        normalized=normalized,
        disposition=disposition,
        investigation_id=investigation_id,
        reject_reason=reject_reason,
        received_at=datetime.now(timezone.utc),
    )
    session.add(row)
    return row


def record_iteration(
    session: Session,
    *,
    investigation_id: uuid.UUID,
    round_num: int,
    plan: dict[str, Any],
    rca_output: dict[str, Any] | None,
    cost_usd: float | None = None,
    duration_ms: int | None = None,
    started_at: datetime | None = None,
    finished_at: datetime | None = None,
) -> Iteration:
    row = Iteration(
        investigation_id=investigation_id,
        round=round_num,
        plan=plan,
        rca_output=rca_output,
        cost_usd=cost_usd,
        duration_ms=duration_ms,
        started_at=started_at or datetime.now(timezone.utc),
        finished_at=finished_at or datetime.now(timezone.utc),
    )
    session.add(row)
    return row


def insert_evidence(
    session: Session,
    *,
    evidence_id: uuid.UUID | None = None,
    investigation_id: uuid.UUID,
    round_num: int,
    tool_name: str,
    args: dict[str, Any] | None,
    exit_code: int | None,
    summary: str | None,
    payload_ref: str | None,
    payload_bytes: int | None,
    redacted: bool = False,
    executed_by: str | None = None,
) -> Evidence:
    row = Evidence(
        evidence_id=evidence_id or uuid.uuid4(),
        investigation_id=investigation_id,
        round=round_num,
        tool_name=tool_name,
        args=args,
        exit_code=exit_code,
        summary=summary,
        payload_ref=payload_ref,
        payload_bytes=payload_bytes,
        redacted=redacted,
        executed_by=executed_by,
        created_at=datetime.now(timezone.utc),
    )
    session.add(row)
    return row


def get_evidence(session: Session, evidence_id: uuid.UUID | str) -> Evidence | None:
    try:
        eid = uuid.UUID(str(evidence_id))
    except (ValueError, AttributeError, TypeError):
        return None
    return session.get(Evidence, eid)


def create_approval(
    session: Session,
    *,
    approval_id: uuid.UUID | None = None,
    investigation_id: uuid.UUID,
    kind: str,
    subject: dict[str, Any],
) -> Approval:
    row = Approval(
        approval_id=approval_id or uuid.uuid4(),
        investigation_id=investigation_id,
        kind=kind,
        subject=subject,
        decision=None,
        created_at=datetime.now(timezone.utc),
    )
    session.add(row)
    return row


def decide_approval(
    session: Session,
    approval_id: uuid.UUID | str,
    *,
    decision: str,
    decided_by: uuid.UUID | None = None,
    comment: str | None = None,
) -> Approval:
    row = session.get(Approval, uuid.UUID(str(approval_id)))
    if row is None:
        raise KeyError(f"approval {approval_id} not found")
    if row.decision is not None:
        raise ValueError("approval already decided")
    row.decision = decision
    row.decided_by = decided_by
    row.comment = comment
    row.decided_at = datetime.now(timezone.utc)
    return row


def merge_platform_budget(
    defaults: dict[str, Any],
    platform_config: dict[str, Any] | None,
) -> dict[str, Any]:
    """Per-platform budget overrides take precedence (Appendix E / F4)."""
    budget = dict(defaults)
    if not platform_config:
        return budget
    overrides = platform_config.get("budget") or platform_config.get("budget_defaults") or {}
    for key in ("max_rounds", "max_cost_usd", "max_wall_seconds"):
        if key in overrides:
            budget[key] = overrides[key]
    return budget


def open_case_from_event(
    session: Session,
    *,
    event: dict[str, Any],
    workflow_id: str,
    budget: dict[str, Any],
    investigation_id: uuid.UUID | None = None,
) -> Investigation:
    """Create investigation in OPEN + write case_opened audit."""
    inv_id = investigation_id or uuid.uuid4()
    event_id = uuid.UUID(str(event["event_id"])) if event.get("event_id") else uuid.uuid4()
    inv = create_investigation(
        session,
        investigation_id=inv_id,
        platform_key=event["platform_key"],
        status="OPEN",
        trigger_event=event_id,
        workflow_id=workflow_id,
        budget=budget,
    )
    write_audit(
        session,
        action="case_opened",
        actor=actor_system(),
        investigation_id=inv_id,
        detail={"platform_key": event["platform_key"], "workflow_id": workflow_id},
    )
    return inv
