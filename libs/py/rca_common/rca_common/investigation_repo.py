"""Persistence helpers for investigations, evidence, iterations, and
approvals (design.md Section 4.3 / 5.2). Used by temporal-worker Activities
and the ingest-gateway correlation path.
"""
from __future__ import annotations

import hashlib
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select, text, update
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


def correlation_lock_key(platform_key: str, fingerprint: str) -> int:
    """Deterministic signed 64-bit advisory-lock key for one correlation slot.

    BLAKE2b digest of ``platform_key + "\\x00" + fingerprint``, first 8 bytes
    as a signed big-endian int64 (design.md §11.3.3 O / FP-IG-16).
    """
    digest = hashlib.blake2b(
        (platform_key + "\x00" + fingerprint).encode("utf-8"), digest_size=8
    ).digest()
    return struct.unpack(">q", digest)[0]


def acquire_correlation_lock(session: Session, platform_key: str, fingerprint: str) -> None:
    """``SELECT pg_advisory_xact_lock(:key)`` — released at COMMIT or ROLLBACK.

    Session-scoped ``pg_advisory_lock`` is forbidden: a pooled connection
    returned while holding one leaks the lock for the process lifetime.
    """
    key = correlation_lock_key(platform_key, fingerprint)
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def find_open_by_fingerprint_stmt(
    *,
    fingerprint: str,
    platform_key: str,
    correlation_window_seconds: int,
    now: datetime | None = None,
):
    """Build the production correlation SELECT (FP-IG-6 / FP-IG-17).

    Factored so FP-IG-17 can EXPLAIN the exact statement the product emits,
    rather than a hand-written facsimile (C6).
    """
    now = now or datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=correlation_window_seconds)
    # Drive FROM alert_events so the planner can use the (fingerprint,
    # received_at) index for both the equality filter and ORDER BY … LIMIT 1
    # as an Index Scan (FP-IG-6 (c) / FP-IG-17). Starting from investigations
    # forces a Bitmap Heap Scan + Sort on small fixtures.
    return (
        select(Investigation)
        .select_from(AlertEventRow)
        .join(
            Investigation,
            AlertEventRow.investigation_id == Investigation.investigation_id,
        )
        .where(
            AlertEventRow.fingerprint == fingerprint,
            AlertEventRow.platform_key == platform_key,
            AlertEventRow.investigation_id.is_not(None),
            AlertEventRow.received_at >= window_start,
            Investigation.status.in_(tuple(NON_TERMINAL_STATUSES)),
        )
        # Order by received_at only so the (fingerprint, received_at) index can
        # satisfy ORDER BY … LIMIT 1 without an Incremental Sort that pulls an
        # extra row (FP-IG-6 (c) / FP-IG-17: one row examined on the active shape).
        .order_by(AlertEventRow.received_at.desc())
        .limit(1)
    )


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

    FP-IG-6: one round trip, at most one ORM row, LIMIT 1 join on non-terminal
    investigations ordered by alert_events.received_at DESC.
    """
    stmt = find_open_by_fingerprint_stmt(
        fingerprint=fingerprint,
        platform_key=platform_key,
        correlation_window_seconds=correlation_window_seconds,
        now=now,
    )
    return session.scalars(stmt).first()


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
