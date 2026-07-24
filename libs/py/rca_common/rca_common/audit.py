"""Audit-log writer (design.md Section 4.3).

Every state transition and significant action emits an ``audit_log`` row
with an actor of the form ``system`` / ``agent:<role>`` / ``user:<id>`` /
``probe:<id>``. Activities and the ingest-gateway call through this
module so the enum and actor conventions stay in one place.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from rca_common.db.models import AUDIT_ACTIONS, AuditLog

# Re-export for callers that want the closed set.
__all__ = ["AUDIT_ACTIONS", "write_audit", "actor_system", "actor_agent", "actor_user", "actor_probe"]


def actor_system() -> str:
    return "system"


def actor_agent(role: str) -> str:
    return f"agent:{role}"


def actor_user(user_id: str | uuid.UUID) -> str:
    return f"user:{user_id}"


def actor_probe(probe_id: str | uuid.UUID) -> str:
    return f"probe:{probe_id}"


def write_audit(
    session,
    *,
    action: str,
    actor: str,
    investigation_id: uuid.UUID | str | None = None,
    detail: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> AuditLog:
    """Insert one audit_log row. ``action`` must be in ``AUDIT_ACTIONS``."""
    if action not in AUDIT_ACTIONS:
        raise ValueError(f"unknown audit action {action!r}; expected one of {AUDIT_ACTIONS}")
    inv: uuid.UUID | None
    if investigation_id is None:
        inv = None
    elif isinstance(investigation_id, uuid.UUID):
        inv = investigation_id
    else:
        inv = uuid.UUID(str(investigation_id))
    row = AuditLog(
        investigation_id=inv,
        actor=actor,
        action=action,
        detail=detail,
        at=at or datetime.now(timezone.utc),
    )
    session.add(row)
    return row
