"""DB-backed query/mutation helpers for dashboard-api (Appendix D)."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from rca_common.audit import actor_user, write_audit
from rca_common.db.models import (
    AlertEventRow,
    Approval,
    AuditLog,
    Evidence,
    Investigation,
    Iteration,
    LLMCall,
    Platform,
    Playbook,
    Probe,
    RemediationExecution,
    User,
)
from rca_common.investigation_repo import TERMINAL_STATUSES
from rca_common.userauth import hash_password

from dashboard_api.errors import APIError


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _encode_cursor(created_at: datetime, id_str: str) -> str:
    raw = f"{created_at.isoformat()}|{id_str}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def _decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        raw = base64.urlsafe_b64decode(cursor.encode()).decode()
        ts, id_str = raw.split("|", 1)
        return datetime.fromisoformat(ts), id_str
    except Exception as exc:  # noqa: BLE001
        raise APIError(400, "invalid_cursor", "invalid pagination cursor") from exc


def sum_llm_cost(session: Session, investigation_id: uuid.UUID) -> float:
    """Derive spent.cost_usd from llm_calls (Section 10.2.3 Spend)."""
    total = session.scalar(
        select(func.coalesce(func.sum(LLMCall.cost_usd), 0)).where(
            LLMCall.investigation_id == investigation_id
        )
    )
    return float(total or 0)


def sum_llm_costs_batch(
    session: Session, investigation_ids: list[uuid.UUID]
) -> dict[uuid.UUID, float]:
    """One GROUP BY for a page of investigation ids (avoids N+1 on list)."""
    if not investigation_ids:
        return {}
    rows = session.execute(
        select(
            LLMCall.investigation_id,
            func.coalesce(func.sum(LLMCall.cost_usd), 0),
        )
        .where(LLMCall.investigation_id.in_(investigation_ids))
        .group_by(LLMCall.investigation_id)
    ).all()
    return {row[0]: float(row[1] or 0) for row in rows if row[0] is not None}


def latest_investigation(session: Session, investigation_id: uuid.UUID) -> Investigation | None:
    return session.scalars(
        select(Investigation)
        .where(Investigation.investigation_id == investigation_id)
        .order_by(Investigation.created_at.desc())
        .limit(1)
    ).first()


def investigation_summary(
    session: Session,
    inv: Investigation,
    *,
    cost_usd: float | None = None,
    severity: str | None = None,
) -> dict[str, Any]:
    spent = dict(inv.spent or {})
    spent["rounds"] = int(spent.get("rounds") or 0)
    spent["cost_usd"] = (
        float(cost_usd) if cost_usd is not None else sum_llm_cost(session, inv.investigation_id)
    )
    if severity is None:
        severity = "unknown"
        if inv.trigger_event:
            ev = session.get(AlertEventRow, inv.trigger_event)
            if ev is not None:
                severity = ev.severity or (ev.normalized or {}).get("severity") or "unknown"
    rca_compact = None
    if inv.rca_report:
        rca_compact = inv.rca_report.get("rca_compact")
    return {
        "investigation_id": str(inv.investigation_id),
        "platform_key": inv.platform_key,
        "status": inv.status,
        "severity": severity,
        "created_at": inv.created_at.isoformat() if inv.created_at else None,
        "closed_at": inv.closed_at.isoformat() if inv.closed_at else None,
        "rca_compact": rca_compact,
        "spent": spent,
        "budget": inv.budget,
    }


def list_investigations(
    session: Session,
    *,
    status: list[str] | None = None,
    platform_key: str | None = None,
    category: str | None = None,
    cursor: str | None = None,
    limit: int = 50,
) -> dict[str, Any]:
    limit = max(1, min(int(limit or 50), 50))
    # Push filters into SQL (including JSONB category) so the page read stays
    # O(limit) rather than scanning then filtering in Python. De-dupe by
    # investigation_id in Python for SQLite-friendly unit tests; PG benefits
    # from the tighter WHERE + ordered limit.
    stmt = select(Investigation).order_by(
        Investigation.created_at.desc(), Investigation.investigation_id.desc()
    )
    if status:
        stmt = stmt.where(Investigation.status.in_(list(status)))
    if platform_key:
        stmt = stmt.where(Investigation.platform_key == platform_key)
    if category:
        # rca_report->root_cause->>category (Appendix D case list filter).
        stmt = stmt.where(
            Investigation.rca_report["root_cause"]["category"].as_string() == category
        )
    if cursor:
        c_at, c_id = _decode_cursor(cursor)
        stmt = stmt.where(
            (Investigation.created_at < c_at)
            | (
                (Investigation.created_at == c_at)
                & (Investigation.investigation_id < uuid.UUID(c_id))
            )
        )

    # Fetch a surplus so de-dupe can still fill `limit` when rare
    # investigation_id collisions exist across partitions (PK is
    # (investigation_id, created_at) on a range-partitioned table).
    fetch_n = max(limit + 1, limit * 4)
    rows = list(session.scalars(stmt.limit(fetch_n)).all())
    seen: set[uuid.UUID] = set()
    unique: list[Investigation] = []
    for r in rows:
        if r.investigation_id in seen:
            continue
        seen.add(r.investigation_id)
        unique.append(r)
        if len(unique) >= limit + 1:
            break

    page = unique[:limit]
    next_cursor = None
    if len(unique) > limit:
        last = page[-1]
        next_cursor = _encode_cursor(last.created_at, str(last.investigation_id))

    # Batch cost + severity lookups — one query each instead of N+1.
    costs = sum_llm_costs_batch(session, [inv.investigation_id for inv in page])
    event_ids = [inv.trigger_event for inv in page if inv.trigger_event]
    severities: dict[uuid.UUID, str] = {}
    if event_ids:
        for ev in session.scalars(
            select(AlertEventRow).where(AlertEventRow.event_id.in_(event_ids))
        ):
            severities[ev.event_id] = (
                ev.severity or (ev.normalized or {}).get("severity") or "unknown"
            )

    items = []
    for inv in page:
        sev = "unknown"
        if inv.trigger_event and inv.trigger_event in severities:
            sev = severities[inv.trigger_event]
        items.append(
            investigation_summary(
                session,
                inv,
                cost_usd=costs.get(inv.investigation_id, 0.0),
                severity=sev,
            )
        )
    return {
        "items": items,
        "next_cursor": next_cursor,
    }


def get_investigation_detail(session: Session, investigation_id: uuid.UUID) -> dict[str, Any]:
    inv = latest_investigation(session, investigation_id)
    if inv is None:
        raise APIError(404, "not_found", f"investigation {investigation_id} not found")
    summary = investigation_summary(session, inv)
    related = session.scalars(
        select(AlertEventRow).where(AlertEventRow.investigation_id == investigation_id)
    ).all()
    related_events = [
        {
            "event_id": str(e.event_id),
            "source": e.source,
            "severity": e.severity,
            "disposition": e.disposition,
            "received_at": e.received_at.isoformat() if e.received_at else None,
            "normalized": e.normalized,
        }
        for e in related
    ]
    executions = session.scalars(
        select(RemediationExecution).where(
            RemediationExecution.investigation_id == investigation_id
        )
    ).all()
    exec_items = [
        {
            "execution_id": str(x.execution_id),
            "playbook_id": x.playbook_id,
            "params": x.params,
            "mode": x.mode,
            "status": x.status,
            "approved_by": str(x.approved_by) if x.approved_by else None,
            "verification_result": x.verification_result,
            "started_at": x.started_at.isoformat() if x.started_at else None,
            "finished_at": x.finished_at.isoformat() if x.finished_at else None,
        }
        for x in executions
    ]
    report = inv.rca_report or {}
    return {
        **summary,
        "workflow_id": inv.workflow_id,
        "trigger_event": str(inv.trigger_event) if inv.trigger_event else None,
        "rca_report": report,  # full
        "rca_compact": report.get("rca_compact") or summary.get("rca_compact"),
        "related_events": related_events,
        "executions": exec_items,
    }


def list_iterations(session: Session, investigation_id: uuid.UUID) -> dict[str, Any]:
    inv = latest_investigation(session, investigation_id)
    if inv is None:
        raise APIError(404, "not_found", f"investigation {investigation_id} not found")
    iters = session.scalars(
        select(Iteration)
        .where(Iteration.investigation_id == investigation_id)
        .order_by(Iteration.round.asc())
    ).all()
    items = []
    for it in iters:
        evidence_refs = session.scalars(
            select(Evidence).where(
                Evidence.investigation_id == investigation_id,
                Evidence.round == it.round,
            )
        ).all()
        items.append(
            {
                "round": it.round,
                "plan": it.plan,
                "rca_output": it.rca_output,
                "cost_usd": float(it.cost_usd) if it.cost_usd is not None else None,
                "duration_ms": it.duration_ms,
                "started_at": it.started_at.isoformat() if it.started_at else None,
                "finished_at": it.finished_at.isoformat() if it.finished_at else None,
                "evidence": [
                    {
                        "evidence_id": str(e.evidence_id),
                        "tool_name": e.tool_name,
                        "summary": e.summary,
                        "payload_ref": e.payload_ref,
                    }
                    for e in evidence_refs
                ],
            }
        )
    return {"items": items}


def get_evidence(
    session: Session,
    evidence_id: uuid.UUID,
    *,
    full: bool,
    object_store: Any,
    ttl: int = 300,
) -> dict[str, Any]:
    row = session.get(Evidence, evidence_id)
    if row is None:
        raise APIError(404, "not_found", f"evidence {evidence_id} not found")
    out: dict[str, Any] = {
        "evidence_id": str(row.evidence_id),
        "investigation_id": str(row.investigation_id),
        "round": row.round,
        "tool_name": row.tool_name,
        "args": row.args,
        "exit_code": row.exit_code,
        "summary": row.summary,
        "payload_ref": row.payload_ref,
        "payload_bytes": row.payload_bytes,
        "redacted": row.redacted,
        "executed_by": row.executed_by,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    if full and row.payload_ref and object_store is not None:
        out["download_url"] = object_store.presigned_url(row.payload_ref, expires_seconds=ttl)
    return out


def list_llm_calls(
    session: Session,
    *,
    investigation_id: str | None,
    round_num: int | None,
    agent_role: str | None,
    cursor: str | None,
    limit: int,
    object_store: Any,
) -> dict[str, Any]:
    limit = max(1, min(int(limit or 50), 50))
    stmt = select(LLMCall).order_by(LLMCall.created_at.desc())
    if investigation_id:
        stmt = stmt.where(LLMCall.investigation_id == uuid.UUID(str(investigation_id)))
    if round_num is not None:
        stmt = stmt.where(LLMCall.round == int(round_num))
    if agent_role:
        stmt = stmt.where(LLMCall.agent_role == agent_role)
    if cursor:
        c_at, c_id = _decode_cursor(cursor)
        stmt = stmt.where(
            (LLMCall.created_at < c_at)
            | ((LLMCall.created_at == c_at) & (LLMCall.call_id < uuid.UUID(c_id)))
        )
    rows = list(session.scalars(stmt.limit(limit + 1)).all())
    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = page[-1]
        next_cursor = _encode_cursor(last.created_at, str(last.call_id))

    def _url(ref: str | None) -> str | None:
        if not ref or object_store is None:
            return ref
        return object_store.presigned_url(ref, expires_seconds=300)

    items = [
        {
            "call_id": str(r.call_id),
            "investigation_id": str(r.investigation_id) if r.investigation_id else None,
            "round": r.round,
            "agent_role": r.agent_role,
            "model": r.model,
            "provider": r.provider,
            "prompt_url": _url(r.prompt_ref),
            "response_url": _url(r.response_ref),
            "prompt_ref": r.prompt_ref,
            "response_ref": r.response_ref,
            "input_tokens": r.input_tokens,
            "output_tokens": r.output_tokens,
            "cost_usd": float(r.cost_usd) if r.cost_usd is not None else None,
            "latency_ms": r.latency_ms,
            "error": r.error,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in page
    ]
    return {"items": items, "next_cursor": next_cursor}


def list_approvals(
    session: Session,
    *,
    pending: bool = True,
    limit: int = 50,
) -> dict[str, Any]:
    limit = max(1, min(int(limit or 50), 100))
    stmt = select(Approval).order_by(Approval.created_at.asc())
    if pending:
        stmt = stmt.where(Approval.decision.is_(None))
    rows = list(session.scalars(stmt.limit(limit)).all())
    now = _now()
    items = []
    for r in rows:
        age_seconds = int((now - r.created_at).total_seconds()) if r.created_at else 0
        items.append(
            {
                "approval_id": str(r.approval_id),
                "investigation_id": str(r.investigation_id),
                "kind": r.kind,
                "subject": r.subject,
                "decision": r.decision,
                "comment": r.comment,
                "created_at": r.created_at.isoformat() if r.created_at else None,
                "age_seconds": age_seconds,
                "investigation_link": f"/api/v1/investigations/{r.investigation_id}",
            }
        )
    return {"items": items}


def decide_approval_atomic(
    session: Session,
    approval_id: uuid.UUID,
    *,
    decision: str,
    decided_by: uuid.UUID,
    comment: str | None,
) -> Approval:
    """Atomic decision gate (Section 10.2.3).

    Returns the updated Approval row. Raises APIError for 404/400/409 cases.
    Does NOT send the Temporal Signal — caller does that after commit.
    """
    if decision not in ("approved", "denied", "need_more"):
        raise APIError(400, "invalid_decision", f"unknown decision {decision!r}")
    if decision == "need_more" and not (comment or "").strip():
        raise APIError(400, "comment_required", "need_more requires a non-empty comment")

    row = session.get(Approval, approval_id)
    if row is None:
        raise APIError(404, "not_found", f"approval {approval_id} not found")

    inv = latest_investigation(session, row.investigation_id)
    if inv is None:
        raise APIError(404, "not_found", "investigation for approval not found")
    if inv.status in TERMINAL_STATUSES:
        raise APIError(409, "case_terminal", "case is terminal; cannot decide approval")

    now = _now()
    result = session.execute(
        update(Approval)
        .where(Approval.approval_id == approval_id, Approval.decision.is_(None))
        .values(
            decision=decision,
            decided_by=decided_by,
            decided_at=now,
            comment=comment,
        )
    )
    if result.rowcount == 0:
        raise APIError(409, "already_decided", "approval already decided")
    session.flush()
    session.refresh(row)

    write_audit(
        session,
        action="approval_decided",
        actor=actor_user(decided_by),
        investigation_id=row.investigation_id,
        detail={
            "approval_id": str(approval_id),
            "decision": decision,
            "comment": comment,
            "kind": row.kind,
        },
    )
    if row.kind == "raw_command":
        if decision == "approved":
            write_audit(
                session,
                action="raw_cmd_approved",
                actor=actor_user(decided_by),
                investigation_id=row.investigation_id,
                detail={"approval_id": str(approval_id)},
            )
        elif decision == "denied":
            write_audit(
                session,
                action="raw_cmd_denied",
                actor=actor_user(decided_by),
                investigation_id=row.investigation_id,
                detail={"approval_id": str(approval_id)},
            )
    return row, inv


# ---- admin helpers ---------------------------------------------------------

CREDENTIAL_GUIDANCE = {
    "k8s": (
        "Create a K8s Secret with keys username/password (and optional ca.crt), "
        "mount it at /etc/rca-probe/platform-credentials on the probe Deployment, "
        "then wait for the probe to re-detect credentials (Section 8.4 step 6)."
    ),
    "swarm": (
        "Create a Docker secret and update the probe service to mount it at "
        "/etc/rca-probe/platform-credentials (keys: username/password/ca.crt). "
        "See Section 8.4 step 6."
    ),
}


def ca_fingerprint(cert_pem_or_path: str) -> str | None:
    """Return sha256:<hex> of the DER CA cert, or None if unavailable."""
    if not cert_pem_or_path:
        return None
    data: bytes
    try:
        # path?
        with open(cert_pem_or_path, "rb") as fh:
            data = fh.read()
    except OSError:
        data = cert_pem_or_path.encode() if isinstance(cert_pem_or_path, str) else cert_pem_or_path
    # If PEM, convert to DER via stripping headers is imperfect; use hashlib of
    # the body bytes between BEGIN/END when PEM, else raw.
    text = data.decode("utf-8", errors="ignore") if isinstance(data, (bytes, bytearray)) else str(data)
    if "BEGIN CERTIFICATE" in text:
        import re

        m = re.search(
            r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)\s*-----END CERTIFICATE-----",
            text,
        )
        if not m:
            return None
        der = base64.b64decode(re.sub(r"\s+", "", m.group(1)))
    else:
        der = data if isinstance(data, (bytes, bytearray)) else data.encode()
    return "sha256:" + hashlib.sha256(der).hexdigest()


def list_platforms(session: Session, *, ca_fp: str | None = None) -> dict[str, Any]:
    rows = list(session.scalars(select(Platform).order_by(Platform.platform_key)).all())
    items = []
    for p in rows:
        item = {
            "platform_key": p.platform_key,
            "platform_type": p.platform_type,
            "deployment": p.deployment,
            "display_name": p.display_name,
            "status": p.status,
            "config": {k: v for k, v in (p.config or {}).items() if k != "bootstrap_token"},
            "created_at": p.created_at.isoformat() if p.created_at else None,
        }
        if p.status == "pending_credentials":
            item["credential_guidance"] = CREDENTIAL_GUIDANCE.get(
                p.deployment, CREDENTIAL_GUIDANCE["k8s"]
            )
        if ca_fp:
            item["bootstrap_ca_fingerprint"] = ca_fp
        items.append(item)
    return {"items": items}


def create_platform(session: Session, body: dict[str, Any], actor_id: uuid.UUID) -> dict[str, Any]:
    key = body.get("platform_key")
    if not key:
        raise APIError(400, "invalid_body", "platform_key is required")
    if session.get(Platform, key) is not None:
        raise APIError(409, "already_exists", f"platform {key} already exists")
    row = Platform(
        platform_key=key,
        platform_type=body.get("platform_type") or "presto",
        deployment=body.get("deployment") or "k8s",
        display_name=body.get("display_name"),
        status="created",
        config=body.get("config") or {},
        created_at=_now(),
    )
    session.add(row)
    write_audit(
        session,
        action="admin_config_changed",
        actor=actor_user(actor_id),
        detail={"entity": "platform", "entity_id": key, "change": "create"},
    )
    return {
        "platform_key": key,
        "platform_type": row.platform_type,
        "deployment": row.deployment,
        "display_name": row.display_name,
        "status": row.status,
        "config": row.config,
    }


def patch_platform(
    session: Session, key: str, body: dict[str, Any], actor_id: uuid.UUID
) -> dict[str, Any]:
    row = session.get(Platform, key)
    if row is None:
        raise APIError(404, "not_found", f"platform {key} not found")
    if "display_name" in body:
        row.display_name = body["display_name"]
    if "config" in body and isinstance(body["config"], dict):
        cfg = dict(row.config or {})
        cfg.update(body["config"])
        row.config = cfg
    write_audit(
        session,
        action="admin_config_changed",
        actor=actor_user(actor_id),
        detail={"entity": "platform", "entity_id": key, "change": "patch", "fields": list(body.keys())},
    )
    return {
        "platform_key": key,
        "status": row.status,
        "display_name": row.display_name,
        "config": {k: v for k, v in (row.config or {}).items() if k != "bootstrap_token"},
    }


def issue_bootstrap_token(
    session: Session, key: str, actor_id: uuid.UUID, ttl_hours: int = 24
) -> dict[str, Any]:
    row = session.get(Platform, key)
    if row is None:
        raise APIError(404, "not_found", f"platform {key} not found")
    token = secrets.token_urlsafe(32)
    expires_at = _now() + timedelta(hours=ttl_hours)
    cfg = dict(row.config or {})
    cfg["bootstrap_token"] = token
    cfg["bootstrap_token_consumed"] = False
    cfg["bootstrap_token_expires_at"] = expires_at.isoformat()
    row.config = cfg
    write_audit(
        session,
        action="admin_config_changed",
        actor=actor_user(actor_id),
        detail={"entity": "bootstrap_token", "entity_id": key, "change": "issue"},
    )
    return {"token": token, "expires_at": expires_at.isoformat()}


def list_probes(session: Session, *, ca_fp: str | None = None) -> dict[str, Any]:
    rows = list(session.scalars(select(Probe)).all())
    items = []
    for p in rows:
        plat = session.get(Platform, p.platform_key) if p.platform_key else None
        caps = p.capabilities or {}
        auth = caps.get("auth") or {}
        item = {
            "probe_id": str(p.probe_id),
            "platform_key": p.platform_key,
            "version": p.version,
            "status": p.status,
            "capabilities": caps,
            "auth_status": auth,
            "missing": auth.get("missing") or [],
            "last_heartbeat": p.last_heartbeat.isoformat() if p.last_heartbeat else None,
            "registered_at": p.registered_at.isoformat() if p.registered_at else None,
            "gateway_replica": p.gateway_replica,
        }
        if plat is not None:
            item["platform_status"] = plat.status
            if plat.status == "pending_credentials" or "credentials" in (auth.get("missing") or []):
                item["credential_guidance"] = CREDENTIAL_GUIDANCE.get(
                    plat.deployment, CREDENTIAL_GUIDANCE["k8s"]
                )
        if ca_fp:
            item["bootstrap_ca_fingerprint"] = ca_fp
        else:
            item["bootstrap_ca_fingerprint_hint"] = (
                "CA volume not mounted; read the fingerprint from probe-gateway startup log"
            )
        items.append(item)
    return {"items": items}


def list_playbooks(session: Session) -> dict[str, Any]:
    rows = list(session.scalars(select(Playbook)).all())
    return {
        "items": [
            {
                "playbook_id": p.playbook_id,
                "platform_type": p.platform_type,
                "risk_level": p.risk_level,
                "params_schema": p.params_schema,
                "steps": p.steps,
                "verification": p.verification,
                "auto_eligible": p.auto_eligible,
                "maturity": p.maturity,
            }
            for p in rows
        ]
    }


def get_playbook(session: Session, playbook_id: str) -> dict[str, Any]:
    p = session.get(Playbook, playbook_id)
    if p is None:
        raise APIError(404, "not_found", f"playbook {playbook_id} not found")
    return {
        "playbook_id": p.playbook_id,
        "platform_type": p.platform_type,
        "risk_level": p.risk_level,
        "params_schema": p.params_schema,
        "steps": p.steps,
        "verification": p.verification,
        "auto_eligible": p.auto_eligible,
        "maturity": p.maturity,
    }


def put_playbook_auto_eligible(
    session: Session, playbook_id: str, body: dict[str, Any], actor_id: uuid.UUID
) -> dict[str, Any]:
    # Phase 3 feature: always 403 in MVP (Section 10.2.4 / Appendix D.5).
    raise APIError(
        403,
        "feature_disabled",
        "auto_eligible cannot be enabled until Phase 3",
    )


def list_users(session: Session) -> dict[str, Any]:
    rows = list(session.scalars(select(User).order_by(User.username)).all())
    return {
        "items": [
            {
                "user_id": str(u.user_id),
                "username": u.username,
                "role": u.role,
                "disabled": u.disabled,
                "must_change_password": bool(getattr(u, "must_change_password", False)),
                "created_at": u.created_at.isoformat() if u.created_at else None,
            }
            for u in rows
        ]
    }


def create_user(session: Session, body: dict[str, Any], actor_id: uuid.UUID) -> dict[str, Any]:
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    role = body.get("role") or "viewer"
    if not username or not password:
        raise APIError(400, "invalid_body", "username and password are required")
    if role not in ("viewer", "approver", "admin"):
        raise APIError(400, "invalid_role", f"unknown role {role!r}")
    existing = session.scalars(select(User).where(User.username == username)).first()
    if existing is not None:
        raise APIError(409, "already_exists", f"user {username} already exists")
    uid = uuid.uuid4()
    row = User(
        user_id=uid,
        username=username,
        password_hash=hash_password(password),
        role=role,
        created_at=_now(),
        disabled=False,
        must_change_password=True,
    )
    session.add(row)
    write_audit(
        session,
        action="admin_config_changed",
        actor=actor_user(actor_id),
        detail={"entity": "user", "entity_id": str(uid), "change": "create", "role": role},
    )
    return {
        "user_id": str(uid),
        "username": username,
        "role": role,
        "must_change_password": True,
    }


def patch_user(
    session: Session, user_id: uuid.UUID, body: dict[str, Any], actor_id: uuid.UUID
) -> dict[str, Any]:
    row = session.get(User, user_id)
    if row is None:
        raise APIError(404, "not_found", f"user {user_id} not found")
    if "role" in body:
        if body["role"] not in ("viewer", "approver", "admin"):
            raise APIError(400, "invalid_role", f"unknown role {body['role']!r}")
        row.role = body["role"]
    if "disabled" in body:
        row.disabled = bool(body["disabled"])
    write_audit(
        session,
        action="admin_config_changed",
        actor=actor_user(actor_id),
        detail={"entity": "user", "entity_id": str(user_id), "change": "patch", "fields": list(body.keys())},
    )
    return {
        "user_id": str(row.user_id),
        "username": row.username,
        "role": row.role,
        "disabled": row.disabled,
        "must_change_password": bool(getattr(row, "must_change_password", False)),
    }


def list_audit(
    session: Session,
    *,
    investigation_id: str | None,
    actor: str | None,
    action: str | None,
    from_ts: str | None,
    to_ts: str | None,
    cursor: str | None,
    limit: int,
) -> dict[str, Any]:
    limit = max(1, min(int(limit or 50), 100))
    stmt = select(AuditLog).order_by(AuditLog.at.desc(), AuditLog.seq.desc())
    if investigation_id:
        stmt = stmt.where(AuditLog.investigation_id == uuid.UUID(str(investigation_id)))
    if actor:
        stmt = stmt.where(AuditLog.actor == actor)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if from_ts:
        stmt = stmt.where(AuditLog.at >= datetime.fromisoformat(from_ts.replace("Z", "+00:00")))
    if to_ts:
        stmt = stmt.where(AuditLog.at <= datetime.fromisoformat(to_ts.replace("Z", "+00:00")))
    if cursor:
        # cursor = base64(at|seq)
        try:
            raw = base64.urlsafe_b64decode(cursor.encode()).decode()
            ts_s, seq_s = raw.split("|", 1)
            c_at = datetime.fromisoformat(ts_s)
            c_seq = int(seq_s)
            stmt = stmt.where(
                (AuditLog.at < c_at) | ((AuditLog.at == c_at) & (AuditLog.seq < c_seq))
            )
        except Exception as exc:  # noqa: BLE001
            raise APIError(400, "invalid_cursor", "invalid pagination cursor") from exc
    rows = list(session.scalars(stmt.limit(limit + 1)).all())
    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit:
        last = page[-1]
        next_cursor = base64.urlsafe_b64encode(
            f"{last.at.isoformat()}|{last.seq}".encode()
        ).decode()
    return {
        "items": [
            {
                "seq": r.seq,
                "investigation_id": str(r.investigation_id) if r.investigation_id else None,
                "actor": r.actor,
                "action": r.action,
                "detail": r.detail,
                "at": r.at.isoformat() if r.at else None,
            }
            for r in page
        ],
        "next_cursor": next_cursor,
    }


def metrics_summary(session: Session, window: str = "7d") -> dict[str, Any]:
    days = 7
    if window.endswith("d"):
        try:
            days = int(window[:-1])
        except ValueError:
            days = 7
    since = _now() - timedelta(days=days)
    all_inv = list(session.scalars(select(Investigation)).all())
    # de-dupe latest
    latest: dict[uuid.UUID, Investigation] = {}
    for inv in sorted(all_inv, key=lambda x: x.created_at or _now()):
        latest[inv.investigation_id] = inv
    invs = list(latest.values())
    open_statuses = {"OPEN", "INVESTIGATING", "AWAITING_APPROVAL", "EXECUTING", "VERIFYING", "RECEIVED"}
    open_count = sum(1 for i in invs if i.status in open_statuses)
    closed = [i for i in invs if i.status in TERMINAL_STATUSES and i.closed_at and i.closed_at >= since]
    pending_approvals = session.scalar(
        select(func.count()).select_from(Approval).where(Approval.decision.is_(None))
    ) or 0
    rounds = [int((i.spent or {}).get("rounds") or 0) for i in closed]
    avg_rounds = (sum(rounds) / len(rounds)) if rounds else 0.0
    costs = [sum_llm_cost(session, i.investigation_id) for i in closed]
    avg_cost = (sum(costs) / len(costs)) if costs else 0.0
    durations = []
    for i in closed:
        if i.created_at and i.closed_at:
            durations.append((i.closed_at - i.created_at).total_seconds())
    avg_duration = (sum(durations) / len(durations)) if durations else 0.0
    by_category: dict[str, int] = {}
    by_platform: dict[str, int] = {}
    for i in invs:
        by_platform[i.platform_key] = by_platform.get(i.platform_key, 0) + 1
        cat = ((i.rca_report or {}).get("root_cause") or {}).get("category") or "unknown"
        by_category[cat] = by_category.get(cat, 0) + 1
    return {
        "window": window,
        "open_cases": open_count,
        "pending_approvals": int(pending_approvals),
        "closed_in_window": len(closed),
        "avg_rounds": round(avg_rounds, 2),
        "avg_cost_usd": round(avg_cost, 4),
        "avg_duration_seconds": round(avg_duration, 1),
        "by_category": by_category,
        "by_platform": by_platform,
    }


async def test_notifications(webhooks: list[dict[str, Any]], actor_id: uuid.UUID, session: Session) -> dict[str, Any]:
    """POST a test payload to each configured outbound webhook.

    Uses the shared ``rca_common.notifications`` module (Section 9.5.3 /
    FP-M4-13 refactor onto the M5 shared formatter/sender).
    """
    from rca_common.notifications import send_to_webhooks

    payload = {
        "event": "notification_test",
        "investigation_id": None,
        "summary": "dashboard notification test",
        "severity": "low",
        "occurred_at": _now().isoformat(),
    }
    results = await send_to_webhooks(webhooks, "notification_test", payload)
    write_audit(
        session,
        action="admin_config_changed",
        actor=actor_user(actor_id),
        detail={"entity": "notifications", "entity_id": "test", "change": "test", "results": results},
    )
    return {"results": results}
