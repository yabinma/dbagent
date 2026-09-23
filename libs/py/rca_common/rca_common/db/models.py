"""SQLAlchemy ORM models mirroring the core PostgreSQL DDL (design.md
Section 4.3). The authoritative schema lives in the alembic migrations
under ``migrations/versions``; these models are the read/write mapping used
by application code and map to the *parent* (partitioned) tables.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class Platform(Base):
    __tablename__ = "platforms"

    platform_key: Mapped[str] = mapped_column(Text, primary_key=True)
    platform_type: Mapped[str] = mapped_column(Text, nullable=False)
    deployment: Mapped[str] = mapped_column(Text, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="created")
    config: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))


class Probe(Base):
    __tablename__ = "probes"

    probe_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    platform_key: Mapped[str | None] = mapped_column(
        Text, ForeignKey("platforms.platform_key", ondelete="CASCADE")
    )
    version: Mapped[str | None] = mapped_column(Text)
    capabilities: Mapped[dict | None] = mapped_column(JSONB)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="offline")
    gateway_replica: Mapped[str | None] = mapped_column(Text)
    last_heartbeat: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    registered_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))


class AlertEventRow(Base):
    __tablename__ = "alert_events"

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    fingerprint: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str | None] = mapped_column(Text)
    platform_key: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(Text)
    payload_ref: Mapped[str | None] = mapped_column(Text)
    normalized: Mapped[dict] = mapped_column(JSONB, nullable=False)
    disposition: Mapped[str] = mapped_column(Text, nullable=False)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    reject_reason: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))


class Investigation(Base):
    __tablename__ = "investigations"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), primary_key=True
    )
    platform_key: Mapped[str] = mapped_column(
        Text, ForeignKey("platforms.platform_key"), nullable=False
    )
    status: Mapped[str] = mapped_column(Text, nullable=False)
    trigger_event: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    workflow_id: Mapped[str] = mapped_column(Text, nullable=False)
    budget: Mapped[dict] = mapped_column(JSONB, nullable=False)
    spent: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    rca_report: Mapped[dict | None] = mapped_column(JSONB)
    closed_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class Iteration(Base):
    __tablename__ = "iterations"

    investigation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True
    )
    round: Mapped[int] = mapped_column(Integer, primary_key=True)
    plan: Mapped[dict] = mapped_column(JSONB, nullable=False)
    rca_output: Mapped[dict | None] = mapped_column(JSONB)
    cost_usd: Mapped[float | None] = mapped_column(Numeric(10, 4))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class Evidence(Base):
    __tablename__ = "evidence"

    evidence_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    round: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_name: Mapped[str] = mapped_column(Text, nullable=False)
    args: Mapped[dict | None] = mapped_column(JSONB)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    summary: Mapped[str | None] = mapped_column(Text)
    payload_ref: Mapped[str | None] = mapped_column(Text)
    payload_bytes: Mapped[int | None] = mapped_column(BigInteger)
    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    executed_by: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))


class LLMCall(Base):
    __tablename__ = "llm_calls"

    call_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), primary_key=True
    )
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    round: Mapped[int | None] = mapped_column(Integer)
    agent_role: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    provider: Mapped[str | None] = mapped_column(Text)
    prompt_ref: Mapped[str | None] = mapped_column(Text)
    response_ref: Mapped[str | None] = mapped_column(Text)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    cost_usd: Mapped[float | None] = mapped_column(Numeric(10, 6))
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    error: Mapped[str | None] = mapped_column(Text)


class Playbook(Base):
    __tablename__ = "playbooks"

    playbook_id: Mapped[str] = mapped_column(Text, primary_key=True)
    platform_type: Mapped[str] = mapped_column(Text, nullable=False)
    risk_level: Mapped[str] = mapped_column(Text, nullable=False)
    params_schema: Mapped[dict] = mapped_column(JSONB, nullable=False)
    steps: Mapped[dict] = mapped_column(JSONB, nullable=False)
    verification: Mapped[dict] = mapped_column(JSONB, nullable=False)
    auto_eligible: Mapped[bool] = mapped_column(Boolean, default=False)
    maturity: Mapped[dict] = mapped_column(
        JSONB, default=lambda: {"approved_runs": 0, "success": 0, "rollbacks": 0}
    )


class RemediationExecution(Base):
    __tablename__ = "remediation_executions"

    execution_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    playbook_id: Mapped[str | None] = mapped_column(Text, ForeignKey("playbooks.playbook_id"))
    params: Mapped[dict | None] = mapped_column(JSONB)
    mode: Mapped[str] = mapped_column(Text, nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    status: Mapped[str] = mapped_column(Text, nullable=False)
    pre_snapshot: Mapped[dict | None] = mapped_column(JSONB)
    verification_result: Mapped[dict | None] = mapped_column(JSONB)
    started_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))


class Approval(Base):
    __tablename__ = "approvals"

    approval_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[dict] = mapped_column(JSONB, nullable=False)
    decision: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    decided_at: Mapped[datetime | None] = mapped_column(TIMESTAMP(timezone=True))
    comment: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True))
    disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # M4 (migration 0002): forces first-login password change (Section 10.2)
    must_change_password: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AuditLog(Base):
    __tablename__ = "audit_log"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), primary_key=True)
    investigation_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    actor: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    detail: Mapped[dict | None] = mapped_column(JSONB)


AUDIT_ACTIONS = (
    "event_received",
    "event_merged",
    "event_rejected",
    "case_opened",
    "round_started",
    "task_dispatched",
    "tool_executed",
    "raw_cmd_requested",
    "raw_cmd_approved",
    "raw_cmd_denied",
    "rca_produced",
    "budget_exceeded",
    "remediation_proposed",
    "approval_requested",
    "approval_decided",
    "remediation_started",
    "remediation_finished",
    "verification_run",
    "case_closed",
    "notification_sent",
    "credentials_detected",
    "credentials_verified",
    "credentials_test_failed",
    # M4 (Section 10.2 / 4.3): signal endpoint + admin mutations
    "case_paused",
    "case_resumed",
    "case_aborted",
    "budget_adjusted",
    "admin_config_changed",
)
