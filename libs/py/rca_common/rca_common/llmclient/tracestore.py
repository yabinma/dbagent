"""Built-in LLM trace store: writes to the `llm_calls` table (design.md
Section 4.3, D5). A fake in-memory implementation is used in unit tests
(Section 14.2: PG is mocked for the llmclient wrapper)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from rca_common.db.models import LLMCall


@dataclass
class LLMCallRecord:
    call_id: uuid.UUID
    investigation_id: uuid.UUID | None
    round: int | None
    agent_role: str
    model: str
    provider: str | None
    prompt_ref: str | None
    response_ref: str | None
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    latency_ms: int | None
    error: str | None
    created_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


class TraceStore(Protocol):
    def insert_llm_call(self, record: LLMCallRecord) -> None: ...

    def get_spend(self, investigation_id: uuid.UUID | str) -> float:
        """Sum of cost_usd for an investigation -- backstop used alongside
        the model gateway's own spend accounting (Section 7)."""


class PGTraceStore:
    """Real backend: writes rows into `llm_calls` via a SQLAlchemy
    session factory."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def insert_llm_call(self, record: LLMCallRecord) -> None:
        with self._session_factory() as session:
            session.add(
                LLMCall(
                    call_id=record.call_id,
                    created_at=record.created_at,
                    investigation_id=record.investigation_id,
                    round=record.round,
                    agent_role=record.agent_role,
                    model=record.model,
                    provider=record.provider,
                    prompt_ref=record.prompt_ref,
                    response_ref=record.response_ref,
                    input_tokens=record.input_tokens,
                    output_tokens=record.output_tokens,
                    cost_usd=record.cost_usd,
                    latency_ms=record.latency_ms,
                    error=record.error,
                )
            )
            session.commit()

    def get_spend(self, investigation_id) -> float:
        from sqlalchemy import func, select

        with self._session_factory() as session:
            stmt = select(func.coalesce(func.sum(LLMCall.cost_usd), 0)).where(
                LLMCall.investigation_id == investigation_id
            )
            return float(session.execute(stmt).scalar_one())


class FakeTraceStore:
    """In-memory `TraceStore` used by unit tests."""

    def __init__(self):
        self.records: list[LLMCallRecord] = []

    def insert_llm_call(self, record: LLMCallRecord) -> None:
        self.records.append(record)

    def get_spend(self, investigation_id) -> float:
        return sum(
            r.cost_usd or 0.0
            for r in self.records
            if str(r.investigation_id) == str(investigation_id)
        )
