"""Shared test doubles for worker unit/functional tests."""
from __future__ import annotations

import json
import uuid
from typing import Any

from rca_common.llmclient.client import GenerateResult, LLMOutputError
from rca_common.llmclient.tracestore import LLMCallRecord


class FakeTraceStore:
    def __init__(self):
        self.rows: list[LLMCallRecord] = []

    def insert_llm_call(self, record: LLMCallRecord) -> None:
        self.rows.append(record)

    def get_spend(self, investigation_id) -> float:
        total = 0.0
        for r in self.rows:
            if r.investigation_id is None:
                continue
            if str(r.investigation_id) == str(investigation_id):
                total += float(r.cost_usd or 0)
        return total


class ScriptedLLM:
    """Deterministic LLMClient stand-in: returns canned JSON by agent_role."""

    def __init__(self, scripts: dict[str, Any] | None = None):
        self.scripts = scripts or {}
        self.calls: list[dict[str, Any]] = []
        self._idx: dict[str, int] = {}
        self._trace_store = FakeTraceStore()
        self.fail_roles: set[str] = set()

    async def generate(self, **kwargs):
        role = kwargs.get("agent_role") or "unknown"
        self.calls.append(kwargs)
        if role in self.fail_roles:
            raise LLMOutputError("schema failed twice")

        script = self.scripts.get(role, {"status": "concluded", "confidence": 0.9})
        if isinstance(script, list):
            i = self._idx.get(role, 0)
            self._idx[role] = i + 1
            content_obj = script[min(i, len(script) - 1)]
        else:
            content_obj = script
        if callable(content_obj):
            content_obj = content_obj(kwargs)
        content = json.dumps(content_obj)
        inv = kwargs.get("investigation_id")
        rec = LLMCallRecord(
            call_id=uuid.uuid4(),
            investigation_id=uuid.UUID(str(inv)) if inv else None,
            round=kwargs.get("round"),
            agent_role=role,
            model=kwargs.get("model") or "fake",
            provider="fake",
            prompt_ref=None,
            response_ref=None,
            input_tokens=10,
            output_tokens=20,
            cost_usd=0.01,
            latency_ms=5,
            error=None,
        )
        self._trace_store.insert_llm_call(rec)
        return GenerateResult(
            call_id=rec.call_id,
            content=content,
            parsed=content_obj,
            input_tokens=10,
            output_tokens=20,
            cost_usd=0.01,
            latency_ms=5,
            retried=False,
        )
