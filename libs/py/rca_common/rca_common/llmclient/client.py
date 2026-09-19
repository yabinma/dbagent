"""The single thin wrapper client every Activity uses for model calls
(design.md Section 7, D5).

Every call: (1) invokes the model gateway backend, (2) stores the
prompt/response payloads in the object store, (3) writes an `llm_calls` row
via the builtin `TraceStore` when `tracing.backend` is `builtin`/`both`, and
(4) notifies the `TracingSink` when `tracing.backend` is `langfuse`/`both`.
Being the sole call path guarantees both backends are fed from day one
(D5) -- and because every step here is driven by injected interfaces, unit
tests substitute fakes for all four (LLM HTTP, S3, PG, Langfuse) per
Section 14.2.

A JSON-schema parse failure triggers exactly one retry with the error
appended to the conversation (Section 6); a second failure raises
`LLMOutputError`, which Activities let propagate as an Activity failure.
"""
from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

import jsonschema

from rca_common.llmclient.backend import ChatCompletionResponse, LLMBackend, LLMBackendError
from rca_common.llmclient.langfuse_sink import TracingSink
from rca_common.llmclient.objectstore import ObjectStore
from rca_common.llmclient.tracestore import LLMCallRecord, TraceStore


class LLMOutputError(Exception):
    """Raised when the model output fails schema validation twice
    (Section 6: "A parse failure triggers exactly one retry with the error
    appended; a second failure is handled as an Activity failure.")."""


@dataclass
class GenerateResult:
    call_id: uuid.UUID
    content: str
    parsed: Any
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    latency_ms: int
    retried: bool


class LLMClient:
    def __init__(
        self,
        *,
        backend: LLMBackend,
        object_store: ObjectStore,
        trace_store: TraceStore | None = None,
        tracing_sink: TracingSink | None = None,
        tracing_backend: str = "builtin",
    ):
        self._backend = backend
        self._object_store = object_store
        self._trace_store = trace_store
        self._tracing_sink = tracing_sink
        self._tracing_backend = tracing_backend

    async def generate(
        self,
        *,
        agent_role: str,
        model: str,
        max_tokens: int,
        messages: list[dict[str, Any]],
        investigation_id: str | uuid.UUID | None = None,
        round: int | None = None,
        output_schema: dict[str, Any] | None = None,
    ) -> GenerateResult:
        call_id = uuid.uuid4()
        metadata = {
            "investigation_id": str(investigation_id) if investigation_id else None,
            "agent_role": agent_role,
            "round": round,
        }
        response_format = (
            {"type": "json_schema", "json_schema": {"name": agent_role, "schema": output_schema}}
            if output_schema is not None
            else None
        )

        working_messages = list(messages)
        retried = False
        error: str | None = None
        response: ChatCompletionResponse | None = None
        parsed: Any = None
        content = ""
        t0 = time.monotonic()

        for attempt in range(2):
            try:
                response = await self._backend.chat_completion(
                    model=model,
                    messages=working_messages,
                    max_tokens=max_tokens,
                    metadata=metadata,
                    response_format=response_format,
                )
            except LLMBackendError as exc:
                error = str(exc)
                break

            content = response.content
            if output_schema is None:
                parsed = None
                error = None
                break

            try:
                parsed = json.loads(content)
                jsonschema.validate(parsed, output_schema)
                error = None
                break
            except (json.JSONDecodeError, jsonschema.ValidationError) as exc:
                error = f"output schema validation failed: {exc}"
                if attempt == 0:
                    retried = True
                    working_messages = working_messages + [
                        {"role": "assistant", "content": content},
                        {
                            "role": "user",
                            "content": (
                                "Your previous output failed schema validation: "
                                f"{exc}. Re-emit a corrected JSON object that "
                                "conforms exactly to the required schema."
                            ),
                        },
                    ]
                    continue
                break

        latency_ms = int((time.monotonic() - t0) * 1000)

        prompt_ref = self._object_store.put(
            f"llm/{call_id}/prompt.json",
            json.dumps({"model": model, "messages": working_messages}).encode("utf-8"),
        )
        response_ref = self._object_store.put(
            f"llm/{call_id}/response.json",
            json.dumps(response.raw if response else {"error": error}).encode("utf-8"),
        )

        record = LLMCallRecord(
            call_id=call_id,
            investigation_id=uuid.UUID(str(investigation_id)) if investigation_id else None,
            round=round,
            agent_role=agent_role,
            model=model,
            provider=response.provider if response else None,
            prompt_ref=prompt_ref,
            response_ref=response_ref,
            input_tokens=response.input_tokens if response else None,
            output_tokens=response.output_tokens if response else None,
            cost_usd=response.cost_usd if response else None,
            latency_ms=latency_ms,
            error=error,
        )

        if self._tracing_backend in ("builtin", "both") and self._trace_store is not None:
            self._trace_store.insert_llm_call(record)

        if self._tracing_backend in ("langfuse", "both") and self._tracing_sink is not None:
            self._tracing_sink.on_call(
                call_id=str(call_id),
                investigation_id=metadata["investigation_id"],
                round=round,
                agent_role=agent_role,
                model=model,
                prompt=json.dumps(working_messages),
                response=content,
                input_tokens=record.input_tokens,
                output_tokens=record.output_tokens,
                cost_usd=record.cost_usd,
                latency_ms=latency_ms,
                error=error,
            )

        if error is not None:
            if response is None:
                raise LLMBackendError(error)
            raise LLMOutputError(error)

        return GenerateResult(
            call_id=call_id,
            content=content,
            parsed=parsed,
            input_tokens=record.input_tokens,
            output_tokens=record.output_tokens,
            cost_usd=record.cost_usd,
            latency_ms=latency_ms,
            retried=retried,
        )
