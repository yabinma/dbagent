"""Optional Langfuse tracing sink (design.md D5, Section 6 `tracing.backend`).

The `llmclient` wrapper is the sole call path for every Activity's model
call (D5), so when `tracing.backend` is `langfuse` or `both` it explicitly
records each call here in addition to (or instead of) the builtin
`TraceStore` -- guaranteeing both backends are fed from day one regardless
of which is configured.
"""
from __future__ import annotations

from typing import Protocol


class TracingSink(Protocol):
    def on_call(
        self,
        *,
        call_id: str,
        investigation_id: str | None,
        round: int | None,
        agent_role: str,
        model: str,
        prompt: str,
        response: str,
        input_tokens: int | None,
        output_tokens: int | None,
        cost_usd: float | None,
        latency_ms: int | None,
        error: str | None,
    ) -> None: ...


class LangfuseSink:
    """Thin wrapper around the Langfuse Python client."""

    def __init__(self, client):
        self._client = client

    def on_call(self, **kwargs) -> None:
        generation = self._client.generation(
            name=kwargs["agent_role"],
            model=kwargs["model"],
            input=kwargs["prompt"],
            output=kwargs["response"],
            usage={
                "input": kwargs.get("input_tokens"),
                "output": kwargs.get("output_tokens"),
                "unit": "TOKENS",
            },
            metadata={
                "investigation_id": kwargs.get("investigation_id"),
                "round": kwargs.get("round"),
                "call_id": kwargs.get("call_id"),
            },
            level="ERROR" if kwargs.get("error") else "DEFAULT",
            status_message=kwargs.get("error"),
        )
        # Some Langfuse client versions return the generation object
        # directly rather than requiring an explicit .end(); calling end()
        # when available flushes latency/cost metadata immediately.
        end = getattr(generation, "end", None)
        if callable(end):
            end()


class FakeTracingSink:
    """In-memory sink used by unit tests (Section 14.2: Langfuse callback
    is mocked)."""

    def __init__(self):
        self.calls: list[dict] = []

    def on_call(self, **kwargs) -> None:
        self.calls.append(kwargs)
