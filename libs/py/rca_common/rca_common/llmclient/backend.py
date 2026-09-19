"""HTTP backend for the model gateway (LiteLLM Proxy, design.md Section 7).

Calls the OpenAI-compatible `/chat/completions` endpoint exposed by the
proxy. `httpx` is injected so unit tests can substitute a transport (e.g.
`respx`) without any network access.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx


class LLMBackendError(Exception):
    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class ChatCompletionResponse:
    content: str
    input_tokens: int | None
    output_tokens: int | None
    cost_usd: float | None
    provider: str | None
    raw: dict[str, Any]


class LLMBackend(Protocol):
    async def chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
        metadata: dict[str, Any],
        response_format: dict[str, Any] | None = None,
    ) -> ChatCompletionResponse: ...


class LiteLLMHTTPBackend:
    """Talks to a running LiteLLM Proxy instance."""

    def __init__(self, base_url: str, master_key: str, client: httpx.AsyncClient | None = None):
        self._base_url = base_url.rstrip("/")
        self._master_key = master_key
        self._client = client or httpx.AsyncClient()

    async def chat_completion(
        self,
        *,
        model: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
        metadata: dict[str, Any],
        response_format: dict[str, Any] | None = None,
    ) -> ChatCompletionResponse:
        body: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": max_tokens,
            "metadata": metadata,
        }
        if response_format is not None:
            body["response_format"] = response_format

        try:
            resp = await self._client.post(
                f"{self._base_url}/chat/completions",
                json=body,
                headers={"Authorization": f"Bearer {self._master_key}"},
                timeout=120.0,
            )
        except httpx.HTTPError as exc:
            raise LLMBackendError(f"transport error calling model gateway: {exc}") from exc

        if resp.status_code >= 400:
            raise LLMBackendError(
                f"model gateway returned {resp.status_code}: {resp.text}",
                status_code=resp.status_code,
            )

        payload = resp.json()
        choice = payload["choices"][0]
        content = choice["message"]["content"]
        usage = payload.get("usage") or {}
        cost_usd = None
        cost_header = resp.headers.get("x-litellm-response-cost")
        if cost_header is not None:
            cost_usd = float(cost_header)
        elif "response_cost" in payload:
            cost_usd = float(payload["response_cost"])

        return ChatCompletionResponse(
            content=content,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
            cost_usd=cost_usd,
            provider=model.split("/", 1)[0] if "/" in model else None,
            raw=payload,
        )
