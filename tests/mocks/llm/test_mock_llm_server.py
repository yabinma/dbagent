"""Unit tests for the shared mock LLM server itself (design.md Section
14.2/14.3: this is one of the "standard mocks, built once in M1 and
shared"). Exercised directly over real HTTP (loopback), since that is
exactly the contract every future functional test relies on.
"""
from __future__ import annotations

import httpx
import pytest

from tests.mocks.llm.mock_llm_server import CannedResponse, MockLLMServer


@pytest.mark.asyncio
async def test_default_response_used_when_no_role_specific_canned_response():
    with MockLLMServer() as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [], "metadata": {"agent_role": "unknown_role"}},
            )
    assert resp.status_code == 200
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == '{"answer": "ok"}'
    assert resp.headers["x-litellm-response-cost"] == "0.001"


@pytest.mark.asyncio
async def test_role_specific_canned_response_takes_precedence():
    with MockLLMServer(
        responses={"rca": CannedResponse(content='{"root_cause": "oom"}', cost_usd=0.02)}
    ) as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [], "metadata": {"agent_role": "rca"}},
            )
    body = resp.json()
    assert body["choices"][0]["message"]["content"] == '{"root_cause": "oom"}'
    assert resp.headers["x-litellm-response-cost"] == "0.02"


@pytest.mark.asyncio
async def test_records_received_requests():
    with MockLLMServer() as server:
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [{"role": "user", "content": "hi"}], "metadata": {}},
            )
    assert len(server.received_requests) == 1
    assert server.received_requests[0]["messages"][0]["content"] == "hi"


@pytest.mark.asyncio
async def test_unknown_path_returns_404():
    with MockLLMServer() as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(f"{server.base_url}/not-a-real-path", json={})
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_usage_and_token_counts_reflect_canned_response():
    with MockLLMServer(default_response=CannedResponse(content="x", input_tokens=42, output_tokens=8)) as server:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{server.base_url}/chat/completions",
                json={"model": "m", "messages": [], "metadata": {}},
            )
    usage = resp.json()["usage"]
    assert usage["prompt_tokens"] == 42
    assert usage["completion_tokens"] == 8
    assert usage["total_tokens"] == 50


def test_start_stop_without_context_manager():
    server = MockLLMServer()
    url = server.start()
    assert url.startswith("http://127.0.0.1:")
    server.stop()
