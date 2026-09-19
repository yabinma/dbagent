"""Unit tests for the `rca_common.llmclient` package (design.md Section 7,
D5): backend HTTP handling, object store, trace store, tracing sink, and
the `LLMClient.generate()` wrapper's dual-write / retry-once behavior.

Per Section 14.2, PG/S3/Langfuse/the model gateway are all mocked here: the
model gateway via `respx` (no real network), the object store via an
in-memory fake (and a `moto`-mocked S3 for `S3ObjectStore` itself), the
trace store via an in-memory fake, and the tracing sink via an in-memory
fake.
"""
from __future__ import annotations

import json
import uuid

import boto3
import httpx
import pytest
import respx
from moto import mock_aws

from rca_common.llmclient.backend import (
    ChatCompletionResponse,
    LiteLLMHTTPBackend,
    LLMBackendError,
)
from rca_common.llmclient.client import LLMClient, LLMOutputError
from rca_common.llmclient.langfuse_sink import FakeTracingSink, LangfuseSink
from rca_common.llmclient.objectstore import FakeObjectStore, S3ObjectStore
from rca_common.llmclient.spend import get_investigation_spend
from rca_common.llmclient.tracestore import FakeTraceStore, LLMCallRecord, PGTraceStore

from rca_common.db.models import Base, LLMCall
from rca_common.db.session import make_engine, make_session_factory


# --------------------------------------------------------------------- objectstore

class TestFakeObjectStore:
    def test_put_get_round_trip(self):
        store = FakeObjectStore()
        ref = store.put("llm/x/prompt.json", b'{"a": 1}')
        assert ref == "llm/x/prompt.json"
        assert store.get("llm/x/prompt.json") == b'{"a": 1}'

    def test_presigned_url_format(self):
        store = FakeObjectStore()
        store.put("k", b"v")
        url = store.presigned_url("k", expires_seconds=60)
        assert url == "https://fake-s3.local/k?expires=60"


class TestS3ObjectStore:
    @mock_aws
    def test_put_get_presigned_url(self):
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="rca-evidence")
        store = S3ObjectStore(client, "rca-evidence")

        ref = store.put("llm/x/response.json", b'{"ok": true}', content_type="application/json")
        assert ref == "llm/x/response.json"
        assert store.get("llm/x/response.json") == b'{"ok": true}'

        url = store.presigned_url("llm/x/response.json", expires_seconds=120)
        assert "llm/x/response.json" in url


# --------------------------------------------------------------------- tracestore

class TestFakeTraceStore:
    def _record(self, **overrides) -> LLMCallRecord:
        defaults = dict(
            call_id=uuid.uuid4(),
            investigation_id=uuid.uuid4(),
            round=1,
            agent_role="planner",
            model="ollama/qwen2.5:14b",
            provider="ollama",
            prompt_ref="llm/x/prompt.json",
            response_ref="llm/x/response.json",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.01,
            latency_ms=500,
            error=None,
        )
        defaults.update(overrides)
        return LLMCallRecord(**defaults)

    def test_insert_and_get_spend(self):
        store = FakeTraceStore()
        inv_id = uuid.uuid4()
        store.insert_llm_call(self._record(investigation_id=inv_id, cost_usd=0.01))
        store.insert_llm_call(self._record(investigation_id=inv_id, cost_usd=0.02))
        store.insert_llm_call(self._record(investigation_id=uuid.uuid4(), cost_usd=100.0))

        assert store.get_spend(inv_id) == pytest.approx(0.03)

    def test_get_spend_ignores_null_cost(self):
        store = FakeTraceStore()
        inv_id = uuid.uuid4()
        store.insert_llm_call(self._record(investigation_id=inv_id, cost_usd=None))
        assert store.get_spend(inv_id) == 0.0

    def test_get_spend_for_unknown_investigation_is_zero(self):
        store = FakeTraceStore()
        assert store.get_spend(uuid.uuid4()) == 0.0


class TestPGTraceStore:
    """Exercises the real SQLAlchemy-backed `TraceStore` against an
    in-memory sqlite database standing in for Postgres (Section 14.2: the
    unit tier mocks the database; a real Postgres is only used in the
    functional tier)."""

    @pytest.fixture()
    def session_factory(self):
        engine = make_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine, tables=[LLMCall.__table__])
        return make_session_factory(engine)

    def _record(self, **overrides) -> LLMCallRecord:
        defaults = dict(
            call_id=uuid.uuid4(),
            investigation_id=uuid.uuid4(),
            round=1,
            agent_role="planner",
            model="ollama/qwen2.5:14b",
            provider="ollama",
            prompt_ref="llm/x/prompt.json",
            response_ref="llm/x/response.json",
            input_tokens=100,
            output_tokens=50,
            cost_usd=0.01,
            latency_ms=500,
            error=None,
        )
        defaults.update(overrides)
        return LLMCallRecord(**defaults)

    def test_insert_llm_call_persists_row(self, session_factory):
        store = PGTraceStore(session_factory)
        record = self._record()
        store.insert_llm_call(record)

        with session_factory() as session:
            row = session.get(LLMCall, (record.call_id, record.created_at))
            assert row is not None
            assert row.agent_role == "planner"
            assert row.model == "ollama/qwen2.5:14b"

    def test_get_spend_sums_cost_for_investigation(self, session_factory):
        store = PGTraceStore(session_factory)
        inv_id = uuid.uuid4()
        store.insert_llm_call(self._record(investigation_id=inv_id, cost_usd=0.01))
        store.insert_llm_call(self._record(investigation_id=inv_id, cost_usd=0.02))
        store.insert_llm_call(self._record(investigation_id=uuid.uuid4(), cost_usd=5.0))

        assert store.get_spend(inv_id) == pytest.approx(0.03)

    def test_get_spend_returns_zero_for_unknown_investigation(self, session_factory):
        store = PGTraceStore(session_factory)
        assert store.get_spend(uuid.uuid4()) == 0.0

# --------------------------------------------------------------------- tracing sink

class TestFakeTracingSink:
    def test_on_call_records_kwargs(self):
        sink = FakeTracingSink()
        sink.on_call(
            call_id="c1",
            investigation_id="i1",
            round=1,
            agent_role="planner",
            model="m",
            prompt="p",
            response="r",
            input_tokens=1,
            output_tokens=2,
            cost_usd=0.1,
            latency_ms=10,
            error=None,
        )
        assert len(sink.calls) == 1
        assert sink.calls[0]["agent_role"] == "planner"


class _FakeLangfuseGeneration:
    def __init__(self):
        self.ended = False

    def end(self):
        self.ended = True


class _FakeLangfuseGenerationNoEnd:
    """Simulates a Langfuse client version whose `.generation()` return
    value has no `.end()` method."""


class _FakeLangfuseClient:
    def __init__(self, generation_obj):
        self.generation_obj = generation_obj
        self.calls: list[dict] = []

    def generation(self, **kwargs):
        self.calls.append(kwargs)
        return self.generation_obj


class TestLangfuseSink:
    def test_on_call_forwards_fields_and_calls_end_when_available(self):
        generation = _FakeLangfuseGeneration()
        client = _FakeLangfuseClient(generation)
        sink = LangfuseSink(client)

        sink.on_call(
            call_id="c1",
            investigation_id="i1",
            round=2,
            agent_role="planner",
            model="ollama/qwen2.5:14b",
            prompt="prompt text",
            response="response text",
            input_tokens=10,
            output_tokens=5,
            cost_usd=0.01,
            latency_ms=100,
            error=None,
        )

        assert generation.ended is True
        assert len(client.calls) == 1
        kwargs = client.calls[0]
        assert kwargs["name"] == "planner"
        assert kwargs["model"] == "ollama/qwen2.5:14b"
        assert kwargs["input"] == "prompt text"
        assert kwargs["output"] == "response text"
        assert kwargs["usage"] == {"input": 10, "output": 5, "unit": "TOKENS"}
        assert kwargs["level"] == "DEFAULT"
        assert kwargs["status_message"] is None

    def test_on_call_marks_error_level_on_failure(self):
        client = _FakeLangfuseClient(_FakeLangfuseGeneration())
        sink = LangfuseSink(client)
        sink.on_call(
            call_id="c1",
            investigation_id=None,
            round=None,
            agent_role="rca",
            model="m",
            prompt="p",
            response="",
            input_tokens=None,
            output_tokens=None,
            cost_usd=None,
            latency_ms=5,
            error="boom",
        )
        assert client.calls[0]["level"] == "ERROR"
        assert client.calls[0]["status_message"] == "boom"

    def test_on_call_tolerates_generation_without_end_method(self):
        client = _FakeLangfuseClient(_FakeLangfuseGenerationNoEnd())
        sink = LangfuseSink(client)
        # Should not raise even though the returned object has no .end().
        sink.on_call(
            call_id="c1",
            investigation_id=None,
            round=None,
            agent_role="rca",
            model="m",
            prompt="p",
            response="r",
            input_tokens=None,
            output_tokens=None,
            cost_usd=None,
            latency_ms=5,
            error=None,
        )


# --------------------------------------------------------------------- backend (respx)

MODEL_GATEWAY_URL = "http://model-gateway.local:4000"


@pytest.mark.asyncio
async def test_backend_parses_cost_from_header():
    async with httpx.AsyncClient() as http_client:
        backend = LiteLLMHTTPBackend(MODEL_GATEWAY_URL, "mk", client=http_client)
        with respx.mock(assert_all_called=True) as router:
            router.post(f"{MODEL_GATEWAY_URL}/chat/completions").mock(
                return_value=httpx.Response(
                    200,
                    headers={"x-litellm-response-cost": "0.0042"},
                    json={
                        "choices": [{"message": {"content": "hello"}}],
                        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
                    },
                )
            )
            result = await backend.chat_completion(
                model="ollama/qwen2.5:14b",
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=100,
                metadata={},
            )
    assert result.content == "hello"
    assert result.input_tokens == 10
    assert result.output_tokens == 5
    assert result.cost_usd == pytest.approx(0.0042)
    assert result.provider == "ollama"


@pytest.mark.asyncio
async def test_backend_includes_response_format_when_output_schema_given():
    async with httpx.AsyncClient() as http_client:
        backend = LiteLLMHTTPBackend(MODEL_GATEWAY_URL, "mk", client=http_client)
        with respx.mock(assert_all_called=True) as router:
            route = router.post(f"{MODEL_GATEWAY_URL}/chat/completions").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "choices": [{"message": {"content": "{}"}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                    },
                )
            )
            await backend.chat_completion(
                model="m",
                messages=[],
                max_tokens=10,
                metadata={},
                response_format={"type": "json_schema", "json_schema": {"name": "x", "schema": {}}},
            )
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body["response_format"]["json_schema"]["name"] == "x"


@pytest.mark.asyncio
async def test_backend_parses_cost_from_body_when_no_header():
    async with httpx.AsyncClient() as http_client:
        backend = LiteLLMHTTPBackend(MODEL_GATEWAY_URL, "mk", client=http_client)
        with respx.mock(assert_all_called=True) as router:
            router.post(f"{MODEL_GATEWAY_URL}/chat/completions").mock(
                return_value=httpx.Response(
                    200,
                    json={
                        "choices": [{"message": {"content": "hi"}}],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
                        "response_cost": 0.0007,
                    },
                )
            )
            result = await backend.chat_completion(
                model="bedrock/anthropic.claude", messages=[], max_tokens=10, metadata={}
            )
    assert result.cost_usd == pytest.approx(0.0007)
    assert result.provider == "bedrock"


@pytest.mark.asyncio
async def test_backend_no_provider_when_model_has_no_slash():
    async with httpx.AsyncClient() as http_client:
        backend = LiteLLMHTTPBackend(MODEL_GATEWAY_URL, "mk", client=http_client)
        with respx.mock(assert_all_called=True) as router:
            router.post(f"{MODEL_GATEWAY_URL}/chat/completions").mock(
                return_value=httpx.Response(
                    200,
                    json={"choices": [{"message": {"content": "x"}}], "usage": {}},
                )
            )
            result = await backend.chat_completion(
                model="gpt4", messages=[], max_tokens=10, metadata={}
            )
    assert result.provider is None
    assert result.input_tokens is None


@pytest.mark.asyncio
async def test_backend_raises_llm_backend_error_on_http_error_status():
    async with httpx.AsyncClient() as http_client:
        backend = LiteLLMHTTPBackend(MODEL_GATEWAY_URL, "mk", client=http_client)
        with respx.mock(assert_all_called=True) as router:
            router.post(f"{MODEL_GATEWAY_URL}/chat/completions").mock(
                return_value=httpx.Response(500, text="internal error")
            )
            with pytest.raises(LLMBackendError) as exc_info:
                await backend.chat_completion(
                    model="m", messages=[], max_tokens=10, metadata={}
                )
    assert exc_info.value.status_code == 500


@pytest.mark.asyncio
async def test_backend_raises_llm_backend_error_on_transport_failure():
    async with httpx.AsyncClient() as http_client:
        backend = LiteLLMHTTPBackend(MODEL_GATEWAY_URL, "mk", client=http_client)
        with respx.mock(assert_all_called=True) as router:
            router.post(f"{MODEL_GATEWAY_URL}/chat/completions").mock(
                side_effect=httpx.ConnectError("boom")
            )
            with pytest.raises(LLMBackendError, match="transport error"):
                await backend.chat_completion(
                    model="m", messages=[], max_tokens=10, metadata={}
                )


@pytest.mark.asyncio
async def test_get_investigation_spend_parses_response():
    async with httpx.AsyncClient() as http_client:
        with respx.mock(assert_all_called=True) as router:
            router.get(f"{MODEL_GATEWAY_URL}/spend").mock(
                return_value=httpx.Response(200, json={"spend": 1.23})
            )
            spend = await get_investigation_spend(
                base_url=MODEL_GATEWAY_URL,
                master_key="mk",
                investigation_id="inv-1",
                client=http_client,
            )
    assert spend == pytest.approx(1.23)


@pytest.mark.asyncio
async def test_get_investigation_spend_owns_and_closes_client_when_not_injected():
    with respx.mock(assert_all_called=True) as router:
        router.get(f"{MODEL_GATEWAY_URL}/spend").mock(
            return_value=httpx.Response(200, json={"spend": 0})
        )
        spend = await get_investigation_spend(
            base_url=MODEL_GATEWAY_URL, master_key="mk", investigation_id="inv-1"
        )
    assert spend == 0.0


# --------------------------------------------------------------------- LLMClient (fakes)

class FakeBackend:
    """Configurable fake `LLMBackend`: returns a canned response, a queue of
    responses (for retry tests), or raises `LLMBackendError`."""

    def __init__(self, responses=None, error: LLMBackendError | None = None):
        self._responses = list(responses or [])
        self._error = error
        self.calls: list[dict] = []

    async def chat_completion(self, **kwargs) -> ChatCompletionResponse:
        self.calls.append(kwargs)
        if self._error is not None:
            raise self._error
        return self._responses.pop(0)


def _resp(content: str, **overrides) -> ChatCompletionResponse:
    defaults = dict(
        content=content,
        input_tokens=10,
        output_tokens=5,
        cost_usd=0.002,
        provider="ollama",
        raw={"choices": [{"message": {"content": content}}]},
    )
    defaults.update(overrides)
    return ChatCompletionResponse(**defaults)


OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {"answer": {"type": "string"}},
    "required": ["answer"],
}


@pytest.mark.asyncio
async def test_generate_no_schema_writes_prompt_and_response_and_builtin_trace():
    backend = FakeBackend(responses=[_resp("plain text answer")])
    object_store = FakeObjectStore()
    trace_store = FakeTraceStore()

    client = LLMClient(
        backend=backend,
        object_store=object_store,
        trace_store=trace_store,
        tracing_backend="builtin",
    )
    result = await client.generate(
        agent_role="planner",
        model="ollama/qwen2.5:14b",
        max_tokens=100,
        messages=[{"role": "user", "content": "hi"}],
        investigation_id=str(uuid.uuid4()),
        round=1,
    )

    assert result.content == "plain text answer"
    assert result.parsed is None
    assert result.retried is False
    assert result.input_tokens == 10
    assert result.output_tokens == 5
    assert result.cost_usd == pytest.approx(0.002)

    assert len(trace_store.records) == 1
    record = trace_store.records[0]
    assert record.agent_role == "planner"
    assert record.model == "ollama/qwen2.5:14b"
    assert record.error is None

    # prompt + response were both written to the object store.
    assert object_store.get(record.prompt_ref)
    assert object_store.get(record.response_ref)


@pytest.mark.asyncio
async def test_generate_with_schema_success_first_try():
    backend = FakeBackend(responses=[_resp(json.dumps({"answer": "42"}))])
    client = LLMClient(
        backend=backend,
        object_store=FakeObjectStore(),
        trace_store=FakeTraceStore(),
        tracing_backend="builtin",
    )
    result = await client.generate(
        agent_role="rca",
        model="m",
        max_tokens=10,
        messages=[],
        output_schema=OUTPUT_SCHEMA,
    )
    assert result.parsed == {"answer": "42"}
    assert result.retried is False
    assert len(backend.calls) == 1


@pytest.mark.asyncio
async def test_generate_retries_once_on_schema_failure_then_succeeds():
    backend = FakeBackend(
        responses=[
            _resp("not json"),
            _resp(json.dumps({"answer": "ok"})),
        ]
    )
    trace_store = FakeTraceStore()
    client = LLMClient(
        backend=backend,
        object_store=FakeObjectStore(),
        trace_store=trace_store,
        tracing_backend="builtin",
    )
    result = await client.generate(
        agent_role="rca",
        model="m",
        max_tokens=10,
        messages=[{"role": "user", "content": "go"}],
        output_schema=OUTPUT_SCHEMA,
    )
    assert result.retried is True
    assert result.parsed == {"answer": "ok"}
    assert len(backend.calls) == 2
    # second attempt's message list grew with the assistant/user correction turns.
    assert len(backend.calls[1]["messages"]) == len(backend.calls[0]["messages"]) + 2
    assert trace_store.records[0].error is None


@pytest.mark.asyncio
async def test_generate_raises_llm_output_error_after_second_schema_failure():
    backend = FakeBackend(responses=[_resp("not json"), _resp("still not json")])
    trace_store = FakeTraceStore()
    object_store = FakeObjectStore()
    client = LLMClient(
        backend=backend,
        object_store=object_store,
        trace_store=trace_store,
        tracing_backend="builtin",
    )
    with pytest.raises(LLMOutputError):
        await client.generate(
            agent_role="rca",
            model="m",
            max_tokens=10,
            messages=[],
            output_schema=OUTPUT_SCHEMA,
        )
    # Failure is still dual-written: a trace row with a non-null error, and
    # both prompt/response objects were still persisted (Section 6/D5:
    # "dual-write of failures too").
    assert len(trace_store.records) == 1
    assert trace_store.records[0].error is not None
    assert len(object_store.objects) == 2


@pytest.mark.asyncio
async def test_generate_raises_llm_backend_error_and_still_writes_trace_row():
    backend = FakeBackend(error=LLMBackendError("model gateway returned 503"))
    trace_store = FakeTraceStore()
    object_store = FakeObjectStore()
    client = LLMClient(
        backend=backend, object_store=object_store, trace_store=trace_store, tracing_backend="builtin"
    )
    with pytest.raises(LLMBackendError):
        await client.generate(agent_role="planner", model="m", max_tokens=10, messages=[])

    assert len(backend.calls) == 1  # no retry on a transport/backend error
    assert len(trace_store.records) == 1
    assert trace_store.records[0].error == "model gateway returned 503"
    assert trace_store.records[0].input_tokens is None
    assert object_store.get(trace_store.records[0].response_ref) == json.dumps(
        {"error": "model gateway returned 503"}
    ).encode("utf-8")


@pytest.mark.asyncio
@pytest.mark.parametrize("tracing_backend", ["builtin", "langfuse", "both"])
async def test_generate_dual_write_matrix(tracing_backend):
    backend = FakeBackend(responses=[_resp("hello")])
    trace_store = FakeTraceStore()
    tracing_sink = FakeTracingSink()
    client = LLMClient(
        backend=backend,
        object_store=FakeObjectStore(),
        trace_store=trace_store,
        tracing_sink=tracing_sink,
        tracing_backend=tracing_backend,
    )
    await client.generate(agent_role="planner", model="m", max_tokens=10, messages=[])

    expect_builtin = tracing_backend in ("builtin", "both")
    expect_langfuse = tracing_backend in ("langfuse", "both")
    assert (len(trace_store.records) == 1) is expect_builtin
    assert (len(tracing_sink.calls) == 1) is expect_langfuse


@pytest.mark.asyncio
async def test_generate_without_configured_sinks_does_not_error():
    backend = FakeBackend(responses=[_resp("hello")])
    client = LLMClient(backend=backend, object_store=FakeObjectStore())
    result = await client.generate(agent_role="planner", model="m", max_tokens=10, messages=[])
    assert result.content == "hello"


@pytest.mark.asyncio
async def test_generate_records_latency_ms_nonnegative():
    backend = FakeBackend(responses=[_resp("hello")])
    client = LLMClient(backend=backend, object_store=FakeObjectStore(), trace_store=FakeTraceStore())
    result = await client.generate(agent_role="planner", model="m", max_tokens=10, messages=[])
    assert result.latency_ms >= 0
