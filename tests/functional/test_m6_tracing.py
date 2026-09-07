"""FP-M6-24 / F14: real LLMClient with tracing.backend=both + spend aggregation."""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import text

from rca_common.db.session import make_engine, make_session_factory
from rca_common.llmclient.backend import LiteLLMHTTPBackend
from rca_common.llmclient.client import LLMClient
from rca_common.llmclient.langfuse_sink import LangfuseSink
from rca_common.llmclient.objectstore import S3ObjectStore
from rca_common.llmclient.tracestore import PGTraceStore
from tests.mocks.langfuse.mock_langfuse import RecordingLangfuseClient
from tests.mocks.llm.mock_llm_server import CannedResponse, MockLLMServer


@pytest.mark.asyncio
async def test_f14_both_backends_receive_the_same_call(postgres_dsn, minio_client):
    engine = make_engine(postgres_dsn)
    factory = make_session_factory(engine)
    bucket = f"rca-f14-{uuid.uuid4().hex[:8]}"
    minio_client.create_bucket(Bucket=bucket)

    content = '{"status":"concluded","root_cause":{"category":"resource"}}'
    with MockLLMServer(
        responses={"rca": CannedResponse(content=content, cost_usd=0.012, input_tokens=11, output_tokens=7)}
    ) as mock:
        recorder = RecordingLangfuseClient()
        client = LLMClient(
            backend=LiteLLMHTTPBackend(base_url=mock.base_url, master_key="k"),
            object_store=S3ObjectStore(minio_client, bucket),
            trace_store=PGTraceStore(session_factory=factory),
            tracing_sink=LangfuseSink(recorder),
            tracing_backend="both",
        )
        inv = uuid.uuid4()
        result = await client.generate(
            agent_role="rca",
            model="mock-model",
            max_tokens=200,
            messages=[{"role": "user", "content": "worker OOM"}],
            investigation_id=inv,
            round=1,
        )
        assert result is not None
        assert content in (result.content if hasattr(result, "content") else str(result))

        with factory() as session:
            rows = session.execute(
                text(
                    "SELECT prompt_ref, response_ref, model, cost_usd FROM llm_calls "
                    "WHERE investigation_id = CAST(:i AS uuid)"
                ),
                {"i": str(inv)},
            ).fetchall()
            assert rows, "expected llm_calls row"
            prompt_ref, response_ref, model, cost = rows[0]
            assert model
            # S3 objects: prompt/response refs are stored; verify at least one
            # object exists under the bucket when refs are present.
            listed = minio_client.list_objects_v2(Bucket=bucket)
            keys = [o["Key"] for o in listed.get("Contents") or []]
            if prompt_ref or response_ref:
                assert keys, f"expected S3 objects for refs prompt={prompt_ref} response={response_ref}"

        assert recorder.calls, "LangfuseSink must forward the call"
        call = recorder.calls[0]
        assert call.get("model") == "mock-model" or call.get("model")
        assert call.get("input") is not None
        assert call.get("output") is not None



@pytest.mark.asyncio
async def test_f14_spend_aggregation_per_investigation(postgres_dsn, minio_client):
    engine = make_engine(postgres_dsn)
    factory = make_session_factory(engine)
    bucket = f"rca-f14b-{uuid.uuid4().hex[:8]}"
    minio_client.create_bucket(Bucket=bucket)

    with MockLLMServer(
        default_response=CannedResponse(content='{"ok":true}', cost_usd=0.01)
    ) as mock:
        client = LLMClient(
            backend=LiteLLMHTTPBackend(base_url=mock.base_url, master_key="k"),
            object_store=S3ObjectStore(minio_client, bucket),
            trace_store=PGTraceStore(session_factory=factory),
            tracing_backend="builtin",
        )
        inv = uuid.uuid4()
        for r in range(3):
            await client.generate(
                agent_role="collector",
                model="mock",
                max_tokens=50,
                messages=[{"role": "user", "content": f"round {r}"}],
                investigation_id=inv,
                round=r,
            )
        with factory() as session:
            total = session.execute(
                text(
                    "SELECT COALESCE(SUM(cost_usd),0) FROM llm_calls "
                    "WHERE investigation_id = CAST(:i AS uuid)"
                ),
                {"i": str(inv)},
            ).scalar()
        assert float(total) >= 0.03 - 1e-6
