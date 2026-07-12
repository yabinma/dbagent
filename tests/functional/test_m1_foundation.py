"""M1 Foundation functional acceptance test (design.md Section 12):

    "An empty workflow runs end to end; one model call produces an
    `llm_calls` row + S3 objects."

Wires real internal components (a real local Temporal dev server, a real
ephemeral Postgres migrated to head, a real ephemeral MinIO bucket, the
real `PingWorkflow`/`echo` Activity, the real `LLMClient`/
`LiteLLMHTTPBackend`/`PGTraceStore`/`S3ObjectStore`) against the one
genuinely external dependency in scope -- the LLM provider -- which is
mocked via `tests.mocks.llm.mock_llm_server.MockLLMServer`, per Section
14.1's isolation bar ("no test in these two tiers may require network
access or a live platform") and Section 14.3's functional-tier mock list
("a mock LLM server").

Decision (documented, non-blocking): this test targets
`LiteLLMHTTPBackend` directly at the mock LLM server rather than standing
up the `deploy/compose/control-plane.yml` LiteLLM proxy container. At M1,
LiteLLM is a transparent OpenAI-compatible relay with no control-plane
logic of ours to exercise; hitting `LiteLLMHTTPBackend` -- the actual
production code path `LLMClient` calls -- against the mock server directly
covers the same code with less incidental complexity (no need to bake a
LiteLLM routing config into the test). The compose file remains the
supported way to run the real LiteLLM proxy for interactive local dev
against a real model provider.

Maps to checkpoint F14 (Tracing, D5/Section 7) slice: "builtin: `llm_calls`
row + S3 prompt/response per model call" -- see
`tests/functional/checkpoints.yaml`.
"""
from __future__ import annotations

import json
import uuid

import httpx
import pytest
from sqlalchemy import create_engine, text
from temporalio.worker import Worker

from rca_common.llmclient import LiteLLMHTTPBackend, LLMClient, PGTraceStore, S3ObjectStore
from rca_common.db.session import make_engine, make_session_factory

from tests.mocks.llm.mock_llm_server import CannedResponse, MockLLMServer
from worker.activities.echo import echo
from worker.workflows.ping import PingWorkflow


@pytest.mark.asyncio
async def test_empty_workflow_runs_end_to_end(temporal_env):
    """M1 acceptance, part 1: "An empty workflow runs end to end" against a
    real local Temporal dev server (not time-skipping -- this is the
    functional tier, Section 14.3)."""
    task_queue = f"m1-ping-{uuid.uuid4()}"
    async with Worker(
        temporal_env.client,
        task_queue=task_queue,
        workflows=[PingWorkflow],
        activities=[echo],
    ):
        result = await temporal_env.client.execute_workflow(
            PingWorkflow.run,
            "m1-acceptance",
            id=f"ping-{uuid.uuid4()}",
            task_queue=task_queue,
        )

    assert result == "pong:m1-acceptance"


@pytest.mark.asyncio
async def test_one_model_call_produces_llm_calls_row_and_s3_objects(
    postgres_dsn, minio_endpoint, minio_client
):
    """M1 acceptance, part 2: "one model call produces an `llm_calls` row +
    S3 objects" -- real Postgres (migrated schema) + real MinIO, LLM
    provider mocked (Section 14.1 isolation bar)."""
    with MockLLMServer(
        responses={"planner": CannedResponse(content="hello from the mock model", cost_usd=0.0042)}
    ) as mock_llm:
        async with httpx.AsyncClient() as http_client:
            backend = LiteLLMHTTPBackend(mock_llm.base_url, "unused-master-key", client=http_client)
            object_store = S3ObjectStore(minio_client, "rca-agent")

            engine = make_engine(postgres_dsn)
            session_factory = make_session_factory(engine)
            trace_store = PGTraceStore(session_factory)

            llm_client = LLMClient(
                backend=backend,
                object_store=object_store,
                trace_store=trace_store,
                tracing_backend="builtin",
            )

            investigation_id = str(uuid.uuid4())
            result = await llm_client.generate(
                agent_role="planner",
                model="ollama/qwen2.5:14b",
                max_tokens=100,
                messages=[{"role": "user", "content": "what should we collect first?"}],
                investigation_id=investigation_id,
                round=1,
            )

    assert result.content == "hello from the mock model"
    assert result.cost_usd == pytest.approx(0.0042)
    assert len(mock_llm.received_requests) == 1

    # --- real llm_calls row in Postgres ---
    sync_engine = create_engine(postgres_dsn)
    with sync_engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT agent_role, model, cost_usd, input_tokens, output_tokens, "
                "prompt_ref, response_ref FROM llm_calls WHERE call_id = :call_id"
            ),
            {"call_id": str(result.call_id)},
        ).mappings().one()

    assert row["agent_role"] == "planner"
    assert row["model"] == "ollama/qwen2.5:14b"
    assert float(row["cost_usd"]) == pytest.approx(0.0042)
    assert row["prompt_ref"] is not None
    assert row["response_ref"] is not None

    # --- real S3 (MinIO) objects for prompt + response ---
    prompt_obj = minio_client.get_object(Bucket="rca-agent", Key=row["prompt_ref"])
    response_obj = minio_client.get_object(Bucket="rca-agent", Key=row["response_ref"])

    prompt_body = json.loads(prompt_obj["Body"].read())
    response_body = json.loads(response_obj["Body"].read())

    assert prompt_body["model"] == "ollama/qwen2.5:14b"
    assert response_body["choices"][0]["message"]["content"] == "hello from the mock model"
