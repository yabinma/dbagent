"""Worker process entrypoint (design.md Section 11 `services/worker`).

Wires the real backends declared in the Appendix E config (LiteLLM HTTP
model gateway, S3-compatible object store, Postgres trace store) into a
single `LLMClient`, then runs a Temporal `Worker` hosting the M1
workflows/activities. `InvestigationWorkflow` and the four production
agent Activities (Section 5.2/5.3) are M3 scope; this process only hosts
`PingWorkflow` + the demo activities that prove the plumbing end to end
(Section 12 M1 acceptance).
"""
from __future__ import annotations

import asyncio
import logging
import os

import boto3
import httpx
from temporalio.client import Client
from temporalio.worker import Worker

from rca_common.config import AppConfig, load_config
from rca_common.db.session import make_engine, make_session_factory
from rca_common.llmclient import LiteLLMHTTPBackend, LLMClient, PGTraceStore, S3ObjectStore

from worker.activities.echo import echo
from worker.activities.llm_demo import LLMDemoActivities
from worker.workflows.ping import PingWorkflow

logger = logging.getLogger(__name__)

TASK_QUEUE = "rca-worker"


def build_llm_client(config: AppConfig, *, http_client: httpx.AsyncClient | None = None) -> LLMClient:
    """Assembles the production `LLMClient` from config (Section 7/D5): a
    LiteLLM HTTP backend, an S3-compatible object store, and the builtin
    Postgres trace store, dual-writing per `tracing.backend`."""
    backend = LiteLLMHTTPBackend(
        config.model_gateway.url,
        config.model_gateway.master_key,
        client=http_client or httpx.AsyncClient(),
    )

    s3_client = boto3.client(
        "s3",
        endpoint_url=config.storage.s3_endpoint or None,
        aws_access_key_id=config.storage.s3_access_key or None,
        aws_secret_access_key=config.storage.s3_secret_key or None,
    )
    object_store = S3ObjectStore(s3_client, config.storage.s3_bucket)

    engine = make_engine(config.storage.postgres_dsn)
    session_factory = make_session_factory(engine)
    trace_store = PGTraceStore(session_factory)

    return LLMClient(
        backend=backend,
        object_store=object_store,
        trace_store=trace_store,
        tracing_backend=config.tracing.backend,
    )


async def run_worker(config: AppConfig, *, client: Client | None = None) -> None:
    llm_client = build_llm_client(config)
    llm_demo = LLMDemoActivities(llm_client)

    temporal_client = client or await Client.connect(
        config.temporal.address, namespace=config.temporal.namespace
    )

    worker = Worker(
        temporal_client,
        task_queue=TASK_QUEUE,
        workflows=[PingWorkflow],
        activities=[echo, llm_demo.generate],
    )
    logger.info("worker starting: task_queue=%s temporal=%s", TASK_QUEUE, config.temporal.address)
    await worker.run()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config_path = os.environ.get("RCA_WORKER_CONFIG", "/etc/rca-agent/config.yaml")
    config = load_config(config_path)
    asyncio.run(run_worker(config))


if __name__ == "__main__":
    main()
