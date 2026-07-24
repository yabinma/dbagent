"""Worker process entrypoint (design.md Section 11 `services/worker`).

Wires backends (LiteLLM, S3, Postgres, probe-gateway ExecuteTool client)
into Activities and runs a Temporal Worker hosting PingWorkflow (M1) plus
InvestigationWorkflow and the full M3 activity set (Section 5.2).
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
from worker.activities.investigation import InvestigationActivities
from worker.activities.llm_demo import LLMDemoActivities
from worker.probeclient import HTTPProbeGatewayClient
from worker.workflows.investigation import InvestigationWorkflow
from worker.workflows.ping import PingWorkflow

logger = logging.getLogger(__name__)

TASK_QUEUE = "rca-worker"


def build_llm_client(config: AppConfig, *, http_client: httpx.AsyncClient | None = None) -> LLMClient:
    """Assembles the production `LLMClient` from config (Section 7/D5)."""
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


def build_investigation_activities(
    config: AppConfig,
    *,
    llm_client: LLMClient | None = None,
    probe_client=None,
    session_factory=None,
    object_store=None,
    signer=None,
) -> InvestigationActivities:
    """Wire InvestigationActivities for production or tests."""
    if llm_client is None:
        llm_client = build_llm_client(config)
    if session_factory is None:
        engine = make_engine(config.storage.postgres_dsn)
        session_factory = make_session_factory(engine)
    if object_store is None:
        s3_client = boto3.client(
            "s3",
            endpoint_url=config.storage.s3_endpoint or None,
            aws_access_key_id=config.storage.s3_access_key or None,
            aws_secret_access_key=config.storage.s3_secret_key or None,
        )
        object_store = S3ObjectStore(s3_client, config.storage.s3_bucket)
    if probe_client is None:
        probe_client = HTTPProbeGatewayClient(
            config.probe_gateway.url,
            timeout_seconds=config.probe_gateway.timeout_seconds,
        )
    if signer is None:
        from rca_common.signing.signer import MountedEd25519Signer, bootstrap_signing_key
        import nacl.signing

        try:
            signer = bootstrap_signing_key(config.signing.key_path)
        except OSError:
            # Fail closed unless config.signing.allow_ephemeral is set (review W1).
            # Production mounts a writable path; silent ephemeral keys must not
            # substitute in prod (probe would reject unknown-key signatures).
            if getattr(config.signing, "allow_ephemeral", False):
                logger.warning(
                    "signing key path %s not writable; using ephemeral signer "
                    "(allow_ephemeral=true)",
                    config.signing.key_path,
                )
                signer = MountedEd25519Signer(nacl.signing.SigningKey.generate())
            else:
                logger.error(
                    "signing key path %s not writable and allow_ephemeral is false; "
                    "refusing to start with an ephemeral key",
                    config.signing.key_path,
                )
                raise
    return InvestigationActivities(
        session_factory=session_factory,
        llm_client=llm_client,
        probe_client=probe_client,
        object_store=object_store,
        config=config,
        signer=signer,
    )


def investigation_activity_list(acts: InvestigationActivities) -> list:
    """Flatten bound activity callables for Worker registration."""
    return [
        acts.create_case,
        acts.get_spend,
        acts.plan_initial,
        acts.plan_next,
        acts.collect,
        acts.analyze,
        acts.record_iteration,
        acts.static_validate_raw_command,
        acts.run_raw_command,
        acts.create_approval_activity,
        acts.record_approval_decision,
        acts.plan_remediation,
        acts.execute_playbook,
        acts.verify_fix,
        acts.send_notifications,
        acts.close_with_summary,
        acts.close_resolved,
        acts.to_needs_human,
        acts.reject_case,
    ]


async def run_worker(config: AppConfig, *, client: Client | None = None) -> None:
    llm_client = build_llm_client(config)
    llm_demo = LLMDemoActivities(llm_client)
    inv_acts = build_investigation_activities(config, llm_client=llm_client)

    temporal_client = client or await Client.connect(
        config.temporal.address, namespace=config.temporal.namespace
    )

    worker = Worker(
        temporal_client,
        task_queue=TASK_QUEUE,
        workflows=[PingWorkflow, InvestigationWorkflow],
        activities=[echo, llm_demo.generate, *investigation_activity_list(inv_acts)],
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
