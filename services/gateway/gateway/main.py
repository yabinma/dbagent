"""ingest-gateway process entrypoint."""
from __future__ import annotations

import asyncio
import logging
import os
import uuid
from typing import Any

import uvicorn
from temporalio.client import Client

from rca_common.config import load_config
from rca_common.db.session import make_engine, make_session_factory

from gateway.app import create_app
from gateway.ingest import IngestService

logger = logging.getLogger(__name__)


class TemporalWorkflowStarter:
    def __init__(self, client: Client, task_queue: str = "rca-worker"):
        self._client = client
        self._task_queue = task_queue

    async def start_investigation(self, event: dict[str, Any], investigation_id: uuid.UUID) -> str:
        # Lazy import so the gateway package does not hard-depend on worker at import time
        # for unit tests that inject a fake starter.
        from worker.workflows.investigation import InvestigationWorkflow

        workflow_id = f"investigation-{investigation_id}"
        handle = await self._client.start_workflow(
            InvestigationWorkflow.run,
            {
                "event": event,
                "investigation_id": str(investigation_id),
            },
            id=workflow_id,
            task_queue=self._task_queue,
        )
        return handle.id


def build_app(config_path: str | None = None):
    path = config_path or os.environ.get("RCA_GATEWAY_CONFIG", "/etc/rca-agent/config.yaml")
    config = load_config(path)
    engine = make_engine(config.storage.postgres_dsn)
    session_factory = make_session_factory(engine)
    secrets = {s.name: s.secret for s in config.ingest.sources}
    # Workflow starter is attached after Temporal connects in main().
    service = IngestService(
        session_factory,
        budget_defaults={
            "max_rounds": config.budget_defaults.max_rounds,
            "max_cost_usd": config.budget_defaults.max_cost_usd,
            "max_wall_seconds": config.budget_defaults.max_wall_seconds,
        },
        correlation_window_seconds=config.ingest.correlation_window_seconds,
        known_sources=secrets,
        workflow_starter=None,
    )
    return create_app(ingest_service=service, source_secrets=secrets), config, service


async def _async_main() -> None:
    logging.basicConfig(level=logging.INFO)
    app, config, service = build_app()
    client = await Client.connect(config.temporal.address, namespace=config.temporal.namespace)
    service._workflow_starter = TemporalWorkflowStarter(client)
    host = os.environ.get("RCA_GATEWAY_HOST", "0.0.0.0")
    port = int(os.environ.get("RCA_GATEWAY_PORT", "8080"))
    uvicorn_config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(uvicorn_config)
    await server.serve()


def main() -> None:
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
