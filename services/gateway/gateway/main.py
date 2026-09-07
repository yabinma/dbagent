"""ingest-gateway process entrypoint."""
from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from temporalio.client import Client

from rca_common.config import load_config
from rca_common.envcompat import reject_legacy_env
from rca_common.db.session import make_engine, make_session_factory

from gateway.app import create_app
from gateway.ingest import IngestService

logger = logging.getLogger(__name__)

# Serve-parameter carrier (§11.3.3 AJ / FP-IG-32). Per-worker open-connection
# ceiling; effective aggregate capacity is workers × (ceiling − 1) because
# uvicorn 0.52.1 refuses at len(connections) >= limit (§11.3.3 AJ).
# Shipped 150 × 4 workers → 596 effective, inside [450, 1000) from B1's
# oracle constants (FP-IG-34 recomputes the interval, never this literal).
DEFAULT_MAX_CONNECTIONS_PER_WORKER = 150
# Declared explicitly — the parameter whose undeclared 5 s default cost
# D0.3-c its first run (§11.3.3 AJ).
DEFAULT_TIMEOUT_KEEP_ALIVE_S = 5
# Pin documenting uvicorn's compiled default; not an operator knob.
BACKLOG = 2048


def _parse_positive_int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise SystemExit(
            f"ingest-gateway: {name} must be a positive integer (got {raw!r})"
        )
    if value <= 0:
        raise SystemExit(
            f"ingest-gateway: {name} must be > 0 (got {value})"
        )
    return value


class TemporalWorkflowStarter:
    def __init__(self, client: Client, task_queue: str = "rca-worker"):
        self._client = client
        self._task_queue = task_queue

    async def start_investigation(self, event: dict[str, Any], investigation_id: uuid.UUID) -> str:
        # Untyped (string) workflow start: deploy/docker/ingest-gateway.Dockerfile
        # installs only rca_common + services/gateway (design.md §11
        # one-service/one-image), so importing worker.workflows.investigation
        # here -- as a previous version of this method did -- raised
        # ModuleNotFoundError on every real investigation in any deployment
        # built from that image (masked in tests only because the functional
        # CI job happens to install gateway and worker into one shared venv).
        # "InvestigationWorkflow" is the real registered type: @workflow.defn
        # on that class carries no name= override, so Temporal defaults the
        # workflow type to the class name.
        workflow_id = f"investigation-{investigation_id}"
        handle = await self._client.start_workflow(
            "InvestigationWorkflow",
            {
                "event": event,
                "investigation_id": str(investigation_id),
            },
            id=workflow_id,
            task_queue=self._task_queue,
        )
        return handle.id


def build_app(config_path: str | None = None):
    path = config_path or os.environ.get("DBAGENT_GATEWAY_CONFIG", "/etc/dbagent/config.yaml")
    config = load_config(path)
    engine = make_engine(config.storage.postgres_dsn)
    session_factory = make_session_factory(engine)
    secrets = {s.name: s.secret for s in config.ingest.sources}
    # Workflow starter is attached after Temporal connects in create_worker_app().
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


def create_worker_app(config_path: str | None = None):
    """Factory for uvicorn's worker manager (FP-IG-20 / FP-IG-25).

    Each spawned worker builds its own app and engine via ``build_app()`` and
    owns its Temporal lifecycle. A connect failure on startup ends the worker
    the same way it ended the former single process.
    """
    app, config, service = build_app(config_path)

    @asynccontextmanager
    async def _lifespan(_app):
        client = await Client.connect(
            config.temporal.address, namespace=config.temporal.namespace
        )
        service._workflow_starter = TemporalWorkflowStarter(
            client, task_queue=config.temporal.task_queue
        )
        yield

    app.router.lifespan_context = _lifespan
    return app


def main() -> None:
    reject_legacy_env()
    logging.basicConfig(level=logging.INFO)
    host = os.environ.get("DBAGENT_GATEWAY_HOST", "0.0.0.0")
    port = int(os.environ.get("DBAGENT_GATEWAY_PORT", "8080"))
    workers = int(os.environ.get("DBAGENT_GATEWAY_WORKERS", "4"))
    max_connections = _parse_positive_int_env(
        "DBAGENT_GATEWAY_MAX_CONNECTIONS_PER_WORKER",
        DEFAULT_MAX_CONNECTIONS_PER_WORKER,
    )
    timeout_keep_alive = _parse_positive_int_env(
        "DBAGENT_GATEWAY_TIMEOUT_KEEP_ALIVE",
        DEFAULT_TIMEOUT_KEEP_ALIVE_S,
    )
    uvicorn.run(
        "gateway.main:create_worker_app",
        factory=True,
        workers=workers,
        host=host,
        port=port,
        log_level="info",
        limit_concurrency=max_connections,
        timeout_keep_alive=timeout_keep_alive,
        backlog=BACKLOG,
    )


if __name__ == "__main__":
    main()
