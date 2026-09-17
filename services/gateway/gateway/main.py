"""ingest-gateway process entrypoint."""
from __future__ import annotations

import logging
import os
import uuid
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from sqlalchemy import event
from sqlalchemy.engine import Engine, make_url
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

# GC-4 (FP-GC4-1/2). Psycopg 3 counts identical executions per physical DBAPI
# connection and creates the prepared form once the threshold is crossed; the
# server plan then survives SQLAlchemy check-in/check-out until that physical
# connection is closed. Five is Psycopg 3's own shipped default for
# ``Connection.prepare_threshold``, so the connect listener below does not turn
# automatic preparation on -- selecting the ``postgresql+psycopg`` dialect does
# that. The listener exists to make the value a repository constant rather than
# an inherited driver default, and it is the only per-connection setting the
# gateway adds: no ``connect_args``, no pool keyword and no engine keyword.
# Five rather than one so the one-off reject/open-path statements are not all
# prepared on first sight, while the dominant fused merge crosses it almost
# immediately. It is a fixed implementation constant, not configuration.
GATEWAY_PREPARE_THRESHOLD = 5


def _pin_gateway_prepare_threshold(dbapi_connection, _connection_record) -> None:
    """Pin Psycopg 3's automatic-preparation threshold on one new connection."""
    dbapi_connection.prepare_threshold = GATEWAY_PREPARE_THRESHOLD


def make_gateway_engine(dsn: str) -> Engine:
    """The ingest gateway's own engine: Psycopg 3 for PostgreSQL, nothing else.

    FP-GC4-1/2: a PostgreSQL DSN is re-rendered onto SQLAlchemy's synchronous
    ``postgresql+psycopg`` dialect through the URL object, so user, password,
    host, port, database and every existing libpq query option survive exactly
    (ad-hoc string replacement is forbidden). The shared
    ``rca_common.db.session.make_engine`` factory, its ``dsn: str`` signature
    and the stock QueuePool are unchanged, and this constructor contains
    exactly one ``make_engine`` call site so the repository's
    one-engine-per-gateway-process connection budget is unchanged.

    The non-PostgreSQL path exists only for the repository's established SQLite
    wiring tests: it converts no dialect and installs no prepare hook.
    """
    url = make_url(dsn)
    is_postgresql = url.get_backend_name() == "postgresql"
    if is_postgresql:
        url = url.set(drivername="postgresql+psycopg")

    engine = make_engine(url.render_as_string(hide_password=False))
    if is_postgresql:
        event.listen(engine, "connect", _pin_gateway_prepare_threshold)
    return engine


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
    engine = make_gateway_engine(config.storage.postgres_dsn)
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
        try:
            yield
        finally:
            # FP-GC5-5: graceful shutdown stops admission and resolves every
            # accepted merge item before this worker's loop goes away. Engine,
            # pool, worker and serve arguments are untouched.
            await service.close()

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
