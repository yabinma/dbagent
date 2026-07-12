"""Shared fixtures for the functional test tier (design.md Section 14.3:
"real internal components together with mocked externals ... ephemeral PG
/ MinIO / Temporal dev-server containers (internal infrastructure, not
external dependencies)").

- Postgres: an ephemeral `testcontainers` Postgres, migrated to head via
  the real `libs/py/rca_common` alembic migration (Section 4.3).
- MinIO: an ephemeral `testcontainers` MinIO container, with the
  `rca-agent` bucket pre-created.
- Temporal: `temporalio.testing.WorkflowEnvironment.start_local()`, a real
  local Temporal dev server binary (not a mock) per the previous session's
  approved plan.
- LLM provider: `tests.mocks.llm.mock_llm_server.MockLLMServer` -- the one
  genuinely *external* dependency in scope, so it is mocked per Section
  14.1's isolation bar; `LiteLLMHTTPBackend` talks to it directly (see
  `test_m1_foundation.py` for why the compose `model-gateway`/LiteLLM
  container itself is not part of this automated tier).

All fixtures are session-scoped (one container/server per test session)
since functional tests in this tier don't mutate global server state in
ways that require per-test isolation beyond fresh per-investigation UUIDs.
"""
from __future__ import annotations

import socket
from pathlib import Path

import boto3
import pytest
import pytest_asyncio
from alembic import command
from alembic.config import Config
from temporalio.testing import WorkflowEnvironment
from testcontainers.core.container import DockerContainer
from testcontainers.core.wait_strategies import LogMessageWaitStrategy
from testcontainers.postgres import PostgresContainer

REPO_ROOT = Path(__file__).resolve().parents[2]
RCA_COMMON_DIR = REPO_ROOT / "libs" / "py" / "rca_common"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def _run_migrations(sync_dsn: str) -> None:
    cfg = Config(str(RCA_COMMON_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(RCA_COMMON_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", sync_dsn)
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def postgres_dsn() -> str:
    """Real ephemeral Postgres, migrated to head (Section 4.3 DDL, verified
    end to end against a live database -- not just compiled DDL)."""
    with PostgresContainer("postgres:16-alpine", dbname="rca_agent", username="rca_agent", password="rca_agent") as pg:
        dsn = pg.get_connection_url()  # postgresql+psycopg2://...
        _run_migrations(dsn)
        yield dsn


@pytest.fixture(scope="session")
def minio_endpoint() -> str:
    """Real ephemeral MinIO (S3-compatible object store, Section 3.2), with
    the `rca-agent` bucket pre-created."""
    access_key = "minioadmin"
    secret_key = "minioadmin"
    container = (
        DockerContainer("minio/minio:latest")
        .with_exposed_ports(9000)
        .with_env("MINIO_ROOT_USER", access_key)
        .with_env("MINIO_ROOT_PASSWORD", secret_key)
        .with_command("server /data")
        .waiting_for(LogMessageWaitStrategy("API:").with_startup_timeout(30))
    )
    with container as minio:
        host = minio.get_container_host_ip()
        port = minio.get_exposed_port(9000)
        endpoint = f"http://{host}:{port}"

        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        client.create_bucket(Bucket="rca-agent")

        yield endpoint


@pytest.fixture()
def minio_client(minio_endpoint):
    return boto3.client(
        "s3",
        endpoint_url=minio_endpoint,
        aws_access_key_id="minioadmin",
        aws_secret_access_key="minioadmin",
    )


@pytest_asyncio.fixture()
async def temporal_env():
    """A real local Temporal dev-server (not a mock -- design.md Section
    14.3 lists Temporal dev-server containers as internal infra, not an
    external dependency that needs mocking)."""
    env = await WorkflowEnvironment.start_local()
    try:
        yield env
    finally:
        await env.shutdown()
