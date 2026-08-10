"""Unit-test fixtures for dashboard-api (ephemeral PG when available, else skip).

Most unit tests use an in-process SQLite-incompatible path: real Postgres via
testcontainers when Docker is available; otherwise a lightweight mock session
is used for pure auth/JWT tests.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from rca_common.llmclient.objectstore import FakeObjectStore

from dashboard_api.app import DashboardAppConfig, create_app
from dashboard_helpers import JWT_SECRET

REPO_ROOT = Path(__file__).resolve().parents[3]
RCA_COMMON_DIR = REPO_ROOT / "libs" / "py" / "rca_common"


class FakeTemporalHandle:
    def __init__(self, workflow_id: str, parent: "FakeTemporalClient"):
        self.workflow_id = workflow_id
        self._parent = parent

    async def signal(self, name, arg=None):
        if self.workflow_id in self._parent.closed:
            raise RuntimeError("workflow execution already completed")
        self._parent.signals.append(
            {"workflow_id": self.workflow_id, "name": name, "arg": arg}
        )


class FakeTemporalClient:
    def __init__(self):
        self.signals: list[dict] = []
        self.closed: set[str] = set()

    def get_workflow_handle(self, workflow_id: str):
        return FakeTemporalHandle(workflow_id, self)


def _run_migrations(dsn: str) -> None:
    cfg = Config(str(RCA_COMMON_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(RCA_COMMON_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", dsn)
    command.upgrade(cfg, "head")


@pytest.fixture(scope="session")
def pg_dsn():
    try:
        from testcontainers.postgres import PostgresContainer
    except Exception:
        pytest.skip("testcontainers not available")
    with PostgresContainer(
        "postgres:16-alpine", dbname="dbagent", username="dbagent", password="dbagent"
    ) as pg:
        dsn = pg.get_connection_url()
        _run_migrations(dsn)
        yield dsn


@pytest.fixture()
def session_factory(pg_dsn):
    engine = create_engine(pg_dsn)
    factory = sessionmaker(bind=engine, expire_on_commit=False)
    # clean tables between tests
    with factory() as session:
        for table in (
            "audit_log",
            "approvals",
            "remediation_executions",
            "llm_calls",
            "evidence",
            "iterations",
            "investigations",
            "alert_events",
            "probes",
            "playbooks",
            "users",
            "platforms",
        ):
            try:
                session.execute(text(f"TRUNCATE {table} CASCADE"))
            except Exception:
                session.rollback()
        session.commit()
    return factory


@pytest.fixture()
def object_store():
    return FakeObjectStore()


@pytest.fixture()
def temporal_client():
    return FakeTemporalClient()


@pytest.fixture()
def app_config():
    return DashboardAppConfig(
        jwt_secret=JWT_SECRET,
        token_ttl_seconds=3600,
        password_min_length=12,
        cors_origins=[],
        bootstrap_ca_cert_path="",
        notification_webhooks=[{"name": "test", "url": ""}],
    )


@pytest.fixture()
def app(session_factory, temporal_client, object_store, app_config):
    return create_app(
        session_factory=session_factory,
        temporal_client=temporal_client,
        object_store=object_store,
        config=app_config,
    )


@pytest.fixture()
async def client(app):
    from httpx import ASGITransport, AsyncClient

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


