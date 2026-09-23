"""dashboard-api process entrypoint (design.md Section 10.2.3)."""
from __future__ import annotations

import asyncio
import logging
import os

import boto3
import uvicorn
from temporalio.client import Client

from rca_common.config import load_config
from rca_common.envcompat import reject_legacy_env
from rca_common.db.session import make_engine, make_session_factory
from rca_common.llmclient.objectstore import S3ObjectStore

from dashboard_api.app import DashboardAppConfig, create_app

logger = logging.getLogger(__name__)


def build_app(config_path: str | None = None):
    path = config_path or os.environ.get(
        "DBAGENT_DASHBOARD_CONFIG", "/etc/dbagent/config.yaml"
    )
    config = load_config(path)
    if not config.dashboard.jwt_secret:
        raise SystemExit(
            "dashboard.jwt_secret is empty; set DASHBOARD_JWT_SECRET / dashboard.jwt_secret"
        )
    engine = make_engine(config.storage.postgres_dsn)
    session_factory = make_session_factory(engine)

    s3_client = boto3.client(
        "s3",
        endpoint_url=config.storage.s3_endpoint or None,
        aws_access_key_id=config.storage.s3_access_key or None,
        aws_secret_access_key=config.storage.s3_secret_key or None,
    )
    object_store = S3ObjectStore(s3_client, config.storage.s3_bucket)

    webhooks = []
    raw_n = (config.raw.get("notifications") or {}).get("outbound_webhooks") or []
    webhooks = list(raw_n)

    app_config = DashboardAppConfig(
        jwt_secret=config.dashboard.jwt_secret,
        token_ttl_seconds=config.dashboard.token_ttl_seconds,
        password_min_length=config.dashboard.password_min_length,
        cors_origins=list(config.dashboard.cors_origins or []),
        bootstrap_ca_cert_path=config.dashboard.bootstrap_ca_cert_path or "",
        notification_webhooks=webhooks,
    )
    # Temporal client attached after connect in main().
    app = create_app(
        session_factory=session_factory,
        temporal_client=None,
        object_store=object_store,
        config=app_config,
    )
    return app, config


async def _async_main() -> None:
    logging.basicConfig(level=logging.INFO)
    app, config = build_app()
    client = await Client.connect(
        config.temporal.address, namespace=config.temporal.namespace
    )
    app.state.temporal_client = client
    host = os.environ.get("DBAGENT_DASHBOARD_HOST", "0.0.0.0")
    port = int(os.environ.get("DBAGENT_DASHBOARD_PORT", "8081"))
    uvicorn_config = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(uvicorn_config)
    await server.serve()


def main() -> None:
    reject_legacy_env()
    asyncio.run(_async_main())


if __name__ == "__main__":
    main()
