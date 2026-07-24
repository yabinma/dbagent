"""Idempotent admin bootstrap (design.md Section 10.2.3).

Reads ADMIN_USERNAME / ADMIN_INITIAL_PASSWORD from the environment and creates
the admin user with must_change_password=true if the username does not already
exist. A no-op otherwise.
"""
from __future__ import annotations

import logging
import os
import sys
import uuid
from datetime import datetime, timezone

from rca_common.config import load_config
from rca_common.db.models import User
from rca_common.db.session import make_engine, make_session_factory
from rca_common.userauth import hash_password
from sqlalchemy import select

logger = logging.getLogger(__name__)


def bootstrap_admin(
    session_factory,
    *,
    username: str,
    password: str,
) -> str:
    """Return 'created' | 'exists' | 'skipped'."""
    if not username or not password:
        return "skipped"
    with session_factory() as session:
        existing = session.scalars(select(User).where(User.username == username)).first()
        if existing is not None:
            return "exists"
        session.add(
            User(
                user_id=uuid.uuid4(),
                username=username,
                password_hash=hash_password(password),
                role="admin",
                created_at=datetime.now(timezone.utc),
                disabled=False,
                must_change_password=True,
            )
        )
        session.commit()
        return "created"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO)
    username = os.environ.get("ADMIN_USERNAME", "").strip()
    password = os.environ.get("ADMIN_INITIAL_PASSWORD", "")
    if not username or not password:
        logger.error("ADMIN_USERNAME and ADMIN_INITIAL_PASSWORD are required")
        return 2
    config_path = os.environ.get("RCA_DASHBOARD_CONFIG", "/etc/rca-agent/config.yaml")
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    config = load_config(config_path)
    engine = make_engine(config.storage.postgres_dsn)
    session_factory = make_session_factory(engine)
    result = bootstrap_admin(session_factory, username=username, password=password)
    logger.info("bootstrap_admin: %s (username=%s)", result, username)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
