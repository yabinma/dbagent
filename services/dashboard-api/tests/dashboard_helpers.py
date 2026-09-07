"""Shared helpers for dashboard-api unit tests."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from rca_common.db.models import User
from rca_common.userauth import hash_password

JWT_SECRET = "test-jwt-secret-for-unit-tests-32b!"


def seed_user(
    session_factory,
    *,
    username: str = "approver1",
    password: str = "approver-pass-12",
    role: str = "approver",
    must_change_password: bool = False,
    disabled: bool = False,
) -> uuid.UUID:
    uid = uuid.uuid4()
    with session_factory() as session:
        session.add(
            User(
                user_id=uid,
                username=username,
                password_hash=hash_password(password),
                role=role,
                created_at=datetime.now(timezone.utc),
                disabled=disabled,
                must_change_password=must_change_password,
            )
        )
        session.commit()
    return uid


async def login(client, username: str, password: str) -> str:
    resp = await client.post(
        "/api/v1/auth/login", json={"username": username, "password": password}
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]
