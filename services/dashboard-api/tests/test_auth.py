"""Auth unit tests: login, JWT, RBAC, forced password change (FP-M4-1..3)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from dashboard_api.auth import decode_token, issue_token, role_at_least
from dashboard_api.errors import APIError
from helpers import JWT_SECRET, login, seed_user


def test_issue_and_decode_token():
    uid = uuid.uuid4()
    token, exp = issue_token(
        user_id=uid,
        username="alice",
        role="admin",
        jwt_secret=JWT_SECRET,
        ttl_seconds=60,
    )
    claims = decode_token(token, JWT_SECRET)
    assert claims["sub"] == str(uid)
    assert claims["username"] == "alice"
    assert claims["role"] == "admin"
    assert "jti" in claims
    assert exp > datetime.now(timezone.utc)


def test_expired_token_raises():
    uid = uuid.uuid4()
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token, _ = issue_token(
        user_id=uid,
        username="x",
        role="viewer",
        jwt_secret=JWT_SECRET,
        ttl_seconds=1,
        now=past,
    )
    # force exp in the past
    claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"], options={"verify_exp": False})
    claims["exp"] = int(past.timestamp())
    bad = jwt.encode(claims, JWT_SECRET, algorithm="HS256")
    with pytest.raises(APIError) as ei:
        decode_token(bad, JWT_SECRET)
    assert ei.value.status_code == 401


def test_role_at_least_cumulative():
    assert role_at_least("viewer", "viewer")
    assert not role_at_least("viewer", "approver")
    assert role_at_least("approver", "viewer")
    assert role_at_least("admin", "approver")
    assert role_at_least("admin", "admin")


@pytest.mark.asyncio
async def test_login_issues_jwt_and_rejects_bad_credentials(client, session_factory):
    seed_user(session_factory, username="u1", password="good-password-12", role="viewer")
    ok = await client.post(
        "/api/v1/auth/login", json={"username": "u1", "password": "good-password-12"}
    )
    assert ok.status_code == 200
    body = ok.json()
    assert "token" in body
    assert body["role"] == "viewer"
    assert body["must_change_password"] is False
    assert "expires_at" in body

    bad = await client.post(
        "/api/v1/auth/login", json={"username": "u1", "password": "wrong-password"}
    )
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "invalid_credentials"

    missing = await client.post(
        "/api/v1/auth/login", json={"username": "nobody", "password": "x"}
    )
    assert missing.status_code == 401


@pytest.mark.asyncio
async def test_disabled_user_login_401(client, session_factory):
    seed_user(
        session_factory,
        username="dis",
        password="good-password-12",
        role="viewer",
        disabled=True,
    )
    resp = await client.post(
        "/api/v1/auth/login", json={"username": "dis", "password": "good-password-12"}
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_rbac_matrix_401_403(client, session_factory):
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    seed_user(session_factory, username="ad", password="admin-pass-123", role="admin")

    # missing token
    r = await client.get("/api/v1/investigations")
    assert r.status_code == 401

    # malformed
    r = await client.get(
        "/api/v1/investigations", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert r.status_code == 401

    vtok = await login(client, "v", "viewer-pass-12")
    atok = await login(client, "a", "approver-pass12")
    adtok = await login(client, "ad", "admin-pass-123")

    # viewer can list investigations
    r = await client.get(
        "/api/v1/investigations", headers={"Authorization": f"Bearer {vtok}"}
    )
    assert r.status_code == 200

    # viewer cannot list approvals
    r = await client.get(
        "/api/v1/approvals", headers={"Authorization": f"Bearer {vtok}"}
    )
    assert r.status_code == 403

    # approver can list approvals
    r = await client.get(
        "/api/v1/approvals", headers={"Authorization": f"Bearer {atok}"}
    )
    assert r.status_code == 200

    # approver cannot create platform
    r = await client.post(
        "/api/v1/platforms",
        headers={"Authorization": f"Bearer {atok}"},
        json={"platform_key": "x", "platform_type": "presto", "deployment": "k8s"},
    )
    assert r.status_code == 403

    # admin can create platform
    r = await client.post(
        "/api/v1/platforms",
        headers={"Authorization": f"Bearer {adtok}"},
        json={"platform_key": "x", "platform_type": "presto", "deployment": "k8s"},
    )
    assert r.status_code == 201


@pytest.mark.asyncio
async def test_forced_password_change_gate(client, session_factory):
    seed_user(
        session_factory,
        username="newadmin",
        password="initial-pass-12",
        role="admin",
        must_change_password=True,
    )
    tok = await login(client, "newadmin", "initial-pass-12")
    # other endpoints blocked
    r = await client.get(
        "/api/v1/investigations", headers={"Authorization": f"Bearer {tok}"}
    )
    assert r.status_code == 403
    assert r.json()["error"]["code"] == "password_change_required"

    # change-password allowed
    r = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {tok}"},
        json={"old_password": "wrong", "new_password": "new-password-12"},
    )
    assert r.status_code == 401

    r = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {tok}"},
        json={"old_password": "initial-pass-12", "new_password": "short"},
    )
    assert r.status_code == 400

    r = await client.post(
        "/api/v1/auth/change-password",
        headers={"Authorization": f"Bearer {tok}"},
        json={"old_password": "initial-pass-12", "new_password": "new-password-12"},
    )
    assert r.status_code == 204

    # re-login and access works
    tok2 = await login(client, "newadmin", "new-password-12")
    r = await client.get(
        "/api/v1/investigations", headers={"Authorization": f"Bearer {tok2}"}
    )
    assert r.status_code == 200
