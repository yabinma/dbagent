"""JWT issue/verify + RBAC dependency (design.md Section 10.2.3 / Appendix D.1)."""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import jwt
from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from dashboard_api.errors import APIError
from rca_common.userauth import verify_password

# Cumulative role order: viewer < approver < admin
ROLE_RANK = {"viewer": 1, "approver": 2, "admin": 3}

_bearer = HTTPBearer(auto_error=False)


@dataclass
class AuthUser:
    user_id: uuid.UUID
    username: str
    role: str
    must_change_password: bool = False


def issue_token(
    *,
    user_id: uuid.UUID | str,
    username: str,
    role: str,
    jwt_secret: str,
    ttl_seconds: int = 43200,
    now: datetime | None = None,
) -> tuple[str, datetime]:
    """Return (token, expires_at). Claims: sub, username, role, iat, exp, jti."""
    if not jwt_secret:
        raise ValueError("jwt_secret is required")
    now = now or datetime.now(timezone.utc)
    exp = now + timedelta(seconds=int(ttl_seconds))
    claims = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = jwt.encode(claims, jwt_secret, algorithm="HS256")
    if isinstance(token, bytes):
        token = token.decode("utf-8")
    return token, exp


def decode_token(token: str, jwt_secret: str) -> dict[str, Any]:
    try:
        return jwt.decode(token, jwt_secret, algorithms=["HS256"])
    except jwt.ExpiredSignatureError as exc:
        raise APIError(401, "token_expired", "token has expired") from exc
    except jwt.InvalidTokenError as exc:
        raise APIError(401, "invalid_token", "invalid or malformed token") from exc


def role_at_least(role: str, min_role: str) -> bool:
    return ROLE_RANK.get(role, 0) >= ROLE_RANK.get(min_role, 99)


def require_role(min_role: str) -> Callable:
    """FastAPI dependency factory enforcing cumulative RBAC + password-change gate."""

    async def _dep(
        request: Request,
        creds: HTTPAuthorizationCredentials | None = Depends(_bearer),
    ) -> AuthUser:
        if creds is None or not creds.credentials:
            raise APIError(401, "missing_token", "Authorization Bearer token required")
        secret = request.app.state.config.jwt_secret
        claims = decode_token(creds.credentials, secret)
        user_id = claims.get("sub")
        role = claims.get("role") or ""
        username = claims.get("username") or ""
        if not user_id or role not in ROLE_RANK:
            raise APIError(401, "invalid_token", "token missing required claims")

        # Load live user flags (disabled / must_change_password) from DB.
        session_factory = request.app.state.session_factory
        from rca_common.db.models import User

        with session_factory() as session:
            row = session.get(User, uuid.UUID(str(user_id)))
            if row is None or row.disabled:
                raise APIError(401, "unauthorized", "user disabled or not found")
            must_change = bool(getattr(row, "must_change_password", False))
            role = row.role
            username = row.username

        # Forced first-login password change (FP-M4-3): only change-password
        # and login are allowed while the flag is set.
        path = request.url.path.rstrip("/")
        if must_change and not path.endswith("/auth/change-password"):
            raise APIError(
                403,
                "password_change_required",
                "password change required before accessing other endpoints",
            )

        if not role_at_least(role, min_role):
            raise APIError(
                403,
                "forbidden",
                f"role {role!r} is below required {min_role!r}",
            )
        return AuthUser(
            user_id=uuid.UUID(str(user_id)),
            username=username,
            role=role,
            must_change_password=must_change,
        )

    return _dep


def authenticate_user(session, username: str, password: str):
    """Return User row or None (bad credentials / disabled)."""
    from sqlalchemy import select
    from rca_common.db.models import User

    row = session.scalars(select(User).where(User.username == username)).first()
    if row is None or row.disabled:
        return None
    if not verify_password(row.password_hash, password):
        return None
    return row
