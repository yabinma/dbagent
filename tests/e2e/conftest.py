"""e2e fixtures over kind NodePorts (design.md §11.1.3)."""
from __future__ import annotations

import os
import time

import httpx
import pytest

INGEST_URL = os.environ.get("E2E_INGEST_URL", "http://127.0.0.1:30080")
DASHBOARD_URL = os.environ.get("E2E_DASHBOARD_URL", "http://127.0.0.1:30081")
PROBE_GW_INTERNAL = os.environ.get("E2E_PROBE_GW_URL", "http://127.0.0.1:30082")
PRESTO_URL = os.environ.get("E2E_PRESTO_URL", "http://127.0.0.1:30880")

ADMIN_USER = os.environ.get("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("E2E_ADMIN_PASS", "admin-e2e-password")
# Generous vs the 30s B1 raced after probe deploy; stays inside the 420s phase.
PLATFORM_ONLINE_DEADLINE_S = float(os.environ.get("E2E_PLATFORM_ONLINE_DEADLINE_S", "180"))
PLATFORM_ONLINE_POLL_S = 2.0


def lookup_platform(
    dashboard_url: str,
    token: str,
    platform_key: str,
    *,
    timeout: float = 10,
) -> tuple[str, dict | None]:
    """Locate *platform_key* via GET /api/v1/platforms (no GET-by-key route).

    Returns ``(observed_diagnostic, platform_or_None)``. There is no
    ``GET /api/v1/platforms/{key}`` — PATCH occupies that path — so B1 and
    the session barrier must share this list lookup.
    """
    resp = httpx.get(
        f"{dashboard_url.rstrip('/')}/api/v1/platforms",
        headers={"Authorization": f"Bearer {token}"},
        timeout=timeout,
    )
    if resp.status_code != 200:
        return f"platforms status={resp.status_code}", None
    payload = resp.json()
    plats = payload.get("items") or payload.get("platforms") or payload
    if not isinstance(plats, list):
        plats = []
    target = next(
        (
            p
            for p in plats
            if isinstance(p, dict) and p.get("platform_key") == platform_key
        ),
        None,
    )
    if target is None:
        return f"platform {platform_key!r} not in listing; listed={plats!r}", None
    status = target.get("status") or ""
    return f"platform {platform_key!r} status={status!r}", target


@pytest.fixture(scope="session")
def ingest_url() -> str:
    return INGEST_URL


@pytest.fixture(scope="session")
def dashboard_url() -> str:
    return DASHBOARD_URL


@pytest.fixture(scope="session")
def probe_gw_url() -> str:
    return PROBE_GW_INTERNAL


@pytest.fixture(scope="session")
def presto_url() -> str:
    return PRESTO_URL


def wait_for_platform_online(
    dashboard_url: str,
    *,
    platform_key: str | None = None,
    deadline_s: float = PLATFORM_ONLINE_DEADLINE_S,
    poll_s: float = PLATFORM_ONLINE_POLL_S,
    admin_user: str = ADMIN_USER,
    admin_pass: str = ADMIN_PASS,
) -> None:
    """Poll until *platform_key* (default presto-e2e) reports status 'online'."""
    key = platform_key or os.environ.get("E2E_PLATFORM_KEY", "presto-e2e")
    deadline = time.monotonic() + max(float(deadline_s), 0.0)
    observed: object = "unqueried"
    while True:
        try:
            login = httpx.post(
                f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
                json={"username": admin_user, "password": admin_pass},
                timeout=10,
            )
            token = None
            if login.status_code == 200:
                body = login.json()
                token = body.get("access_token") or body.get("token")
            if not token:
                observed = f"login status={login.status_code}"
            else:
                observed, target = lookup_platform(
                    dashboard_url, token, key, timeout=10
                )
                if target is not None and (target.get("status") or "").lower() == "online":
                    return
        except Exception as exc:  # noqa: BLE001 — keep polling until the deadline
            observed = f"error: {exc}"
        if time.monotonic() >= deadline:
            break
        if poll_s > 0:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(poll_s, remaining))
    raise AssertionError(
        f"platform {key!r} did not reach 'online' within {deadline_s:.0f}s; "
        f"last observed status={observed!r}"
    )


@pytest.fixture(scope="session", autouse=True)
def wait_until_platform_online(dashboard_url: str) -> None:
    wait_for_platform_online(dashboard_url)
