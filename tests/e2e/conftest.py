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
                resp = httpx.get(
                    f"{dashboard_url.rstrip('/')}/api/v1/platforms",
                    headers={"Authorization": f"Bearer {token}"},
                    timeout=10,
                )
                if resp.status_code != 200:
                    observed = f"platforms status={resp.status_code}"
                else:
                    payload = resp.json()
                    plats = payload.get("items") or payload.get("platforms") or payload
                    if not isinstance(plats, list):
                        plats = []
                    target = next(
                        (
                            p
                            for p in plats
                            if isinstance(p, dict) and p.get("platform_key") == key
                        ),
                        None,
                    )
                    if target is None:
                        observed = (
                            f"platform {key!r} not in listing; listed={plats!r}"
                        )
                    else:
                        status = target.get("status") or ""
                        observed = f"platform {key!r} status={status!r}"
                        if status.lower() == "online":
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
