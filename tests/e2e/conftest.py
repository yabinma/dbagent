"""e2e fixtures over kind NodePorts (design.md §11.1.3)."""
from __future__ import annotations

import os

import pytest

INGEST_URL = os.environ.get("E2E_INGEST_URL", "http://127.0.0.1:30080")
DASHBOARD_URL = os.environ.get("E2E_DASHBOARD_URL", "http://127.0.0.1:30081")
PROBE_GW_INTERNAL = os.environ.get("E2E_PROBE_GW_URL", "http://127.0.0.1:30082")
PRESTO_URL = os.environ.get("E2E_PRESTO_URL", "http://127.0.0.1:30880")


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
