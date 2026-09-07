"""FastAPI app tests for POST /api/v1/events (F1)."""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from gateway.app import create_app
from gateway.hmac_auth import compute_signature
from gateway.ingest import IngestService


class _Sess:
    def get(self, *a, **k):
        return None

    def add(self, *a, **k):
        return None

    def commit(self):
        return None

    def scalars(self, *a, **k):
        class R:
            def __iter__(self):
                return iter([])

            def first(self):
                return None

        return R()


class _Factory:
    def __call__(self):
        return _Ctx()


class _Ctx:
    def __enter__(self):
        return _Sess()

    def __exit__(self, *a):
        return False


@pytest.fixture
def client():
    secrets = {"grafana-prod": "test-secret"}
    svc = IngestService(
        _Factory(),
        budget_defaults={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        known_sources=secrets,
        workflow_starter=None,
    )
    # Force reject path for platform missing
    app = create_app(ingest_service=svc, source_secrets=secrets)
    return TestClient(app), secrets


def test_healthz(client):
    c, _ = client
    assert c.get("/healthz").json()["status"] == "ok"


def test_valid_hmac_unknown_platform_rejected_200(client):
    c, secrets = client
    body = {
        "source": "grafana-prod",
        "platform_key": "missing",
        "error_summary": "boom",
        "occurred_at": "2026-07-11T00:00:00Z",
    }
    raw = json.dumps(body).encode()
    sig = compute_signature(raw, secrets["grafana-prod"])
    resp = c.post("/api/v1/events", content=raw, headers={"X-Signature": sig, "Content-Type": "application/json"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "rejected"


def test_bad_signature_401(client):
    c, _ = client
    body = b'{"source":"grafana-prod","platform_key":"p","error_summary":"x","occurred_at":"2026-07-11T00:00:00Z"}'
    resp = c.post(
        "/api/v1/events",
        content=body,
        headers={"X-Signature": "00" * 32, "Content-Type": "application/json"},
    )
    assert resp.status_code == 401


def test_missing_signature_401(client):
    c, _ = client
    body = b'{"source":"grafana-prod","platform_key":"p","error_summary":"x","occurred_at":"2026-07-11T00:00:00Z"}'
    resp = c.post("/api/v1/events", content=body, headers={"Content-Type": "application/json"})
    assert resp.status_code == 401
