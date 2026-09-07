"""FP-IG-25 / UT-IG-8: create_worker_app factory and Temporal task_queue.

Against the unfixed tree (2a2e348): red — ``create_worker_app`` does not
exist, and ``main()`` constructs ``TemporalWorkflowStarter(client)`` so the
class default ``rca-worker`` wins over a configured non-default queue.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import pytest
from fastapi.testclient import TestClient

import gateway.main as main_mod
from gateway.main import TemporalWorkflowStarter, create_worker_app


def _write_config(path, *, task_queue: str = "rca-worker") -> None:
    path.write_text(
        f"""
storage:
  postgres_dsn: "sqlite:///:memory:"
ingest:
  sources:
    - {{name: manual, secret: s}}
temporal:
  address: localhost:7233
  namespace: default
  task_queue: {task_queue}
"""
    )


def _hmac(body: bytes, secret: bytes = b"s") -> str:
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def test_create_worker_app_builds_via_build_app_and_connects_on_startup(
    tmp_path, monkeypatch
):
    """UT-IG-8: factory calls build_app(); startup attaches starter; connect
    failure propagates (the worker dies, as today's single process did)."""
    cfg = tmp_path / "config.yaml"
    _write_config(cfg, task_queue="configured-queue")

    connected: list[tuple] = []

    class FakeClient:
        pass

    async def fake_connect(address, namespace="default"):
        connected.append((address, namespace))
        return FakeClient()

    monkeypatch.setattr(main_mod.Client, "connect", fake_connect)
    app = create_worker_app(str(cfg))
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200
    assert connected == [("localhost:7233", "default")]
    service = app.state.ingest_service
    starter = service._workflow_starter
    assert isinstance(starter, TemporalWorkflowStarter)
    assert starter._task_queue == "configured-queue"
    assert isinstance(starter._client, FakeClient)

    async def boom(*_a, **_k):
        raise RuntimeError("temporal unavailable")

    monkeypatch.setattr(main_mod.Client, "connect", boom)
    app2 = create_worker_app(str(cfg))
    with pytest.raises(RuntimeError, match="temporal unavailable"):
        with TestClient(app2):
            pass


def test_worker_app_starts_workflows_on_the_configured_task_queue(
    tmp_path, monkeypatch
):
    """FP-IG-25: a non-default temporal.task_queue reaches start_workflow.

    Against the unfixed tree: red because ``main()`` dropped the configured
    queue and ``TemporalWorkflowStarter(client)`` used the class default.
    """
    cfg = tmp_path / "config.yaml"
    _write_config(cfg, task_queue="non-default-queue")

    recorded: list[dict] = []

    class FakeHandle:
        id = "wf-1"

    class FakeClient:
        async def start_workflow(self, *args, **kwargs):
            recorded.append({"args": args, "kwargs": kwargs})
            return FakeHandle()

    async def fake_connect(*_a, **_k):
        return FakeClient()

    monkeypatch.setattr(main_mod.Client, "connect", fake_connect)
    app = create_worker_app(str(cfg))
    opened_id = uuid.uuid4()

    def fake_txn(event):
        return 202, {"investigation_id": str(opened_id)}, opened_id

    with TestClient(app) as client:
        app.state.ingest_service._ingest_txn = fake_txn
        body = json.dumps(
            {
                "source": "manual",
                "platform_key": "p",
                "error_summary": "opened-branch",
                "occurred_at": "2026-01-01T00:00:00Z",
            }
        ).encode()
        resp = client.post(
            "/api/v1/events",
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Signature": _hmac(body),
            },
        )
        assert resp.status_code == 202, resp.text

    assert recorded, "start_workflow was never called"
    assert recorded[0]["kwargs"]["task_queue"] == "non-default-queue"
