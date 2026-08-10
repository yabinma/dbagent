"""Entrypoint wiring tests for ingest-gateway (main is a thin shell)."""
from __future__ import annotations

import pytest

import gateway.main as main_mod
from gateway.main import TemporalWorkflowStarter, build_app


def test_build_app_loads_config(tmp_path, monkeypatch):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
storage:
  postgres_dsn: "sqlite:///:memory:"
ingest:
  sources:
    - {name: manual, secret: s}
temporal:
  address: localhost:7233
  namespace: default
"""
    )
    monkeypatch.setenv("DBAGENT_GATEWAY_CONFIG", str(cfg))
    app, config, service = build_app(str(cfg))
    assert app is not None
    assert config.ingest.sources[0].name == "manual"
    assert service is not None


def test_main_starts_async(monkeypatch, tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text("storage:\n  postgres_dsn: 'sqlite:///:memory:'\n")
    monkeypatch.setenv("DBAGENT_GATEWAY_CONFIG", str(cfg))

    called = {}

    async def fake_async_main():
        called["ok"] = True

    monkeypatch.setattr(main_mod, "_async_main", fake_async_main)
    main_mod.main()
    assert called["ok"] is True


@pytest.mark.asyncio
async def test_async_main_wires_starter(monkeypatch, tmp_path):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(
        """
storage:
  postgres_dsn: "sqlite:///:memory:"
ingest:
  sources:
    - {name: manual, secret: s}
temporal:
  address: localhost:7233
  namespace: default
"""
    )
    monkeypatch.setenv("DBAGENT_GATEWAY_CONFIG", str(cfg))
    monkeypatch.setenv("DBAGENT_GATEWAY_PORT", "0")

    class FakeClient:
        pass

    async def fake_connect(*a, **k):
        return FakeClient()

    served = {}

    class FakeServer:
        async def serve(self):
            served["ok"] = True

    class FakeConfig:
        def __init__(self, app, host, port, log_level="info"):
            self.app = app
            self.host = host
            self.port = port

    monkeypatch.setattr("gateway.main.Client.connect", fake_connect)
    monkeypatch.setattr("gateway.main.uvicorn.Config", FakeConfig)
    monkeypatch.setattr("gateway.main.uvicorn.Server", lambda cfg: FakeServer())

    await main_mod._async_main()
    assert served["ok"] is True


@pytest.mark.asyncio
async def test_temporal_starter_does_not_import_worker(monkeypatch):
    """deploy/docker/ingest-gateway.Dockerfile installs only rca_common +
    services/gateway (design.md §11 one-service/one-image) -- no `worker`
    package is ever present in the real deployed image. A previous version of
    start_investigation imported worker.workflows.investigation.InvestigationWorkflow
    directly, which raised ModuleNotFoundError on every real investigation in
    any real deployment; it was masked here only by a fake `worker` module this
    test injected into sys.modules, which made the bug invisible. This test
    instead asserts `worker` is genuinely absent and that start_workflow is
    called with the plain string "InvestigationWorkflow" (Temporal's untyped
    workflow-start form, which needs no import of worker's code at all)."""
    import sys

    assert "worker" not in sys.modules, (
        "an earlier test left a fake `worker` module in sys.modules; this "
        "test needs it genuinely absent to prove no import is attempted"
    )

    class FakeHandle:
        id = "wf-1"

    calls: list[tuple[tuple, dict]] = []

    class FakeClient:
        async def start_workflow(self, *a, **k):
            calls.append((a, k))
            return FakeHandle()

    starter = TemporalWorkflowStarter(FakeClient())
    import uuid

    wid = await starter.start_investigation(
        {"platform_key": "p", "error_summary": "x"}, uuid.uuid4()
    )
    assert wid == "wf-1"
    assert "worker" not in sys.modules, "start_investigation imported the worker package"
    assert calls[0][0][0] == "InvestigationWorkflow", (
        f"expected the untyped workflow type name, got {calls[0][0]!r}"
    )
