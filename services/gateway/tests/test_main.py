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
async def test_temporal_starter_lazy_import(monkeypatch):
    class FakeHandle:
        id = "wf-1"

    class FakeClient:
        async def start_workflow(self, *a, **k):
            return FakeHandle()

    starter = TemporalWorkflowStarter(FakeClient())
    # Will try to import InvestigationWorkflow — ensure worker package is on path
    # or that the import is attempted. If worker is not installed in gateway
    # venv this may fail; guard by injecting a fake module.
    import sys
    import types

    inv_mod = types.ModuleType("worker.workflows.investigation")

    class InvestigationWorkflow:
        @staticmethod
        async def run(x):
            return None

    inv_mod.InvestigationWorkflow = InvestigationWorkflow
    workflows_mod = types.ModuleType("worker.workflows")
    worker_mod = types.ModuleType("worker")
    sys.modules["worker"] = worker_mod
    sys.modules["worker.workflows"] = workflows_mod
    sys.modules["worker.workflows.investigation"] = inv_mod
    import uuid

    wid = await starter.start_investigation(
        {"platform_key": "p", "error_summary": "x"}, uuid.uuid4()
    )
    assert wid == "wf-1"
