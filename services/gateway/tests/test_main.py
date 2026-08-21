"""Entrypoint wiring tests for ingest-gateway (main is a thin shell)."""
from __future__ import annotations

import pytest

import gateway.main as main_mod
from gateway.main import (
    BACKLOG,
    DEFAULT_MAX_CONNECTIONS_PER_WORKER,
    DEFAULT_TIMEOUT_KEEP_ALIVE_S,
    TemporalWorkflowStarter,
    build_app,
)


def _write_min_config(path) -> None:
    path.write_text("storage:\n  postgres_dsn: 'sqlite:///:memory:'\n")


def _patch_uvicorn_run(monkeypatch):
    called = {}

    def fake_run(app, **kwargs):
        called["app"] = app
        called["kwargs"] = kwargs

    monkeypatch.setattr(main_mod.uvicorn, "run", fake_run)
    return called


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


def test_main_invokes_uvicorn_worker_manager(monkeypatch, tmp_path):
    cfg = tmp_path / "config.yaml"
    _write_min_config(cfg)
    monkeypatch.setenv("DBAGENT_GATEWAY_CONFIG", str(cfg))
    monkeypatch.setenv("DBAGENT_GATEWAY_WORKERS", "4")
    monkeypatch.delenv("DBAGENT_GATEWAY_MAX_CONNECTIONS_PER_WORKER", raising=False)
    monkeypatch.delenv("DBAGENT_GATEWAY_TIMEOUT_KEEP_ALIVE", raising=False)

    called = _patch_uvicorn_run(monkeypatch)
    main_mod.main()
    assert called["app"] == "gateway.main:create_worker_app"
    assert called["kwargs"]["factory"] is True
    assert called["kwargs"]["workers"] == 4
    assert called["kwargs"]["limit_concurrency"] == DEFAULT_MAX_CONNECTIONS_PER_WORKER
    assert called["kwargs"]["timeout_keep_alive"] == DEFAULT_TIMEOUT_KEEP_ALIVE_S
    assert called["kwargs"]["backlog"] == BACKLOG


@pytest.mark.parametrize(
    ("env_name", "env_value", "kwarg"),
    [
        ("DBAGENT_GATEWAY_MAX_CONNECTIONS_PER_WORKER", "42", "limit_concurrency"),
        ("DBAGENT_GATEWAY_TIMEOUT_KEEP_ALIVE", "9", "timeout_keep_alive"),
    ],
)
def test_main_passes_env_overrides_for_serve_carrier(
    monkeypatch, tmp_path, env_name, env_value, kwarg
):
    cfg = tmp_path / "config.yaml"
    _write_min_config(cfg)
    monkeypatch.setenv("DBAGENT_GATEWAY_CONFIG", str(cfg))
    monkeypatch.delenv("DBAGENT_GATEWAY_MAX_CONNECTIONS_PER_WORKER", raising=False)
    monkeypatch.delenv("DBAGENT_GATEWAY_TIMEOUT_KEEP_ALIVE", raising=False)
    monkeypatch.setenv(env_name, env_value)

    called = _patch_uvicorn_run(monkeypatch)
    main_mod.main()
    assert called["kwargs"][kwarg] == int(env_value)


@pytest.mark.parametrize(
    "env_name",
    ["DBAGENT_GATEWAY_MAX_CONNECTIONS_PER_WORKER", "DBAGENT_GATEWAY_TIMEOUT_KEEP_ALIVE"],
)
@pytest.mark.parametrize("bad_value", ["0", "-1", "abc"])
def test_main_refuses_invalid_serve_carrier_env(
    monkeypatch, tmp_path, env_name, bad_value
):
    cfg = tmp_path / "config.yaml"
    _write_min_config(cfg)
    monkeypatch.setenv("DBAGENT_GATEWAY_CONFIG", str(cfg))
    monkeypatch.delenv("DBAGENT_GATEWAY_MAX_CONNECTIONS_PER_WORKER", raising=False)
    monkeypatch.delenv("DBAGENT_GATEWAY_TIMEOUT_KEEP_ALIVE", raising=False)
    monkeypatch.setenv(env_name, bad_value)
    called = _patch_uvicorn_run(monkeypatch)

    with pytest.raises(SystemExit):
        main_mod.main()

    assert called == {}, "uvicorn.run must not be invoked when carrier env validation fails"


@pytest.mark.asyncio
async def test_temporal_starter_does_not_import_worker(monkeypatch):
    """deploy/docker/ingest-gateway.Dockerfile installs only rca_common +
    services/gateway (design.md §11 one-service/one-image) -- no `worker`
    package is ever present in the real deployed image. A previous version of
    start_investigation imported worker.workflows.investigation.InvestigationWorkflow
    directly, which raised ModuleNotFoundError on every real investigation in
    any real deployment; it was masked here only by a fake `worker` module a
    previous version of this test injected into sys.modules, which made the
    bug invisible. This test instead poisons every `worker`/`worker.*` entry
    in sys.modules with the None sentinel -- CPython's own convention for
    "this import was already attempted and disallowed", which makes any
    `import worker` (or `from worker.x import y`) inside start_investigation
    raise ImportError immediately. This has to be poison rather than absence:
    the real `services/worker` package IS legitimately installed in this
    job's shared venv (services/worker/tests import it directly, elsewhere in
    the same pytest session), so a bare `assert "worker" not in sys.modules`
    is order-dependent and was false whenever a worker test ran first in the
    same process -- exactly what broke this test the first time it ran as
    part of the full functional suite rather than gateway's tests alone. And
    poisoning only the top-level `worker` entry is not enough either: CPython
    resolves `from worker.workflows.investigation import X` by checking each
    dotted level's own sys.modules entry, and when `worker.workflows.
    investigation` is *already* fully cached from an earlier worker test in
    the same session, that check succeeds without re-touching the poisoned
    `worker` entry at all -- confirmed by reverting the gateway/main.py fix
    locally and finding this exact gap: poisoning only "worker" let the old
    buggy import through silently in a combined worker+gateway test run.
    Every existing dotted level must be poisoned for the same reason a
    partial mock would be. Also asserts start_workflow is called with the
    plain string "InvestigationWorkflow" (Temporal's untyped workflow-start
    form, which needs no import of worker's code at all)."""
    import sys

    sentinel = object()
    # Poison every dotted level already cached (handles "worker already
    # imported by an earlier test this session"), AND poison the top-level
    # name pre-emptively even if absent (handles "worker never imported yet
    # this process, but is installed on disk in this shared venv" -- a fresh
    # import would otherwise succeed silently).
    to_poison = {name for name in sys.modules if name == "worker" or name.startswith("worker.")}
    to_poison.add("worker")
    previous = {name: sys.modules.get(name, sentinel) for name in to_poison}
    for name in to_poison:
        sys.modules[name] = None  # type: ignore[assignment]
    try:
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
    finally:
        for name, value in previous.items():
            if value is sentinel:
                del sys.modules[name]
            else:
                sys.modules[name] = value

    assert wid == "wf-1"
    assert calls[0][0][0] == "InvestigationWorkflow", (
        f"expected the untyped workflow type name, got {calls[0][0]!r}"
    )
