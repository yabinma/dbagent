import asyncio

import httpx
import pytest
from temporalio.testing import WorkflowEnvironment

from rca_common.config import parse_config
from rca_common.llmclient import LiteLLMHTTPBackend, LLMClient, PGTraceStore, S3ObjectStore

import worker.worker_main as worker_main
from worker.worker_main import TASK_QUEUE, build_llm_client, run_worker


def _config(**overrides):
    raw = {
        "storage": {
            "postgres_dsn": "sqlite:///:memory:",
            "s3": {
                "endpoint": "http://minio.local:9000",
                "bucket": "dbagent",
                "access_key": "minioadmin",
                "secret_key": "minioadmin",
            },
        },
        "model_gateway": {"url": "http://model-gateway.local:4000", "master_key": "mk"},
        "tracing": {"backend": "builtin"},
        # Test harness only: allow ephemeral when no mounted key is available (W1).
        "signing": {"allow_ephemeral": True},
    }
    raw.update(overrides)
    return parse_config(raw)


def test_task_queue_constant():
    assert TASK_QUEUE == "rca-worker"


def test_build_llm_client_wires_expected_backends():
    config = _config()
    http_client = httpx.AsyncClient()
    llm_client = build_llm_client(config, http_client=http_client)

    assert isinstance(llm_client, LLMClient)
    assert isinstance(llm_client._backend, LiteLLMHTTPBackend)
    assert isinstance(llm_client._object_store, S3ObjectStore)
    assert isinstance(llm_client._trace_store, PGTraceStore)
    assert llm_client._tracing_backend == "builtin"
    assert llm_client._object_store._bucket == "dbagent"


def test_build_llm_client_defaults_to_owned_http_client():
    config = _config()
    llm_client = build_llm_client(config)
    assert isinstance(llm_client._backend, LiteLLMHTTPBackend)


@pytest.mark.asyncio
async def test_run_worker_polls_the_configured_task_queue(monkeypatch):
    """W1 / FP-IG-25: a non-default temporal.task_queue reaches Worker().

    Against the hardcoded ``TASK_QUEUE = "rca-worker"`` form this is red —
    the gateway starts workflows on the configured queue while the worker
    still polls the constant, and investigations are silently stranded.
    """
    captured: dict[str, object] = {}

    class FakeWorker:
        def __init__(self, client, *, task_queue, workflows, activities):
            captured["task_queue"] = task_queue

        async def run(self):
            return None

    monkeypatch.setattr(worker_main, "Worker", FakeWorker)
    monkeypatch.setattr(worker_main, "build_llm_client", lambda *_a, **_k: object())
    monkeypatch.setattr(
        worker_main, "build_investigation_activities", lambda *_a, **_k: object()
    )
    monkeypatch.setattr(worker_main, "investigation_activity_list", lambda *_a, **_k: [])

    class FakeDemo:
        generate = None

        def __init__(self, _llm):
            pass

    monkeypatch.setattr(worker_main, "LLMDemoActivities", FakeDemo)

    config = _config(
        temporal={
            "address": "localhost:7233",
            "namespace": "default",
            "task_queue": "non-default-queue",
        }
    )
    await run_worker(config, client=object())
    assert captured.get("task_queue") == "non-default-queue", (
        f"worker polled {captured.get('task_queue')!r}; "
        "a hardcoded TASK_QUEUE ignores temporal.task_queue"
    )


@pytest.mark.asyncio
async def test_run_worker_starts_and_hosts_ping_workflow_against_injected_client():
    """Exercises `run_worker`'s real wiring path (build_llm_client -> Worker
    construction -> `worker.run()`) using an injected time-skipping test
    client, so no live Temporal server or network is needed. Proves the
    entrypoint actually produces a worker capable of running `PingWorkflow`,
    not just that its helper functions type-check."""
    config = _config()
    async with await WorkflowEnvironment.start_time_skipping() as env:
        task = asyncio.create_task(run_worker(config, client=env.client))
        try:
            # give the worker a moment to register with the test server.
            await asyncio.sleep(0.2)
            result = await env.client.execute_workflow(
                "PingWorkflow",
                "hi",
                id="run-worker-smoke",
                task_queue=worker_main.TASK_QUEUE,
            )
            assert result == "pong:hi"
        finally:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task


def test_main_invokes_run_worker_with_loaded_config(monkeypatch, tmp_path):
    config_file = tmp_path / "config.yaml"
    config_file.write_text('storage:\n  postgres_dsn: "sqlite:///:memory:"\n')
    monkeypatch.setenv("DBAGENT_WORKER_CONFIG", str(config_file))

    captured = {}

    async def fake_run_worker(config, *, client=None):
        captured["config"] = config

    monkeypatch.setattr(worker_main, "run_worker", fake_run_worker)

    worker_main.main()

    assert captured["config"].storage.postgres_dsn == "sqlite:///:memory:"


def test_build_investigation_activities_fails_closed_without_ephemeral(monkeypatch):
    """W1: unwritable key_path without allow_ephemeral must raise (fail closed)."""
    from worker.worker_main import build_investigation_activities
    from unittest.mock import MagicMock

    config = _config(signing={"key_path": "/etc/dbagent/signing/ed25519.key", "allow_ephemeral": False})

    def boom(_path):
        raise OSError("read-only filesystem")

    monkeypatch.setattr("rca_common.signing.signer.bootstrap_signing_key", boom)
    with pytest.raises(OSError, match="read-only"):
        build_investigation_activities(
            config,
            llm_client=MagicMock(),
            probe_client=MagicMock(),
            session_factory=MagicMock(),
            object_store=MagicMock(),
        )


def test_build_investigation_activities_allows_ephemeral_when_flagged(monkeypatch):
    """W1: allow_ephemeral=true may use an in-process key for dev/test."""
    from worker.worker_main import build_investigation_activities
    from unittest.mock import MagicMock

    config = _config(signing={"key_path": "/etc/dbagent/signing/ed25519.key", "allow_ephemeral": True})

    def boom(_path):
        raise OSError("read-only filesystem")

    monkeypatch.setattr("rca_common.signing.signer.bootstrap_signing_key", boom)
    acts = build_investigation_activities(
        config,
        llm_client=MagicMock(),
        probe_client=MagicMock(),
        session_factory=MagicMock(),
        object_store=MagicMock(),
    )
    assert acts._signer is not None
