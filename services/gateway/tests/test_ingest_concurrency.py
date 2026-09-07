"""FP-IG-5: ingest does no sync DB work on the event loop."""
from __future__ import annotations

import ast
import asyncio
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from gateway.app import create_app
from gateway.ingest import IngestService


class _BlockingFactory:
    """Session factory whose transaction blocks on an asyncio-compatible event."""

    def __init__(self, hold: float):
        self.hold = hold
        self.entered = 0

    def __call__(self):
        return self

    def __enter__(self):
        self.entered += 1
        time.sleep(self.hold)
        return MagicMock()

    def __exit__(self, *a):
        return False


@pytest.mark.asyncio
async def test_ingest_does_no_sync_db_work_on_the_event_loop():
    """Two concurrent ingests complete in ≈ T, not ≈ 2T; healthz answers under load."""
    hold = 0.25
    factory = _BlockingFactory(hold)
    svc = IngestService(
        factory,
        budget_defaults={},
        known_sources={"manual": "s"},
    )

    # Patch the DB work so only the session-factory block takes time.
    with (
        patch("gateway.ingest.get_platform", return_value=None),
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
    ):
        t0 = time.perf_counter()
        results = await asyncio.gather(
            svc.ingest(
                {
                    "source": "manual",
                    "platform_key": "p1",
                    "error_summary": "a",
                    "event_id": "00000000-0000-0000-0000-000000000001",
                }
            ),
            svc.ingest(
                {
                    "source": "manual",
                    "platform_key": "p1",
                    "error_summary": "b",
                    "event_id": "00000000-0000-0000-0000-000000000002",
                }
            ),
        )
        elapsed = time.perf_counter() - t0

    assert all(r[0] == 200 for r in results)
    # Concurrent: wall ≈ hold, not 2×hold. Allow slack for scheduling.
    assert elapsed < hold * 1.8, f"elapsed={elapsed:.3f}s suggests serialised txn (hold={hold})"
    assert factory.entered == 2

    # Concurrent healthz while an ingest is in flight.
    app = create_app(ingest_service=svc, source_secrets={"manual": "s"})
    hold2 = 0.4
    factory2 = _BlockingFactory(hold2)
    svc2 = IngestService(factory2, budget_defaults={}, known_sources={"manual": "s"})
    app2 = create_app(ingest_service=svc2, source_secrets={"manual": "s"})

    async with AsyncClient(
        transport=ASGITransport(app=app2), base_url="http://test"
    ) as client:
        with (
            patch("gateway.ingest.get_platform", return_value=None),
            patch("gateway.ingest.insert_alert_event"),
            patch("gateway.ingest.write_audit"),
        ):
            ingest_task = asyncio.create_task(
                svc2.ingest(
                    {
                        "source": "manual",
                        "platform_key": "p1",
                        "error_summary": "x",
                        "event_id": "00000000-0000-0000-0000-000000000003",
                    }
                )
            )
            await asyncio.sleep(0.05)  # let the thread start holding
            t_h0 = time.perf_counter()
            health = await client.get("/healthz")
            health_ms = (time.perf_counter() - t_h0) * 1000
            await ingest_task
    assert health.status_code == 200
    assert health_ms < 200, f"healthz blocked on event loop: {health_ms:.1f}ms"


def test_ingest_txn_is_a_sync_function_dispatched_through_the_threadpool():
    """Structural sibling: AST requires run_in_threadpool(_ingest_txn)."""
    src = Path(__file__).resolve().parents[1] / "gateway" / "ingest.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    ingest_fn = None
    txn_fn = None
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == "IngestService":
            for item in node.body:
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if item.name == "ingest":
                        ingest_fn = item
                    if item.name == "_ingest_txn":
                        txn_fn = item
    assert ingest_fn is not None
    assert txn_fn is not None
    assert isinstance(txn_fn, ast.FunctionDef), "_ingest_txn must be a plain def"
    assert isinstance(ingest_fn, ast.AsyncFunctionDef)

    # await run_in_threadpool(self._ingest_txn, ...)
    found = False
    for node in ast.walk(ingest_fn):
        if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
            call = node.value
            func = call.func
            name = None
            if isinstance(func, ast.Name):
                name = func.id
            elif isinstance(func, ast.Attribute):
                name = func.attr
            if name == "run_in_threadpool":
                found = True
                break
    assert found, "ingest must await run_in_threadpool(...)"

    # no self._session_factory outside _ingest_txn
    for node in ast.walk(ingest_fn):
        if isinstance(node, ast.Attribute) and node.attr == "_session_factory":
            raise AssertionError("ingest body must not call _session_factory")
