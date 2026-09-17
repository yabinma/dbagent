"""FP-IG-5: ingest does no sync DB work on the event loop.

GC-5 (FP-GC5-3/4) adds a second synchronous database callback -- the shared
merge group -- so this module now proves the property for BOTH: the group and
the individual fallback transaction are plain synchronous functions, each
reached only through ``run_in_threadpool``, and neither the event-loop
coroutine nor the coalescer module touches a Session, a commit or a savepoint.
"""
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

INGEST_SOURCE = Path(__file__).resolve().parents[1] / "gateway" / "ingest.py"
COALESCER_SOURCE = Path(__file__).resolve().parents[1] / "gateway" / "merge_commit.py"
#: Every database helper the ingest path may reach, and the synchronous
#: transaction methods that alone may reach them.
DB_HELPERS = {
    "merge_existing_event_with_audit",
    "get_platform",
    "find_open_by_fingerprint",
    "acquire_correlation_lock",
    "insert_alert_event",
    "write_audit",
    "create_investigation",
}
SYNC_TRANSACTION_METHODS = ("_ingest_txn", "_execute_merge_batch")


class _BlockingFactory:
    """Session factory whose INDIVIDUAL transactions block on a real sleep.

    The first session it hands out is the shared merge group's, which runs its
    candidates in FIFO order by design; the claim under test is about the
    individual fallback transactions that follow a miss, so those are the ones
    made slow.
    """

    def __init__(self, hold: float, free_sessions: int = 1):
        self.hold = hold
        self.free_sessions = free_sessions
        self.entered = 0

    def __call__(self):
        return self

    def __enter__(self):
        self.entered += 1
        if self.entered > self.free_sessions:
            time.sleep(self.hold)
        return MagicMock()

    def __exit__(self, *a):
        return False


@pytest.mark.asyncio
async def test_ingest_does_no_sync_db_work_on_the_event_loop():
    """Two concurrent fallbacks complete in ≈ T, not ≈ 2T; healthz answers."""
    hold = 0.25
    factory = _BlockingFactory(hold)
    svc = IngestService(
        factory,
        budget_defaults={},
        known_sources={"manual": "s"},
    )

    # Patch the DB work so only the session-factory block takes time.
    with (
        patch("gateway.ingest.merge_existing_event_with_audit", return_value=None),
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
        await svc.close()

    assert all(r[0] == 200 for r in results)
    # Concurrent: wall ≈ hold, not 2×hold. Allow slack for scheduling.
    assert elapsed < hold * 1.8, f"elapsed={elapsed:.3f}s suggests serialised txn (hold={hold})"
    # One shared group session, then one individual session per miss.
    assert factory.entered == 3

    # Concurrent healthz while an ingest is in flight.
    app = create_app(ingest_service=svc, source_secrets={"manual": "s"})
    hold2 = 0.4
    factory2 = _BlockingFactory(hold2, free_sessions=0)
    svc2 = IngestService(factory2, budget_defaults={}, known_sources={"manual": "s"})
    app2 = create_app(ingest_service=svc2, source_secrets={"manual": "s"})

    async with AsyncClient(
        transport=ASGITransport(app=app2), base_url="http://test"
    ) as client:
        with (
            patch("gateway.ingest.merge_existing_event_with_audit", return_value=None),
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
            await svc2.close()
    assert health.status_code == 200
    assert health_ms < 200, f"healthz blocked on event loop: {health_ms:.1f}ms"


def _class_methods(tree: ast.AST, class_name: str) -> dict[str, ast.AST]:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            return {
                item.name: item
                for item in node.body
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
    raise AssertionError(f"{class_name} not found")


def _called_names(fn: ast.AST) -> set[str]:
    names = set()
    for node in ast.walk(fn):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name):
            names.add(func.id)
        elif isinstance(func, ast.Attribute):
            names.add(func.attr)
    return names


def _threadpool_dispatched(fn: ast.AST) -> set[str]:
    """First positional argument of every awaited ``run_in_threadpool`` call."""
    dispatched = set()
    for node in ast.walk(fn):
        if not (isinstance(node, ast.Await) and isinstance(node.value, ast.Call)):
            continue
        call = node.value
        func = call.func
        name = (
            func.id if isinstance(func, ast.Name)
            else (func.attr if isinstance(func, ast.Attribute) else None)
        )
        if name != "run_in_threadpool" or not call.args:
            continue
        target = call.args[0]
        dispatched.add(
            target.attr if isinstance(target, ast.Attribute)
            else ast.unparse(target)
        )
    return dispatched


def test_gc5_database_paths_are_sync_and_threadpool_dispatched():
    """FP-GC5-3/4: both database callbacks are plain sync, off the loop.

    GC-5 replaced the old one-transaction-only structural assertion: there are
    now two synchronous database callbacks, the shared merge group and the
    individual fallback transaction. Each must be a plain ``def``, each must be
    reached only through ``run_in_threadpool``, and the event-loop coroutine
    must still touch no Session, helper, commit or savepoint of its own.
    """
    ingest_src = INGEST_SOURCE.read_text(encoding="utf-8")
    ingest_tree = ast.parse(ingest_src)
    methods = _class_methods(ingest_tree, "IngestService")
    ingest_fn = methods["ingest"]
    close_fn = methods["close"]

    # (1) The coroutine is async; both database callbacks are plain defs.
    assert isinstance(ingest_fn, ast.AsyncFunctionDef)
    assert isinstance(close_fn, ast.AsyncFunctionDef)
    for name in SYNC_TRANSACTION_METHODS:
        assert name in methods, name
        assert isinstance(methods[name], ast.FunctionDef), f"{name} must be a plain def"

    # (2) The individual transaction is dispatched through the threadpool from
    # the coroutine, by that exact name.
    assert "_ingest_txn" in _threadpool_dispatched(ingest_fn), (
        "ingest must await run_in_threadpool(self._ingest_txn, ...)"
    )

    # (3) The shared group is dispatched through the threadpool too -- by the
    # coalescer's drainer, which is the only caller of the bound callback.
    coalescer_src = COALESCER_SOURCE.read_text(encoding="utf-8")
    coalescer_tree = ast.parse(coalescer_src)
    drainer = next(
        node for node in ast.walk(coalescer_tree)
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_run_batch"
    )
    assert "self._execute_batch" in {
        ast.unparse(call.args[0])
        for call in ast.walk(drainer)
        if isinstance(call, ast.Call)
        and getattr(call.func, "attr", getattr(call.func, "id", None))
        == "run_in_threadpool"
        and call.args
    }, "the merge group is not dispatched through run_in_threadpool"

    # (4) The coroutine itself touches no session, helper or transaction verb.
    for node in ast.walk(ingest_fn):
        if isinstance(node, ast.Attribute) and node.attr == "_session_factory":
            raise AssertionError("ingest body must not call _session_factory")
    loop_calls = _called_names(ingest_fn) | _called_names(close_fn)
    assert not (DB_HELPERS & loop_calls), sorted(DB_HELPERS & loop_calls)
    for verb in ("begin_nested", "commit", "rollback"):
        assert verb not in loop_calls, f"the event loop performs {verb}()"

    # (5) Every database helper is reachable only from the two synchronous
    # transaction methods, and each of them owns exactly the calls it should.
    txn_calls = _called_names(methods["_ingest_txn"])
    batch_calls = _called_names(methods["_execute_merge_batch"])
    assert "merge_existing_event_with_audit" in batch_calls, (
        "the shared group must call the fused merge helper"
    )
    assert "merge_existing_event_with_audit" not in txn_calls, (
        "the fused statement must not be repeated on the fallback"
    )
    assert DB_HELPERS - {"merge_existing_event_with_audit"} <= txn_calls, sorted(
        DB_HELPERS - {"merge_existing_event_with_audit"} - txn_calls
    )
    assert "begin_nested" in batch_calls, "the group lost its per-item savepoint"

    # ...and nowhere else in the module: no class-level or module-level call.
    # ``_reject`` is the third owner: a plain synchronous helper reached only
    # from the individual transaction.
    reject = methods["_reject"]
    assert isinstance(reject, ast.FunctionDef)
    assert "_reject" in _called_names(methods["_ingest_txn"])
    assert "_reject" not in _called_names(ingest_fn)
    assert "_reject" not in _called_names(methods["_execute_merge_batch"])
    owners = [methods[name] for name in SYNC_TRANSACTION_METHODS] + [reject]
    for node in ast.walk(ingest_tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in DB_HELPERS
        ):
            assert any(
                owner.lineno <= node.lineno <= (owner.end_lineno or node.lineno)
                for owner in owners
            ), f"{node.func.id} called at line {node.lineno}, outside a sync transaction"

    # (6) The coalescer module owns queueing only: no database import, no
    # Session, no transaction verb of its own.
    for node in ast.walk(coalescer_tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            rendered = ast.unparse(node)
            for forbidden in ("sqlalchemy", "rca_common", "psycopg", "gateway.ingest"):
                assert forbidden not in rendered, rendered
    # Identifier-level, not substring-level: the module is legitimately named
    # for the commit shape it groups, so the check is on what it CALLS.
    forbidden_names = {
        "begin_nested",
        "rollback",
        "execute",
        "session",
        "Session",
        "session_factory",
        "_session_factory",
        "engine",
        "connection",
    }
    used = set()
    for node in ast.walk(coalescer_tree):
        if isinstance(node, ast.Attribute):
            used.add(node.attr)
        elif isinstance(node, ast.Name):
            used.add(node.id)
        elif isinstance(node, ast.arg):
            used.add(node.arg)
    assert not (forbidden_names & used), sorted(forbidden_names & used)
    # ...and the one commit the shape is named for is not performed here: the
    # coalescer never calls `.commit()` on anything.
    assert not any(
        isinstance(node, ast.Call)
        and getattr(node.func, "attr", None) == "commit"
        for node in ast.walk(coalescer_tree)
    ), "the coalescer performs a commit of its own"
