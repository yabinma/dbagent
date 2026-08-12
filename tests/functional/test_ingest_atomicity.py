"""FP-IG-16: concurrent identical alerts open exactly one investigation."""
from __future__ import annotations

import asyncio
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import select, text

from gateway.ingest import IngestService
from rca_common.db.models import AlertEventRow, Investigation, Platform
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import find_open_by_fingerprint


class _RecordingStarter:
    def __init__(self):
        self.started: list = []
        self._lock = threading.Lock()

    async def start_investigation(self, event, investigation_id):
        with self._lock:
            self.started.append(investigation_id)
        return f"investigation-{investigation_id}"


def _seed_platform(session_factory, platform_key: str) -> None:
    with session_factory() as session:
        session.add(
            Platform(
                platform_key=platform_key,
                platform_type="presto",
                deployment="k8s",
                status="online",
                config={},
            )
        )
        session.commit()


def _make_service(session_factory, starter):
    return IngestService(
        session_factory,
        budget_defaults={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        known_sources={"manual": "s"},
        workflow_starter=starter,
        correlation_window_seconds=1800,
    )


@pytest.mark.asyncio
async def test_concurrent_identical_alerts_open_exactly_one_investigation(postgres_dsn):
    """n=8 contenders; barrier AFTER every first lock-free correlation read completes.

    Call the real first lookup BEFORE entering the barrier so all eight
    transactions have observed 'missing' before any may open (C5 / FP-IG-16).
    """
    engine = make_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"atomicity-{uuid.uuid4().hex[:8]}"
    fingerprint_summary = "same-fingerprint-storm"
    n = 8

    _seed_platform(session_factory, platform_key)

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)

    barrier = threading.Barrier(n, timeout=30)
    arrived = {"count": 0}
    count_lock = threading.Lock()
    isolation_levels: list[str] = []
    isolation_lock = threading.Lock()

    from rca_common import investigation_repo as repo

    real_find = repo.find_open_by_fingerprint
    per_thread_calls: dict[int, int] = {}
    pt_lock = threading.Lock()

    def gated_find(session, **kwargs):
        tid = threading.get_ident()
        with pt_lock:
            per_thread_calls[tid] = per_thread_calls.get(tid, 0) + 1
            call_n = per_thread_calls[tid]
        # First (lock-free) call: run the real lookup, THEN barrier.
        # All eight must observe "missing" before any proceeds to open.
        if call_n == 1:
            result = real_find(session, **kwargs)
            # Capture isolation inside the contending transaction (not later).
            level = session.execute(text("SHOW transaction_isolation")).scalar()
            with isolation_lock:
                isolation_levels.append(str(level))
            with count_lock:
                arrived["count"] += 1
            try:
                barrier.wait()
            except threading.BrokenBarrierError as exc:
                raise AssertionError(
                    f"barrier expired; arrived={arrived['count']}/{n}"
                ) from exc
            return result
        return real_find(session, **kwargs)

    results: list = []

    def one(i: int):
        payload = {
            "source": "manual",
            "platform_key": platform_key,
            "error_summary": fingerprint_summary,
            "event_id": str(uuid.uuid4()),
            "occurred_at": "2026-08-11T00:00:00Z",
        }
        return asyncio.run(svc.ingest(payload))

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(repo, "find_open_by_fingerprint", gated_find)
            mp.setattr("gateway.ingest.find_open_by_fingerprint", gated_find)
            with ThreadPoolExecutor(max_workers=n) as pool:
                futs = [pool.submit(one, i) for i in range(n)]
                results = [f.result(timeout=60) for f in futs]
    finally:
        engine.dispose()

    opened = [r for r in results if r[0] == 202]
    merged = [r for r in results if r[0] == 200 and r[1].get("status") == "merged"]
    assert len(opened) == 1, f"expected exactly one 202, got {results}"
    assert len(merged) == n - 1, f"expected {n-1} merges, got {results}"
    assert len(starter.started) == 1

    # Isolation asserted inside contending transactions (C5).
    assert isolation_levels, "no isolation level captured inside contenders"
    for level in isolation_levels:
        assert "read committed" in level.lower().replace("-", " "), level

    engine = make_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            invs = session.scalars(
                select(Investigation).where(Investigation.platform_key == platform_key)
            ).all()
            ids = {i.investigation_id for i in invs}
            assert len(ids) == 1, f"investigations={ids}"

            events = session.scalars(
                select(AlertEventRow).where(AlertEventRow.platform_key == platform_key)
            ).all()
            assert len(events) == n

            received = session.execute(
                text(
                    "SELECT count(*) FROM audit_log WHERE action = 'event_received' "
                    "AND investigation_id = :iid"
                ),
                {"iid": list(ids)[0]},
            ).scalar()
            merged_n = session.execute(
                text(
                    "SELECT count(*) FROM audit_log WHERE action = 'event_merged' "
                    "AND investigation_id = :iid"
                ),
                {"iid": list(ids)[0]},
            ).scalar()
            assert int(received) == 1
            assert int(merged_n) == n - 1
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_merge_racing_open_keeps_single_investigation(postgres_dsn):
    """FP-IG-16 merge-vs-open: merger read/insert while an opener is uncommitted.

    No pre-seeded investigation — a committed seed would make the under-lock
    re-read succeed regardless of the advisory lock, so neutralising the lock
    would not turn the test red (review C2).

    Roles are passed through a ``contextvars.ContextVar`` that
    ``run_in_threadpool`` propagates into the AnyIO worker where
    ``_ingest_txn`` / ``find_open_by_fingerprint`` actually run. Inferring
    role from the outer ThreadPoolExecutor thread id is wrong: that id never
    appears on the transaction seam (review C2).

    Interleaving (n=8, half/half):
    - Open racers (4): first lock-free read on an empty slot → all miss →
      barrier → open path (lock → re-read → open/merge). The winning opener
      pauses after ``create_investigation`` (still uncommitted) until every
      merger has completed its first lock-free read.
    - Mergers (4): wait until an opener holds an uncommitted open, then
      perform a real first lock-free read (misses under READ COMMITTED) and
      proceed into the lock / re-read / merge path while that open is still
      in flight. This is the merge-vs-open case from §11.3.3 O.
    """
    import contextvars

    engine = make_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"merge-race-{uuid.uuid4().hex[:8]}"
    fingerprint_summary = "merge-racing-open-fp"
    n = 8
    n_openers = n // 2
    n_mergers = n - n_openers

    _seed_platform(session_factory, platform_key)
    # Deliberately no pre-seeded investigation — the open is concurrent.

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)

    opener_barrier = threading.Barrier(n_openers, timeout=30)
    # Set after create_investigation, *before* commit — opener still uncommitted.
    opener_holding_uncommitted = threading.Event()
    # Set once every merger has finished its first lock-free find.
    mergers_first_find_done = threading.Event()
    arrived = {"count": 0}
    merger_first_finds = {"count": 0}
    count_lock = threading.Lock()
    # Explicit role seam visible inside the transaction worker thread.
    role_var: contextvars.ContextVar[str] = contextvars.ContextVar(
        "ingest_race_role", default="opener"
    )
    role_by_index: dict[int, str] = {
        i: ("opener" if i < n_openers else "merger") for i in range(n)
    }
    # Prove roles were observed on the *transaction* thread, not only the
    # outer executor thread.
    roles_seen_on_txn: list[str] = []
    roles_seen_lock = threading.Lock()

    from rca_common import investigation_repo as repo

    real_find = repo.find_open_by_fingerprint
    real_create = repo.create_investigation
    per_txn_calls: dict[int, int] = {}
    pt_lock = threading.Lock()

    def gated_find(session, **kwargs):
        # Role comes from the contextvar propagated into this AnyIO worker.
        role = role_var.get()
        tid = threading.get_ident()
        with pt_lock:
            per_txn_calls[tid] = per_txn_calls.get(tid, 0) + 1
            call_n = per_txn_calls[tid]
        with roles_seen_lock:
            if call_n == 1:
                roles_seen_on_txn.append(role)

        if role == "merger":
            if call_n == 1:
                # Block until an opener has created an investigation but has
                # not yet committed — the read races an uncommitted open.
                if not opener_holding_uncommitted.wait(timeout=30):
                    raise AssertionError(
                        "timed out waiting for opener to hold uncommitted open"
                    )
                result = real_find(session, **kwargs)
                with count_lock:
                    merger_first_finds["count"] += 1
                    if merger_first_finds["count"] >= n_mergers:
                        mergers_first_find_done.set()
                return result
            return real_find(session, **kwargs)

        # Opener path: first real miss, barrier with other openers, then race.
        if call_n == 1:
            result = real_find(session, **kwargs)
            with count_lock:
                arrived["count"] += 1
            try:
                opener_barrier.wait()
            except threading.BrokenBarrierError as exc:
                raise AssertionError(
                    f"opener barrier expired; arrived={arrived['count']}/{n_openers}"
                ) from exc
            return result
        return real_find(session, **kwargs)

    def gated_create(session, **kwargs):
        inv = real_create(session, **kwargs)
        # Investigation row is in this transaction but not committed. Signal
        # mergers, then wait until they have all performed their first find
        # against this still-uncommitted state.
        opener_holding_uncommitted.set()
        if not mergers_first_find_done.wait(timeout=30):
            raise AssertionError(
                "timed out waiting for mergers to complete first find "
                f"while opener uncommitted; seen={merger_first_finds['count']}/{n_mergers}"
            )
        return inv

    results: list = [None] * n  # type: ignore[list-item]

    def one(i: int):
        # Bind role on this executor thread; anyio.to_thread copies the
        # context into the worker that runs _ingest_txn / gated_find.
        role_var.set(role_by_index[i])
        payload = {
            "source": "manual",
            "platform_key": platform_key,
            "error_summary": fingerprint_summary,
            "event_id": str(uuid.uuid4()),
            "occurred_at": "2026-08-11T00:00:00Z",
        }
        return asyncio.run(svc.ingest(payload))

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(repo, "find_open_by_fingerprint", gated_find)
            mp.setattr("gateway.ingest.find_open_by_fingerprint", gated_find)
            mp.setattr(repo, "create_investigation", gated_create)
            mp.setattr("gateway.ingest.create_investigation", gated_create)
            with ThreadPoolExecutor(max_workers=n) as pool:
                futs = {pool.submit(one, i): i for i in range(n)}
                for fut in futs:
                    idx = futs[fut]
                    results[idx] = fut.result(timeout=60)
    finally:
        # Unblock any waiter if a contender failed before signalling.
        opener_holding_uncommitted.set()
        mergers_first_find_done.set()
        engine.dispose()

    opened = [r for r in results if r[0] == 202]
    merged = [r for r in results if r[0] == 200 and r[1].get("status") == "merged"]
    assert len(opened) == 1, f"expected exactly one 202 open, got {results}"
    assert len(merged) == n - 1, f"expected {n-1} merges, got {results}"
    assert len(starter.started) == 1

    # Roles must have been observed on the transaction seam (not defaulted).
    with roles_seen_lock:
        seen = list(roles_seen_on_txn)
    assert seen.count("opener") == n_openers, f"opener roles on txn seam: {seen}"
    assert seen.count("merger") == n_mergers, f"merger roles on txn seam: {seen}"
    assert merger_first_finds["count"] == n_mergers, (
        f"mergers did not all read while opener uncommitted: "
        f"{merger_first_finds['count']}/{n_mergers}"
    )
    assert opener_holding_uncommitted.is_set()

    engine = make_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            invs = session.scalars(
                select(Investigation).where(Investigation.platform_key == platform_key)
            ).all()
            ids = {i.investigation_id for i in invs}
            assert len(ids) == 1, f"investigations={ids}"
            events = session.scalars(
                select(AlertEventRow).where(AlertEventRow.platform_key == platform_key)
            ).all()
            assert len(events) == n
    finally:
        engine.dispose()
