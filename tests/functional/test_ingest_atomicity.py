"""FP-IG-16: concurrent identical alerts open exactly one investigation.

GC-2 (FP-GC2-1/2/3) adds the real-PostgreSQL proofs for the fused
committed-existing-case merge and moves both ``n = 8`` race tests' lock-free
rendezvous onto it. The seam is a wrapper around
``gateway.ingest.merge_existing_event_with_audit``; ``find_open_by_fingerprint``
is deliberately left unpatched in both modules, so the deciding under-lock
re-read that follows the advisory lock is the real product read.

GC-4 (FP-GC4-1/3/4) runs every one of those product gateway-path proofs through
``gateway.main.make_gateway_engine`` -- the scoped synchronous Psycopg 3 engine
the gateway really builds -- and adds the planning-enabled fixture-integrity
proof and the separate plan-reuse regression below.
"""
from __future__ import annotations

import asyncio
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import select, text

from gateway.main import GATEWAY_PREPARE_THRESHOLD, make_gateway_engine
from gateway.ingest import IngestService
from rca_common.db.models import AlertEventRow, Investigation, Platform
from rca_common.db.session import make_session_factory
from rca_common.investigation_repo import (
    create_investigation,
    merge_existing_event_with_audit,
)


class _RecordingStarter:
    def __init__(self):
        self.started: list = []
        self._lock = threading.Lock()

    async def start_investigation(self, event, investigation_id):
        with self._lock:
            self.started.append(investigation_id)
        return f"investigation-{investigation_id}"


def _seed_platform(session_factory, platform_key: str, config: dict | None = None) -> None:
    with session_factory() as session:
        session.add(
            Platform(
                platform_key=platform_key,
                platform_type="presto",
                deployment="k8s",
                status="online",
                config=config if config is not None else {},
                created_at=datetime.now(timezone.utc),
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


_SEED_EVENT_SQL = text(
    "INSERT INTO alert_events (event_id, fingerprint, source, platform_key, severity, "
    "payload_ref, normalized, disposition, investigation_id, reject_reason, received_at) "
    "VALUES (:event_id, :fingerprint, 'manual', :platform_key, 'high', NULL, "
    "'{}'::jsonb, 'opened', :investigation_id, NULL, :received_at)"
)


def _seed_committed_case(
    session_factory,
    platform_key: str,
    fingerprint: str,
    *,
    age_seconds: int = 60,
    status: str = "OPEN",
) -> uuid.UUID:
    """One committed non-terminal investigation plus its correlating event."""
    investigation_id = uuid.uuid4()
    with session_factory() as session:
        create_investigation(
            session,
            investigation_id=investigation_id,
            platform_key=platform_key,
            status=status,
            trigger_event=uuid.uuid4(),
            workflow_id=f"investigation-{investigation_id}",
            budget={"max_rounds": 15},
        )
        session.execute(
            _SEED_EVENT_SQL,
            {
                "event_id": uuid.uuid4(),
                "fingerprint": fingerprint,
                "platform_key": platform_key,
                "investigation_id": investigation_id,
                "received_at": datetime.now(timezone.utc) - timedelta(seconds=age_seconds),
            },
        )
        session.commit()
    return investigation_id


def _payload(platform_key: str, fingerprint: str, *, event_id: str | None = None) -> dict:
    return {
        "source": "manual",
        "platform_key": platform_key,
        "error_summary": "gc2 merge",
        "fingerprint": fingerprint,
        "event_id": event_id or str(uuid.uuid4()),
        "occurred_at": "2026-09-16T00:00:00Z",
        "severity": "high",
    }


def _audit_count(session, investigation_id, action: str) -> int:
    return int(
        session.execute(
            text(
                "SELECT count(*) FROM audit_log WHERE action = :action "
                "AND investigation_id = :iid"
            ),
            {"action": action, "iid": investigation_id},
        ).scalar()
    )


GC5_CONTENDERS = 8
#: The only transaction-control statements the happy path may add per request.
GC5_SAVEPOINT_CONTROL = ("SAVEPOINT ", "RELEASE SAVEPOINT ")
#: ...and the failure-path one, owned by FP-GC5-2 rather than by a happy path.
GC5_ROLLBACK_TO_SAVEPOINT = "ROLLBACK TO SAVEPOINT "


def _split_cursor_statements(statements: list[str]) -> tuple[list[str], list[str]]:
    """Partition observed cursor statements into data-modifying and control.

    Transaction control is recognised by its own leading keyword, never by a
    substring: a data-modifying statement that merely mentions a savepoint in
    a comment stays on the data side and still has to answer for itself.
    """
    data: list[str] = []
    control: list[str] = []
    for statement in statements:
        head = statement.strip().upper()
        if head.startswith(GC5_SAVEPOINT_CONTROL) or head.startswith(
            GC5_ROLLBACK_TO_SAVEPOINT
        ):
            control.append(statement.strip())
        else:
            data.append(statement)
    return data, control


@pytest.mark.asyncio
async def test_concurrent_identical_alerts_open_exactly_one_investigation(postgres_dsn):
    """n=8 contenders on ONE loop; barrier immediately before the real lock.

    GC-5 moved the lock-free fused merge into a per-worker group that runs its
    candidates sequentially in one thread, so the old rendezvous on the fused
    seam would now deadlock rather than race. The contention that matters is
    unchanged and is where it always was: all eight fused statements miss in
    one read-only batch transaction, and only then do eight individual
    fallback transactions race at the advisory lock. Each waits in the
    threadpool immediately before the real ``acquire_correlation_lock`` and
    then calls it, so removing the lock or the deciding re-read still lets all
    eight open (C5 / FP-IG-16 / FP-GC2-3 / FP-GC5-3).
    """
    engine = make_gateway_engine(postgres_dsn)
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
    #: The backend each capture came from. Eight distinct backends is what
    #: makes the capture a claim about the eight CONTENDING transactions: a
    #: capture moved into the shared batch Session would report one backend
    #: eight times, and read committed either way.
    isolation_backends: list[int] = []
    isolation_lock = threading.Lock()
    fused_results: list = []

    from rca_common import investigation_repo as repo

    real_merge = repo.merge_existing_event_with_audit
    real_lock = repo.acquire_correlation_lock

    def recording_merge(session, **kwargs):
        # The real fused statement, inside the shared batch transaction: on an
        # empty slot every one of them must miss and write nothing.
        result = real_merge(session, **kwargs)
        with isolation_lock:
            fused_results.append(result)
        return result

    def gated_lock(session, platform_key_arg, fingerprint_arg):
        # Runs in the AnyIO worker thread that owns THIS contender's fallback
        # Session -- already open after `get_platform` -- immediately before
        # the real advisory lock. The isolation capture belongs here, not in
        # the batch Session, so it observes the eight contending transactions
        # rather than one batch transaction eight times (C5).
        try:
            observed = session.execute(
                text("SELECT current_setting('transaction_isolation'), pg_backend_pid()")
            ).one()
        except BaseException:
            barrier.abort()
            raise
        with isolation_lock:
            isolation_levels.append(str(observed[0]))
            isolation_backends.append(int(observed[1]))
        with count_lock:
            arrived["count"] += 1
        try:
            barrier.wait()
        except threading.BrokenBarrierError as exc:
            raise AssertionError(
                f"barrier expired; arrived={arrived['count']}/{n}"
            ) from exc
        return real_lock(session, platform_key_arg, fingerprint_arg)

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("gateway.ingest.merge_existing_event_with_audit", recording_merge)
            mp.setattr("gateway.ingest.acquire_correlation_lock", gated_lock)
            results = await asyncio.gather(
                *[
                    svc.ingest(_payload(platform_key, fingerprint_summary))
                    for _ in range(n)
                ]
            )
    finally:
        await svc.close()
        engine.dispose()

    opened = [r for r in results if r[0] == 202]
    merged = [r for r in results if r[0] == 200 and r[1].get("status") == "merged"]
    assert len(opened) == 1, f"expected exactly one 202, got {results}"
    assert len(merged) == n - 1, f"expected {n-1} merges, got {results}"
    assert len(starter.started) == 1

    # The race is not vacuous: every fused statement ran once and missed, so
    # the outcome was decided by the advisory lock and the read under it.
    assert fused_results == [None] * n, fused_results

    # Isolation asserted inside each contending fallback transaction (C5).
    assert isolation_levels, "no isolation level captured inside contenders"
    assert len(isolation_levels) == n
    for level in isolation_levels:
        assert "read committed" in level.lower().replace("-", " "), level
    assert len(isolation_backends) == n
    assert len(set(isolation_backends)) == n, (
        f"the isolation capture observed {len(set(isolation_backends))} backend(s) "
        f"for {n} contenders: {isolation_backends}"
    )

    engine = make_gateway_engine(postgres_dsn)
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
            dispositions = sorted(e.disposition for e in events)
            assert dispositions == ["merged"] * (n - 1) + ["opened"], dispositions

            assert _audit_count(session, list(ids)[0], "event_received") == 1
            assert _audit_count(session, list(ids)[0], "event_merged") == n - 1
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_merge_racing_open_keeps_single_investigation(postgres_dsn):
    """FP-IG-16 merge-vs-open: merger read/insert while an opener is uncommitted.

    No pre-seeded investigation -- a committed seed would make the under-lock
    re-read succeed regardless of the advisory lock, so neutralising the lock
    would not turn the test red (review C2).

    Roles are immutable event-ID membership, read from the ``event`` the fused
    helper is called with. Nothing here infers a role from a ``ContextVar``,
    from a thread identity or from thread-local state: under GC-5 one batch
    thread runs several contenders' statements in turn, so a per-thread role
    would be wrong by construction (FP-GC5-3).

    Interleaving (n=8, half/half), all on the one pytest event loop:
    - Open racers (4): enter immediately; their four fused statements miss in
      one read-only batch; the four fallbacks then rendezvous immediately
      before the real advisory lock. The winning opener pauses after
      ``create_investigation`` -- still uncommitted -- until every merger has
      run its own fused statement.
    - Mergers (4): each awaits an ``asyncio.Event`` the opener's hook sets
      through ``loop.call_soon_threadsafe`` before it enters ``svc.ingest`` at
      all; a synchronous ``threading.Event.wait()`` in a coroutine would block
      the single loop the drainer runs on and deadlock the test. Their fused
      statements must then miss, because READ COMMITTED cannot see the
      uncommitted open, and their fallbacks queue on the real advisory lock.
      This is the merge-vs-open case from 11.3.3 O, decided by the unpatched
      under-lock read (FP-GC2-3).
    """
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"merge-race-{uuid.uuid4().hex[:8]}"
    fingerprint_summary = "merge-racing-open-fp"
    n = 8
    n_openers = n // 2
    n_mergers = n - n_openers

    _seed_platform(session_factory, platform_key)
    # Deliberately no pre-seeded investigation -- the open is concurrent.

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)

    # Explicit immutable event IDs, in two disjoint sets. This membership is
    # the only role seam.
    opener_event_ids = tuple(str(uuid.uuid4()) for _ in range(n_openers))
    merger_event_ids = tuple(str(uuid.uuid4()) for _ in range(n_mergers))
    assert not set(opener_event_ids) & set(merger_event_ids)
    role_by_event_id = {
        **{event_id: "opener" for event_id in opener_event_ids},
        **{event_id: "merger" for event_id in merger_event_ids},
    }

    loop = asyncio.get_running_loop()
    opener_barrier = threading.Barrier(n_openers, timeout=30)
    # Set after create_investigation, *before* commit -- opener still
    # uncommitted. An asyncio.Event, bridged from the threadpool thread.
    opener_holding_uncommitted = asyncio.Event()
    # Set once every merger has run its own fused statement.
    mergers_first_find_done = threading.Event()
    arrived = {"count": 0}
    merger_first_finds = {"count": 0}
    count_lock = threading.Lock()
    roles_seen_on_txn: list[str] = []
    roles_seen_lock = threading.Lock()

    from rca_common import investigation_repo as repo

    real_merge = repo.merge_existing_event_with_audit
    real_create = repo.create_investigation
    real_lock = repo.acquire_correlation_lock

    def gated_merge(session, **kwargs):
        # Role from the immutable event id this call carries, nothing else.
        role = role_by_event_id[kwargs["event"]["event_id"]]
        with roles_seen_lock:
            roles_seen_on_txn.append(role)
        result = real_merge(session, **kwargs)
        if role == "merger":
            assert result is None, (
                f"READ COMMITTED must not see the uncommitted open; got {result}"
            )
            with count_lock:
                merger_first_finds["count"] += 1
                if merger_first_finds["count"] >= n_mergers:
                    mergers_first_find_done.set()
            return result
        try:
            assert result is None, f"fused merge hit an empty slot: {result}"
        except BaseException:
            opener_barrier.abort()
            raise
        return result

    def gated_lock(session, platform_key_arg, fingerprint_arg):
        # The openers' rendezvous, immediately before the real lock, in the
        # fallback thread that owns this contender's own Session. The mergers
        # reach it later, after the opener already holds it.
        with count_lock:
            arrived["count"] += 1
            waiting_for_openers = arrived["count"] <= n_openers
        if waiting_for_openers:
            try:
                opener_barrier.wait()
            except threading.BrokenBarrierError as exc:
                raise AssertionError(
                    f"opener barrier expired; arrived={arrived['count']}/{n_openers}"
                ) from exc
        return real_lock(session, platform_key_arg, fingerprint_arg)

    def gated_create(session, **kwargs):
        inv = real_create(session, **kwargs)
        # Investigation row is in this transaction but not committed. Signal
        # the mergers from this threadpool thread onto the loop, then wait
        # until they have all run their fused statement against this
        # still-uncommitted state.
        loop.call_soon_threadsafe(opener_holding_uncommitted.set)
        if not mergers_first_find_done.wait(timeout=30):
            raise AssertionError(
                "timed out waiting for mergers to complete their fused merge "
                f"while opener uncommitted; seen={merger_first_finds['count']}/{n_mergers}"
            )
        return inv

    async def _opener(event_id: str):
        return await svc.ingest(
            _payload(platform_key, fingerprint_summary, event_id=event_id)
        )

    async def _merger(event_id: str):
        await asyncio.wait_for(opener_holding_uncommitted.wait(), 30)
        return await svc.ingest(
            _payload(platform_key, fingerprint_summary, event_id=event_id)
        )

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("gateway.ingest.merge_existing_event_with_audit", gated_merge)
            mp.setattr("gateway.ingest.acquire_correlation_lock", gated_lock)
            mp.setattr(repo, "create_investigation", gated_create)
            mp.setattr("gateway.ingest.create_investigation", gated_create)
            results = await asyncio.gather(
                *[_opener(event_id) for event_id in opener_event_ids],
                *[_merger(event_id) for event_id in merger_event_ids],
            )
    finally:
        # Unblock any waiter if a contender failed before signalling.
        mergers_first_find_done.set()
        loop.call_soon_threadsafe(opener_holding_uncommitted.set)
        await svc.close()
        engine.dispose()

    opened = [r for r in results if r[0] == 202]
    merged = [r for r in results if r[0] == 200 and r[1].get("status") == "merged"]
    assert len(opened) == 1, f"expected exactly one 202 open, got {results}"
    assert len(merged) == n - 1, f"expected {n-1} merges, got {results}"
    assert len(starter.started) == 1

    # Roles must have been observed on the fused-statement seam, by event id.
    with roles_seen_lock:
        seen = list(roles_seen_on_txn)
    assert seen.count("opener") == n_openers, f"opener roles on txn seam: {seen}"
    assert seen.count("merger") == n_mergers, f"merger roles on txn seam: {seen}"
    assert len(seen) == n, f"the fused merge runs exactly once per request: {seen}"
    assert merger_first_finds["count"] == n_mergers, (
        f"mergers did not all read while opener uncommitted: "
        f"{merger_first_finds['count']}/{n_mergers}"
    )
    assert opener_holding_uncommitted.is_set()

    engine = make_gateway_engine(postgres_dsn)
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
            dispositions = sorted(e.disposition for e in events)
            assert dispositions == ["merged"] * (n - 1) + ["opened"], dispositions
            assert _audit_count(session, list(ids)[0], "event_received") == 1
            assert _audit_count(session, list(ids)[0], "event_merged") == n - 1
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# GC-2 — the fused committed-existing-case merge against real PostgreSQL
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gc2_existing_merge_is_one_product_statement_plus_commit(postgres_dsn):
    """FP-GC2-1/2 (re-scoped by GC-5): one fused DML, savepoint control, one commit.

    Execution is observed at SQLAlchemy's cursor boundary, so the count is of
    statements the product really sent, not of calls the test made. GC-5 puts
    each candidate inside its own savepoint, so the observations are
    CLASSIFIED rather than counted raw: exactly one data-modifying statement
    per request -- the unchanged fused statement, one ``INSERT INTO
    alert_events``, one ``INSERT INTO audit_log``, no advisory lock -- and the
    only additional cursor statements the happy path may carry are the
    enumerated ``SAVEPOINT`` / ``RELEASE SAVEPOINT`` control statements. A
    second data-modifying statement, any other control statement, a second
    commit or any rollback fails this test. ``ROLLBACK TO SAVEPOINT`` is a
    failure-path statement and is owned by FP-GC5-2, never admitted here.
    """
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc2-one-stmt-{uuid.uuid4().hex[:8]}"
    fingerprint = f"fp-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key)
    investigation_id = _seed_committed_case(session_factory, platform_key, fingerprint)

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)
    event_id = str(uuid.uuid4())

    statements: list[str] = []
    commits: list[int] = []
    rollbacks: list[int] = []

    def _before_cursor(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    def _on_commit(conn):
        commits.append(1)

    def _on_rollback(conn):
        rollbacks.append(1)

    sa_event.listen(engine, "before_cursor_execute", _before_cursor)
    sa_event.listen(engine, "commit", _on_commit)
    sa_event.listen(engine, "rollback", _on_rollback)
    try:
        code, body = await svc.ingest(_payload(platform_key, fingerprint, event_id=event_id))
    finally:
        sa_event.remove(engine, "before_cursor_execute", _before_cursor)
        sa_event.remove(engine, "commit", _on_commit)
        sa_event.remove(engine, "rollback", _on_rollback)
        engine.dispose()

    # (a) The API contract is unchanged.
    assert code == 200
    assert body == {"status": "merged", "investigation_id": str(investigation_id)}
    assert starter.started == []

    # (b) Exactly one data-modifying statement, carrying both inserts; the
    # only other cursor statements are this request's savepoint and its
    # release; one commit; no rollback of any kind.
    data, control = _split_cursor_statements(statements)
    assert len(data) == 1, data
    only = data[0]
    assert only.count("INSERT INTO alert_events") == 1, only
    assert only.count("INSERT INTO audit_log") == 1, only
    assert "pg_advisory_xact_lock" not in only
    for statement in control:
        assert statement.upper().startswith(GC5_SAVEPOINT_CONTROL), statement
    assert len(control) == 2, control
    assert len(commits) == 1, commits
    assert rollbacks == []

    # (c) The persisted rows carry exactly the frozen values.
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            rows = session.execute(
                text(
                    "SELECT event_id, fingerprint, source, platform_key, severity, "
                    "payload_ref, normalized, disposition, investigation_id, "
                    "reject_reason, received_at FROM alert_events "
                    "WHERE event_id = :event_id"
                ),
                {"event_id": event_id},
            ).mappings().all()
            assert len(rows) == 1
            row = rows[0]
            assert str(row["event_id"]) == event_id
            assert row["fingerprint"] == fingerprint
            assert row["source"] == "manual"
            assert row["platform_key"] == platform_key
            assert row["severity"] == "high"
            assert row["payload_ref"] is None
            assert row["disposition"] == "merged"
            assert row["investigation_id"] == investigation_id
            assert row["reject_reason"] is None
            assert row["normalized"] == svc.normalize_payload(
                _payload(platform_key, fingerprint, event_id=event_id)
            )

            audits = session.execute(
                text(
                    "SELECT investigation_id, actor, action, detail, at FROM audit_log "
                    "WHERE action = 'event_merged' AND investigation_id = :iid"
                ),
                {"iid": investigation_id},
            ).mappings().all()
            assert len(audits) == 1
            audit = audits[0]
            assert audit["actor"] == "system"
            assert audit["action"] == "event_merged"
            assert audit["detail"] == {"event_id": event_id, "fingerprint": fingerprint}
            # One instant for the correlation boundary and both rows: an audit
            # timestamp can never precede its own event.
            assert audit["at"] == row["received_at"]
            # Exactly one admissible audit row for this merge, and no other
            # ingest audit action was written.
            assert _audit_count(session, investigation_id, "event_received") == 0
            assert (
                int(
                    session.execute(
                        text(
                            "SELECT count(*) FROM audit_log WHERE investigation_id = :iid"
                        ),
                        {"iid": investigation_id},
                    ).scalar()
                )
                == 1
            )
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_gc2_merge_commit_failure_rolls_back_event_and_audit(postgres_dsn):
    """FP-GC2-2: neither row survives a failed commit or a failed statement."""
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc2-rollback-{uuid.uuid4().hex[:8]}"
    fingerprint = f"fp-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key)
    investigation_id = _seed_committed_case(session_factory, platform_key, fingerprint)

    class _CommitFails:
        """Session proxy whose commit raises before the database commits."""

        def __init__(self, session):
            object.__setattr__(self, "_session", session)

        def __getattr__(self, name):
            return getattr(object.__getattribute__(self, "_session"), name)

        def commit(self):
            raise RuntimeError("induced commit failure")

    class _Ctx:
        def __init__(self, session):
            self._session = session

        def __enter__(self):
            return _CommitFails(self._session.__enter__())

        def __exit__(self, *exc):
            return self._session.__exit__(*exc)

    def failing_factory():
        return _Ctx(session_factory())

    starter = _RecordingStarter()
    failing = _make_service(failing_factory, starter)
    failed_event_id = str(uuid.uuid4())

    # (a) The commit fails: no 2xx reaches the caller and neither row is
    # visible afterwards.
    with pytest.raises(RuntimeError, match="induced commit failure"):
        await failing.ingest(
            _payload(platform_key, fingerprint, event_id=failed_event_id)
        )
    assert starter.started == []

    with session_factory() as session:
        assert (
            int(
                session.execute(
                    text("SELECT count(*) FROM alert_events WHERE event_id = :e"),
                    {"e": failed_event_id},
                ).scalar()
            )
            == 0
        ), "the merged event survived a failed commit"
        assert _audit_count(session, investigation_id, "event_merged") == 0, (
            "the audit row survived a failed commit"
        )

    # (b) The one statement fails: PostgreSQL cannot retain only one of its
    # two data-modifying CTEs. A duplicate event id aborts the statement after
    # a first, successful merge.
    from sqlalchemy.exc import IntegrityError

    svc = _make_service(session_factory, starter)
    duplicate_event_id = str(uuid.uuid4())
    code, body = await svc.ingest(
        _payload(platform_key, fingerprint, event_id=duplicate_event_id)
    )
    assert code == 200 and body["status"] == "merged"
    with pytest.raises(IntegrityError):
        await svc.ingest(
            _payload(platform_key, fingerprint, event_id=duplicate_event_id)
        )

    with session_factory() as session:
        assert (
            int(
                session.execute(
                    text("SELECT count(*) FROM alert_events WHERE event_id = :e"),
                    {"e": duplicate_event_id},
                ).scalar()
            )
            == 1
        )
        # The rejected retry left no second audit row behind.
        assert _audit_count(session, investigation_id, "event_merged") == 1
    engine.dispose()


# (config, event age in seconds, fast-statement hit?, end-to-end status).
# The fast statement takes only canonical integers; every other shape is a
# side-effect-free miss whose outcome is then decided by the frozen Python
# `int(...)` precedence on the fallback path.
GC2_WINDOW_CASES = [
    ("service-default", {}, 60, True, 200),
    ("primary-json-int", {"correlation_window_seconds": 900}, 60, True, 200),
    ("primary-outside-window", {"correlation_window_seconds": 900}, 1200, False, 202),
    ("primary-string-int", {"correlation_window_seconds": "900"}, 60, True, 200),
    ("legacy-json-int", {"correlation_window": 600}, 60, True, 200),
    ("legacy-outside-window", {"correlation_window": 600}, 900, False, 202),
    (
        "primary-beats-legacy",
        {"correlation_window_seconds": 60, "correlation_window": 100000},
        600,
        False,
        202,
    ),
    ("fractional-falls-back", {"correlation_window_seconds": 900.5}, 60, False, 200),
    ("boolean-falls-back", {"correlation_window_seconds": True}, 60, False, 202),
    ("whitespace-falls-back", {"correlation_window_seconds": " 900 "}, 60, False, 200),
    ("int32-overflow-falls-back", {"correlation_window_seconds": "2147483648"}, 60, False, 200),
    # Twelve bytes, so the octet_length guard refuses it even though the
    # digits are a canonical 900 that the Python int(...) path accepts.
    ("long-digits-fall-back", {"correlation_window_seconds": "000000000900"}, 60, False, 200),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "label,config,age_seconds,fast_hit,expected_status",
    GC2_WINDOW_CASES,
    ids=[case[0] for case in GC2_WINDOW_CASES],
)
async def test_gc2_window_override_fast_and_fallback_cases(
    postgres_dsn, label, config, age_seconds, fast_hit, expected_status
):
    """FP-GC2-3: actual SQL decides precedence; ineligible overrides fall back."""
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc2-window-{uuid.uuid4().hex[:8]}"
    fingerprint = f"fp-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key, config)
    investigation_id = _seed_committed_case(
        session_factory, platform_key, fingerprint, age_seconds=age_seconds
    )

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)
    try:
        # (a) The fast statement's own verdict, discarded afterwards.
        probe_event = svc.normalize_payload(_payload(platform_key, fingerprint))
        with session_factory() as session:
            probed = merge_existing_event_with_audit(
                session,
                event=probe_event,
                default_correlation_window_seconds=1800,
            )
            session.rollback()
        if fast_hit:
            assert probed == investigation_id, label
        else:
            assert probed is None, (label, probed)

        # (b) The end-to-end outcome, which the frozen Python path decides on
        # every fast miss.
        event_id = str(uuid.uuid4())
        code, body = await svc.ingest(
            _payload(platform_key, fingerprint, event_id=event_id)
        )
        assert code == expected_status, (label, code, body)
        if expected_status == 200:
            assert body == {
                "status": "merged",
                "investigation_id": str(investigation_id),
            }, label
        else:
            assert body["investigation_id"] != str(investigation_id), label

        with session_factory() as session:
            # The discarded probe left nothing behind.
            assert (
                int(
                    session.execute(
                        text("SELECT count(*) FROM alert_events WHERE event_id = :e"),
                        {"e": probe_event["event_id"]},
                    ).scalar()
                )
                == 0
            ), label
            merged_rows = int(
                session.execute(
                    text(
                        "SELECT count(*) FROM alert_events WHERE platform_key = :p "
                        "AND disposition = 'merged'"
                    ),
                    {"p": platform_key},
                ).scalar()
            )
            assert merged_rows == (1 if expected_status == 200 else 0), label
            assert _audit_count(session, investigation_id, "event_merged") == (
                1 if expected_status == 200 else 0
            ), label
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# GC-4 — the planning-enabled fixture, then the plan-reuse regression that
# rests on it. Two separate tests on purpose: fixture trustworthiness is
# established before any plans/calls ratio is allowed to mean anything.
# ---------------------------------------------------------------------------

GC4_FUSED_QUERY_PREFIX = "WITH platform AS MATERIALIZED"
GC4_MERGE_CALLS = 1000
GC4_DISTINCT_FINGERPRINTS = 50
GC4_PLAN_RATIO_DIVISOR = 10


def _pgss_row(conn, pattern: str):
    return conn.execute(
        text(
            "SELECT calls, plans, total_plan_time FROM pg_stat_statements "
            "WHERE query LIKE :pattern"
        ),
        {"pattern": pattern},
    ).all()


def test_gc4_plan_reuse_fixture_tracks_planning(pg_stat_statements_dsn):
    """FP-GC4-4: the fixture proves its own preload, tracking, extension and reset.

    This test owns fixture trustworthiness. Without it, a server that silently
    failed to preload ``pg_stat_statements`` -- or one tracking execution but
    not planning -- would report ``plans = 0`` for every statement, and a
    ``plans < calls / 10`` assertion would pass for exactly the wrong reason.
    The ordinary shared factory builds the engine here: this is a claim about
    the server, not about the gateway's driver.
    """
    from rca_common.db.session import make_engine

    engine = make_engine(pg_stat_statements_dsn)
    try:
        with engine.connect() as conn:
            # (1) The server really was started with the preload and both
            # tracking settings -- read back from the running server, never
            # from the fixture's own command string.
            preload = conn.execute(text("SHOW shared_preload_libraries")).scalar()
            assert "pg_stat_statements" in (preload or ""), (
                f"shared_preload_libraries={preload!r} does not load pg_stat_statements"
            )
            track_planning = conn.execute(
                text("SHOW pg_stat_statements.track_planning")
            ).scalar()
            assert track_planning == "on", (
                f"pg_stat_statements.track_planning={track_planning!r}: planning "
                f"counters would be zero for every statement"
            )
            track = conn.execute(text("SHOW pg_stat_statements.track")).scalar()
            assert track == "all", f"pg_stat_statements.track={track!r}"

            # (2) The extension is installed, not merely preloaded.
            installed = conn.execute(
                text("SELECT extname FROM pg_extension WHERE extname = 'pg_stat_statements'")
            ).scalar()
            assert installed == "pg_stat_statements", (
                "pg_stat_statements is not installed in this database"
            )

            # (3) Reset really empties the view: a sentinel statement is
            # observed present, then observed gone. Without this, a fixture
            # that never reset could carry another test's counters.
            sentinel_alias = f"gc4_fixture_sentinel_{uuid.uuid4().hex[:8]}"
            conn.execute(text(f"SELECT CAST(:n AS integer) AS {sentinel_alias}"), {"n": 1})
            conn.commit()
            assert len(_pgss_row(conn, f"%{sentinel_alias}%")) == 1, (
                "the sentinel statement was not tracked at all"
            )
            conn.execute(text("SELECT pg_stat_statements_reset()"))
            conn.commit()
            assert _pgss_row(conn, f"%{sentinel_alias}%") == [], (
                "pg_stat_statements_reset() left the sentinel row behind"
            )

            # (4) ...and after the reset a uniquely aliased parameterized
            # probe produces positive call AND planning counters.
            probe_alias = f"gc4_fixture_probe_{uuid.uuid4().hex[:8]}"
            probes = 5
            for _ in range(probes):
                conn.execute(text(f"SELECT CAST(:n AS integer) AS {probe_alias}"), {"n": 7})
            conn.commit()
            rows = _pgss_row(conn, f"%{probe_alias}%")
            assert len(rows) == 1, f"expected exactly one probe row, got {rows}"
            calls, plans, total_plan_time = rows[0]
            assert calls == probes, f"calls={calls}, expected {probes} after the reset"
            assert plans > 0, "plans == 0: planning is not being counted"
            assert total_plan_time > 0, (
                "total_plan_time == 0: planning time is not being counted"
            )
    finally:
        engine.dispose()


def test_gc4_fused_merge_reuses_server_plan(pg_stat_statements_dsn):
    """FP-GC4-1: >=1000 real merges replan fewer than one time in ten.

    The production helper, the production session factory and the gateway's own
    engine constructor -- nothing here reimplements the statement, and nothing
    issues SQL ``PREPARE``. The row is matched STRUCTURALLY (``ltrim(query)``
    starts with the constant's first line, and the text carries both inserts),
    never by byte equality with the Psycopg 2 rendering or with the Python
    constant: SQLAlchemy's Psycopg dialect renders bind casts on the wire, so
    the observed text is legitimately different there.
    """
    engine = make_gateway_engine(pg_stat_statements_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc4-plan-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key)

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)

    # (1) Fifty committed non-terminal cases with distinct fingerprints, in the
    # B1 request shape (`burst-{i % 50}` error summaries, no explicit
    # fingerprint, so the product's own fingerprint function decides it).
    raws = [
        {
            "source": "manual",
            "platform_key": platform_key,
            "error_summary": f"burst-{index}",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
        }
        for index in range(GC4_DISTINCT_FINGERPRINTS)
    ]
    events = [svc.normalize_payload(raw) for raw in raws]
    fingerprints = {event["fingerprint"] for event in events}
    assert len(fingerprints) == GC4_DISTINCT_FINGERPRINTS, fingerprints
    for event in events:
        _seed_committed_case(session_factory, platform_key, event["fingerprint"])

    try:
        # (2) Reset AFTER every migration and seed statement, so the window
        # contains the measured merges and nothing else.
        with session_factory() as session:
            session.execute(text("SELECT pg_stat_statements_reset()"))
            session.commit()

        # (3) >=1000 real merges: one fresh Session context per request over
        # the one engine, a fresh event UUID each time, one commit each --
        # exactly what `_ingest_txn` does on a committed hit.
        for index in range(GC4_MERGE_CALLS):
            event = dict(events[index % GC4_DISTINCT_FINGERPRINTS])
            event["event_id"] = str(uuid.uuid4())
            with session_factory() as session:
                merged = merge_existing_event_with_audit(
                    session,
                    event=event,
                    default_correlation_window_seconds=1800,
                )
                assert merged is not None, (index, event["fingerprint"])
                session.commit()

        # (4) Exactly ONE structurally matched row. A type or query-shape fork
        # would produce two rows and is caught here rather than summed away.
        with session_factory() as session:
            rows = session.execute(
                text(
                    "SELECT query, calls, plans, total_plan_time "
                    "FROM pg_stat_statements "
                    "WHERE ltrim(query) LIKE :prefix"
                ),
                {"prefix": f"{GC4_FUSED_QUERY_PREFIX}%"},
            ).all()
        assert len(rows) == 1, (
            f"expected exactly one fused-merge row, got {len(rows)}: "
            f"{[(row[0][:80], row[1], row[2]) for row in rows]}"
        )
        query, calls, plans, total_plan_time = rows[0]
        assert query.lstrip().startswith(GC4_FUSED_QUERY_PREFIX), query[:120]
        assert query.count("INSERT INTO alert_events") == 1, query
        assert query.count("INSERT INTO audit_log") == 1, query

        # (5) The regression itself.
        print(
            f"GC-4 fused merge plan reuse: calls={calls} plans={plans} "
            f"ratio={plans / calls:.4f} total_plan_time_ms={total_plan_time:.3f}",
            flush=True,
        )
        assert calls >= GC4_MERGE_CALLS, f"calls={calls}"
        assert plans > 0, "plans == 0: the fixture is not counting planning"
        assert total_plan_time > 0, "total_plan_time == 0"
        assert plans < calls / GC4_PLAN_RATIO_DIVISOR, (
            f"the fused merge is replanned per call: plans={plans}, calls={calls}, "
            f"ratio={plans / calls:.4f} (bar: < {1 / GC4_PLAN_RATIO_DIVISOR})"
        )

        # (6) Defense in depth, after the ratio: the pooled physical connection
        # really carries the pinned threshold. Read through `getattr` so a
        # Psycopg 2 connection reports the miss as a value rather than as an
        # AttributeError.
        raw = engine.raw_connection()
        try:
            threshold = getattr(raw.driver_connection, "prepare_threshold", None)
            assert threshold == GATEWAY_PREPARE_THRESHOLD == 5, (
                f"{type(raw.driver_connection).__module__}."
                f"{type(raw.driver_connection).__name__} reports "
                f"prepare_threshold={threshold!r}"
            )
        finally:
            raw.close()
    finally:
        engine.dispose()


# ---------------------------------------------------------------------------
# GC-4 FP-GC4-5 — the quantitative gate: the fused statement's own server time.
#
# This is the one GC-4 performance outcome. It measures exactly the quantity
# the mechanism governs -- `(total_plan_time + total_exec_time) / calls` for
# the fused statement itself -- and nothing else. Container CPU, queueing and
# latency are recorded elsewhere and decide nothing.
# ---------------------------------------------------------------------------

#: Candidate fused-statement server time per call, as a fraction of its matched
#: Psycopg 2 control. The conservative envelope above every observed ratio
#: (0.143 one-thread, 0.292 RCA same-SQL prepared process CPU, 0.495 under
#: 40-thread contention) -- not the expected value of this sequential test,
#: whose own shape corresponds to the one-thread datum.
GC4_STATEMENT_TIME_RATIO = 0.60
#: Leg identity, established from the measurement itself rather than from a
#: driver name: the control replans essentially every call, the candidate
#: essentially never.
GC4_CONTROL_MIN_PLANS_PER_CALL = 0.90
GC4_CANDIDATE_MAX_PLANS_PER_CALL = 0.10


def _gc4_seed_population(session_factory, svc, platform_key: str) -> list[dict]:
    """One online platform and 50 committed non-terminal cases, B1 request shape."""
    _seed_platform(session_factory, platform_key)
    events = []
    for index in range(GC4_DISTINCT_FINGERPRINTS):
        event = svc.normalize_payload(
            {
                "source": "manual",
                "platform_key": platform_key,
                "error_summary": f"burst-{index}",
                "occurred_at": datetime.now(timezone.utc).isoformat(),
                "event_id": str(uuid.uuid4()),
            }
        )
        events.append(event)
        _seed_committed_case(session_factory, platform_key, event["fingerprint"])
    return events


def _gc4_measure_statement_leg(dsn: str, engine_factory, events: list[dict], label: str) -> dict:
    """One variant leg: fresh engine, own reset, >=1000 sequential merges, one row.

    The engine is disposed before this function returns, so the next leg's
    `pg_stat_statements_reset()` cannot run while a pooled connection of this
    leg -- and its retained server plan -- is still open.
    """
    engine = engine_factory(dsn)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            session.execute(text("SELECT pg_stat_statements_reset()"))
            session.commit()

        for index in range(GC4_MERGE_CALLS):
            event = dict(events[index % GC4_DISTINCT_FINGERPRINTS])
            event["event_id"] = str(uuid.uuid4())
            with session_factory() as session:
                merged = merge_existing_event_with_audit(
                    session,
                    event=event,
                    default_correlation_window_seconds=1800,
                )
                assert merged is not None, (label, index, event["fingerprint"])
                session.commit()

        with session_factory() as session:
            rows = session.execute(
                text(
                    "SELECT query, calls, plans, total_plan_time, total_exec_time "
                    "FROM pg_stat_statements WHERE ltrim(query) LIKE :prefix"
                ),
                {"prefix": f"{GC4_FUSED_QUERY_PREFIX}%"},
            ).all()
    finally:
        engine.dispose()

    assert len(rows) == 1, (
        f"{label}: expected exactly one fused-merge row, got {len(rows)}: "
        f"{[(row[0][:80], row[1], row[2]) for row in rows]}"
    )
    query, calls, plans, total_plan_time, total_exec_time = rows[0]
    assert query.lstrip().startswith(GC4_FUSED_QUERY_PREFIX), (label, query[:120])
    assert query.count("INSERT INTO alert_events") == 1, label
    assert query.count("INSERT INTO audit_log") == 1, label
    assert calls >= GC4_MERGE_CALLS, (label, calls)
    assert total_plan_time > 0, (label, total_plan_time)
    assert total_exec_time > 0, (label, total_exec_time)
    leg = {
        "label": label,
        "calls": int(calls),
        "plans": int(plans),
        "total_plan_time": float(total_plan_time),
        "total_exec_time": float(total_exec_time),
        "plans_per_call": float(plans) / float(calls),
        "server_us_per_call": 1000.0 * (float(total_plan_time) + float(total_exec_time))
        / float(calls),
    }
    print(
        f"GC-4 statement time [{label}]: calls={leg['calls']} plans={leg['plans']} "
        f"plans_per_call={leg['plans_per_call']:.4f} "
        f"total_plan_ms={leg['total_plan_time']:.3f} "
        f"total_exec_ms={leg['total_exec_time']:.3f} "
        f"server_us_per_call={leg['server_us_per_call']:.3f}",
        flush=True,
    )
    return leg


def test_gc4_fused_merge_reduces_server_statement_time(pg_stat_statements_dsn):
    """FP-GC4-5: prepared fused-statement server time/call <= 60% of the control.

    Two order-balanced rounds over four isolated, equivalent populations, each
    keyed by its own platform key so no leg can see another leg's rows. The
    control builds its engine with the shared
    ``rca_common.db.session.make_engine`` -- the testcontainers DSN is
    ``postgresql+psycopg2``, so that leg is the real unprepared path -- and the
    candidate with the gateway's own ``make_gateway_engine``. Leg identity is
    established by the measurement (`plans/calls`), never by a driver name, so
    a mutation that returns the candidate to Psycopg 2 fails here for its own
    reason rather than passing quietly.
    """
    from rca_common.db.session import make_engine

    seed_engine = make_engine(pg_stat_statements_dsn)
    seed_factory = make_session_factory(seed_engine)
    starter = _RecordingStarter()
    svc = _make_service(seed_factory, starter)
    suffix = uuid.uuid4().hex[:8]

    # (1) Four isolated but equivalent populations, all seeded before any round
    # is measured, each under its own platform key.
    legs = [
        ("round1-control", "control", f"gc4-r1c-{suffix}"),
        ("round1-candidate", "candidate", f"gc4-r1k-{suffix}"),
        ("round2-candidate", "candidate", f"gc4-r2k-{suffix}"),
        ("round2-control", "control", f"gc4-r2c-{suffix}"),
    ]
    populations: dict[str, list[dict]] = {}
    try:
        for label, _variant, platform_key in legs:
            populations[label] = _gc4_seed_population(seed_factory, svc, platform_key)
    finally:
        # Seed work is done; no seeding connection may be open across a leg's
        # own reset.
        seed_engine.dispose()

    factories = {"control": make_engine, "candidate": make_gateway_engine}

    # (2) Round one runs control then candidate; round two reverses that order.
    measured = [
        _gc4_measure_statement_leg(
            pg_stat_statements_dsn, factories[variant], populations[label], label
        )
        for label, variant, _platform_key in legs
    ]

    # (3) Leg identity, from the counters themselves.
    by_variant: dict[str, list[dict]] = {"control": [], "candidate": []}
    for (label, variant, _key), leg in zip(legs, measured):
        by_variant[variant].append(leg)
    for leg in by_variant["control"]:
        assert leg["plans_per_call"] >= GC4_CONTROL_MIN_PLANS_PER_CALL, (
            f"{leg['label']} is not an unprepared control: "
            f"plans/calls={leg['plans_per_call']:.4f}"
        )
    for leg in by_variant["candidate"]:
        assert leg["plans_per_call"] < GC4_CANDIDATE_MAX_PLANS_PER_CALL, (
            f"{leg['label']} did not reuse a server plan: "
            f"plans/calls={leg['plans_per_call']:.4f}"
        )

    # (4) Aggregate each variant across its two order-balanced legs.
    aggregates = {}
    for variant, variant_legs in by_variant.items():
        assert len(variant_legs) == 2, (variant, variant_legs)
        calls = sum(leg["calls"] for leg in variant_legs)
        server_ms = sum(
            leg["total_plan_time"] + leg["total_exec_time"] for leg in variant_legs
        )
        aggregates[variant] = 1000.0 * server_ms / calls
    ratio = aggregates["candidate"] / aggregates["control"]
    print(
        f"GC-4 statement time: control={aggregates['control']:.3f} us/call "
        f"candidate={aggregates['candidate']:.3f} us/call ratio={ratio:.4f} "
        f"(bar: <= {GC4_STATEMENT_TIME_RATIO})",
        flush=True,
    )

    # (5) The gate.
    assert aggregates["control"] > 0 and aggregates["candidate"] > 0
    assert aggregates["candidate"] <= GC4_STATEMENT_TIME_RATIO * aggregates["control"], (
        f"the prepared fused statement did not cut its own server time: "
        f"candidate={aggregates['candidate']:.3f} us/call, "
        f"control={aggregates['control']:.3f} us/call, ratio={ratio:.4f} "
        f"(bar: <= {GC4_STATEMENT_TIME_RATIO})"
    )


# ---------------------------------------------------------------------------
# GC-5 — the per-worker commit coalescer against real PostgreSQL
# (FP-GC5-1 / FP-GC5-2 / FP-GC5-3)
#
# The metric these nodes own is the number of OUTER commits the product really
# emitted for n concurrent committed hits, observed at SQLAlchemy's own
# transaction events rather than counted from calls the test made. Against the
# pre-GC-5 head the first node observes eight commits for eight requests; under
# the coalescer it observes one.
# ---------------------------------------------------------------------------

class _CursorTrace:
    """Thread-safe record of cursor statements and transaction events."""

    def __init__(self, engine):
        self._engine = engine
        self._lock = threading.Lock()
        self.statements: list[str] = []
        self.commits: list[float] = []
        self.rollbacks: list[float] = []
        self.savepoints: list[str] = []
        self.releases: list[str] = []
        self.rollback_savepoints: list[str] = []

    def _before_cursor(self, conn, cursor, statement, parameters, context, executemany):
        with self._lock:
            self.statements.append(statement)

    def _on_commit(self, conn):
        with self._lock:
            self.commits.append(time.monotonic())

    def _on_rollback(self, conn):
        with self._lock:
            self.rollbacks.append(time.monotonic())

    def _on_savepoint(self, conn, name):
        with self._lock:
            self.savepoints.append(str(name))

    def _on_release_savepoint(self, conn, name, context):
        with self._lock:
            self.releases.append(str(name))

    def _on_rollback_savepoint(self, conn, name, context):
        with self._lock:
            self.rollback_savepoints.append(str(name))

    _HOOKS = (
        ("before_cursor_execute", "_before_cursor"),
        ("commit", "_on_commit"),
        ("rollback", "_on_rollback"),
        ("savepoint", "_on_savepoint"),
        ("release_savepoint", "_on_release_savepoint"),
        ("rollback_savepoint", "_on_rollback_savepoint"),
    )

    def __enter__(self):
        for name, attr in self._HOOKS:
            sa_event.listen(self._engine, name, getattr(self, attr))
        return self

    def __exit__(self, *exc):
        for name, attr in self._HOOKS:
            sa_event.remove(self._engine, name, getattr(self, attr))
        return False

    def fused(self) -> list[str]:
        data, _control = _split_cursor_statements(self.statements)
        return data


@pytest.mark.asyncio
async def test_gc5_eight_concurrent_merges_share_one_durable_commit(postgres_dsn):
    """FP-GC5-1: eight committed hits, eight fused statements, ONE outer commit.

    The benchmark witness for the coalescer: outer commits per successful merge
    must be exactly ``1 / 8``, with eight exact event/audit pairs and no 200
    released before that commit succeeded. Against the pre-GC-5 head the same
    body observes eight commits -- a red at the governed quantity, not at a
    missing import.
    """
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc5-batch-{uuid.uuid4().hex[:8]}"
    fingerprint = f"fp-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key)
    investigation_id = _seed_committed_case(session_factory, platform_key, fingerprint)

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)
    event_ids = [str(uuid.uuid4()) for _ in range(GC5_CONTENDERS)]

    async def _one(event_id: str):
        code, body = await svc.ingest(
            _payload(platform_key, fingerprint, event_id=event_id)
        )
        return code, body, time.monotonic()

    try:
        with _CursorTrace(engine) as trace:
            results = await asyncio.gather(*[_one(event_id) for event_id in event_ids])
    finally:
        engine.dispose()

    # (a) One outer commit for the whole batch, and no rollback at all.
    assert len(trace.commits) == 1, (
        f"outer commits per batch = {len(trace.commits)}, expected 1 "
        f"(bar: {1}/{GC5_CONTENDERS} commits per successful merge)"
    )
    assert trace.rollbacks == [], trace.rollbacks
    assert len(trace.rollback_savepoints) == 0, trace.rollback_savepoints

    # (b) Eight unchanged fused statements, one per request, each carrying both
    # inserts and no advisory lock; every other statement is savepoint control.
    fused = trace.fused()
    assert len(fused) == GC5_CONTENDERS, [statement[:60] for statement in fused]
    for statement in fused:
        assert statement.count("INSERT INTO alert_events") == 1, statement
        assert statement.count("INSERT INTO audit_log") == 1, statement
        assert "pg_advisory_xact_lock" not in statement
    assert len(trace.savepoints) == GC5_CONTENDERS, trace.savepoints
    assert len(trace.releases) == GC5_CONTENDERS, trace.releases

    # (c) Eight exact 200 bodies, none released before the outer commit, and no
    # workflow for a merge.
    commit_at = trace.commits[0]
    for code, body, resolved_at in results:
        assert code == 200
        assert body == {
            "status": "merged",
            "investigation_id": str(investigation_id),
        }, body
        assert resolved_at >= commit_at, (
            "a 200 was released before the shared durable commit"
        )
    assert starter.started == []

    # (d) Eight persisted event/audit pairs, all of them inside that commit.
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            rows = session.execute(
                text(
                    "SELECT event_id, disposition, investigation_id FROM alert_events "
                    "WHERE platform_key = :p AND disposition = 'merged'"
                ),
                {"p": platform_key},
            ).mappings().all()
            assert len(rows) == GC5_CONTENDERS, rows
            assert {str(row["event_id"]) for row in rows} == set(event_ids)
            assert {row["investigation_id"] for row in rows} == {investigation_id}
            assert _audit_count(session, investigation_id, "event_merged") == GC5_CONTENDERS
            assert _audit_count(session, investigation_id, "event_received") == 0
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_gc5_savepoint_isolates_one_merge_failure_and_outer_commit_failure_fails_batch(
    postgres_dsn,
):
    """FP-GC5-2: one bad item is item-local; a failed outer commit fails all.

    (a) uses a REAL immediate constraint failure -- a duplicate ``event_id``
    against the primary key of ``alert_events`` -- inside a group of eight, so
    the isolation proved here is PostgreSQL's own savepoint behaviour and not
    a fake. (b) induces a failure at the one place whose outcome can be
    uncertain, the outer commit, and requires that no member is released as a
    success and no row survives.
    """
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc5-savepoint-{uuid.uuid4().hex[:8]}"
    fingerprint = f"fp-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key)
    investigation_id = _seed_committed_case(session_factory, platform_key, fingerprint)

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)

    # One committed merge first: its event id is the duplicate below.
    duplicate_event_id = str(uuid.uuid4())
    code, body = await svc.ingest(
        _payload(platform_key, fingerprint, event_id=duplicate_event_id)
    )
    assert code == 200 and body["status"] == "merged"

    # (a) Eight candidates, one of which repeats that event id.
    valid_event_ids = [str(uuid.uuid4()) for _ in range(GC5_CONTENDERS - 1)]
    event_ids = [valid_event_ids[0], duplicate_event_id, *valid_event_ids[1:]]
    try:
        with _CursorTrace(engine) as trace:
            results = await asyncio.gather(
                *[
                    svc.ingest(_payload(platform_key, fingerprint, event_id=event_id))
                    for event_id in event_ids
                ],
                return_exceptions=True,
            )
    finally:
        await svc.close()

    from sqlalchemy.exc import IntegrityError

    failed = results[1]
    assert isinstance(failed, IntegrityError), failed
    for index, result in enumerate(results):
        if index == 1:
            continue
        assert result == (
            200,
            {"status": "merged", "investigation_id": str(investigation_id)},
        ), (index, result)

    # One savepoint rollback for the bad item, one shared commit for the rest,
    # and no outer rollback: the surrounding transaction stayed usable.
    assert len(trace.rollback_savepoints) == 1, trace.rollback_savepoints
    assert len(trace.commits) == 1, trace.commits
    assert trace.rollbacks == [], trace.rollbacks
    assert len(trace.savepoints) == GC5_CONTENDERS, trace.savepoints
    assert len(trace.releases) == GC5_CONTENDERS - 1, trace.releases
    assert starter.started == []

    with session_factory() as session:
        merged_rows = int(
            session.execute(
                text(
                    "SELECT count(*) FROM alert_events WHERE platform_key = :p "
                    "AND disposition = 'merged'"
                ),
                {"p": platform_key},
            ).scalar()
        )
        # The first request plus the seven valid siblings; the duplicate
        # contributed no second row.
        assert merged_rows == GC5_CONTENDERS, merged_rows
        assert _audit_count(session, investigation_id, "event_merged") == GC5_CONTENDERS

    # (b) The outer commit fails: every member fails, nothing persists, and no
    # member is retried.
    class _CommitFails:
        """Session proxy whose outer commit raises before the database commits."""

        def __init__(self, session):
            object.__setattr__(self, "_session", session)

        def __getattr__(self, name):
            return getattr(object.__getattribute__(self, "_session"), name)

        def commit(self):
            raise RuntimeError("induced outer commit failure")

    class _Ctx:
        def __init__(self, session):
            self._session = session

        def __enter__(self):
            return _CommitFails(self._session.__enter__())

        def __exit__(self, *exc):
            return self._session.__exit__(*exc)

    def failing_factory():
        return _Ctx(session_factory())

    failing_starter = _RecordingStarter()
    failing = _make_service(failing_factory, failing_starter)
    failing_event_ids = [str(uuid.uuid4()) for _ in range(GC5_CONTENDERS)]
    try:
        with _CursorTrace(engine) as failing_trace:
            failed_results = await asyncio.gather(
                *[
                    failing.ingest(
                        _payload(platform_key, fingerprint, event_id=event_id)
                    )
                    for event_id in failing_event_ids
                ],
                return_exceptions=True,
            )
    finally:
        await failing.close()
        engine.dispose()

    assert len(failed_results) == GC5_CONTENDERS
    for result in failed_results:
        assert isinstance(result, RuntimeError), result
        assert "induced outer commit failure" in str(result)
    assert failing_trace.commits == [], failing_trace.commits
    assert failing_starter.started == []

    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            survivors = int(
                session.execute(
                    text(
                        "SELECT count(*) FROM alert_events WHERE event_id = ANY(:ids)"
                    ),
                    {"ids": [uuid.UUID(e) for e in failing_event_ids]},
                ).scalar()
            )
            assert survivors == 0, "a merged event survived a failed outer commit"
            assert _audit_count(session, investigation_id, "event_merged") == (
                GC5_CONTENDERS
            ), "an audit row survived a failed outer commit"
    finally:
        engine.dispose()


@pytest.mark.asyncio
async def test_gc5_batch_misses_preserve_one_open_and_complete_audit(postgres_dsn):
    """FP-GC5-3: misses leave the group unwritten and keep the frozen open path.

    Eight simultaneous no-case events: every fused statement misses inside one
    read-only group transaction, nothing is written there, and each event then
    takes the unchanged individual reject / advisory-lock / deciding-read /
    open transaction exactly once -- the fused statement is not repeated on
    the fallback. One 202, seven 200s, one investigation, eight events, one
    ``event_received`` and seven ``event_merged`` audit rows.
    """
    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc5-miss-{uuid.uuid4().hex[:8]}"
    fingerprint = f"fp-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key)

    starter = _RecordingStarter()
    svc = _make_service(session_factory, starter)
    event_ids = [str(uuid.uuid4()) for _ in range(GC5_CONTENDERS)]

    from rca_common import investigation_repo as repo

    real_merge = repo.merge_existing_event_with_audit
    fused_calls: list[tuple[str, object]] = []
    fused_lock = threading.Lock()

    def recording_merge(session, **kwargs):
        result = real_merge(session, **kwargs)
        with fused_lock:
            fused_calls.append((kwargs["event"]["event_id"], result))
        return result

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("gateway.ingest.merge_existing_event_with_audit", recording_merge)
            results = await asyncio.gather(
                *[
                    svc.ingest(_payload(platform_key, fingerprint, event_id=event_id))
                    for event_id in event_ids
                ]
            )
    finally:
        await svc.close()
        engine.dispose()

    # The fused statement ran exactly once per event and missed every time:
    # no group write, and no second fused call on the fallback.
    assert len(fused_calls) == GC5_CONTENDERS, fused_calls
    assert [event_id for event_id, _ in fused_calls] and sorted(
        event_id for event_id, _ in fused_calls
    ) == sorted(event_ids)
    assert {result for _, result in fused_calls} == {None}

    opened = [r for r in results if r[0] == 202]
    merged = [r for r in results if r[0] == 200 and r[1].get("status") == "merged"]
    assert len(opened) == 1, results
    assert len(merged) == GC5_CONTENDERS - 1, results
    assert len(starter.started) == 1

    engine = make_gateway_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    try:
        with session_factory() as session:
            invs = session.scalars(
                select(Investigation).where(Investigation.platform_key == platform_key)
            ).all()
            ids = {i.investigation_id for i in invs}
            assert len(ids) == 1, f"investigations={ids}"
            investigation_id = list(ids)[0]
            assert str(investigation_id) == opened[0][1]["investigation_id"]
            events = session.scalars(
                select(AlertEventRow).where(AlertEventRow.platform_key == platform_key)
            ).all()
            assert len(events) == GC5_CONTENDERS
            assert sorted(e.disposition for e in events) == (
                ["merged"] * (GC5_CONTENDERS - 1) + ["opened"]
            )
            assert {str(e.event_id) for e in events} == set(event_ids)
            assert _audit_count(session, investigation_id, "event_received") == 1
            assert _audit_count(session, investigation_id, "event_merged") == (
                GC5_CONTENDERS - 1
            )
    finally:
        engine.dispose()
