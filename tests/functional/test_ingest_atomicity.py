"""FP-IG-16: concurrent identical alerts open exactly one investigation.

GC-2 (FP-GC2-1/2/3) adds the real-PostgreSQL proofs for the fused
committed-existing-case merge and moves both ``n = 8`` race tests' lock-free
rendezvous onto it. The seam is a wrapper around
``gateway.ingest.merge_existing_event_with_audit``; ``find_open_by_fingerprint``
is deliberately left unpatched in both modules, so the deciding under-lock
re-read that follows the advisory lock is the real product read.
"""
from __future__ import annotations

import asyncio
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event as sa_event
from sqlalchemy import select, text

from gateway.ingest import IngestService
from rca_common.db.models import AlertEventRow, Investigation, Platform
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import create_investigation


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


@pytest.mark.asyncio
async def test_concurrent_identical_alerts_open_exactly_one_investigation(postgres_dsn):
    """n=8 contenders; barrier AFTER every lock-free fused merge has missed.

    Call the real fused statement BEFORE entering the barrier so all eight
    transactions have observed 'missing' before any may open (C5 / FP-IG-16 /
    FP-GC2-3). The fused statement takes no advisory lock and, on a miss,
    leaves no row lock, so all eight can sit in the rendezvous at once; the
    advisory lock and the deciding re-read after it are unpatched product code.
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

    real_merge = repo.merge_existing_event_with_audit

    def gated_merge(session, **kwargs):
        # Real fused statement first: on an empty slot it must miss, write
        # nothing, and hold no lock that would stop the other seven arriving.
        result = real_merge(session, **kwargs)
        try:
            assert result is None, f"fused merge hit an empty slot: {result}"
            # Capture isolation inside the contending transaction (not later);
            # the helper's execute has already opened it.
            level = session.execute(text("SHOW transaction_isolation")).scalar()
        except BaseException:
            barrier.abort()
            raise
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

    results: list = []

    def one(i: int):
        return asyncio.run(svc.ingest(_payload(platform_key, fingerprint_summary)))

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("gateway.ingest.merge_existing_event_with_audit", gated_merge)
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
    assert len(isolation_levels) == n
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
            dispositions = sorted(e.disposition for e in events)
            assert dispositions == ["merged"] * (n - 1) + ["opened"], dispositions

            assert _audit_count(session, list(ids)[0], "event_received") == 1
            assert _audit_count(session, list(ids)[0], "event_merged") == n - 1
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
    ``_ingest_txn`` / the fused merge statement actually run. Inferring role
    from the outer ThreadPoolExecutor thread id is wrong: that id never
    appears on the transaction seam (review C2).

    Interleaving (n=8, half/half):
    - Open racers (4): the real fused merge on an empty slot → all miss →
      barrier → open path (lock → deciding re-read → open/merge). The winning
      opener pauses after ``create_investigation`` (still uncommitted) until
      every merger has run its own fused merge.
    - Mergers (4): wait until an opener holds an uncommitted open, then run
      the real fused merge, which must miss because READ COMMITTED cannot see
      that uncommitted open, and proceed into the lock / re-read / merge path
      while it is still in flight. This is the merge-vs-open case from
      §11.3.3 O, now decided by the unpatched under-lock read (FP-GC2-3).
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
    # Set once every merger has run its own lock-free fused merge.
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

    real_merge = repo.merge_existing_event_with_audit
    real_create = repo.create_investigation

    def gated_merge(session, **kwargs):
        # Role comes from the contextvar propagated into this AnyIO worker.
        role = role_var.get()
        with roles_seen_lock:
            roles_seen_on_txn.append(role)

        if role == "merger":
            # Block until an opener has created an investigation but has not
            # yet committed — the fused statement races an uncommitted open.
            if not opener_holding_uncommitted.wait(timeout=30):
                raise AssertionError(
                    "timed out waiting for opener to hold uncommitted open"
                )
            result = real_merge(session, **kwargs)
            assert result is None, (
                f"READ COMMITTED must not see the uncommitted open; got {result}"
            )
            with count_lock:
                merger_first_finds["count"] += 1
                if merger_first_finds["count"] >= n_mergers:
                    mergers_first_find_done.set()
            return result

        # Opener path: real fused miss, barrier with other openers, then race.
        result = real_merge(session, **kwargs)
        try:
            assert result is None, f"fused merge hit an empty slot: {result}"
        except BaseException:
            opener_barrier.abort()
            raise
        with count_lock:
            arrived["count"] += 1
        try:
            opener_barrier.wait()
        except threading.BrokenBarrierError as exc:
            raise AssertionError(
                f"opener barrier expired; arrived={arrived['count']}/{n_openers}"
            ) from exc
        return result

    def gated_create(session, **kwargs):
        inv = real_create(session, **kwargs)
        # Investigation row is in this transaction but not committed. Signal
        # mergers, then wait until they have all run their fused merge against
        # this still-uncommitted state.
        opener_holding_uncommitted.set()
        if not mergers_first_find_done.wait(timeout=30):
            raise AssertionError(
                "timed out waiting for mergers to complete their fused merge "
                f"while opener uncommitted; seen={merger_first_finds['count']}/{n_mergers}"
            )
        return inv

    results: list = [None] * n  # type: ignore[list-item]

    def one(i: int):
        # Bind role on this executor thread; anyio.to_thread copies the
        # context into the worker that runs _ingest_txn / gated_merge.
        role_var.set(role_by_index[i])
        return asyncio.run(svc.ingest(_payload(platform_key, fingerprint_summary)))

    try:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr("gateway.ingest.merge_existing_event_with_audit", gated_merge)
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
    assert len(seen) == n, f"the fused merge runs exactly once per request: {seen}"
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
    """FP-GC2-1/2: one product statement carrying both inserts, then one commit.

    Execution is observed at SQLAlchemy's cursor boundary, so the count is of
    statements the product really sent, not of calls the test made.
    """
    engine = make_engine(postgres_dsn)
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

    # (b) Exactly one product statement, carrying both inserts, then one commit.
    assert len(statements) == 1, statements
    only = statements[0]
    assert only.count("INSERT INTO alert_events") == 1, only
    assert only.count("INSERT INTO audit_log") == 1, only
    assert "pg_advisory_xact_lock" not in only
    assert len(commits) == 1, commits
    assert rollbacks == []

    # (c) The persisted rows carry exactly the frozen values.
    engine = make_engine(postgres_dsn)
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
    engine = make_engine(postgres_dsn)
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
    engine = make_engine(postgres_dsn)
    session_factory = make_session_factory(engine)
    platform_key = f"gc2-window-{uuid.uuid4().hex[:8]}"
    fingerprint = f"fp-{uuid.uuid4().hex[:8]}"
    _seed_platform(session_factory, platform_key, config)
    investigation_id = _seed_committed_case(
        session_factory, platform_key, fingerprint, age_seconds=age_seconds
    )

    from rca_common.investigation_repo import merge_existing_event_with_audit

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
