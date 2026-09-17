"""IngestService unit tests: normalize, reject, open, merge (Section 4.1 / §11.3).

UT-IG-1: ``_ingest_txn`` returns ``(status, payload, investigation_id)`` on every
branch; ``ingest`` preserves pre-flight reject pairs.
UT-IG-2: workflow starts only on the opened branch, never inside the thread.

GC-2 (FP-GC2-1/2/3): the lock-free merge is ``merge_existing_event_with_audit``,
one parameterized statement. The fake session below holds no committed
correlation candidate, so it answers that statement with ``None``; a test of
the fast branch patches the helper explicitly, and a test of the fallback
names the miss and keeps the frozen reject / advisory-lock / deciding-re-read
/ open assertions.

GC-5 (FP-GC5-1/2/3): that statement now runs inside the per-worker coalescer's
shared transaction, one savepoint per candidate, and ``_ingest_txn`` owns only
the individual reject / advisory-lock / open transaction a miss falls through
to. The ordered fake below therefore records savepoint, release, rollback-to,
commit and rollback in one trace, so a claim about the order of the real calls
is still a claim about order.
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from gateway.ingest import IngestService
from gateway.merge_commit import MergeHit, MergeMiss
from rca_common.db.models import AlertEventRow, Investigation, Platform
from rca_common.fingerprint import compute_fingerprint


class _Savepoint:
    """The nested SessionTransaction one candidate runs inside (FP-GC5-2)."""

    def __init__(self, session):
        self._session = session

    def commit(self):
        self._session.released += 1

    def rollback(self):
        self._session.rolled_back_to += 1


class _Sess:
    is_active = True

    def __init__(self, store):
        self.store = store
        self.added = []
        self.executed = []
        self.savepoints = 0
        self.released = 0
        self.rolled_back_to = 0

    def begin_nested(self):
        self.savepoints += 1
        return _Savepoint(self)

    def rollback(self):
        return None

    def get(self, model, key):
        if model is Platform:
            return self.store.get("platforms", {}).get(key)
        return None

    def add(self, obj):
        self.added.append(obj)
        if isinstance(obj, Platform):
            self.store.setdefault("platforms", {})[obj.platform_key] = obj
        if isinstance(obj, Investigation):
            self.store.setdefault("investigations", []).append(obj)
        if isinstance(obj, AlertEventRow):
            self.store.setdefault("events", []).append(obj)

    def commit(self):
        return None

    def execute(self, stmt, params=None):
        # No committed correlation candidate lives in this fake store, so the
        # GC-2 fused merge statement selects nothing and writes nothing.
        self.executed.append((stmt, params))
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        return result

    def scalars(self, stmt):
        class R:
            def __init__(self, items):
                self._items = items

            def __iter__(self):
                return iter(self._items)

            def first(self):
                return self._items[0] if self._items else None

        return R([])


class _Factory:
    def __init__(self, store):
        self.store = store
        self.last = None

    def __call__(self):
        self.last = _Sess(self.store)
        return _Ctx(self.last)


class _Ctx:
    def __init__(self, s):
        self.s = s

    def __enter__(self):
        return self.s

    def __exit__(self, *a):
        return False


class _Starter:
    def __init__(self):
        self.started = []

    async def start_investigation(self, event, investigation_id):
        self.started.append((event, investigation_id))
        return f"investigation-{investigation_id}"


def _online_platform(key="presto-us1", config=None):
    return Platform(
        platform_key=key,
        platform_type="presto",
        deployment="k8s",
        status="online",
        config=config or {},
    )


def _svc(store, starter=None, **kwargs):
    return IngestService(
        _Factory(store),
        budget_defaults=kwargs.pop(
            "budget_defaults",
            {"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        ),
        known_sources=kwargs.pop("known_sources", {"grafana-prod": "sec", "manual": "s"}),
        workflow_starter=starter,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# UT-IG-1 — pre-flight rejects and every _ingest_txn branch
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_preflight_missing_platform_key():
    code, body = await _svc({}).ingest({"error_summary": "x", "source": "manual"})
    assert code == 200
    assert body == {"status": "rejected", "reason": "missing_platform_key"}


@pytest.mark.asyncio
async def test_preflight_missing_error_summary():
    code, body = await _svc({}).ingest({"platform_key": "p", "source": "manual"})
    assert code == 200
    assert body == {"status": "rejected", "reason": "missing_error_summary"}


@pytest.mark.asyncio
async def test_reject_unknown_source():
    store = {"platforms": {"presto-us1": _online_platform()}}
    code, body = await _svc(store, known_sources={"grafana-prod": "s"}).ingest(
        {
            "source": "jenkins",
            "platform_key": "presto-us1",
            "error_summary": "x",
            "occurred_at": "2026-07-11T00:00:00Z",
        }
    )
    assert body["reason"] == "unknown_source"


@pytest.mark.asyncio
async def test_reject_unknown_platform():
    store = {"platforms": {}}
    with patch(
        "gateway.ingest.merge_existing_event_with_audit", return_value=None
    ), patch("gateway.ingest.get_platform", return_value=None), patch(
        "gateway.ingest.acquire_correlation_lock"
    ):
        code, body = await _svc(store).ingest(
            {
                "source": "manual",
                "platform_key": "nope",
                "error_summary": "x",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert code == 200
    assert body["status"] == "rejected"
    assert body["reason"] == "unknown_platform_key"


@pytest.mark.asyncio
async def test_reject_platform_not_ready():
    p = _online_platform()
    p.status = "pending_credentials"
    store = {"platforms": {"presto-us1": p}}
    with patch(
        "gateway.ingest.merge_existing_event_with_audit", return_value=None
    ), patch("gateway.ingest.get_platform", return_value=p), patch(
        "gateway.ingest.acquire_correlation_lock"
    ):
        code, body = await _svc(store).ingest(
            {
                "source": "manual",
                "platform_key": "presto-us1",
                "error_summary": "x",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert body["reason"] == "platform_not_ready"


@pytest.mark.asyncio
async def test_open_new_investigation():
    store = {"platforms": {"presto-us1": _online_platform()}}
    starter = _Starter()
    platform = _online_platform()
    with (
        patch("gateway.ingest.merge_existing_event_with_audit", return_value=None),
        patch("gateway.ingest.get_platform", return_value=platform),
        patch("gateway.ingest.find_open_by_fingerprint", return_value=None),
        patch("gateway.ingest.acquire_correlation_lock") as lock,
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
        patch("gateway.ingest.create_investigation"),
        patch("gateway.ingest.merge_platform_budget", return_value={"max_rounds": 15}),
    ):
        code, body = await _svc(store, starter=starter).ingest(
            {
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "Worker OOM killed",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert code == 202
    assert "investigation_id" in body
    assert len(starter.started) == 1
    lock.assert_called_once()


@pytest.mark.asyncio
async def test_merge_inside_correlation_window():
    inv_id = uuid.uuid4()
    inv = Investigation(
        investigation_id=inv_id,
        created_at=datetime.now(timezone.utc),
        platform_key="presto-us1",
        status="INVESTIGATING",
        trigger_event=uuid.uuid4(),
        workflow_id=f"investigation-{inv_id}",
        budget={"max_rounds": 15},
        spent={"rounds": 1, "cost_usd": 0},
    )
    store = {"platforms": {"presto-us1": _online_platform()}}
    starter = _Starter()
    with (
        patch(
            "gateway.ingest.merge_existing_event_with_audit", return_value=inv_id
        ) as fused,
        patch("gateway.ingest.get_platform") as platform_lookup,
        patch("gateway.ingest.find_open_by_fingerprint") as find,
        patch("gateway.ingest.acquire_correlation_lock") as lock,
        patch("gateway.ingest.insert_alert_event") as insert,
        patch("gateway.ingest.write_audit") as audit,
    ):
        code, body = await _svc(store, starter=starter).ingest(
            {
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "worker oom killed",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert code == 200
    assert body["status"] == "merged"
    assert body["investigation_id"] == str(inv_id)
    assert starter.started == []
    # FP-IG-16 / FP-GC2-1: the committed-case merge takes no advisory lock,
    # and the one statement replaced the platform lookup, the correlation
    # lookup and both ORM inserts.
    lock.assert_not_called()
    fused.assert_called_once()
    platform_lookup.assert_not_called()
    find.assert_not_called()
    insert.assert_not_called()
    audit.assert_not_called()


@pytest.mark.asyncio
async def test_ingest_txn_return_tuple_on_open():
    """UT-IG-1: _ingest_txn returns the three-tuple on the open branch."""
    store = {"platforms": {"presto-us1": _online_platform()}}
    svc = _svc(store)
    with (
        patch("gateway.ingest.merge_existing_event_with_audit", return_value=None),
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch("gateway.ingest.find_open_by_fingerprint", return_value=None),
        patch("gateway.ingest.acquire_correlation_lock"),
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
        patch("gateway.ingest.create_investigation"),
        patch("gateway.ingest.merge_platform_budget", return_value={}),
    ):
        status, payload, inv_id = svc._ingest_txn(
            {
                "event_id": str(uuid.uuid4()),
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "x",
                "severity": "high",
                "fingerprint": "fp",
            }
        )
    assert status == 202
    assert "investigation_id" in payload
    assert inv_id is not None
    assert str(inv_id) == payload["investigation_id"]


@pytest.mark.asyncio
async def test_ingest_txn_return_tuple_on_merge():
    """UT-IG-1: the under-lock merge branch still returns the merged triple.

    GC-5 moved the lock-free fused hit out of ``_ingest_txn`` and into the
    shared batch, so the merged triple this branch returns is the one the
    deciding re-read under the advisory lock produces.
    """
    inv_id = uuid.uuid4()
    inv = Investigation(
        investigation_id=inv_id,
        created_at=datetime.now(timezone.utc),
        platform_key="presto-us1",
        status="OPEN",
        trigger_event=uuid.uuid4(),
        workflow_id="w",
        budget={},
        spent={},
    )
    store = {"platforms": {"presto-us1": _online_platform()}}
    svc = _svc(store)
    with (
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch("gateway.ingest.acquire_correlation_lock"),
        patch("gateway.ingest.find_open_by_fingerprint", return_value=inv),
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
    ):
        status, payload, out_id = svc._ingest_txn(
            {
                "event_id": str(uuid.uuid4()),
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "x",
                "severity": "high",
                "fingerprint": "fp",
            }
        )
    assert status == 200
    assert payload["status"] == "merged"
    assert payload["investigation_id"] == str(inv_id)
    assert out_id is None


# ---------------------------------------------------------------------------
# UT-IG-2 — workflow start only on open, and never inside the thread
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_workflow_starts_only_on_opened_branch():
    store = {"platforms": {"presto-us1": _online_platform()}}
    starter = _Starter()
    with (
        patch("gateway.ingest.merge_existing_event_with_audit", return_value=None),
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch("gateway.ingest.find_open_by_fingerprint", return_value=None),
        patch("gateway.ingest.acquire_correlation_lock"),
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
        patch("gateway.ingest.create_investigation"),
        patch("gateway.ingest.merge_platform_budget", return_value={}),
    ):
        await _svc(store, starter=starter).ingest(
            {
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "Worker OOM killed",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert len(starter.started) == 1


@pytest.mark.asyncio
async def test_workflow_not_started_on_merge():
    inv = Investigation(
        investigation_id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        platform_key="presto-us1",
        status="OPEN",
        trigger_event=uuid.uuid4(),
        workflow_id="w",
        budget={},
        spent={},
    )
    store = {"platforms": {"presto-us1": _online_platform()}}
    starter = _Starter()
    with (
        patch(
            "gateway.ingest.merge_existing_event_with_audit",
            return_value=inv.investigation_id,
        ),
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
    ):
        await _svc(store, starter=starter).ingest(
            {
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "x",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert starter.started == []


@pytest.mark.asyncio
async def test_workflow_start_not_inside_threadpool():
    """UT-IG-2: start_investigation is awaited on the loop, not inside _ingest_txn."""
    store = {"platforms": {"presto-us1": _online_platform()}}
    starter = _Starter()
    calls: list[str] = []

    real_txn = IngestService._ingest_txn

    def tracking_txn(self, event):
        calls.append("txn")
        assert starter.started == [], "workflow started inside the thread"
        return real_txn(self, event)

    with (
        patch("gateway.ingest.merge_existing_event_with_audit", return_value=None),
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch("gateway.ingest.find_open_by_fingerprint", return_value=None),
        patch("gateway.ingest.acquire_correlation_lock"),
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
        patch("gateway.ingest.create_investigation"),
        patch("gateway.ingest.merge_platform_budget", return_value={}),
        patch.object(IngestService, "_ingest_txn", tracking_txn),
    ):
        await _svc(store, starter=starter).ingest(
            {
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "x",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert calls == ["txn"]
    assert len(starter.started) == 1


@pytest.mark.asyncio
async def test_merge_after_lock_re_read():
    """Under-lock re-read finds a winner the lock-free fused statement missed."""
    inv = Investigation(
        investigation_id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        platform_key="presto-us1",
        status="OPEN",
        trigger_event=uuid.uuid4(),
        workflow_id="w",
        budget={},
        spent={},
    )
    store = {"platforms": {"presto-us1": _online_platform()}}
    order: list[str] = []

    with (
        patch(
            "gateway.ingest.merge_existing_event_with_audit",
            side_effect=lambda *a, **k: order.append("fused") or None,
        ),
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch(
            "gateway.ingest.find_open_by_fingerprint",
            side_effect=lambda *a, **k: order.append("find") or inv,
        ) as find,
        patch(
            "gateway.ingest.acquire_correlation_lock",
            side_effect=lambda *a, **k: order.append("lock"),
        ) as lock,
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
    ):
        code, body = await _svc(store).ingest(
            {
                "source": "grafana-prod",
                "platform_key": "presto-us1",
                "error_summary": "race",
                "occurred_at": "2026-07-11T00:00:00Z",
            }
        )
    assert code == 200
    assert body["status"] == "merged"
    assert body["investigation_id"] == str(inv.investigation_id)
    lock.assert_called_once()
    # Exactly one correlation lookup survives, and it happens under the lock.
    assert find.call_count == 1
    assert order == ["fused", "lock", "find"], order


@pytest.mark.asyncio
async def test_normalize_computes_fingerprint():
    svc = IngestService(lambda: _Ctx(_Sess({})), budget_defaults={})
    event = svc.normalize_payload(
        {
            "source": "manual",
            "platform_key": "presto-us1",
            "error_summary": "Queue saturation",
            "occurred_at": "2026-07-11T00:00:00Z",
        }
    )
    assert event["fingerprint"] == compute_fingerprint("presto-us1", "Queue saturation")


# ---------------------------------------------------------------------------
# GC-2 — the fused committed-existing-case merge and its fallbacks
# (FP-GC2-1 / FP-GC2-2 / FP-GC2-3)
#
# Ordering here is ordering of fakes; the real statement, the real advisory
# lock and the real deciding re-read are decided by
# tests/functional/test_ingest_atomicity.py against a migrated PostgreSQL.
# ---------------------------------------------------------------------------


class _OrderedSavepoint:
    """Records the savepoint control statements GC-5 adds, in order."""

    def __init__(self, session):
        self._session = session

    def commit(self):
        self._session.released += 1
        self._session.trace.append("release")

    def rollback(self):
        if self._session.savepoint_error is not None:
            self._session.trace.append("rollback-to-raised")
            raise self._session.savepoint_error
        self._session.rolled_back_to += 1
        self._session.trace.append("rollback-to")
        if self._session.deactivate_on_error:
            # A recovery that "succeeds" but leaves the outer transaction
            # unusable: the proof the group relies on is gone.
            self._session.is_active = False


class _OrderedSess(_Sess):
    """Fake session recording savepoint/commit/rollback order on one trace."""

    def __init__(self, store, trace, *, commit_error=None, savepoint_error=None,
                 deactivate_on_error=False):
        super().__init__(store)
        self.trace = trace
        self.commit_error = commit_error
        self.savepoint_error = savepoint_error
        self.deactivate_on_error = deactivate_on_error
        self.committed = 0
        self.rolled_back = 0
        self.is_active = True

    def begin_nested(self):
        self.savepoints += 1
        self.trace.append("savepoint")
        return _OrderedSavepoint(self)

    def commit(self):
        if self.commit_error is not None:
            self.trace.append("commit-raised")
            raise self.commit_error
        self.committed += 1
        self.trace.append("commit")
        return None

    def rollback(self):
        self.rolled_back += 1
        self.trace.append("rollback")
        return None


class _OrderedFactory:
    def __init__(self, store, trace, *, commit_error=None, savepoint_error=None,
                 deactivate_on_error=False):
        self.store = store
        self.trace = trace
        self.commit_error = commit_error
        self.savepoint_error = savepoint_error
        self.deactivate_on_error = deactivate_on_error
        self.sessions: list[_OrderedSess] = []

    def __call__(self):
        session = _OrderedSess(
            self.store,
            self.trace,
            commit_error=self.commit_error,
            savepoint_error=self.savepoint_error,
            deactivate_on_error=self.deactivate_on_error,
        )
        self.sessions.append(session)
        return _OrderedCtx(session, self.trace)


class _OrderedCtx:
    def __init__(self, session, trace):
        self.session = session
        self.trace = trace

    def __enter__(self):
        return self.session

    def __exit__(self, exc_type, exc, tb):
        # A real Session context manager closes (and so rolls back) on the way
        # out; record which way out this was.
        self.trace.append("exit-error" if exc_type is not None else "exit-clean")
        return False


def _ordered_service(trace, *, commit_error=None, starter=None, store=None,
                     savepoint_error=None, deactivate_on_error=False):
    factory = _OrderedFactory(store if store is not None else {}, trace,
                              commit_error=commit_error,
                              savepoint_error=savepoint_error,
                              deactivate_on_error=deactivate_on_error)
    svc = IngestService(
        factory,
        budget_defaults={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        known_sources={"grafana-prod": "sec", "manual": "s"},
        workflow_starter=starter,
        correlation_window_seconds=1800,
    )
    return svc, factory


def _gc2_raw(**overrides):
    raw = {
        "source": "grafana-prod",
        "platform_key": "presto-us1",
        "error_summary": "worker oom killed",
        "occurred_at": "2026-07-11T00:00:00Z",
        "severity": "critical",
    }
    raw.update(overrides)
    return raw


@pytest.mark.asyncio
async def test_gc2_fast_merge_commits_before_return_and_never_starts_workflow():
    """FP-GC2-2 / FP-GC5-1: fused statement, savepoint, commit, then the 200.

    GC-5 re-scopes this pin exactly as it re-scopes the real-PostgreSQL one:
    the unchanged fused statement still carries the whole merge and the exact
    200 body still follows one durable commit, but the commit is now the
    shared batch's and the statement runs inside its own savepoint.
    """
    inv_id = uuid.uuid4()
    trace: list[str] = []
    starter = _Starter()
    svc, factory = _ordered_service(trace, starter=starter)

    def fused(session, *, event, default_correlation_window_seconds):
        trace.append("fused")
        # This transaction has not committed yet: every commit recorded so far
        # belongs to an already-completed transaction.
        assert trace.count("commit") == trace.count("exit-clean")
        assert default_correlation_window_seconds == 1800
        assert event["fingerprint"]
        return inv_id

    with (
        patch("gateway.ingest.merge_existing_event_with_audit", side_effect=fused),
        patch("gateway.ingest.get_platform") as platform_lookup,
        patch("gateway.ingest.find_open_by_fingerprint") as find,
        patch("gateway.ingest.acquire_correlation_lock") as lock,
        patch("gateway.ingest.insert_alert_event") as insert,
        patch("gateway.ingest.write_audit") as audit,
        patch("gateway.ingest.create_investigation") as create,
    ):
        code, body = await svc.ingest(_gc2_raw())
        second_code, second_body = await svc.ingest(_gc2_raw())
        await svc.close()

    # (a) Savepoint, the one fused statement, its release, then exactly one
    # commit -- before the 200 body is produced, on both invocations.
    assert trace == [
        "savepoint", "fused", "release", "commit", "exit-clean",
        "savepoint", "fused", "release", "commit", "exit-clean",
    ], trace
    assert all(s.committed == 1 for s in factory.sessions)
    assert all(s.savepoints == 1 and s.released == 1 for s in factory.sessions)
    assert all(s.rolled_back_to == 0 and s.rolled_back == 0 for s in factory.sessions)
    # (b) The HTTP pair is the unchanged 200 merged body, both times.
    assert code == 200
    assert body == {"status": "merged", "investigation_id": str(inv_id)}
    assert (second_code, second_body) == (code, body)
    # (c) No workflow is started for a merge, and no fallback work happened.
    assert starter.started == []
    platform_lookup.assert_not_called()
    find.assert_not_called()
    lock.assert_not_called()
    insert.assert_not_called()
    audit.assert_not_called()
    create.assert_not_called()


@pytest.mark.asyncio
async def test_gc2_fast_merge_execute_or_commit_failure_cannot_return_success():
    """FP-GC2-2 / FP-GC5-2: a statement or commit failure never returns a 2xx."""
    # (a) The one statement fails: its savepoint is rolled back, the read-only
    # outer transaction is rolled back rather than committed, and the caller
    # sees its own error rather than a status.
    trace: list[str] = []
    starter = _Starter()
    svc, factory = _ordered_service(trace, starter=starter)
    boom = RuntimeError("execute failed")
    with (
        patch("gateway.ingest.merge_existing_event_with_audit", side_effect=boom),
        patch("gateway.ingest.get_platform") as platform_lookup,
    ):
        with pytest.raises(RuntimeError, match="execute failed"):
            await svc.ingest(_gc2_raw())
        await svc.close()
    assert trace == [
        "savepoint", "rollback-to", "rollback", "exit-clean",
    ], trace
    assert all(s.committed == 0 for s in factory.sessions)
    platform_lookup.assert_not_called()
    assert starter.started == []

    # (b) The commit fails after a successful statement: no merged body is
    # produced and nothing is committed.
    trace = []
    starter = _Starter()
    commit_error = RuntimeError("commit failed")
    svc, factory = _ordered_service(trace, commit_error=commit_error, starter=starter)
    with patch(
        "gateway.ingest.merge_existing_event_with_audit", return_value=uuid.uuid4()
    ):
        with pytest.raises(RuntimeError, match="commit failed"):
            await svc.ingest(_gc2_raw())
        with pytest.raises(RuntimeError, match="commit failed"):
            await svc.ingest(_gc2_raw())
        await svc.close()
    assert trace == [
        "savepoint", "release", "commit-raised", "rollback", "exit-clean",
        "savepoint", "release", "commit-raised", "rollback", "exit-clean",
    ], trace
    assert all(s.committed == 0 for s in factory.sessions)
    assert starter.started == []


@pytest.mark.asyncio
async def test_gc2_fast_miss_preserves_platform_rejections():
    """FP-GC2-3: unknown and non-online platforms keep their exact rejects."""
    offline = _online_platform()
    offline.status = "pending_credentials"
    for platform, reason in ((None, "unknown_platform_key"), (offline, "platform_not_ready")):
        trace: list[str] = []
        starter = _Starter()
        svc, factory = _ordered_service(trace, starter=starter)
        with (
            patch(
                "gateway.ingest.merge_existing_event_with_audit", return_value=None
            ) as fused,
            patch("gateway.ingest.get_platform", return_value=platform),
            patch("gateway.ingest.acquire_correlation_lock") as lock,
            patch("gateway.ingest.find_open_by_fingerprint") as find,
            patch("gateway.ingest.insert_alert_event") as insert,
            patch("gateway.ingest.write_audit") as audit,
        ):
            code, body = await svc.ingest(_gc2_raw())
        assert code == 200, reason
        assert body == {"status": "rejected", "reason": reason}
        fused.assert_called_once()
        # The reject path is unchanged: one rejected alert row, one
        # event_rejected audit row, one commit, no lock and no correlation read.
        assert insert.call_args.kwargs["disposition"] == "rejected"
        assert insert.call_args.kwargs["reject_reason"] == reason
        assert insert.call_args.kwargs["investigation_id"] is None
        assert audit.call_args.kwargs["action"] == "event_rejected"
        assert audit.call_args.kwargs["investigation_id"] is None
        assert audit.call_args.kwargs["detail"]["reason"] == reason
        # The read-only batch transaction is rolled back, never committed, and
        # the individual reject transaction keeps its own single commit.
        assert trace == [
            "savepoint", "release", "rollback", "exit-clean",
            "commit", "exit-clean",
        ], (reason, trace)
        lock.assert_not_called()
        find.assert_not_called()
        assert starter.started == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "config,window",
    [
        ({"correlation_window_seconds": 900}, 900),
        ({"correlation_window": 600}, 600),
        ({}, 1800),
    ],
    ids=["primary-override", "legacy-override", "service-default"],
)
async def test_gc2_fast_miss_preserves_under_lock_merge(config, window):
    """FP-GC2-3: ordered fake calls — the lock precedes the deciding lookup."""
    inv = Investigation(
        investigation_id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        platform_key="presto-us1",
        status="OPEN",
        trigger_event=uuid.uuid4(),
        workflow_id="w",
        budget={},
        spent={},
    )
    trace: list[str] = []
    starter = _Starter()
    svc, _factory = _ordered_service(trace, starter=starter)
    platform = _online_platform(config=config)
    with (
        patch(
            "gateway.ingest.merge_existing_event_with_audit",
            side_effect=lambda *a, **k: trace.append("fused") or None,
        ),
        patch(
            "gateway.ingest.get_platform",
            side_effect=lambda *a, **k: trace.append("get_platform") or platform,
        ),
        patch(
            "gateway.ingest.acquire_correlation_lock",
            side_effect=lambda *a, **k: trace.append("lock"),
        ),
        patch(
            "gateway.ingest.find_open_by_fingerprint",
            side_effect=lambda *a, **k: trace.append("find") or inv,
        ) as find,
        patch(
            "gateway.ingest.insert_alert_event",
            side_effect=lambda *a, **k: trace.append("insert"),
        ) as insert,
        patch(
            "gateway.ingest.write_audit",
            side_effect=lambda *a, **k: trace.append("audit"),
        ) as audit,
        patch("gateway.ingest.create_investigation") as create,
    ):
        code, body = await svc.ingest(_gc2_raw())

    assert code == 200
    assert body == {"status": "merged", "investigation_id": str(inv.investigation_id)}
    assert trace == [
        "savepoint", "fused", "release", "rollback", "exit-clean",
        "get_platform", "lock", "find", "insert", "audit",
        "commit", "exit-clean",
    ], trace
    # The configured window, by the frozen Python precedence, still reaches
    # the deciding lookup.
    assert find.call_args.kwargs["correlation_window_seconds"] == window
    assert insert.call_args.kwargs["disposition"] == "merged"
    assert insert.call_args.kwargs["investigation_id"] == inv.investigation_id
    assert insert.call_args.kwargs["payload_ref"] is None
    assert audit.call_args.kwargs["action"] == "event_merged"
    assert audit.call_args.kwargs["investigation_id"] == inv.investigation_id
    assert set(audit.call_args.kwargs["detail"]) == {"event_id", "fingerprint"}
    create.assert_not_called()
    assert starter.started == []


@pytest.mark.asyncio
async def test_gc2_fast_miss_preserves_open_and_workflow_boundary():
    """FP-GC2-3: an under-lock miss still opens and starts one workflow."""
    trace: list[str] = []
    starter = _Starter()
    svc, _factory = _ordered_service(trace, starter=starter)
    platform = _online_platform()
    with (
        patch(
            "gateway.ingest.merge_existing_event_with_audit",
            side_effect=lambda *a, **k: trace.append("fused") or None,
        ),
        patch("gateway.ingest.get_platform", return_value=platform),
        patch(
            "gateway.ingest.acquire_correlation_lock",
            side_effect=lambda *a, **k: trace.append("lock"),
        ) as lock,
        patch(
            "gateway.ingest.find_open_by_fingerprint",
            side_effect=lambda *a, **k: trace.append("find") or None,
        ) as find,
        patch(
            "gateway.ingest.insert_alert_event",
            side_effect=lambda *a, **k: trace.append("insert"),
        ) as insert,
        patch(
            "gateway.ingest.write_audit",
            side_effect=lambda *a, **k: trace.append("audit"),
        ) as audit,
        patch(
            "gateway.ingest.create_investigation",
            side_effect=lambda *a, **k: trace.append("create"),
        ) as create,
        patch("gateway.ingest.merge_platform_budget", return_value={"max_rounds": 15}),
    ):
        event = svc.normalize_payload(_gc2_raw())
        status, payload, returned_id = svc._ingest_txn(event)
        assert starter.started == [], "workflow started inside the transaction"
        code, body = await svc.ingest(_gc2_raw())
        await svc.close()

    assert status == 202
    assert returned_id is not None
    assert payload == {"investigation_id": str(returned_id)}
    assert code == 202 and "investigation_id" in body
    # The direct transaction call owns the open path alone; the HTTP call adds
    # the read-only batch in front of the same unchanged open transaction.
    assert trace[:7] == [
        "lock", "find", "insert", "audit", "create", "commit", "exit-clean",
    ], trace
    assert trace[7:] == [
        "savepoint", "fused", "release", "rollback", "exit-clean",
        "lock", "find", "insert", "audit", "create", "commit", "exit-clean",
    ], trace
    assert lock.call_count == 2 and find.call_count == 2
    assert insert.call_args.kwargs["disposition"] == "opened"
    assert audit.call_args.kwargs["action"] == "event_received"
    assert create.call_count == 2
    # The workflow starts once, on the loop, after the transaction returned.
    assert len(starter.started) == 1
    assert starter.started[0][1] is not None


# ---------------------------------------------------------------------------
# GC-5 — the per-worker commit coalescer's integration with the write path
# (FP-GC5-1 / FP-GC5-2 / FP-GC5-3)
#
# Ordering here is ordering of fakes; the real savepoints, the real shared
# commit and the real advisory lock are decided by
# tests/functional/test_ingest_atomicity.py against a migrated PostgreSQL.
# ---------------------------------------------------------------------------


async def _gc5_gather(svc, count, *, event_ids=None):
    """Drive ``count`` concurrent ingests and record when each resolved."""
    resolutions: list[object] = []

    async def _one(index):
        raw = _gc2_raw()
        if event_ids is not None:
            raw["event_id"] = event_ids[index]
        try:
            outcome = await svc.ingest(raw)
        except BaseException as exc:  # noqa: BLE001 — the item's own failure
            resolutions.append(("error", index))
            return exc
        resolutions.append(("resolved", index))
        return outcome

    results = await asyncio.gather(*[_one(index) for index in range(count)])
    return results, resolutions


@pytest.mark.asyncio
async def test_gc5_batch_hit_resolves_only_after_outer_commit():
    """FP-GC5-1/3: one session, one savepoint per item, one commit, then 200s."""
    inv_id = uuid.uuid4()
    trace: list[str] = []
    starter = _Starter()
    svc, factory = _ordered_service(trace, starter=starter)

    def fused(session, *, event, default_correlation_window_seconds):
        trace.append("fused")
        assert default_correlation_window_seconds == 1800
        return inv_id

    with (
        patch("gateway.ingest.merge_existing_event_with_audit", side_effect=fused),
        patch("gateway.ingest.get_platform") as platform_lookup,
        patch("gateway.ingest.acquire_correlation_lock") as lock,
        patch("gateway.ingest.find_open_by_fingerprint") as find,
        patch("gateway.ingest.insert_alert_event") as insert,
        patch("gateway.ingest.write_audit") as audit,
    ):
        results, resolutions = await _gc5_gather(svc, 8)
        await svc.close()

    # (a) Eight candidates shared ONE session and ONE commit.
    assert len(factory.sessions) == 1, factory.sessions
    session = factory.sessions[0]
    assert session.savepoints == 8 and session.released == 8
    assert session.committed == 1
    assert session.rolled_back_to == 0 and session.rolled_back == 0

    # (b) The ordered trace: savepoint/fused/release per item, then the one
    # commit, and nothing resolves before it.
    assert trace == ["savepoint", "fused", "release"] * 8 + ["commit", "exit-clean"], (
        trace
    )
    assert len(resolutions) == 8
    assert all(kind == "resolved" for kind, _ in resolutions)

    # (c) Every request got the exact unchanged 200 body, and no workflow ran.
    for code, body in results:
        assert code == 200
        assert body == {"status": "merged", "investigation_id": str(inv_id)}
    assert starter.started == []
    platform_lookup.assert_not_called()
    lock.assert_not_called()
    find.assert_not_called()
    insert.assert_not_called()
    audit.assert_not_called()


@pytest.mark.asyncio
async def test_gc5_savepoint_failure_is_item_local_but_outer_failure_is_batch_wide():
    """FP-GC5-2: recoverable item failures are local; the rest fail the group."""
    inv_id = uuid.uuid4()

    def _fused_failing_at(index_to_fail, calls):
        def fused(session, *, event, default_correlation_window_seconds):
            position = len(calls)
            calls.append(event["event_id"])
            if position == index_to_fail:
                raise RuntimeError("item statement failed")
            return inv_id
        return fused

    # (a) A recoverable statement failure: its savepoint is rolled back, the
    # surrounding transaction stays usable, and the siblings still commit.
    trace: list[str] = []
    calls: list[str] = []
    starter = _Starter()
    svc, factory = _ordered_service(trace, starter=starter)
    with patch(
        "gateway.ingest.merge_existing_event_with_audit",
        side_effect=_fused_failing_at(1, calls),
    ):
        results, _ = await _gc5_gather(svc, 3)
        await svc.close()
    assert isinstance(results[1], RuntimeError), results
    assert str(results[1]) == "item statement failed"
    assert results[0] == (200, {"status": "merged", "investigation_id": str(inv_id)})
    assert results[2] == results[0]
    session = factory.sessions[0]
    assert session.savepoints == 3
    assert session.released == 2 and session.rolled_back_to == 1
    assert session.committed == 1 and session.rolled_back == 0
    assert len(calls) == 3, "the fused statement ran once per candidate"

    # (b) A failed savepoint recovery destroys the proof that the surrounding
    # transaction is usable: every unresolved member fails with the group, the
    # failing member keeps its own error, and nothing is committed or retried.
    trace = []
    calls = []
    recovery_error = RuntimeError("savepoint recovery failed")
    svc, factory = _ordered_service(
        trace, starter=_Starter(), savepoint_error=recovery_error
    )
    with patch(
        "gateway.ingest.merge_existing_event_with_audit",
        side_effect=_fused_failing_at(1, calls),
    ):
        results, _ = await _gc5_gather(svc, 3)
        await svc.close()
    assert results[0] is recovery_error
    assert isinstance(results[1], RuntimeError)
    assert str(results[1]) == "item statement failed"
    assert results[2] is recovery_error
    assert factory.sessions[0].committed == 0
    assert factory.sessions[0].rolled_back == 1
    assert len(calls) == 2, "a group-fatal failure stops the group, never retries"

    # (c) A recovery that leaves the outer transaction inactive is equally
    # fatal, even though the rollback itself reported success.
    trace = []
    calls = []
    svc, factory = _ordered_service(
        trace, starter=_Starter(), deactivate_on_error=True
    )
    with patch(
        "gateway.ingest.merge_existing_event_with_audit",
        side_effect=_fused_failing_at(1, calls),
    ):
        results, _ = await _gc5_gather(svc, 3)
        await svc.close()
    for result in results:
        assert isinstance(result, RuntimeError), result
        assert str(result) == "item statement failed"
    assert factory.sessions[0].committed == 0
    assert factory.sessions[0].rolled_back == 1

    # (d) A failed outer commit fails the whole group, is never retried, and
    # releases no success.
    trace = []
    calls = []
    commit_error = RuntimeError("outer commit failed")
    starter = _Starter()
    svc, factory = _ordered_service(trace, commit_error=commit_error, starter=starter)
    with patch(
        "gateway.ingest.merge_existing_event_with_audit",
        side_effect=_fused_failing_at(None, calls),
    ):
        results, resolutions = await _gc5_gather(svc, 4)
        await svc.close()
    assert [result for result in results] == [commit_error] * 4
    assert all(kind == "error" for kind, _ in resolutions)
    assert trace.count("commit-raised") == 1, trace
    assert trace.count("commit") == 0, trace
    assert factory.sessions[0].rolled_back == 1
    assert len(calls) == 4
    assert starter.started == []


@pytest.mark.asyncio
async def test_gc5_batch_miss_runs_frozen_fallback_once():
    """FP-GC5-3: a miss writes nothing in the group and is not re-fused."""
    trace: list[str] = []
    calls: list[str] = []
    starter = _Starter()
    svc, factory = _ordered_service(trace, starter=starter)
    platform = _online_platform()
    inv = Investigation(
        investigation_id=uuid.uuid4(),
        created_at=datetime.now(timezone.utc),
        platform_key="presto-us1",
        status="OPEN",
        trigger_event=uuid.uuid4(),
        workflow_id="w",
        budget={},
        spent={},
    )

    def fused(session, *, event, default_correlation_window_seconds):
        calls.append(event["event_id"])
        trace.append("fused")
        return None

    with (
        patch("gateway.ingest.merge_existing_event_with_audit", side_effect=fused),
        patch(
            "gateway.ingest.get_platform",
            side_effect=lambda *a, **k: trace.append("get_platform") or platform,
        ),
        patch(
            "gateway.ingest.acquire_correlation_lock",
            side_effect=lambda *a, **k: trace.append("lock"),
        ) as lock,
        patch(
            "gateway.ingest.find_open_by_fingerprint",
            side_effect=lambda *a, **k: trace.append("find") or inv,
        ) as find,
        patch(
            "gateway.ingest.insert_alert_event",
            side_effect=lambda *a, **k: trace.append("insert"),
        ) as insert,
        patch(
            "gateway.ingest.write_audit",
            side_effect=lambda *a, **k: trace.append("audit"),
        ) as audit,
        patch("gateway.ingest.create_investigation") as create,
    ):
        results, _ = await _gc5_gather(svc, 3)
        await svc.close()

    # (a) One read-only group transaction: three savepoints, three releases,
    # an explicit rollback, and NO commit.
    batch_session = factory.sessions[0]
    assert batch_session.savepoints == 3 and batch_session.released == 3
    assert batch_session.committed == 0, "a group of misses committed a transaction"
    assert batch_session.rolled_back == 1
    assert trace[:11] == [
        "savepoint", "fused", "release",
        "savepoint", "fused", "release",
        "savepoint", "fused", "release",
        "rollback", "exit-clean",
    ], trace

    # (b) Each miss then took the unchanged individual transaction exactly
    # once, and the fused statement was not repeated on it.
    assert len(calls) == 3, calls
    assert len(set(calls)) == 3
    assert len(factory.sessions) == 4, "one group session plus one per fallback"
    assert lock.call_count == 3 and find.call_count == 3
    assert insert.call_args.kwargs["disposition"] == "merged"
    assert audit.call_args.kwargs["action"] == "event_merged"
    create.assert_not_called()
    for code, body in results:
        assert code == 200
        assert body == {
            "status": "merged",
            "investigation_id": str(inv.investigation_id),
        }
    assert starter.started == []
    assert all(session.committed == 1 for session in factory.sessions[1:])
