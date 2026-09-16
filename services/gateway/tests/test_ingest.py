"""IngestService unit tests: normalize, reject, open, merge (Section 4.1 / §11.3).

UT-IG-1: ``_ingest_txn`` returns ``(status, payload, investigation_id)`` on every
branch; ``ingest`` preserves pre-flight reject pairs.
UT-IG-2: workflow starts only on the opened branch, never inside the thread.

GC-2 (FP-GC2-1/2/3): the lock-free merge is ``merge_existing_event_with_audit``,
one parameterized statement executed before ``get_platform``. The fake session
below holds no committed correlation candidate, so it answers that statement
with ``None``; a test of the fast branch patches the helper explicitly, and a
test of the fallback names the miss and keeps the frozen reject /
advisory-lock / deciding-re-read / open assertions.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from gateway.ingest import IngestService
from rca_common.db.models import AlertEventRow, Investigation, Platform
from rca_common.fingerprint import compute_fingerprint


class _Sess:
    def __init__(self, store):
        self.store = store
        self.added = []
        self.executed = []

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
        patch("gateway.ingest.merge_existing_event_with_audit", return_value=inv_id),
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


class _OrderedSess(_Sess):
    """Fake session that records commit/rollback order on a shared trace."""

    def __init__(self, store, trace, *, commit_error=None):
        super().__init__(store)
        self.trace = trace
        self.commit_error = commit_error
        self.committed = 0

    def commit(self):
        if self.commit_error is not None:
            self.trace.append("commit-raised")
            raise self.commit_error
        self.committed += 1
        self.trace.append("commit")
        return None


class _OrderedFactory:
    def __init__(self, store, trace, *, commit_error=None):
        self.store = store
        self.trace = trace
        self.commit_error = commit_error
        self.sessions: list[_OrderedSess] = []

    def __call__(self):
        session = _OrderedSess(self.store, self.trace, commit_error=self.commit_error)
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


def _ordered_service(trace, *, commit_error=None, starter=None, store=None):
    factory = _OrderedFactory(store if store is not None else {}, trace,
                              commit_error=commit_error)
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
    """FP-GC2-2: fused statement, then commit, then the exact 200 body."""
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
        event = svc.normalize_payload(_gc2_raw())
        result = svc._ingest_txn(event)
        code, body = await svc.ingest(_gc2_raw())

    # (a) The transaction result is exactly the merged triple.
    assert result == (200, {"status": "merged", "investigation_id": str(inv_id)}, None)
    # (b) Commit precedes the return on both invocations, and nothing else ran.
    assert trace == [
        "fused", "commit", "exit-clean",
        "fused", "commit", "exit-clean",
    ], trace
    assert all(s.committed == 1 for s in factory.sessions)
    # (c) The HTTP pair is the unchanged 200 merged body.
    assert code == 200
    assert body == {"status": "merged", "investigation_id": str(inv_id)}
    # (d) No workflow is started for a merge, and no fallback work happened.
    assert starter.started == []
    platform_lookup.assert_not_called()
    find.assert_not_called()
    lock.assert_not_called()
    insert.assert_not_called()
    audit.assert_not_called()
    create.assert_not_called()


@pytest.mark.asyncio
async def test_gc2_fast_merge_execute_or_commit_failure_cannot_return_success():
    """FP-GC2-2: an execute or commit failure propagates; no 2xx is produced."""
    # (a) The one statement fails: nothing is committed, the session context
    # exits by exception, and the caller sees the error rather than a status.
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
    assert trace == ["exit-error"], trace
    assert all(s.committed == 0 for s in factory.sessions)
    platform_lookup.assert_not_called()
    assert starter.started == []

    # (b) The commit fails after a successful execute: the merged triple is
    # never returned, and the context still exits by exception.
    trace = []
    starter = _Starter()
    commit_error = RuntimeError("commit failed")
    svc, factory = _ordered_service(trace, commit_error=commit_error, starter=starter)
    with patch(
        "gateway.ingest.merge_existing_event_with_audit", return_value=uuid.uuid4()
    ):
        with pytest.raises(RuntimeError, match="commit failed"):
            svc._ingest_txn(svc.normalize_payload(_gc2_raw()))
        with pytest.raises(RuntimeError, match="commit failed"):
            await svc.ingest(_gc2_raw())
    assert trace == [
        "commit-raised", "exit-error",
        "commit-raised", "exit-error",
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
        assert trace == ["commit", "exit-clean"], (reason, trace)
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
        "fused", "get_platform", "lock", "find", "insert", "audit",
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

    assert status == 202
    assert returned_id is not None
    assert payload == {"investigation_id": str(returned_id)}
    assert code == 202 and "investigation_id" in body
    assert trace[:8] == [
        "fused", "lock", "find", "insert", "audit", "create", "commit", "exit-clean",
    ], trace
    assert lock.call_count == 2 and find.call_count == 2
    assert insert.call_args.kwargs["disposition"] == "opened"
    assert audit.call_args.kwargs["action"] == "event_received"
    assert create.call_count == 2
    # The workflow starts once, on the loop, after the transaction returned.
    assert len(starter.started) == 1
    assert starter.started[0][1] is not None
