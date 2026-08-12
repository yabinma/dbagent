"""IngestService unit tests: normalize, reject, open, merge (Section 4.1 / §11.3).

UT-IG-1: ``_ingest_txn`` returns ``(status, payload, investigation_id)`` on every
branch; ``ingest`` preserves pre-flight reject pairs.
UT-IG-2: workflow starts only on the opened branch, never inside the thread.
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
        self.executed.append((stmt, params))
        return MagicMock()

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
    with patch("gateway.ingest.get_platform", return_value=None), patch(
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
    with patch("gateway.ingest.get_platform", return_value=p), patch(
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
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch("gateway.ingest.find_open_by_fingerprint", return_value=inv),
        patch("gateway.ingest.acquire_correlation_lock") as lock,
        patch("gateway.ingest.insert_alert_event"),
        patch("gateway.ingest.write_audit"),
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
    lock.assert_not_called()


@pytest.mark.asyncio
async def test_ingest_txn_return_tuple_on_open():
    """UT-IG-1: _ingest_txn returns the three-tuple on the open branch."""
    store = {"platforms": {"presto-us1": _online_platform()}}
    svc = _svc(store)
    with (
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
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
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
    assert out_id is None


# ---------------------------------------------------------------------------
# UT-IG-2 — workflow start only on open, and never inside the thread
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_workflow_starts_only_on_opened_branch():
    store = {"platforms": {"presto-us1": _online_platform()}}
    starter = _Starter()
    with (
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
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch("gateway.ingest.find_open_by_fingerprint", return_value=inv),
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
    """Under-lock re-read finds a winner that the lock-free read missed."""
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
    calls = {"n": 0}

    def find_side_effect(*a, **k):
        calls["n"] += 1
        if calls["n"] == 1:
            return None  # lock-free miss
        return inv  # under-lock hit

    with (
        patch("gateway.ingest.get_platform", return_value=_online_platform()),
        patch("gateway.ingest.find_open_by_fingerprint", side_effect=find_side_effect),
        patch("gateway.ingest.acquire_correlation_lock") as lock,
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
    lock.assert_called_once()
    assert calls["n"] == 2


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
