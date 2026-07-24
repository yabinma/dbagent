"""IngestService unit tests: normalize, reject, open, merge (Section 4.1)."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from gateway.ingest import IngestService
from rca_common.db.models import AlertEventRow, Investigation, Platform
from rca_common.fingerprint import compute_fingerprint


class _Sess:
    def __init__(self, store):
        self.store = store
        self.added = []

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

    def scalars(self, stmt):
        # Minimal: return events matching fingerprint lookups for merge tests.
        class R:
            def __init__(self, items):
                self._items = items

            def __iter__(self):
                return iter(self._items)

            def first(self):
                return self._items[0] if self._items else None

        events = self.store.get("events", [])
        # Always return in reverse received order for find_open_by_fingerprint.
        return R(list(reversed(events)))


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
    p = Platform(
        platform_key=key,
        platform_type="presto",
        deployment="k8s",
        status="online",
        config=config or {},
    )
    return p


@pytest.mark.asyncio
async def test_open_new_investigation():
    store = {"platforms": {"presto-us1": _online_platform()}}
    starter = _Starter()
    svc = IngestService(
        _Factory(store),
        budget_defaults={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        known_sources={"grafana-prod": "sec"},
        workflow_starter=starter,
    )
    code, body = await svc.ingest(
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


@pytest.mark.asyncio
async def test_reject_unknown_platform():
    store = {"platforms": {}}
    svc = IngestService(_Factory(store), budget_defaults={}, known_sources={"manual": "s"})
    code, body = await svc.ingest(
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
    svc = IngestService(_Factory(store), budget_defaults={}, known_sources={"manual": "s"})
    code, body = await svc.ingest(
        {
            "source": "manual",
            "platform_key": "presto-us1",
            "error_summary": "x",
            "occurred_at": "2026-07-11T00:00:00Z",
        }
    )
    assert body["reason"] == "platform_not_ready"


@pytest.mark.asyncio
async def test_reject_unknown_source():
    store = {"platforms": {"presto-us1": _online_platform()}}
    svc = IngestService(
        _Factory(store),
        budget_defaults={},
        known_sources={"grafana-prod": "s"},
    )
    code, body = await svc.ingest(
        {
            "source": "jenkins",
            "platform_key": "presto-us1",
            "error_summary": "x",
            "occurred_at": "2026-07-11T00:00:00Z",
        }
    )
    assert body["reason"] == "unknown_source"


@pytest.mark.asyncio
async def test_merge_inside_correlation_window():
    store = {"platforms": {"presto-us1": _online_platform()}}
    inv_id = uuid.uuid4()
    fp = compute_fingerprint("presto-us1", "Worker OOM killed")
    # Seed prior opened event + non-terminal investigation.
    prior_event = AlertEventRow(
        event_id=uuid.uuid4(),
        fingerprint=fp,
        source="grafana-prod",
        platform_key="presto-us1",
        severity="high",
        payload_ref=None,
        normalized={},
        disposition="opened",
        investigation_id=inv_id,
        received_at=datetime.now(timezone.utc),
    )
    inv = Investigation(
        investigation_id=inv_id,
        created_at=datetime.now(timezone.utc),
        platform_key="presto-us1",
        status="INVESTIGATING",
        trigger_event=prior_event.event_id,
        workflow_id=f"investigation-{inv_id}",
        budget={"max_rounds": 15},
        spent={"rounds": 1, "cost_usd": 0},
    )
    store["events"] = [prior_event]
    store["investigations"] = [inv]

    factory = _Factory(store)
    # Patch find path: session.scalars returns events; we need _latest_investigation.
    # Override session.get path via scalars for Investigation - investigation_repo uses select.
    # Monkeypatch get for Investigation by intercepting session.scalars second call.

    original_factory = factory

    class SmartFactory:
        def __call__(self):
            s = _Sess(store)

            def scalars(stmt):
                class R:
                    def __init__(self, items):
                        self._items = items

                    def __iter__(self):
                        return iter(self._items)

                    def first(self):
                        return self._items[0] if self._items else None

                # Heuristic: if store has investigations and events, return events first.
                # investigation_repo.find_open_by_fingerprint iterates events then
                # _latest_investigation uses scalars again.
                # We'll return events when any AlertEventRow in store, then investigations.
                if not hasattr(s, "_call"):
                    s._call = 0
                s._call += 1
                if s._call == 1:
                    return R(list(reversed(store.get("events", []))))
                return R(list(reversed(store.get("investigations", []))))

            s.scalars = scalars
            return _Ctx(s)

    svc = IngestService(
        SmartFactory(),
        budget_defaults={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
        known_sources={"grafana-prod": "s"},
        correlation_window_seconds=1800,
    )
    code, body = await svc.ingest(
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
