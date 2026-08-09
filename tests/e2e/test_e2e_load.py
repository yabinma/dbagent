"""FP-M6-30 / B1: the 5x burst profile, run for real.

`thresholds.yaml` B1 reads ">= 200 req/s sustained, p99 < 150 ms, 0 errors at 5x
burst for 30s", and design.md Section 11.1.3 fixes the interpretation: **1,000
alerts/s offered for 30 s with 0 errors**, "which entails 1,000 `audit_log`
rows/s actually committed" (`services/gateway/gateway/ingest.py` writes exactly
one audit row per ingested alert, on three mutually exclusive branches).

So this test:

* **paces** the offer at 1,000 req/s — the workload is scheduled on a clock, not
  emitted as fast as a response loop happens to spin — and proves the offered
  rate from measured submission timestamps;
* asserts zero errors and every request accounted for;
* asserts p99 latency against B1's 150 ms;
* asserts the sustained *successful* throughput from measured wall-clock time;
* asserts the entailed `audit_log` rows were really committed, read back through
  the real dashboard-api.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx
import pytest

# B1's bars are not environment-tunable: a rate knob would let a green run mean
# nothing. Only the client-side resource used to reach the rate is tunable.
BURST_RATE = 1000          # alerts/s offered (5x the 200/s base rate)
BURST_SECONDS = 30
TOTAL_REQUESTS = BURST_RATE * BURST_SECONDS
BASE_RATE = 200
P99_MS = 150.0
SLOT_SECONDS = 0.05        # pacing granularity: 50 requests every 50 ms
CONCURRENCY = int(os.environ.get("E2E_B1_CONCURRENCY", "256"))
HMAC_SECRET = os.environ.get("E2E_HMAC_SECRET", "e2e-hmac-secret")
ADMIN_USER = os.environ.get("E2E_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("E2E_ADMIN_PASS", "admin-e2e-password")
PLATFORM_KEY = os.environ.get("E2E_PLATFORM_KEY", "presto-e2e")
INGEST_AUDIT_ACTIONS = ("event_received", "event_merged", "event_rejected")


def _sign(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _p99(samples: list[float]) -> float:
    if not samples:
        return float("inf")
    ordered = sorted(samples)
    return ordered[min(len(ordered) - 1, int(0.99 * (len(ordered) - 1)))]


def _build_requests(count: int) -> list[tuple[bytes, dict[str, str]]]:
    """Payloads and signatures are built *outside* the timed window so the
    measurement is of the server, not of this client's json/hmac cost."""
    out = []
    for i in range(count):
        payload = {
            "source": "grafana-e2e",
            "platform_key": PLATFORM_KEY,
            # 50 distinct fingerprints: the real PG dedup lookup is the point.
            "error_summary": f"burst-{i % 50}",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "event_id": str(uuid.uuid4()),
        }
        raw = json.dumps(payload).encode()
        out.append(
            (
                raw,
                {
                    "Content-Type": "application/json",
                    "X-Signature": _sign(raw, HMAC_SECRET),
                },
            )
        )
    return out


def _admin_token(dashboard_url: str) -> str:
    r = httpx.post(
        f"{dashboard_url.rstrip('/')}/api/v1/auth/login",
        json={"username": ADMIN_USER, "password": ADMIN_PASS},
        timeout=30,
    )
    assert r.status_code == 200, r.text
    body = r.json()
    token = body.get("access_token") or body.get("token")
    assert token, body
    return token


def _count_ingest_audit_rows(dashboard_url: str, token: str, since: datetime, cap: int) -> int:
    """Page the real audit API and count the rows the burst committed."""
    base = dashboard_url.rstrip("/")
    headers = {"Authorization": f"Bearer {token}"}
    counted = 0
    for action in INGEST_AUDIT_ACTIONS:
        cursor = None
        while counted < cap:
            params = {
                "action": action,
                "from": since.isoformat(),
                "limit": 100,
            }
            if cursor:
                params["cursor"] = cursor
            r = httpx.get(f"{base}/api/v1/audit", headers=headers, params=params, timeout=60)
            assert r.status_code == 200, r.text
            body = r.json()
            items = body.get("items") or []
            counted += len(items)
            cursor = body.get("next_cursor") or body.get("cursor")
            if not cursor or not items:
                break
    return counted


@pytest.mark.e2e
def test_b1_ingest_burst_profile(ingest_url, dashboard_url):
    requests = _build_requests(TOTAL_REQUESTS)
    latencies: list[float] = []
    statuses: list[int] = []
    endpoint = f"{ingest_url.rstrip('/')}/api/v1/events"

    limits = httpx.Limits(
        max_connections=CONCURRENCY, max_keepalive_connections=CONCURRENCY
    )
    started_at = datetime.now(timezone.utc) - timedelta(seconds=1)

    with httpx.Client(limits=limits, timeout=10.0) as client:

        def one(index: int) -> tuple[float, int]:
            raw, headers = requests[index]
            t0 = time.perf_counter()
            try:
                r = client.post(endpoint, content=raw, headers=headers)
                return (time.perf_counter() - t0) * 1000, r.status_code
            except Exception:  # noqa: BLE001 - a transport failure is an error
                return (time.perf_counter() - t0) * 1000, 599

        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futures = []
            per_slot = int(BURST_RATE * SLOT_SECONDS)
            slots = TOTAL_REQUESTS // per_slot
            t_start = time.perf_counter()
            for slot in range(slots):
                target = t_start + slot * SLOT_SECONDS
                now = time.perf_counter()
                if now < target:
                    time.sleep(target - now)
                base = slot * per_slot
                for offset in range(per_slot):
                    futures.append(pool.submit(one, base + offset))
            t_offer_end = time.perf_counter()
            for future in futures:
                ms, code = future.result()
                latencies.append(ms)
                statuses.append(code)
            t_done = time.perf_counter()

    ok = sum(1 for code in statuses if code in (200, 202))
    errors = len(statuses) - ok
    offered_seconds = t_offer_end - t_start
    elapsed = t_done - t_start
    offered_rate = TOTAL_REQUESTS / offered_seconds if offered_seconds else 0.0
    p99 = _p99(latencies)
    # The trailing drain is at most one p99 of in-flight requests; discount
    # exactly that much rather than an invented tolerance.
    served_window = max(elapsed - p99 / 1000.0, 1e-9)
    sustained = ok / served_window

    assert len(statuses) == TOTAL_REQUESTS, (
        f"B1 accounted for {len(statuses)} of {TOTAL_REQUESTS} requests"
    )
    assert ok > 0, (
        f"B1 measured zero successful requests (errors={errors}); check E2E_HMAC_SECRET"
    )
    # The offer itself: 1,000/s really was put on the wire for 30 s.
    assert offered_seconds >= BURST_SECONDS * 0.99, (
        f"B1 burst lasted {offered_seconds:.2f}s, not the required {BURST_SECONDS}s"
    )
    assert offered_rate >= BURST_RATE * 0.99, (
        f"B1 offered only {offered_rate:.1f} req/s; the profile requires "
        f"{BURST_RATE} req/s paced for {BURST_SECONDS}s"
    )
    assert errors == 0, f"B1 errors={errors} (statuses={sorted(set(statuses))})"
    assert p99 < P99_MS, f"B1 p99={p99:.1f}ms (threshold {P99_MS}ms)"
    assert sustained >= BURST_RATE, (
        f"B1 sustained {sustained:.1f} successful req/s over {served_window:.2f}s "
        f"measured; the 5x burst requires {BURST_RATE} req/s "
        f"(base rate {BASE_RATE} req/s)"
    )

    # The entailment the threshold rests on: one audit row per ingested alert.
    token = _admin_token(dashboard_url)
    committed = _count_ingest_audit_rows(
        dashboard_url, token, started_at, cap=TOTAL_REQUESTS + 1000
    )
    assert committed >= ok, (
        f"B1 committed {committed} ingest audit rows for {ok} accepted alerts; "
        "every ingested alert writes exactly one audit_log row"
    )
    audit_rate = committed / served_window
    assert audit_rate >= BURST_RATE, (
        f"B1 committed audit rows at {audit_rate:.1f}/s; the burst entails "
        f"{BURST_RATE} audit_log rows/s"
    )
