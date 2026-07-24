"""B12: dashboard hot endpoints under 50 concurrent users, p99 < 300 ms.

In-process ASGI micro-benchmark against real Postgres (ephemeral) with seeded
data — locks the shipped hot-path cost under the Section 14.4 threshold.
"""
from __future__ import annotations

import asyncio
import statistics
import time
import uuid
from datetime import datetime, timezone

import pytest

from rca_common.db.models import Approval, Investigation, Platform
from helpers import login, seed_user


def _seed(sf, n_inv=30, n_pending=10):
    with sf() as s:
        if s.get(Platform, "presto-us1") is None:
            s.add(
                Platform(
                    platform_key="presto-us1",
                    platform_type="presto",
                    deployment="k8s",
                    display_name="us1",
                    status="online",
                    config={},
                    created_at=datetime.now(timezone.utc),
                )
            )
            s.flush()
        for i in range(n_inv):
            inv_id = uuid.uuid4()
            s.add(
                Investigation(
                    investigation_id=inv_id,
                    created_at=datetime.now(timezone.utc),
                    platform_key="presto-us1",
                    status="INVESTIGATING",
                    trigger_event=None,
                    workflow_id=f"investigation-{inv_id}",
                    budget={"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800},
                    spent={"rounds": 1, "cost_usd": 0},
                    rca_report=None,
                )
            )
        for i in range(n_pending):
            s.add(
                Approval(
                    approval_id=uuid.uuid4(),
                    investigation_id=uuid.uuid4(),
                    kind="raw_command",
                    subject={"command": "x"},
                    decision=None,
                    created_at=datetime.now(timezone.utc),
                )
            )
        s.commit()


@pytest.mark.asyncio
async def test_b12_dashboard_hot_endpoints_p99_under_300ms(client, session_factory):
    seed_user(session_factory, username="v", password="viewer-pass-12", role="viewer")
    seed_user(session_factory, username="a", password="approver-pass12", role="approver")
    _seed(session_factory)
    vtok = await login(client, "v", "viewer-pass-12")
    atok = await login(client, "a", "approver-pass12")

    endpoints = [
        ("GET", "/api/v1/investigations", vtok),
        ("GET", "/api/v1/approvals?pending=true", atok),
        ("GET", "/api/v1/metrics/summary", vtok),
    ]

    async def one(method, path, token):
        t0 = time.perf_counter()
        r = await client.request(method, path, headers={"Authorization": f"Bearer {token}"})
        elapsed_ms = (time.perf_counter() - t0) * 1000
        assert r.status_code == 200, r.text
        return elapsed_ms

    # Warm-up
    for method, path, token in endpoints:
        await one(method, path, token)

    # 50 concurrent users × 3 endpoints ≈ 150 requests
    tasks = []
    for _ in range(50):
        for method, path, token in endpoints:
            tasks.append(one(method, path, token))
    latencies = await asyncio.gather(*tasks)
    latencies = sorted(latencies)
    # p99 index
    idx = max(0, int(len(latencies) * 0.99) - 1)
    p99 = latencies[idx]
    assert p99 < 300, f"B12 p99={p99:.1f}ms exceeds 300ms (n={len(latencies)}, median={statistics.median(latencies):.1f})"
