"""B2 / B10 / B11 scale benchmarks (design.md FP-M6-20/21/22)."""
from __future__ import annotations

import os
import statistics
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from rca_common.audit import actor_system, write_audit
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import find_open_by_fingerprint
from rca_common.llmclient.tracestore import LLMCallRecord, PGTraceStore

# Sibling conftest (pytest prepends tests/benchmark/ on sys.path for this module).
from conftest import load_b11_writer_model


def _p99(samples: list[float]) -> float:
    if not samples:
        return 0.0
    s = sorted(samples)
    idx = max(0, int(round(0.99 * (len(s) - 1))))
    return s[idx]


def test_b2_fingerprint_correlation_p99_under_20ms(scale_pg):
    factory = scale_pg["factory"]
    with factory() as session:
        find_open_by_fingerprint(
            session,
            fingerprint="fp-1",
            platform_key="plat-1",
            correlation_window_seconds=1800,
        )
        session.commit()

    samples_ms: list[float] = []
    for i in range(200):
        fp = f"fp-{i % 5000}"
        plat = f"plat-{i % 10}"
        t0 = time.perf_counter()
        with factory() as session:
            find_open_by_fingerprint(
                session,
                fingerprint=fp,
                platform_key=plat,
                correlation_window_seconds=1800,
            )
            session.commit()
        samples_ms.append((time.perf_counter() - t0) * 1000)
    p99 = _p99(samples_ms)
    assert p99 < 20.0, (
        f"B2 p99={p99:.2f}ms (threshold 20ms); median={statistics.median(samples_ms):.2f}"
    )


def test_b10_partitioned_list_and_filter_p99(scale_pg):
    """Two shapes through real dashboard_api.services.list_investigations."""
    from dashboard_api import services as dash_services

    factory = scale_pg["factory"]
    samples_cursor: list[float] = []
    samples_filter: list[float] = []

    for _ in range(50):
        with factory() as session:
            t0 = time.perf_counter()
            dash_services.list_investigations(session, limit=50)
            samples_cursor.append((time.perf_counter() - t0) * 1000)

            t0 = time.perf_counter()
            dash_services.list_investigations(
                session,
                status=["RESOLVED"],
                platform_key="plat-1",
                category="resource",
                limit=50,
            )
            samples_filter.append((time.perf_counter() - t0) * 1000)
            session.commit()

    p99_c = _p99(samples_cursor)
    p99_f = _p99(samples_filter)
    assert p99_c < 200.0, f"B10 cursor p99={p99_c:.2f}ms"
    assert p99_f < 200.0, f"B10 filter p99={p99_f:.2f}ms"


def test_b11_audit_llm_insert_throughput(scale_pg):
    """Combined audit + llm_calls insert rate under durable Postgres.

    Writer count and mapping come from B11's structured concurrency_model
    (design.md §11.1.3 / FP-M6-22 / FP-IG-21): four writer *services*, seven
    process *instances* in the default deployment, each with an independent
    make_engine-default pool. Threads proxy process instances.
    """
    dsn = scale_pg["dsn"]
    writers = load_b11_writer_model()
    instances = [
        (entry, i)
        for entry in writers
        for i in range(entry["processes"])
    ]
    n_iters = 800
    now = datetime.now(timezone.utc)

    # One independent engine per process instance at make_engine defaults.
    # Built and warmed *outside* the timed window so we measure insert rate only.
    engines = []
    factories = []
    stores = []
    for _ in instances:
        eng = make_engine(dsn)
        fac = make_session_factory(eng)
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        engines.append(eng)
        factories.append(fac)
        stores.append(PGTraceStore(session_factory=fac))

    def _run_writer(idx: int) -> int:
        """Return rows committed by instances[idx].

        One commit per row — production shape for write_audit / insert_llm_call.
        Session is held open across commits (same connection from the pool),
        matching a long-lived process rather than open/close per row.
        """
        factory = factories[idx]
        store = stores[idx]
        process = instances[idx][0]["process"]
        rows = 0
        with factory() as session:
            for i in range(n_iters):
                if process == "temporal-worker" and i % 2 == 1:
                    store.insert_llm_call(
                        LLMCallRecord(
                            call_id=uuid.uuid4(),
                            investigation_id=None,
                            round=None,
                            agent_role="rca",
                            model="mock",
                            provider=None,
                            prompt_ref="p",
                            response_ref="r",
                            input_tokens=1,
                            output_tokens=1,
                            cost_usd=0.0,
                            latency_ms=1,
                            error=None,
                            created_at=now,
                        )
                    )
                else:
                    write_audit(
                        session,
                        action="event_received",
                        actor=actor_system(),
                        detail={"i": i, "writer": process},
                    )
                    session.commit()
                rows += 1
        return rows

    writer_map = ",".join(
        f"{(entry['process'] + '#' + str(i)) if entry['process'] == 'ingest-gateway' else entry['process']}"
        f":{'+'.join(entry['tables'])}"
        for entry, i in instances
    )

    def _warmup(idx: int) -> None:
        factory = factories[idx]
        process = instances[idx][0]["process"]
        with factory() as session:
            for i in range(50):
                write_audit(
                    session,
                    action="event_received",
                    actor=actor_system(),
                    detail={"i": i, "writer": process, "warmup": True},
                )
                session.commit()

    # Pool created and warmed outside the timed window.
    pool = ThreadPoolExecutor(max_workers=len(instances))
    try:
        list(pool.map(_warmup, range(len(instances))))
        t0 = time.perf_counter()
        committed = list(pool.map(_run_writer, range(len(instances))))
        elapsed = time.perf_counter() - t0
    finally:
        pool.shutdown(wait=True)
    total_rows = sum(committed)
    rate = total_rows / elapsed if elapsed > 0 else 0.0

    # Single-writer diagnostic on a pre-warmed engine (printed; not the bar).
    t_sw = time.perf_counter()
    sw_rows = 0
    with factories[0]() as session:
        for i in range(100):
            write_audit(
                session,
                action="event_received",
                actor=actor_system(),
                detail={"i": i, "writer": "single"},
            )
            session.commit()
            sw_rows += 1
    sw_elapsed = time.perf_counter() - t_sw
    single_writer_rate = sw_rows / sw_elapsed if sw_elapsed > 0 else 0.0
    serial_commit_ms = 1000.0 / single_writer_rate if single_writer_rate > 0 else 0.0
    combined_over_single = rate / single_writer_rate if single_writer_rate > 0 else 0.0
    env_line = (
        f"B11 env=cpus={os.cpu_count()},"
        f"serial_commit_ms={serial_commit_ms:.3f},"
        f"combined_over_single={combined_over_single:.2f}"
    )
    print(f"B11 writers={len(instances)}")
    print(f"B11 writer_map={writer_map}")
    print(f"B11 single_writer_rate={single_writer_rate:.1f}/s")
    print(env_line)
    assert rate >= 1000.0, (
        f"B11 combined insert rate={rate:.1f}/s (threshold 1000); "
        f"B11 writers={len(instances)}; B11 writer_map={writer_map}; "
        f"B11 single_writer_rate={single_writer_rate:.1f}/s; {env_line}"
    )
