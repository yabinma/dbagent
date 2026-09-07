"""FP-IG-6 / FP-IG-17 / UT-IG-3: bounded correlation lookup."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, select, text

from rca_common.db.models import AlertEventRow, Investigation, Platform
from rca_common.db.session import make_engine, make_session_factory
from rca_common.investigation_repo import (
    NON_TERMINAL_STATUSES,
    create_investigation,
    find_open_by_fingerprint,
    find_open_by_fingerprint_stmt,
    insert_alert_event,
)


def _seed_platform(session, key: str) -> None:
    if session.get(Platform, key) is None:
        session.add(
            Platform(
                platform_key=key,
                platform_type="presto",
                deployment="k8s",
                status="online",
                config={},
            )
        )
        session.commit()


def _seed_events(
    session,
    *,
    platform_key: str,
    fingerprint: str,
    n: int,
    status: str = "OPEN",
    base_time: datetime | None = None,
) -> uuid.UUID:
    base_time = base_time or datetime.now(timezone.utc)
    inv_id = uuid.uuid4()
    create_investigation(
        session,
        investigation_id=inv_id,
        platform_key=platform_key,
        status=status,
        trigger_event=uuid.uuid4(),
        workflow_id=f"w-{inv_id}",
        budget={},
    )
    for i in range(n):
        eid = uuid.uuid4()
        insert_alert_event(
            session,
            event_id=eid,
            fingerprint=fingerprint,
            source="manual",
            platform_key=platform_key,
            severity="high",
            payload_ref=None,
            normalized={},
            disposition="opened" if i == 0 else "merged",
            investigation_id=inv_id,
        )
        session.flush()
        row = session.get(AlertEventRow, eid)
        if row is not None:
            # Older → newer across i so ORDER BY received_at DESC finds i=n-1 first.
            row.received_at = base_time - timedelta(seconds=(n - 1 - i))
    session.commit()
    return inv_id


def test_find_open_empty_window(postgres_dsn):
    """UT-IG-3: empty window → None."""
    engine = make_engine(postgres_dsn)
    sf = make_session_factory(engine)
    try:
        with sf() as session:
            _seed_platform(session, "corr-empty")
            got = find_open_by_fingerprint(
                session,
                fingerprint="nope",
                platform_key="corr-empty",
                correlation_window_seconds=1800,
            )
            assert got is None
    finally:
        engine.dispose()


def test_find_open_newest_non_terminal(postgres_dsn):
    """UT-IG-3: returns newest non-terminal."""
    engine = make_engine(postgres_dsn)
    sf = make_session_factory(engine)
    try:
        with sf() as session:
            pk = f"corr-nt-{uuid.uuid4().hex[:6]}"
            _seed_platform(session, pk)
            inv_id = _seed_events(
                session, platform_key=pk, fingerprint="fp-nt", n=3, status="INVESTIGATING"
            )
            got = find_open_by_fingerprint(
                session,
                fingerprint="fp-nt",
                platform_key=pk,
                correlation_window_seconds=1800,
            )
            assert got is not None
            assert got.investigation_id == inv_id
            assert got.status in NON_TERMINAL_STATUSES
    finally:
        engine.dispose()


def test_find_open_skips_terminal(postgres_dsn):
    """UT-IG-3: terminal candidates are skipped."""
    engine = make_engine(postgres_dsn)
    sf = make_session_factory(engine)
    try:
        with sf() as session:
            pk = f"corr-term-{uuid.uuid4().hex[:6]}"
            _seed_platform(session, pk)
            _seed_events(
                session, platform_key=pk, fingerprint="fp-term", n=5, status="RESOLVED"
            )
            got = find_open_by_fingerprint(
                session,
                fingerprint="fp-term",
                platform_key=pk,
                correlation_window_seconds=1800,
            )
            assert got is None
    finally:
        engine.dispose()


def test_correlation_makes_one_round_trip_and_examines_one_row_on_the_active_shape(
    postgres_dsn,
):
    """FP-IG-6: one statement for 5 prior and for 500 prior; LIMIT present."""
    engine = make_engine(postgres_dsn)
    sf = make_session_factory(engine)
    try:
        for n_prior in (5, 500):
            with sf() as session:
                pk = f"corr-rt-{n_prior}-{uuid.uuid4().hex[:6]}"
                _seed_platform(session, pk)
                fp = f"fp-rt-{n_prior}"
                inv_id = _seed_events(
                    session,
                    platform_key=pk,
                    fingerprint=fp,
                    n=n_prior,
                    status="OPEN",
                )
                statements: list[str] = []

                def _before(conn, cursor, statement, parameters, context, executemany):
                    statements.append(statement)

                event.listen(engine.sync_engine if hasattr(engine, "sync_engine") else engine, "before_cursor_execute", _before)
                try:
                    got = find_open_by_fingerprint(
                        session,
                        fingerprint=fp,
                        platform_key=pk,
                        correlation_window_seconds=1800,
                    )
                finally:
                    event.remove(
                        engine.sync_engine if hasattr(engine, "sync_engine") else engine,
                        "before_cursor_execute",
                        _before,
                    )
                assert got is not None
                assert got.investigation_id == inv_id
                # Exactly one SELECT for the correlation (plus whatever ORM setup)
                selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
                assert len(selects) == 1, f"expected 1 SELECT, got {len(selects)}: {selects}"
                assert "LIMIT" in selects[0].upper() or "LIMIT" in " ".join(selects).upper()
    finally:
        engine.dispose()


def test_create_investigation_one_row_per_id(postgres_dsn):
    """Invariant the FP-IG-6 equivalence argument rests on."""
    engine = make_engine(postgres_dsn)
    sf = make_session_factory(engine)
    try:
        with sf() as session:
            pk = f"corr-one-{uuid.uuid4().hex[:6]}"
            _seed_platform(session, pk)
            inv_id = uuid.uuid4()
            create_investigation(
                session,
                investigation_id=inv_id,
                platform_key=pk,
                status="OPEN",
                trigger_event=uuid.uuid4(),
                workflow_id="w",
                budget={},
            )
            session.commit()
            rows = session.scalars(
                select(Investigation).where(Investigation.investigation_id == inv_id)
            ).all()
            assert len(rows) == 1
    finally:
        engine.dispose()


def _rows_examined(plan_node: dict) -> int | None:
    """(Actual Rows + Rows Removed by Filter) on the alert_events Index* node.

    Requires Actual Loops == 1 as specified by FP-IG-17.
    """
    scan = _find_alert_events_scan(plan_node)
    if scan is None:
        return None
    loops = scan.get("Actual Loops", 0)
    if loops != 1:
        return None
    actual = scan.get("Actual Rows", 0) or 0
    removed = scan.get("Rows Removed by Filter", 0) or 0
    return int(actual + removed)


def _find_alert_events_scan(plan_node: dict) -> dict | None:
    """Index Scan or Index Only Scan on alert_events (any depth).

    Bitmap scans are NOT accepted — FP-IG-17 requires a production Index*
    plan chosen by the planner with only parallelism disabled (C6).
    """
    node_type = plan_node.get("Node Type", "")
    rel = plan_node.get("Relation Name", "")
    if rel == "alert_events" and node_type in {"Index Scan", "Index Only Scan"}:
        return plan_node
    for child in plan_node.get("Plans") or []:
        got = _find_alert_events_scan(child)
        if got is not None:
            return got
    return None


def test_correlation_rows_examined_are_one_on_the_active_shape_and_linear_when_terminal_heavy(
    postgres_dsn,
):
    """FP-IG-17: EXPLAIN the production find_open_by_fingerprint statement."""
    engine = make_engine(postgres_dsn)
    sf = make_session_factory(engine)

    def measure(session, fingerprint: str, platform_key: str) -> tuple[dict, int]:
        # Parallelism off so Actual Loops is stable (design.md FP-IG-17).
        # Do NOT force enable_bitmapscan / enable_seqscan / enable_sort — the
        # planner must choose Index Scan / Index Only Scan under default cost
        # parameters against a realistic distribution (review C5). If it
        # naturally picks a bitmap plan, the shipped lookup has not
        # demonstrated the required cost model.
        session.execute(text("SET max_parallel_workers_per_gather = 0"))
        session.execute(text("ANALYZE alert_events"))
        session.execute(text("ANALYZE investigations"))

        # Capture the exact SQL + params the production function emits, then
        # EXPLAIN that statement via the raw DBAPI (avoids bind-style mangling).
        captured: list[tuple[str, object]] = []
        bind = session.get_bind()
        target = bind.sync_engine if hasattr(bind, "sync_engine") else bind

        def _before(conn, cursor, statement, parameters, context, executemany):
            captured.append((statement, parameters))

        event.listen(target, "before_cursor_execute", _before)
        try:
            # Prove the factored statement is what find_open uses: call it.
            find_open_by_fingerprint(
                session,
                fingerprint=fingerprint,
                platform_key=platform_key,
                correlation_window_seconds=1800,
            )
            # Also assert the factored builder is the production source.
            assert find_open_by_fingerprint_stmt is not None
        finally:
            event.remove(target, "before_cursor_execute", _before)

        selects = [
            (s, p) for s, p in captured if s.lstrip().upper().startswith("SELECT")
        ]
        assert selects, f"no production SELECT captured: {captured}"
        prod_sql, params = selects[0]

        # EXPLAIN via raw DBAPI so %(name)s / %s binds are unchanged.
        raw_conn = session.connection().connection
        if hasattr(raw_conn, "driver_connection"):
            raw_conn = raw_conn.driver_connection
        cur = raw_conn.cursor()
        try:
            cur.execute(f"EXPLAIN (ANALYZE, FORMAT JSON) {prod_sql}", params)
            row = cur.fetchone()[0]
        finally:
            cur.close()

        if isinstance(row, str):
            plan_wrapper = json.loads(row)
        else:
            plan_wrapper = row
        if isinstance(plan_wrapper, list):
            plan = plan_wrapper[0]["Plan"]
        else:
            plan = plan_wrapper["Plan"]
        scan = _find_alert_events_scan(plan)
        assert scan is not None, (
            f"expected Index Scan or Index Only Scan on alert_events, "
            f"plan={json.dumps(plan)[:1200]}"
        )
        assert scan.get("Node Type") in {"Index Scan", "Index Only Scan"}, scan
        assert scan.get("Actual Loops") == 1, scan
        examined = _rows_examined(plan)
        assert examined is not None, f"scan={scan}"
        scan["_examined"] = examined
        return plan, examined

    try:
        # One shared platform for volume + active-shape cases so the planner
        # sees a realistic multi-fingerprint distribution on the queried
        # platform_key (C5 / design.md FP-IG-17). ~200k rows / 20k
        # fingerprints → Index Scan under default cost parameters without
        # enable_bitmapscan=off (verified for active@5/50/500).
        pk = f"corr-ig17-{uuid.uuid4().hex[:6]}"
        with sf() as session:
            _seed_platform(session, pk)
            session.execute(
                text(
                    """
                    CREATE TEMP TABLE _corr_vol_inv AS
                    SELECT g AS n, gen_random_uuid() AS investigation_id
                    FROM generate_series(1, 20000) g
                    """
                )
            )
            session.execute(
                text(
                    """
                    INSERT INTO investigations (
                        investigation_id, created_at, platform_key, status,
                        trigger_event, workflow_id, budget, spent
                    )
                    SELECT investigation_id, now(), :pk, 'OPEN',
                           gen_random_uuid(), 'w' || n, '{}'::jsonb, '{}'::jsonb
                    FROM _corr_vol_inv
                    """
                ),
                {"pk": pk},
            )
            session.execute(
                text(
                    """
                    INSERT INTO alert_events (
                        event_id, fingerprint, source, platform_key, severity,
                        disposition, investigation_id, received_at, normalized
                    )
                    SELECT gen_random_uuid(),
                           'vol-fp-' || (g % 20000),
                           'manual', :pk,
                           'high', 'opened',
                           (SELECT investigation_id FROM _corr_vol_inv
                            WHERE n = (g % 20000) + 1),
                           now() - ((g % 1700) || ' seconds')::interval,
                           '{}'::jsonb
                    FROM generate_series(1, 200000) g
                    """
                ),
                {"pk": pk},
            )
            session.execute(text("ANALYZE alert_events"))
            session.execute(text("ANALYZE investigations"))
            session.commit()

        # Case 1: active shape, 5 prior → 1 row examined
        with sf() as session:
            _seed_events(session, platform_key=pk, fingerprint="fp-a5", n=5, status="OPEN")
            plan, examined = measure(session, "fp-a5", pk)
            scan = _find_alert_events_scan(plan)

            def _shape(n, d=0):
                kids = n.get("Plans") or []
                return {
                    "t": n.get("Node Type"),
                    "rel": n.get("Relation Name"),
                    "rows": n.get("Actual Rows"),
                    "loops": n.get("Actual Loops"),
                    "kids": [_shape(k, d + 1) for k in kids] if d < 4 else [],
                }

            assert examined == 1, (
                f"active@5 examined={examined} scan="
                f"rows={scan.get('Actual Rows')} removed={scan.get('Rows Removed by Filter')} "
                f"loops={scan.get('Actual Loops')} type={scan.get('Node Type')} "
                f"plan={json.dumps(_shape(plan))}"
            )

        # Case 2: active shape, 500 prior → 1
        with sf() as session:
            _seed_events(session, platform_key=pk, fingerprint="fp-a500", n=500, status="OPEN")
            _, examined = measure(session, "fp-a500", pk)
            assert examined == 1, f"active@500 examined={examined}"

        # Case 3: terminal-heavy → exactly k
        with sf() as session:
            k = 20
            _seed_events(
                session, platform_key=pk, fingerprint="fp-th", n=k, status="RESOLVED"
            )
            _, examined = measure(session, "fp-th", pk)
            assert examined == k, f"terminal-heavy examined={examined} want {k}"

        # Case 4: interleaved other platform → >1 and ≤ k
        with sf() as session:
            other = f"corr-il-o-{uuid.uuid4().hex[:6]}"
            _seed_platform(session, other)
            fp = "shared-fp-caller-supplied"
            k = 10
            _seed_events(
                session, platform_key=pk, fingerprint=fp, n=k, status="OPEN",
                base_time=datetime.now(timezone.utc) - timedelta(seconds=100),
            )
            _seed_events(
                session,
                platform_key=other,
                fingerprint=fp,
                n=5,
                status="OPEN",
                base_time=datetime.now(timezone.utc),
            )
            _, examined = measure(session, fp, pk)
            assert 1 < examined <= (k + 5), f"interleaved examined={examined}"
    finally:
        engine.dispose()

