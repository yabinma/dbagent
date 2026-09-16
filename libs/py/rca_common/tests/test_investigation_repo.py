"""Unit tests for investigation_repo helpers."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest

from rca_common.investigation_repo import (
    NON_TERMINAL_STATUSES,
    TERMINAL_STATUSES,
    create_approval,
    create_investigation,
    decide_approval,
    find_open_by_fingerprint,
    get_evidence,
    get_platform,
    insert_alert_event,
    insert_evidence,
    merge_platform_budget,
    open_case_from_event,
    record_iteration,
    update_investigation_status,
)


def test_merge_platform_budget_overrides():
    defaults = {"max_rounds": 15, "max_cost_usd": 10.0, "max_wall_seconds": 1800}
    merged = merge_platform_budget(defaults, {"budget": {"max_rounds": 3}})
    assert merged["max_rounds"] == 3
    assert merged["max_cost_usd"] == 10.0
    assert merge_platform_budget(defaults, None) == defaults
    assert merge_platform_budget(defaults, {"budget_defaults": {"max_cost_usd": 1.0}})["max_cost_usd"] == 1.0
    assert merge_platform_budget(defaults, {}) == defaults


def test_status_sets():
    assert "INVESTIGATING" in NON_TERMINAL_STATUSES
    assert "RESOLVED" in TERMINAL_STATUSES


def test_create_helpers_add_rows():
    session = MagicMock()
    inv_id = uuid.uuid4()
    inv = create_investigation(
        session,
        investigation_id=inv_id,
        platform_key="p",
        status="OPEN",
        trigger_event=uuid.uuid4(),
        workflow_id="wf",
        budget={"max_rounds": 1},
    )
    assert inv.investigation_id == inv_id
    session.add.assert_called()

    insert_alert_event(
        session,
        event_id=uuid.uuid4(),
        fingerprint="fp",
        source="s",
        platform_key="p",
        severity="high",
        payload_ref=None,
        normalized={},
        disposition="opened",
        investigation_id=inv_id,
    )
    record_iteration(
        session,
        investigation_id=inv_id,
        round_num=1,
        plan={"tool_calls": []},
        rca_output={"status": "concluded"},
    )
    insert_evidence(
        session,
        investigation_id=inv_id,
        round_num=1,
        tool_name="presto_nodes",
        args={},
        exit_code=0,
        summary="ok",
        payload_ref="s3://x",
        payload_bytes=10,
    )
    create_approval(session, investigation_id=inv_id, kind="raw_command", subject={"c": "cat x"})
    assert session.add.call_count >= 5


def test_get_platform_and_evidence():
    session = MagicMock()
    session.get = MagicMock(return_value="plat")
    assert get_platform(session, "k") == "plat"
    assert get_evidence(session, uuid.uuid4()) == "plat"
    assert get_evidence(session, "not-a-uuid") is None


def test_update_investigation_status():
    session = MagicMock()
    inv = MagicMock()
    inv.status = "OPEN"
    inv.rca_report = None
    inv.spent = {}
    inv.closed_at = None
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=inv)))
    update_investigation_status(
        session, uuid.uuid4(), "RESOLVED", rca_report={"status": "concluded"}, spent={"rounds": 1}, close=True
    )
    assert inv.status == "RESOLVED"
    assert inv.rca_report["status"] == "concluded"
    assert inv.closed_at is not None

    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))
    with pytest.raises(KeyError):
        update_investigation_status(session, uuid.uuid4(), "OPEN")


def test_decide_approval():
    session = MagicMock()
    row = MagicMock()
    row.decision = None
    session.get = MagicMock(return_value=row)
    decide_approval(session, uuid.uuid4(), decision="approved", comment="ok")
    assert row.decision == "approved"

    row.decision = "approved"
    with pytest.raises(ValueError):
        decide_approval(session, uuid.uuid4(), decision="denied")

    session.get = MagicMock(return_value=None)
    with pytest.raises(KeyError):
        decide_approval(session, uuid.uuid4(), decision="approved")


def test_open_case_from_event():
    session = MagicMock()
    inv = open_case_from_event(
        session,
        event={"event_id": str(uuid.uuid4()), "platform_key": "presto-us1"},
        workflow_id="wf-1",
        budget={"max_rounds": 5},
    )
    assert inv.platform_key == "presto-us1"
    assert session.add.call_count >= 2  # investigation + audit


def test_find_open_by_fingerprint_hits_and_misses():
    session = MagicMock()
    inv_id = uuid.uuid4()
    inv = MagicMock()
    inv.status = "INVESTIGATING"
    inv.investigation_id = inv_id

    # FP-IG-6: single SELECT … LIMIT 1; scalars().first() returns the Investigation.
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=inv)))
    found = find_open_by_fingerprint(
        session,
        fingerprint="fp",
        platform_key="p",
        correlation_window_seconds=1800,
        now=datetime.now(timezone.utc),
    )
    assert found is inv
    session.scalars.assert_called_once()

    # Empty window → None
    session.scalars = MagicMock(return_value=MagicMock(first=MagicMock(return_value=None)))
    assert (
        find_open_by_fingerprint(
            session, fingerprint="x", platform_key="p", correlation_window_seconds=60
        )
        is None
    )


# ---------------------------------------------------------------------------
# GC-2 — the fused committed-existing-case merge statement
# (FP-GC2-1 / FP-GC2-2 / FP-GC2-3).
#
# These are structure-and-contract tests. The behaviour of the statement
# against a real PostgreSQL is decided by
# tests/functional/test_ingest_atomicity.py, which runs it on a migrated
# database; nothing here may stand in for that.
# ---------------------------------------------------------------------------


def _gc2_event(**overrides):
    event = {
        "event_id": str(uuid.uuid4()),
        "source": "manual",
        "platform_key": "presto-us1",
        "error_summary": "worker oom",
        "error_detail": None,
        "occurred_at": "2026-09-16T00:00:00Z",
        "reporter": None,
        "severity": "high",
        "labels": {},
        "fingerprint": "fp-gc2",
    }
    event.update(overrides)
    return event


def test_merge_existing_event_statement_is_static_typed_and_closed():
    """FP-GC2-1/2: one module-scoped statement, typed binds, fixed literals."""
    import ast
    import inspect

    from sqlalchemy.dialects.postgresql import ARRAY, JSONB, TIMESTAMP
    from sqlalchemy.dialects.postgresql import UUID as PG_UUID
    from sqlalchemy.sql.elements import TextClause
    from sqlalchemy.types import Integer, Text

    from rca_common import investigation_repo as repo
    from rca_common.audit import actor_system
    from rca_common.db.models import AUDIT_ACTIONS

    stmt = repo._MERGE_EXISTING_EVENT_WITH_AUDIT_STMT
    assert isinstance(stmt, TextClause)

    # (a) Module scope, built once: two helper calls execute the *same* object.
    seen = []
    session = MagicMock()
    session.execute = MagicMock(
        side_effect=lambda s, p: seen.append(s) or MagicMock(
            scalar_one_or_none=MagicMock(return_value=None)
        )
    )
    repo.merge_existing_event_with_audit(
        session, event=_gc2_event(), default_correlation_window_seconds=1800
    )
    repo.merge_existing_event_with_audit(
        session, event=_gc2_event(), default_correlation_window_seconds=1800
    )
    assert seen[0] is stmt and seen[1] is stmt, "statement is rebuilt per request"

    # (b) Every request value is a typed bind parameter.
    binds = stmt._bindparams
    expected_types = {
        "platform_key": Text,
        "fingerprint": Text,
        "source": Text,
        "severity": Text,
        "event_id": PG_UUID,
        "event_id_text": Text,
        "normalized": JSONB,
        "non_terminal_statuses": ARRAY,
        "statement_at": TIMESTAMP,
        "default_correlation_window_seconds": Integer,
    }
    assert set(binds) == set(expected_types), sorted(binds)
    for name, type_ in expected_types.items():
        assert isinstance(binds[name].type, type_), (name, binds[name].type)
    assert binds["event_id"].type.as_uuid is True
    assert isinstance(binds["non_terminal_statuses"].type.item_type, Text)
    assert binds["statement_at"].type.timezone is True

    sql = repo._MERGE_EXISTING_EVENT_WITH_AUDIT_SQL
    # (c) Fixed tables, disposition, actor and action; closed status source.
    assert "INSERT INTO alert_events" in sql
    assert "INSERT INTO audit_log" in sql
    assert "FROM platforms AS p" in sql
    assert "'merged'" in sql
    assert "'system', 'event_merged'" in sql
    assert repo.MERGE_EXISTING_EVENT_AUDIT_ACTION == "event_merged"
    assert repo.MERGE_EXISTING_EVENT_AUDIT_ACTOR == "system"
    assert repo.MERGE_EXISTING_EVENT_AUDIT_ACTION in AUDIT_ACTIONS
    assert repo.MERGE_EXISTING_EVENT_AUDIT_ACTOR == actor_system()
    assert set(repo.NON_TERMINAL_STATUS_LIST) == set(NON_TERMINAL_STATUSES)
    assert repo.NON_TERMINAL_STATUS_LIST == tuple(sorted(NON_TERMINAL_STATUSES))
    for status in NON_TERMINAL_STATUSES | TERMINAL_STATUSES:
        assert f"'{status}'" not in sql, f"{status} is interpolated, not bound"
    assert "i.status = ANY(:non_terminal_statuses)" in sql

    # (d) No dynamic identifier or value construction anywhere: the SQL is one
    # plain string constant, and the helper builds no statement of its own.
    module_src = inspect.getsource(repo)
    tree = ast.parse(module_src)
    sql_assigns = [
        node for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(t, ast.Name) and t.id == "_MERGE_EXISTING_EVENT_WITH_AUDIT_SQL"
            for t in node.targets
        )
    ]
    assert len(sql_assigns) == 1
    assert isinstance(sql_assigns[0].value, ast.Constant), "SQL is not a plain literal"
    assert isinstance(sql_assigns[0].value.value, str)
    helper = next(
        node for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "merge_existing_event_with_audit"
    )
    helper_src = ast.get_source_segment(module_src, helper) or ""
    for forbidden in ("text(", ".format(", "%s", "+ str(", 'f"', "f'"):
        assert forbidden not in helper_src, f"helper builds SQL dynamically: {forbidden}"
    assert sum(1 for n in ast.walk(helper) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Attribute) and n.func.attr == "execute") == 1


def test_merge_existing_event_hit_and_miss_scalar_contract():
    """FP-GC2-1/3: one execute, UUID on hit, None on miss, exact parameters."""
    from rca_common import investigation_repo as repo

    inv_id = uuid.uuid4()
    event = _gc2_event()
    statement_at = datetime(2026, 9, 16, 8, 0, tzinfo=timezone.utc)

    session = MagicMock()
    session.execute = MagicMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=inv_id))
    )
    got = repo.merge_existing_event_with_audit(
        session,
        event=event,
        default_correlation_window_seconds=1800,
        now=statement_at,
    )
    assert got == inv_id
    session.execute.assert_called_once()
    stmt, params = session.execute.call_args.args
    assert stmt is repo._MERGE_EXISTING_EVENT_WITH_AUDIT_STMT
    assert params == {
        "platform_key": event["platform_key"],
        "fingerprint": event["fingerprint"],
        "source": event["source"],
        "severity": event["severity"],
        "event_id": uuid.UUID(event["event_id"]),
        "event_id_text": event["event_id"],
        "normalized": event,
        "non_terminal_statuses": list(repo.NON_TERMINAL_STATUS_LIST),
        "statement_at": statement_at,
        "default_correlation_window_seconds": 1800,
    }
    # The helper owns no transaction and materialises nothing.
    session.add.assert_not_called()
    session.flush.assert_not_called()
    session.commit.assert_not_called()
    session.scalars.assert_not_called()
    session.get.assert_not_called()

    # Miss: the statement returned no row, so nothing was written.
    session = MagicMock()
    session.execute = MagicMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
    )
    assert (
        repo.merge_existing_event_with_audit(
            session, event=_gc2_event(), default_correlation_window_seconds=60
        )
        is None
    )
    session.execute.assert_called_once()
    session.add.assert_not_called()
    session.commit.assert_not_called()

    # `now` defaults to an aware UTC instant used for both inserts and the
    # correlation boundary alike.
    session = MagicMock()
    session.execute = MagicMock(
        return_value=MagicMock(scalar_one_or_none=MagicMock(return_value=None))
    )
    before = datetime.now(timezone.utc)
    repo.merge_existing_event_with_audit(
        session, event=_gc2_event(), default_correlation_window_seconds=1800
    )
    after = datetime.now(timezone.utc)
    used = session.execute.call_args.args[1]["statement_at"]
    assert used.tzinfo is not None and used.utcoffset() == timedelta(0)
    assert before <= used <= after


def test_merge_statement_carries_closed_window_precedence_and_fallback():
    """FP-GC2-3: primary/legacy/default order and the NULL-on-ineligible route.

    Only the compiled statement is inspected here; the real-database function
    test decides the behaviour these clauses produce.
    """
    from rca_common import investigation_repo as repo

    sql = repo._MERGE_EXISTING_EVENT_WITH_AUDIT_SQL
    primary = sql.index("p.config ? 'correlation_window_seconds'")
    legacy = sql.index("WHEN p.config ? 'correlation_window' THEN")
    default = sql.index(":default_correlation_window_seconds")
    assert primary < legacy < default, (primary, legacy, default)
    # The legacy key is only consulted when the primary key is absent: both
    # are branches of one CASE whose first WHEN is the primary key.
    assert sql.count("WHEN p.config ? ") == 2
    assert sql.count("ELSE :default_correlation_window_seconds") == 1

    # Safe-integer guards on both keys, and nothing else takes the fast path.
    for key in ("correlation_window_seconds", "correlation_window"):
        assert f"jsonb_typeof(p.config -> '{key}')" in sql
        assert f"(p.config ->> '{key}') ~ '^-?[0-9]+$'" in sql
        assert f"(p.config ->> '{key}')::bigint" in sql
    assert sql.count("IN ('number', 'string')") == 2
    assert sql.count("BETWEEN -2147483648 AND 2147483647") == 2
    assert sql.count("<= 11") == 2
    assert sql.count("ELSE NULL") == 4

    # An ineligible override makes the statement a side-effect-free miss:
    # window_seconds is NULL and the candidate CTE requires it to be present.
    assert "p.window_seconds IS NOT NULL" in sql
    # Only an online platform is eligible at all.
    assert "lower(p.status) = 'online'" in sql
    assert "p.platform_key = :platform_key" in sql
    # The candidate is the same shape find_open_by_fingerprint_stmt selects.
    assert "ae.fingerprint = :fingerprint" in sql
    assert "ae.investigation_id IS NOT NULL" in sql
    assert "make_interval(secs => p.window_seconds)" in sql
    assert "ORDER BY ae.received_at DESC" in sql
    assert "LIMIT 1" in sql
    # Both inserts are CTEs of the one statement, chained so that the audit
    # row cannot be written without the event row.
    assert sql.index("event_write AS (") < sql.index("audit_write AS (")
    assert "FROM event_write" in sql
    assert sql.rstrip().endswith("SELECT investigation_id FROM audit_write")
