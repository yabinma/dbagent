"""Pure-Python tests for the monthly-partition helper (design.md Section
3.3). No real database is required for `_month_bounds` / the
invalid-table-name guard; `ensure_month`/`ensure_current_and_next_month`
SQL-execution paths are exercised against a real Postgres in the
functional tier (F-checkpoints), not here.
"""
import datetime as dt

import pytest

from rca_common.db.partitions import _PARTITIONED_TABLES, _month_bounds, ensure_month


def test_month_bounds_mid_year():
    start, end = _month_bounds(2026, 6)
    assert start == dt.date(2026, 6, 1)
    assert end == dt.date(2026, 7, 1)


def test_month_bounds_december_rolls_into_next_year():
    start, end = _month_bounds(2026, 12)
    assert start == dt.date(2026, 12, 1)
    assert end == dt.date(2027, 1, 1)


def test_month_bounds_january():
    start, end = _month_bounds(2026, 1)
    assert start == dt.date(2026, 1, 1)
    assert end == dt.date(2026, 2, 1)


@pytest.mark.parametrize("table", sorted(_PARTITIONED_TABLES))
def test_partitioned_tables_are_the_expected_set(table):
    assert table in ("investigations", "llm_calls", "audit_log")


def test_ensure_month_rejects_non_partitioned_table():
    with pytest.raises(ValueError, match="not a monthly-partitioned table"):
        ensure_month(conn=None, table="platforms", year=2026, month=7)


class _FakeConnection:
    """Minimal stand-in for a SQLAlchemy Connection: records the executed
    statement text and bound parameters without needing a real database."""

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []

    def execute(self, statement, params):
        self.calls.append((str(statement), params))


def test_ensure_month_issues_expected_ddl_and_params():
    conn = _FakeConnection()
    name = ensure_month(conn, "llm_calls", 2026, 7)

    assert name == "llm_calls_2026_07"
    assert len(conn.calls) == 1
    statement, params = conn.calls[0]
    assert "CREATE TABLE IF NOT EXISTS llm_calls_2026_07" in statement
    assert "PARTITION OF llm_calls" in statement
    assert params == {"start": dt.date(2026, 7, 1), "end": dt.date(2026, 8, 1)}


def test_ensure_current_and_next_month_creates_two_partitions(monkeypatch):
    from rca_common.db import partitions as partitions_mod

    class _FixedDate(dt.date):
        @classmethod
        def today(cls):
            return cls(2026, 12, 15)

    monkeypatch.setattr(partitions_mod.dt, "date", _FixedDate)

    conn = _FakeConnection()
    names = partitions_mod.ensure_current_and_next_month(conn, "audit_log")

    assert names == ["audit_log_2026_12", "audit_log_2027_01"]
    assert len(conn.calls) == 2
