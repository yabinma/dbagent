"""Helper for creating monthly range partitions ahead of time (design.md
Section 3.3: "PG tables `investigations`, `llm_calls`, `audit_log`
partitioned by month"). The initial migration creates a DEFAULT partition
per table so the schema works out of the box in dev/test; this helper is
what a scheduled ops job calls in production to pre-provision the next
month's partition (avoiding rows silently landing in DEFAULT at scale).
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import text
from sqlalchemy.engine import Connection

_PARTITIONED_TABLES = ("investigations", "llm_calls", "audit_log")


def _month_bounds(year: int, month: int) -> tuple[dt.date, dt.date]:
    start = dt.date(year, month, 1)
    if month == 12:
        end = dt.date(year + 1, 1, 1)
    else:
        end = dt.date(year, month + 1, 1)
    return start, end


def ensure_month(conn: Connection, table: str, year: int, month: int) -> str:
    """Idempotently creates the partition for (year, month) on `table`.
    Returns the partition table name."""
    if table not in _PARTITIONED_TABLES:
        raise ValueError(f"{table} is not a monthly-partitioned table")
    start, end = _month_bounds(year, month)
    partition_name = f"{table}_{year:04d}_{month:02d}"
    conn.execute(
        text(
            f"CREATE TABLE IF NOT EXISTS {partition_name} "
            f"PARTITION OF {table} FOR VALUES FROM (:start) TO (:end)"
        ),
        {"start": start, "end": end},
    )
    return partition_name


def ensure_current_and_next_month(conn: Connection, table: str) -> list[str]:
    today = dt.date.today()
    names = [ensure_month(conn, table, today.year, today.month)]
    ny, nm = (today.year + 1, 1) if today.month == 12 else (today.year, today.month + 1)
    names.append(ensure_month(conn, table, ny, nm))
    return names
