"""Shared seeded PG fixture for B2/B10/B11 (design.md §11.1.3)."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from testcontainers.postgres import PostgresContainer

from rca_common.db.partitions import ensure_month
from rca_common.db.session import make_engine, make_session_factory

REPO_ROOT = Path(__file__).resolve().parents[2]
RCA_COMMON_DIR = REPO_ROOT / "libs" / "py" / "rca_common"


def _months_back(n: int) -> list[tuple[int, int]]:
    now = datetime.now(timezone.utc)
    y, m = now.year, now.month
    out: list[tuple[int, int]] = []
    for _ in range(n):
        out.append((y, m))
        m -= 1
        if m == 0:
            m = 12
            y -= 1
    return list(reversed(out))


def _run_migrations(dsn: str) -> None:
    """Migrate via the alembic Python API (no PATH dependency on the alembic binary)."""
    cfg = Config(str(RCA_COMMON_DIR / "alembic.ini"))
    cfg.set_main_option("script_location", str(RCA_COMMON_DIR / "migrations"))
    cfg.set_main_option("sqlalchemy.url", dsn)
    command.upgrade(cfg, "head")


def load_b11_writer_model():
    manifest = yaml.safe_load(
        Path(__file__).with_name("thresholds.yaml").read_text(encoding="utf-8")
    )
    by_id = {entry["id"]: entry for entry in manifest["benchmarks"]}
    return by_id["B11"]["concurrency_model"]["writer_processes"]


@pytest.fixture(scope="session")
def scale_pg():
    """Session-scoped Postgres with B2/B10/B11 seed data (server-side INSERT…SELECT).

    Uses stock durable Postgres settings (same as production chart/compose —
    no fsync/synchronous_commit overrides). B11 measures application insert
    throughput under that contract via the production insert_llm_call path.
    """
    pg = PostgresContainer(
        "postgres:16-alpine",
        dbname="dbagent",
        username="dbagent",
        password="dbagent",
    )
    with pg:
        dsn = pg.get_connection_url()
        _run_migrations(dsn)
        # Production-default pool (make_engine kwargs empty). B11 gives each
        # simulated writer its own engine; the seed fixture uses one engine only.
        engine = make_engine(dsn)
        factory = make_session_factory(engine)

        months = _months_back(12)
        with engine.begin() as conn:
            for y, m in months:
                ensure_month(conn, "investigations", y, m)
                ensure_month(conn, "llm_calls", y, m)
                ensure_month(conn, "audit_log", y, m)

            # FK parents for investigations.platform_key (plat-0 … plat-9).
            conn.execute(
                text(
                    """
                    INSERT INTO platforms (
                      platform_key, platform_type, deployment, display_name, status, config
                    )
                    SELECT
                      'plat-' || g::text,
                      'presto',
                      'k8s',
                      'plat-' || g::text,
                      'online',
                      '{}'::jsonb
                    FROM generate_series(0, 9) AS g
                    ON CONFLICT (platform_key) DO NOTHING
                    """
                )
            )

            conn.execute(
                text(
                    """
                    INSERT INTO alert_events (
                      event_id, fingerprint, source, platform_key, severity,
                      payload_ref, normalized, disposition, received_at
                    )
                    SELECT
                      gen_random_uuid(),
                      'fp-' || (g % 5000)::text,
                      'grafana',
                      'plat-' || (g % 10)::text,
                      'high',
                      NULL,
                      '{}'::jsonb,
                      'opened',
                      now() - ((g % 3600) * interval '1 second')
                    FROM generate_series(1, 1000000) AS g
                    """
                )
            )
            conn.execute(text("ANALYZE alert_events"))

            # workflow_id is NOT NULL; seed unique ids so the constraint holds.
            conn.execute(
                text(
                    """
                    INSERT INTO investigations (
                      investigation_id, created_at, platform_key, status,
                      workflow_id, budget, spent, rca_report
                    )
                    SELECT
                      gen_random_uuid(),
                      date_trunc('month', now()) - ((g % 12) * interval '1 month')
                        + ((g % 28) * interval '1 day'),
                      'plat-' || (g % 10)::text,
                      (ARRAY['OPEN','RESOLVED','CLOSED_SUMMARY','NEEDS_HUMAN'])[1 + (g % 4)],
                      'wf-seed-' || g::text,
                      '{}'::jsonb,
                      '{}'::jsonb,
                      jsonb_build_object(
                        'status', 'concluded',
                        'root_cause', jsonb_build_object(
                          'category',
                          (ARRAY['resource','configuration','capacity','query'])[1 + (g % 4)],
                          'summary', 'seed'
                        )
                      )
                    FROM generate_series(1, 100000) AS g
                    """
                )
            )
            # Attach a realistic fraction of llm_calls to seeded investigations
            # so B10's cost aggregation and llm_calls_investigation_id_idx are
            # exercised (partial index WHERE investigation_id IS NOT NULL).
            # Map g%100000 → investigations via a numbered CTE (no per-row OFFSET).
            conn.execute(
                text(
                    """
                    WITH inv AS (
                      SELECT investigation_id,
                             row_number() OVER (ORDER BY created_at) - 1 AS rn
                      FROM investigations
                    )
                    INSERT INTO llm_calls (
                      call_id, created_at, investigation_id, agent_role, model,
                      prompt_ref, response_ref, input_tokens, output_tokens,
                      cost_usd, latency_ms
                    )
                    SELECT
                      gen_random_uuid(),
                      date_trunc('month', now()) - ((g % 12) * interval '1 month')
                        + ((g % 20) * interval '1 day'),
                      CASE
                        WHEN g % 5 = 0 THEN inv.investigation_id
                        ELSE NULL
                      END,
                      'rca',
                      'mock',
                      'p', 'r', 10, 5, 0.001, 50
                    FROM generate_series(1, 2500000) AS g
                    LEFT JOIN inv ON inv.rn = (g % 100000)
                    """
                )
            )
            conn.execute(
                text(
                    """
                    INSERT INTO audit_log (investigation_id, actor, action, detail, at)
                    SELECT
                      NULL,
                      'system',
                      'event_received',
                      '{}'::jsonb,
                      date_trunc('month', now()) - ((g % 12) * interval '1 month')
                        + ((g % 20) * interval '1 day')
                    FROM generate_series(1, 2500000) AS g
                    """
                )
            )
            conn.execute(text("ANALYZE investigations"))
            conn.execute(text("ANALYZE llm_calls"))
            conn.execute(text("ANALYZE audit_log"))

        yield {"dsn": dsn, "factory": factory, "engine": engine}
