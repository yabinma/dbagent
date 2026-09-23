"""initial schema (design.md Section 4.3)

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-07-08

Creates the core control-plane tables verbatim from design.md Section 4.3.
`investigations`, `llm_calls`, and `audit_log` are monthly range-partitioned
per the design; this migration additionally creates a DEFAULT partition for
each so the schema is immediately usable in dev/test/CI without a partition
pre-provisioning job. Production operators should run
`rca_common.db.partitions.ensure_month(...)` (see that module) ahead of each
month via a scheduled job -- see docs/ops runbooks (M6).

Note: literal colons inside the raw SQL strings below (e.g. JSONB default
literals like '{"rounds":0}') must be backslash-escaped ('\\:') because
`op.execute()` coerces plain strings into a SQLAlchemy `text()` construct,
which otherwise treats `:name`-shaped substrings as bind parameters. This
was caught by actually running this migration against a real Postgres
(design.md Section 14.1 isolation bar exempts the functional tier from
this, but a real DB is still used there to prove the DDL itself, per
Section 14.3's "ephemeral PG ... containers").
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0001_initial_schema"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE platforms (
          platform_key   TEXT PRIMARY KEY,
          platform_type  TEXT NOT NULL,
          deployment     TEXT NOT NULL,
          display_name   TEXT,
          status         TEXT NOT NULL DEFAULT 'created',
          config         JSONB NOT NULL DEFAULT '{}',
          created_at     TIMESTAMPTZ DEFAULT now()
        );
        """
    )

    op.execute(
        """
        CREATE TABLE probes (
          probe_id       UUID PRIMARY KEY,
          platform_key   TEXT REFERENCES platforms ON DELETE CASCADE,
          version        TEXT,
          capabilities   JSONB,
          status         TEXT NOT NULL DEFAULT 'offline',
          gateway_replica TEXT,
          last_heartbeat TIMESTAMPTZ,
          registered_at  TIMESTAMPTZ DEFAULT now()
        );
        """
    )

    op.execute(
        """
        CREATE TABLE alert_events (
          event_id     UUID PRIMARY KEY,
          fingerprint  TEXT NOT NULL,
          source       TEXT, platform_key TEXT, severity TEXT,
          payload_ref  TEXT,
          normalized   JSONB NOT NULL,
          disposition  TEXT NOT NULL,
          investigation_id UUID,
          reject_reason TEXT,
          received_at  TIMESTAMPTZ DEFAULT now()
        );
        """
    )
    op.execute("CREATE INDEX ON alert_events (fingerprint, received_at);")

    op.execute(
        r"""
        CREATE TABLE investigations (
          investigation_id UUID NOT NULL,
          platform_key   TEXT NOT NULL REFERENCES platforms,
          status         TEXT NOT NULL,
          trigger_event  UUID,
          workflow_id    TEXT NOT NULL,
          budget         JSONB NOT NULL,
          spent          JSONB NOT NULL DEFAULT '{"rounds"\:0,"cost_usd"\:0}',
          rca_report     JSONB,
          created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
          closed_at      TIMESTAMPTZ,
          PRIMARY KEY (investigation_id, created_at)
        ) PARTITION BY RANGE (created_at);
        """
    )
    op.execute(
        "CREATE TABLE investigations_default PARTITION OF investigations DEFAULT;"
    )

    op.execute(
        """
        CREATE TABLE iterations (
          investigation_id UUID NOT NULL,
          round          INT NOT NULL,
          plan           JSONB NOT NULL,
          rca_output     JSONB,
          cost_usd       NUMERIC(10,4), duration_ms INT,
          started_at     TIMESTAMPTZ, finished_at TIMESTAMPTZ,
          PRIMARY KEY (investigation_id, round)
        );
        """
    )

    op.execute(
        """
        CREATE TABLE evidence (
          evidence_id    UUID PRIMARY KEY,
          investigation_id UUID NOT NULL, round INT NOT NULL,
          tool_name      TEXT NOT NULL,
          args           JSONB, exit_code INT,
          summary        TEXT,
          payload_ref    TEXT,
          payload_bytes  BIGINT, redacted BOOLEAN DEFAULT false,
          executed_by    TEXT,
          created_at     TIMESTAMPTZ DEFAULT now()
        );
        """
    )

    op.execute(
        """
        CREATE TABLE llm_calls (
          call_id        UUID NOT NULL,
          investigation_id UUID, round INT,
          agent_role     TEXT NOT NULL,
          model          TEXT NOT NULL, provider TEXT,
          prompt_ref     TEXT, response_ref TEXT,
          input_tokens INT, output_tokens INT, cost_usd NUMERIC(10,6),
          latency_ms INT, error TEXT,
          created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
          PRIMARY KEY (call_id, created_at)
        ) PARTITION BY RANGE (created_at);
        """
    )
    op.execute("CREATE TABLE llm_calls_default PARTITION OF llm_calls DEFAULT;")

    op.execute(
        r"""
        CREATE TABLE playbooks (
          playbook_id    TEXT PRIMARY KEY,
          platform_type  TEXT NOT NULL,
          risk_level     TEXT NOT NULL,
          params_schema  JSONB NOT NULL,
          steps          JSONB NOT NULL,
          verification   JSONB NOT NULL,
          auto_eligible  BOOLEAN DEFAULT false,
          maturity       JSONB DEFAULT '{"approved_runs"\:0,"success"\:0,"rollbacks"\:0}'
        );
        """
    )

    op.execute(
        """
        CREATE TABLE remediation_executions (
          execution_id   UUID PRIMARY KEY,
          investigation_id UUID NOT NULL,
          playbook_id    TEXT REFERENCES playbooks,
          params         JSONB,
          mode           TEXT NOT NULL,
          approved_by    UUID,
          status         TEXT NOT NULL,
          pre_snapshot   JSONB,
          verification_result JSONB,
          started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ
        );
        """
    )

    op.execute(
        """
        CREATE TABLE approvals (
          approval_id    UUID PRIMARY KEY,
          investigation_id UUID NOT NULL,
          kind           TEXT NOT NULL,
          subject        JSONB NOT NULL,
          decision       TEXT,
          decided_by     UUID, decided_at TIMESTAMPTZ, comment TEXT,
          created_at     TIMESTAMPTZ DEFAULT now()
        );
        """
    )

    op.execute(
        """
        CREATE TABLE users (
          user_id UUID PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          role TEXT NOT NULL,
          created_at TIMESTAMPTZ DEFAULT now(), disabled BOOLEAN DEFAULT false
        );
        """
    )

    op.execute(
        """
        CREATE TABLE audit_log (
          seq BIGSERIAL,
          investigation_id UUID,
          actor TEXT NOT NULL,
          action TEXT NOT NULL,
          detail JSONB,
          at TIMESTAMPTZ NOT NULL DEFAULT now(),
          PRIMARY KEY (seq, at)
        ) PARTITION BY RANGE (at);
        """
    )
    op.execute("CREATE TABLE audit_log_default PARTITION OF audit_log DEFAULT;")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS audit_log_default;")
    op.execute("DROP TABLE IF EXISTS audit_log;")
    op.execute("DROP TABLE IF EXISTS users;")
    op.execute("DROP TABLE IF EXISTS approvals;")
    op.execute("DROP TABLE IF EXISTS remediation_executions;")
    op.execute("DROP TABLE IF EXISTS playbooks;")
    op.execute("DROP TABLE IF EXISTS llm_calls_default;")
    op.execute("DROP TABLE IF EXISTS llm_calls;")
    op.execute("DROP TABLE IF EXISTS evidence;")
    op.execute("DROP TABLE IF EXISTS iterations;")
    op.execute("DROP TABLE IF EXISTS investigations_default;")
    op.execute("DROP TABLE IF EXISTS investigations;")
    op.execute("DROP TABLE IF EXISTS alert_events;")
    op.execute("DROP TABLE IF EXISTS probes;")
    op.execute("DROP TABLE IF EXISTS platforms;")
