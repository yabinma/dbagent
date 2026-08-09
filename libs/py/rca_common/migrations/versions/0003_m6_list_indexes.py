"""M6 list/detail performance indexes (design.md B10 / FP-M6-21).

Btree indexes only — no tsvector, no full-text search, no wire-contract change.
Supports dashboard list_investigations cost batching and filtered history queries
over partitioned investigations / llm_calls.

Revision ID: 0003_m6_list_indexes
Revises: 0002_dashboard_m4
Create Date: 2026-07-26
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0003_m6_list_indexes"
down_revision: Union[str, None] = "0002_dashboard_m4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Partial index: list/detail only look up non-null investigation_ids.
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS llm_calls_investigation_id_idx
          ON llm_calls (investigation_id)
          WHERE investigation_id IS NOT NULL
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS investigations_list_idx
          ON investigations (created_at DESC, investigation_id DESC)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS investigations_filter_idx
          ON investigations (status, platform_key, created_at DESC)
        """
    )


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS investigations_filter_idx")
    op.execute("DROP INDEX IF EXISTS investigations_list_idx")
    op.execute("DROP INDEX IF EXISTS llm_calls_investigation_id_idx")
