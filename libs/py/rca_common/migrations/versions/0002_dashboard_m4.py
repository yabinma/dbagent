"""M4 dashboard: users.must_change_password (design.md Section 10.2.3).

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-24
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

revision: str = "0002_dashboard_m4"
down_revision: Union[str, None] = "0001_initial_schema"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE users
        ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT false;
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE users DROP COLUMN IF EXISTS must_change_password;")
