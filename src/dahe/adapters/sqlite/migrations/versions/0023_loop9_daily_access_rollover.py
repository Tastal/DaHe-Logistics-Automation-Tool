"""Add durable authority for daily access-window rollover.

Revision ID: 0023_loop9_daily_access_rollover
Revises: 0022_loop9_selection_lifecycle
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0023_loop9_daily_access_rollover"
down_revision = "0022_loop9_selection_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "daily_capture_invocations",
        sa.Column("authority_json", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(
        "daily_capture_invocations",
        "authority_json",
    )
