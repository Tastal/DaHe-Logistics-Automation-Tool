"""Add durable idempotency for starting a Loop 9 daily capture.

Revision ID: 0017_loop9_daily_start_idempotency
Revises: 0016_loop9_daily_read_model
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0017_loop9_daily_start_idempotency"
down_revision = "0016_loop9_daily_read_model"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "daily_capture_start_requests",
        sa.Column("idempotency_key", sa.String(200), primary_key=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("access_window_id", sa.String(100), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("invocation_id", sa.String(100)),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 "
            "AND record_version >= 1 "
            "AND status IN ('reserved', 'completed') "
            "AND ((status = 'reserved' AND invocation_id IS NULL) "
            "OR (status = 'completed' AND invocation_id IS NOT NULL))",
            name="ck_daily_capture_start_request_shape",
        ),
    )
    op.create_index(
        "ix_daily_capture_start_requests_access_window",
        "daily_capture_start_requests",
        ["access_window_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_daily_capture_start_requests_access_window",
        table_name="daily_capture_start_requests",
    )
    op.drop_table("daily_capture_start_requests")
