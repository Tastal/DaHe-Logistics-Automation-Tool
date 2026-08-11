"""Add fixed strategies and normalized progress for operational batches.

Revision ID: 0028_operational_batch_capture
Revises: 0027_platform_credentials
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028_operational_batch_capture"
down_revision = "0027_platform_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "settlement_capture_strategies",
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("strategy", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "strategy IN ('legacy', 'batch_v1')",
            name="ck_settlement_capture_strategy_value",
        ),
    )
    op.create_table(
        "operational_capture_runs",
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("total", sa.Integer(), nullable=False),
        sa.Column("items_json", sa.Text(), nullable=False),
        sa.Column("items_sha256", sa.String(64), nullable=False),
        sa.Column("next_item_index", sa.Integer(), nullable=False),
        sa.Column("committed_batch_count", sa.Integer(), nullable=False),
        sa.Column("batch_size", sa.Integer(), nullable=False),
        sa.Column("detail_concurrency", sa.Integer(), nullable=False),
        sa.Column("image_concurrency", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "total >= 0 AND next_item_index >= 0 "
            "AND next_item_index <= total "
            "AND committed_batch_count >= 0 "
            "AND batch_size = 15 "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND status IN ('collecting', 'complete') "
            "AND record_version >= 1 "
            "AND length(items_sha256) = 64 "
            "AND ((status = 'complete' AND next_item_index = total) "
            "OR (status = 'collecting' AND "
            "(next_item_index < total OR total = 0)))",
            name="ck_operational_capture_run_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("operational_capture_runs")
    op.drop_table("settlement_capture_strategies")
