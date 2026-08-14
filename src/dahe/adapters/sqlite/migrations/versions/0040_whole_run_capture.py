"""Add atomic whole-run capture and one-to-one review links.

Revision ID: 0040_whole_run_capture
Revises: 0039_network_batch_default
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0040_whole_run_capture"
down_revision = "0039_network_batch_default"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("settlement_capture_strategies") as batch:
        batch.drop_constraint("ck_settlement_capture_strategy_value", type_="check")
        batch.create_check_constraint(
            "ck_settlement_capture_strategy_value",
            "strategy IN ('legacy', 'batch_v1', 'whole_run_v1')",
        )
    with op.batch_alter_table("operational_capture_runs") as batch:
        batch.add_column(
            sa.Column(
                "capture_mode",
                sa.String(length=20),
                nullable=False,
                server_default="batch_v1",
            )
        )
        batch.drop_constraint("ck_operational_capture_run_shape", type_="check")
        batch.create_check_constraint(
            "ck_operational_capture_run_shape",
            "total >= 0 AND next_item_index >= 0 AND next_item_index <= total "
            "AND committed_batch_count >= 0 "
            "AND capture_mode IN ('batch_v1', 'whole_run_v1') "
            "AND ((capture_mode = 'batch_v1' AND batch_size IN (15, 20, 50, 100)) "
            "OR (capture_mode = 'whole_run_v1' AND committed_batch_count <= 1 "
            "AND ((total = 0 AND batch_size = 1) OR batch_size = total))) "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND status IN ('collecting', 'complete') AND record_version >= 1 "
            "AND metadata_checked_count BETWEEN 0 AND total "
            "AND reused_count BETWEEN 0 AND metadata_checked_count "
            "AND images_downloaded_count >= 0 AND length(items_sha256) = 64 "
            "AND ((status = 'complete' AND next_item_index = total) "
            "OR (status = 'collecting' AND (next_item_index < total OR total = 0)))",
        )
    op.create_table(
        "operational_review_links",
        sa.Column(
            "source_job_id",
            sa.String(length=32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("business_kind", sa.String(length=20), nullable=False),
        sa.Column(
            "review_job_id",
            sa.String(length=32),
            sa.ForeignKey("jobs.job_id", ondelete="RESTRICT"),
            nullable=True,
            unique=True,
        ),
        sa.Column("eligible_item_count", sa.Integer(), nullable=False),
        sa.Column("missing_item_count", sa.Integer(), nullable=False),
        sa.Column("source_manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "business_kind IN ('settlement', 'daily') "
            "AND eligible_item_count >= 0 AND missing_item_count >= 0 "
            "AND length(source_manifest_sha256) = 64 "
            "AND ((eligible_item_count = 0 AND review_job_id IS NULL) "
            "OR (eligible_item_count > 0 AND review_job_id IS NOT NULL))",
            name="ck_operational_review_link_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("operational_review_links")
    with op.batch_alter_table("operational_capture_runs") as batch:
        batch.drop_constraint("ck_operational_capture_run_shape", type_="check")
        batch.drop_column("capture_mode")
        batch.create_check_constraint(
            "ck_operational_capture_run_shape",
            "total >= 0 AND next_item_index >= 0 AND next_item_index <= total "
            "AND committed_batch_count >= 0 AND batch_size IN (15, 20, 50, 100) "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND status IN ('collecting', 'complete') AND record_version >= 1 "
            "AND metadata_checked_count BETWEEN 0 AND total "
            "AND reused_count BETWEEN 0 AND metadata_checked_count "
            "AND images_downloaded_count >= 0 AND length(items_sha256) = 64 "
            "AND ((status = 'complete' AND next_item_index = total) "
            "OR (status = 'collecting' AND (next_item_index < total OR total = 0)))",
        )
    with op.batch_alter_table("settlement_capture_strategies") as batch:
        batch.drop_constraint("ck_settlement_capture_strategy_value", type_="check")
        batch.create_check_constraint(
            "ck_settlement_capture_strategy_value",
            "strategy IN ('legacy', 'batch_v1')",
        )
