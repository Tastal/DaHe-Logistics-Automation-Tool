"""Add verified operational evidence reuse and progress counters.

Revision ID: 0037_operational_reuse
Revises: 0036_guard_policy
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0037_operational_reuse"
down_revision = "0036_guard_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("operational_capture_runs") as batch:
        batch.add_column(
            sa.Column(
                "metadata_checked_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column(
                "reused_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch.add_column(
            sa.Column(
                "images_downloaded_count",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
    op.create_table(
        "operational_evidence_reuse",
        sa.Column("platform_waybill_id", sa.String(64), primary_key=True),
        sa.Column("source_revision_sha256", sa.String(64), nullable=False),
        sa.Column("loading_sha256", sa.String(64)),
        sa.Column("loading_media_type", sa.String(80)),
        sa.Column("loading_validator_sha256", sa.String(64)),
        sa.Column("unloading_sha256", sa.String(64)),
        sa.Column("unloading_media_type", sa.String(80)),
        sa.Column("unloading_validator_sha256", sa.String(64)),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(source_revision_sha256) = 64 "
            "AND ((loading_sha256 IS NULL "
            "AND loading_media_type IS NULL "
            "AND loading_validator_sha256 IS NULL) "
            "OR (length(loading_sha256) = 64 "
            "AND length(loading_media_type) > 0 "
            "AND length(loading_validator_sha256) = 64)) "
            "AND ((unloading_sha256 IS NULL "
            "AND unloading_media_type IS NULL "
            "AND unloading_validator_sha256 IS NULL) "
            "OR (length(unloading_sha256) = 64 "
            "AND length(unloading_media_type) > 0 "
            "AND length(unloading_validator_sha256) = 64))",
            name="ck_operational_evidence_reuse_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("operational_evidence_reuse")
    with op.batch_alter_table("operational_capture_runs") as batch:
        batch.drop_constraint("ck_operational_capture_run_shape", type_="check")
        batch.drop_column("images_downloaded_count")
        batch.drop_column("reused_count")
        batch.drop_column("metadata_checked_count")
        batch.create_check_constraint(
            "ck_operational_capture_run_shape",
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
        )
