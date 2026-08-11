"""Allow configurable operational network batches.

Revision ID: 0038_network_batches
Revises: 0037_operational_reuse
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0038_network_batches"
down_revision = "0037_operational_reuse"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("performance_settings") as batch:
        batch.add_column(
            sa.Column(
                "network_batch_size",
                sa.Integer(),
                nullable=False,
                server_default="20",
            )
        )
        batch.drop_constraint("ck_performance_settings_shape", type_="check")
        batch.create_check_constraint(
            "ck_performance_settings_shape",
            "settings_id = 'primary' "
            "AND preset IN ('responsive', 'balanced', 'speed') "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND cpu_ocr_threads BETWEEN 1 AND 8 "
            "AND gpu_idle_minutes BETWEEN 0 AND 60 "
            "AND keep_gpu_ready IN (0, 1) "
            "AND network_batch_size IN (20, 50, 100) "
            "AND record_version >= 1",
        )
    with op.batch_alter_table("operational_capture_runs") as batch:
        batch.drop_constraint("ck_operational_capture_run_shape", type_="check")
        batch.create_check_constraint(
            "ck_operational_capture_run_shape",
            "total >= 0 AND next_item_index >= 0 "
            "AND next_item_index <= total "
            "AND committed_batch_count >= 0 "
            "AND batch_size IN (15, 20, 50, 100) "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND status IN ('collecting', 'complete') "
            "AND record_version >= 1 "
            "AND metadata_checked_count BETWEEN 0 AND total "
            "AND reused_count BETWEEN 0 AND metadata_checked_count "
            "AND images_downloaded_count >= 0 "
            "AND length(items_sha256) = 64 "
            "AND ((status = 'complete' AND next_item_index = total) "
            "OR (status = 'collecting' AND "
            "(next_item_index < total OR total = 0)))",
        )
    with op.batch_alter_table("daily_operational_ocr_batches") as batch:
        batch.drop_constraint("ck_daily_operational_ocr_batch_shape", type_="check")
        batch.create_check_constraint(
            "ck_daily_operational_ocr_batch_shape",
            "batch_number >= 1 "
            "AND eligible_item_count >= 0 "
            "AND missing_ticket_count >= 0 "
            "AND eligible_item_count + missing_ticket_count BETWEEN 1 AND 100 "
            "AND ((eligible_item_count = 0 AND ocr_job_id IS NULL) "
            "OR (eligible_item_count > 0 AND ocr_job_id IS NOT NULL))",
        )


def downgrade() -> None:
    with op.batch_alter_table("daily_operational_ocr_batches") as batch:
        batch.drop_constraint("ck_daily_operational_ocr_batch_shape", type_="check")
        batch.create_check_constraint(
            "ck_daily_operational_ocr_batch_shape",
            "batch_number >= 1 "
            "AND eligible_item_count >= 0 "
            "AND missing_ticket_count >= 0 "
            "AND eligible_item_count + missing_ticket_count BETWEEN 1 AND 15 "
            "AND ((eligible_item_count = 0 AND ocr_job_id IS NULL) "
            "OR (eligible_item_count > 0 AND ocr_job_id IS NOT NULL))",
        )
    with op.batch_alter_table("operational_capture_runs") as batch:
        batch.drop_constraint("ck_operational_capture_run_shape", type_="check")
        batch.create_check_constraint(
            "ck_operational_capture_run_shape",
            "total >= 0 AND next_item_index >= 0 "
            "AND next_item_index <= total "
            "AND committed_batch_count >= 0 AND batch_size = 15 "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND status IN ('collecting', 'complete') "
            "AND record_version >= 1 "
            "AND metadata_checked_count BETWEEN 0 AND total "
            "AND reused_count BETWEEN 0 AND metadata_checked_count "
            "AND images_downloaded_count >= 0 "
            "AND length(items_sha256) = 64 "
            "AND ((status = 'complete' AND next_item_index = total) "
            "OR (status = 'collecting' AND "
            "(next_item_index < total OR total = 0)))",
        )
    with op.batch_alter_table("performance_settings") as batch:
        batch.drop_constraint("ck_performance_settings_shape", type_="check")
        batch.drop_column("network_batch_size")
        batch.create_check_constraint(
            "ck_performance_settings_shape",
            "settings_id = 'primary' "
            "AND preset IN ('responsive', 'balanced', 'speed') "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND cpu_ocr_threads BETWEEN 1 AND 8 "
            "AND gpu_idle_minutes BETWEEN 0 AND 60 "
            "AND keep_gpu_ready IN (0, 1) AND record_version >= 1",
        )
