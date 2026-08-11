"""Add append-only daily manual revisions and stale report tracking.

Revision ID: 0035_daily_revisions
Revises: 0034_guard_identity
"""

from __future__ import annotations

from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0035_daily_revisions"
down_revision = "0034_guard_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "performance_settings",
        sa.Column("settings_id", sa.String(32), primary_key=True),
        sa.Column("preset", sa.String(20), nullable=False),
        sa.Column("detail_concurrency", sa.Integer(), nullable=False),
        sa.Column("image_concurrency", sa.Integer(), nullable=False),
        sa.Column("cpu_ocr_threads", sa.Integer(), nullable=False),
        sa.Column("gpu_idle_minutes", sa.Integer(), nullable=False),
        sa.Column("keep_gpu_ready", sa.Integer(), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "settings_id = 'primary' AND preset IN ('responsive', 'balanced', 'speed') "
            "AND detail_concurrency BETWEEN 1 AND 4 "
            "AND image_concurrency BETWEEN 1 AND 6 "
            "AND cpu_ocr_threads BETWEEN 1 AND 8 "
            "AND gpu_idle_minutes BETWEEN 0 AND 60 "
            "AND keep_gpu_ready IN (0, 1) AND record_version >= 1",
            name="ck_performance_settings_shape",
        ),
    )
    op.create_table(
        "daily_manual_revisions",
        sa.Column("action_id", sa.String(32), primary_key=True),
        sa.Column("platform_waybill_id", sa.String(200), nullable=False),
        sa.Column("manual_revision_number", sa.Integer(), nullable=False),
        sa.Column(
            "base_observation_id",
            sa.String(100),
            sa.ForeignKey("daily_observations.observation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("base_loading_ticket_sha256", sa.String(64)),
        sa.Column("base_unloading_ticket_sha256", sa.String(64)),
        sa.Column("changes_json", sa.Text(), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.UniqueConstraint(
            "platform_waybill_id",
            "manual_revision_number",
            name="uq_daily_manual_revision_number",
        ),
        sa.CheckConstraint(
            "manual_revision_number >= 1 AND length(request_hash) = 64 "
            "AND (base_loading_ticket_sha256 IS NULL "
            "OR length(base_loading_ticket_sha256) = 64) "
            "AND (base_unloading_ticket_sha256 IS NULL "
            "OR length(base_unloading_ticket_sha256) = 64)",
            name="ck_daily_manual_revision_shape",
        ),
    )
    op.create_table(
        "daily_manual_revision_idempotency",
        sa.Column("idempotency_key", sa.String(200), primary_key=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("platform_waybill_id", sa.String(200), nullable=False),
        sa.Column("action_id", sa.String(32), nullable=False),
        sa.Column("result_record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND result_record_version >= 1",
            name="ck_daily_manual_revision_idempotency_shape",
        ),
    )
    _replace_daily_reports_table(include_stale=True, unique_business_date=False)


def downgrade() -> None:
    _replace_daily_reports_table(include_stale=False, unique_business_date=True)
    op.drop_table("daily_manual_revision_idempotency")
    op.drop_table("daily_manual_revisions")
    op.drop_table("performance_settings")


def _replace_daily_reports_table(
    *, include_stale: bool, unique_business_date: bool
) -> None:
    """Replace the SQLite table without relying on generated constraint names."""

    columns: list[Any] = [
        sa.Column("report_id", sa.String(32), primary_key=True),
        sa.Column("business_date", sa.String(10), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("settings_record_version", sa.Integer(), nullable=False),
        sa.Column("output_directory", sa.Text(), nullable=False),
        sa.Column("file_name", sa.String(255), nullable=False),
        sa.Column("file_sha256", sa.String(64), nullable=False),
        sa.Column("data_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=False),
        sa.Column("row_count", sa.Integer(), nullable=False),
        sa.Column("loading_net_total", sa.String(50), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("confirmed_at", sa.String(40)),
    ]
    if include_stale:
        columns.append(
            sa.Column("stale", sa.Integer(), nullable=False, server_default="0")
        )
    if unique_business_date:
        columns.append(sa.UniqueConstraint("business_date"))
    check = (
        "status IN ('pending_confirmation', 'confirmed') "
        "AND settings_record_version >= 1 AND row_count >= 0 "
        "AND record_version >= 1 AND length(file_sha256) = 64 "
        "AND length(data_snapshot_sha256) = 64"
    )
    if include_stale:
        check += " AND stale IN (0, 1)"
    columns.append(sa.CheckConstraint(check, name="ck_daily_report_shape"))
    op.create_table("daily_reports_replacement", *columns)

    target_columns = (
        "report_id, business_date, status, settings_record_version, "
        "output_directory, file_name, file_sha256, data_snapshot_sha256, "
        "data_json, row_count, loading_net_total, record_version, created_at, "
        "confirmed_at"
    )
    if include_stale:
        op.execute(
            "INSERT INTO daily_reports_replacement ("
            + target_columns
            + ", stale) SELECT "
            + target_columns
            + ", 0 FROM daily_reports"
        )
    else:
        op.execute(
            "INSERT INTO daily_reports_replacement ("
            + target_columns
            + ") SELECT "
            + target_columns
            + " FROM daily_reports WHERE stale = 0"
        )
    op.drop_table("daily_reports")
    op.rename_table("daily_reports_replacement", "daily_reports")
    if include_stale:
        op.create_index(
            "ix_daily_reports_business_date", "daily_reports", ["business_date"]
        )
