"""Add production daily report settings and immutable file records.

Revision ID: 0032_daily_reports
Revises: 0031_loop9_authority_contexts
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0032_daily_reports"
down_revision = "0031_loop9_authority_contexts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "daily_report_settings",
        sa.Column("settings_id", sa.String(32), primary_key=True),
        sa.Column("shipping_mine", sa.String(200), nullable=False),
        sa.Column("coal_type", sa.String(200), nullable=False),
        sa.Column("unloading_place", sa.String(200), nullable=False),
        sa.Column("query_place_keyword", sa.String(200), nullable=False),
        sa.Column("output_directory", sa.Text(), nullable=False),
        sa.Column("confirmed", sa.Integer(), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "settings_id = 'primary' AND confirmed IN (0, 1) "
            "AND record_version >= 1",
            name="ck_daily_report_settings_shape",
        ),
    )
    op.create_table(
        "daily_reports",
        sa.Column("report_id", sa.String(32), primary_key=True),
        sa.Column("business_date", sa.String(10), nullable=False, unique=True),
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
        sa.CheckConstraint(
            "status IN ('pending_confirmation', 'confirmed') "
            "AND settings_record_version >= 1 AND row_count >= 0 "
            "AND record_version >= 1 AND length(file_sha256) = 64 "
            "AND length(data_snapshot_sha256) = 64",
            name="ck_daily_report_shape",
        ),
    )
    op.create_table(
        "daily_report_idempotency",
        sa.Column("idempotency_key", sa.String(200), primary_key=True),
        sa.Column("operation", sa.String(40), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64",
            name="ck_daily_report_idempotency_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("daily_report_idempotency")
    op.drop_table("daily_reports")
    op.drop_table("daily_report_settings")
