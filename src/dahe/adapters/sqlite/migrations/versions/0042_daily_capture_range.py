"""Add versioned operational daily capture range settings.

Revision ID: 0042_daily_capture_range
Revises: 0041_contract_subject_scope
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0042_daily_capture_range"
down_revision = "0041_contract_subject_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("daily_report_settings") as batch:
        batch.drop_constraint("ck_daily_report_settings_shape", type_="check")
        batch.add_column(
            sa.Column(
                "capture_start_time",
                sa.String(length=8),
                nullable=False,
                server_default="14:00:00",
            )
        )
        batch.add_column(
            sa.Column(
                "capture_end_mode",
                sa.String(length=30),
                nullable=False,
                server_default="system_current_time",
            )
        )
        batch.add_column(
            sa.Column(
                "capture_fixed_end_day_offset",
                sa.Integer(),
                nullable=False,
                server_default="1",
            )
        )
        batch.add_column(
            sa.Column(
                "capture_fixed_end_time",
                sa.String(length=8),
                nullable=False,
                server_default="14:30:00",
            )
        )
        batch.create_check_constraint(
            "ck_daily_report_settings_shape",
            "settings_id = 'primary' AND confirmed IN (0, 1) "
            "AND record_version >= 1 "
            "AND capture_end_mode IN ('system_current_time', 'fixed_time') "
            "AND capture_fixed_end_day_offset IN (0, 1)",
        )


def downgrade() -> None:
    with op.batch_alter_table("daily_report_settings") as batch:
        batch.drop_constraint("ck_daily_report_settings_shape", type_="check")
        batch.drop_column("capture_fixed_end_time")
        batch.drop_column("capture_fixed_end_day_offset")
        batch.drop_column("capture_end_mode")
        batch.drop_column("capture_start_time")
        batch.create_check_constraint(
            "ck_daily_report_settings_shape",
            "settings_id = 'primary' AND confirmed IN (0, 1) "
            "AND record_version >= 1",
        )
