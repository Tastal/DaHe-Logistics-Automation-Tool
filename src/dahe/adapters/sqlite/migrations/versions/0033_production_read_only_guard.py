"""Add the first-batch production read-only guard.

Revision ID: 0033_production_guard
Revises: 0032_daily_reports
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0033_production_guard"
down_revision = "0032_daily_reports"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "production_read_only_guard",
        sa.Column("guard_id", sa.String(32), primary_key=True),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("target_count", sa.Integer(), nullable=False),
        sa.Column("registered_count", sa.Integer(), nullable=False),
        sa.Column("reviewed_target_count", sa.Integer(), nullable=False),
        sa.Column("false_normal_count", sa.Integer(), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("activated_at", sa.String(40), nullable=False),
        sa.Column("resolved_at", sa.String(40)),
        sa.CheckConstraint(
            "guard_id = 'primary' "
            "AND status IN ('operational_read_only_with_guard', "
            "'operational_read_only_accepted') "
            "AND target_count = 30 AND registered_count >= 0 "
            "AND reviewed_target_count BETWEEN 0 AND target_count "
            "AND false_normal_count >= 0 AND record_version >= 1",
            name="ck_production_read_only_guard_shape",
        ),
    )
    op.create_table(
        "production_read_only_guard_items",
        sa.Column(
            "work_item_id",
            sa.String(32),
            sa.ForeignKey("work_items.work_item_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("ordinal", sa.Integer(), nullable=False, unique=True),
        sa.Column("counts_toward_gate", sa.Integer(), nullable=False),
        sa.Column("machine_outcome", sa.String(50), nullable=False),
        sa.Column("manual_outcome", sa.String(50)),
        sa.Column("manual_action_id", sa.String(100), unique=True),
        sa.Column("protected", sa.Integer(), nullable=False),
        sa.Column("released", sa.Integer(), nullable=False),
        sa.Column("registered_at", sa.String(40), nullable=False),
        sa.Column("reviewed_at", sa.String(40)),
        sa.CheckConstraint(
            "ordinal >= 1 AND counts_toward_gate IN (0, 1) "
            "AND protected IN (0, 1) AND released IN (0, 1) "
            "AND machine_outcome IN ('normal_ready', 'awaiting_review', "
            "'confirmed_problem', 'technical_failure') "
            "AND (manual_outcome IS NULL OR manual_outcome IN "
            "('normal_ready', 'confirmed_problem')) "
            "AND ((manual_outcome IS NULL AND manual_action_id IS NULL "
            "AND reviewed_at IS NULL) OR (manual_outcome IS NOT NULL "
            "AND manual_action_id IS NOT NULL AND reviewed_at IS NOT NULL))",
            name="ck_production_read_only_guard_item_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("production_read_only_guard_items")
    op.drop_table("production_read_only_guard")
