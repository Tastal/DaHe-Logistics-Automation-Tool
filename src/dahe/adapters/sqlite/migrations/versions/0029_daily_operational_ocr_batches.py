"""Link operational daily evidence batches to local OCR jobs.

Revision ID: 0029_daily_batch_ocr
Revises: 0028_operational_batch_capture
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0029_daily_batch_ocr"
down_revision = "0028_operational_batch_capture"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "daily_operational_ocr_batches",
        sa.Column(
            "daily_job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("batch_number", sa.Integer(), primary_key=True),
        sa.Column(
            "ocr_job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="RESTRICT"),
            unique=True,
        ),
        sa.Column("eligible_item_count", sa.Integer(), nullable=False),
        sa.Column("missing_ticket_count", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "batch_number >= 1 "
            "AND eligible_item_count >= 0 "
            "AND missing_ticket_count >= 0 "
            "AND eligible_item_count + missing_ticket_count BETWEEN 1 AND 15 "
            "AND ((eligible_item_count = 0 AND ocr_job_id IS NULL) "
            "OR (eligible_item_count > 0 AND ocr_job_id IS NOT NULL))",
            name="ck_daily_operational_ocr_batch_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("daily_operational_ocr_batches")
