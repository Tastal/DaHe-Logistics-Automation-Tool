"""Persist explicit OCR mode and image-sized shared runtime artifacts.

Revision ID: 0004_loop6_image_quanta
Revises: 0003_loop6_ocr_runs
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004_loop6_image_quanta"
down_revision = "0003_loop6_ocr_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.add_column(
            sa.Column(
                "ocr_execution_mode",
                sa.String(10),
                nullable=False,
                server_default="fake",
            )
        )

    with op.batch_alter_table("shared_evidence_work") as batch_op:
        batch_op.add_column(sa.Column("image_relative_path", sa.String(500)))
        batch_op.add_column(
            sa.Column(
                "execution_mode",
                sa.String(10),
                nullable=False,
                server_default="fake",
            )
        )
        batch_op.add_column(sa.Column("runtime_kind", sa.String(10)))
        batch_op.add_column(sa.Column("profile_id", sa.String(100)))
        batch_op.add_column(sa.Column("runtime_fingerprint", sa.String(64)))
        batch_op.add_column(sa.Column("output_json", sa.Text()))
        batch_op.add_column(sa.Column("output_fingerprint", sa.String(64)))


def downgrade() -> None:
    with op.batch_alter_table("shared_evidence_work") as batch_op:
        batch_op.drop_column("output_fingerprint")
        batch_op.drop_column("output_json")
        batch_op.drop_column("runtime_fingerprint")
        batch_op.drop_column("profile_id")
        batch_op.drop_column("runtime_kind")
        batch_op.drop_column("execution_mode")
        batch_op.drop_column("image_relative_path")
    with op.batch_alter_table("jobs") as batch_op:
        batch_op.drop_column("ocr_execution_mode")
