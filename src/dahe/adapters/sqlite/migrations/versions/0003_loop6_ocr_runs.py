"""Add persistent waybill OCR run generations.

Revision ID: 0003_loop6_ocr_runs
Revises: 0002_retry_lease_fk
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003_loop6_ocr_runs"
down_revision = "0002_retry_lease_fk"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("work_items") as batch_op:
        batch_op.add_column(
            sa.Column("loading_image_relative_path", sa.String(500))
        )
        batch_op.add_column(
            sa.Column("unloading_image_relative_path", sa.String(500))
        )
        batch_op.add_column(sa.Column("ocr_generation_id", sa.String(32)))

    with op.batch_alter_table("stage_attempts") as batch_op:
        batch_op.add_column(sa.Column("generation_id", sa.String(32)))
        batch_op.add_column(sa.Column("runtime_kind", sa.String(10)))
        batch_op.add_column(sa.Column("profile_id", sa.String(100)))
        batch_op.add_column(sa.Column("runtime_fingerprint", sa.String(64)))
        batch_op.add_column(sa.Column("pipeline_fingerprint", sa.String(64)))
        batch_op.add_column(sa.Column("input_fingerprint", sa.String(64)))
        batch_op.add_column(sa.Column("output_fingerprint", sa.String(64)))
        batch_op.add_column(
            sa.Column(
                "discarded",
                sa.Integer(),
                nullable=False,
                server_default="0",
            )
        )
        batch_op.add_column(sa.Column("error_kind", sa.String(50)))

    op.create_table(
        "ocr_run_generations",
        sa.Column("generation_id", sa.String(32), primary_key=True),
        sa.Column(
            "work_item_id",
            sa.String(32),
            sa.ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("pipeline_fingerprint", sa.String(64), nullable=False),
        sa.Column("primary_runtime_kind", sa.String(10), nullable=False),
        sa.Column("next_runtime_kind", sa.String(10), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("committed_runtime_kind", sa.String(10)),
        sa.Column("committed_profile_id", sa.String(100)),
        sa.Column("committed_runtime_fingerprint", sa.String(64)),
        sa.Column("loading_output_json", sa.Text()),
        sa.Column("unloading_output_json", sa.Text()),
        sa.Column("loading_output_fingerprint", sa.String(64)),
        sa.Column("unloading_output_fingerprint", sa.String(64)),
        sa.Column("diagnostic_code", sa.String(100)),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("ocr_run_generations")
    with op.batch_alter_table("stage_attempts") as batch_op:
        batch_op.drop_column("error_kind")
        batch_op.drop_column("discarded")
        batch_op.drop_column("output_fingerprint")
        batch_op.drop_column("input_fingerprint")
        batch_op.drop_column("pipeline_fingerprint")
        batch_op.drop_column("runtime_fingerprint")
        batch_op.drop_column("profile_id")
        batch_op.drop_column("runtime_kind")
        batch_op.drop_column("generation_id")
    with op.batch_alter_table("work_items") as batch_op:
        batch_op.drop_column("ocr_generation_id")
        batch_op.drop_column("unloading_image_relative_path")
        batch_op.drop_column("loading_image_relative_path")
