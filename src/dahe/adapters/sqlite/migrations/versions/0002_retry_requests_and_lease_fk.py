"""Add durable retry requests and fence lease resources.

Revision ID: 0002_retry_lease_fk
Revises: 0001_loop4
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0002_retry_lease_fk"
down_revision = "0001_loop4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "shared_work_retry_requests",
        sa.Column(
            "shared_work_id",
            sa.String(32),
            sa.ForeignKey("shared_evidence_work.shared_work_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("expected_record_version", sa.Integer(), nullable=False),
        sa.Column(
            "stage_attempt_id",
            sa.String(32),
            sa.ForeignKey("stage_attempts.stage_attempt_id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.UniqueConstraint(
            "shared_work_id",
            "idempotency_key",
            name="uq_shared_work_retry_request",
        ),
    )
    with op.batch_alter_table("leases", recreate="always") as batch_op:
        batch_op.create_foreign_key(
            "fk_leases_resource_name_resource_slots",
            "resource_slots",
            ["resource_name"],
            ["resource_name"],
        )


def downgrade() -> None:
    with op.batch_alter_table("leases", recreate="always") as batch_op:
        batch_op.drop_constraint(
            "fk_leases_resource_name_resource_slots",
            type_="foreignkey",
        )
    op.drop_table("shared_work_retry_requests")
