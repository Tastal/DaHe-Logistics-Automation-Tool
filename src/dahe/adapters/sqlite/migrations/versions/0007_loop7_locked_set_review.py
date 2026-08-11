"""Add isolated manual review state for locked-set candidates.

Revision ID: 0007_loop7_locked_set_review
Revises: 0006_loop7_locked_set_authority
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0007_loop7_locked_set_review"
down_revision = "0006_loop7_locked_set_authority"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "locked_set_review_items",
        sa.Column("package_sha256", sa.String(64), primary_key=True),
        sa.Column("sample_id", sa.String(100), primary_key=True),
        sa.Column("record_version", sa.Integer(), primary_key=True),
        sa.Column("review_status", sa.String(30), nullable=False),
        sa.Column("decision", sa.String(30), nullable=False),
        sa.Column("review_payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(package_sha256) = 64",
            name="ck_locked_set_review_items_package_sha256",
        ),
        sa.CheckConstraint(
            "review_status IN ('confirmed', 'replace_candidate')",
            name="ck_locked_set_review_items_status",
        ),
        sa.CheckConstraint(
            "decision IN ('confirmed', 'replace_candidate') "
            "AND decision = review_status",
            name="ck_locked_set_review_items_decision",
        ),
        sa.CheckConstraint(
            "record_version >= 1",
            name="ck_locked_set_review_items_record_version",
        ),
    )
    op.create_table(
        "locked_set_review_idempotency",
        sa.Column("package_sha256", sa.String(64), primary_key=True),
        sa.Column("idempotency_key", sa.String(200), primary_key=True),
        sa.Column("sample_id", sa.String(100), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("resulting_record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            [
                "package_sha256",
                "sample_id",
                "resulting_record_version",
            ],
            [
                "locked_set_review_items.package_sha256",
                "locked_set_review_items.sample_id",
                "locked_set_review_items.record_version",
            ],
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "length(package_sha256) = 64 AND length(request_hash) = 64",
            name="ck_locked_set_review_idempotency_hashes",
        ),
        sa.CheckConstraint(
            "resulting_record_version >= 1",
            name="ck_locked_set_review_idempotency_record_version",
        ),
    )
    op.execute(
        """
        CREATE TRIGGER locked_set_review_items_immutable_update
        BEFORE UPDATE ON locked_set_review_items
        BEGIN
            SELECT RAISE(
                ABORT,
                'locked_set_review_items is append-only'
            );
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER locked_set_review_items_immutable_delete
        BEFORE DELETE ON locked_set_review_items
        BEGIN
            SELECT RAISE(
                ABORT,
                'locked_set_review_items is append-only'
            );
        END
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS locked_set_review_items_immutable_delete"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS locked_set_review_items_immutable_update"
    )
    op.drop_table("locked_set_review_idempotency")
    op.drop_table("locked_set_review_items")
