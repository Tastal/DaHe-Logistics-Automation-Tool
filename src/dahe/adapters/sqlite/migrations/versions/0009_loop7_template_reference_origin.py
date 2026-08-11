"""Add immutable development template-reference provenance.

Revision ID: 0009_loop7_template_reference_origin
Revises: 0008_loop7_review_authority
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0009_loop7_template_reference_origin"
down_revision = "0008_loop7_review_authority"
branch_labels = None
depends_on = None

_TABLE = "template_reference_origins"
_SHA256_COLUMNS = (
    "candidate_evidence_sha256",
    "candidate_record_blob_sha256",
    "source_image_sha256",
    "waybill_identity_sha256",
    "package_sha256",
    "review_history_authority_sha256",
    "source_authority_sha256",
    "review_record_evidence_sha256",
    "origin_sha256",
)


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "version_id",
            sa.String(32),
            sa.ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("candidate_evidence_sha256", sa.String(64), nullable=False),
        sa.Column(
            "candidate_record_blob_sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "source_image_sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("waybill_identity_sha256", sa.String(64), nullable=False),
        sa.Column("sample_id", sa.String(100), nullable=False),
        sa.Column("submitted_slot", sa.String(20), nullable=False),
        sa.Column("confirmed_role", sa.String(20), nullable=False),
        sa.Column("package_sha256", sa.String(64), nullable=False),
        sa.Column(
            "review_history_authority_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("source_authority_sha256", sa.String(64), nullable=False),
        sa.Column(
            "review_record_evidence_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("origin_payload_json", sa.Text(), nullable=False),
        sa.Column("origin_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "submitted_slot IN ('loading', 'unloading')",
            name="ck_template_reference_origins_slot",
        ),
        sa.CheckConstraint(
            "confirmed_role IN ('loading', 'unloading')",
            name="ck_template_reference_origins_role",
        ),
        sa.CheckConstraint(
            " AND ".join(
                f"length({column}) = 64 "
                f"AND {column} = lower({column}) "
                f"AND {column} NOT GLOB '*[^0-9a-f]*'"
                for column in _SHA256_COLUMNS
            ),
            name="ck_template_reference_origins_hashes",
        ),
    )
    op.execute(
        f"""
        CREATE TRIGGER {_TABLE}_immutable_update
        BEFORE UPDATE ON {_TABLE}
        BEGIN
            SELECT RAISE(ABORT, '{_TABLE} is append-only');
        END
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER {_TABLE}_immutable_delete
        BEFORE DELETE ON {_TABLE}
        BEGIN
            SELECT RAISE(ABORT, '{_TABLE} is append-only');
        END
        """
    )


def downgrade() -> None:
    op.execute(f"DROP TRIGGER IF EXISTS {_TABLE}_immutable_delete")
    op.execute(f"DROP TRIGGER IF EXISTS {_TABLE}_immutable_update")
    op.drop_table(_TABLE)
