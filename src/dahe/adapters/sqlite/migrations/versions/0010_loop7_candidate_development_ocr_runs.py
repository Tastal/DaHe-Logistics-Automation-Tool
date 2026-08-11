"""Add append-only completed candidate OCR run authority.

Revision ID: 0010_loop7_candidate_development_ocr_runs
Revises: 0009_loop7_template_reference_origin
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0010_loop7_candidate_development_ocr_runs"
down_revision = "0009_loop7_template_reference_origin"
branch_labels = None
depends_on = None

_TABLE = "candidate_development_ocr_runs"
_SHA256_COLUMNS = (
    "evidence_sha256",
    "evidence_blob_sha256",
    "package_sha256",
    "review_history_authority_sha256",
    "source_authority_sha256",
    "application_build_sha256",
    "composition_evidence_sha256",
    "runtime_set_sha256",
    "pipeline_contract_sha256",
    "authority_sha256",
)


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "evidence_sha256",
            sa.String(64),
            primary_key=True,
        ),
        sa.Column(
            "evidence_blob_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "evidence_relative_path",
            sa.String(500),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "evidence_byte_size",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("package_sha256", sa.String(64), nullable=False),
        sa.Column(
            "review_history_authority_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "source_authority_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("reviewer_id", sa.String(200), nullable=False),
        sa.Column(
            "application_build_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "composition_evidence_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "runtime_set_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "pipeline_contract_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "completion_status",
            sa.String(50),
            nullable=False,
        ),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.Column("authority_payload_json", sa.Text(), nullable=False),
        sa.Column("authority_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "evidence_byte_size > 0",
            name="ck_candidate_development_ocr_runs_byte_size",
        ),
        sa.CheckConstraint(
            "completion_status IN ("
            "'completed', "
            "'completed_with_runtime_differences'"
            ")",
            name="ck_candidate_development_ocr_runs_status",
        ),
        sa.CheckConstraint(
            " AND ".join(
                f"length({column}) = 64 "
                f"AND {column} = lower({column}) "
                f"AND {column} NOT GLOB '*[^0-9a-f]*'"
                for column in _SHA256_COLUMNS
            ),
            name="ck_candidate_development_ocr_runs_hashes",
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
