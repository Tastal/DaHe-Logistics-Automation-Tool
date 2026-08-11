"""Add immutable candidate-review source authority.

Revision ID: 0008_loop7_review_authority
Revises: 0007_loop7_locked_set_review
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0008_loop7_review_authority"
down_revision = "0007_loop7_locked_set_review"
branch_labels = None
depends_on = None

_TABLE = "locked_set_candidate_review_source_authority"
_SHA256_COLUMNS = (
    "manifest_sha256",
    "seal_sha256",
    "package_sha256",
    "record_set_sha256",
    "review_history_authority_sha256",
    "source_authority_sha256",
)


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column(
            "dataset_id",
            sa.String(200),
            sa.ForeignKey(
                "locked_set_datasets.dataset_id",
                ondelete="RESTRICT",
            ),
            primary_key=True,
        ),
        *(sa.Column(column, sa.String(64), nullable=False) for column in _SHA256_COLUMNS),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            " AND ".join(
                f"length({column}) = 64 "
                f"AND {column} = lower({column}) "
                f"AND {column} NOT GLOB '*[^0-9a-f]*'"
                for column in _SHA256_COLUMNS
            ),
            name="ck_locked_set_candidate_review_source_authority_hashes",
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
