"""Add the immutable formal development-authority binding.

Revision ID: 0012_loop7_development_authority
Revises: 0011_loop7_terminal_attempt_ledgers
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0012_loop7_development_authority"
down_revision = "0011_loop7_terminal_attempt_ledgers"
branch_labels = None
depends_on = None

_TABLE = "locked_set_development_authority"
_SHA256_COLUMNS = (
    "manifest_sha256",
    "authority_sha256",
    "source_exclusion_snapshot_sha256",
    "formal_exclusion_snapshot_sha256",
    "shadow_template_set_fingerprint",
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
        *(
            sa.Column(column, sa.String(64), nullable=False)
            for column in _SHA256_COLUMNS
        ),
        sa.Column(
            "source_inventory_high_watermark",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            " AND ".join(
                f"length({column}) = 64 "
                f"AND {column} = lower({column}) "
                f"AND {column} NOT GLOB '*[^0-9a-f]*'"
                for column in _SHA256_COLUMNS
            ),
            name="ck_locked_set_development_authority_hashes",
        ),
        sa.CheckConstraint(
            "source_inventory_high_watermark >= 1",
            name="ck_locked_set_development_authority_watermark",
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
