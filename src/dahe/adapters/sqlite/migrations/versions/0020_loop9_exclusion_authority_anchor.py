"""Add the append-only Loop 9 exclusion authority anchor.

Revision ID: 0020_loop9_exclusion_authority_anchor
Revises: 0019_loop9_settlement_capture
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0020_loop9_exclusion_authority_anchor"
down_revision = "0019_loop9_settlement_capture"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "loop9_exclusion_authority_anchors",
        sa.Column("sequence", sa.Integer(), primary_key=True),
        sa.Column("node_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "previous_head_sha256",
            sa.String(64),
            sa.ForeignKey(
                "loop9_exclusion_authority_anchors.node_sha256",
                ondelete="RESTRICT",
            ),
            unique=True,
        ),
        sa.Column(
            "source_boundary_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "source_inventory_high_watermark",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "identity_context_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_current_build_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_settlement_contract_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_daily_contract_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_settlement_selection_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_daily_selection_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "child_inventory_sha256",
            sa.String(64),
            nullable=False,
            unique=True,
        ),
        sa.Column("child_exclusion_kind", sa.String(32), nullable=False),
        sa.Column(
            "child_platform_identity_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("child_image_count", sa.Integer(), nullable=False),
        sa.Column(
            "child_scope_exclusion_token_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "child_perceptual_fingerprint_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "sequence >= 1 "
            "AND source_inventory_high_watermark >= 1 "
            "AND child_platform_identity_count >= 0 "
            "AND child_image_count >= 0 "
            "AND child_scope_exclusion_token_count >= 0 "
            "AND child_perceptual_fingerprint_count = child_image_count "
            "AND child_exclusion_kind IN ('development', 'legacy_loop7') "
            "AND (child_image_count >= 1 "
            "OR child_exclusion_kind = 'development') "
            "AND (child_platform_identity_count + child_image_count "
            "+ child_scope_exclusion_token_count >= 1) "
            "AND ((sequence = 1 AND previous_head_sha256 IS NULL) "
            "OR (sequence > 1 AND previous_head_sha256 IS NOT NULL)) "
            "AND length(node_sha256) = 64 "
            "AND length(source_boundary_sha256) = 64 "
            "AND length(identity_context_sha256) = 64 "
            "AND length(expected_current_build_sha256) = 64 "
            "AND length(expected_settlement_contract_sha256) = 64 "
            "AND length(expected_daily_contract_sha256) = 64 "
            "AND length(expected_settlement_selection_sha256) = 64 "
            "AND length(expected_daily_selection_sha256) = 64 "
            "AND length(child_inventory_sha256) = 64",
            name="ck_loop9_exclusion_authority_anchor_shape",
        ),
    )
    op.execute(
        """
        CREATE TRIGGER trg_loop9_exclusion_authority_anchor_no_update
        BEFORE UPDATE ON loop9_exclusion_authority_anchors
        BEGIN
          SELECT RAISE(ABORT, 'Loop 9 exclusion authority anchors are immutable');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_loop9_exclusion_authority_anchor_no_delete
        BEFORE DELETE ON loop9_exclusion_authority_anchors
        BEGIN
          SELECT RAISE(ABORT, 'Loop 9 exclusion authority anchors are immutable');
        END
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_loop9_exclusion_authority_anchor_no_delete"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_loop9_exclusion_authority_anchor_no_update"
    )
    op.drop_table("loop9_exclusion_authority_anchors")
