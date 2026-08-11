"""Add the append-only Loop 9 formal selection lifecycle anchor.

Revision ID: 0022_loop9_selection_lifecycle
Revises: 0021_loop9_settlement_selection_state
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022_loop9_selection_lifecycle"
down_revision = "0021_loop9_settlement_selection_state"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "loop9_formal_selection_lifecycle_anchors",
        sa.Column("target_kind", sa.String(32), primary_key=True),
        sa.Column("sequence", sa.Integer(), primary_key=True),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("event_kind", sa.String(16), nullable=False),
        sa.Column("node_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "previous_head_sha256",
            sa.String(64),
            sa.ForeignKey(
                "loop9_formal_selection_lifecycle_anchors.node_sha256",
                ondelete="RESTRICT",
            ),
            unique=True,
        ),
        sa.Column("selection_sha256", sa.String(64), nullable=False),
        sa.Column("predecessor_selection_sha256", sa.String(64)),
        sa.Column("failure_attestation_sha256", sa.String(64)),
        sa.Column("exclusion_inventory_sha256", sa.String(64)),
        sa.Column(
            "exclusion_authority_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "exclusion_child_head_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("source_build_sha256", sa.String(64), nullable=False),
        sa.Column("pipeline_fingerprint", sa.String(64), nullable=False),
        sa.Column("identity_context_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "target_kind = 'current_locked_50' "
            "AND sequence >= 1 "
            "AND generation >= 1 "
            "AND event_kind IN ('activated', 'invalidated') "
            "AND length(node_sha256) = 64 "
            "AND length(selection_sha256) = 64 "
            "AND length(exclusion_authority_sha256) = 64 "
            "AND length(exclusion_child_head_sha256) = 64 "
            "AND length(source_build_sha256) = 64 "
            "AND length(pipeline_fingerprint) = 64 "
            "AND length(identity_context_sha256) = 64 "
            "AND ((sequence = 1 "
            "AND generation = 1 "
            "AND event_kind = 'activated' "
            "AND previous_head_sha256 IS NULL "
            "AND predecessor_selection_sha256 IS NULL "
            "AND failure_attestation_sha256 IS NULL "
            "AND exclusion_inventory_sha256 IS NULL) "
            "OR (sequence > 1 "
            "AND previous_head_sha256 IS NOT NULL)) "
            "AND ((event_kind = 'activated' "
            "AND failure_attestation_sha256 IS NULL "
            "AND exclusion_inventory_sha256 IS NULL "
            "AND (generation = 1 "
            "OR predecessor_selection_sha256 IS NOT NULL)) "
            "OR (event_kind = 'invalidated' "
            "AND predecessor_selection_sha256 IS NULL "
            "AND failure_attestation_sha256 IS NOT NULL "
            "AND exclusion_inventory_sha256 IS NOT NULL))",
            name="ck_loop9_formal_selection_lifecycle_anchor_shape",
        ),
    )
    op.execute(
        """
        CREATE TRIGGER trg_loop9_formal_selection_lifecycle_no_update
        BEFORE UPDATE ON loop9_formal_selection_lifecycle_anchors
        BEGIN
          SELECT RAISE(
            ABORT,
            'Loop 9 formal selection lifecycle anchors are immutable'
          );
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_loop9_formal_selection_lifecycle_no_delete
        BEFORE DELETE ON loop9_formal_selection_lifecycle_anchors
        BEGIN
          SELECT RAISE(
            ABORT,
            'Loop 9 formal selection lifecycle anchors are immutable'
          );
        END
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_loop9_formal_selection_lifecycle_no_delete"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_loop9_formal_selection_lifecycle_no_update"
    )
    op.drop_table("loop9_formal_selection_lifecycle_anchors")
