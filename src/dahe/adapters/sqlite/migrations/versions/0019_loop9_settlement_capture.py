"""Add protected Loop 9 settlement capture authorities.

Revision ID: 0019_loop9_settlement_capture
Revises: 0018_loop9_daily_window_fks
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0019_loop9_settlement_capture"
down_revision = "0018_loop9_daily_window_fks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "settlement_capture_invocations",
        sa.Column("invocation_id", sa.String(32), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "access_window_id",
            sa.String(32),
            sa.ForeignKey(
                "platform_access_windows.access_window_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
            unique=True,
        ),
        sa.Column("scope", sa.String(20), nullable=False),
        sa.Column("page_size", sa.Integer(), nullable=False),
        sa.Column("source_build_sha256", sa.String(64), nullable=False),
        sa.Column(
            "contract_canonical_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("contract_file_sha256", sa.String(64), nullable=False),
        sa.Column(
            "contract_selection_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("identity_context_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("manifest_json", sa.Text()),
        sa.Column("diagnostic_code", sa.String(100)),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "scope = 'current' AND page_size = 50 "
            "AND status IN ('collecting', 'sealed', 'failed') "
            "AND record_version >= 1 "
            "AND length(source_build_sha256) = 64 "
            "AND length(contract_canonical_sha256) = 64 "
            "AND length(contract_file_sha256) = 64 "
            "AND length(contract_selection_sha256) = 64 "
            "AND length(identity_context_sha256) = 64 "
            "AND ((status = 'sealed' "
            "AND manifest_sha256 IS NOT NULL "
            "AND manifest_json IS NOT NULL "
            "AND diagnostic_code IS NULL) "
            "OR (status = 'collecting' "
            "AND manifest_sha256 IS NULL "
            "AND manifest_json IS NULL "
            "AND diagnostic_code IS NULL) "
            "OR (status = 'failed' "
            "AND manifest_sha256 IS NULL "
            "AND manifest_json IS NULL "
            "AND diagnostic_code IS NOT NULL))",
            name="ck_settlement_capture_invocation_shape",
        ),
    )
    op.create_index(
        "ix_settlement_capture_invocation_status",
        "settlement_capture_invocations",
        ["status", "created_at"],
    )

    op.create_table(
        "settlement_capture_identities",
        sa.Column(
            "invocation_id",
            sa.String(32),
            sa.ForeignKey(
                "settlement_capture_invocations.invocation_id",
                ondelete="RESTRICT",
            ),
            primary_key=True,
        ),
        sa.Column(
            "item_identity_sha256",
            sa.String(64),
            primary_key=True,
        ),
        sa.Column("platform_waybill_id", sa.String(500), nullable=False),
        sa.Column("waybill_number", sa.String(500), nullable=False),
        sa.Column("vehicle_number", sa.String(500)),
        sa.Column("source_page_number", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.UniqueConstraint(
            "invocation_id",
            "platform_waybill_id",
            name="uq_settlement_capture_platform_identity",
        ),
        sa.UniqueConstraint(
            "invocation_id",
            "waybill_number",
            name="uq_settlement_capture_waybill_identity",
        ),
        sa.CheckConstraint(
            "length(item_identity_sha256) = 64 "
            "AND source_page_number >= 1",
            name="ck_settlement_capture_identity_shape",
        ),
    )
    op.create_index(
        "ix_settlement_capture_identity_item",
        "settlement_capture_identities",
        ["item_identity_sha256"],
    )
    for action in ("UPDATE", "DELETE"):
        op.execute(
            f"""
            CREATE TRIGGER settlement_capture_identities_immutable_{action.lower()}
            BEFORE {action} ON settlement_capture_identities
            BEGIN
                SELECT RAISE(
                    ABORT,
                    'settlement_capture_identities is append-only'
                );
            END
            """
        )


def downgrade() -> None:
    for action in ("delete", "update"):
        op.execute(
            "DROP TRIGGER IF EXISTS "
            f"settlement_capture_identities_immutable_{action}"
        )
    op.drop_index(
        "ix_settlement_capture_identity_item",
        table_name="settlement_capture_identities",
    )
    op.drop_table("settlement_capture_identities")
    op.drop_index(
        "ix_settlement_capture_invocation_status",
        table_name="settlement_capture_invocations",
    )
    op.drop_table("settlement_capture_invocations")
