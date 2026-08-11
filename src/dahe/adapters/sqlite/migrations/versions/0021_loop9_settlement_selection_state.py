"""Add crash-safe Loop 9 settlement selection state.

Revision ID: 0021_loop9_settlement_selection_state
Revises: 0020_loop9_exclusion_authority_anchor
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0021_loop9_settlement_selection_state"
down_revision = "0020_loop9_exclusion_authority_anchor"
branch_labels = None
depends_on = None

_IDENTITY_BACKUP_TABLE = "_loop9_0021_settlement_capture_identities"


_CHECK = (
    "scope = 'current' AND page_size = 50 "
    "AND status IN ("
    "'collecting', 'sealed', 'selected', 'selection_blocked', 'failed'"
    ") "
    "AND record_version >= 1 "
    "AND length(source_build_sha256) = 64 "
    "AND length(contract_canonical_sha256) = 64 "
    "AND length(contract_file_sha256) = 64 "
    "AND length(contract_selection_sha256) = 64 "
    "AND length(identity_context_sha256) = 64 "
    "AND ((status = 'selected' "
    "AND manifest_sha256 IS NOT NULL "
    "AND manifest_json IS NOT NULL "
    "AND selection_manifest_sha256 IS NOT NULL "
    "AND batch_manifest_sha256 IS NOT NULL "
    "AND diagnostic_code IS NULL) "
    "OR (status = 'sealed' "
    "AND manifest_sha256 IS NOT NULL "
    "AND manifest_json IS NOT NULL "
    "AND selection_manifest_sha256 IS NULL "
    "AND batch_manifest_sha256 IS NULL "
    "AND diagnostic_code IS NULL) "
    "OR (status = 'selection_blocked' "
    "AND manifest_sha256 IS NOT NULL "
    "AND manifest_json IS NOT NULL "
    "AND selection_manifest_sha256 IS NULL "
    "AND batch_manifest_sha256 IS NULL "
    "AND diagnostic_code IS NOT NULL) "
    "OR (status = 'collecting' "
    "AND manifest_sha256 IS NULL "
    "AND manifest_json IS NULL "
    "AND selection_manifest_sha256 IS NULL "
    "AND batch_manifest_sha256 IS NULL "
    "AND diagnostic_code IS NULL) "
    "OR (status = 'failed' "
    "AND manifest_sha256 IS NULL "
    "AND manifest_json IS NULL "
    "AND selection_manifest_sha256 IS NULL "
    "AND batch_manifest_sha256 IS NULL "
    "AND diagnostic_code IS NOT NULL))"
)


def _detach_identity_children() -> None:
    op.execute(
        f"""
        CREATE TABLE {_IDENTITY_BACKUP_TABLE} AS
        SELECT
            invocation_id,
            item_identity_sha256,
            platform_waybill_id,
            waybill_number,
            vehicle_number,
            source_page_number,
            created_at
        FROM settlement_capture_identities
        """
    )
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


def _restore_identity_children() -> None:
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
    op.execute(
        f"""
        INSERT INTO settlement_capture_identities (
            invocation_id,
            item_identity_sha256,
            platform_waybill_id,
            waybill_number,
            vehicle_number,
            source_page_number,
            created_at
        )
        SELECT
            invocation_id,
            item_identity_sha256,
            platform_waybill_id,
            waybill_number,
            vehicle_number,
            source_page_number,
            created_at
        FROM {_IDENTITY_BACKUP_TABLE}
        """
    )
    op.drop_table(_IDENTITY_BACKUP_TABLE)
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


def upgrade() -> None:
    # Alembic recreates the parent table on SQLite. Preserve and temporarily
    # detach its append-only children so populated databases can be upgraded
    # without disabling foreign-key enforcement.
    _detach_identity_children()
    with op.batch_alter_table(
        "settlement_capture_invocations",
        recreate="always",
    ) as batch:
        batch.add_column(
            sa.Column(
                "selection_manifest_sha256",
                sa.String(64),
                nullable=True,
            )
        )
        batch.add_column(
            sa.Column(
                "batch_manifest_sha256",
                sa.String(64),
                nullable=True,
            )
        )
        batch.drop_constraint(
            "ck_settlement_capture_invocation_shape",
            type_="check",
        )
        batch.create_check_constraint(
            "ck_settlement_capture_invocation_shape",
            _CHECK,
        )
    _restore_identity_children()


def downgrade() -> None:
    _detach_identity_children()
    with op.batch_alter_table(
        "settlement_capture_invocations",
        recreate="always",
    ) as batch:
        batch.drop_constraint(
            "ck_settlement_capture_invocation_shape",
            type_="check",
        )
        batch.drop_column("batch_manifest_sha256")
        batch.drop_column("selection_manifest_sha256")
        batch.create_check_constraint(
            "ck_settlement_capture_invocation_shape",
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
        )
    _restore_identity_children()
