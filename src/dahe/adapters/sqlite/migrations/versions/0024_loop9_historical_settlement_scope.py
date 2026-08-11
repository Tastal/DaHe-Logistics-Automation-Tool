"""Allow the bounded historical source for the Loop 9 locked set.

Revision ID: 0024_loop9_historical_settlement_scope
Revises: 0023_loop9_daily_access_rollover
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0024_loop9_historical_settlement_scope"
down_revision = "0023_loop9_daily_access_rollover"
branch_labels = None
depends_on = None

_IDENTITY_BACKUP_TABLE = "_loop9_0024_settlement_capture_identities"

_STATE_CHECK = (
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

_CURRENT_CHECK = (
    "scope = 'current' AND page_size = 50 " + _STATE_CHECK
)
_HISTORICAL_CHECK = (
    "((scope = 'current' AND page_size = 50) "
    "OR (scope = 'settled_history' AND page_size = 100)) "
    + _STATE_CHECK
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


def _replace_check(expression: str) -> None:
    _detach_identity_children()
    with op.batch_alter_table(
        "settlement_capture_invocations",
        recreate="always",
    ) as batch:
        batch.drop_constraint(
            "ck_settlement_capture_invocation_shape",
            type_="check",
        )
        batch.create_check_constraint(
            "ck_settlement_capture_invocation_shape",
            expression,
        )
    _restore_identity_children()


def upgrade() -> None:
    _replace_check(_HISTORICAL_CHECK)


def downgrade() -> None:
    _replace_check(_CURRENT_CHECK)
