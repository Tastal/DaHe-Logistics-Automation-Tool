"""Add non-secret metadata for the Windows platform credential.

Revision ID: 0027_platform_credentials
Revises: 0026_business_connection_session
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0027_platform_credentials"
down_revision = "0026_business_connection_session"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "platform_credential_config",
        sa.Column("config_id", sa.Integer(), primary_key=True),
        sa.Column("credential_reference", sa.String(100), nullable=False),
        sa.Column("configured", sa.Integer(), nullable=False),
        sa.Column("masked_username", sa.String(520)),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "config_id = 1 AND configured IN (0, 1) "
            "AND record_version >= 0 "
            "AND ((configured = 0 AND masked_username IS NULL) "
            "OR (configured = 1 AND masked_username IS NOT NULL))",
            name="ck_platform_credential_config_shape",
        ),
    )
    op.bulk_insert(
        sa.table(
            "platform_credential_config",
            sa.column("config_id", sa.Integer()),
            sa.column("credential_reference", sa.String()),
            sa.column("configured", sa.Integer()),
            sa.column("masked_username", sa.String()),
            sa.column("record_version", sa.Integer()),
            sa.column("updated_at", sa.String()),
        ),
        [
            {
                "config_id": 1,
                "credential_reference": "DaHeLogistics/Chengfeng/Primary",
                "configured": 0,
                "masked_username": None,
                "record_version": 0,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        ],
    )
    op.create_table(
        "platform_credential_idempotency",
        sa.Column("operation", sa.String(20), primary_key=True),
        sa.Column("idempotency_key", sa.String(200), primary_key=True),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("result_record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "operation IN ('save', 'delete') "
            "AND length(request_fingerprint) = 64 "
            "AND result_record_version >= 1",
            name="ck_platform_credential_idempotency_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("platform_credential_idempotency")
    op.drop_table("platform_credential_config")
