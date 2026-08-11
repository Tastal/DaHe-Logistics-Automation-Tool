"""Persist exact credential idempotency responses without secrets.

Revision ID: 0030_credential_results
Revises: 0029_daily_batch_ocr
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0030_credential_results"
down_revision = "0029_daily_batch_ocr"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("platform_credential_idempotency") as batch:
        batch.add_column(sa.Column("result_configured", sa.Integer()))
        batch.add_column(sa.Column("result_masked_username", sa.String(520)))


def downgrade() -> None:
    with op.batch_alter_table("platform_credential_idempotency") as batch:
        batch.drop_column("result_masked_username")
        batch.drop_column("result_configured")
