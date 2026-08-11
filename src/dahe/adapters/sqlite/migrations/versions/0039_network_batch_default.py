"""Select the verified operational network batch default.

Revision ID: 0039_network_batch_default
Revises: 0038_network_batches
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0039_network_batch_default"
down_revision = "0038_network_batches"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE performance_settings "
            "SET network_batch_size = 50, record_version = record_version + 1 "
            "WHERE settings_id = 'primary' AND network_batch_size = 20"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "UPDATE performance_settings "
            "SET network_batch_size = 20, record_version = record_version + 1 "
            "WHERE settings_id = 'primary' AND network_batch_size = 50"
        )
    )
