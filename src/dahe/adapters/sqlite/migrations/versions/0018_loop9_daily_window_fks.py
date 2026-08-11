"""Bind Loop 9 daily work to an existing platform access window.

Revision ID: 0018_loop9_daily_window_fks
Revises: 0017_loop9_daily_start_idempotency
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0018_loop9_daily_window_fks"
down_revision = "0017_loop9_daily_start_idempotency"
branch_labels = None
depends_on = None

_TABLES = (
    (
        "daily_capture_invocations",
        "fk_daily_capture_invocations_access_window",
    ),
    (
        "daily_capture_start_requests",
        "fk_daily_capture_start_requests_access_window",
    ),
)


def _reject_orphaned_bindings() -> None:
    connection = op.get_bind()
    for table_name, _ in _TABLES:
        orphan_count = connection.execute(
            sa.text(
                f"""
                SELECT COUNT(*)
                FROM {table_name} AS daily
                LEFT JOIN platform_access_windows AS access
                  ON access.access_window_id = daily.access_window_id
                WHERE access.access_window_id IS NULL
                """
            )
        ).scalar_one()
        if int(orphan_count) != 0:
            raise RuntimeError(
                f"{table_name} contains orphaned platform access bindings"
            )


def upgrade() -> None:
    _reject_orphaned_bindings()
    for table_name, constraint_name in _TABLES:
        with op.batch_alter_table(
            table_name,
            recreate="always",
        ) as batch:
            batch.alter_column(
                "access_window_id",
                existing_type=sa.String(100),
                type_=sa.String(32),
                existing_nullable=False,
            )
            batch.create_foreign_key(
                constraint_name,
                "platform_access_windows",
                ["access_window_id"],
                ["access_window_id"],
                ondelete="RESTRICT",
            )


def downgrade() -> None:
    for table_name, constraint_name in reversed(_TABLES):
        with op.batch_alter_table(
            table_name,
            recreate="always",
        ) as batch:
            batch.drop_constraint(
                constraint_name,
                type_="foreignkey",
            )
            batch.alter_column(
                "access_window_id",
                existing_type=sa.String(32),
                type_=sa.String(100),
                existing_nullable=False,
            )
