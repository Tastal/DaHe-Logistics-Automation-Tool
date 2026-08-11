"""Block replace-style overwrites of append-only Loop 7 authorities.

Revision ID: 0013_loop7_authority_insert_guards
Revises: 0012_loop7_development_authority
"""

from __future__ import annotations

from alembic import op

revision = "0013_loop7_authority_insert_guards"
down_revision = "0012_loop7_development_authority"
branch_labels = None
depends_on = None

_TABLES = (
    "locked_set_candidate_review_source_authority",
    "locked_set_development_authority",
)


def upgrade() -> None:
    for table in _TABLES:
        op.execute(
            f"""
            CREATE TRIGGER {table}_immutable_insert
            BEFORE INSERT ON {table}
            WHEN EXISTS (
                SELECT 1
                FROM {table}
                WHERE dataset_id = NEW.dataset_id
            )
            BEGIN
                SELECT RAISE(ABORT, '{table} is append-only');
            END
            """
        )


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.execute(
            f"DROP TRIGGER IF EXISTS {table}_immutable_insert"
        )
