"""Add durable, identity-free Loop 9 platform access windows.

Revision ID: 0015_loop9_platform_access
Revises: 0014_loop8_offline_audit
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0015_loop9_platform_access"
down_revision = "0014_loop8_offline_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "platform_access_windows",
        sa.Column("access_window_id", sa.String(32), primary_key=True),
        sa.Column("purpose", sa.String(40), nullable=False),
        sa.Column("job_id", sa.String(100), nullable=False),
        sa.Column("session_id", sa.String(100), nullable=False),
        sa.Column("build_sha256", sa.String(64), nullable=False),
        sa.Column("token_digest", sa.String(64), nullable=False),
        sa.Column("issued_at", sa.String(40), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("consumed_at", sa.String(40)),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('contract_discovery', 'formal_locked_set', "
            "'production_shadow') AND record_version >= 1 "
            "AND length(build_sha256) = 64 "
            "AND length(token_digest) = 64 "
            "AND length(request_hash) = 64",
            name="ck_platform_access_window_shape",
        ),
    )
    op.create_index(
        "ix_platform_access_windows_session",
        "platform_access_windows",
        ["session_id", "expires_at"],
    )
    op.create_table(
        "platform_access_events",
        sa.Column("event_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "access_window_id",
            sa.String(32),
            sa.ForeignKey(
                "platform_access_windows.access_window_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(60), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "event_type IN ('issued', 'consumed') AND record_version >= 1",
            name="ck_platform_access_event_shape",
        ),
    )
    op.create_table(
        "platform_control_idempotency",
        sa.Column("operation", sa.String(80), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("session_id", sa.String(100), nullable=False),
        sa.Column("access_window_id", sa.String(32), nullable=False),
        sa.Column("result_record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.PrimaryKeyConstraint(
            "operation",
            "idempotency_key",
            name="pk_platform_control_idempotency",
        ),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND result_record_version >= 1",
            name="ck_platform_control_idempotency_shape",
        ),
    )
    for action in ("UPDATE", "DELETE"):
        op.execute(
            f"""
            CREATE TRIGGER platform_access_events_immutable_{action.lower()}
            BEFORE {action} ON platform_access_events
            BEGIN
                SELECT RAISE(ABORT, 'platform_access_events is append-only');
            END
            """
        )


def downgrade() -> None:
    for action in ("delete", "update"):
        op.execute(
            f"DROP TRIGGER IF EXISTS platform_access_events_immutable_{action}"
        )
    op.drop_table("platform_control_idempotency")
    op.drop_table("platform_access_events")
    op.drop_index(
        "ix_platform_access_windows_session",
        table_name="platform_access_windows",
    )
    op.drop_table("platform_access_windows")
