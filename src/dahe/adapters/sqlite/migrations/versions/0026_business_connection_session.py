"""Add the working-day operational browser session.

Revision ID: 0026_business_connection_session
Revises: 0025_operational_compat_capture
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026_business_connection_session"
down_revision = "0025_operational_compat_capture"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "business_connection_sessions",
        sa.Column("business_session_id", sa.String(32), primary_key=True),
        sa.Column("platform_session_id", sa.String(100), nullable=False),
        sa.Column("build_sha256", sa.String(64), nullable=False),
        sa.Column(
            "login_access_window_id",
            sa.String(32),
            sa.ForeignKey(
                "platform_access_windows.access_window_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
            unique=True,
        ),
        sa.Column("confirmation_sha256", sa.String(64), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("expires_at", sa.String(40), nullable=False),
        sa.Column("closed_at", sa.String(40)),
        sa.Column("close_reason", sa.String(40)),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "status IN ('active', 'closed') "
            "AND record_version >= 1 "
            "AND length(build_sha256) = 64 "
            "AND length(confirmation_sha256) = 64 "
            "AND ((status = 'active' AND closed_at IS NULL "
            "AND close_reason IS NULL) OR (status = 'closed' "
            "AND closed_at IS NOT NULL AND close_reason IN "
            "('explicit', 'expired', 'browser_closed', 'shutdown')))",
            name="ck_business_connection_session_shape",
        ),
    )
    op.create_index(
        "ix_business_connection_session_platform",
        "business_connection_sessions",
        ["platform_session_id", "created_at"],
    )
    op.create_table(
        "business_connection_reads",
        sa.Column(
            "business_session_id",
            sa.String(32),
            sa.ForeignKey(
                "business_connection_sessions.business_session_id",
                ondelete="RESTRICT",
            ),
            primary_key=True,
        ),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="RESTRICT"),
            primary_key=True,
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
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "business_connection_idempotency",
        sa.Column("operation", sa.String(80), primary_key=True),
        sa.Column("idempotency_key", sa.String(200), primary_key=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column(
            "business_session_id",
            sa.String(32),
            sa.ForeignKey(
                "business_connection_sessions.business_session_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("result_record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND result_record_version >= 1",
            name="ck_business_connection_idempotency_shape",
        ),
    )


def downgrade() -> None:
    op.drop_table("business_connection_idempotency")
    op.drop_table("business_connection_reads")
    op.drop_index(
        "ix_business_connection_session_platform",
        table_name="business_connection_sessions",
    )
    op.drop_table("business_connection_sessions")
