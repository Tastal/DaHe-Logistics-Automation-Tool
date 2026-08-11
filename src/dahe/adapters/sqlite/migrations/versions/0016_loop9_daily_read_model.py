"""Add immutable Loop 9 loading and unloading read records.

Revision ID: 0016_loop9_daily_read_model
Revises: 0015_loop9_platform_access
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0016_loop9_daily_read_model"
down_revision = "0015_loop9_platform_access"
branch_labels = None
depends_on = None

_IMMUTABLE_TABLES = (
    "daily_candidate_snapshots",
    "daily_observations",
    "daily_record_revisions",
)


def upgrade() -> None:
    op.create_table(
        "daily_capture_invocations",
        sa.Column("invocation_id", sa.String(100), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("access_window_id", sa.String(100), nullable=False),
        sa.Column("request_fingerprint", sa.String(64), nullable=False),
        sa.Column("request_json", sa.Text(), nullable=False),
        sa.Column("checkpoint_json", sa.Text()),
        sa.Column("next_stage", sa.String(100), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("diagnostic_code", sa.String(100)),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(request_fingerprint) = 64 "
            "AND record_version >= 1 "
            "AND status IN ('ready', 'running', 'succeeded', 'failed')",
            name="ck_daily_capture_invocation_shape",
        ),
    )
    op.create_index(
        "ix_daily_capture_invocations_access_window",
        "daily_capture_invocations",
        ["access_window_id"],
    )

    op.create_table(
        "daily_candidate_snapshots",
        sa.Column("snapshot_id", sa.String(100), primary_key=True),
        sa.Column("target_business_date", sa.String(10), nullable=False),
        sa.Column("query_started_at", sa.String(40), nullable=False),
        sa.Column("query_ended_at", sa.String(40), nullable=False),
        sa.Column("query_safety_ended_at", sa.String(40), nullable=False),
        sa.Column("source_contract_sha256", sa.String(64), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("captured_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "candidate_count >= 0 "
            "AND length(source_contract_sha256) = 64 "
            "AND length(fingerprint) = 64",
            name="ck_daily_candidate_snapshot_shape",
        ),
    )
    op.create_index(
        "ix_daily_candidate_snapshots_business_date",
        "daily_candidate_snapshots",
        ["target_business_date", "captured_at"],
    )

    op.create_table(
        "daily_observations",
        sa.Column("observation_id", sa.String(100), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.String(100),
            sa.ForeignKey(
                "daily_candidate_snapshots.snapshot_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("platform_waybill_id", sa.String(200), nullable=False),
        sa.Column("waybill_number", sa.String(200)),
        sa.Column("source_detail_sha256", sa.String(64), nullable=False),
        sa.Column("loading_ticket_sha256", sa.String(64)),
        sa.Column("unloading_ticket_sha256", sa.String(64)),
        sa.Column("field_fingerprint", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column(
            "observation_fingerprint",
            sa.String(64),
            nullable=False,
            unique=True,
        ),
        sa.Column("observed_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "length(source_detail_sha256) = 64 "
            "AND (loading_ticket_sha256 IS NULL "
            "OR length(loading_ticket_sha256) = 64) "
            "AND (unloading_ticket_sha256 IS NULL "
            "OR length(unloading_ticket_sha256) = 64) "
            "AND length(field_fingerprint) = 64 "
            "AND length(observation_fingerprint) = 64",
            name="ck_daily_observation_shape",
        ),
    )
    op.create_index(
        "ix_daily_observations_waybill",
        "daily_observations",
        ["platform_waybill_id", "observed_at"],
    )
    op.create_index(
        "ix_daily_observations_snapshot",
        "daily_observations",
        ["snapshot_id"],
    )

    op.create_table(
        "daily_record_revisions",
        sa.Column("revision_id", sa.String(32), primary_key=True),
        sa.Column("platform_waybill_id", sa.String(200), nullable=False),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column(
            "observation_id",
            sa.String(100),
            sa.ForeignKey(
                "daily_observations.observation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
            unique=True,
        ),
        sa.Column("field_fingerprint", sa.String(64), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.UniqueConstraint(
            "platform_waybill_id",
            "revision_number",
            name="uq_daily_record_revision_number",
        ),
        sa.CheckConstraint(
            "revision_number >= 1 AND length(field_fingerprint) = 64",
            name="ck_daily_record_revision_shape",
        ),
    )
    op.create_index(
        "ix_daily_record_revisions_waybill",
        "daily_record_revisions",
        ["platform_waybill_id", "revision_number"],
    )

    for table in _IMMUTABLE_TABLES:
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"""
                CREATE TRIGGER {table}_immutable_{action.lower()}
                BEFORE {action} ON {table}
                BEGIN
                    SELECT RAISE(ABORT, '{table} is append-only');
                END
                """
            )


def downgrade() -> None:
    for table in reversed(_IMMUTABLE_TABLES):
        for action in ("delete", "update"):
            op.execute(
                f"DROP TRIGGER IF EXISTS {table}_immutable_{action}"
            )
    op.drop_index(
        "ix_daily_record_revisions_waybill",
        table_name="daily_record_revisions",
    )
    op.drop_table("daily_record_revisions")
    op.drop_index(
        "ix_daily_observations_snapshot",
        table_name="daily_observations",
    )
    op.drop_index(
        "ix_daily_observations_waybill",
        table_name="daily_observations",
    )
    op.drop_table("daily_observations")
    op.drop_index(
        "ix_daily_candidate_snapshots_business_date",
        table_name="daily_candidate_snapshots",
    )
    op.drop_table("daily_candidate_snapshots")
    op.drop_index(
        "ix_daily_capture_invocations_access_window",
        table_name="daily_capture_invocations",
    )
    op.drop_table("daily_capture_invocations")
