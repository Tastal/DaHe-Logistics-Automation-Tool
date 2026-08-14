"""Scope Chengfeng platform data by contract subject.

Revision ID: 0041_contract_subject_scope
Revises: 0040_whole_run_capture
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import sqlalchemy as sa
from alembic import op

revision = "0041_contract_subject_scope"
down_revision = "0040_whole_run_capture"
branch_labels = None
depends_on = None

_SHANXI = "shanxi_guienbo"
_SUBJECT_CHECK = "contract_subject_code IN ('shanxi_guienbo', 'shanghai_jinyisheng')"


def _subject_column() -> sa.Column[str]:
    return sa.Column(
        "contract_subject_code",
        sa.String(length=40),
        nullable=False,
        server_default=_SHANXI,
    )


def upgrade() -> None:
    op.create_table(
        "platform_contract_subject_state",
        sa.Column("state_id", sa.String(length=32), primary_key=True),
        sa.Column("current_subject_code", sa.String(length=40), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "state_id = 'primary' AND current_subject_code IN "
            "('shanxi_guienbo', 'shanghai_jinyisheng') AND record_version >= 1",
            name="ck_platform_contract_subject_state_shape",
        ),
    )
    op.execute(
        sa.text(
            "INSERT INTO platform_contract_subject_state "
            "(state_id, current_subject_code, record_version, updated_at) "
            "VALUES ('primary', :subject, 1, :updated_at)"
        ).bindparams(
            subject=_SHANXI,
            updated_at=datetime.now(UTC).isoformat(),
        )
    )
    op.create_table(
        "platform_job_subjects",
        sa.Column(
            "job_id",
            sa.String(length=32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("contract_subject_code", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            _SUBJECT_CHECK,
            name="ck_platform_job_subject_value",
        ),
    )

    for table_name in (
        "operational_capture_runs",
        "settlement_capture_invocations",
        "daily_capture_invocations",
        "daily_candidate_snapshots",
        "daily_observations",
    ):
        with op.batch_alter_table(table_name) as batch:
            batch.add_column(_subject_column())

    _scope_manual_revision_idempotency()
    _scope_report_idempotency()

    with op.batch_alter_table("daily_record_revisions") as batch:
        batch.add_column(_subject_column())
        batch.drop_constraint("uq_daily_record_revision_number", type_="unique")
        batch.create_unique_constraint(
            "uq_daily_record_revision_number",
            ["contract_subject_code", "platform_waybill_id", "revision_number"],
        )
    with op.batch_alter_table("daily_manual_revisions") as batch:
        batch.add_column(_subject_column())
        batch.drop_constraint("uq_daily_manual_revision_number", type_="unique")
        batch.create_unique_constraint(
            "uq_daily_manual_revision_number",
            [
                "contract_subject_code",
                "platform_waybill_id",
                "manual_revision_number",
            ],
        )
    _replace_daily_reports_scoped()

    _replace_operational_evidence_reuse()

    for table_name in (
        "daily_candidate_snapshots",
        "daily_observations",
        "daily_record_revisions",
    ):
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS {table_name}_immutable_{action.lower()}
                BEFORE {action} ON {table_name}
                BEGIN
                    SELECT RAISE(ABORT, '{table_name} is append-only');
                END
                """
            )

    now = datetime.now(UTC).isoformat().replace("'", "")
    op.execute(
        "INSERT INTO platform_job_subjects "
        "(job_id, contract_subject_code, created_at) "
        "SELECT job_id, 'shanxi_guienbo', '" + now + "' FROM settlement_capture_invocations "
        "UNION SELECT job_id, 'shanxi_guienbo', '" + now + "' FROM daily_capture_invocations"
    )


def _replace_operational_evidence_reuse() -> None:
    op.create_table(
        "operational_evidence_reuse_replacement",
        sa.Column("contract_subject_code", sa.String(length=40), primary_key=True),
        sa.Column("platform_waybill_id", sa.String(length=64), primary_key=True),
        sa.Column("source_revision_sha256", sa.String(length=64), nullable=False),
        sa.Column("loading_sha256", sa.String(length=64)),
        sa.Column("loading_media_type", sa.String(length=80)),
        sa.Column("loading_validator_sha256", sa.String(length=64)),
        sa.Column("unloading_sha256", sa.String(length=64)),
        sa.Column("unloading_media_type", sa.String(length=80)),
        sa.Column("unloading_validator_sha256", sa.String(length=64)),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            _SUBJECT_CHECK + " AND length(source_revision_sha256) = 64 "
            "AND ((loading_sha256 IS NULL AND loading_media_type IS NULL "
            "AND loading_validator_sha256 IS NULL) OR "
            "(length(loading_sha256) = 64 AND length(loading_media_type) > 0 "
            "AND length(loading_validator_sha256) = 64)) "
            "AND ((unloading_sha256 IS NULL AND unloading_media_type IS NULL "
            "AND unloading_validator_sha256 IS NULL) OR "
            "(length(unloading_sha256) = 64 AND length(unloading_media_type) > 0 "
            "AND length(unloading_validator_sha256) = 64))",
            name="ck_operational_evidence_reuse_shape",
        ),
    )
    op.execute(
        "INSERT INTO operational_evidence_reuse_replacement "
        "(contract_subject_code, platform_waybill_id, source_revision_sha256, "
        "loading_sha256, loading_media_type, loading_validator_sha256, "
        "unloading_sha256, unloading_media_type, unloading_validator_sha256, "
        "updated_at) SELECT 'shanxi_guienbo', platform_waybill_id, "
        "source_revision_sha256, loading_sha256, loading_media_type, "
        "loading_validator_sha256, unloading_sha256, unloading_media_type, "
        "unloading_validator_sha256, updated_at FROM operational_evidence_reuse"
    )
    op.drop_table("operational_evidence_reuse")
    op.rename_table(
        "operational_evidence_reuse_replacement",
        "operational_evidence_reuse",
    )


def _scope_manual_revision_idempotency() -> None:
    op.create_table(
        "daily_manual_revision_idempotency_replacement",
        sa.Column("idempotency_key", sa.String(length=200), primary_key=True),
        sa.Column("contract_subject_code", sa.String(length=40), primary_key=True),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("platform_waybill_id", sa.String(length=200), nullable=False),
        sa.Column("action_id", sa.String(length=32), nullable=False),
        sa.Column("result_record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND result_record_version >= 1",
            name="ck_daily_manual_revision_idempotency_shape",
        ),
    )
    op.execute(
        "INSERT INTO daily_manual_revision_idempotency_replacement "
        "(idempotency_key, contract_subject_code, request_hash, "
        "platform_waybill_id, action_id, result_record_version, created_at) "
        "SELECT idempotency_key, 'shanxi_guienbo', request_hash, "
        "platform_waybill_id, action_id, result_record_version, created_at "
        "FROM daily_manual_revision_idempotency"
    )
    op.drop_table("daily_manual_revision_idempotency")
    op.rename_table(
        "daily_manual_revision_idempotency_replacement",
        "daily_manual_revision_idempotency",
    )


def _scope_report_idempotency() -> None:
    op.create_table(
        "daily_report_idempotency_replacement",
        sa.Column("idempotency_key", sa.String(length=200), primary_key=True),
        sa.Column("contract_subject_code", sa.String(length=40), primary_key=True),
        sa.Column("operation", sa.String(length=40), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64",
            name="ck_daily_report_idempotency_shape",
        ),
    )
    op.execute(
        "INSERT INTO daily_report_idempotency_replacement "
        "(idempotency_key, contract_subject_code, operation, request_hash, "
        "result_json, created_at) SELECT idempotency_key, 'shanxi_guienbo', "
        "operation, request_hash, result_json, created_at "
        "FROM daily_report_idempotency"
    )
    op.drop_table("daily_report_idempotency")
    op.rename_table("daily_report_idempotency_replacement", "daily_report_idempotency")


def _daily_report_columns(*, scoped: bool) -> list[Any]:
    columns: list[Any] = [
        sa.Column("report_id", sa.String(length=32), primary_key=True),
        sa.Column("business_date", sa.String(length=10), nullable=False),
    ]
    if scoped:
        columns.append(
            sa.Column(
                "contract_subject_code",
                sa.String(length=40),
                nullable=False,
            )
        )
    columns.extend(
        [
            sa.Column("status", sa.String(length=32), nullable=False),
            sa.Column("settings_record_version", sa.Integer(), nullable=False),
            sa.Column("output_directory", sa.Text(), nullable=False),
            sa.Column("file_name", sa.String(length=255), nullable=False),
            sa.Column("file_sha256", sa.String(length=64), nullable=False),
            sa.Column("data_snapshot_sha256", sa.String(length=64), nullable=False),
            sa.Column("data_json", sa.Text(), nullable=False),
            sa.Column("row_count", sa.Integer(), nullable=False),
            sa.Column("loading_net_total", sa.String(length=50), nullable=False),
            sa.Column("record_version", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.String(length=40), nullable=False),
            sa.Column("confirmed_at", sa.String(length=40)),
            sa.Column("stale", sa.Integer(), nullable=False, server_default="0"),
            sa.CheckConstraint(
                "status IN ('pending_confirmation', 'confirmed') "
                "AND settings_record_version >= 1 AND row_count >= 0 "
                "AND record_version >= 1 AND length(file_sha256) = 64 "
                "AND length(data_snapshot_sha256) = 64 AND stale IN (0, 1)",
                name="ck_daily_report_shape",
            ),
        ]
    )
    return columns


def _replace_daily_reports_scoped() -> None:
    """Remove the legacy date-only uniqueness while assigning history to Shanxi."""

    op.create_table(
        "daily_reports_replacement",
        *_daily_report_columns(scoped=True),
    )
    op.execute(
        "INSERT INTO daily_reports_replacement ("
        "report_id, business_date, contract_subject_code, status, "
        "settings_record_version, output_directory, file_name, file_sha256, "
        "data_snapshot_sha256, data_json, row_count, loading_net_total, "
        "record_version, created_at, confirmed_at, stale) SELECT "
        "report_id, business_date, 'shanxi_guienbo', status, "
        "settings_record_version, output_directory, file_name, file_sha256, "
        "data_snapshot_sha256, data_json, row_count, loading_net_total, "
        "record_version, created_at, confirmed_at, stale FROM daily_reports"
    )
    op.drop_table("daily_reports")
    op.rename_table("daily_reports_replacement", "daily_reports")
    op.create_index("ix_daily_reports_business_date", "daily_reports", ["business_date"])
    op.create_index(
        "uq_daily_report_subject_business_date_current",
        "daily_reports",
        ["contract_subject_code", "business_date"],
        unique=True,
        sqlite_where=sa.text("stale = 0"),
    )


def _replace_daily_reports_legacy() -> None:
    op.create_table(
        "daily_reports_legacy",
        *_daily_report_columns(scoped=False),
    )
    columns = (
        "report_id, business_date, status, settings_record_version, "
        "output_directory, file_name, file_sha256, data_snapshot_sha256, "
        "data_json, row_count, loading_net_total, record_version, created_at, "
        "confirmed_at, stale"
    )
    op.execute(f"INSERT INTO daily_reports_legacy ({columns}) SELECT {columns} FROM daily_reports")
    op.drop_table("daily_reports")
    op.rename_table("daily_reports_legacy", "daily_reports")
    op.create_index("ix_daily_reports_business_date", "daily_reports", ["business_date"])


def downgrade() -> None:
    connection = op.get_bind()
    scoped_tables = (
        "platform_job_subjects",
        "operational_capture_runs",
        "settlement_capture_invocations",
        "daily_capture_invocations",
        "daily_candidate_snapshots",
        "daily_observations",
        "daily_record_revisions",
        "daily_manual_revisions",
        "daily_manual_revision_idempotency",
        "daily_reports",
        "daily_report_idempotency",
        "operational_evidence_reuse",
    )
    for table_name in scoped_tables:
        non_default = connection.execute(
            sa.text(f"SELECT 1 FROM {table_name} WHERE contract_subject_code <> :subject LIMIT 1"),
            {"subject": _SHANXI},
        ).first()
        if non_default is not None:
            raise RuntimeError(
                "contract-subject scoping cannot be downgraded after Shanghai data exists"
            )

    _downgrade_operational_evidence_reuse()

    _replace_daily_reports_legacy()
    with op.batch_alter_table("daily_manual_revisions") as batch:
        batch.drop_constraint("uq_daily_manual_revision_number", type_="unique")
        batch.create_unique_constraint(
            "uq_daily_manual_revision_number",
            ["platform_waybill_id", "manual_revision_number"],
        )
        batch.drop_column("contract_subject_code")
    with op.batch_alter_table("daily_record_revisions") as batch:
        batch.drop_constraint("uq_daily_record_revision_number", type_="unique")
        batch.create_unique_constraint(
            "uq_daily_record_revision_number",
            ["platform_waybill_id", "revision_number"],
        )
        batch.drop_column("contract_subject_code")

    _downgrade_manual_revision_idempotency()
    _downgrade_report_idempotency()

    # These subject columns are not part of table constraints. Use SQLite's
    # native DROP COLUMN so referenced parent tables are not rebuilt while
    # child rows still point at them.
    for table_name in reversed(
        (
            "operational_capture_runs",
            "settlement_capture_invocations",
            "daily_capture_invocations",
            "daily_candidate_snapshots",
            "daily_observations",
        )
    ):
        op.execute(f"ALTER TABLE {table_name} DROP COLUMN contract_subject_code")

    for table_name in (
        "daily_candidate_snapshots",
        "daily_observations",
        "daily_record_revisions",
    ):
        for action in ("UPDATE", "DELETE"):
            op.execute(
                f"""
                CREATE TRIGGER IF NOT EXISTS {table_name}_immutable_{action.lower()}
                BEFORE {action} ON {table_name}
                BEGIN
                    SELECT RAISE(ABORT, '{table_name} is append-only');
                END
                """
            )

    op.drop_table("platform_job_subjects")
    op.drop_table("platform_contract_subject_state")


def _downgrade_manual_revision_idempotency() -> None:
    op.create_table(
        "daily_manual_revision_idempotency_legacy",
        sa.Column("idempotency_key", sa.String(length=200), primary_key=True),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("platform_waybill_id", sa.String(length=200), nullable=False),
        sa.Column("action_id", sa.String(length=32), nullable=False),
        sa.Column("result_record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64 AND result_record_version >= 1",
            name="ck_daily_manual_revision_idempotency_shape",
        ),
    )
    op.execute(
        "INSERT INTO daily_manual_revision_idempotency_legacy "
        "(idempotency_key, request_hash, platform_waybill_id, action_id, "
        "result_record_version, created_at) SELECT idempotency_key, "
        "request_hash, platform_waybill_id, action_id, result_record_version, "
        "created_at FROM daily_manual_revision_idempotency"
    )
    op.drop_table("daily_manual_revision_idempotency")
    op.rename_table(
        "daily_manual_revision_idempotency_legacy",
        "daily_manual_revision_idempotency",
    )


def _downgrade_report_idempotency() -> None:
    op.create_table(
        "daily_report_idempotency_legacy",
        sa.Column("idempotency_key", sa.String(length=200), primary_key=True),
        sa.Column("operation", sa.String(length=40), nullable=False),
        sa.Column("request_hash", sa.String(length=64), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "length(request_hash) = 64",
            name="ck_daily_report_idempotency_shape",
        ),
    )
    op.execute(
        "INSERT INTO daily_report_idempotency_legacy "
        "(idempotency_key, operation, request_hash, result_json, created_at) "
        "SELECT idempotency_key, operation, request_hash, result_json, "
        "created_at FROM daily_report_idempotency"
    )
    op.drop_table("daily_report_idempotency")
    op.rename_table("daily_report_idempotency_legacy", "daily_report_idempotency")


def _downgrade_operational_evidence_reuse() -> None:
    op.create_table(
        "operational_evidence_reuse_legacy",
        sa.Column("platform_waybill_id", sa.String(length=64), primary_key=True),
        sa.Column("source_revision_sha256", sa.String(length=64), nullable=False),
        sa.Column("loading_sha256", sa.String(length=64)),
        sa.Column("loading_media_type", sa.String(length=80)),
        sa.Column("loading_validator_sha256", sa.String(length=64)),
        sa.Column("unloading_sha256", sa.String(length=64)),
        sa.Column("unloading_media_type", sa.String(length=80)),
        sa.Column("unloading_validator_sha256", sa.String(length=64)),
        sa.Column("updated_at", sa.String(length=40), nullable=False),
        sa.CheckConstraint(
            "length(source_revision_sha256) = 64 "
            "AND ((loading_sha256 IS NULL AND loading_media_type IS NULL "
            "AND loading_validator_sha256 IS NULL) OR "
            "(length(loading_sha256) = 64 AND length(loading_media_type) > 0 "
            "AND length(loading_validator_sha256) = 64)) "
            "AND ((unloading_sha256 IS NULL AND unloading_media_type IS NULL "
            "AND unloading_validator_sha256 IS NULL) OR "
            "(length(unloading_sha256) = 64 AND length(unloading_media_type) > 0 "
            "AND length(unloading_validator_sha256) = 64))",
            name="ck_operational_evidence_reuse_shape",
        ),
    )
    op.execute(
        "INSERT INTO operational_evidence_reuse_legacy "
        "(platform_waybill_id, source_revision_sha256, loading_sha256, "
        "loading_media_type, loading_validator_sha256, unloading_sha256, "
        "unloading_media_type, unloading_validator_sha256, updated_at) "
        "SELECT platform_waybill_id, source_revision_sha256, loading_sha256, "
        "loading_media_type, loading_validator_sha256, unloading_sha256, "
        "unloading_media_type, unloading_validator_sha256, updated_at "
        "FROM operational_evidence_reuse"
    )
    op.drop_table("operational_evidence_reuse")
    op.rename_table("operational_evidence_reuse_legacy", "operational_evidence_reuse")
