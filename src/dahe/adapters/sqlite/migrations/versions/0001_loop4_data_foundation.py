"""Create the durable Loop 4 data foundation.

Revision ID: 0001_loop4
Revises:
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0001_loop4"
down_revision = None
branch_labels = None
depends_on = None


def _create_task_tables() -> None:
    op.create_table(
        "system_meta",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.String(200), nullable=False),
    )
    op.create_table(
        "jobs",
        sa.Column("job_id", sa.String(32), primary_key=True),
        sa.Column("task_type", sa.String(32), nullable=False),
        sa.Column("scope_label", sa.String(200), nullable=False),
        sa.Column("scope_fixture_id", sa.String(100), nullable=False),
        sa.Column("scope_fingerprint", sa.String(64), nullable=False),
        sa.Column("run_mode", sa.String(20), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("current_stage", sa.String(100)),
        sa.Column("diagnostic_code", sa.String(100)),
        sa.Column("job_kind", sa.String(20), nullable=False, server_default="business"),
        sa.Column("conflict_key", sa.String(200)),
        sa.Column("created_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "work_items",
        sa.Column("work_item_id", sa.String(32), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("waybill_number", sa.String(100), nullable=False),
        sa.Column("vehicle_number", sa.String(100), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("current_stage", sa.String(100), nullable=False),
        sa.Column("business_outcome", sa.String(50)),
        sa.Column("platform_loading_net", sa.String(40)),
        sa.Column("platform_unloading_net", sa.String(40)),
        sa.Column("ticket_loading_net", sa.String(40)),
        sa.Column("ticket_unloading_net", sa.String(40)),
        sa.Column("decision", sa.String(50)),
        sa.Column("review_reason", sa.String(100)),
        sa.Column("item_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("end_reason", sa.String(50)),
        sa.Column("waiting_reason_kind", sa.String(30)),
        sa.Column("waiting_reason", sa.String(200)),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("diagnostic_code", sa.String(100)),
        sa.Column("loading_image_sha256", sa.String(64)),
        sa.Column("unloading_image_sha256", sa.String(64)),
        sa.Column("pipeline_fingerprint", sa.String(100)),
        sa.Column("fixture_outcome", sa.String(50)),
        sa.Column("fixture_review_reason", sa.String(100)),
        sa.Column("download_complete", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "loading_ocr_complete",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "unloading_ocr_complete",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
        sa.Column("ready_sequence", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_work_items_job_id", "work_items", ["job_id"])
    op.create_table(
        "idempotency_records",
        sa.Column("operation", sa.String(100), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.UniqueConstraint(
            "operation",
            "idempotency_key",
            name="uq_idempotency_operation_key",
        ),
    )
    op.create_table(
        "event_outbox",
        sa.Column("event_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("aggregate_type", sa.String(30), nullable=False),
        sa.Column("aggregate_id", sa.String(32), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "scheduler_meta",
        sa.Column("key", sa.String(100), primary_key=True),
        sa.Column("value", sa.String(200), nullable=False),
    )
    op.create_table(
        "stage_attempts",
        sa.Column("stage_attempt_id", sa.String(32), primary_key=True),
        sa.Column("owner_kind", sa.String(30), nullable=False),
        sa.Column("owner_id", sa.String(100), nullable=False),
        sa.Column("consumer_job_id", sa.String(32), sa.ForeignKey("jobs.job_id")),
        sa.Column("work_item_id", sa.String(32), sa.ForeignKey("work_items.work_item_id")),
        sa.Column("stage", sa.String(100), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("resource_name", sa.String(100)),
        sa.Column("attempt_number", sa.Integer(), nullable=False),
        sa.Column("started_sequence", sa.Integer(), nullable=False),
        sa.Column("finished_sequence", sa.Integer()),
        sa.Column("diagnostic_code", sa.String(100)),
    )
    op.create_table(
        "checkpoints",
        sa.Column("checkpoint_id", sa.String(32), primary_key=True),
        sa.Column("owner_kind", sa.String(30), nullable=False),
        sa.Column("owner_id", sa.String(100), nullable=False),
        sa.Column("job_id", sa.String(32), sa.ForeignKey("jobs.job_id")),
        sa.Column("work_item_id", sa.String(32), sa.ForeignKey("work_items.work_item_id")),
        sa.Column("stage", sa.String(100), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
    )
    op.create_table(
        "resource_slots",
        sa.Column("resource_name", sa.String(100), primary_key=True),
        sa.Column("capacity", sa.Integer(), nullable=False),
        sa.Column("last_granted_job_id", sa.String(32), sa.ForeignKey("jobs.job_id")),
        sa.Column("grant_sequence", sa.Integer(), nullable=False),
    )
    op.create_table(
        "conflict_keys",
        sa.Column("conflict_key", sa.String(200), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("active", sa.Integer(), nullable=False),
    )
    op.create_table(
        "dependencies",
        sa.Column("dependency_id", sa.String(32), primary_key=True),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("depends_on_job_id", sa.String(32), sa.ForeignKey("jobs.job_id")),
        sa.Column("frozen_result_ref", sa.String(200)),
        sa.Column("status", sa.String(30), nullable=False),
    )
    op.create_table(
        "shared_evidence_work",
        sa.Column("shared_work_id", sa.String(32), primary_key=True),
        sa.Column("fingerprint", sa.String(200), nullable=False, unique=True),
        sa.Column("image_sha256", sa.String(64), nullable=False),
        sa.Column("pipeline_fingerprint", sa.String(100), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.Column("artifact_ref", sa.String(200)),
        sa.Column("reference_count", sa.Integer(), nullable=False),
        sa.Column("runnable_consumer_count", sa.Integer(), nullable=False),
        sa.Column("diagnostic_code", sa.String(100)),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("retry_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("retry_budget", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failure_propagation_id", sa.String(64)),
    )
    op.create_table(
        "shared_evidence_consumers",
        sa.Column(
            "shared_work_id",
            sa.String(32),
            sa.ForeignKey("shared_evidence_work.shared_work_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "work_item_id",
            sa.String(32),
            sa.ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("image_role", sa.String(20), nullable=False),
        sa.Column("status", sa.String(30), nullable=False),
        sa.UniqueConstraint(
            "shared_work_id",
            "work_item_id",
            "image_role",
            name="uq_shared_evidence_consumer",
        ),
    )
    op.create_table(
        "control_idempotency",
        sa.Column("operation", sa.String(100), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column(
            "job_id",
            sa.String(32),
            sa.ForeignKey("jobs.job_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("result_record_version", sa.Integer(), nullable=False),
        sa.Column("result_status", sa.String(30), nullable=False),
        sa.UniqueConstraint(
            "operation",
            "idempotency_key",
            name="uq_control_idempotency_operation_key",
        ),
    )


def _create_recovery_tables() -> None:
    op.create_table(
        "application_instances",
        sa.Column("instance_id", sa.String(64), primary_key=True),
        sa.Column("data_root_identity", sa.String(64), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("process_started_at", sa.String(40), nullable=False),
        sa.Column("application_version", sa.String(40), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("registered_at", sa.String(40), nullable=False),
        sa.Column("heartbeat_at", sa.String(40), nullable=False),
        sa.Column("stopped_at", sa.String(40)),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_table(
        "worker_processes",
        sa.Column("worker_id", sa.String(100), primary_key=True),
        sa.Column(
            "instance_id",
            sa.String(64),
            sa.ForeignKey("application_instances.instance_id"),
            nullable=False,
        ),
        sa.Column("worker_kind", sa.String(40), nullable=False),
        sa.Column("pid", sa.Integer(), nullable=False),
        sa.Column("process_started_at", sa.String(40), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("heartbeat_at", sa.String(40), nullable=False),
        sa.Column("stopped_at", sa.String(40)),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
    )
    op.create_table(
        "leases",
        sa.Column("lease_id", sa.String(32), primary_key=True),
        sa.Column("resource_name", sa.String(100), nullable=False),
        sa.Column("slot_index", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("holder_kind", sa.String(20), nullable=False),
        sa.Column("holder_id", sa.String(100), nullable=False),
        sa.Column("job_id", sa.String(32), sa.ForeignKey("jobs.job_id")),
        sa.Column("work_item_id", sa.String(32), sa.ForeignKey("work_items.work_item_id")),
        sa.Column(
            "stage_attempt_id",
            sa.String(32),
            sa.ForeignKey("stage_attempts.stage_attempt_id"),
        ),
        sa.Column(
            "instance_id",
            sa.String(64),
            sa.ForeignKey("application_instances.instance_id"),
        ),
        sa.Column("worker_id", sa.String(100)),
        sa.Column("acquired_sequence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("released_sequence", sa.Integer()),
        sa.Column("acquired_at", sa.String(40)),
        sa.Column("heartbeat_at", sa.String(40)),
        sa.Column("expires_at", sa.String(40)),
        sa.Column("released_at", sa.String(40)),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("fencing_token", sa.String(100)),
        sa.Column("release_reason", sa.String(100)),
        sa.Column("status", sa.String(20), nullable=False),
    )
    op.create_index(
        "uq_active_lease_slot",
        "leases",
        ["resource_name", "slot_index"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
    )
    op.create_table(
        "browser_control_sessions",
        sa.Column("session_id", sa.String(100), primary_key=True),
        sa.Column("browser_lifecycle", sa.String(20), nullable=False),
        sa.Column("browser_control_mode", sa.String(20), nullable=False),
        sa.Column("holder_kind", sa.String(20)),
        sa.Column("holder_id", sa.String(100)),
        sa.Column("instance_id", sa.String(64)),
        sa.Column("worker_id", sa.String(100)),
        sa.Column("job_id", sa.String(32)),
        sa.Column("control_epoch", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("fencing_token", sa.String(100)),
        sa.Column("acquired_at", sa.String(40)),
        sa.Column("heartbeat_at", sa.String(40)),
        sa.Column("expires_at", sa.String(40)),
        sa.Column("returned_at", sa.String(40)),
        sa.Column("recovery_reason", sa.String(200)),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("updated_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "browser_control_events",
        sa.Column("event_id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "session_id",
            sa.String(100),
            sa.ForeignKey("browser_control_sessions.session_id"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("control_epoch", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )


def _create_evidence_tables() -> None:
    op.create_table(
        "evidence_imports",
        sa.Column("import_id", sa.String(32), primary_key=True),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("capture_id", sa.String(100), nullable=False, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "platform_snapshots",
        sa.Column("snapshot_id", sa.String(32), primary_key=True),
        sa.Column(
            "import_id",
            sa.String(32),
            sa.ForeignKey("evidence_imports.import_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("platform_waybill_id", sa.String(100), nullable=False),
        sa.Column("waybill_number", sa.String(100), nullable=False),
        sa.Column("captured_at", sa.String(40), nullable=False),
        sa.Column("request_contract_version", sa.String(100), nullable=False),
        sa.Column("business_fields_json", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.UniqueConstraint(
            "import_id",
            "platform_waybill_id",
            name="uq_snapshot_import_waybill",
        ),
    )
    op.create_table(
        "audit_decisions",
        sa.Column("decision_id", sa.String(32), primary_key=True),
        sa.Column(
            "snapshot_id",
            sa.String(32),
            sa.ForeignKey("platform_snapshots.snapshot_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("decision", sa.String(40), nullable=False),
        sa.Column("business_outcome", sa.String(50), nullable=False),
        sa.Column("rule_version", sa.String(100), nullable=False),
        sa.Column("eligible_for_handoff", sa.Integer(), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.execute(
        "CREATE TRIGGER platform_snapshots_reject_update "
        "BEFORE UPDATE ON platform_snapshots "
        "BEGIN SELECT RAISE(ABORT, 'platform_snapshots immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER platform_snapshots_reject_delete "
        "BEFORE DELETE ON platform_snapshots "
        "BEGIN SELECT RAISE(ABORT, 'platform_snapshots immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER audit_decisions_reject_update "
        "BEFORE UPDATE ON audit_decisions "
        "BEGIN SELECT RAISE(ABORT, 'audit_decisions immutable'); END"
    )
    op.execute(
        "CREATE TRIGGER audit_decisions_reject_delete "
        "BEFORE DELETE ON audit_decisions "
        "BEGIN SELECT RAISE(ABORT, 'audit_decisions immutable'); END"
    )
    op.create_table(
        "evidence_blobs",
        sa.Column("sha256", sa.String(64), primary_key=True),
        sa.Column("relative_path", sa.String(300), nullable=False, unique=True),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("storage_state", sa.String(20), nullable=False, server_default="available"),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("verified_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "evidence_references",
        sa.Column("reference_id", sa.String(32), primary_key=True),
        sa.Column(
            "sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("snapshot_id", sa.String(32), sa.ForeignKey("platform_snapshots.snapshot_id")),
        sa.Column("owner_kind", sa.String(40), nullable=False),
        sa.Column("owner_id", sa.String(100), nullable=False),
        sa.Column("role", sa.String(40), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("released_at", sa.String(40)),
        sa.UniqueConstraint(
            "sha256",
            "owner_kind",
            "owner_id",
            "role",
            name="uq_evidence_reference_owner_role",
        ),
    )
    op.create_index("ix_evidence_references_sha256", "evidence_references", ["sha256"])
    op.create_table(
        "evidence_holds",
        sa.Column("hold_id", sa.String(32), primary_key=True),
        sa.Column(
            "sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("hold_kind", sa.String(40), nullable=False),
        sa.Column("owner_id", sa.String(100), nullable=False),
        sa.Column("reason", sa.String(200), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("released_at", sa.String(40)),
    )
    op.create_index("ix_evidence_holds_sha256", "evidence_holds", ["sha256"])
    op.create_table(
        "evidence_cleanup_claims",
        sa.Column("claim_id", sa.String(100), primary_key=True),
        sa.Column(
            "sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("record_version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("released_at", sa.String(40)),
        sa.Column("release_reason", sa.String(100)),
    )
    op.create_index(
        "uq_active_cleanup_claim",
        "evidence_cleanup_claims",
        ["sha256"],
        unique=True,
        sqlite_where=sa.text("status = 'active'"),
    )


def upgrade() -> None:
    _create_task_tables()
    _create_recovery_tables()
    _create_evidence_tables()
    op.bulk_insert(
        sa.table(
            "resource_slots",
            sa.column("resource_name", sa.String()),
            sa.column("capacity", sa.Integer()),
            sa.column("grant_sequence", sa.Integer()),
        ),
        [
            {"resource_name": "platform_browser", "capacity": 1, "grant_sequence": 0},
            {"resource_name": "gpu_ocr_slot", "capacity": 1, "grant_sequence": 0},
            {"resource_name": "cpu_ocr_slot", "capacity": 1, "grant_sequence": 0},
            {"resource_name": "db_commit_gate", "capacity": 1, "grant_sequence": 0},
            {"resource_name": "maintenance_exclusive", "capacity": 1, "grant_sequence": 0},
        ],
    )
    op.bulk_insert(
        sa.table(
            "scheduler_meta",
            sa.column("key", sa.String()),
            sa.column("value", sa.String()),
        ),
        [{"key": "sequence", "value": "0"}],
    )


def downgrade() -> None:
    for table_name in (
        "evidence_cleanup_claims",
        "evidence_holds",
        "evidence_references",
        "evidence_blobs",
        "audit_decisions",
        "platform_snapshots",
        "evidence_imports",
        "browser_control_events",
        "browser_control_sessions",
        "leases",
        "worker_processes",
        "application_instances",
        "control_idempotency",
        "shared_evidence_consumers",
        "shared_evidence_work",
        "dependencies",
        "conflict_keys",
        "resource_slots",
        "checkpoints",
        "stage_attempts",
        "scheduler_meta",
        "event_outbox",
        "idempotency_records",
        "work_items",
        "jobs",
        "system_meta",
    ):
        op.drop_table(table_name)
