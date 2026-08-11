from __future__ import annotations

from sqlalchemy import (
    CheckConstraint,
    Column,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    UniqueConstraint,
)

from dahe.adapters.sqlite.loop3_schema import define_loop3_tables

METADATA = MetaData()

JOBS = Table(
    "jobs",
    METADATA,
    Column("job_id", String(32), primary_key=True),
    Column("task_type", String(32), nullable=False),
    Column("scope_label", String(200), nullable=False),
    Column("scope_fixture_id", String(100), nullable=False),
    Column("scope_fingerprint", String(64), nullable=False),
    Column("run_mode", String(20), nullable=False),
    Column("status", String(32), nullable=False),
    Column("current_stage", String(100)),
    Column("diagnostic_code", String(100)),
    Column("job_kind", String(20), nullable=False, default="business"),
    Column("ocr_execution_mode", String(10), nullable=False, default="fake"),
    Column("conflict_key", String(200)),
    Column("created_sequence", Integer, nullable=False, default=0),
    Column("record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
)

WORK_ITEMS = Table(
    "work_items",
    METADATA,
    Column("work_item_id", String(32), primary_key=True),
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("record_version", Integer, nullable=False),
    Column("waybill_number", String(100), nullable=False),
    Column("vehicle_number", String(100), nullable=False),
    Column("status", String(32), nullable=False),
    Column("current_stage", String(100), nullable=False),
    Column("business_outcome", String(50)),
    Column("platform_loading_net", String(40)),
    Column("platform_unloading_net", String(40)),
    Column("ticket_loading_net", String(40)),
    Column("ticket_unloading_net", String(40)),
    Column("decision", String(50)),
    Column("review_reason", String(100)),
    Column("item_index", Integer, nullable=False, default=0),
    Column("end_reason", String(50)),
    Column("waiting_reason_kind", String(30)),
    Column("waiting_reason", String(200)),
    Column("attempt_count", Integer, nullable=False, default=0),
    Column("diagnostic_code", String(100)),
    Column("loading_image_sha256", String(64)),
    Column("unloading_image_sha256", String(64)),
    Column("pipeline_fingerprint", String(100)),
    Column("fixture_outcome", String(50)),
    Column("fixture_review_reason", String(100)),
    Column("fixture_platform_loading_net", String(40)),
    Column("fixture_platform_unloading_net", String(40)),
    Column("fixture_ticket_loading_net", String(40)),
    Column("fixture_ticket_unloading_net", String(40)),
    Column("fixture_diagnostic_code", String(100)),
    Column("download_complete", Integer, nullable=False, default=0),
    Column("loading_ocr_complete", Integer, nullable=False, default=0),
    Column("unloading_ocr_complete", Integer, nullable=False, default=0),
    Column("ready_sequence", Integer, nullable=False, default=0),
    Column("loading_image_relative_path", String(500)),
    Column("unloading_image_relative_path", String(500)),
    Column("ocr_generation_id", String(32)),
)

IDEMPOTENCY_RECORDS = Table(
    "idempotency_records",
    METADATA,
    Column("operation", String(100), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint("operation", "idempotency_key", name="uq_idempotency_operation_key"),
)

OUTBOX = Table(
    "event_outbox",
    METADATA,
    Column("event_id", Integer, primary_key=True, autoincrement=True),
    Column("event_type", String(100), nullable=False),
    Column("aggregate_type", String(30), nullable=False),
    Column("aggregate_id", String(32), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
)

PLATFORM_ACCESS_WINDOWS = Table(
    "platform_access_windows",
    METADATA,
    Column("access_window_id", String(32), primary_key=True),
    Column("purpose", String(40), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("session_id", String(100), nullable=False),
    Column("build_sha256", String(64), nullable=False),
    Column("token_digest", String(64), nullable=False),
    Column("issued_at", String(40), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("consumed_at", String(40)),
    Column("record_version", Integer, nullable=False),
    Column("idempotency_key", String(200), nullable=False, unique=True),
    Column("request_hash", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "purpose IN ('contract_discovery', 'formal_locked_set', "
        "'production_shadow') AND record_version >= 1 "
        "AND length(build_sha256) = 64 "
        "AND length(token_digest) = 64 "
        "AND length(request_hash) = 64",
        name="ck_platform_access_window_shape",
    ),
)

PLATFORM_ACCESS_EVENTS = Table(
    "platform_access_events",
    METADATA,
    Column("event_id", Integer, primary_key=True, autoincrement=True),
    Column(
        "access_window_id",
        String(32),
        ForeignKey("platform_access_windows.access_window_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("event_type", String(60), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "event_type IN ('issued', 'consumed') AND record_version >= 1",
        name="ck_platform_access_event_shape",
    ),
)

PLATFORM_CONTROL_IDEMPOTENCY = Table(
    "platform_control_idempotency",
    METADATA,
    Column("operation", String(80), primary_key=True),
    Column("idempotency_key", String(200), primary_key=True),
    Column("request_hash", String(64), nullable=False),
    Column("session_id", String(100), nullable=False),
    Column("access_window_id", String(32), nullable=False),
    Column("result_record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "length(request_hash) = 64 AND result_record_version >= 1",
        name="ck_platform_control_idempotency_shape",
    ),
)

BUSINESS_CONNECTION_SESSIONS = Table(
    "business_connection_sessions",
    METADATA,
    Column("business_session_id", String(32), primary_key=True),
    Column("platform_session_id", String(100), nullable=False),
    Column("build_sha256", String(64), nullable=False),
    Column(
        "login_access_window_id",
        String(32),
        ForeignKey("platform_access_windows.access_window_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("confirmation_sha256", String(64), nullable=False),
    Column("status", String(20), nullable=False),
    Column("expires_at", String(40), nullable=False),
    Column("closed_at", String(40)),
    Column("close_reason", String(40)),
    Column("record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "status IN ('active', 'closed') "
        "AND record_version >= 1 "
        "AND length(build_sha256) = 64 "
        "AND length(confirmation_sha256) = 64 "
        "AND ((status = 'active' AND closed_at IS NULL AND close_reason IS NULL) "
        "OR (status = 'closed' AND closed_at IS NOT NULL "
        "AND close_reason IN ('explicit', 'expired', 'browser_closed', 'shutdown')))",
        name="ck_business_connection_session_shape",
    ),
)

BUSINESS_CONNECTION_READS = Table(
    "business_connection_reads",
    METADATA,
    Column(
        "business_session_id",
        String(32),
        ForeignKey("business_connection_sessions.business_session_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="RESTRICT"),
        primary_key=True,
        unique=True,
    ),
    Column(
        "access_window_id",
        String(32),
        ForeignKey("platform_access_windows.access_window_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("created_at", String(40), nullable=False),
)

BUSINESS_CONNECTION_IDEMPOTENCY = Table(
    "business_connection_idempotency",
    METADATA,
    Column("operation", String(80), primary_key=True),
    Column("idempotency_key", String(200), primary_key=True),
    Column("request_hash", String(64), nullable=False),
    Column(
        "business_session_id",
        String(32),
        ForeignKey("business_connection_sessions.business_session_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("result_record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "length(request_hash) = 64 AND result_record_version >= 1",
        name="ck_business_connection_idempotency_shape",
    ),
)

PLATFORM_CREDENTIAL_CONFIG = Table(
    "platform_credential_config",
    METADATA,
    Column("config_id", Integer, primary_key=True),
    Column("credential_reference", String(100), nullable=False),
    Column("configured", Integer, nullable=False),
    Column("masked_username", String(520)),
    Column("record_version", Integer, nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "config_id = 1 AND configured IN (0, 1) "
        "AND record_version >= 0 "
        "AND ((configured = 0 AND masked_username IS NULL) "
        "OR (configured = 1 AND masked_username IS NOT NULL))",
        name="ck_platform_credential_config_shape",
    ),
)

PLATFORM_CREDENTIAL_IDEMPOTENCY = Table(
    "platform_credential_idempotency",
    METADATA,
    Column("operation", String(20), primary_key=True),
    Column("idempotency_key", String(200), primary_key=True),
    Column("request_fingerprint", String(64), nullable=False),
    Column("result_record_version", Integer, nullable=False),
    Column("result_configured", Integer),
    Column("result_masked_username", String(520)),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "operation IN ('save', 'delete') "
        "AND length(request_fingerprint) = 64 "
        "AND result_record_version >= 1",
        name="ck_platform_credential_idempotency_shape",
    ),
)

SETTLEMENT_CAPTURE_STRATEGIES = Table(
    "settlement_capture_strategies",
    METADATA,
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("strategy", String(20), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "strategy IN ('legacy', 'batch_v1')",
        name="ck_settlement_capture_strategy_value",
    ),
)

OPERATIONAL_CAPTURE_RUNS = Table(
    "operational_capture_runs",
    METADATA,
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("scope", String(20), nullable=False),
    Column("total", Integer, nullable=False),
    Column("items_json", Text, nullable=False),
    Column("items_sha256", String(64), nullable=False),
    Column("next_item_index", Integer, nullable=False),
    Column("committed_batch_count", Integer, nullable=False),
    Column("batch_size", Integer, nullable=False),
    Column("detail_concurrency", Integer, nullable=False),
    Column("image_concurrency", Integer, nullable=False),
    Column("status", String(20), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("metadata_checked_count", Integer, nullable=False, default=0),
    Column("reused_count", Integer, nullable=False, default=0),
    Column("images_downloaded_count", Integer, nullable=False, default=0),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "total >= 0 AND next_item_index >= 0 "
        "AND next_item_index <= total "
        "AND committed_batch_count >= 0 "
        "AND batch_size IN (15, 20, 50, 100) "
        "AND detail_concurrency BETWEEN 1 AND 4 "
        "AND image_concurrency BETWEEN 1 AND 6 "
        "AND status IN ('collecting', 'complete') "
        "AND record_version >= 1 "
        "AND metadata_checked_count BETWEEN 0 AND total "
        "AND reused_count BETWEEN 0 AND metadata_checked_count "
        "AND images_downloaded_count >= 0 "
        "AND length(items_sha256) = 64 "
        "AND ((status = 'complete' AND next_item_index = total) "
        "OR (status = 'collecting' AND "
        "(next_item_index < total OR total = 0)))",
        name="ck_operational_capture_run_shape",
    ),
)

OPERATIONAL_EVIDENCE_REUSE = Table(
    "operational_evidence_reuse",
    METADATA,
    Column("platform_waybill_id", String(64), primary_key=True),
    Column("source_revision_sha256", String(64), nullable=False),
    Column("loading_sha256", String(64)),
    Column("loading_media_type", String(80)),
    Column("loading_validator_sha256", String(64)),
    Column("unloading_sha256", String(64)),
    Column("unloading_media_type", String(80)),
    Column("unloading_validator_sha256", String(64)),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
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

DAILY_OPERATIONAL_OCR_BATCHES = Table(
    "daily_operational_ocr_batches",
    METADATA,
    Column(
        "daily_job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("batch_number", Integer, primary_key=True),
    Column(
        "ocr_job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="RESTRICT"),
        unique=True,
    ),
    Column("eligible_item_count", Integer, nullable=False),
    Column("missing_ticket_count", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "batch_number >= 1 "
        "AND eligible_item_count >= 0 "
        "AND missing_ticket_count >= 0 "
        "AND eligible_item_count + missing_ticket_count BETWEEN 1 AND 100 "
        "AND ((eligible_item_count = 0 AND ocr_job_id IS NULL) "
        "OR (eligible_item_count > 0 AND ocr_job_id IS NOT NULL))",
        name="ck_daily_operational_ocr_batch_shape",
    ),
)

SETTLEMENT_CAPTURE_INVOCATIONS = Table(
    "settlement_capture_invocations",
    METADATA,
    Column("invocation_id", String(32), primary_key=True),
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    ),
    Column(
        "access_window_id",
        String(32),
        ForeignKey(
            "platform_access_windows.access_window_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        unique=True,
    ),
    Column("scope", String(20), nullable=False),
    Column("page_size", Integer, nullable=False),
    Column("source_build_sha256", String(64), nullable=False),
    Column("contract_canonical_sha256", String(64), nullable=False),
    Column("contract_file_sha256", String(64), nullable=False),
    Column("contract_selection_sha256", String(64), nullable=False),
    Column("identity_context_sha256", String(64), nullable=False),
    Column("status", String(20), nullable=False),
    Column("manifest_sha256", String(64)),
    Column("manifest_json", Text),
    Column("selection_manifest_sha256", String(64)),
    Column("batch_manifest_sha256", String(64)),
    Column("diagnostic_code", String(100)),
    Column("record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "((scope = 'current' AND page_size = 50) "
        "OR (scope = 'settled_history' AND page_size = 100)) "
        "AND status IN ("
        "'collecting', 'sealed', 'selected', 'operational_ready', "
        "'selection_blocked', 'failed'"
        ") "
        "AND record_version >= 1 "
        "AND length(source_build_sha256) = 64 "
        "AND length(contract_canonical_sha256) = 64 "
        "AND length(contract_file_sha256) = 64 "
        "AND length(contract_selection_sha256) = 64 "
        "AND length(identity_context_sha256) = 64 "
        "AND ((status = 'selected' "
        "AND manifest_sha256 IS NOT NULL "
        "AND manifest_json IS NOT NULL "
        "AND selection_manifest_sha256 IS NOT NULL "
        "AND batch_manifest_sha256 IS NOT NULL "
        "AND diagnostic_code IS NULL) "
        "OR (status = 'operational_ready' "
        "AND manifest_sha256 IS NOT NULL "
        "AND manifest_json IS NULL "
        "AND selection_manifest_sha256 IS NULL "
        "AND batch_manifest_sha256 IS NULL "
        "AND diagnostic_code IS NULL) "
        "OR (status = 'sealed' "
        "AND manifest_sha256 IS NOT NULL "
        "AND manifest_json IS NOT NULL "
        "AND selection_manifest_sha256 IS NULL "
        "AND batch_manifest_sha256 IS NULL "
        "AND diagnostic_code IS NULL) "
        "OR (status = 'selection_blocked' "
        "AND manifest_sha256 IS NOT NULL "
        "AND manifest_json IS NOT NULL "
        "AND selection_manifest_sha256 IS NULL "
        "AND batch_manifest_sha256 IS NULL "
        "AND diagnostic_code IS NOT NULL) "
        "OR (status = 'collecting' "
        "AND manifest_sha256 IS NULL "
        "AND manifest_json IS NULL "
        "AND selection_manifest_sha256 IS NULL "
        "AND batch_manifest_sha256 IS NULL "
        "AND diagnostic_code IS NULL) "
        "OR (status = 'failed' "
        "AND manifest_sha256 IS NULL "
        "AND manifest_json IS NULL "
        "AND selection_manifest_sha256 IS NULL "
        "AND batch_manifest_sha256 IS NULL "
        "AND diagnostic_code IS NOT NULL))",
        name="ck_settlement_capture_invocation_shape",
    ),
)

SETTLEMENT_CAPTURE_IDENTITIES = Table(
    "settlement_capture_identities",
    METADATA,
    Column(
        "invocation_id",
        String(32),
        ForeignKey(
            "settlement_capture_invocations.invocation_id",
            ondelete="RESTRICT",
        ),
        primary_key=True,
    ),
    Column("item_identity_sha256", String(64), primary_key=True),
    Column("platform_waybill_id", String(500), nullable=False),
    Column("waybill_number", String(500), nullable=False),
    Column("vehicle_number", String(500)),
    Column("source_page_number", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint(
        "invocation_id",
        "platform_waybill_id",
        name="uq_settlement_capture_platform_identity",
    ),
    UniqueConstraint(
        "invocation_id",
        "waybill_number",
        name="uq_settlement_capture_waybill_identity",
    ),
    CheckConstraint(
        "length(item_identity_sha256) = 64 "
        "AND source_page_number >= 1",
        name="ck_settlement_capture_identity_shape",
    ),
)

LOOP9_EXCLUSION_AUTHORITY_ANCHORS = Table(
    "loop9_exclusion_authority_anchors",
    METADATA,
    Column("authority_context_sha256", String(64), primary_key=True),
    Column("sequence", Integer, primary_key=True),
    Column("node_sha256", String(64), nullable=False, unique=True),
    Column(
        "previous_head_sha256",
        String(64),
        ForeignKey(
            "loop9_exclusion_authority_anchors.node_sha256",
            ondelete="RESTRICT",
        ),
        unique=True,
    ),
    Column("source_boundary_sha256", String(64), nullable=False),
    Column("source_inventory_high_watermark", Integer, nullable=False),
    Column("identity_context_sha256", String(64), nullable=False),
    Column("expected_current_build_sha256", String(64), nullable=False),
    Column(
        "expected_settlement_contract_sha256",
        String(64),
        nullable=False,
    ),
    Column("expected_daily_contract_sha256", String(64), nullable=False),
    Column(
        "expected_settlement_selection_sha256",
        String(64),
        nullable=False,
    ),
    Column("expected_daily_selection_sha256", String(64), nullable=False),
    Column("child_inventory_sha256", String(64), nullable=False),
    Column("child_exclusion_kind", String(32), nullable=False),
    Column("child_platform_identity_count", Integer, nullable=False),
    Column("child_image_count", Integer, nullable=False),
    Column("child_scope_exclusion_token_count", Integer, nullable=False),
    Column("child_perceptual_fingerprint_count", Integer, nullable=False),
    UniqueConstraint(
        "authority_context_sha256",
        "child_inventory_sha256",
        name="uq_loop9_exclusion_anchor_context_child",
    ),
    CheckConstraint(
        "sequence >= 1 "
        "AND source_inventory_high_watermark >= 1 "
        "AND child_platform_identity_count >= 0 "
        "AND child_image_count >= 0 "
        "AND child_scope_exclusion_token_count >= 0 "
        "AND child_perceptual_fingerprint_count = child_image_count "
        "AND child_exclusion_kind IN ('development', 'legacy_loop7') "
        "AND (child_image_count >= 1 "
        "OR child_exclusion_kind = 'development') "
        "AND (child_platform_identity_count + child_image_count "
        "+ child_scope_exclusion_token_count >= 1) "
        "AND ((sequence = 1 AND previous_head_sha256 IS NULL) "
        "OR (sequence > 1 AND previous_head_sha256 IS NOT NULL)) "
        "AND length(authority_context_sha256) = 64 "
        "AND length(node_sha256) = 64 "
        "AND length(source_boundary_sha256) = 64 "
        "AND length(identity_context_sha256) = 64 "
        "AND length(expected_current_build_sha256) = 64 "
        "AND length(expected_settlement_contract_sha256) = 64 "
        "AND length(expected_daily_contract_sha256) = 64 "
        "AND length(expected_settlement_selection_sha256) = 64 "
        "AND length(expected_daily_selection_sha256) = 64 "
        "AND length(child_inventory_sha256) = 64",
        name="ck_loop9_exclusion_authority_anchor_shape",
    ),
)

LOOP9_FORMAL_SELECTION_LIFECYCLE_ANCHORS = Table(
    "loop9_formal_selection_lifecycle_anchors",
    METADATA,
    Column("target_kind", String(32), primary_key=True),
    Column("sequence", Integer, primary_key=True),
    Column("generation", Integer, nullable=False),
    Column("event_kind", String(16), nullable=False),
    Column("node_sha256", String(64), nullable=False, unique=True),
    Column(
        "previous_head_sha256",
        String(64),
        ForeignKey(
            "loop9_formal_selection_lifecycle_anchors.node_sha256",
            ondelete="RESTRICT",
        ),
        unique=True,
    ),
    Column("selection_sha256", String(64), nullable=False),
    Column("predecessor_selection_sha256", String(64)),
    Column("failure_attestation_sha256", String(64)),
    Column("exclusion_inventory_sha256", String(64)),
    Column("exclusion_authority_sha256", String(64), nullable=False),
    Column("exclusion_child_head_sha256", String(64), nullable=False),
    Column("source_build_sha256", String(64), nullable=False),
    Column("pipeline_fingerprint", String(64), nullable=False),
    Column("identity_context_sha256", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "target_kind = 'current_locked_50' "
        "AND sequence >= 1 "
        "AND generation >= 1 "
        "AND event_kind IN ('activated', 'invalidated') "
        "AND length(node_sha256) = 64 "
        "AND length(selection_sha256) = 64 "
        "AND length(exclusion_authority_sha256) = 64 "
        "AND length(exclusion_child_head_sha256) = 64 "
        "AND length(source_build_sha256) = 64 "
        "AND length(pipeline_fingerprint) = 64 "
        "AND length(identity_context_sha256) = 64 "
        "AND ((sequence = 1 "
        "AND generation = 1 "
        "AND event_kind = 'activated' "
        "AND previous_head_sha256 IS NULL "
        "AND predecessor_selection_sha256 IS NULL "
        "AND failure_attestation_sha256 IS NULL "
        "AND exclusion_inventory_sha256 IS NULL) "
        "OR (sequence > 1 "
        "AND previous_head_sha256 IS NOT NULL)) "
        "AND ((event_kind = 'activated' "
        "AND failure_attestation_sha256 IS NULL "
        "AND exclusion_inventory_sha256 IS NULL "
        "AND (generation = 1 "
        "OR predecessor_selection_sha256 IS NOT NULL)) "
        "OR (event_kind = 'invalidated' "
        "AND predecessor_selection_sha256 IS NULL "
        "AND failure_attestation_sha256 IS NOT NULL "
        "AND exclusion_inventory_sha256 IS NOT NULL))",
        name="ck_loop9_formal_selection_lifecycle_anchor_shape",
    ),
)

SYSTEM_META = Table(
    "system_meta",
    METADATA,
    Column("key", String(100), primary_key=True),
    Column("value", String(200), nullable=False),
)

TEMPLATE_REFERENCE_UPLOADS = Table(
    "template_reference_uploads",
    METADATA,
    Column("staged_reference_id", String(32), primary_key=True),
    Column(
        "image_sha256",
        String(64),
        ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("media_type", String(100), nullable=False),
    Column("width", Integer, nullable=False),
    Column("height", Integer, nullable=False),
    Column("state", String(20), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "media_type IN ('image/jpeg', 'image/png')",
        name="ck_template_reference_uploads_media_type",
    ),
    CheckConstraint(
        "width >= 1 AND height >= 1",
        name="ck_template_reference_uploads_dimensions",
    ),
    CheckConstraint(
        "state IN ('staged', 'consumed', 'abandoned')",
        name="ck_template_reference_uploads_state",
    ),
    CheckConstraint(
        "record_version >= 1",
        name="ck_template_reference_uploads_record_version",
    ),
)

CANDIDATE_DEVELOPMENT_OCR_RUNS = Table(
    "candidate_development_ocr_runs",
    METADATA,
    Column("evidence_sha256", String(64), primary_key=True),
    Column("evidence_blob_sha256", String(64), nullable=False),
    Column(
        "evidence_relative_path",
        String(500),
        nullable=False,
        unique=True,
    ),
    Column("evidence_byte_size", Integer, nullable=False),
    Column("package_sha256", String(64), nullable=False),
    Column("review_history_authority_sha256", String(64), nullable=False),
    Column("source_authority_sha256", String(64), nullable=False),
    Column("reviewer_id", String(200), nullable=False),
    Column("application_build_sha256", String(64), nullable=False),
    Column("composition_evidence_sha256", String(64), nullable=False),
    Column("runtime_set_sha256", String(64), nullable=False),
    Column("pipeline_contract_sha256", String(64), nullable=False),
    Column("completion_status", String(50), nullable=False),
    Column("completed_at", String(40), nullable=False),
    Column("authority_payload_json", Text, nullable=False),
    Column("authority_sha256", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "evidence_byte_size > 0",
        name="ck_candidate_development_ocr_runs_byte_size",
    ),
    CheckConstraint(
        "completion_status IN ("
        "'completed', "
        "'completed_with_runtime_differences'"
        ")",
        name="ck_candidate_development_ocr_runs_status",
    ),
    CheckConstraint(
        " AND ".join(
            f"length({column}) = 64 "
            f"AND {column} = lower({column}) "
            f"AND {column} NOT GLOB '*[^0-9a-f]*'"
            for column in (
                "evidence_sha256",
                "evidence_blob_sha256",
                "package_sha256",
                "review_history_authority_sha256",
                "source_authority_sha256",
                "application_build_sha256",
                "composition_evidence_sha256",
                "runtime_set_sha256",
                "pipeline_contract_sha256",
                "authority_sha256",
            )
        ),
        name="ck_candidate_development_ocr_runs_hashes",
    ),
)

CANDIDATE_DEVELOPMENT_OCR_ATTEMPTS = Table(
    "candidate_development_ocr_attempts",
    METADATA,
    Column(
        "attempt_sequence",
        Integer,
        primary_key=True,
        autoincrement=True,
    ),
    Column("scope_sha256", String(64), nullable=False),
    Column("evidence_sha256", String(64), nullable=False, unique=True),
    Column("evidence_blob_sha256", String(64), nullable=False),
    Column("evidence_relative_path", String(500), nullable=False),
    Column("evidence_byte_size", Integer, nullable=False),
    Column("package_sha256", String(64), nullable=False),
    Column("review_history_authority_sha256", String(64), nullable=False),
    Column("source_authority_sha256", String(64), nullable=False),
    Column("reviewer_id", String(200), nullable=False),
    Column("application_build_sha256", String(64), nullable=False),
    Column("composition_evidence_sha256", String(64), nullable=False),
    Column("runtime_set_sha256", String(64), nullable=False),
    Column("pipeline_contract_sha256", String(64), nullable=False),
    Column("completion_status", String(50), nullable=False),
    Column("terminal_status", String(30), nullable=False),
    Column(
        "authorized_evidence_sha256",
        String(64),
        ForeignKey(
            "candidate_development_ocr_runs.evidence_sha256",
            ondelete="RESTRICT",
        ),
    ),
    Column("completed_at", String(40), nullable=False),
    Column("attempt_payload_json", Text, nullable=False),
    Column("attempt_sha256", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "evidence_byte_size > 0",
        name="ck_candidate_development_ocr_attempts_byte_size",
    ),
    CheckConstraint(
        "terminal_status IN ('succeeded', 'technical_failed')",
        name="ck_candidate_development_ocr_attempts_terminal_status",
    ),
    CheckConstraint(
        "(terminal_status = 'succeeded' "
        "AND completion_status IN ("
        "'completed', 'completed_with_runtime_differences') "
        "AND authorized_evidence_sha256 = evidence_sha256) "
        "OR (terminal_status = 'technical_failed' "
        "AND completion_status = 'failed' "
        "AND authorized_evidence_sha256 IS NULL)",
        name="ck_candidate_development_ocr_attempts_outcome",
    ),
    CheckConstraint(
        " AND ".join(
            f"length({column}) = 64 "
            f"AND {column} = lower({column}) "
            f"AND {column} NOT GLOB '*[^0-9a-f]*'"
            for column in (
                "scope_sha256",
                "evidence_sha256",
                "evidence_blob_sha256",
                "package_sha256",
                "review_history_authority_sha256",
                "source_authority_sha256",
                "application_build_sha256",
                "composition_evidence_sha256",
                "runtime_set_sha256",
                "pipeline_contract_sha256",
                "attempt_sha256",
            )
        ),
        name="ck_candidate_development_ocr_attempts_hashes",
    ),
)

TEMPLATE_FAMILIES = Table(
    "template_families",
    METADATA,
    Column("family_id", String(100), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("role", String(20), nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "role IN ('loading', 'unloading')",
        name="ck_template_families_role",
    ),
)

TEMPLATE_VERSIONS = Table(
    "template_versions",
    METADATA,
    Column("version_id", String(32), primary_key=True),
    Column(
        "family_id",
        String(100),
        ForeignKey("template_families.family_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("version_number", Integer, nullable=False),
    Column(
        "parent_version_id",
        String(32),
        ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
    ),
    Column("definition_json", Text, nullable=False),
    Column("content_sha256", String(64), nullable=False),
    Column(
        "reference_image_sha256",
        String(64),
        ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column(
        "reference_mask_sha256",
        String(64),
        ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("alignment_fingerprint", String(64), nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint("version_number >= 1", name="ck_template_versions_number"),
    UniqueConstraint(
        "family_id",
        "version_number",
        name="uq_template_versions_family_number",
    ),
    UniqueConstraint(
        "family_id",
        "version_id",
        name="uq_template_versions_family_identity",
    ),
)

TEMPLATE_REFERENCE_ORIGINS = Table(
    "template_reference_origins",
    METADATA,
    Column(
        "version_id",
        String(32),
        ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("candidate_evidence_sha256", String(64), nullable=False),
    Column(
        "candidate_record_blob_sha256",
        String(64),
        ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column(
        "source_image_sha256",
        String(64),
        ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("waybill_identity_sha256", String(64), nullable=False),
    Column("sample_id", String(100), nullable=False),
    Column("submitted_slot", String(20), nullable=False),
    Column("confirmed_role", String(20), nullable=False),
    Column("package_sha256", String(64), nullable=False),
    Column("review_history_authority_sha256", String(64), nullable=False),
    Column("source_authority_sha256", String(64), nullable=False),
    Column("review_record_evidence_sha256", String(64), nullable=False),
    Column("origin_payload_json", Text, nullable=False),
    Column("origin_sha256", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "submitted_slot IN ('loading', 'unloading')",
        name="ck_template_reference_origins_slot",
    ),
    CheckConstraint(
        "confirmed_role IN ('loading', 'unloading')",
        name="ck_template_reference_origins_role",
    ),
    CheckConstraint(
        " AND ".join(
            f"length({column}) = 64 "
            f"AND {column} = lower({column}) "
            f"AND {column} NOT GLOB '*[^0-9a-f]*'"
            for column in (
                "candidate_evidence_sha256",
                "candidate_record_blob_sha256",
                "source_image_sha256",
                "waybill_identity_sha256",
                "package_sha256",
                "review_history_authority_sha256",
                "source_authority_sha256",
                "review_record_evidence_sha256",
                "origin_sha256",
            )
        ),
        name="ck_template_reference_origins_hashes",
    ),
)

TEMPLATE_VERSION_STATES = Table(
    "template_version_states",
    METADATA,
    Column(
        "version_id",
        String(32),
        ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("lifecycle", String(30), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "lifecycle IN ('draft', 'development_tested', 'shadow')",
        name="ck_template_version_states_lifecycle",
    ),
    CheckConstraint(
        "record_version >= 1",
        name="ck_template_version_states_record_version",
    ),
)

TEMPLATE_EVALUATIONS = Table(
    "template_evaluations",
    METADATA,
    Column("evaluation_id", String(100), primary_key=True),
    Column("dataset_kind", String(20), nullable=False),
    Column("dataset_id", String(200), nullable=False),
    Column("dataset_manifest_sha256", String(64), nullable=False),
    Column("template_set_fingerprint", String(64), nullable=False),
    Column("matcher_fingerprint", String(64), nullable=False),
    Column("policy_fingerprint", String(64), nullable=False),
    Column("build_fingerprint", String(64), nullable=False),
    Column("runtime_fingerprint", String(64), nullable=False),
    Column("verification_source", String(30), nullable=False),
    Column("stable_outcome_sha256", String(64)),
    Column("expected_count", Integer, nullable=False),
    Column("result_count", Integer, nullable=False),
    Column("metrics_json", Text, nullable=False),
    Column("metrics_sha256", String(64), nullable=False),
    Column("gate_passed", Integer, nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("completed_at", String(40), nullable=False),
    CheckConstraint(
        "dataset_kind IN ('development', 'locked', 'shadow')",
        name="ck_template_evaluations_dataset_kind",
    ),
    CheckConstraint(
        "expected_count >= 1 AND result_count = expected_count",
        name="ck_template_evaluations_reconciled_counts",
    ),
    CheckConstraint(
        "gate_passed IN (0, 1)",
        name="ck_template_evaluations_gate_passed",
    ),
    CheckConstraint(
        "verification_source IN ('untrusted_record', 'frozen_runner')",
        name="ck_template_evaluations_verification_source",
    ),
    CheckConstraint(
        "(verification_source = 'frozen_runner' AND stable_outcome_sha256 IS NOT NULL) "
        "OR (verification_source = 'untrusted_record' "
        "AND stable_outcome_sha256 IS NULL)",
        name="ck_template_evaluations_verification_evidence",
    ),
)

TEMPLATE_LIFECYCLE_ATTEMPTS = Table(
    "template_lifecycle_attempts",
    METADATA,
    Column(
        "attempt_sequence",
        Integer,
        primary_key=True,
        autoincrement=True,
    ),
    Column("attempt_id", String(32), nullable=False, unique=True),
    Column("scope_sha256", String(64), nullable=False),
    Column("terminal_status", String(30), nullable=False),
    Column(
        "evaluation_id",
        String(100),
        ForeignKey(
            "template_evaluations.evaluation_id",
            ondelete="RESTRICT",
        ),
    ),
    Column("failure_code", String(100)),
    Column("ocr_evidence_sha256", String(64), nullable=False),
    Column("package_sha256", String(64), nullable=False),
    Column("review_history_authority_sha256", String(64), nullable=False),
    Column("source_authority_sha256", String(64), nullable=False),
    Column("reviewer_id", String(200), nullable=False),
    Column("ocr_capture_build_sha256", String(64), nullable=False),
    Column("role_evaluator_build_sha256", String(64), nullable=False),
    Column("composition_evidence_sha256", String(64), nullable=False),
    Column("runtime_set_sha256", String(64), nullable=False),
    Column("pipeline_contract_sha256", String(64), nullable=False),
    Column("dataset_manifest_sha256", String(64), nullable=False),
    Column("candidate_set_sha256", String(64), nullable=False),
    Column("matcher_fingerprint", String(64), nullable=False),
    Column("policy_fingerprint", String(64), nullable=False),
    Column("template_set_fingerprint", String(64), nullable=False),
    Column("composite_policy_sha256", String(64), nullable=False),
    Column("attempt_payload_json", Text, nullable=False),
    Column("attempt_sha256", String(64), nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "terminal_status IN ("
        "'succeeded', 'business_failed', 'technical_failed')",
        name="ck_template_lifecycle_attempts_terminal_status",
    ),
    CheckConstraint(
        "(terminal_status = 'succeeded' "
        "AND evaluation_id IS NOT NULL AND failure_code IS NULL) "
        "OR (terminal_status IN ('business_failed', 'technical_failed') "
        "AND evaluation_id IS NULL AND failure_code IS NOT NULL)",
        name="ck_template_lifecycle_attempts_outcome",
    ),
    CheckConstraint(
        " AND ".join(
            f"length({column}) = 64 "
            f"AND {column} = lower({column}) "
            f"AND {column} NOT GLOB '*[^0-9a-f]*'"
            for column in (
                "scope_sha256",
                "ocr_evidence_sha256",
                "package_sha256",
                "review_history_authority_sha256",
                "source_authority_sha256",
                "ocr_capture_build_sha256",
                "role_evaluator_build_sha256",
                "composition_evidence_sha256",
                "runtime_set_sha256",
                "pipeline_contract_sha256",
                "dataset_manifest_sha256",
                "candidate_set_sha256",
                "matcher_fingerprint",
                "policy_fingerprint",
                "template_set_fingerprint",
                "composite_policy_sha256",
                "attempt_sha256",
            )
        ),
        name="ck_template_lifecycle_attempts_hashes",
    ),
)

TEMPLATE_EVALUATION_CANDIDATES = Table(
    "template_evaluation_candidates",
    METADATA,
    Column(
        "evaluation_id",
        String(100),
        ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("family_id", String(100), nullable=False),
    Column("version_id", String(32), nullable=False),
    Column("content_sha256", String(64), nullable=False),
    Column("evaluated_lifecycle", String(30), nullable=False),
    ForeignKeyConstraint(
        ["family_id", "version_id"],
        ["template_versions.family_id", "template_versions.version_id"],
        name="fk_template_evaluation_candidate_version",
        ondelete="RESTRICT",
    ),
    UniqueConstraint(
        "evaluation_id",
        "family_id",
        name="uq_template_evaluation_candidate_family",
    ),
    UniqueConstraint(
        "evaluation_id",
        "version_id",
        name="uq_template_evaluation_candidate_version",
    ),
    CheckConstraint(
        "evaluated_lifecycle IN ('draft', 'development_tested', 'shadow')",
        name="ck_template_evaluation_candidate_lifecycle",
    ),
)

TEMPLATE_EVALUATION_ITEMS = Table(
    "template_evaluation_items",
    METADATA,
    Column("item_id", String(32), primary_key=True),
    Column(
        "evaluation_id",
        String(100),
        ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("sample_id", String(200), nullable=False),
    Column("waybill_id", String(200), nullable=False),
    Column("image_sha256", String(64), nullable=False),
    Column("truth", String(20), nullable=False),
    Column("prediction", String(20), nullable=False),
    Column("confidence", String(40), nullable=False),
    Column("high_confidence", Integer, nullable=False),
    Column("orientation_degrees", Integer, nullable=False),
    Column("evidence_json", Text, nullable=False),
    Column("assessment_fingerprint", String(64), nullable=False),
    Column("elapsed_ms", String(40), nullable=False),
    Column("pair_issue", String(100)),
    Column("unknown_reason", String(200)),
    CheckConstraint(
        "truth IN ('loading', 'unloading', 'unknown')",
        name="ck_template_evaluation_items_truth",
    ),
    CheckConstraint(
        "prediction IN ('loading', 'unloading', 'unknown')",
        name="ck_template_evaluation_items_prediction",
    ),
    CheckConstraint(
        "high_confidence IN (0, 1)",
        name="ck_template_evaluation_items_high_confidence",
    ),
    CheckConstraint(
        "orientation_degrees IN (0, 90, 180, 270)",
        name="ck_template_evaluation_items_orientation",
    ),
    UniqueConstraint(
        "evaluation_id",
        "sample_id",
        name="uq_template_evaluation_item_sample",
    ),
)

TEMPLATE_EVALUATION_PAIRS = Table(
    "template_evaluation_pairs",
    METADATA,
    Column("pair_id", String(32), primary_key=True),
    Column(
        "evaluation_id",
        String(100),
        ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("case_id", String(200), nullable=False),
    Column("expected_issue", String(100)),
    Column("result_issue", String(100)),
    Column("expected_matches_result", Integer, nullable=False),
    CheckConstraint(
        "expected_matches_result IN (0, 1)",
        name="ck_template_evaluation_pairs_match",
    ),
    UniqueConstraint(
        "evaluation_id",
        "case_id",
        name="uq_template_evaluation_pair_case",
    ),
)

TEMPLATE_EVALUATION_INVALIDATIONS = Table(
    "template_evaluation_invalidations",
    METADATA,
    Column("invalidation_id", String(32), primary_key=True),
    Column(
        "evaluation_id",
        String(100),
        ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("reason", String(500), nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("created_at", String(40), nullable=False),
)

TEMPLATE_DEVELOPMENT_CONTRACT_STATE = Table(
    "template_development_contract_state",
    METADATA,
    Column("singleton_id", Integer, primary_key=True),
    Column("development_manifest_sha256", String(64), nullable=False),
    Column(
        "evaluation_id",
        String(100),
        ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("actor_id", String(200), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "singleton_id = 1",
        name="ck_template_development_contract_singleton",
    ),
    CheckConstraint(
        "record_version >= 1",
        name="ck_template_development_contract_record_version",
    ),
)

TEMPLATE_LIFECYCLE_EVENTS = Table(
    "template_lifecycle_events",
    METADATA,
    Column("event_id", String(32), primary_key=True),
    Column(
        "version_id",
        String(32),
        ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("operation", String(50), nullable=False),
    Column("from_lifecycle", String(30)),
    Column("to_lifecycle", String(30), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column(
        "evaluation_id",
        String(100),
        ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
    ),
    Column("developer_authorization_id", String(200)),
    Column("actor_id", String(200), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "to_lifecycle IN ('draft', 'development_tested', 'shadow')",
        name="ck_template_lifecycle_events_to_lifecycle",
    ),
    CheckConstraint(
        "from_lifecycle IS NULL OR from_lifecycle IN ('draft', 'development_tested', 'shadow')",
        name="ck_template_lifecycle_events_from_lifecycle",
    ),
    CheckConstraint(
        "record_version >= 1",
        name="ck_template_lifecycle_events_record_version",
    ),
    UniqueConstraint(
        "version_id",
        "record_version",
        name="uq_template_lifecycle_events_version_record",
    ),
)

TEMPLATE_SHADOW_POINTERS = Table(
    "template_shadow_pointers",
    METADATA,
    Column(
        "family_id",
        String(100),
        ForeignKey("template_families.family_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("version_id", String(32), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("updated_at", String(40), nullable=False),
    ForeignKeyConstraint(
        ["family_id", "version_id"],
        ["template_versions.family_id", "template_versions.version_id"],
        name="fk_template_shadow_pointer_family_version",
        ondelete="RESTRICT",
    ),
    CheckConstraint(
        "record_version >= 1",
        name="ck_template_shadow_pointers_record_version",
    ),
)

TEMPLATE_IDEMPOTENCY_RECORDS = Table(
    "template_idempotency_records",
    METADATA,
    Column("operation", String(50), primary_key=True),
    Column("idempotency_key", String(200), primary_key=True),
    Column("request_hash", String(64), nullable=False),
    Column("result_kind", String(20), nullable=False),
    Column("result_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "result_kind IN ('version', 'shadow_pointer', 'reference_upload', 'template_evidence')",
        name="ck_template_idempotency_result_kind",
    ),
)

TEMPLATE_AUDIT_EVENTS = Table(
    "template_audit_events",
    METADATA,
    Column("audit_id", String(32), primary_key=True),
    Column("event_kind", String(50), nullable=False),
    Column(
        "family_id",
        String(100),
        ForeignKey("template_families.family_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column(
        "version_id",
        String(32),
        ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
    ),
    Column("actor_id", String(200), nullable=False),
    Column("developer_authorization_id", String(200)),
    Column("detail_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
)

TEMPLATE_UNKNOWN_SAMPLES = Table(
    "template_unknown_samples",
    METADATA,
    Column("sample_id", String(32), primary_key=True),
    Column(
        "image_sha256",
        String(64),
        ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("source_kind", String(20), nullable=False),
    Column(
        "source_evaluation_id",
        String(100),
        ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
    ),
    Column("unknown_reason", String(500), nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("idempotency_key", String(200), nullable=False, unique=True),
    Column("request_hash", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "source_kind IN ('development', 'calibration')",
        name="ck_template_unknown_samples_source_kind",
    ),
)

LOCKED_SET_EXCLUSION_INVENTORY = Table(
    "locked_set_exclusion_inventory",
    METADATA,
    Column("entry_sequence", Integer, primary_key=True, autoincrement=True),
    Column("category", String(40), nullable=False),
    Column("identity_sha256", String(64), nullable=False),
    Column("source_kind", String(50), nullable=False),
    Column("source_id", String(200), nullable=False),
    Column("perceptual_fingerprint_json", Text),
    Column("fingerprint_sha256", String(64)),
    Column("algorithm_version", String(100)),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "category IN ("
        "'template_reference_image', "
        "'development_image', "
        "'calibration_image', "
        "'shadow_image', "
        "'prior_locked_image', "
        "'prior_waybill_identity'"
        ")",
        name="ck_locked_set_exclusion_inventory_category",
    ),
    CheckConstraint(
        "length(identity_sha256) = 64",
        name="ck_locked_set_exclusion_inventory_sha256_length",
    ),
    CheckConstraint(
        "(perceptual_fingerprint_json IS NULL "
        "AND fingerprint_sha256 IS NULL "
        "AND algorithm_version IS NULL) "
        "OR (perceptual_fingerprint_json IS NOT NULL "
        "AND fingerprint_sha256 IS NOT NULL "
        "AND algorithm_version IS NOT NULL)",
        name="ck_locked_set_exclusion_inventory_fingerprint_triplet",
    ),
    UniqueConstraint(
        "category",
        "identity_sha256",
        "source_kind",
        "source_id",
        name="uq_locked_set_exclusion_inventory_source",
    ),
)

LOCKED_SET_EXCLUSION_SNAPSHOTS = Table(
    "locked_set_exclusion_snapshots",
    METADATA,
    Column("snapshot_id", String(64), primary_key=True),
    Column("source_id", String(200), nullable=False),
    Column("inventory_high_watermark", Integer, nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("canonical_sha256", String(64), nullable=False, unique=True),
    Column("template_reference_count", Integer, nullable=False),
    Column("development_count", Integer, nullable=False),
    Column("calibration_count", Integer, nullable=False),
    Column("shadow_count", Integer, nullable=False),
    Column("prior_locked_count", Integer, nullable=False),
    Column("prior_waybill_count", Integer, nullable=False),
    Column("inventory_image_count", Integer, nullable=False),
    Column("fingerprinted_image_count", Integer, nullable=False),
    Column("missing_fingerprint_count", Integer, nullable=False),
    Column("fingerprint_algorithm_versions_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "inventory_high_watermark >= 0",
        name="ck_locked_set_exclusion_snapshots_watermark",
    ),
    CheckConstraint(
        "template_reference_count >= 0 "
        "AND development_count >= 0 "
        "AND calibration_count >= 0 "
        "AND shadow_count >= 0 "
        "AND prior_locked_count >= 0 "
        "AND prior_waybill_count >= 0 "
        "AND inventory_image_count >= 0 "
        "AND fingerprinted_image_count >= 0 "
        "AND missing_fingerprint_count >= 0 "
        "AND fingerprinted_image_count + missing_fingerprint_count "
        "= inventory_image_count",
        name="ck_locked_set_exclusion_snapshots_counts",
    ),
)

LOCKED_SET_DATASETS = Table(
    "locked_set_datasets",
    METADATA,
    Column("dataset_id", String(200), primary_key=True),
    Column("manifest_sha256", String(64), nullable=False, unique=True),
    Column("member_identity_sha256", String(64), nullable=False, unique=True),
    Column("manifest_json", Text, nullable=False),
    Column("state", String(40), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("created_by", String(200), nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "state IN ('sealed', 'preflight_passed', 'formal_evaluated', 'invalidated_to_development')",
        name="ck_locked_set_datasets_state",
    ),
    CheckConstraint(
        "record_version >= 1",
        name="ck_locked_set_datasets_record_version",
    ),
)

_LOCKED_SET_CANDIDATE_AUTHORITY_SHA256_COLUMNS = (
    "manifest_sha256",
    "seal_sha256",
    "package_sha256",
    "record_set_sha256",
    "review_history_authority_sha256",
    "source_authority_sha256",
)

LOCKED_SET_CANDIDATE_REVIEW_SOURCE_AUTHORITY = Table(
    "locked_set_candidate_review_source_authority",
    METADATA,
    Column(
        "dataset_id",
        String(200),
        ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    *(
        Column(column, String(64), nullable=False)
        for column in _LOCKED_SET_CANDIDATE_AUTHORITY_SHA256_COLUMNS
    ),
    Column("payload_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        " AND ".join(
            f"length({column}) = 64 "
            f"AND {column} = lower({column}) "
            f"AND {column} NOT GLOB '*[^0-9a-f]*'"
            for column in _LOCKED_SET_CANDIDATE_AUTHORITY_SHA256_COLUMNS
        ),
        name="ck_locked_set_candidate_review_source_authority_hashes",
    ),
)

_LOCKED_SET_DEVELOPMENT_AUTHORITY_SHA256_COLUMNS = (
    "manifest_sha256",
    "authority_sha256",
    "source_exclusion_snapshot_sha256",
    "formal_exclusion_snapshot_sha256",
    "shadow_template_set_fingerprint",
)

LOCKED_SET_DEVELOPMENT_AUTHORITY = Table(
    "locked_set_development_authority",
    METADATA,
    Column(
        "dataset_id",
        String(200),
        ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    *(
        Column(column, String(64), nullable=False)
        for column in _LOCKED_SET_DEVELOPMENT_AUTHORITY_SHA256_COLUMNS
    ),
    Column("source_inventory_high_watermark", Integer, nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        " AND ".join(
            f"length({column}) = 64 "
            f"AND {column} = lower({column}) "
            f"AND {column} NOT GLOB '*[^0-9a-f]*'"
            for column in _LOCKED_SET_DEVELOPMENT_AUTHORITY_SHA256_COLUMNS
        ),
        name="ck_locked_set_development_authority_hashes",
    ),
    CheckConstraint(
        "source_inventory_high_watermark >= 1",
        name="ck_locked_set_development_authority_watermark",
    ),
)

LOCKED_SET_PREFLIGHT_ATTESTATIONS = Table(
    "locked_set_preflight_attestations",
    METADATA,
    Column("attestation_id", String(64), primary_key=True),
    Column(
        "dataset_id",
        String(200),
        ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("manifest_sha256", String(64), nullable=False),
    Column(
        "exclusion_snapshot_id",
        String(64),
        ForeignKey(
            "locked_set_exclusion_snapshots.snapshot_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("exclusion_snapshot_sha256", String(64), nullable=False),
    Column("exclusion_source_id", String(200), nullable=False),
    Column("inventory_high_watermark", Integer, nullable=False),
    Column("waybill_count", Integer, nullable=False),
    Column("image_count", Integer, nullable=False),
    Column("total_bytes", Integer, nullable=False),
    Column("attestation_sha256", String(64), nullable=False, unique=True),
    Column("actor_id", String(200), nullable=False),
    Column("completed_at", String(40), nullable=False),
    CheckConstraint(
        "inventory_high_watermark >= 0",
        name="ck_locked_set_preflight_attestations_watermark",
    ),
    CheckConstraint(
        "waybill_count = 50 AND image_count = 100 AND total_bytes > 0",
        name="ck_locked_set_preflight_attestations_counts",
    ),
    UniqueConstraint(
        "dataset_id",
        "exclusion_snapshot_id",
        name="uq_locked_set_preflight_dataset_snapshot",
    ),
)

LOCKED_SET_SIMILARITY_SCANS = Table(
    "locked_set_similarity_scans",
    METADATA,
    Column("scan_id", String(64), primary_key=True),
    Column(
        "dataset_id",
        String(200),
        ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("manifest_sha256", String(64), nullable=False),
    Column(
        "exclusion_snapshot_id",
        String(64),
        ForeignKey(
            "locked_set_exclusion_snapshots.snapshot_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("exclusion_snapshot_sha256", String(64), nullable=False),
    Column("inventory_high_watermark", Integer, nullable=False),
    Column("scan_json", Text, nullable=False),
    Column("scan_fingerprint", String(64), nullable=False, unique=True),
    Column("detector_fingerprint", String(64), nullable=False),
    Column("locked_image_count", Integer, nullable=False),
    Column("excluded_image_count", Integer, nullable=False),
    Column("candidate_count", Integer, nullable=False),
    Column("locked_image_fingerprints_json", Text, nullable=False),
    Column("locked_image_fingerprints_sha256", String(64), nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("completed_at", String(40), nullable=False),
    CheckConstraint(
        "inventory_high_watermark >= 0",
        name="ck_locked_set_similarity_scans_watermark",
    ),
    CheckConstraint(
        "locked_image_count = 100 AND excluded_image_count >= 0 AND candidate_count >= 0",
        name="ck_locked_set_similarity_scans_counts",
    ),
)

LOCKED_SET_FORMAL_EVALUATIONS = Table(
    "locked_set_formal_evaluations",
    METADATA,
    Column("evaluation_id", String(64), primary_key=True),
    Column(
        "dataset_id",
        String(200),
        ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("manifest_sha256", String(64), nullable=False),
    Column(
        "exclusion_snapshot_id",
        String(64),
        ForeignKey(
            "locked_set_exclusion_snapshots.snapshot_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("exclusion_snapshot_sha256", String(64), nullable=False),
    Column("inventory_high_watermark", Integer, nullable=False),
    Column(
        "preflight_attestation_id",
        String(64),
        ForeignKey(
            "locked_set_preflight_attestations.attestation_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column(
        "scan_id",
        String(64),
        ForeignKey("locked_set_similarity_scans.scan_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("scan_fingerprint", String(64), nullable=False),
    Column("idempotency_key", String(200), nullable=False, unique=True),
    Column("request_hash", String(64), nullable=False),
    Column("runner_report_json", Text, nullable=False),
    Column("runner_report_sha256", String(64), nullable=False),
    Column("committed_report_json", Text, nullable=False),
    Column("committed_report_sha256", String(64), nullable=False),
    Column("quality_coverage_json", Text, nullable=False),
    Column("quality_coverage_sha256", String(64), nullable=False),
    Column("decision_set_json", Text, nullable=False),
    Column("decision_set_sha256", String(64), nullable=False),
    Column("run_context_sha256", String(64), nullable=False),
    Column("gate_passed", Integer, nullable=False),
    Column("formal_report", Integer, nullable=False),
    Column("formal_accuracy_claim", Integer, nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("completed_at", String(40), nullable=False),
    CheckConstraint(
        "inventory_high_watermark >= 0",
        name="ck_locked_set_formal_evaluations_watermark",
    ),
    CheckConstraint(
        "gate_passed IN (0, 1) "
        "AND formal_report = 1 "
        "AND formal_accuracy_claim IN (0, 1) "
        "AND (formal_accuracy_claim = 0 OR gate_passed = 1)",
        name="ck_locked_set_formal_evaluations_claim",
    ),
)

LOCKED_SET_INVALIDATIONS = Table(
    "locked_set_invalidations",
    METADATA,
    Column("invalidation_id", String(32), primary_key=True),
    Column(
        "dataset_id",
        String(200),
        ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("influence_kind", String(40), nullable=False),
    Column("reason", String(500), nullable=False),
    Column("actor_id", String(200), nullable=False),
    Column("idempotency_key", String(200), nullable=False, unique=True),
    Column("request_hash", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "influence_kind IN ("
        "'code', 'preprocessing', 'configuration', 'template', 'model', "
        "'threshold', 'rule', 'mapping', 'adapter', 'error_handling', 'label'"
        ")",
        name="ck_locked_set_invalidations_influence_kind",
    ),
)

LOCKED_SET_REVIEW_ITEMS = Table(
    "locked_set_review_items",
    METADATA,
    Column("package_sha256", String(64), primary_key=True),
    Column("sample_id", String(100), primary_key=True),
    Column("record_version", Integer, primary_key=True),
    Column("review_status", String(30), nullable=False),
    Column("decision", String(30), nullable=False),
    Column("review_payload_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "length(package_sha256) = 64",
        name="ck_locked_set_review_items_package_sha256",
    ),
    CheckConstraint(
        "review_status IN ('confirmed', 'replace_candidate')",
        name="ck_locked_set_review_items_status",
    ),
    CheckConstraint(
        "decision IN ('confirmed', 'replace_candidate') "
        "AND decision = review_status",
        name="ck_locked_set_review_items_decision",
    ),
    CheckConstraint(
        "record_version >= 1",
        name="ck_locked_set_review_items_record_version",
    ),
)

LOCKED_SET_REVIEW_IDEMPOTENCY = Table(
    "locked_set_review_idempotency",
    METADATA,
    Column("package_sha256", String(64), primary_key=True),
    Column("idempotency_key", String(200), primary_key=True),
    Column("sample_id", String(100), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("resulting_record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    ForeignKeyConstraint(
        [
            "package_sha256",
            "sample_id",
            "resulting_record_version",
        ],
        [
            "locked_set_review_items.package_sha256",
            "locked_set_review_items.sample_id",
            "locked_set_review_items.record_version",
        ],
        ondelete="RESTRICT",
    ),
    CheckConstraint(
        "length(package_sha256) = 64 AND length(request_hash) = 64",
        name="ck_locked_set_review_idempotency_hashes",
    ),
    CheckConstraint(
        "resulting_record_version >= 1",
        name="ck_locked_set_review_idempotency_record_version",
    ),
)

AUDIT_EVIDENCE_REVISIONS = Table(
    "audit_evidence_revisions",
    METADATA,
    Column("evidence_revision_id", String(32), primary_key=True),
    Column(
        "work_item_id",
        String(32),
        ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("revision_number", Integer, nullable=False),
    Column("platform_snapshot_sha256", String(64), nullable=False),
    Column("loading_image_sha256", String(64)),
    Column("unloading_image_sha256", String(64)),
    Column("payload_json", Text, nullable=False),
    Column("fingerprint", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint(
        "work_item_id",
        "revision_number",
        name="uq_audit_evidence_revision_number",
    ),
)

AUDIT_OCR_OBSERVATIONS = Table(
    "audit_ocr_observations",
    METADATA,
    Column("ocr_observation_id", String(32), primary_key=True),
    Column(
        "evidence_revision_id",
        String(32),
        ForeignKey(
            "audit_evidence_revisions.evidence_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("image_role", String(20), nullable=False),
    Column("image_sha256", String(64), nullable=False),
    Column("pipeline_fingerprint", String(64), nullable=False),
    Column("template_version_id", String(64)),
    Column("runtime_kind", String(20), nullable=False),
    Column("runtime_fingerprint", String(64), nullable=False),
    Column("ticket_role", String(20), nullable=False),
    Column("ordinary_net_raw", String(100)),
    Column("ordinary_net_normalized", String(40)),
    Column("unit", String(20)),
    Column("reliable", Integer, nullable=False),
    Column("anomaly_reason", String(100)),
    Column("payload_json", Text, nullable=False),
    Column("observation_sha256", String(64), nullable=False, unique=True),
    Column("created_at", String(40), nullable=False),
)

AUDIT_DECISION_REVISIONS = Table(
    "audit_decision_revisions",
    METADATA,
    Column("decision_revision_id", String(32), primary_key=True),
    Column(
        "work_item_id",
        String(32),
        ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "evidence_revision_id",
        String(32),
        ForeignKey(
            "audit_evidence_revisions.evidence_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("revision_number", Integer, nullable=False),
    Column("rules_fingerprint", String(64), nullable=False),
    Column("business_outcome", String(50), nullable=False),
    Column("review_reason", String(100)),
    Column("decision", String(30), nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("fingerprint", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint(
        "work_item_id",
        "revision_number",
        name="uq_audit_decision_revision_number",
    ),
)

AUDIT_REVIEW_ACTIONS = Table(
    "audit_review_actions",
    METADATA,
    Column("action_id", String(32), primary_key=True),
    Column(
        "work_item_id",
        String(32),
        ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column(
        "evidence_revision_id",
        String(32),
        ForeignKey(
            "audit_evidence_revisions.evidence_revision_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("action_type", String(40), nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("correct_value", String(40)),
    Column("note", String(500)),
    Column(
        "revokes_action_id",
        String(32),
        ForeignKey("audit_review_actions.action_id", ondelete="RESTRICT"),
    ),
    Column("record_version", Integer, nullable=False),
    Column("idempotency_key", String(200), nullable=False, unique=True),
    Column("request_hash", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
)

AUDIT_TIMELINE_EVENTS = Table(
    "audit_timeline_events",
    METADATA,
    Column("timeline_event_id", String(32), primary_key=True),
    Column(
        "work_item_id",
        String(32),
        ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("event_type", String(100), nullable=False),
    Column("reference_id", String(32)),
    Column("payload_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
)

DAILY_CAPTURE_INVOCATIONS = Table(
    "daily_capture_invocations",
    METADATA,
    Column("invocation_id", String(100), primary_key=True),
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    ),
    Column(
        "access_window_id",
        String(32),
        ForeignKey(
            "platform_access_windows.access_window_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("request_fingerprint", String(64), nullable=False),
    Column("request_json", Text, nullable=False),
    Column("authority_json", Text),
    Column("checkpoint_json", Text),
    Column("next_stage", String(100), nullable=False),
    Column("status", String(32), nullable=False),
    Column("diagnostic_code", String(100)),
    Column("record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "length(request_fingerprint) = 64 "
        "AND record_version >= 1 "
        "AND status IN ('ready', 'running', 'succeeded', 'failed')",
        name="ck_daily_capture_invocation_shape",
    ),
)

DAILY_CAPTURE_START_REQUESTS = Table(
    "daily_capture_start_requests",
    METADATA,
    Column("idempotency_key", String(200), primary_key=True),
    Column("request_hash", String(64), nullable=False),
    Column(
        "job_id",
        String(32),
        ForeignKey("jobs.job_id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    ),
    Column(
        "access_window_id",
        String(32),
        ForeignKey(
            "platform_access_windows.access_window_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("status", String(32), nullable=False),
    Column("invocation_id", String(100)),
    Column("record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "length(request_hash) = 64 "
        "AND record_version >= 1 "
        "AND status IN ('reserved', 'completed') "
        "AND ((status = 'reserved' AND invocation_id IS NULL) "
        "OR (status = 'completed' AND invocation_id IS NOT NULL))",
        name="ck_daily_capture_start_request_shape",
    ),
)

DAILY_CANDIDATE_SNAPSHOTS = Table(
    "daily_candidate_snapshots",
    METADATA,
    Column("snapshot_id", String(100), primary_key=True),
    Column("target_business_date", String(10), nullable=False),
    Column("query_started_at", String(40), nullable=False),
    Column("query_ended_at", String(40), nullable=False),
    Column("query_safety_ended_at", String(40), nullable=False),
    Column("source_contract_sha256", String(64), nullable=False),
    Column("candidate_count", Integer, nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("fingerprint", String(64), nullable=False, unique=True),
    Column("captured_at", String(40), nullable=False),
    CheckConstraint(
        "candidate_count >= 0 "
        "AND length(source_contract_sha256) = 64 "
        "AND length(fingerprint) = 64",
        name="ck_daily_candidate_snapshot_shape",
    ),
)

DAILY_OBSERVATIONS = Table(
    "daily_observations",
    METADATA,
    Column("observation_id", String(100), primary_key=True),
    Column(
        "snapshot_id",
        String(100),
        ForeignKey(
            "daily_candidate_snapshots.snapshot_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
    ),
    Column("platform_waybill_id", String(200), nullable=False),
    Column("waybill_number", String(200)),
    Column("source_detail_sha256", String(64), nullable=False),
    Column("loading_ticket_sha256", String(64)),
    Column("unloading_ticket_sha256", String(64)),
    Column("field_fingerprint", String(64), nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("observation_fingerprint", String(64), nullable=False, unique=True),
    Column("observed_at", String(40), nullable=False),
    CheckConstraint(
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

DAILY_RECORD_REVISIONS = Table(
    "daily_record_revisions",
    METADATA,
    Column("revision_id", String(32), primary_key=True),
    Column("platform_waybill_id", String(200), nullable=False),
    Column("revision_number", Integer, nullable=False),
    Column(
        "observation_id",
        String(100),
        ForeignKey("daily_observations.observation_id", ondelete="RESTRICT"),
        nullable=False,
        unique=True,
    ),
    Column("field_fingerprint", String(64), nullable=False),
    Column("payload_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint(
        "platform_waybill_id",
        "revision_number",
        name="uq_daily_record_revision_number",
    ),
    CheckConstraint(
        "revision_number >= 1 AND length(field_fingerprint) = 64",
        name="ck_daily_record_revision_shape",
    ),
)

DAILY_MANUAL_REVISIONS = Table(
    "daily_manual_revisions",
    METADATA,
    Column("action_id", String(32), primary_key=True),
    Column("platform_waybill_id", String(200), nullable=False),
    Column("manual_revision_number", Integer, nullable=False),
    Column(
        "base_observation_id",
        String(100),
        ForeignKey("daily_observations.observation_id", ondelete="RESTRICT"),
        nullable=False,
    ),
    Column("base_loading_ticket_sha256", String(64)),
    Column("base_unloading_ticket_sha256", String(64)),
    Column("changes_json", Text, nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("created_at", String(40), nullable=False),
    UniqueConstraint(
        "platform_waybill_id",
        "manual_revision_number",
        name="uq_daily_manual_revision_number",
    ),
    CheckConstraint(
        "manual_revision_number >= 1 AND length(request_hash) = 64 "
        "AND (base_loading_ticket_sha256 IS NULL "
        "OR length(base_loading_ticket_sha256) = 64) "
        "AND (base_unloading_ticket_sha256 IS NULL "
        "OR length(base_unloading_ticket_sha256) = 64)",
        name="ck_daily_manual_revision_shape",
    ),
)

DAILY_MANUAL_REVISION_IDEMPOTENCY = Table(
    "daily_manual_revision_idempotency",
    METADATA,
    Column("idempotency_key", String(200), primary_key=True),
    Column("request_hash", String(64), nullable=False),
    Column("platform_waybill_id", String(200), nullable=False),
    Column("action_id", String(32), nullable=False),
    Column("result_record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "length(request_hash) = 64 AND result_record_version >= 1",
        name="ck_daily_manual_revision_idempotency_shape",
    ),
)

PERFORMANCE_SETTINGS = Table(
    "performance_settings",
    METADATA,
    Column("settings_id", String(32), primary_key=True),
    Column("preset", String(20), nullable=False),
    Column("detail_concurrency", Integer, nullable=False),
    Column("image_concurrency", Integer, nullable=False),
    Column("cpu_ocr_threads", Integer, nullable=False),
    Column("gpu_idle_minutes", Integer, nullable=False),
    Column("keep_gpu_ready", Integer, nullable=False),
    Column("network_batch_size", Integer, nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "settings_id = 'primary' AND preset IN ('responsive', 'balanced', 'speed') "
        "AND detail_concurrency BETWEEN 1 AND 4 "
        "AND image_concurrency BETWEEN 1 AND 6 "
        "AND cpu_ocr_threads BETWEEN 1 AND 8 "
        "AND gpu_idle_minutes BETWEEN 0 AND 60 "
        "AND keep_gpu_ready IN (0, 1) "
        "AND network_batch_size IN (20, 50, 100) "
        "AND record_version >= 1",
        name="ck_performance_settings_shape",
    ),
)

DAILY_REPORT_SETTINGS = Table(
    "daily_report_settings",
    METADATA,
    Column("settings_id", String(32), primary_key=True),
    Column("shipping_mine", String(200), nullable=False),
    Column("coal_type", String(200), nullable=False),
    Column("unloading_place", String(200), nullable=False),
    Column("query_place_keyword", String(200), nullable=False),
    Column("output_directory", Text, nullable=False),
    Column("confirmed", Integer, nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("updated_at", String(40), nullable=False),
    CheckConstraint(
        "settings_id = 'primary' AND confirmed IN (0, 1) "
        "AND record_version >= 1",
        name="ck_daily_report_settings_shape",
    ),
)

DAILY_REPORTS = Table(
    "daily_reports",
    METADATA,
    Column("report_id", String(32), primary_key=True),
    Column("business_date", String(10), nullable=False, index=True),
    Column("status", String(32), nullable=False),
    Column("settings_record_version", Integer, nullable=False),
    Column("output_directory", Text, nullable=False),
    Column("file_name", String(255), nullable=False),
    Column("file_sha256", String(64), nullable=False),
    Column("data_snapshot_sha256", String(64), nullable=False),
    Column("data_json", Text, nullable=False),
    Column("row_count", Integer, nullable=False),
    Column("loading_net_total", String(50), nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("created_at", String(40), nullable=False),
    Column("confirmed_at", String(40)),
    Column("stale", Integer, nullable=False, default=0),
    CheckConstraint(
        "status IN ('pending_confirmation', 'confirmed') "
        "AND settings_record_version >= 1 AND row_count >= 0 "
        "AND record_version >= 1 AND length(file_sha256) = 64 "
        "AND length(data_snapshot_sha256) = 64 AND stale IN (0, 1)",
        name="ck_daily_report_shape",
    ),
)

DAILY_REPORT_IDEMPOTENCY = Table(
    "daily_report_idempotency",
    METADATA,
    Column("idempotency_key", String(200), primary_key=True),
    Column("operation", String(40), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("result_json", Text, nullable=False),
    Column("created_at", String(40), nullable=False),
    CheckConstraint(
        "length(request_hash) = 64",
        name="ck_daily_report_idempotency_shape",
    ),
)

PRODUCTION_READ_ONLY_GUARD = Table(
    "production_read_only_guard",
    METADATA,
    Column("guard_id", String(32), primary_key=True),
    Column("status", String(64), nullable=False),
    Column("target_count", Integer, nullable=False),
    Column("registered_count", Integer, nullable=False),
    Column("reviewed_target_count", Integer, nullable=False),
    Column("false_normal_count", Integer, nullable=False),
    Column("record_version", Integer, nullable=False),
    Column("activated_at", String(40), nullable=False),
    Column("resolved_at", String(40)),
    CheckConstraint(
        "guard_id = 'primary' "
        "AND status IN ('operational_read_only_with_guard', "
        "'operational_read_only_accepted', 'operational_read_only_active') "
        "AND target_count = 30 AND registered_count >= 0 "
        "AND reviewed_target_count BETWEEN 0 AND target_count "
        "AND false_normal_count >= 0 AND record_version >= 1",
        name="ck_production_read_only_guard_shape",
    ),
)

PRODUCTION_READ_ONLY_GUARD_ITEMS = Table(
    "production_read_only_guard_items",
    METADATA,
    Column(
        "work_item_id",
        String(32),
        ForeignKey("work_items.work_item_id", ondelete="RESTRICT"),
        primary_key=True,
    ),
    Column("ordinal", Integer, nullable=False, unique=True),
    Column("business_identity_sha256", String(64), nullable=False),
    Column("counts_toward_gate", Integer, nullable=False),
    Column("machine_outcome", String(50), nullable=False),
    Column("manual_outcome", String(50)),
    Column("manual_action_id", String(100), unique=True),
    Column("protected", Integer, nullable=False),
    Column("released", Integer, nullable=False),
    Column("registered_at", String(40), nullable=False),
    Column("reviewed_at", String(40)),
    CheckConstraint(
        "ordinal >= 1 AND counts_toward_gate IN (0, 1) "
        "AND protected IN (0, 1) AND released IN (0, 1) "
        "AND machine_outcome IN ('normal_ready', 'awaiting_review', "
        "'confirmed_problem', 'technical_failure') "
        "AND (manual_outcome IS NULL OR manual_outcome IN "
        "('normal_ready', 'confirmed_problem')) "
        "AND ((manual_outcome IS NULL AND manual_action_id IS NULL "
        "AND reviewed_at IS NULL) OR (manual_outcome IS NOT NULL "
        "AND manual_action_id IS NOT NULL AND reviewed_at IS NOT NULL))",
        name="ck_production_read_only_guard_item_shape",
    ),
    CheckConstraint(
        "length(business_identity_sha256) = 64",
        name="ck_production_guard_business_identity",
    ),
)

Index(
    "ix_production_guard_business_identity",
    PRODUCTION_READ_ONLY_GUARD_ITEMS.c.business_identity_sha256,
)

LOOP3_TABLES = define_loop3_tables(METADATA)
STAGE_ATTEMPTS = LOOP3_TABLES["stage_attempts"]
CHECKPOINTS = LOOP3_TABLES["checkpoints"]
RESOURCE_SLOTS = LOOP3_TABLES["resource_slots"]
LEASES = LOOP3_TABLES["leases"]
CONFLICT_KEYS = LOOP3_TABLES["conflict_keys"]
DEPENDENCIES = LOOP3_TABLES["dependencies"]
SHARED_EVIDENCE_WORK = LOOP3_TABLES["shared_evidence_work"]
SHARED_EVIDENCE_CONSUMERS = LOOP3_TABLES["shared_evidence_consumers"]
CONTROL_IDEMPOTENCY = LOOP3_TABLES["control_idempotency"]
SHARED_WORK_RETRY_REQUESTS = LOOP3_TABLES["shared_work_retry_requests"]
SCHEDULER_META = LOOP3_TABLES["scheduler_meta"]
OCR_RUN_GENERATIONS = LOOP3_TABLES["ocr_run_generations"]
