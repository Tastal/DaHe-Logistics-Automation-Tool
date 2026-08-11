"""Add immutable template versions and shadow publication records.

Revision ID: 0005_loop7_template_studio
Revises: 0004_loop6_image_quanta
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005_loop7_template_studio"
down_revision = "0004_loop6_image_quanta"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "template_reference_uploads",
        sa.Column("staged_reference_id", sa.String(32), primary_key=True),
        sa.Column(
            "image_sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("media_type", sa.String(100), nullable=False),
        sa.Column("width", sa.Integer(), nullable=False),
        sa.Column("height", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(20), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "media_type IN ('image/jpeg', 'image/png')",
            name="ck_template_reference_uploads_media_type",
        ),
        sa.CheckConstraint(
            "width >= 1 AND height >= 1",
            name="ck_template_reference_uploads_dimensions",
        ),
        sa.CheckConstraint(
            "state IN ('staged', 'consumed', 'abandoned')",
            name="ck_template_reference_uploads_state",
        ),
        sa.CheckConstraint(
            "record_version >= 1",
            name="ck_template_reference_uploads_record_version",
        ),
    )
    op.create_table(
        "template_families",
        sa.Column("family_id", sa.String(100), primary_key=True),
        sa.Column("name", sa.String(200), nullable=False),
        sa.Column("role", sa.String(20), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "role IN ('loading', 'unloading')",
            name="ck_template_families_role",
        ),
    )
    op.create_table(
        "template_versions",
        sa.Column("version_id", sa.String(32), primary_key=True),
        sa.Column(
            "family_id",
            sa.String(100),
            sa.ForeignKey("template_families.family_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column(
            "parent_version_id",
            sa.String(32),
            sa.ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
        ),
        sa.Column("definition_json", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column(
            "reference_image_sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "reference_mask_sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("alignment_fingerprint", sa.String(64), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "version_number >= 1",
            name="ck_template_versions_number",
        ),
        sa.UniqueConstraint(
            "family_id",
            "version_number",
            name="uq_template_versions_family_number",
        ),
        sa.UniqueConstraint(
            "family_id",
            "version_id",
            name="uq_template_versions_family_identity",
        ),
    )
    op.create_table(
        "template_version_states",
        sa.Column(
            "version_id",
            sa.String(32),
            sa.ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("lifecycle", sa.String(30), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "lifecycle IN ('draft', 'development_tested', 'shadow')",
            name="ck_template_version_states_lifecycle",
        ),
        sa.CheckConstraint(
            "record_version >= 1",
            name="ck_template_version_states_record_version",
        ),
    )
    op.create_table(
        "template_evaluations",
        sa.Column("evaluation_id", sa.String(100), primary_key=True),
        sa.Column("dataset_kind", sa.String(20), nullable=False),
        sa.Column("dataset_id", sa.String(200), nullable=False),
        sa.Column("dataset_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("template_set_fingerprint", sa.String(64), nullable=False),
        sa.Column("matcher_fingerprint", sa.String(64), nullable=False),
        sa.Column("policy_fingerprint", sa.String(64), nullable=False),
        sa.Column("build_fingerprint", sa.String(64), nullable=False),
        sa.Column("runtime_fingerprint", sa.String(64), nullable=False),
        sa.Column("verification_source", sa.String(30), nullable=False),
        sa.Column("stable_outcome_sha256", sa.String(64)),
        sa.Column("expected_count", sa.Integer(), nullable=False),
        sa.Column("result_count", sa.Integer(), nullable=False),
        sa.Column("metrics_json", sa.Text(), nullable=False),
        sa.Column("metrics_sha256", sa.String(64), nullable=False),
        sa.Column("gate_passed", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "dataset_kind IN ('development', 'locked', 'shadow')",
            name="ck_template_evaluations_dataset_kind",
        ),
        sa.CheckConstraint(
            "expected_count >= 1 AND result_count = expected_count",
            name="ck_template_evaluations_reconciled_counts",
        ),
        sa.CheckConstraint(
            "gate_passed IN (0, 1)",
            name="ck_template_evaluations_gate_passed",
        ),
        sa.CheckConstraint(
            "verification_source IN ('untrusted_record', 'frozen_runner')",
            name="ck_template_evaluations_verification_source",
        ),
        sa.CheckConstraint(
            "(verification_source = 'frozen_runner' "
            "AND stable_outcome_sha256 IS NOT NULL) "
            "OR (verification_source = 'untrusted_record' "
            "AND stable_outcome_sha256 IS NULL)",
            name="ck_template_evaluations_verification_evidence",
        ),
    )
    op.create_table(
        "template_evaluation_candidates",
        sa.Column(
            "evaluation_id",
            sa.String(100),
            sa.ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("family_id", sa.String(100), nullable=False),
        sa.Column("version_id", sa.String(32), nullable=False),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("evaluated_lifecycle", sa.String(30), nullable=False),
        sa.ForeignKeyConstraint(
            ["family_id", "version_id"],
            ["template_versions.family_id", "template_versions.version_id"],
            name="fk_template_evaluation_candidate_version",
            ondelete="RESTRICT",
        ),
        sa.UniqueConstraint(
            "evaluation_id",
            "family_id",
            name="uq_template_evaluation_candidate_family",
        ),
        sa.UniqueConstraint(
            "evaluation_id",
            "version_id",
            name="uq_template_evaluation_candidate_version",
        ),
        sa.CheckConstraint(
            "evaluated_lifecycle IN ('draft', 'development_tested', 'shadow')",
            name="ck_template_evaluation_candidate_lifecycle",
        ),
    )
    op.create_table(
        "template_evaluation_items",
        sa.Column("item_id", sa.String(32), primary_key=True),
        sa.Column(
            "evaluation_id",
            sa.String(100),
            sa.ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("sample_id", sa.String(200), nullable=False),
        sa.Column("waybill_id", sa.String(200), nullable=False),
        sa.Column("image_sha256", sa.String(64), nullable=False),
        sa.Column("truth", sa.String(20), nullable=False),
        sa.Column("prediction", sa.String(20), nullable=False),
        sa.Column("confidence", sa.String(40), nullable=False),
        sa.Column("high_confidence", sa.Integer(), nullable=False),
        sa.Column("orientation_degrees", sa.Integer(), nullable=False),
        sa.Column("evidence_json", sa.Text(), nullable=False),
        sa.Column("assessment_fingerprint", sa.String(64), nullable=False),
        sa.Column("elapsed_ms", sa.String(40), nullable=False),
        sa.Column("pair_issue", sa.String(100)),
        sa.Column("unknown_reason", sa.String(200)),
        sa.CheckConstraint(
            "truth IN ('loading', 'unloading', 'unknown')",
            name="ck_template_evaluation_items_truth",
        ),
        sa.CheckConstraint(
            "prediction IN ('loading', 'unloading', 'unknown')",
            name="ck_template_evaluation_items_prediction",
        ),
        sa.CheckConstraint(
            "high_confidence IN (0, 1)",
            name="ck_template_evaluation_items_high_confidence",
        ),
        sa.CheckConstraint(
            "orientation_degrees IN (0, 90, 180, 270)",
            name="ck_template_evaluation_items_orientation",
        ),
        sa.UniqueConstraint(
            "evaluation_id",
            "sample_id",
            name="uq_template_evaluation_item_sample",
        ),
    )
    op.create_table(
        "template_evaluation_pairs",
        sa.Column("pair_id", sa.String(32), primary_key=True),
        sa.Column(
            "evaluation_id",
            sa.String(100),
            sa.ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("case_id", sa.String(200), nullable=False),
        sa.Column("expected_issue", sa.String(100)),
        sa.Column("result_issue", sa.String(100)),
        sa.Column("expected_matches_result", sa.Integer(), nullable=False),
        sa.CheckConstraint(
            "expected_matches_result IN (0, 1)",
            name="ck_template_evaluation_pairs_match",
        ),
        sa.UniqueConstraint(
            "evaluation_id",
            "case_id",
            name="uq_template_evaluation_pair_case",
        ),
    )
    op.create_table(
        "template_evaluation_invalidations",
        sa.Column("invalidation_id", sa.String(32), primary_key=True),
        sa.Column(
            "evaluation_id",
            sa.String(100),
            sa.ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "template_development_contract_state",
        sa.Column("singleton_id", sa.Integer(), primary_key=True),
        sa.Column(
            "development_manifest_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "evaluation_id",
            sa.String(100),
            sa.ForeignKey(
                "template_evaluations.evaluation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "singleton_id = 1",
            name="ck_template_development_contract_singleton",
        ),
        sa.CheckConstraint(
            "record_version >= 1",
            name="ck_template_development_contract_record_version",
        ),
    )
    op.create_table(
        "template_lifecycle_events",
        sa.Column("event_id", sa.String(32), primary_key=True),
        sa.Column(
            "version_id",
            sa.String(32),
            sa.ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("operation", sa.String(50), nullable=False),
        sa.Column("from_lifecycle", sa.String(30)),
        sa.Column("to_lifecycle", sa.String(30), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column(
            "evaluation_id",
            sa.String(100),
            sa.ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
        ),
        sa.Column("developer_authorization_id", sa.String(200)),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "to_lifecycle IN ('draft', 'development_tested', 'shadow')",
            name="ck_template_lifecycle_events_to_lifecycle",
        ),
        sa.CheckConstraint(
            "from_lifecycle IS NULL OR from_lifecycle IN ('draft', 'development_tested', 'shadow')",
            name="ck_template_lifecycle_events_from_lifecycle",
        ),
        sa.CheckConstraint(
            "record_version >= 1",
            name="ck_template_lifecycle_events_record_version",
        ),
        sa.UniqueConstraint(
            "version_id",
            "record_version",
            name="uq_template_lifecycle_events_version_record",
        ),
    )
    op.create_table(
        "template_shadow_pointers",
        sa.Column(
            "family_id",
            sa.String(100),
            sa.ForeignKey("template_families.family_id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column("version_id", sa.String(32), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["family_id", "version_id"],
            ["template_versions.family_id", "template_versions.version_id"],
            name="fk_template_shadow_pointer_family_version",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "record_version >= 1",
            name="ck_template_shadow_pointers_record_version",
        ),
    )
    op.create_table(
        "template_idempotency_records",
        sa.Column("operation", sa.String(50), primary_key=True),
        sa.Column("idempotency_key", sa.String(200), primary_key=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("result_kind", sa.String(20), nullable=False),
        sa.Column("result_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "result_kind IN ('version', 'shadow_pointer', 'reference_upload', 'template_evidence')",
            name="ck_template_idempotency_result_kind",
        ),
    )
    op.create_table(
        "template_audit_events",
        sa.Column("audit_id", sa.String(32), primary_key=True),
        sa.Column("event_kind", sa.String(50), nullable=False),
        sa.Column(
            "family_id",
            sa.String(100),
            sa.ForeignKey("template_families.family_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "version_id",
            sa.String(32),
            sa.ForeignKey("template_versions.version_id", ondelete="RESTRICT"),
        ),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("developer_authorization_id", sa.String(200)),
        sa.Column("detail_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_table(
        "template_unknown_samples",
        sa.Column("sample_id", sa.String(32), primary_key=True),
        sa.Column(
            "image_sha256",
            sa.String(64),
            sa.ForeignKey("evidence_blobs.sha256", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_kind", sa.String(20), nullable=False),
        sa.Column(
            "source_evaluation_id",
            sa.String(100),
            sa.ForeignKey("template_evaluations.evaluation_id", ondelete="RESTRICT"),
        ),
        sa.Column("unknown_reason", sa.String(500), nullable=False),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "source_kind IN ('development', 'calibration')",
            name="ck_template_unknown_samples_source_kind",
        ),
    )

    for table_name in (
        "template_versions",
        "template_evaluations",
        "template_evaluation_candidates",
        "template_evaluation_items",
        "template_evaluation_pairs",
        "template_evaluation_invalidations",
        "template_lifecycle_events",
        "template_audit_events",
        "template_unknown_samples",
    ):
        op.execute(
            f"""
            CREATE TRIGGER {table_name}_immutable_update
            BEFORE UPDATE ON {table_name}
            BEGIN
                SELECT RAISE(ABORT, '{table_name} is append-only');
            END
            """
        )
        op.execute(
            f"""
            CREATE TRIGGER {table_name}_immutable_delete
            BEFORE DELETE ON {table_name}
            BEGIN
                SELECT RAISE(ABORT, '{table_name} is append-only');
            END
            """
        )


def downgrade() -> None:
    for table_name in (
        "template_unknown_samples",
        "template_audit_events",
        "template_lifecycle_events",
        "template_evaluation_invalidations",
        "template_evaluation_pairs",
        "template_evaluation_items",
        "template_evaluation_candidates",
        "template_evaluations",
        "template_versions",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS {table_name}_immutable_delete")
        op.execute(f"DROP TRIGGER IF EXISTS {table_name}_immutable_update")
    op.drop_table("template_unknown_samples")
    op.drop_table("template_audit_events")
    op.drop_table("template_idempotency_records")
    op.drop_table("template_reference_uploads")
    op.drop_table("template_shadow_pointers")
    op.drop_table("template_lifecycle_events")
    op.drop_table("template_development_contract_state")
    op.drop_table("template_evaluation_invalidations")
    op.drop_table("template_evaluation_pairs")
    op.drop_table("template_evaluation_items")
    op.drop_table("template_evaluation_candidates")
    op.drop_table("template_evaluations")
    op.drop_table("template_version_states")
    op.drop_table("template_versions")
    op.drop_table("template_families")
