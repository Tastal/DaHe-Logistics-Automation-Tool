"""Add durable locked-set authority and exclusion inventory.

Revision ID: 0006_loop7_locked_set_authority
Revises: 0005_loop7_template_studio
"""

from __future__ import annotations

import hashlib

import sqlalchemy as sa
from alembic import op

revision = "0006_loop7_locked_set_authority"
down_revision = "0005_loop7_template_studio"
branch_labels = None
depends_on = None

_EXCLUSION_CATEGORIES = (
    "template_reference_image",
    "development_image",
    "calibration_image",
    "shadow_image",
    "prior_locked_image",
    "prior_waybill_identity",
)


def _legacy_waybill_identity(value: str) -> str:
    return hashlib.sha256(
        b"dahe:persisted-waybill-identity:v1\0" + value.encode("utf-8")
    ).hexdigest()


def _insert_inventory(
    connection: sa.Connection,
    *,
    category: str,
    identity_sha256: str,
    source_kind: str,
    source_id: str,
    created_at: str,
) -> None:
    connection.execute(
        sa.text(
            """
            INSERT OR IGNORE INTO locked_set_exclusion_inventory (
                category, identity_sha256, source_kind, source_id,
                perceptual_fingerprint_json, fingerprint_sha256,
                algorithm_version, created_at
            ) VALUES (
                :category, :identity_sha256, :source_kind, :source_id,
                NULL, NULL, NULL, :created_at
            )
            """
        ),
        {
            "category": category,
            "identity_sha256": identity_sha256,
            "source_kind": source_kind,
            "source_id": source_id,
            "created_at": created_at,
        },
    )


def _backfill_inventory() -> None:
    connection = op.get_bind()
    template_rows = connection.execute(
        sa.text(
            """
            SELECT version_id, reference_image_sha256, created_at
            FROM template_versions
            ORDER BY version_id
            """
        )
    ).mappings()
    for row in template_rows:
        _insert_inventory(
            connection,
            category="template_reference_image",
            identity_sha256=str(row["reference_image_sha256"]),
            source_kind="template_version",
            source_id=str(row["version_id"]),
            created_at=str(row["created_at"]),
        )

    evaluation_rows = connection.execute(
        sa.text(
            """
            SELECT
                evaluation.evaluation_id,
                evaluation.dataset_kind,
                evaluation.completed_at,
                item.sample_id,
                item.image_sha256,
                item.waybill_id,
                evidence.sha256 AS evidence_sha256
            FROM template_evaluation_items AS item
            JOIN template_evaluations AS evaluation
              ON evaluation.evaluation_id = item.evaluation_id
            LEFT JOIN evidence_blobs AS evidence
              ON evidence.sha256 = item.image_sha256
             AND evidence.storage_state = 'available'
            WHERE evaluation.dataset_kind IN ('development', 'shadow', 'locked')
            ORDER BY evaluation.evaluation_id, item.sample_id
            """
        )
    ).mappings()
    for row in evaluation_rows:
        dataset_kind = str(row["dataset_kind"])
        if row["evidence_sha256"] is not None:
            category = "prior_locked_image" if dataset_kind == "locked" else f"{dataset_kind}_image"
            _insert_inventory(
                connection,
                category=category,
                identity_sha256=str(row["image_sha256"]),
                source_kind=f"{dataset_kind}_evaluation",
                source_id=f"{row['evaluation_id']}:{row['sample_id']}",
                created_at=str(row["completed_at"]),
            )
        _insert_inventory(
            connection,
            category="prior_waybill_identity",
            identity_sha256=_legacy_waybill_identity(str(row["waybill_id"])),
            source_kind="legacy_evaluation_waybill",
            source_id=f"{row['evaluation_id']}:{row['waybill_id']}",
            created_at=str(row["completed_at"]),
        )

    unknown_rows = connection.execute(
        sa.text(
            """
            SELECT sample_id, image_sha256, source_kind, created_at
            FROM template_unknown_samples
            ORDER BY sample_id
            """
        )
    ).mappings()
    for row in unknown_rows:
        source_kind = str(row["source_kind"])
        _insert_inventory(
            connection,
            category=f"{source_kind}_image",
            identity_sha256=str(row["image_sha256"]),
            source_kind="template_unknown_sample",
            source_id=str(row["sample_id"]),
            created_at=str(row["created_at"]),
        )


def upgrade() -> None:
    op.create_table(
        "locked_set_exclusion_inventory",
        sa.Column(
            "entry_sequence",
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("identity_sha256", sa.String(64), nullable=False),
        sa.Column("source_kind", sa.String(50), nullable=False),
        sa.Column("source_id", sa.String(200), nullable=False),
        sa.Column("perceptual_fingerprint_json", sa.Text()),
        sa.Column("fingerprint_sha256", sa.String(64)),
        sa.Column("algorithm_version", sa.String(100)),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "category IN (" + ", ".join(f"'{value}'" for value in _EXCLUSION_CATEGORIES) + ")",
            name="ck_locked_set_exclusion_inventory_category",
        ),
        sa.CheckConstraint(
            "length(identity_sha256) = 64",
            name="ck_locked_set_exclusion_inventory_sha256_length",
        ),
        sa.CheckConstraint(
            "(perceptual_fingerprint_json IS NULL "
            "AND fingerprint_sha256 IS NULL "
            "AND algorithm_version IS NULL) "
            "OR (perceptual_fingerprint_json IS NOT NULL "
            "AND fingerprint_sha256 IS NOT NULL "
            "AND algorithm_version IS NOT NULL)",
            name="ck_locked_set_exclusion_inventory_fingerprint_triplet",
        ),
        sa.UniqueConstraint(
            "category",
            "identity_sha256",
            "source_kind",
            "source_id",
            name="uq_locked_set_exclusion_inventory_source",
        ),
    )
    op.create_table(
        "locked_set_exclusion_snapshots",
        sa.Column("snapshot_id", sa.String(64), primary_key=True),
        sa.Column("source_id", sa.String(200), nullable=False),
        sa.Column("inventory_high_watermark", sa.Integer(), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("canonical_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("template_reference_count", sa.Integer(), nullable=False),
        sa.Column("development_count", sa.Integer(), nullable=False),
        sa.Column("calibration_count", sa.Integer(), nullable=False),
        sa.Column("shadow_count", sa.Integer(), nullable=False),
        sa.Column("prior_locked_count", sa.Integer(), nullable=False),
        sa.Column("prior_waybill_count", sa.Integer(), nullable=False),
        sa.Column("inventory_image_count", sa.Integer(), nullable=False),
        sa.Column("fingerprinted_image_count", sa.Integer(), nullable=False),
        sa.Column("missing_fingerprint_count", sa.Integer(), nullable=False),
        sa.Column(
            "fingerprint_algorithm_versions_json",
            sa.Text(),
            nullable=False,
        ),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "inventory_high_watermark >= 0",
            name="ck_locked_set_exclusion_snapshots_watermark",
        ),
        sa.CheckConstraint(
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
    op.create_table(
        "locked_set_datasets",
        sa.Column("dataset_id", sa.String(200), primary_key=True),
        sa.Column("manifest_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "member_identity_sha256",
            sa.String(64),
            nullable=False,
            unique=True,
        ),
        sa.Column("manifest_json", sa.Text(), nullable=False),
        sa.Column("state", sa.String(40), nullable=False),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.Column("updated_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "state IN ("
            "'sealed', 'preflight_passed', 'formal_evaluated', "
            "'invalidated_to_development'"
            ")",
            name="ck_locked_set_datasets_state",
        ),
        sa.CheckConstraint(
            "record_version >= 1",
            name="ck_locked_set_datasets_record_version",
        ),
    )
    op.create_table(
        "locked_set_preflight_attestations",
        sa.Column("attestation_id", sa.String(64), primary_key=True),
        sa.Column(
            "dataset_id",
            sa.String(200),
            sa.ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column(
            "exclusion_snapshot_id",
            sa.String(64),
            sa.ForeignKey(
                "locked_set_exclusion_snapshots.snapshot_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("exclusion_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("exclusion_source_id", sa.String(200), nullable=False),
        sa.Column("inventory_high_watermark", sa.Integer(), nullable=False),
        sa.Column("waybill_count", sa.Integer(), nullable=False),
        sa.Column("image_count", sa.Integer(), nullable=False),
        sa.Column("total_bytes", sa.Integer(), nullable=False),
        sa.Column("attestation_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "inventory_high_watermark >= 0",
            name="ck_locked_set_preflight_attestations_watermark",
        ),
        sa.CheckConstraint(
            "waybill_count = 50 AND image_count = 100 AND total_bytes > 0",
            name="ck_locked_set_preflight_attestations_counts",
        ),
        sa.UniqueConstraint(
            "dataset_id",
            "exclusion_snapshot_id",
            name="uq_locked_set_preflight_dataset_snapshot",
        ),
    )
    op.create_table(
        "locked_set_similarity_scans",
        sa.Column("scan_id", sa.String(64), primary_key=True),
        sa.Column(
            "dataset_id",
            sa.String(200),
            sa.ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column(
            "exclusion_snapshot_id",
            sa.String(64),
            sa.ForeignKey(
                "locked_set_exclusion_snapshots.snapshot_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("exclusion_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("inventory_high_watermark", sa.Integer(), nullable=False),
        sa.Column("scan_json", sa.Text(), nullable=False),
        sa.Column("scan_fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("detector_fingerprint", sa.String(64), nullable=False),
        sa.Column("locked_image_count", sa.Integer(), nullable=False),
        sa.Column("excluded_image_count", sa.Integer(), nullable=False),
        sa.Column("candidate_count", sa.Integer(), nullable=False),
        sa.Column("locked_image_fingerprints_json", sa.Text(), nullable=False),
        sa.Column(
            "locked_image_fingerprints_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "inventory_high_watermark >= 0",
            name="ck_locked_set_similarity_scans_watermark",
        ),
        sa.CheckConstraint(
            "locked_image_count = 100 AND excluded_image_count >= 0 AND candidate_count >= 0",
            name="ck_locked_set_similarity_scans_counts",
        ),
    )
    op.create_table(
        "locked_set_formal_evaluations",
        sa.Column("evaluation_id", sa.String(64), primary_key=True),
        sa.Column(
            "dataset_id",
            sa.String(200),
            sa.ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column(
            "exclusion_snapshot_id",
            sa.String(64),
            sa.ForeignKey(
                "locked_set_exclusion_snapshots.snapshot_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("exclusion_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("inventory_high_watermark", sa.Integer(), nullable=False),
        sa.Column(
            "preflight_attestation_id",
            sa.String(64),
            sa.ForeignKey(
                "locked_set_preflight_attestations.attestation_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(64),
            sa.ForeignKey(
                "locked_set_similarity_scans.scan_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
            unique=True,
        ),
        sa.Column("scan_fingerprint", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("runner_report_json", sa.Text(), nullable=False),
        sa.Column("runner_report_sha256", sa.String(64), nullable=False),
        sa.Column("committed_report_json", sa.Text(), nullable=False),
        sa.Column("committed_report_sha256", sa.String(64), nullable=False),
        sa.Column("quality_coverage_json", sa.Text(), nullable=False),
        sa.Column("quality_coverage_sha256", sa.String(64), nullable=False),
        sa.Column("decision_set_json", sa.Text(), nullable=False),
        sa.Column("decision_set_sha256", sa.String(64), nullable=False),
        sa.Column("run_context_sha256", sa.String(64), nullable=False),
        sa.Column("gate_passed", sa.Integer(), nullable=False),
        sa.Column("formal_report", sa.Integer(), nullable=False),
        sa.Column("formal_accuracy_claim", sa.Integer(), nullable=False),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "inventory_high_watermark >= 0",
            name="ck_locked_set_formal_evaluations_watermark",
        ),
        sa.CheckConstraint(
            "gate_passed IN (0, 1) "
            "AND formal_report = 1 "
            "AND formal_accuracy_claim IN (0, 1) "
            "AND (formal_accuracy_claim = 0 OR gate_passed = 1)",
            name="ck_locked_set_formal_evaluations_claim",
        ),
    )
    op.create_table(
        "locked_set_invalidations",
        sa.Column("invalidation_id", sa.String(32), primary_key=True),
        sa.Column(
            "dataset_id",
            sa.String(200),
            sa.ForeignKey("locked_set_datasets.dataset_id", ondelete="RESTRICT"),
            nullable=False,
            unique=True,
        ),
        sa.Column("influence_kind", sa.String(40), nullable=False),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "influence_kind IN ("
            "'code', 'preprocessing', 'configuration', 'template', 'model', "
            "'threshold', 'rule', 'mapping', 'adapter', 'error_handling', 'label'"
            ")",
            name="ck_locked_set_invalidations_influence_kind",
        ),
    )

    _backfill_inventory()

    for table_name in (
        "locked_set_exclusion_inventory",
        "locked_set_exclusion_snapshots",
        "locked_set_preflight_attestations",
        "locked_set_similarity_scans",
        "locked_set_formal_evaluations",
        "locked_set_invalidations",
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
    op.execute(
        """
        CREATE TRIGGER locked_set_datasets_immutable_identity_update
        BEFORE UPDATE OF
            dataset_id,
            manifest_sha256,
            member_identity_sha256,
            manifest_json,
            created_by,
            created_at
        ON locked_set_datasets
        BEGIN
            SELECT RAISE(ABORT, 'locked_set_datasets identity is immutable');
        END
        """
    )
    op.execute(
        """
        CREATE TRIGGER locked_set_datasets_immutable_delete
        BEFORE DELETE ON locked_set_datasets
        BEGIN
            SELECT RAISE(ABORT, 'locked_set_datasets cannot be deleted');
        END
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS locked_set_datasets_immutable_delete")
    op.execute("DROP TRIGGER IF EXISTS locked_set_datasets_immutable_identity_update")
    for table_name in (
        "locked_set_invalidations",
        "locked_set_formal_evaluations",
        "locked_set_similarity_scans",
        "locked_set_preflight_attestations",
        "locked_set_exclusion_snapshots",
        "locked_set_exclusion_inventory",
    ):
        op.execute(f"DROP TRIGGER IF EXISTS {table_name}_immutable_delete")
        op.execute(f"DROP TRIGGER IF EXISTS {table_name}_immutable_update")
    op.drop_table("locked_set_invalidations")
    op.drop_table("locked_set_formal_evaluations")
    op.drop_table("locked_set_similarity_scans")
    op.drop_table("locked_set_preflight_attestations")
    op.drop_table("locked_set_datasets")
    op.drop_table("locked_set_exclusion_snapshots")
    op.drop_table("locked_set_exclusion_inventory")
