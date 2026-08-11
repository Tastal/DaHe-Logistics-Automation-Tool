"""Add identity-free immutable records for the Loop 8 offline audit.

Revision ID: 0014_loop8_offline_audit
Revises: 0013_loop7_authority_insert_guards
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0014_loop8_offline_audit"
down_revision = "0013_loop7_authority_insert_guards"
branch_labels = None
depends_on = None

_IMMUTABLE_TABLES = (
    "audit_evidence_revisions",
    "audit_ocr_observations",
    "audit_decision_revisions",
    "audit_review_actions",
    "audit_timeline_events",
)


def upgrade() -> None:
    with op.batch_alter_table("work_items") as batch_op:
        batch_op.add_column(sa.Column("fixture_platform_loading_net", sa.String(40)))
        batch_op.add_column(sa.Column("fixture_platform_unloading_net", sa.String(40)))
        batch_op.add_column(sa.Column("fixture_ticket_loading_net", sa.String(40)))
        batch_op.add_column(sa.Column("fixture_ticket_unloading_net", sa.String(40)))
        batch_op.add_column(sa.Column("fixture_diagnostic_code", sa.String(100)))

    op.create_table(
        "audit_evidence_revisions",
        sa.Column("evidence_revision_id", sa.String(32), primary_key=True),
        sa.Column(
            "work_item_id",
            sa.String(32),
            sa.ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("platform_snapshot_sha256", sa.String(64), nullable=False),
        sa.Column("loading_image_sha256", sa.String(64)),
        sa.Column("unloading_image_sha256", sa.String(64)),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.UniqueConstraint(
            "work_item_id",
            "revision_number",
            name="uq_audit_evidence_revision_number",
        ),
        sa.CheckConstraint(
            "revision_number >= 1 AND length(platform_snapshot_sha256) = 64 "
            "AND length(fingerprint) = 64",
            name="ck_audit_evidence_revision_shape",
        ),
    )
    op.create_index(
        "ix_audit_evidence_revisions_work_item",
        "audit_evidence_revisions",
        ["work_item_id", "revision_number"],
    )

    op.create_table(
        "audit_ocr_observations",
        sa.Column("ocr_observation_id", sa.String(32), primary_key=True),
        sa.Column(
            "evidence_revision_id",
            sa.String(32),
            sa.ForeignKey(
                "audit_evidence_revisions.evidence_revision_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("image_role", sa.String(20), nullable=False),
        sa.Column("image_sha256", sa.String(64), nullable=False),
        sa.Column("pipeline_fingerprint", sa.String(64), nullable=False),
        sa.Column("template_version_id", sa.String(64)),
        sa.Column("runtime_kind", sa.String(20), nullable=False),
        sa.Column("runtime_fingerprint", sa.String(64), nullable=False),
        sa.Column("ticket_role", sa.String(20), nullable=False),
        sa.Column("ordinary_net_raw", sa.String(100)),
        sa.Column("ordinary_net_normalized", sa.String(40)),
        sa.Column("unit", sa.String(20)),
        sa.Column("reliable", sa.Integer(), nullable=False),
        sa.Column("anomaly_reason", sa.String(100)),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("observation_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "image_role IN ('loading', 'unloading') "
            "AND runtime_kind IN ('cpu', 'gpu', 'fixture') "
            "AND ticket_role IN ('loading', 'unloading', 'unknown') "
            "AND reliable IN (0, 1)",
            name="ck_audit_ocr_observation_values",
        ),
    )
    op.create_index(
        "ix_audit_ocr_observations_evidence",
        "audit_ocr_observations",
        ["evidence_revision_id"],
    )

    op.create_table(
        "audit_decision_revisions",
        sa.Column("decision_revision_id", sa.String(32), primary_key=True),
        sa.Column(
            "work_item_id",
            sa.String(32),
            sa.ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_revision_id",
            sa.String(32),
            sa.ForeignKey(
                "audit_evidence_revisions.evidence_revision_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("revision_number", sa.Integer(), nullable=False),
        sa.Column("rules_fingerprint", sa.String(64), nullable=False),
        sa.Column("business_outcome", sa.String(50), nullable=False),
        sa.Column("review_reason", sa.String(100)),
        sa.Column("decision", sa.String(30), nullable=False),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.UniqueConstraint(
            "work_item_id",
            "revision_number",
            name="uq_audit_decision_revision_number",
        ),
        sa.CheckConstraint(
            "revision_number >= 1 AND length(rules_fingerprint) = 64 "
            "AND length(fingerprint) = 64 "
            "AND decision IN ('pass', 'review', 'problem', 'failed')",
            name="ck_audit_decision_revision_shape",
        ),
    )
    op.create_index(
        "ix_audit_decision_revisions_work_item",
        "audit_decision_revisions",
        ["work_item_id", "revision_number"],
    )

    op.create_table(
        "audit_review_actions",
        sa.Column("action_id", sa.String(32), primary_key=True),
        sa.Column(
            "work_item_id",
            sa.String(32),
            sa.ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "evidence_revision_id",
            sa.String(32),
            sa.ForeignKey(
                "audit_evidence_revisions.evidence_revision_id",
                ondelete="RESTRICT",
            ),
            nullable=False,
        ),
        sa.Column("action_type", sa.String(40), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("correct_value", sa.String(40)),
        sa.Column("note", sa.String(500)),
        sa.Column(
            "revokes_action_id",
            sa.String(32),
            sa.ForeignKey("audit_review_actions.action_id", ondelete="RESTRICT"),
        ),
        sa.Column("record_version", sa.Integer(), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False, unique=True),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.CheckConstraint(
            "action_type IN ('correction', 'problem_confirmation', "
            "'problem_dismissal', 'revocation') "
            "AND record_version >= 1 AND length(request_hash) = 64",
            name="ck_audit_review_action_shape",
        ),
        sa.CheckConstraint(
            "(action_type = 'correction' AND correct_value IS NOT NULL "
            "AND revokes_action_id IS NULL) "
            "OR (action_type IN ('problem_confirmation', 'problem_dismissal') "
            "AND revokes_action_id IS NULL) "
            "OR (action_type = 'revocation' AND revokes_action_id IS NOT NULL "
            "AND correct_value IS NULL)",
            name="ck_audit_review_action_payload",
        ),
    )
    op.create_index(
        "ix_audit_review_actions_work_item",
        "audit_review_actions",
        ["work_item_id", "created_at"],
    )

    op.create_table(
        "audit_timeline_events",
        sa.Column("timeline_event_id", sa.String(32), primary_key=True),
        sa.Column(
            "work_item_id",
            sa.String(32),
            sa.ForeignKey("work_items.work_item_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("reference_id", sa.String(32)),
        sa.Column("payload_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
    )
    op.create_index(
        "ix_audit_timeline_events_work_item",
        "audit_timeline_events",
        ["work_item_id", "created_at"],
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
        op.drop_table(table)
    with op.batch_alter_table("work_items") as batch_op:
        batch_op.drop_column("fixture_diagnostic_code")
        batch_op.drop_column("fixture_ticket_unloading_net")
        batch_op.drop_column("fixture_ticket_loading_net")
        batch_op.drop_column("fixture_platform_unloading_net")
        batch_op.drop_column("fixture_platform_loading_net")
