"""Add DB-ordered terminal attempt ledgers for Loop 7 authorities.

Revision ID: 0011_loop7_terminal_attempt_ledgers
Revises: 0010_loop7_candidate_development_ocr_runs
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0011_loop7_terminal_attempt_ledgers"
down_revision = "0010_loop7_candidate_development_ocr_runs"
branch_labels = None
depends_on = None

_OCR_ATTEMPTS = "candidate_development_ocr_attempts"
_LIFECYCLE_ATTEMPTS = "template_lifecycle_attempts"


def _hash_check(columns: tuple[str, ...]) -> str:
    return " AND ".join(
        f"length({column}) = 64 "
        f"AND {column} = lower({column}) "
        f"AND {column} NOT GLOB '*[^0-9a-f]*'"
        for column in columns
    )


def _add_append_only_triggers(table: str) -> None:
    op.execute(
        f"""
        CREATE TRIGGER {table}_immutable_update
        BEFORE UPDATE ON {table}
        BEGIN
            SELECT RAISE(ABORT, '{table} is append-only');
        END
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER {table}_immutable_delete
        BEFORE DELETE ON {table}
        BEGIN
            SELECT RAISE(ABORT, '{table} is append-only');
        END
        """
    )


def upgrade() -> None:
    op.create_table(
        _OCR_ATTEMPTS,
        sa.Column(
            "attempt_sequence",
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column(
            "evidence_sha256",
            sa.String(64),
            nullable=False,
            unique=True,
        ),
        sa.Column("evidence_blob_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_relative_path", sa.String(500), nullable=False),
        sa.Column("evidence_byte_size", sa.Integer(), nullable=False),
        sa.Column("package_sha256", sa.String(64), nullable=False),
        sa.Column(
            "review_history_authority_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("source_authority_sha256", sa.String(64), nullable=False),
        sa.Column("reviewer_id", sa.String(200), nullable=False),
        sa.Column("application_build_sha256", sa.String(64), nullable=False),
        sa.Column(
            "composition_evidence_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("runtime_set_sha256", sa.String(64), nullable=False),
        sa.Column(
            "pipeline_contract_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("completion_status", sa.String(50), nullable=False),
        sa.Column("terminal_status", sa.String(30), nullable=False),
        sa.Column("authorized_evidence_sha256", sa.String(64)),
        sa.Column("completed_at", sa.String(40), nullable=False),
        sa.Column("attempt_payload_json", sa.Text(), nullable=False),
        sa.Column("attempt_sha256", sa.String(64), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["authorized_evidence_sha256"],
            ["candidate_development_ocr_runs.evidence_sha256"],
            name="fk_candidate_ocr_attempt_authorized_run",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "evidence_byte_size > 0",
            name="ck_candidate_development_ocr_attempts_byte_size",
        ),
        sa.CheckConstraint(
            "terminal_status IN ('succeeded', 'technical_failed')",
            name="ck_candidate_development_ocr_attempts_terminal_status",
        ),
        sa.CheckConstraint(
            "(terminal_status = 'succeeded' "
            "AND completion_status IN ("
            "'completed', 'completed_with_runtime_differences') "
            "AND authorized_evidence_sha256 = evidence_sha256) "
            "OR (terminal_status = 'technical_failed' "
            "AND completion_status = 'failed' "
            "AND authorized_evidence_sha256 IS NULL)",
            name="ck_candidate_development_ocr_attempts_outcome",
        ),
        sa.CheckConstraint(
            _hash_check(
                (
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
    op.create_index(
        "ix_candidate_development_ocr_attempts_scope_sequence",
        _OCR_ATTEMPTS,
        ["scope_sha256", "attempt_sequence"],
    )
    _add_append_only_triggers(_OCR_ATTEMPTS)

    op.create_table(
        _LIFECYCLE_ATTEMPTS,
        sa.Column(
            "attempt_sequence",
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("attempt_id", sa.String(32), nullable=False, unique=True),
        sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("terminal_status", sa.String(30), nullable=False),
        sa.Column("evaluation_id", sa.String(100)),
        sa.Column("failure_code", sa.String(100)),
        sa.Column("ocr_evidence_sha256", sa.String(64), nullable=False),
        sa.Column("package_sha256", sa.String(64), nullable=False),
        sa.Column(
            "review_history_authority_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("source_authority_sha256", sa.String(64), nullable=False),
        sa.Column("reviewer_id", sa.String(200), nullable=False),
        sa.Column("ocr_capture_build_sha256", sa.String(64), nullable=False),
        sa.Column(
            "role_evaluator_build_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "composition_evidence_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("runtime_set_sha256", sa.String(64), nullable=False),
        sa.Column(
            "pipeline_contract_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("dataset_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("candidate_set_sha256", sa.String(64), nullable=False),
        sa.Column("matcher_fingerprint", sa.String(64), nullable=False),
        sa.Column("policy_fingerprint", sa.String(64), nullable=False),
        sa.Column("template_set_fingerprint", sa.String(64), nullable=False),
        sa.Column("composite_policy_sha256", sa.String(64), nullable=False),
        sa.Column("attempt_payload_json", sa.Text(), nullable=False),
        sa.Column("attempt_sha256", sa.String(64), nullable=False),
        sa.Column("actor_id", sa.String(200), nullable=False),
        sa.Column("created_at", sa.String(40), nullable=False),
        sa.ForeignKeyConstraint(
            ["evaluation_id"],
            ["template_evaluations.evaluation_id"],
            name="fk_template_lifecycle_attempt_evaluation",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "terminal_status IN ("
            "'succeeded', 'business_failed', 'technical_failed')",
            name="ck_template_lifecycle_attempts_terminal_status",
        ),
        sa.CheckConstraint(
            "(terminal_status = 'succeeded' "
            "AND evaluation_id IS NOT NULL AND failure_code IS NULL) "
            "OR (terminal_status IN ('business_failed', 'technical_failed') "
            "AND evaluation_id IS NULL AND failure_code IS NOT NULL)",
            name="ck_template_lifecycle_attempts_outcome",
        ),
        sa.CheckConstraint(
            _hash_check(
                (
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
    op.create_index(
        "ix_template_lifecycle_attempts_scope_sequence",
        _LIFECYCLE_ATTEMPTS,
        ["scope_sha256", "attempt_sequence"],
    )
    _add_append_only_triggers(_LIFECYCLE_ATTEMPTS)


def downgrade() -> None:
    op.execute(
        f"DROP TRIGGER IF EXISTS {_LIFECYCLE_ATTEMPTS}_immutable_delete"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS {_LIFECYCLE_ATTEMPTS}_immutable_update"
    )
    op.drop_index(
        "ix_template_lifecycle_attempts_scope_sequence",
        table_name=_LIFECYCLE_ATTEMPTS,
    )
    op.drop_table(_LIFECYCLE_ATTEMPTS)
    op.execute(
        f"DROP TRIGGER IF EXISTS {_OCR_ATTEMPTS}_immutable_delete"
    )
    op.execute(
        f"DROP TRIGGER IF EXISTS {_OCR_ATTEMPTS}_immutable_update"
    )
    op.drop_index(
        "ix_candidate_development_ocr_attempts_scope_sequence",
        table_name=_OCR_ATTEMPTS,
    )
    op.drop_table(_OCR_ATTEMPTS)
