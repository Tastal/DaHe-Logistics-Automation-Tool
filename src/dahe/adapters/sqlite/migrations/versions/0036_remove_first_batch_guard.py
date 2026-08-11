"""Remove mandatory first-batch confirmation from read-only production.

Revision ID: 0036_guard_policy
Revises: 0035_daily_revisions
"""

from __future__ import annotations

from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0036_guard_policy"
down_revision = "0035_daily_revisions"
branch_labels = None
depends_on = None


_GUARD_CHECK = (
    "guard_id = 'primary' "
    "AND status IN ('operational_read_only_with_guard', "
    "'operational_read_only_accepted', 'operational_read_only_active') "
    "AND target_count = 30 AND registered_count >= 0 "
    "AND reviewed_target_count BETWEEN 0 AND target_count "
    "AND false_normal_count >= 0 AND record_version >= 1"
)


def upgrade() -> None:
    with op.batch_alter_table(
        "production_read_only_guard",
        recreate="always",
    ) as batch:
        batch.drop_constraint(
            "ck_production_read_only_guard_shape",
            type_="check",
        )
        batch.create_check_constraint(
            "ck_production_read_only_guard_shape",
            _GUARD_CHECK,
        )

    bind = op.get_bind()
    affected_jobs = tuple(
        str(row[0])
        for row in bind.execute(
            sa.text(
                "SELECT DISTINCT items.job_id "
                "FROM production_read_only_guard_items AS guard "
                "JOIN work_items AS items "
                "ON items.work_item_id = guard.work_item_id "
                "WHERE guard.protected = 1 AND guard.released = 0 "
                "AND guard.manual_outcome IS NULL "
                "AND items.review_reason = 'production_first_batch_guard'"
            )
        )
    )
    bind.execute(
        sa.text(
            "UPDATE work_items SET status = 'succeeded', "
            "current_stage = 'audit.recheck', business_outcome = 'normal_ready', "
            "decision = 'pass', review_reason = NULL, "
            "waiting_reason_kind = NULL, waiting_reason = NULL, "
            "record_version = record_version + 1 "
            "WHERE work_item_id IN ("
            "SELECT guard.work_item_id "
            "FROM production_read_only_guard_items AS guard "
            "WHERE guard.protected = 1 AND guard.released = 0 "
            "AND guard.manual_outcome IS NULL"
            ") AND review_reason = 'production_first_batch_guard'"
        )
    )
    bind.execute(
        sa.text(
            "UPDATE production_read_only_guard_items SET released = 1 "
            "WHERE protected = 1 AND released = 0 AND manual_outcome IS NULL"
        )
    )
    now = datetime.now(UTC).isoformat()
    for job_id in affected_jobs:
        statuses = tuple(
            str(row[0])
            for row in bind.execute(
                sa.text(
                    "SELECT status FROM work_items WHERE job_id = :job_id"
                ),
                {"job_id": job_id},
            )
        )
        if any(status == "waiting_user" for status in statuses):
            continue
        if any(
            status not in {"succeeded", "failed", "cancelled"}
            for status in statuses
        ):
            continue
        terminal_status = "failed" if any(
            status == "failed" for status in statuses
        ) else "succeeded"
        bind.execute(
            sa.text(
                "UPDATE jobs SET status = :status, "
                "current_stage = 'audit.recheck', "
                "record_version = record_version + 1, updated_at = :updated_at "
                "WHERE job_id = :job_id"
            ),
            {
                "job_id": job_id,
                "status": terminal_status,
                "updated_at": now,
            },
        )
    bind.execute(
        sa.text(
            "UPDATE production_read_only_guard "
            "SET status = 'operational_read_only_active', "
            "record_version = record_version + 1, resolved_at = :resolved_at "
            "WHERE guard_id = 'primary'"
        ),
        {"resolved_at": now},
    )


def downgrade() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            "UPDATE production_read_only_guard SET "
            "status = 'operational_read_only_with_guard', "
            "record_version = record_version + 1, resolved_at = NULL "
            "WHERE guard_id = 'primary' "
            "AND status = 'operational_read_only_active'"
        )
    )
    with op.batch_alter_table(
        "production_read_only_guard",
        recreate="always",
    ) as batch:
        batch.drop_constraint(
            "ck_production_read_only_guard_shape",
            type_="check",
        )
        batch.create_check_constraint(
            "ck_production_read_only_guard_shape",
            _GUARD_CHECK.replace(
                ", 'operational_read_only_active'",
                "",
            ),
        )
