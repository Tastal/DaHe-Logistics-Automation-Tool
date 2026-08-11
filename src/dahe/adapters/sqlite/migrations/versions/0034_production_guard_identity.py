"""Count first-batch protection by stable business identity.

Revision ID: 0034_guard_identity
Revises: 0033_production_guard
"""

from __future__ import annotations

import hashlib
import unicodedata
from collections import defaultdict

import sqlalchemy as sa
from alembic import op

revision = "0034_guard_identity"
down_revision = "0033_production_guard"
branch_labels = None
depends_on = None


def _identity(value: object) -> str:
    normalized = unicodedata.normalize("NFKC", str(value)).strip().upper()
    if not normalized:
        raise RuntimeError("production guard waybill identity is empty")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def upgrade() -> None:
    op.add_column(
        "production_read_only_guard_items",
        sa.Column("business_identity_sha256", sa.String(64), nullable=True),
    )
    bind = op.get_bind()
    rows = tuple(
        bind.execute(
            sa.text(
                "SELECT guard.work_item_id, guard.ordinal, "
                "guard.machine_outcome, guard.manual_outcome, "
                "guard.manual_action_id, guard.reviewed_at, "
                "items.waybill_number "
                "FROM production_read_only_guard_items AS guard "
                "JOIN work_items AS items "
                "ON items.work_item_id = guard.work_item_id "
                "ORDER BY guard.ordinal"
            )
        ).mappings()
    )
    grouped: dict[str, list[sa.RowMapping]] = defaultdict(list)
    identity_order: list[str] = []
    for row in rows:
        identity = _identity(row["waybill_number"])
        if identity not in grouped:
            identity_order.append(identity)
        grouped[identity].append(row)
        bind.execute(
            sa.text(
                "UPDATE production_read_only_guard_items "
                "SET business_identity_sha256 = :identity, "
                "counts_toward_gate = 0 "
                "WHERE work_item_id = :work_item_id"
            ),
            {"identity": identity, "work_item_id": row["work_item_id"]},
        )

    reviewed = 0
    false_normals = 0
    for identity in identity_order[:30]:
        identity_rows = grouped[identity]
        decisions = {
            str(row["manual_outcome"])
            for row in identity_rows
            if row["manual_outcome"] is not None
        }
        if len(decisions) > 1:
            raise RuntimeError(
                "production guard contains conflicting decisions for one waybill"
            )
        decided = next(
            (row for row in identity_rows if row["manual_outcome"] is not None),
            None,
        )
        target = identity_rows[0]
        if decided is not None and decided["work_item_id"] != target["work_item_id"]:
            bind.execute(
                sa.text(
                    "UPDATE production_read_only_guard_items "
                    "SET manual_outcome = NULL, manual_action_id = NULL, "
                    "reviewed_at = NULL WHERE work_item_id = :work_item_id"
                ),
                {"work_item_id": decided["work_item_id"]},
            )
        bind.execute(
            sa.text(
                "UPDATE production_read_only_guard_items "
                "SET counts_toward_gate = 1, manual_outcome = :manual_outcome, "
                "manual_action_id = :manual_action_id, reviewed_at = :reviewed_at "
                "WHERE work_item_id = :work_item_id"
            ),
            {
                "manual_action_id": (
                    decided["manual_action_id"] if decided is not None else None
                ),
                "manual_outcome": (
                    decided["manual_outcome"] if decided is not None else None
                ),
                "reviewed_at": decided["reviewed_at"] if decided is not None else None,
                "work_item_id": target["work_item_id"],
            },
        )
        if decided is not None:
            reviewed += 1
            if decided["manual_outcome"] == "confirmed_problem" and any(
                row["machine_outcome"] == "normal_ready" for row in identity_rows
            ):
                false_normals += 1

    accepted = reviewed == 30 and false_normals == 0
    state = bind.execute(
        sa.text(
            "SELECT record_version FROM production_read_only_guard "
            "WHERE guard_id = 'primary'"
        )
    ).mappings().one_or_none()
    if state is not None:
        bind.execute(
            sa.text(
                "UPDATE production_read_only_guard SET status = :status, "
                "registered_count = :registered_count, "
                "reviewed_target_count = :reviewed_count, "
                "false_normal_count = :false_normal_count, "
                "record_version = :record_version, "
                "resolved_at = CASE WHEN :accepted = 1 THEN resolved_at ELSE NULL END "
                "WHERE guard_id = 'primary'"
            ),
            {
                "accepted": int(accepted),
                "false_normal_count": false_normals,
                "record_version": int(state["record_version"]) + 1,
                "registered_count": len(identity_order),
                "reviewed_count": reviewed,
                "status": (
                    "operational_read_only_accepted"
                    if accepted
                    else "operational_read_only_with_guard"
                ),
            },
        )

    with op.batch_alter_table(
        "production_read_only_guard_items",
        recreate="always",
    ) as batch:
        batch.alter_column(
            "business_identity_sha256",
            existing_type=sa.String(64),
            nullable=False,
        )
        batch.create_check_constraint(
            "ck_production_guard_business_identity",
            "length(business_identity_sha256) = 64",
        )
        batch.create_index(
            "ix_production_guard_business_identity",
            ["business_identity_sha256"],
            unique=False,
        )


def downgrade() -> None:
    with op.batch_alter_table(
        "production_read_only_guard_items",
        recreate="always",
    ) as batch:
        batch.drop_index("ix_production_guard_business_identity")
        batch.drop_constraint(
            "ck_production_guard_business_identity",
            type_="check",
        )
        batch.drop_column("business_identity_sha256")
