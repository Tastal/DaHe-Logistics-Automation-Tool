"""Partition immutable Loop 9 exclusion anchors by authority context.

Revision ID: 0031_loop9_authority_contexts
Revises: 0030_credential_results
"""

from __future__ import annotations

import hashlib
import json

import sqlalchemy as sa
from alembic import op
from sqlalchemy.engine import RowMapping

revision = "0031_loop9_authority_contexts"
down_revision = "0030_credential_results"
branch_labels = None
depends_on = None

_TABLE = "loop9_exclusion_authority_anchors"
_TEMP_TABLE = "loop9_exclusion_authority_anchors_v2"
_COLUMNS = (
    "sequence",
    "node_sha256",
    "previous_head_sha256",
    "source_boundary_sha256",
    "source_inventory_high_watermark",
    "identity_context_sha256",
    "expected_current_build_sha256",
    "expected_settlement_contract_sha256",
    "expected_daily_contract_sha256",
    "expected_settlement_selection_sha256",
    "expected_daily_selection_sha256",
    "child_inventory_sha256",
    "child_exclusion_kind",
    "child_platform_identity_count",
    "child_image_count",
    "child_scope_exclusion_token_count",
    "child_perceptual_fingerprint_count",
)


def _context_sha256(row: RowMapping) -> str:
    payload = {
        "expected_current_build_sha256": row[
            "expected_current_build_sha256"
        ],
        "expected_daily_contract_sha256": row[
            "expected_daily_contract_sha256"
        ],
        "expected_daily_selection_sha256": row[
            "expected_daily_selection_sha256"
        ],
        "expected_settlement_contract_sha256": row[
            "expected_settlement_contract_sha256"
        ],
        "expected_settlement_selection_sha256": row[
            "expected_settlement_selection_sha256"
        ],
        "identity_context_sha256": row["identity_context_sha256"],
        "kind": "loop9_exclusion_authority_anchor_context",
        "schema_version": 1,
        "source_boundary_sha256": row["source_boundary_sha256"],
        "source_inventory_high_watermark": row[
            "source_inventory_high_watermark"
        ],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _create_table(name: str) -> None:
    op.create_table(
        name,
        sa.Column(
            "authority_context_sha256",
            sa.String(64),
            primary_key=True,
        ),
        sa.Column("sequence", sa.Integer(), primary_key=True),
        sa.Column("node_sha256", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "previous_head_sha256",
            sa.String(64),
            sa.ForeignKey(f"{name}.node_sha256", ondelete="RESTRICT"),
            unique=True,
        ),
        sa.Column("source_boundary_sha256", sa.String(64), nullable=False),
        sa.Column(
            "source_inventory_high_watermark",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("identity_context_sha256", sa.String(64), nullable=False),
        sa.Column(
            "expected_current_build_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_settlement_contract_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_daily_contract_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_settlement_selection_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column(
            "expected_daily_selection_sha256",
            sa.String(64),
            nullable=False,
        ),
        sa.Column("child_inventory_sha256", sa.String(64), nullable=False),
        sa.Column("child_exclusion_kind", sa.String(32), nullable=False),
        sa.Column(
            "child_platform_identity_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column("child_image_count", sa.Integer(), nullable=False),
        sa.Column(
            "child_scope_exclusion_token_count",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "child_perceptual_fingerprint_count", sa.Integer(), nullable=False
        ),
        sa.UniqueConstraint(
            "authority_context_sha256",
            "child_inventory_sha256",
            name="uq_loop9_exclusion_anchor_context_child",
        ),
        sa.CheckConstraint(
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


def _create_immutable_triggers() -> None:
    op.execute(
        f"""
        CREATE TRIGGER trg_loop9_exclusion_authority_anchor_no_update
        BEFORE UPDATE ON {_TABLE}
        BEGIN
          SELECT RAISE(ABORT, 'Loop 9 exclusion authority anchors are immutable');
        END
        """
    )
    op.execute(
        f"""
        CREATE TRIGGER trg_loop9_exclusion_authority_anchor_no_delete
        BEFORE DELETE ON {_TABLE}
        BEGIN
          SELECT RAISE(ABORT, 'Loop 9 exclusion authority anchors are immutable');
        END
        """
    )


def upgrade() -> None:
    connection = op.get_bind()
    staged_exists = connection.execute(
        sa.text(
            "SELECT COUNT(*) FROM sqlite_master "
            "WHERE type = 'table' AND name = :name"
        ),
        {"name": _TEMP_TABLE},
    ).scalar_one()
    if staged_exists:
        staged_rows = connection.execute(
            sa.text(f"SELECT COUNT(*) FROM {_TEMP_TABLE}")
        ).scalar_one()
        if staged_rows:
            raise RuntimeError(
                "non-empty staged exclusion authority migration exists"
            )
        op.drop_table(_TEMP_TABLE)
    columns = ", ".join(_COLUMNS)
    rows = connection.execute(
        sa.text(f"SELECT {columns} FROM {_TABLE} ORDER BY sequence")
    ).mappings().all()
    _create_table(_TEMP_TABLE)
    insert_columns = "authority_context_sha256, " + columns
    placeholders = ", ".join(
        f":{column}" for column in insert_columns.split(", ")
    )
    for row in rows:
        values = {column: row[column] for column in _COLUMNS}
        values["authority_context_sha256"] = _context_sha256(row)
        connection.execute(
            sa.text(
                f"INSERT INTO {_TEMP_TABLE} ({insert_columns}) "
                f"VALUES ({placeholders})"
            ),
            values,
        )
    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_loop9_exclusion_authority_anchor_no_delete"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS "
        "trg_loop9_exclusion_authority_anchor_no_update"
    )
    for row in reversed(rows):
        connection.execute(
            sa.text(
                f"DELETE FROM {_TABLE} "
                "WHERE sequence = :sequence AND node_sha256 = :node_sha256"
            ),
            {
                "sequence": row["sequence"],
                "node_sha256": row["node_sha256"],
            },
        )
    op.drop_table(_TABLE)
    op.rename_table(_TEMP_TABLE, _TABLE)
    _create_immutable_triggers()


def downgrade() -> None:
    raise RuntimeError(
        "0031 cannot be downgraded without discarding immutable authority history"
    )
