from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from dahe.adapters.sqlite.runtime import SqliteRuntime


def test_current_head_preserves_append_only_formal_selection_lifecycle_anchor(
    tmp_path: Path,
) -> None:
    data_root = tmp_path.resolve()
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=Path(__file__).resolve().parents[2],
        instance_id="loop9-selection-lifecycle-migration-test",
    )
    runtime.close()
    database = data_root / "database" / "dahe.sqlite3"

    with sqlite3.connect(database) as connection:
        revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        assert revision == ("0041_contract_subject_scope",)
        columns = {
            row[1]
            for row in connection.execute(
                "PRAGMA table_info("
                "loop9_formal_selection_lifecycle_anchors)"
            )
        }
        assert {
            "target_kind",
            "sequence",
            "generation",
            "event_kind",
            "node_sha256",
            "previous_head_sha256",
            "selection_sha256",
            "predecessor_selection_sha256",
            "failure_attestation_sha256",
            "exclusion_inventory_sha256",
            "exclusion_authority_sha256",
            "exclusion_child_head_sha256",
            "source_build_sha256",
            "pipeline_fingerprint",
            "identity_context_sha256",
            "created_at",
        }.issubset(columns)

        connection.execute(
            """
            INSERT INTO loop9_formal_selection_lifecycle_anchors (
                target_kind,
                sequence,
                generation,
                event_kind,
                node_sha256,
                previous_head_sha256,
                selection_sha256,
                predecessor_selection_sha256,
                failure_attestation_sha256,
                exclusion_inventory_sha256,
                exclusion_authority_sha256,
                exclusion_child_head_sha256,
                source_build_sha256,
                pipeline_fingerprint,
                identity_context_sha256,
                created_at
            ) VALUES (
                'current_locked_50',
                1,
                1,
                'activated',
                :node_sha256,
                NULL,
                :selection_sha256,
                NULL,
                NULL,
                NULL,
                :exclusion_authority_sha256,
                :exclusion_child_head_sha256,
                :source_build_sha256,
                :pipeline_fingerprint,
                :identity_context_sha256,
                '2026-07-30T01:02:03Z'
            )
            """,
            {
                "node_sha256": "1" * 64,
                "selection_sha256": "2" * 64,
                "exclusion_authority_sha256": "3" * 64,
                "exclusion_child_head_sha256": "4" * 64,
                "source_build_sha256": "5" * 64,
                "pipeline_fingerprint": "6" * 64,
                "identity_context_sha256": "7" * 64,
            },
        )
        connection.commit()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                """
                UPDATE loop9_formal_selection_lifecycle_anchors
                SET generation = 2
                WHERE target_kind = 'current_locked_50' AND sequence = 1
                """
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                """
                DELETE FROM loop9_formal_selection_lifecycle_anchors
                WHERE target_kind = 'current_locked_50' AND sequence = 1
                """
            )
