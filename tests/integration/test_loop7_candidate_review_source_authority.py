from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.sqlite.locked_set import (
    LockedSetConflictError,
    LockedSetPersistenceError,
    SqliteLockedSetRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.maintenance.backup import SqliteBackupService
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedTicketImage,
    LockedWaybill,
)

EXPECTED_REVISION = "0039_network_batch_default"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode()).hexdigest()


def _runtime(
    *,
    data_root: Path,
    project_root: Path,
    instance_id: str,
) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=data_root,
        project_root=project_root,
        instance_id=instance_id,
    )


def _manifest(dataset_id: str) -> LockedSetManifest:
    waybills: list[LockedWaybill] = []
    for position in range(1, 51):
        images = tuple(
            LockedTicketImage(
                image_sha256=hashlib.sha256(
                    f"{dataset_id}:{position}:{slot.value}".encode()
                ).hexdigest(),
                relative_path=(f"images/{position:03d}-{slot.value}.jpg"),
                slot=slot,
                role=role,
                ordinary_net=Decimal("30.00"),
            )
            for slot, role in (
                (TicketSlot.LOADING, TicketRole.LOADING),
                (TicketSlot.UNLOADING, TicketRole.UNLOADING),
            )
        )
        waybills.append(
            LockedWaybill(
                sample_id=f"{dataset_id}-{position:03d}",
                waybill_identity_sha256=hashlib.sha256(
                    f"{dataset_id}:waybill:{position}".encode()
                ).hexdigest(),
                images=images,
            )
        )
    return LockedSetManifest(
        dataset_id=dataset_id,
        dataset_kind="locked",
        tuning_prohibited=True,
        waybills=tuple(waybills),
    )


def _authority_values(
    *,
    dataset_id: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    package_sha256 = hashlib.sha256(f"{dataset_id}:package".encode()).hexdigest()
    record_set_sha256 = hashlib.sha256(f"{dataset_id}:records".encode()).hexdigest()
    without_hash: dict[str, object] = {
        "schema_version": 2,
        "kind": "candidate_review_formal_source_authority",
        "authority_scope": "computed_unsealed_snapshot",
        "persistent_seal": False,
        "dataset_id": dataset_id,
        "manifest_sha256": manifest_sha256,
        "package_id": f"{dataset_id}-candidate-package",
        "package_sha256": package_sha256,
        "configured_reviewer_id": "operator-a",
        "record_count": 50,
        "record_set_sha256": record_set_sha256,
        "records": [],
        "verified_image_count": 100,
        "verified_image_set_sha256": hashlib.sha256(f"{dataset_id}:images".encode()).hexdigest(),
        "verified_images": [],
    }
    source_authority_sha256 = _canonical_sha256(without_hash)
    return {
        "dataset_id": dataset_id,
        "manifest_sha256": manifest_sha256,
        "seal_sha256": hashlib.sha256(f"{dataset_id}:seal".encode()).hexdigest(),
        "package_sha256": package_sha256,
        "record_set_sha256": record_set_sha256,
        "review_history_authority_sha256": hashlib.sha256(
            f"{dataset_id}:history".encode()
        ).hexdigest(),
        "source_authority_sha256": source_authority_sha256,
        "payload": {
            **without_hash,
            "source_authority_sha256": source_authority_sha256,
        },
    }


def _seal_dataset(
    repository: SqliteLockedSetRepository,
    dataset_id: str,
) -> LockedSetManifest:
    manifest = _manifest(dataset_id)
    repository.seal_manifest(manifest, actor_id="operator-a")
    return manifest


def test_migration_adds_lowercase_append_only_authority_table(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="source-authority-schema",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        manifest = _seal_dataset(repository, "locked-source-schema")
        values = _authority_values(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
        )
        record = repository.register_candidate_review_source_authority(**values)

        assert runtime.current_revision() == EXPECTED_REVISION
        with runtime.engine.connect() as connection:
            columns = {
                str(row["name"]): int(row["pk"])
                for row in connection.execute(
                    text("PRAGMA table_info(locked_set_candidate_review_source_authority)")
                ).mappings()
            }
            foreign_keys = tuple(
                connection.execute(
                    text("PRAGMA foreign_key_list(locked_set_candidate_review_source_authority)")
                ).mappings()
            )
            triggers = {
                str(row[0])
                for row in connection.execute(
                    text(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'trigger' "
                        "AND tbl_name = "
                        "'locked_set_candidate_review_source_authority'"
                    )
                )
            }
        assert columns == {
            "dataset_id": 1,
            "manifest_sha256": 0,
            "seal_sha256": 0,
            "package_sha256": 0,
            "record_set_sha256": 0,
            "review_history_authority_sha256": 0,
            "source_authority_sha256": 0,
            "payload_json": 0,
            "created_at": 0,
        }
        assert any(
            row["table"] == "locked_set_datasets"
            and row["from"] == "dataset_id"
            and row["to"] == "dataset_id"
            and row["on_delete"] == "RESTRICT"
            for row in foreign_keys
        )
        assert triggers == {
            "locked_set_candidate_review_source_authority_immutable_insert",
            "locked_set_candidate_review_source_authority_immutable_update",
            "locked_set_candidate_review_source_authority_immutable_delete",
        }

        with (
            pytest.raises(IntegrityError, match="append-only"),
            runtime.engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "UPDATE locked_set_candidate_review_source_authority "
                    "SET payload_json = '{}' "
                    "WHERE dataset_id = :dataset_id"
                ),
                {"dataset_id": record.dataset_id},
            )
        with (
            pytest.raises(IntegrityError, match="append-only"),
            runtime.engine.begin() as connection,
        ):
            connection.execute(
                text(
                    "DELETE FROM "
                    "locked_set_candidate_review_source_authority "
                    "WHERE dataset_id = :dataset_id"
                ),
                {"dataset_id": record.dataset_id},
            )

        second = _seal_dataset(repository, "locked-source-uppercase")
        second_values = _authority_values(
            dataset_id=second.dataset_id,
            manifest_sha256=second.canonical_sha256,
        )
        with (
            pytest.raises(IntegrityError),
            runtime.engine.begin() as connection,
        ):
            connection.execute(
                text(
                    """
                    INSERT INTO
                        locked_set_candidate_review_source_authority (
                            dataset_id, manifest_sha256, seal_sha256,
                            package_sha256, record_set_sha256,
                            review_history_authority_sha256,
                            source_authority_sha256, payload_json,
                            created_at
                        ) VALUES (
                            :dataset_id, :manifest_sha256, :seal_sha256,
                            :package_sha256, :record_set_sha256,
                            :review_history_authority_sha256,
                            :source_authority_sha256, :payload_json,
                            :created_at
                        )
                    """
                ),
                {
                    **second_values,
                    "seal_sha256": "A" * 64,
                    "payload_json": _canonical_json(second_values["payload"]),
                    "created_at": "2026-07-26T00:00:00+00:00",
                },
            )
    finally:
        runtime.close()


def test_registration_is_canonical_idempotent_and_manifest_bound(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="source-authority-register",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        manifest = _seal_dataset(repository, "locked-source-register")
        values = _authority_values(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
        )

        first = repository.register_candidate_review_source_authority(**values)
        replay = repository.register_candidate_review_source_authority(**values)
        loaded = repository.get_candidate_review_source_authority(manifest.dataset_id)

        assert replay == first
        assert loaded == first
        assert first.payload_json == _canonical_json(values["payload"])
        with runtime.engine.connect() as connection:
            count = connection.execute(
                text("SELECT count(*) FROM locked_set_candidate_review_source_authority")
            ).scalar_one()
        assert count == 1

        conflicting = {
            **values,
            "seal_sha256": hashlib.sha256(b"different-seal").hexdigest(),
        }
        with pytest.raises(
            LockedSetConflictError,
            match="different candidate-review source authority",
        ):
            repository.register_candidate_review_source_authority(**conflicting)

        another = _seal_dataset(repository, "locked-source-mismatch")
        mismatched = _authority_values(
            dataset_id=another.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
        )
        with pytest.raises(
            LockedSetConflictError,
            match="manifest",
        ):
            repository.register_candidate_review_source_authority(**mismatched)
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "insert_prefix",
    ("REPLACE", "INSERT OR REPLACE"),
)
def test_migration_rejects_replace_style_source_authority_overwrite(
    tmp_path: Path,
    project_root: Path,
    insert_prefix: str,
) -> None:
    runtime = _runtime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id=f"source-authority-{insert_prefix.lower().replace(' ', '-')}",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        manifest = _seal_dataset(
            repository,
            "locked-source-replace",
        )
        values = _authority_values(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
        )
        created = repository.register_candidate_review_source_authority(
            **values
        )

        with runtime.engine.connect() as connection:
            assert int(
                connection.exec_driver_sql(
                    "PRAGMA recursive_triggers"
                ).scalar_one()
            ) == 0
        with (
            pytest.raises(IntegrityError, match="append-only"),
            runtime.engine.begin() as connection,
        ):
            connection.execute(
                text(
                    f"""
                    {insert_prefix} INTO
                        locked_set_candidate_review_source_authority (
                            dataset_id, manifest_sha256, seal_sha256,
                            package_sha256, record_set_sha256,
                            review_history_authority_sha256,
                            source_authority_sha256, payload_json,
                            created_at
                        )
                    SELECT
                        dataset_id, manifest_sha256,
                        :changed_seal_sha256,
                        package_sha256, record_set_sha256,
                        review_history_authority_sha256,
                        source_authority_sha256, payload_json,
                        created_at
                    FROM
                        locked_set_candidate_review_source_authority
                    WHERE dataset_id = :dataset_id
                    """
                ),
                {
                    "changed_seal_sha256": "e" * 64,
                    "dataset_id": manifest.dataset_id,
                },
            )

        assert (
            repository.get_candidate_review_source_authority(
                manifest.dataset_id
            )
            == created
        )
    finally:
        runtime.close()


def test_registration_rejects_noncanonical_or_unbound_payload(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="source-authority-invalid",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        manifest = _seal_dataset(repository, "locked-source-invalid")
        values = _authority_values(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
        )
        payload = dict(values["payload"])
        payload["dataset_id"] = "another-dataset"
        with pytest.raises(
            LockedSetPersistenceError,
            match="payload bindings",
        ):
            repository.register_candidate_review_source_authority(**{**values, "payload": payload})

        legacy_payload = dict(values["payload"])
        legacy_payload["schema_version"] = 1
        legacy_without_hash = {
            key: value for key, value in legacy_payload.items() if key != "source_authority_sha256"
        }
        legacy_sha256 = _canonical_sha256(legacy_without_hash)
        legacy_payload["source_authority_sha256"] = legacy_sha256
        with pytest.raises(
            LockedSetPersistenceError,
            match="payload bindings",
        ):
            repository.register_candidate_review_source_authority(
                **{
                    **values,
                    "source_authority_sha256": legacy_sha256,
                    "payload": legacy_payload,
                }
            )

        non_json_payload = dict(values["payload"])
        non_json_payload["invalid_number"] = float("nan")
        with pytest.raises(
            LockedSetPersistenceError,
            match="canonical JSON",
        ):
            repository.register_candidate_review_source_authority(
                **{**values, "payload": non_json_payload}
            )

        with pytest.raises(
            LockedSetPersistenceError,
            match="lowercase SHA-256",
        ):
            repository.register_candidate_review_source_authority(
                **{**values, "seal_sha256": "A" * 64}
            )
        with runtime.engine.connect() as connection:
            count = connection.execute(
                text("SELECT count(*) FROM locked_set_candidate_review_source_authority")
            ).scalar_one()
        assert count == 0
    finally:
        runtime.close()


def test_get_rejects_persisted_payload_tampering(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(
        data_root=tmp_path / "data",
        project_root=project_root,
        instance_id="source-authority-tamper",
    )
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        manifest = _seal_dataset(repository, "locked-source-tamper")
        values = _authority_values(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
        )
        repository.register_candidate_review_source_authority(**values)
        with runtime.engine.begin() as connection:
            connection.execute(
                text("DROP TRIGGER locked_set_candidate_review_source_authority_immutable_update")
            )
            connection.execute(
                text(
                    "UPDATE locked_set_candidate_review_source_authority "
                    "SET payload_json = '{}' "
                    "WHERE dataset_id = :dataset_id"
                ),
                {"dataset_id": manifest.dataset_id},
            )

        with pytest.raises(
            LockedSetConflictError,
            match="persisted candidate-review source authority is inconsistent",
        ):
            repository.get_candidate_review_source_authority(manifest.dataset_id)
    finally:
        runtime.close()


def test_online_backup_restore_retains_source_authority(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(
        data_root=data_root,
        project_root=project_root,
        instance_id="source-authority-backup",
    )
    restored_runtime: SqliteRuntime | None = None
    try:
        repository = SqliteLockedSetRepository(runtime=runtime)
        manifest = _seal_dataset(repository, "locked-source-backup")
        values = _authority_values(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
        )
        expected = repository.register_candidate_review_source_authority(**values)
        backup_service = SqliteBackupService(
            runtime=runtime,
            evidence_store=ContentAddressedEvidenceStore(data_root / "evidence"),
            backup_root=data_root / "backups",
        )
        backup = backup_service.create_online_backup()
        restored_root = tmp_path / "restored"
        restored_root.mkdir()
        backup_service.restore_to_temporary(
            backup.path,
            restored_root,
        )
        restored_runtime = _runtime(
            data_root=restored_root,
            project_root=project_root,
            instance_id="source-authority-restored",
        )

        restored = SqliteLockedSetRepository(
            runtime=restored_runtime
        ).get_candidate_review_source_authority(manifest.dataset_id)
        assert restored == expected
    finally:
        if restored_runtime is not None:
            restored_runtime.close()
        runtime.close()
