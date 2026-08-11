from __future__ import annotations

import hashlib
import importlib
import json
import sqlite3
import threading
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import URL

LOADING_BYTES = b"\x89PNG\r\n\x1a\nDaHe Loop 4 loading synthetic evidence"
UNLOADING_BYTES = b"\x89PNG\r\n\x1a\nDaHe Loop 4 unloading synthetic evidence"


class InjectedCommitFailure(RuntimeError):
    pass


def _module(name: str) -> ModuleType:
    return importlib.import_module(name)


def _runtime(
    tmp_path: Path,
    project_root: Path,
    *,
    instance_id: str = "loop4-test-instance",
) -> Any:
    runtime_module = _module("dahe.adapters.sqlite.runtime")
    return runtime_module.SqliteRuntime(
        data_root=tmp_path,
        project_root=project_root,
        instance_id=instance_id,
    )


def _store(data_root: Path) -> Any:
    files_module = _module("dahe.adapters.files.content_addressed")
    return files_module.ContentAddressedEvidenceStore(data_root / "evidence")


def _repository(runtime: Any, store: Any) -> Any:
    evidence_module = _module("dahe.adapters.sqlite.evidence")
    return evidence_module.DurableEvidenceRepository(runtime=runtime, evidence_store=store)


def _bundle(capture_id: str = "capture-001") -> dict[str, object]:
    return {
        "capture_id": capture_id,
        "captured_at": "2026-07-25T08:00:00+00:00",
        "request_contract_version": "loop4-frozen-v1",
        "waybills": [
            {
                "platform_waybill_id": "fixture-waybill-001",
                "waybill_number": "WB-LOOP4-001",
                "business_fields": {
                    "vehicle_number": "TEST-001",
                    "loading_net": "30.00",
                    "unloading_net": "29.80",
                },
                "images": [
                    {
                        "slot": "loading",
                        "content": LOADING_BYTES,
                        "media_type": "image/png",
                    },
                    {
                        "slot": "unloading",
                        "content": UNLOADING_BYTES,
                        "media_type": "image/png",
                    },
                ],
            }
        ],
    }


def _scalar(runtime: Any, sql: str) -> int:
    with runtime.engine.connect() as connection:
        return int(connection.execute(text(sql)).scalar_one())


def _migration_config(project_root: Path, database_path: Path) -> Config:
    config = Config(str(project_root / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(project_root / "src" / "dahe" / "adapters" / "sqlite" / "migrations"),
    )
    url = URL.create("sqlite+pysqlite", database=str(database_path))
    config.set_main_option(
        "sqlalchemy.url",
        url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    return config


def test_fresh_runtime_is_at_migration_head_with_required_sqlite_pragmas(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    try:
        assert runtime.database_path == tmp_path.resolve() / "database" / "dahe.sqlite3"
        assert runtime.current_revision() == runtime.head_revision
        with runtime.engine.connect() as connection:
            assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() >= 1000
            assert connection.exec_driver_sql("PRAGMA integrity_check").scalar_one() == "ok"
            assert (
                connection.execute(text("SELECT count(*) FROM alembic_version")).scalar_one() == 1
            )
            tables = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            lease_foreign_keys = {
                (str(row[2]), str(row[3]), str(row[4]))
                for row in connection.exec_driver_sql("PRAGMA foreign_key_list('leases')")
            }
            assert "shared_work_retry_requests" in tables
            assert (
                "resource_slots",
                "resource_name",
                "resource_name",
            ) in lease_foreign_keys
    finally:
        runtime.close()


def test_runtime_upgrades_0001_with_backup_and_preserves_data(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "upgrade-from-0001"
    database_path = data_root / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    command.upgrade(_migration_config(project_root, database_path), "0001_loop4")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO system_meta (key, value) VALUES (?, ?)",
            ("migration-fixture", "preserve-me"),
        )
        connection.execute(
            """
            INSERT INTO leases (
                lease_id,
                resource_name,
                holder_kind,
                holder_id,
                status
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                "lease-before-0002",
                "gpu_ocr_slot",
                "job",
                "fixture-holder",
                "released",
            ),
        )
        connection.commit()
        assert (
            connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
            == "0001_loop4"
        )
        assert (
            connection.execute(
                "SELECT count(*) FROM sqlite_master "
                "WHERE type = 'table' AND name = 'shared_work_retry_requests'"
            ).fetchone()[0]
            == 0
        )

    runtime = _runtime(data_root, project_root, instance_id="upgrade-0001-test")
    try:
        assert runtime.current_revision() == (
            "0039_network_batch_default"
        )
        assert runtime.pre_migration_backup_path is not None
        backup_path = runtime.pre_migration_backup_path
        manifest = json.loads((backup_path / "manifest.json").read_text(encoding="utf-8"))
        backup_database = backup_path / "dahe.sqlite3"

        assert manifest["from_revision"] == "0001_loop4"
        assert manifest["to_revision"] == (
            "0039_network_batch_default"
        )
        assert (
            manifest["database_sha256"] == hashlib.sha256(backup_database.read_bytes()).hexdigest()
        )
        with sqlite3.connect(backup_database) as connection:
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert (
                connection.execute("SELECT version_num FROM alembic_version").fetchone()[0]
                == "0001_loop4"
            )
            assert (
                connection.execute(
                    "SELECT value FROM system_meta WHERE key = 'migration-fixture'"
                ).fetchone()[0]
                == "preserve-me"
            )

        with runtime.engine.connect() as connection:
            tables = {
                str(row[0])
                for row in connection.exec_driver_sql(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            lease_foreign_keys = {
                (str(row[2]), str(row[3]), str(row[4]))
                for row in connection.exec_driver_sql("PRAGMA foreign_key_list('leases')")
            }
            assert (
                connection.execute(
                    text("SELECT value FROM system_meta WHERE key = 'migration-fixture'")
                ).scalar_one()
                == "preserve-me"
            )
            assert (
                connection.execute(
                    text("SELECT resource_name FROM leases WHERE lease_id = 'lease-before-0002'")
                ).scalar_one()
                == "gpu_ocr_slot"
            )
            assert "shared_work_retry_requests" in tables
            assert (
                "resource_slots",
                "resource_name",
                "resource_name",
            ) in lease_foreign_keys
    finally:
        runtime.close()


def test_upgrade_0020_preserves_settlement_identity_children(
    tmp_path: Path,
    project_root: Path,
) -> None:
    data_root = tmp_path / "upgrade-from-0020-with-settlement-identities"
    database_path = data_root / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    config = _migration_config(project_root, database_path)
    command.upgrade(config, "0020_loop9_exclusion_authority_anchor")
    created_at = "2026-07-30T08:00:00+00:00"
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(
            """
            INSERT INTO jobs (
                job_id, task_type, scope_label, scope_fixture_id,
                scope_fingerprint, run_mode, status, current_stage,
                diagnostic_code, job_kind, ocr_execution_mode, conflict_key,
                created_sequence, record_version, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "migration-settlement-job",
                "settlement_capture",
                "formal locked set capture",
                "chengfeng-pending-settlement",
                "a" * 64,
                "shadow",
                "queued",
                "settlement_capture.read",
                None,
                "business",
                "fake",
                "settlement_capture:formal",
                1,
                1,
                created_at,
                created_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO platform_access_windows (
                access_window_id, purpose, job_id, session_id, build_sha256,
                token_digest, issued_at, expires_at, consumed_at,
                record_version, idempotency_key, request_hash,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "migration-access-window",
                "formal_locked_set",
                "migration-settlement-job",
                "migration-browser-session",
                "b" * 64,
                "c" * 64,
                created_at,
                "2026-07-30T09:00:00+00:00",
                None,
                1,
                "migration-access-idempotency",
                "d" * 64,
                created_at,
                created_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO settlement_capture_invocations (
                invocation_id, job_id, access_window_id, scope, page_size,
                source_build_sha256, contract_canonical_sha256,
                contract_file_sha256, contract_selection_sha256,
                identity_context_sha256, status, manifest_sha256,
                manifest_json, diagnostic_code, record_version,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "migration-invocation",
                "migration-settlement-job",
                "migration-access-window",
                "current",
                50,
                "e" * 64,
                "f" * 64,
                "1" * 64,
                "2" * 64,
                "3" * 64,
                "collecting",
                None,
                None,
                None,
                1,
                created_at,
                created_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO settlement_capture_identities (
                invocation_id, item_identity_sha256, platform_waybill_id,
                waybill_number, vehicle_number, source_page_number, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "migration-invocation",
                "4" * 64,
                "protected-platform-waybill",
                "protected-waybill-number",
                "protected-vehicle",
                1,
                created_at,
            ),
        )
        connection.execute(
            """
            INSERT INTO loop9_exclusion_authority_anchors (
                sequence, node_sha256, previous_head_sha256,
                source_boundary_sha256, source_inventory_high_watermark,
                identity_context_sha256, expected_current_build_sha256,
                expected_settlement_contract_sha256,
                expected_daily_contract_sha256,
                expected_settlement_selection_sha256,
                expected_daily_selection_sha256, child_inventory_sha256,
                child_exclusion_kind, child_platform_identity_count,
                child_image_count, child_scope_exclusion_token_count,
                child_perceptual_fingerprint_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                1,
                "5" * 64,
                None,
                "6" * 64,
                23,
                "7" * 64,
                "8" * 64,
                "9" * 64,
                "a" * 64,
                "b" * 64,
                "c" * 64,
                "d" * 64,
                "development",
                1,
                1,
                0,
                1,
            ),
        )
        connection.execute(
            """
            INSERT INTO loop9_exclusion_authority_anchors (
                sequence, node_sha256, previous_head_sha256,
                source_boundary_sha256, source_inventory_high_watermark,
                identity_context_sha256, expected_current_build_sha256,
                expected_settlement_contract_sha256,
                expected_daily_contract_sha256,
                expected_settlement_selection_sha256,
                expected_daily_selection_sha256, child_inventory_sha256,
                child_exclusion_kind, child_platform_identity_count,
                child_image_count, child_scope_exclusion_token_count,
                child_perceptual_fingerprint_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                2,
                "e" * 64,
                "5" * 64,
                "6" * 64,
                23,
                "7" * 64,
                "8" * 64,
                "9" * 64,
                "a" * 64,
                "b" * 64,
                "c" * 64,
                "f" * 64,
                "development",
                1,
                1,
                0,
                1,
            ),
        )
        connection.execute(
            "CREATE TABLE loop9_exclusion_authority_anchors_v2 "
            "(failed_attempt_marker INTEGER)"
        )
        connection.commit()

    command.upgrade(config, "head")

    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        assert connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone() == ("0039_network_batch_default",)
        assert connection.execute(
            """
            SELECT invocation_id, item_identity_sha256, platform_waybill_id,
                   waybill_number, vehicle_number, source_page_number
            FROM settlement_capture_identities
            """
        ).fetchone() == (
            "migration-invocation",
            "4" * 64,
            "protected-platform-waybill",
            "protected-waybill-number",
            "protected-vehicle",
            1,
        )
        anchors = connection.execute(
            """
            SELECT authority_context_sha256, sequence, node_sha256
            FROM loop9_exclusion_authority_anchors
            ORDER BY sequence
            """
        ).fetchall()
        assert len(anchors) == 2
        assert len(str(anchors[0][0])) == 64
        assert anchors[0][0] == anchors[1][0]
        assert [anchor[1:] for anchor in anchors] == [
            (1, "5" * 64),
            (2, "e" * 64),
        ]
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE loop9_exclusion_authority_anchors "
                "SET sequence = sequence"
            )
        connection.rollback()
        invocation_columns = {
            str(row[1])
            for row in connection.execute(
                "PRAGMA table_info('settlement_capture_invocations')"
            )
        }
        assert {
            "selection_manifest_sha256",
            "batch_manifest_sha256",
        } <= invocation_columns
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        with pytest.raises(
            sqlite3.IntegrityError,
            match="settlement_capture_identities is append-only",
        ):
            connection.execute(
                """
                UPDATE settlement_capture_identities
                SET vehicle_number = ?
                WHERE invocation_id = ?
                """,
                ("must-not-change", "migration-invocation"),
            )


def test_alembic_task_schema_matches_the_runtime_metadata_contract(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    schema_module = _module("dahe.adapters.sqlite.schema")
    try:
        with runtime.engine.connect() as connection:
            for table in schema_module.METADATA.tables.values():
                migrated_columns = {
                    str(row[1])
                    for row in connection.exec_driver_sql(f'PRAGMA table_info("{table.name}")')
                }
                assert migrated_columns == {column.name for column in table.columns}
    finally:
        runtime.close()


def test_daily_capture_tables_reference_existing_access_windows(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    try:
        with runtime.engine.connect() as connection:
            for table_name in (
                "daily_capture_invocations",
                "daily_capture_start_requests",
            ):
                columns = {
                    str(row[1]): str(row[2]).upper()
                    for row in connection.exec_driver_sql(
                        f'PRAGMA table_info("{table_name}")'
                    )
                }
                foreign_keys = {
                    (
                        str(row[2]),
                        str(row[3]),
                        str(row[4]),
                        str(row[6]).upper(),
                    )
                    for row in connection.exec_driver_sql(
                        f'PRAGMA foreign_key_list("{table_name}")'
                    )
                }
                assert columns["access_window_id"] == "VARCHAR(32)"
                assert (
                    "platform_access_windows",
                    "access_window_id",
                    "access_window_id",
                    "RESTRICT",
                ) in foreign_keys
    finally:
        runtime.close()


def test_import_bundle_is_atomic_idempotent_and_keeps_one_blob_per_hash(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    store = _store(tmp_path)
    repository = _repository(runtime, store)
    try:
        first = repository.import_bundle(_bundle(), idempotency_key="import-001")
        replay = repository.import_bundle(_bundle(), idempotency_key="import-001")

        assert first.created is True
        assert replay.created is False
        assert replay.import_id == first.import_id
        assert _scalar(runtime, "SELECT count(*) FROM platform_snapshots") == 1
        assert _scalar(runtime, "SELECT count(*) FROM evidence_blobs") == 2
        assert _scalar(runtime, "SELECT count(*) FROM evidence_references") == 2
        assert store.read_bytes(first.image_sha256s["loading"]) == LOADING_BYTES
        assert store.read_bytes(first.image_sha256s["unloading"]) == UNLOADING_BYTES
    finally:
        runtime.close()


def test_failure_inside_snapshot_transaction_leaves_no_partial_business_rows(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    store = _store(tmp_path)
    repository = _repository(runtime, store)

    def failpoint(name: str) -> None:
        if name == "after_snapshot_insert":
            raise InjectedCommitFailure("simulated process interruption")

    try:
        with pytest.raises(InjectedCommitFailure):
            repository.import_bundle(
                _bundle(),
                idempotency_key="import-crash-001",
                failpoint=failpoint,
            )

        assert _scalar(runtime, "SELECT count(*) FROM platform_snapshots") == 0
        assert _scalar(runtime, "SELECT count(*) FROM evidence_references") == 0
        assert _scalar(runtime, "SELECT count(*) FROM evidence_blobs") == 0

        recovered = repository.import_bundle(
            _bundle(),
            idempotency_key="import-crash-001",
        )
        assert recovered.created is True
        assert _scalar(runtime, "SELECT count(*) FROM platform_snapshots") == 1
        assert _scalar(runtime, "SELECT count(*) FROM evidence_references") == 2
    finally:
        runtime.close()


def test_hold_blocks_cleanup_and_cleanup_claim_races_safely_with_new_reference(
    tmp_path: Path,
    project_root: Path,
) -> None:
    runtime = _runtime(tmp_path, project_root)
    store = _store(tmp_path)
    repository = _repository(runtime, store)
    evidence_module = _module("dahe.adapters.sqlite.evidence")
    try:
        imported = repository.import_bundle(_bundle(), idempotency_key="import-race-001")
        sha256 = imported.image_sha256s["loading"]
        state = repository.get_evidence_state(sha256)
        for reference in state.references:
            repository.release_reference(
                reference.reference_id,
                expected_record_version=reference.record_version,
                idempotency_key=f"release-{reference.reference_id}",
            )
        state = repository.get_evidence_state(sha256)
        hold = repository.add_hold(
            sha256=sha256,
            hold_kind="manual_pin",
            owner_id="loop4-test",
            reason="test hold",
            expected_record_version=state.record_version,
            idempotency_key="hold-001",
        )
        assert (
            repository.claim_for_cleanup(
                sha256=sha256,
                claim_id="claim-blocked",
                expected_record_version=hold.evidence_record_version,
            )
            is None
        )
        repository.release_hold(
            hold.hold_id,
            expected_record_version=hold.record_version,
            idempotency_key="release-hold-001",
        )

        barrier = threading.Barrier(2)
        results: dict[str, object] = {}
        errors: dict[str, BaseException] = {}
        race_version = repository.get_evidence_state(sha256).record_version

        def run(name: str, action: Callable[[], object]) -> None:
            try:
                barrier.wait(timeout=2)
                results[name] = action()
            except BaseException as exc:  # captured for assertions after both threads finish
                errors[name] = exc

        claim_thread = threading.Thread(
            target=run,
            args=(
                "claim",
                lambda: repository.claim_for_cleanup(
                    sha256=sha256,
                    claim_id="claim-race",
                    expected_record_version=race_version,
                ),
            ),
        )
        reference_thread = threading.Thread(
            target=run,
            args=(
                "reference",
                lambda: repository.add_reference(
                    sha256=sha256,
                    owner_kind="work_item",
                    owner_id="concurrent-work-item",
                    role="loading",
                    expected_record_version=race_version,
                    idempotency_key="concurrent-reference-001",
                ),
            ),
        )
        claim_thread.start()
        reference_thread.start()
        claim_thread.join(timeout=3)
        reference_thread.join(timeout=3)

        assert not claim_thread.is_alive()
        assert not reference_thread.is_alive()
        allowed_conflicts = (
            evidence_module.EvidenceCleanupConflictError,
            evidence_module.EvidenceRecordVersionConflictError,
        )
        assert all(isinstance(error, allowed_conflicts) for error in errors.values())
        final_state = repository.get_evidence_state(sha256)
        assert not (
            final_state.active_cleanup_claim is not None and final_state.active_reference_count > 0
        )
        assert "claim" in results or "reference" in results
    finally:
        runtime.close()


def test_online_backup_restores_database_and_evidence_to_an_empty_temporary_root(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source_root = tmp_path / "source"
    restore_root = tmp_path / "restored"
    runtime = _runtime(source_root, project_root, instance_id="backup-source")
    store = _store(source_root)
    repository = _repository(runtime, store)
    backup_module = _module("dahe.maintenance.backup")
    service = backup_module.SqliteBackupService(
        runtime=runtime,
        evidence_store=store,
        backup_root=source_root / "backups",
    )
    restored_runtime = None
    try:
        imported = repository.import_bundle(_bundle(), idempotency_key="backup-import-001")
        backup = service.create_online_backup()
        restore_root.mkdir()
        report = service.restore_to_temporary(backup.path, restore_root)

        assert report.data_root == restore_root.resolve()
        assert report.integrity_check == "ok"
        restored_runtime = _runtime(
            restore_root,
            project_root,
            instance_id="backup-restored-validation",
        )
        assert _scalar(restored_runtime, "SELECT count(*) FROM platform_snapshots") == 1
        assert _scalar(restored_runtime, "SELECT count(*) FROM evidence_references") == 2
        restored_store = _store(restore_root)
        assert restored_store.read_bytes(imported.image_sha256s["loading"]) == LOADING_BYTES
        assert restored_store.read_bytes(imported.image_sha256s["unloading"]) == UNLOADING_BYTES
    finally:
        if restored_runtime is not None:
            restored_runtime.close()
        runtime.close()


def test_online_backup_includes_evidence_protected_only_by_an_active_hold(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source_root = tmp_path / "source"
    restore_root = tmp_path / "restored"
    runtime = _runtime(source_root, project_root, instance_id="backup-hold-source")
    store = _store(source_root)
    repository = _repository(runtime, store)
    backup_module = _module("dahe.maintenance.backup")
    service = backup_module.SqliteBackupService(
        runtime=runtime,
        evidence_store=store,
        backup_root=source_root / "backups",
    )
    try:
        imported = repository.import_bundle(_bundle(), idempotency_key="backup-hold-import")
        held_sha256 = imported.image_sha256s["loading"]
        state = repository.get_evidence_state(held_sha256)
        for reference in state.references:
            repository.release_reference(
                reference.reference_id,
                expected_record_version=reference.record_version,
                idempotency_key=f"backup-hold-release-{reference.reference_id}",
            )
        state = repository.get_evidence_state(held_sha256)
        repository.add_hold(
            sha256=held_sha256,
            hold_kind="manual_pin",
            owner_id="backup-hold-test",
            reason="must remain recoverable",
            expected_record_version=state.record_version,
            idempotency_key="backup-hold-add",
        )

        backup = service.create_online_backup()
        report = service.restore_to_temporary(backup.path, restore_root)

        assert report.evidence_count == 2
        restored_store = _store(restore_root)
        assert restored_store.read_bytes(held_sha256) == LOADING_BYTES
    finally:
        runtime.close()


def test_failed_restore_leaves_target_retryable_after_evidence_is_repaired(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source_root = tmp_path / "source"
    restore_root = tmp_path / "restored"
    runtime = _runtime(source_root, project_root, instance_id="backup-retry-source")
    store = _store(source_root)
    repository = _repository(runtime, store)
    backup_module = _module("dahe.maintenance.backup")
    service = backup_module.SqliteBackupService(
        runtime=runtime,
        evidence_store=store,
        backup_root=source_root / "backups",
    )
    try:
        repository.import_bundle(_bundle(), idempotency_key="backup-retry-import")
        backup = service.create_online_backup()
        manifest = json.loads((backup.path / "manifest.json").read_text(encoding="utf-8"))
        second_entry = manifest["evidence"][1]
        evidence_path = backup.path / "evidence" / second_entry["relative_path"]
        original_content = evidence_path.read_bytes()
        evidence_path.write_bytes(b"x" * len(original_content))

        with pytest.raises(
            backup_module.BackupIntegrityError,
            match="evidence hash",
        ):
            service.restore_to_temporary(backup.path, restore_root)

        assert not restore_root.exists() or not any(restore_root.iterdir())
        assert not tuple(tmp_path.glob(".restored.*.restore-staging"))

        evidence_path.write_bytes(original_content)
        report = service.restore_to_temporary(backup.path, restore_root)
        assert report.integrity_check == "ok"
        assert report.evidence_count == 2
    finally:
        runtime.close()


def test_restore_rejects_manifest_missing_an_active_database_evidence_identity(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source_root = tmp_path / "source"
    restore_root = tmp_path / "restored"
    runtime = _runtime(source_root, project_root, instance_id="backup-manifest-source")
    store = _store(source_root)
    repository = _repository(runtime, store)
    backup_module = _module("dahe.maintenance.backup")
    service = backup_module.SqliteBackupService(
        runtime=runtime,
        evidence_store=store,
        backup_root=source_root / "backups",
    )
    try:
        repository.import_bundle(_bundle(), idempotency_key="backup-manifest-import")
        backup = service.create_online_backup()
        manifest_path = backup.path / "manifest.json"
        original_manifest = manifest_path.read_bytes()
        manifest = json.loads(original_manifest)
        manifest["evidence"].pop()
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

        with pytest.raises(
            backup_module.BackupIntegrityError,
            match="every active database identity",
        ):
            service.restore_to_temporary(backup.path, restore_root)

        assert not restore_root.exists() or not any(restore_root.iterdir())
        assert not tuple(tmp_path.glob(".restored.*.restore-staging"))

        manifest_path.write_bytes(original_manifest)
        report = service.restore_to_temporary(backup.path, restore_root)
        assert report.integrity_check == "ok"
        assert report.evidence_count == 2
    finally:
        runtime.close()


def test_restore_refuses_a_nonempty_target(
    tmp_path: Path,
    project_root: Path,
) -> None:
    source_root = tmp_path / "source"
    runtime = _runtime(source_root, project_root, instance_id="backup-source")
    store = _store(source_root)
    repository = _repository(runtime, store)
    backup_module = _module("dahe.maintenance.backup")
    service = backup_module.SqliteBackupService(
        runtime=runtime,
        evidence_store=store,
        backup_root=source_root / "backups",
    )
    try:
        repository.import_bundle(_bundle(), idempotency_key="backup-import-002")
        backup = service.create_online_backup()
        restore_root = tmp_path / "not-empty"
        restore_root.mkdir()
        (restore_root / "keep.txt").write_text("do not overwrite", encoding="utf-8")

        with pytest.raises(backup_module.UnsafeRestoreTargetError):
            service.restore_to_temporary(backup.path, restore_root)
        assert (restore_root / "keep.txt").read_text(encoding="utf-8") == "do not overwrite"
    finally:
        runtime.close()


def test_unknown_alembic_revision_is_rejected_without_modifying_database(
    tmp_path: Path,
    project_root: Path,
) -> None:
    database_path = tmp_path / "database" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)")
        connection.execute("INSERT INTO alembic_version (version_num) VALUES ('unknown-loop4')")
        connection.commit()
    original_sha256 = hashlib.sha256(database_path.read_bytes()).hexdigest()
    runtime_module = _module("dahe.adapters.sqlite.runtime")

    with pytest.raises(
        runtime_module.DatabaseMigrationError,
        match="revision is unknown",
    ):
        _runtime(tmp_path, project_root)

    assert hashlib.sha256(database_path.read_bytes()).hexdigest() == original_sha256
    assert not database_path.with_name(f"{database_path.name}-wal").exists()
    assert not database_path.with_name(f"{database_path.name}-shm").exists()


def test_pre_migration_backup_is_integrity_checked_and_self_describing(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "source" / "dahe.sqlite3"
    database_path.parent.mkdir(parents=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE evidence (value TEXT NOT NULL)")
        connection.execute("INSERT INTO evidence (value) VALUES ('frozen')")
        connection.commit()
    runtime_module = _module("dahe.adapters.sqlite.runtime")

    backup_path = runtime_module.create_pre_migration_backup(
        database_path=database_path,
        backup_root=tmp_path / "backups",
        from_revision="loop4-old",
        to_revision="loop4-new",
    )

    database_copy = backup_path / "dahe.sqlite3"
    manifest = json.loads((backup_path / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["backup_kind"] == "pre_migration"
    assert manifest["from_revision"] == "loop4-old"
    assert manifest["to_revision"] == "loop4-new"
    assert manifest["database_sha256"] == hashlib.sha256(database_copy.read_bytes()).hexdigest()
    with sqlite3.connect(database_copy) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT value FROM evidence").fetchone()[0] == "frozen"
