from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.engine import URL

from dahe.adapters.sqlite.production_guard import ProductionReadOnlyGuardStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    JOBS,
    PRODUCTION_READ_ONLY_GUARD_ITEMS,
    WORK_ITEMS,
)
from dahe.verification.operational_read_only_acceptance import _verify_guard

PROJECT_ROOT = Path(__file__).parents[2]


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _runtime(tmp_path: Path) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="production-guard-test",
    )


def _migration_config(database_path: Path) -> Config:
    config = Config(str(PROJECT_ROOT / "alembic.ini"))
    config.set_main_option(
        "script_location",
        str(PROJECT_ROOT / "src" / "dahe" / "adapters" / "sqlite" / "migrations"),
    )
    url = URL.create("sqlite+pysqlite", database=str(database_path))
    config.set_main_option(
        "sqlalchemy.url",
        url.render_as_string(hide_password=False).replace("%", "%%"),
    )
    return config


def _seed_items(runtime: SqliteRuntime, count: int) -> tuple[str, ...]:
    job_id = "p" * 32
    identities = tuple(f"{index:032x}" for index in range(1, count + 1))
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        connection.execute(
            JOBS.insert().values(
                job_id=job_id,
                task_type="audit",
                scope_label="生产首批",
                scope_fixture_id="operational:first-batch",
                scope_fingerprint=_sha("production-guard"),
                run_mode="operational",
                status="succeeded",
                current_stage="audit.complete",
                job_kind="business",
                ocr_execution_mode="local",
                conflict_key="audit:production:first-batch",
                created_sequence=1,
                record_version=1,
                created_at="2026-08-02T00:00:00+00:00",
                updated_at="2026-08-02T00:00:00+00:00",
            )
        )
        for index, identity in enumerate(identities):
            connection.execute(
                WORK_ITEMS.insert().values(
                    work_item_id=identity,
                    job_id=job_id,
                    record_version=1,
                    waybill_number=f"WB-{index + 1:03d}",
                    vehicle_number=f"TEST-{index + 1:03d}",
                    status="succeeded",
                    current_stage="audit.complete",
                    business_outcome="normal_ready",
                    decision="pass",
                    item_index=index,
                    attempt_count=1,
                    download_complete=1,
                    loading_ocr_complete=1,
                    unloading_ocr_complete=1,
                    ready_sequence=index + 1,
                )
            )
    return identities


def _seed_duplicate_waybill(
    runtime: SqliteRuntime,
    *,
    source_work_item_id: str,
    duplicate_work_item_id: str,
) -> None:
    with runtime.commit_gate.transaction(runtime.engine) as connection:
        source = connection.execute(
            select(WORK_ITEMS).where(
                WORK_ITEMS.c.work_item_id == source_work_item_id
            )
        ).one()
        connection.execute(
            WORK_ITEMS.insert().values(
                work_item_id=duplicate_work_item_id,
                job_id=source.job_id,
                record_version=1,
                waybill_number=source.waybill_number,
                vehicle_number=source.vehicle_number,
                status="succeeded",
                current_stage="audit.complete",
                business_outcome="normal_ready",
                decision="pass",
                item_index=100,
                attempt_count=1,
                download_complete=1,
                loading_ocr_complete=1,
                unloading_ocr_complete=1,
                ready_sequence=101,
            )
        )


@pytest.mark.integration
def test_all_machine_normal_items_are_guarded_until_first_30_pass(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    try:
        identities = _seed_items(runtime, 35)
        guard = ProductionReadOnlyGuardStore(runtime, enforce_first_batch=True)
        for identity in identities:
            guarded = guard.register_result(
                work_item_id=identity,
                machine_outcome="normal_ready",
            )
            assert guarded is True

        with runtime.engine.connect() as connection:
            guarded_count = connection.execute(
                select(WORK_ITEMS).where(
                    WORK_ITEMS.c.business_outcome == "awaiting_review"
                )
            ).all()
        assert len(guarded_count) == 35
        assert guard.status().status == "operational_read_only_with_guard"

        for index, identity in enumerate(identities[:30], start=1):
            guard.record_manual_decision(
                work_item_id=identity,
                action_id=f"action-{index}",
                manual_outcome="normal_ready",
            )

        status = guard.status()
        assert status.status == "operational_read_only_accepted"
        assert status.reviewed_target_count == 30
        assert status.false_normal_count == 0
        with runtime.engine.connect() as connection:
            overflow = tuple(
                connection.execute(
                    select(
                        WORK_ITEMS.c.status,
                        WORK_ITEMS.c.business_outcome,
                        WORK_ITEMS.c.review_reason,
                    ).where(WORK_ITEMS.c.work_item_id.in_(identities[30:]))
                )
            )
        assert overflow == (("succeeded", "normal_ready", None),) * 5
    finally:
        runtime.close()


@pytest.mark.integration
def test_one_false_normal_keeps_all_future_normal_items_guarded(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    try:
        identities = _seed_items(runtime, 31)
        guard = ProductionReadOnlyGuardStore(runtime, enforce_first_batch=True)
        for identity in identities[:30]:
            guard.register_result(
                work_item_id=identity,
                machine_outcome="normal_ready",
            )
        for index, identity in enumerate(identities[:29], start=1):
            guard.record_manual_decision(
                work_item_id=identity,
                action_id=f"normal-{index}",
                manual_outcome="normal_ready",
            )
        guard.record_manual_decision(
            work_item_id=identities[29],
            action_id="found-problem",
            manual_outcome="confirmed_problem",
        )
        assert guard.status().status == "operational_read_only_with_guard"
        assert guard.status().false_normal_count == 1

        assert guard.register_result(
            work_item_id=identities[30],
            machine_outcome="normal_ready",
        ) is True
        with runtime.engine.connect() as connection:
            future = connection.execute(
                select(WORK_ITEMS).where(
                    WORK_ITEMS.c.work_item_id == identities[30]
                )
            ).one()
        assert future.business_outcome == "awaiting_review"
        assert future.review_reason == "production_first_batch_guard"
    finally:
        runtime.close()


@pytest.mark.integration
def test_technical_failure_never_consumes_a_first_batch_slot(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    try:
        identities = _seed_items(runtime, 31)
        guard = ProductionReadOnlyGuardStore(runtime, enforce_first_batch=True)

        assert guard.register_result(
            work_item_id=identities[0],
            machine_outcome="technical_failure",
        ) is False
        assert guard.status().registered_count == 0

        for identity in identities[1:]:
            guard.register_result(
                work_item_id=identity,
                machine_outcome="normal_ready",
            )

        status = guard.status()
        assert status.registered_count == 30
        assert status.reviewed_target_count == 0
    finally:
        runtime.close()


@pytest.mark.integration
def test_repeated_capture_of_same_waybill_uses_one_guard_slot(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    try:
        identities = _seed_items(runtime, 1)
        duplicate_id = "f" * 32
        _seed_duplicate_waybill(
            runtime,
            source_work_item_id=identities[0],
            duplicate_work_item_id=duplicate_id,
        )
        guard = ProductionReadOnlyGuardStore(runtime, enforce_first_batch=True)

        assert guard.register_result(
            work_item_id=identities[0],
            machine_outcome="normal_ready",
        ) is True
        assert guard.register_result(
            work_item_id=duplicate_id,
            machine_outcome="normal_ready",
        ) is True
        assert guard.status().registered_count == 1

        status = guard.record_manual_decision(
            work_item_id=duplicate_id,
            action_id="duplicate-review",
            manual_outcome="normal_ready",
        )
        assert status.registered_count == 1
        assert status.reviewed_target_count == 1
        with runtime.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(PRODUCTION_READ_ONLY_GUARD_ITEMS).order_by(
                        PRODUCTION_READ_ONLY_GUARD_ITEMS.c.ordinal
                    )
                )
            )
        assert len(rows) == 2
        assert sum(row.counts_toward_gate for row in rows) == 1
        assert rows[0].business_identity_sha256 == rows[1].business_identity_sha256
        assert rows[0].manual_action_id == "duplicate-review"
    finally:
        runtime.close()


@pytest.mark.integration
def test_operational_acceptance_preserves_an_incomplete_guard(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    runtime = _runtime(tmp_path)
    try:
        identities = _seed_items(runtime, 2)
        guard = ProductionReadOnlyGuardStore(runtime, enforce_first_batch=True)
        for identity in identities:
            guard.register_result(
                work_item_id=identity,
                machine_outcome="normal_ready",
            )

        projection = _verify_guard(data_root)
        assert projection == {
            "false_normal_count": 0,
            "record_version": 3,
            "registered_count": 2,
            "reviewed_count": 0,
            "status": "operational_read_only_with_guard",
            "target_count": 30,
        }
    finally:
        runtime.close()


@pytest.mark.integration
def test_migration_collapses_legacy_duplicate_guard_slots(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    database_path = runtime.database_path
    identities = _seed_items(runtime, 1)
    duplicate_id = "e" * 32
    _seed_duplicate_waybill(
        runtime,
        source_work_item_id=identities[0],
        duplicate_work_item_id=duplicate_id,
    )
    guard = ProductionReadOnlyGuardStore(runtime, enforce_first_batch=True)
    guard.register_result(work_item_id=identities[0], machine_outcome="normal_ready")
    guard.register_result(work_item_id=duplicate_id, machine_outcome="normal_ready")
    runtime.close()

    config = _migration_config(database_path)
    command.downgrade(config, "0033_production_guard")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE production_read_only_guard_items SET counts_toward_gate = 1"
        )
        connection.execute(
            "UPDATE production_read_only_guard SET registered_count = 2"
        )
        connection.commit()

    migrated = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="production-guard-migration-test",
    )
    try:
        assert migrated.current_revision() == "0039_network_batch_default"
        assert migrated.pre_migration_backup_path is not None
        migrated_status = ProductionReadOnlyGuardStore(migrated).status()
        assert migrated_status.status == "operational_read_only_active"
        assert migrated_status.registered_count == 1
        with migrated.engine.connect() as connection:
            rows = tuple(
                connection.execute(
                    select(PRODUCTION_READ_ONLY_GUARD_ITEMS).order_by(
                        PRODUCTION_READ_ONLY_GUARD_ITEMS.c.ordinal
                    )
                )
            )
        assert len(rows) == 2
        assert sum(row.counts_toward_gate for row in rows) == 1
        assert rows[0].business_identity_sha256 == rows[1].business_identity_sha256
        assert all(row.released == 1 for row in rows)
        with migrated.engine.connect() as connection:
            restored_items = tuple(
                connection.execute(
                    select(
                        WORK_ITEMS.c.status,
                        WORK_ITEMS.c.business_outcome,
                        WORK_ITEMS.c.review_reason,
                    ).order_by(WORK_ITEMS.c.item_index)
                )
            )
            restored_job = connection.execute(select(JOBS)).one()
        assert restored_items == (
            ("succeeded", "normal_ready", None),
            ("succeeded", "normal_ready", None),
        )
        assert restored_job.status == "succeeded"
    finally:
        migrated.close()


@pytest.mark.integration
def test_active_read_only_production_does_not_guard_machine_normal_items(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        identity = _seed_items(runtime, 1)[0]
        guard = ProductionReadOnlyGuardStore(runtime)

        assert guard.register_result(
            work_item_id=identity,
            machine_outcome="normal_ready",
        ) is False
        status = guard.status()
        assert status.status == "operational_read_only_active"
        assert status.registered_count == 0
        assert status.to_payload() == {
            "false_normal_count": 0,
            "guard_active": False,
            "record_version": 1,
            "registered_count": 0,
            "reviewed_count": 0,
            "status": "operational_read_only_active",
            "target_count": 30,
        }
        with runtime.engine.connect() as connection:
            item = connection.execute(
                select(WORK_ITEMS).where(WORK_ITEMS.c.work_item_id == identity)
            ).one()
        assert item.status == "succeeded"
        assert item.business_outcome == "normal_ready"
        assert item.review_reason is None
    finally:
        runtime.close()
