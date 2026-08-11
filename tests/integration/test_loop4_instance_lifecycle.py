from __future__ import annotations

import hashlib
import os
import sqlite3
import sys
import time
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

import dahe.api.app as app_module
from dahe.adapters.fake.loop3 import get_loop3_fixture
from dahe.adapters.sqlite.recovery import PersistentRecoveryStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.api.app import create_app
from dahe.system.instance_lifecycle import ApplicationInstanceLifecycle

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(sys.platform != "win32", reason="Windows-only process identity"),
]

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_persistent_instance_heartbeat_and_clean_shutdown(tmp_path: Path) -> None:
    data_root = tmp_path / "profile"
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id="loop4-lifecycle",
    )
    store = PersistentRecoveryStore(runtime.engine, runtime.commit_gate)
    lifecycle = ApplicationInstanceLifecycle(
        store,
        instance_id="loop4-lifecycle",
        data_root=data_root,
        application_version="0.6.0",
        port=8877,
        heartbeat_interval=timedelta(milliseconds=10),
    )

    try:
        lifecycle.start()
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with runtime.engine.connect() as connection:
                record_version = connection.execute(
                    text(
                        "SELECT record_version FROM application_instances "
                        "WHERE instance_id = 'loop4-lifecycle'"
                    )
                ).scalar_one()
            if int(record_version) >= 2:
                break
            time.sleep(0.01)
        else:
            pytest.fail("periodic heartbeat was not persisted")

        lifecycle.close()
        lifecycle.close()

        with runtime.engine.connect() as connection:
            row = connection.execute(
                text(
                    """
                    SELECT data_root_identity, pid, process_started_at, status,
                           stopped_at, record_version
                    FROM application_instances
                    WHERE instance_id = 'loop4-lifecycle'
                    """
                )
            ).mappings().one()
        canonical = str(data_root.resolve()).casefold().encode("utf-8")
        assert row["data_root_identity"] == hashlib.sha256(canonical).hexdigest()
        assert row["pid"] == os.getpid()
        assert str(row["process_started_at"]).startswith("windows-filetime:")
        assert row["status"] == "stopped"
        assert row["stopped_at"] is not None
        assert int(row["record_version"]) >= 3
    finally:
        lifecycle.close()
        runtime.close()


def test_application_lifespan_registers_and_stops_the_guarded_instance(
    tmp_path: Path,
) -> None:
    instance_id = "loop4-app-lifespan"
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=instance_id,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )

    with TestClient(app):
        assert app.state.instance_lifecycle.is_running

    with sqlite3.connect(tmp_path / "database" / "dahe.sqlite3") as connection:
        row = connection.execute(
            "SELECT status, stopped_at FROM application_instances "
            "WHERE instance_id = ?",
            (instance_id,),
        ).fetchone()
    assert row is not None
    assert row[0] == "stopped"
    assert row[1] is not None


def test_application_shutdown_abandons_only_its_uncommitted_atomic_attempt(
    tmp_path: Path,
) -> None:
    instance_id = "loop4-app-shutdown"
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=instance_id,
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_test_fixtures=True,
    )

    with TestClient(app):
        repository = app.state.repository
        job, created = repository.create_scheduled_job(
            fixture=get_loop3_fixture("audit-batch-short-002"),
            scope_label="Loop 4 clean shutdown",
            idempotency_key="loop4-clean-shutdown",
            request_hash="loop4-clean-shutdown-request",
            expected_record_version=0,
        )
        assert created is True
        assert app.state.scheduler.tick() is True
        running = repository.list_stage_attempts()
        assert len(running) == 1
        assert running[0]["status"] == "running"
        attempt_id = str(running[0]["stage_attempt_id"])
        work_item_id = str(running[0]["work_item_id"])

    with sqlite3.connect(tmp_path / "database" / "dahe.sqlite3") as connection:
        attempt_status = connection.execute(
            "SELECT status FROM stage_attempts WHERE stage_attempt_id = ?",
            (attempt_id,),
        ).fetchone()
        item_status = connection.execute(
            "SELECT status FROM work_items WHERE work_item_id = ?",
            (work_item_id,),
        ).fetchone()
        succeeded_checkpoints = connection.execute(
            "SELECT count(*) FROM checkpoints "
            "WHERE owner_id = ? AND payload_json LIKE '%\"committed\":true%'",
            (work_item_id,),
        ).fetchone()
        job_status = connection.execute(
            "SELECT status FROM jobs WHERE job_id = ?",
            (job.job_id,),
        ).fetchone()
    assert attempt_status == ("abandoned",)
    assert item_status == ("queued",)
    assert succeeded_checkpoints == (0,)
    assert job_status is not None
    assert job_status[0] != "succeeded"


def test_application_shutdown_stops_owned_workers_before_requeueing_attempts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class ObservableSupervisor:
        def __init__(self, *, instance_id: str, runtime_dir: Path) -> None:
            assert instance_id == "loop4-shutdown-order"
            assert runtime_dir == tmp_path / "runtime" / "workers"

        def close(self) -> None:
            events.append("workers_stopped")

    monkeypatch.setattr(
        "dahe.api.app.OwnedProcessSupervisor",
        ObservableSupervisor,
    )
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id="loop4-shutdown-order",
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    repository = app.state.repository
    original_abandon = repository.abandon_instance_attempts

    def observe_abandon(*, instance_id: str) -> int:
        events.append("attempts_abandoned")
        return original_abandon(instance_id=instance_id)

    monkeypatch.setattr(repository, "abandon_instance_attempts", observe_abandon)

    with TestClient(app):
        pass

    assert events == ["workers_stopped", "attempts_abandoned"]


def test_application_shutdown_attempts_all_cleanup_after_early_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    original_scheduler_close = (
        app_module.CooperativeSchedulerRunner.close
    )
    original_outbox_close = app_module.RuntimeOutboxLogBridge.close

    def observe_scheduler_close(
        runner: app_module.CooperativeSchedulerRunner,
    ) -> None:
        events.append("scheduler")
        original_scheduler_close(runner)

    def observe_outbox_close(
        bridge: app_module.RuntimeOutboxLogBridge,
    ) -> None:
        events.append("outbox")
        original_outbox_close(bridge)

    class ObservableSupervisor:
        def __init__(self, *, instance_id: str, runtime_dir: Path) -> None:
            assert instance_id == "loop4-shutdown-best-effort"
            assert runtime_dir == tmp_path / "runtime" / "workers"

        def close(self) -> None:
            events.append("supervisor")

    monkeypatch.setattr(
        app_module.CooperativeSchedulerRunner,
        "close",
        observe_scheduler_close,
    )
    monkeypatch.setattr(
        app_module.RuntimeOutboxLogBridge,
        "close",
        observe_outbox_close,
    )
    monkeypatch.setattr(
        app_module,
        "OwnedProcessSupervisor",
        ObservableSupervisor,
    )

    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id="loop4-shutdown-best-effort",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_chengfeng_shadow=True,
        platform_build_sha256="a" * 64,
    )
    expiry_reconciler = app.state.platform_access_expiry_reconciler
    repository = app.state.repository
    lifecycle = app.state.instance_lifecycle
    browser_runtime = app.state.browser_runtime

    original_expiry_close = expiry_reconciler.close
    original_stop_execution = repository.stop_ocr_execution
    original_abandon = repository.abandon_instance_attempts
    original_lifecycle_close = lifecycle.close
    original_repository_close = repository.close
    original_browser_close = browser_runtime.close

    def fail_after_expiry_close() -> None:
        events.append("expiry")
        original_expiry_close()
        raise RuntimeError("injected early shutdown failure")

    def observe_stop_execution() -> None:
        events.append("execution_backends")
        original_stop_execution()

    def observe_abandon(*, instance_id: str) -> int:
        events.append("attempts")
        return original_abandon(instance_id=instance_id)

    def observe_lifecycle_close() -> None:
        events.append("lifecycle")
        original_lifecycle_close()

    def observe_repository_close() -> None:
        events.append("repository")
        original_repository_close()

    def observe_browser_close() -> None:
        events.append("browser")
        original_browser_close()

    monkeypatch.setattr(expiry_reconciler, "close", fail_after_expiry_close)
    monkeypatch.setattr(
        repository,
        "stop_ocr_execution",
        observe_stop_execution,
    )
    monkeypatch.setattr(
        repository,
        "abandon_instance_attempts",
        observe_abandon,
    )
    monkeypatch.setattr(lifecycle, "close", observe_lifecycle_close)
    monkeypatch.setattr(repository, "close", observe_repository_close)
    monkeypatch.setattr(browser_runtime, "close", observe_browser_close)

    with pytest.raises(
        RuntimeError,
        match="injected early shutdown failure",
    ), TestClient(app):
        pass

    assert events == [
        "expiry",
        "scheduler",
        "outbox",
        "execution_backends",
        "supervisor",
        "attempts",
        "lifecycle",
        "repository",
        "browser",
    ]
