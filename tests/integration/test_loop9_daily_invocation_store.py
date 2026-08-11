from __future__ import annotations

import hashlib
from datetime import date, datetime
from pathlib import Path

import pytest
from sqlalchemy import text

from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationConflictError,
    SqliteDailyInvocationStore,
)
from dahe.adapters.sqlite.platform_access import (
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.application.daily.capture import (
    DailyCaptureCheckpoint,
    DailyCaptureRequest,
    DailyCaptureStage,
)
from dahe.domain.daily.calendar import SHANGHAI

PROJECT_ROOT = Path(__file__).parents[2]


def _runtime(tmp_path: Path) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="daily-invocation-test",
    )


def _request() -> DailyCaptureRequest:
    return DailyCaptureRequest(
        invocation_id="daily-invocation-1",
        business_date=date(2026, 7, 29),
        receive_place="榆林",
        now=datetime(2026, 7, 29, 20, 15, tzinfo=SHANGHAI),
        source_contract_sha256="a" * 64,
    )


def _insert_daily_job(
    runtime: SqliteRuntime,
    *,
    fixture_id: str = "daily-capture-v1",
) -> None:
    now = datetime(2026, 7, 29, 12, 15, tzinfo=SHANGHAI).isoformat()
    with runtime.engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO jobs (
                    job_id, task_type, scope_label, scope_fixture_id,
                    scope_fingerprint, run_mode, status, current_stage,
                    job_kind, ocr_execution_mode, created_sequence,
                    record_version, created_at, updated_at
                ) VALUES (
                    'dailyjob000000000000000000000001', 'daily',
                    'Refresh daily records', :fixture_id,
                    :fingerprint, 'shadow', 'queued', 'daily.list_page',
                    'business', 'fake', 1, 1, :now, :now
                )
                """
            ),
            {
                "fingerprint": "b" * 64,
                "fixture_id": fixture_id,
                "now": now,
            },
        )


@pytest.mark.integration
@pytest.mark.parametrize(
    "fixture_id",
    [
        "daily-operational-batch-v1:2026-07-20",
        "daily-operational-network-only-v1:2026-07-20",
    ],
)
def test_operational_daily_fixture_uses_batch_capture_strategy(
    tmp_path: Path,
    fixture_id: str,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        _insert_daily_job(runtime, fixture_id=fixture_id)
        store = SqliteDailyInvocationStore(runtime)
        assert (
            store.capture_strategy("dailyjob000000000000000000000001")
            == "batch_v1"
        )
        assert store.is_network_only_measurement(
            "dailyjob000000000000000000000001"
        ) is fixture_id.startswith("daily-operational-network-only-v1:")
    finally:
        runtime.close()


def _issue_access_window(runtime: SqliteRuntime) -> str:
    repository = SqlitePlatformAccessRepository(runtime)
    grant, replay = repository.issue(
        purpose=AccessPurpose.PRODUCTION_SHADOW,
        job_id="dailyjob000000000000000000000001",
        session_id="daily-browser-session",
        build_sha256=hashlib.sha256(b"daily-build").hexdigest(),
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="shadow",
        idempotency_key="daily-access-window",
        request_hash=hashlib.sha256(b"daily-access-window").hexdigest(),
        now=datetime(2026, 7, 29, 20, 0, tzinfo=SHANGHAI),
    )
    assert replay is False
    return grant.access_window_id


@pytest.mark.integration
def test_daily_invocation_checkpoint_is_versioned_and_replayable(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        _insert_daily_job(runtime)
        access_window_id = _issue_access_window(runtime)
        store = SqliteDailyInvocationStore(runtime)
        first = store.create(
            job_id="dailyjob000000000000000000000001",
            access_window_id=access_window_id,
            request=_request(),
        )
        replay = store.create(
            job_id="dailyjob000000000000000000000001",
            access_window_id=access_window_id,
            request=_request(),
        )
        assert first == replay
        assert first.record_version == 1
        assert first.checkpoint is None
        assert first.next_stage is DailyCaptureStage.LIST_PAGE

        checkpoint = DailyCaptureCheckpoint(
            invocation_id=_request().invocation_id,
            invocation_fingerprint=_request().fingerprint,
            revision=1,
        )
        updated = store.commit_checkpoint(
            job_id=first.job_id,
            expected_record_version=first.record_version,
            checkpoint=checkpoint,
            next_stage=DailyCaptureStage.LIST_PAGE,
            completed=False,
        )
        assert updated.record_version == 2
        assert updated.checkpoint == checkpoint
        assert updated.status == "ready"
        assert store.get_by_job(first.job_id) == updated

        with pytest.raises(DailyInvocationConflictError, match="version"):
            store.commit_checkpoint(
                job_id=first.job_id,
                expected_record_version=1,
                checkpoint=checkpoint,
                next_stage=DailyCaptureStage.LIST_PAGE,
                completed=False,
            )
    finally:
        runtime.close()


@pytest.mark.integration
def test_daily_invocation_rejects_changed_request_and_records_technical_failure(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        _insert_daily_job(runtime)
        access_window_id = _issue_access_window(runtime)
        store = SqliteDailyInvocationStore(runtime)
        first = store.create(
            job_id="dailyjob000000000000000000000001",
            access_window_id=access_window_id,
            request=_request(),
        )
        with pytest.raises(DailyInvocationConflictError, match="content"):
            store.create(
                job_id=first.job_id,
                access_window_id=access_window_id,
                request=DailyCaptureRequest(
                    **{
                        **_request().constructor_payload(),
                        "receive_place": "Changed",
                    }
                ),
            )

        failed = store.fail(
            job_id=first.job_id,
            expected_record_version=first.record_version,
            diagnostic_code="CF-DAILY-TECHNICAL-FAILURE",
        )
        assert failed.status == "failed"
        assert failed.diagnostic_code == "CF-DAILY-TECHNICAL-FAILURE"
        assert failed.checkpoint is None

        with runtime.engine.connect() as connection:
            columns = {
                str(row[1]).lower()
                for row in connection.exec_driver_sql(
                    "PRAGMA table_info(daily_capture_invocations)"
                )
            }
        assert columns.isdisjoint(
            {
                "operator",
                "operator_id",
                "reviewer",
                "reviewer_id",
                "actor",
                "actor_id",
                "windows_sid",
            }
        )
    finally:
        runtime.close()


@pytest.mark.integration
def test_daily_capture_start_is_durable_and_content_bound(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        _insert_daily_job(runtime)
        access_window_id = _issue_access_window(runtime)
        store = SqliteDailyInvocationStore(runtime)
        first, replayed = store.reserve_start(
            idempotency_key="daily-start-key",
            request_hash="c" * 64,
            job_id="dailyjob000000000000000000000001",
            access_window_id=access_window_id,
        )
        replay, replayed_again = store.reserve_start(
            idempotency_key="daily-start-key",
            request_hash="c" * 64,
            job_id="dailyjob000000000000000000000001",
            access_window_id=access_window_id,
        )
        assert replayed is False
        assert replayed_again is True
        assert replay == first
        assert first.status == "reserved"

        with pytest.raises(
            DailyInvocationConflictError,
            match="different daily capture",
        ):
            store.reserve_start(
                idempotency_key="daily-start-key",
                request_hash="d" * 64,
                job_id="dailyjob000000000000000000000001",
                access_window_id=access_window_id,
            )
        with pytest.raises(
            DailyInvocationConflictError,
            match="already has a start request",
        ):
            store.reserve_start(
                idempotency_key="another-daily-start-key",
                request_hash="e" * 64,
                job_id="dailyjob000000000000000000000001",
                access_window_id=access_window_id,
            )

        invocation = store.create(
            job_id=first.job_id,
            access_window_id=first.access_window_id,
            request=_request(),
        )
        completed = store.complete_start(
            idempotency_key=first.idempotency_key,
            expected_record_version=first.record_version,
            invocation_id=invocation.invocation_id,
        )
        assert completed.status == "completed"
        assert completed.invocation_id == invocation.invocation_id
        assert completed.record_version == 2
        assert (
            store.complete_start(
                idempotency_key=completed.idempotency_key,
                expected_record_version=completed.record_version,
                invocation_id=invocation.invocation_id,
            )
            == completed
        )
    finally:
        runtime.close()


@pytest.mark.integration
def test_daily_invocation_rejects_missing_or_mismatched_access_windows(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        _insert_daily_job(runtime)
        store = SqliteDailyInvocationStore(runtime)

        with pytest.raises(
            DailyInvocationConflictError,
            match="access window",
        ):
            store.reserve_start(
                idempotency_key="missing-window-start",
                request_hash="c" * 64,
                job_id="dailyjob000000000000000000000001",
                access_window_id="missing-window",
            )
        with pytest.raises(
            DailyInvocationConflictError,
            match="access window",
        ):
            store.create(
                job_id="dailyjob000000000000000000000001",
                access_window_id="missing-window",
                request=_request(),
            )
    finally:
        runtime.close()
