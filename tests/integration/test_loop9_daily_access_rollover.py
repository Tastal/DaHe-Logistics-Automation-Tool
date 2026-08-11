from __future__ import annotations

import hashlib
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import text

from dahe.adapters.sqlite.browser_control import (
    BrowserControlStore,
)
from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationAuthority,
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
from dahe.ports.jobs import IdempotencyConflictError

PROJECT_ROOT = Path(__file__).parents[2]
NOW = datetime(2026, 7, 30, 8, 0, tzinfo=UTC)
ROLLOVER_AT = NOW + timedelta(minutes=61)
JOB_ID = "dailyrollover000000000000000001"
SESSION_ID = "daily-rollover-session"
BUILD_SHA = hashlib.sha256(b"daily-rollover-build").hexdigest()


def _runtime(data_root: Path, *, instance_id: str) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id=instance_id,
    )


def _authority() -> DailyInvocationAuthority:
    return DailyInvocationAuthority(
        source_build_sha256=BUILD_SHA,
        daily_contract_sha256="a" * 64,
        daily_contract_file_sha256="b" * 64,
        daily_contract_selection_sha256="c" * 64,
        settlement_contract_sha256="d" * 64,
        settlement_contract_selection_sha256="e" * 64,
    )


def _request() -> DailyCaptureRequest:
    return DailyCaptureRequest(
        invocation_id=JOB_ID,
        business_date=date(2026, 7, 29),
        receive_place="Test receive place",
        now=datetime(2026, 7, 29, 20, 0, tzinfo=SHANGHAI),
        source_contract_sha256="a" * 64,
    )


def _insert_paused_daily_job(runtime: SqliteRuntime) -> None:
    timestamp = NOW.isoformat()
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
                    :job_id, 'daily', 'Daily capture',
                    'daily-rollover-v1', :fingerprint, 'shadow',
                    'paused', 'daily.list_page', 'business', 'fake',
                    1, 2, :timestamp, :timestamp
                )
                """
            ),
            {
                "fingerprint": hashlib.sha256(
                    b"daily-rollover-scope"
                ).hexdigest(),
                "job_id": JOB_ID,
                "timestamp": timestamp,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO work_items (
                    work_item_id, job_id, record_version,
                    waybill_number, vehicle_number, status,
                    current_stage, item_index, attempt_count,
                    download_complete, loading_ocr_complete,
                    unloading_ocr_complete, ready_sequence,
                    waiting_reason_kind, waiting_reason,
                    diagnostic_code
                ) VALUES (
                    'dailyrolloveritem000000000001', :job_id, 2,
                    'daily:2026-07-29', '', 'waiting_external',
                    'daily.list_page', 0, 1, 0, 0, 0, 1,
                    'external', 'access_window_expired',
                    'CF-DAILY-ACCESS-WINDOW-INVALID'
                )
                """
            ),
            {"job_id": JOB_ID},
        )


def _issue(
    runtime: SqliteRuntime,
    *,
    key: str,
    now: datetime,
) -> str:
    grant, replayed = SqlitePlatformAccessRepository(runtime).issue(
        purpose=AccessPurpose.PRODUCTION_SHADOW,
        job_id=JOB_ID,
        session_id=SESSION_ID,
        build_sha256=BUILD_SHA,
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="shadow",
        idempotency_key=key,
        request_hash=hashlib.sha256(key.encode()).hexdigest(),
        now=now,
    )
    assert replayed is False
    return grant.access_window_id


@pytest.mark.integration
def test_daily_rollover_is_cas_bound_idempotent_and_restartable(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    first = _runtime(data_root, instance_id="daily-rollover-before")
    try:
        _insert_paused_daily_job(first)
        browser_store = BrowserControlStore(
            first.engine,
            first.commit_gate,
        )
        browser = browser_store.initialize(
            session_id=SESSION_ID,
            now=NOW,
        )
        browser = browser_store.mark_ready(
            session_id=SESSION_ID,
            expected_record_version=browser.record_version,
            now=NOW,
        )
        old_access = _issue(
            first,
            key="daily-rollover-old",
            now=NOW,
        )
        invocation_store = SqliteDailyInvocationStore(first)
        invocation = invocation_store.create(
            job_id=JOB_ID,
            access_window_id=old_access,
            request=_request(),
            authority=_authority(),
            now=NOW,
        )
        checkpoint = DailyCaptureCheckpoint(
            invocation_id=JOB_ID,
            invocation_fingerprint=_request().fingerprint,
            revision=1,
        )
        invocation = invocation_store.commit_checkpoint(
            job_id=JOB_ID,
            expected_record_version=invocation.record_version,
            checkpoint=checkpoint,
            next_stage=DailyCaptureStage.LIST_PAGE,
            completed=False,
            now=NOW,
        )
        checkpoint_payload = invocation.checkpoint
        assert checkpoint_payload is not None
    finally:
        first.close()

    restarted = _runtime(
        data_root,
        instance_id="daily-rollover-after",
    )
    try:
        access_repository = SqlitePlatformAccessRepository(restarted)
        _old_grant, old_version = (
            access_repository.get_with_version(old_access)
        )
        access_repository.retire(
            access_window_id=old_access,
            expected_record_version=old_version,
            now=ROLLOVER_AT,
        )
        replacement = _issue(
            restarted,
            key="daily-rollover-new",
            now=ROLLOVER_AT,
        )
        store = SqliteDailyInvocationStore(restarted)
        result = store.rebind_access_window(
            job_id=JOB_ID,
            new_access_window_id=replacement,
            expected_invocation_record_version=(
                invocation.record_version
            ),
            expected_browser_record_version=browser.record_version,
            session_id=SESSION_ID,
            authority=_authority(),
            idempotency_key="daily-rollover-rebind",
            request_hash=hashlib.sha256(
                b"daily-rollover-rebind"
            ).hexdigest(),
            now=ROLLOVER_AT,
        )

        assert result.idempotent_replay is False
        assert result.invocation.access_window_id == replacement
        assert result.invocation.checkpoint == checkpoint_payload
        assert result.invocation.record_version == (
            invocation.record_version + 1
        )
        assert store.access_window_lineage(JOB_ID).access_window_ids == (
            old_access,
            replacement,
        )

        replay = store.rebind_access_window(
            job_id=JOB_ID,
            new_access_window_id=replacement,
            expected_invocation_record_version=(
                invocation.record_version
            ),
            expected_browser_record_version=browser.record_version,
            session_id=SESSION_ID,
            authority=_authority(),
            idempotency_key="daily-rollover-rebind",
            request_hash=hashlib.sha256(
                b"daily-rollover-rebind"
            ).hexdigest(),
            now=ROLLOVER_AT,
        )
        assert replay.idempotent_replay is True
        assert replay.invocation == result.invocation

        with pytest.raises(IdempotencyConflictError):
            store.rebind_access_window(
                job_id=JOB_ID,
                new_access_window_id=replacement,
                expected_invocation_record_version=(
                    invocation.record_version
                ),
                expected_browser_record_version=browser.record_version,
                session_id=SESSION_ID,
                authority=_authority(),
                idempotency_key="daily-rollover-rebind",
                request_hash="f" * 64,
                now=ROLLOVER_AT,
            )
        changed_authority = DailyInvocationAuthority(
            **{
                **_authority().to_payload(),
                "daily_contract_selection_sha256": "9" * 64,
            }
        )
        with pytest.raises(
            DailyInvocationConflictError,
            match="authority",
        ):
            store.rebind_access_window(
                job_id=JOB_ID,
                new_access_window_id=replacement,
                expected_invocation_record_version=(
                    result.invocation.record_version
                ),
                expected_browser_record_version=(
                    browser.record_version + 1
                ),
                session_id=SESSION_ID,
                authority=changed_authority,
                idempotency_key="daily-rollover-authority-change",
                request_hash="8" * 64,
                now=ROLLOVER_AT,
            )
    finally:
        restarted.close()
