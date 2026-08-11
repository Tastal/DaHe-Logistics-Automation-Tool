from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from threading import Event, Lock, Thread

import pytest
from sqlalchemy import text

from dahe.adapters.chengfeng.browser_runtime import (
    BrowserReadPayload,
    BrowserRuntimeError,
    BrowserRuntimeLifecycle,
    BrowserRuntimeLifecycleGuard,
)
from dahe.adapters.files.content_addressed import (
    ContentAddressedEvidenceStore,
)
from dahe.adapters.files.platform_request_audit import (
    PlatformReadAuditEvidenceStore,
)
from dahe.adapters.sqlite.browser_control import BrowserControlStore
from dahe.adapters.sqlite.daily_invocation_store import (
    DailyInvocationConflictError,
    SqliteDailyInvocationStore,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
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
from dahe.application.daily.live_execution import DailyLiveStageExecutor
from dahe.application.daily.operational_capture import (
    OperationalDailyStepResult,
)
from dahe.domain.daily.calendar import SHANGHAI, business_date_for
from dahe.domain.daily.models import DailyCandidateSnapshot
from dahe.jobs.daily_execution import DailyStageWork
from dahe.ports.chengfeng import ChengfengStage, LoginRequiredError
from tests.unit.platform.test_loop9_daily_manifest import daily_manifest

PROJECT_ROOT = Path(__file__).parents[2]
BUILD_SHA256 = hashlib.sha256(b"daily-live-execution").hexdigest()
DAILY_SELECTION_SHA256 = hashlib.sha256(
    b"daily-contract-selection"
).hexdigest()
SETTLEMENT_CONTRACT_SHA256 = hashlib.sha256(
    b"settlement-contract"
).hexdigest()
SETTLEMENT_SELECTION_SHA256 = hashlib.sha256(
    b"settlement-contract-selection"
).hexdigest()
SESSION_ID = "daily-live-session"
INSTANCE_ID = "daily-live-instance"
NOW = datetime.now(UTC)
JOB_ID = "dailyjob000000000000000000000001"
OTHER_JOB_ID = "dailyjob000000000000000000000002"


class _Browser:
    def __init__(self, *, error_code: str | None = None) -> None:
        self._running = True
        self.error_code = error_code
        self.close_count = 0
        self.park_count = 0
        self.read_count = 0
        self.start_count = 0
        self.prepare_daily_count = 0
        self.prepare_operational_daily_count = 0
        self.prepare_operational_count = 0
        self.prepare_daily_from_automated_count = 0

    @property
    def running(self) -> bool:
        return self._running

    def read_daily(self, request: object) -> BrowserReadPayload:
        del request
        self.read_count += 1
        if self.error_code is not None:
            raise BrowserRuntimeError(
                "daily read failed",
                code=self.error_code,
            )
        content = json.dumps(
            {"code": 200, "data": {"total": 0, "list": []}},
            separators=(",", ":"),
        ).encode()
        return BrowserReadPayload(
            content=content,
            sha256=hashlib.sha256(content).hexdigest(),
            media_type="application/json",
            byte_size=len(content),
            status_code=200,
        )

    def close(self) -> None:
        self.close_count += 1
        self._running = False

    def park_operational_session(self) -> None:
        self.park_count += 1

    def start_human_login(self) -> str:
        self.start_count += 1
        self._running = True
        return "msedge"

    def prepare_daily(self) -> None:
        self.prepare_daily_count += 1

    def prepare_operational_daily(self) -> None:
        self.prepare_operational_daily_count += 1
        if self.error_code is not None:
            raise BrowserRuntimeError(
                "operational daily preparation failed",
                code=self.error_code,
            )

    def prepare_operational_compat(self) -> None:
        self.prepare_operational_count += 1
        if self.error_code is not None:
            raise BrowserRuntimeError(
                "operational preparation failed",
                code=self.error_code,
            )

    def prepare_daily_from_automated(self) -> None:
        self.prepare_daily_from_automated_count += 1


class _FastDailyCoordinator:
    def __init__(
        self,
        *,
        login_required: bool = False,
        has_more: bool = False,
    ) -> None:
        self.calls = 0
        self.login_required = login_required
        self.has_more = has_more

    def advance(
        self,
        *,
        invocation: object,
        authority: object,
        list_port: object,
    ) -> object:
        del authority
        self.calls += 1
        if self.login_required:
            raise LoginRequiredError(stage=ChengfengStage.DETAIL_QUERY)
        request = invocation.request
        page = list_port.list_waybills(
            query_window=request.query_window,
            receive_place=request.receive_place,
            page_number=1,
            page_size=request.page_size,
        )
        assert page.total == 0
        snapshot = DailyCandidateSnapshot(
            snapshot_id=request.invocation_id,
            target_business_date=request.business_date,
            receive_place=request.receive_place,
            query_window=request.query_window,
            source_contract_sha256=request.source_contract_sha256,
            candidates=(),
            captured_at=max(NOW, request.query_window.end),
        )
        return OperationalDailyStepResult(
            has_more=self.has_more,
            checkpoint=DailyCaptureCheckpoint(
                invocation_id=request.invocation_id,
                invocation_fingerprint=request.fingerprint,
                revision=1,
                snapshot=snapshot,
            ),
            platform_read_performed=True,
            request_audit_counts=(
                None
                if self.has_more
                else {"list_daily_waybills": 1}
            ),
        )


class _ObservedLifecycle:
    """Expose whether a second lifecycle operation had to wait."""

    def __init__(self) -> None:
        self._lock = Lock()
        self.waiter_observed = Event()

    @contextmanager
    def hold(self) -> Iterator[None]:
        if not self._lock.acquire(blocking=False):
            self.waiter_observed.set()
            self._lock.acquire()
        try:
            yield
        finally:
            self._lock.release()


class _UnusedConnector:
    def get_waybill_detail(self, **kwargs: object) -> object:
        del kwargs
        raise AssertionError("empty daily capture cannot read a detail")

    def download_ticket_image(self, **kwargs: object) -> object:
        del kwargs
        raise AssertionError("empty daily capture cannot read an image")


def _insert_daily_job(
    runtime: SqliteRuntime,
    *,
    job_id: str,
    status: str = "queued",
    run_mode: str = "shadow",
    fixture_id: str = "daily-capture-v1",
) -> None:
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
                    :job_id, 'daily', 'Daily capture', :fixture_id,
                    :fingerprint, :run_mode, :status, 'daily.list_page',
                    'business', 'fake', 1, 1, :timestamp, :timestamp
                )
                """
            ),
            {
                "fingerprint": hashlib.sha256(job_id.encode()).hexdigest(),
                "fixture_id": fixture_id,
                "job_id": job_id,
                "run_mode": run_mode,
                "status": status,
                "timestamp": timestamp,
            },
        )


def _issue_window(
    repository: SqlitePlatformAccessRepository,
    *,
    job_id: str,
    key: str,
    run_mode: str = "shadow",
) -> str:
    grant, _ = repository.issue(
        purpose=AccessPurpose.PRODUCTION_SHADOW,
        job_id=job_id,
        session_id=SESSION_ID,
        build_sha256=BUILD_SHA256,
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode=run_mode,
        idempotency_key=key,
        request_hash=hashlib.sha256(key.encode()).hexdigest(),
        now=NOW,
    )
    return grant.access_window_id


def _request(job_id: str) -> DailyCaptureRequest:
    manifest = daily_manifest()
    business_now = NOW.astimezone(SHANGHAI)
    return DailyCaptureRequest(
        invocation_id=job_id,
        business_date=business_date_for(business_now),
        receive_place="榆林",
        now=business_now,
        source_contract_sha256=manifest.canonical_sha256,
        page_size=100,
    )


def _work(
    *,
    job_id: str = JOB_ID,
    stage: str = "daily.list_page",
    attempt: str = "daily-attempt-1",
) -> DailyStageWork:
    return DailyStageWork(
        stage_attempt_id=attempt,
        job_id=job_id,
        work_item_id=f"work-{job_id[-6:]}",
        stage=stage,
    )


def _setup(
    tmp_path: Path,
    *,
    browser: _Browser,
    window_job_id: str = JOB_ID,
    create_invocation: bool = True,
    browser_lifecycle: BrowserRuntimeLifecycle | None = None,
    settlement_validation_passed: bool = True,
    operational: bool = False,
    network_only_measurement: bool = False,
    operational_coordinator: object | None = None,
    operational_materializer: object | None = None,
    browser_control_ready: bool = True,
) -> tuple[
    SqliteRuntime,
    DailyLiveStageExecutor,
    SqliteDailyInvocationStore,
    SqlitePlatformAccessRepository,
    BrowserControlStore,
    str,
]:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id=INSTANCE_ID,
    )
    _insert_daily_job(
        runtime,
        job_id=JOB_ID,
        run_mode="operational" if operational else "shadow",
        fixture_id=(
            (
                "daily-operational-network-only-v1:"
                if network_only_measurement
                else "daily-operational-batch-v1:"
            )
            + _request(JOB_ID).business_date.isoformat()
            if operational
            else "daily-capture-v1"
        ),
    )
    if window_job_id != JOB_ID:
        _insert_daily_job(runtime, job_id=window_job_id)
    access = SqlitePlatformAccessRepository(runtime)
    access_window_id = _issue_window(
        access,
        job_id=window_job_id,
        key=f"window-{window_job_id}",
        run_mode="operational" if operational else "shadow",
    )
    control = BrowserControlStore(runtime.engine, runtime.commit_gate)
    initial = control.initialize(session_id=SESSION_ID, now=NOW)
    if browser_control_ready:
        control.mark_ready(
            session_id=SESSION_ID,
            expected_record_version=initial.record_version,
            now=NOW,
        )
    invocations = SqliteDailyInvocationStore(runtime)
    if create_invocation:
        invocations.create(
            job_id=JOB_ID,
            access_window_id=access_window_id,
            request=_request(JOB_ID),
            now=NOW,
        )
    executor = DailyLiveStageExecutor(
        invocation_store=invocations,
        access_repository=access,
        browser_control=control,
        browser_runtime=browser,  # type: ignore[arg-type]
        browser_lifecycle=(
            browser_lifecycle or BrowserRuntimeLifecycleGuard()
        ),
        manifest=daily_manifest(),
        connector=_UnusedConnector(),  # type: ignore[arg-type]
        evidence_store=ContentAddressedEvidenceStore(
            tmp_path / "evidence"
        ),
        request_audit_store=PlatformReadAuditEvidenceStore(
            tmp_path / "data"
        ),
        daily_store=SqliteDailyStore(runtime),
        instance_id=INSTANCE_ID,
        session_id=SESSION_ID,
        build_sha256=BUILD_SHA256,
        settlement_contract_sha256=SETTLEMENT_CONTRACT_SHA256,
        settlement_contract_selection_sha256=(
            SETTLEMENT_SELECTION_SHA256
        ),
        daily_contract_selection_sha256=DAILY_SELECTION_SHA256,
        settlement_validation_gate=(
            lambda: settlement_validation_passed
        ),
        operational_coordinator=operational_coordinator,  # type: ignore[arg-type]
        operational_materializer=operational_materializer,  # type: ignore[arg-type]
        clock=lambda: NOW,
    )
    return (
        runtime,
        executor,
        invocations,
        access,
        control,
        access_window_id,
    )


def test_operational_daily_reconciles_running_browser_with_stopped_control(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, invocations, _access, control, _window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=_FastDailyCoordinator(),
        browser_control_ready=False,
    )
    try:
        assert browser.running is True
        assert control.get(SESSION_ID).browser_lifecycle == "stopped"

        result = executor(_work())

        assert result.outcome == "succeeded"
        assert invocations.get_by_job(JOB_ID).status == "succeeded"
        reconciled = control.get(SESSION_ID)
        assert reconciled.browser_lifecycle == "ready"
        assert reconciled.browser_control_mode == "idle"
    finally:
        runtime.close()


def test_batch_v1_daily_executor_defers_final_ocr_until_terminal_reconciliation(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    coordinator = _FastDailyCoordinator()
    materialized: list[str] = []
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=coordinator,
        operational_materializer=materialized.append,
    )
    try:
        result = executor(_work())

        assert result.outcome == "succeeded"
        assert result.next_stage is None
        assert result.checkpoint_revision == 1
        assert coordinator.calls == 1
        assert materialized == []
        assert browser.prepare_daily_count == 0
        assert browser.prepare_operational_daily_count == 1
        assert browser.prepare_operational_count == 0
        assert browser.prepare_daily_from_automated_count == 0
        assert browser.read_count == 1
        assert invocations.get_by_job(JOB_ID).status == "succeeded"
        audit = PlatformReadAuditEvidenceStore(
            tmp_path / "data"
        ).load_sealed_for_job(
            job_id=JOB_ID,
        )
        assert audit.purpose == "operational_daily"
        assert audit.request_counts.succeeded == 1
        assert control.get(SESSION_ID).browser_control_mode == "idle"
        assert access.get(window_id).consumed_at is None

        executor.close_terminal_job(JOB_ID)

        assert materialized == [JOB_ID]
        assert access.get(window_id).consumed_at is not None
        assert browser.park_count == 1
        assert browser.close_count == 0
        assert browser.running is True
    finally:
        runtime.close()


def test_network_only_daily_measurement_never_materializes_ocr(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    coordinator = _FastDailyCoordinator()
    materialized: list[str] = []
    runtime, executor, _invocations, access, _control, window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        network_only_measurement=True,
        operational_coordinator=coordinator,
        operational_materializer=materialized.append,
    )
    try:
        result = executor(_work())
        assert result.outcome == "succeeded"

        executor.close_terminal_job(JOB_ID)

        assert materialized == []
        assert access.get(window_id).consumed_at is not None
    finally:
        runtime.close()


def test_failed_batch_v1_daily_job_parks_and_preserves_visible_runtime(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=_FastDailyCoordinator(),
    )
    try:
        current = invocations.get_by_job(JOB_ID)
        invocations.fail(
            job_id=JOB_ID,
            expected_record_version=current.record_version,
            diagnostic_code="CF-DAILY-TECHNICAL-FAILURE",
            now=NOW,
        )

        executor.close_terminal_job(JOB_ID)

        assert access.get(window_id).consumed_at is not None
        idle = control.get(SESSION_ID)
        assert idle.browser_lifecycle == "ready"
        assert idle.browser_control_mode == "idle"
        assert browser.park_count == 1
        assert browser.close_count == 0
        assert browser.running is True
    finally:
        runtime.close()


def test_cancelled_batch_v1_daily_job_parks_and_preserves_visible_runtime(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, _invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=_FastDailyCoordinator(),
    )
    try:
        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = 'cancelled',
                        current_stage = NULL,
                        record_version = record_version + 1,
                        updated_at = :now
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": JOB_ID, "now": NOW.isoformat()},
            )

        executor.close_terminal_job(JOB_ID)

        assert access.get(window_id).consumed_at is not None
        idle = control.get(SESSION_ID)
        assert idle.browser_lifecycle == "ready"
        assert idle.browser_control_mode == "idle"
        assert browser.park_count == 1
        assert browser.close_count == 0
        assert browser.running is True
    finally:
        runtime.close()


def test_batch_v1_daily_executor_does_not_materialize_ocr_between_network_batches(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    coordinator = _FastDailyCoordinator(has_more=True)
    calls: list[str] = []

    runtime, executor, invocations, _access, _control, _window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=coordinator,
        operational_materializer=calls.append,
    )
    try:
        result = executor(_work())

        assert result.outcome == "succeeded"
        assert result.next_stage == DailyCaptureStage.LIST_PAGE.value
        assert calls == []
        assert invocations.get_by_job(JOB_ID).status == "ready"

        coordinator.has_more = False
        terminal = executor(_work(attempt="daily-attempt-2"))

        assert terminal.outcome in {"succeeded", "failed"}
        assert browser.prepare_operational_daily_count == 2
    finally:
        runtime.close()


def test_batch_v1_terminal_materialization_failure_is_retried_without_platform_read(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    coordinator = _FastDailyCoordinator()
    calls: list[str] = []

    def transient_materializer(job_id: str) -> None:
        calls.append(job_id)
        if len(calls) == 1:
            raise RuntimeError("transient local materialization failure")

    runtime, executor, invocations, access, _control, window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=coordinator,
        operational_materializer=transient_materializer,
    )
    try:
        result = executor(_work())
        assert result.outcome == "succeeded"
        assert invocations.get_by_job(JOB_ID).status == "succeeded"

        with pytest.raises(RuntimeError, match="transient local materialization failure"):
            executor.close_terminal_job(JOB_ID)

        assert calls == [JOB_ID]
        assert access.get(window_id).consumed_at is None

        executor.close_terminal_job(JOB_ID)

        assert calls == [JOB_ID, JOB_ID]
        assert access.get(window_id).consumed_at is not None
        assert browser.close_count == 0
        assert browser.park_count == 1
    finally:
        runtime.close()


def test_batch_v1_reports_only_safe_unexpected_failure_metadata(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    coordinator = _FastDailyCoordinator()
    observed: list[tuple[str, str, str]] = []
    runtime, executor, _invocations, _access, _control, _window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=coordinator,
    )
    executor._unexpected_error_observer = (
        lambda job_id, step, error_type: observed.append(
            (job_id, step, error_type)
        )
    )
    original_release = executor._browser_control.release_automated
    release_calls = 0

    def transient_release(**kwargs: object) -> object:
        nonlocal release_calls
        release_calls += 1
        if release_calls == 1:
            raise OSError("sensitive detail")
        return original_release(**kwargs)  # type: ignore[arg-type]

    executor._browser_control.release_automated = (  # type: ignore[method-assign]
        transient_release
    )
    try:
        result = executor(_work())

        assert result.outcome == "failed"
        assert observed == [
            (JOB_ID, "release_browser_control", "OSError")
        ]
        assert "sensitive detail" not in repr(observed)
    finally:
        runtime.close()


def test_batch_v1_daily_login_interruption_waits_at_last_checkpoint(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    coordinator = _FastDailyCoordinator(login_required=True)
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=coordinator,
    )
    try:
        created = invocations.get_by_job(JOB_ID)
        checkpoint = DailyCaptureCheckpoint(
            invocation_id=created.invocation_id,
            invocation_fingerprint=created.request.fingerprint,
            revision=1,
        )
        before = invocations.commit_checkpoint(
            job_id=JOB_ID,
            expected_record_version=created.record_version,
            checkpoint=checkpoint,
            next_stage=DailyCaptureStage.LIST_PAGE,
            completed=False,
            now=NOW,
        )

        result = executor(_work(attempt="daily-login-interrupted"))

        assert result.outcome == "waiting_external"
        assert result.next_stage == "daily.list_page"
        assert result.checkpoint_revision == 1
        assert result.diagnostic_code == "CF-LOGIN-REQUIRED"
        assert browser.prepare_daily_count == 0
        assert browser.prepare_operational_daily_count == 1
        assert invocations.get_by_job(JOB_ID) == before
        assert control.get(SESSION_ID).browser_control_mode == "idle"
        assert access.get(window_id).consumed_at is None
    finally:
        runtime.close()


def test_batch_v1_unreviewed_browser_failure_is_not_retried_forever(
    tmp_path: Path,
) -> None:
    browser = _Browser(
        error_code="browser_operational_batch_prepare_required"
    )
    coordinator = _FastDailyCoordinator()
    runtime, executor, invocations, _access, control, _window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=coordinator,
    )
    try:
        result = executor(_work(attempt="daily-browser-contract-failed"))

        assert result.outcome == "failed"
        assert result.next_stage is None
        assert result.diagnostic_code == "CF-DAILY-BROWSER-RUNTIME-FAILED"
        assert invocations.get_by_job(JOB_ID).status == "failed"
        assert coordinator.calls == 0
        assert control.get(SESSION_ID).browser_control_mode == "idle"
    finally:
        runtime.close()


def test_batch_v1_reports_only_the_safe_browser_error_code(
    tmp_path: Path,
) -> None:
    browser = _Browser(error_code="browser_daily_list_empty")
    coordinator = _FastDailyCoordinator()
    observed: list[tuple[str, str, str]] = []
    runtime, executor, _invocations, _access, _control, _window_id = _setup(
        tmp_path,
        browser=browser,
        operational=True,
        operational_coordinator=coordinator,
    )
    executor._unexpected_error_observer = (
        lambda job_id, step, error_type: observed.append(
            (job_id, step, error_type)
        )
    )
    try:
        result = executor(_work(attempt="daily-browser-code-observed"))

        assert result.outcome == "failed"
        assert observed == [
            (
                JOB_ID,
                "load_invocation",
                "BrowserRuntimeError:browser_daily_list_empty",
            )
        ]
        assert "operational daily preparation failed" not in repr(observed)
    finally:
        runtime.close()


def test_daily_stage_rejects_missing_settlement_validation_before_browser_read(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        settlement_validation_passed=False,
    )
    try:
        result = executor(_work())

        assert result.outcome == "failed"
        assert (
            result.diagnostic_code
            == "CF-DAILY-SETTLEMENT-VALIDATION-REQUIRED"
        )
        invocation = invocations.get_by_job(JOB_ID)
        assert invocation.status == "failed"
        assert invocation.diagnostic_code == result.diagnostic_code
        assert browser.read_count == 0
        assert control.get(SESSION_ID).browser_control_mode == "idle"
        assert access.get(window_id).consumed_at is None
    finally:
        runtime.close()


def test_daily_invocation_rejects_access_window_bound_to_another_job(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, _executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        window_job_id=OTHER_JOB_ID,
        create_invocation=False,
    )
    try:
        with pytest.raises(
            DailyInvocationConflictError,
            match="does not match the job",
        ):
            invocations.create(
                job_id=JOB_ID,
                access_window_id=window_id,
                request=_request(JOB_ID),
                now=NOW,
            )

        assert control.get(SESSION_ID).browser_control_mode == "idle"
        assert access.get(window_id).consumed_at is None
        assert control.get(SESSION_ID).browser_lifecycle == "ready"
        assert browser.read_count == 0
        assert browser.running is True
    finally:
        runtime.close()


def test_transient_daily_failure_preserves_checkpoint_and_releases_lease(
    tmp_path: Path,
) -> None:
    browser = _Browser(error_code="browser_read_network_failed")
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
    )
    try:
        created = invocations.get_by_job(JOB_ID)
        checkpoint = DailyCaptureCheckpoint(
            invocation_id=created.invocation_id,
            invocation_fingerprint=created.request.fingerprint,
            revision=1,
        )
        before = invocations.commit_checkpoint(
            job_id=JOB_ID,
            expected_record_version=created.record_version,
            checkpoint=checkpoint,
            next_stage=DailyCaptureStage.LIST_PAGE,
            completed=False,
            now=NOW,
        )

        result = executor(_work())

        assert result.outcome == "retry"
        assert result.checkpoint_revision == 1
        assert result.diagnostic_code == "CF-NETWORK-TRANSIENT"
        assert invocations.get_by_job(JOB_ID) == before
        browser_state = control.get(SESSION_ID)
        assert browser_state.browser_lifecycle == "ready"
        assert browser_state.browser_control_mode == "idle"
        assert access.get(window_id).consumed_at is None
        assert browser.running is True
    finally:
        runtime.close()


def test_expired_daily_window_waits_external_without_failing_invocation(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
    )
    try:
        created = invocations.get_by_job(JOB_ID)
        checkpoint = DailyCaptureCheckpoint(
            invocation_id=created.invocation_id,
            invocation_fingerprint=created.request.fingerprint,
            revision=1,
        )
        before = invocations.commit_checkpoint(
            job_id=JOB_ID,
            expected_record_version=created.record_version,
            checkpoint=checkpoint,
            next_stage=DailyCaptureStage.LIST_PAGE,
            completed=False,
            now=NOW,
        )
        _grant, access_version = access.get_with_version(window_id)
        access.retire(
            access_window_id=window_id,
            expected_record_version=access_version,
            now=NOW,
        )

        result = executor(_work())

        assert result.outcome == "waiting_external"
        assert result.next_stage == "daily.list_page"
        assert result.checkpoint_revision == 1
        assert (
            result.diagnostic_code
            == "CF-DAILY-ACCESS-WINDOW-INVALID"
        )
        assert invocations.get_by_job(JOB_ID) == before
        assert control.get(SESSION_ID).browser_control_mode == "idle"
        assert browser.read_count == 0
    finally:
        runtime.close()


def test_nonretryable_daily_contract_failure_never_becomes_review(
    tmp_path: Path,
) -> None:
    browser = _Browser(
        error_code="browser_daily_response_contract_changed"
    )
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
    )
    try:
        result = executor(_work())

        assert result.outcome == "failed"
        assert result.next_stage is None
        assert result.diagnostic_code is not None
        assert result.diagnostic_code.startswith("CF-DAILY-CONTRACT-")
        failed = invocations.get_by_job(JOB_ID)
        assert failed.status == "failed"
        assert failed.diagnostic_code == result.diagnostic_code
        assert control.get(SESSION_ID).browser_control_mode == "idle"

        executor.close_terminal_job(JOB_ID)
        assert access.get(window_id).consumed_at == NOW
        assert browser.running is False
        assert browser.close_count == 1
        assert control.get(SESSION_ID).browser_lifecycle == "stopped"
    finally:
        runtime.close()


def test_terminal_cleanup_consumes_its_window_and_closes_idle_runtime(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
    )
    try:
        first = executor(_work())
        assert first.outcome == "succeeded"
        assert first.next_stage == "daily.list_page"
        assert control.get(SESSION_ID).browser_control_mode == "idle"

        second = executor(
            _work(
                stage="daily.list_page",
                attempt="daily-attempt-2",
            )
        )
        assert second.outcome == "succeeded"
        assert second.next_stage == "daily.save_snapshot"

        third = executor(
            _work(
                stage="daily.save_snapshot",
                attempt="daily-attempt-3",
            )
        )
        assert third.outcome == "succeeded"
        assert third.next_stage is None
        assert invocations.get_by_job(JOB_ID).status == "succeeded"
        assert access.get(window_id).consumed_at is None

        assert executor.reconcile_terminal_or_expired() == (JOB_ID,)
        executor.close_terminal_job(JOB_ID)

        assert access.get(window_id).consumed_at == NOW
        state = control.get(SESSION_ID)
        assert state.browser_lifecycle == "stopped"
        assert state.browser_control_mode == "idle"
        assert browser.running is False
        assert browser.close_count == 1
    finally:
        runtime.close()


def test_terminal_browser_stop_is_idempotent_per_access_window(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, _, access, control, first_window_id = _setup(
        tmp_path,
        browser=browser,
    )
    try:
        _, first_window_version = access.get_with_version(first_window_id)
        access.retire(
            access_window_id=first_window_id,
            expected_record_version=first_window_version,
            now=NOW,
        )
        second_window_id = _issue_window(
            access,
            job_id=JOB_ID,
            key="window-retry-same-daily-job",
        )
        ready = control.get(SESSION_ID)
        executor._stop_browser(
            access_window_id=first_window_id,
            job_id=JOB_ID,
            expected_record_version=ready.record_version,
        )
        stopped = control.get(SESSION_ID)
        control.mark_ready(
            session_id=SESSION_ID,
            expected_record_version=stopped.record_version,
            now=NOW,
        )
        ready_again = control.get(SESSION_ID)

        executor._stop_browser(
            access_window_id=second_window_id,
            job_id=JOB_ID,
            expected_record_version=ready_again.record_version,
        )

        assert control.get(SESSION_ID).browser_lifecycle == "stopped"
    finally:
        runtime.close()


def test_startup_reconciliation_fences_its_crashed_automated_lease(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
    )
    try:
        current = invocations.get_by_job(JOB_ID)
        invocations.fail(
            job_id=JOB_ID,
            expected_record_version=current.record_version,
            diagnostic_code="CF-DAILY-TECHNICAL-FAILURE",
            now=NOW,
        )
        ready = control.get(SESSION_ID)
        control.acquire_automated(
            session_id=SESSION_ID,
            instance_id=INSTANCE_ID,
            worker_id="crashed-daily-worker",
            job_id=JOB_ID,
            expected_record_version=ready.record_version,
            now=NOW,
            ttl=datetime.resolution * 600_000_000,
        )

        assert executor.reconcile_terminal_or_expired() == (JOB_ID,)

        assert access.get(window_id).consumed_at == NOW
        stopped = control.get(SESSION_ID)
        assert stopped.browser_lifecycle == "stopped"
        assert stopped.browser_control_mode == "idle"
        assert stopped.job_id is None
        assert browser.running is False
        assert browser.close_count == 1
    finally:
        runtime.close()


def test_old_consumed_cleanup_never_touches_a_newer_automated_owner(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, invocations, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
    )
    try:
        current = invocations.get_by_job(JOB_ID)
        invocations.fail(
            job_id=JOB_ID,
            expected_record_version=current.record_version,
            diagnostic_code="CF-DAILY-TECHNICAL-FAILURE",
            now=NOW,
        )
        access.retire(
            access_window_id=window_id,
            expected_record_version=1,
            now=NOW,
        )
        _insert_daily_job(runtime, job_id=OTHER_JOB_ID)
        ready = control.get(SESSION_ID)
        newer = control.acquire_automated(
            session_id=SESSION_ID,
            instance_id=INSTANCE_ID,
            worker_id="newer-job-worker",
            job_id=OTHER_JOB_ID,
            expected_record_version=ready.record_version,
            now=NOW,
            ttl=datetime.resolution * 600_000_000,
        )

        executor.close_terminal_job(JOB_ID)

        unchanged = control.get(SESSION_ID)
        assert unchanged.browser_control_mode == "automated"
        assert unchanged.job_id == OTHER_JOB_ID
        assert unchanged.control_epoch == newer.control_epoch
        assert browser.running is True
        assert browser.close_count == 0
    finally:
        runtime.close()


def test_cancelled_job_without_invocation_retires_only_its_window(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, _, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        create_invocation=False,
    )
    try:
        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = 'cancelled',
                        current_stage = NULL,
                        record_version = record_version + 1,
                        updated_at = :now
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": JOB_ID, "now": NOW.isoformat()},
            )
        _insert_daily_job(runtime, job_id=OTHER_JOB_ID)
        ready = control.get(SESSION_ID)
        newer = control.acquire_automated(
            session_id=SESSION_ID,
            instance_id=INSTANCE_ID,
            worker_id="newer-job-worker",
            job_id=OTHER_JOB_ID,
            expected_record_version=ready.record_version,
            now=NOW,
            ttl=datetime.resolution * 600_000_000,
        )

        assert executor.reconcile_terminal_or_expired() == (JOB_ID,)

        assert access.get(window_id).consumed_at == NOW
        unchanged = control.get(SESSION_ID)
        assert unchanged.browser_control_mode == "automated"
        assert unchanged.job_id == OTHER_JOB_ID
        assert unchanged.control_epoch == newer.control_epoch
        assert browser.running is True
        assert browser.close_count == 0
    finally:
        runtime.close()


def test_cancelled_idle_job_closes_the_terminal_runtime(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, _, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        create_invocation=False,
    )
    try:
        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = 'cancelled',
                        current_stage = NULL,
                        record_version = record_version + 1,
                        updated_at = :now
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": JOB_ID, "now": NOW.isoformat()},
            )

        executor.close_terminal_job(JOB_ID)

        assert access.get(window_id).consumed_at == NOW
        stopped = control.get(SESSION_ID)
        assert stopped.browser_lifecycle == "stopped"
        assert stopped.browser_control_mode == "idle"
        assert browser.running is False
        assert browser.close_count == 1
    finally:
        runtime.close()


def test_cancelled_job_fences_matching_human_window_before_close(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, _, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        create_invocation=False,
    )
    try:
        ready = control.get(SESSION_ID)
        held, _ = control.acquire_human_session_control(
            session_id=SESSION_ID,
            control_mode="human_login",
            human_session_id=window_id,
            expected_record_version=ready.record_version,
            idempotency_key="cancelled-human-window",
            request_hash=hashlib.sha256(
                b"cancelled-human-window"
            ).hexdigest(),
            now=NOW,
        )
        assert held.browser_control_mode == "human_login"
        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = 'cancelled',
                        current_stage = NULL,
                        record_version = record_version + 1,
                        updated_at = :now
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": JOB_ID, "now": NOW.isoformat()},
            )

        executor.close_terminal_job(JOB_ID)

        assert access.get(window_id).consumed_at == NOW
        stopped = control.get(SESSION_ID)
        assert stopped.browser_lifecycle == "stopped"
        assert stopped.browser_control_mode == "idle"
        assert browser.running is False
        assert browser.close_count == 1
    finally:
        runtime.close()


def test_terminal_cleanup_cannot_close_a_newer_human_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    browser = _Browser()
    lifecycle = _ObservedLifecycle()
    runtime, executor, _, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        create_invocation=False,
        browser_lifecycle=lifecycle,
    )
    cleanup_reached_stopped = Event()
    allow_old_close = Event()
    starter_attempted = Event()
    starter_completed = Event()
    cleanup_errors: list[BaseException] = []
    starter_errors: list[BaseException] = []
    try:
        ready = control.get(SESSION_ID)
        control.acquire_human_session_control(
            session_id=SESSION_ID,
            control_mode="human_login",
            human_session_id=window_id,
            expected_record_version=ready.record_version,
            idempotency_key="old-human-window",
            request_hash=hashlib.sha256(b"old-human-window").hexdigest(),
            now=NOW,
        )
        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = 'cancelled',
                        current_stage = NULL,
                        record_version = record_version + 1,
                        updated_at = :now
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": JOB_ID, "now": NOW.isoformat()},
            )
        _insert_daily_job(runtime, job_id=OTHER_JOB_ID)

        original_mark_closed = control.mark_human_session_closed

        def delayed_mark_closed(**kwargs: object) -> object:
            result = original_mark_closed(**kwargs)  # type: ignore[arg-type]
            cleanup_reached_stopped.set()
            if not allow_old_close.wait(timeout=5):
                raise AssertionError("test did not release old browser cleanup")
            return result

        monkeypatch.setattr(
            control,
            "mark_human_session_closed",
            delayed_mark_closed,
        )

        def cleanup_old_session() -> None:
            try:
                executor.close_terminal_job(JOB_ID)
            except BaseException as exc:  # pragma: no cover - assertion reports it
                cleanup_errors.append(exc)

        cleanup_thread = Thread(target=cleanup_old_session)
        cleanup_thread.start()
        assert cleanup_reached_stopped.wait(timeout=5)

        new_window_id = _issue_window(
            access,
            job_id=OTHER_JOB_ID,
            key="window-new-human-session",
        )

        def start_new_session() -> None:
            try:
                starter_attempted.set()
                with lifecycle.hold():
                    current = control.get(SESSION_ID)
                    assert current.browser_lifecycle == "stopped"
                    browser.start_human_login()
                    current = control.mark_ready(
                        session_id=SESSION_ID,
                        expected_record_version=current.record_version,
                        now=NOW,
                    )
                    control.acquire_human_session_control(
                        session_id=SESSION_ID,
                        control_mode="human_login",
                        human_session_id=new_window_id,
                        expected_record_version=current.record_version,
                        idempotency_key="new-human-window",
                        request_hash=hashlib.sha256(
                            b"new-human-window"
                        ).hexdigest(),
                        now=NOW,
                    )
                    starter_completed.set()
            except BaseException as exc:  # pragma: no cover - assertion reports it
                starter_errors.append(exc)

        starter_thread = Thread(target=start_new_session)
        starter_thread.start()
        assert starter_attempted.wait(timeout=5)
        second_lifecycle_waited = lifecycle.waiter_observed.wait(timeout=1)
    finally:
        allow_old_close.set()
        if "cleanup_thread" in locals():
            cleanup_thread.join(timeout=5)
        if "starter_thread" in locals():
            starter_thread.join(timeout=5)

    try:
        assert second_lifecycle_waited
        assert cleanup_errors == []
        assert starter_errors == []
        assert starter_completed.is_set()
        newer = control.get(SESSION_ID)
        assert newer.browser_lifecycle == "ready"
        assert newer.browser_control_mode == "human_login"
        assert newer.holder_id == new_window_id
        assert browser.running is True
        assert browser.close_count == 1
        assert browser.start_count == 1
    finally:
        runtime.close()


def test_terminal_cleanup_closes_a_stopped_orphan_runtime(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    runtime, executor, _, access, control, window_id = _setup(
        tmp_path,
        browser=browser,
        create_invocation=False,
    )
    try:
        ready = control.get(SESSION_ID)
        stopped, _ = control.mark_stopped(
            session_id=SESSION_ID,
            access_window_id=window_id,
            expected_record_version=ready.record_version,
            idempotency_key="stopped-orphan-runtime",
            request_hash=hashlib.sha256(
                b"stopped-orphan-runtime"
            ).hexdigest(),
            now=NOW,
        )
        assert stopped.browser_lifecycle == "stopped"
        assert browser.running is True
        with runtime.engine.begin() as connection:
            connection.execute(
                text(
                    """
                    UPDATE jobs
                    SET status = 'cancelled',
                        current_stage = NULL,
                        record_version = record_version + 1,
                        updated_at = :now
                    WHERE job_id = :job_id
                    """
                ),
                {"job_id": JOB_ID, "now": NOW.isoformat()},
            )

        executor.close_terminal_job(JOB_ID)

        assert access.get(window_id).consumed_at == NOW
        assert control.get(SESSION_ID).browser_lifecycle == "stopped"
        assert browser.running is False
        assert browser.close_count == 1
    finally:
        runtime.close()


def test_startup_retires_crashed_preflight_before_invocation(
    tmp_path: Path,
) -> None:
    browser = _Browser()
    (
        runtime,
        executor,
        invocations,
        access,
        control,
        window_id,
    ) = _setup(
        tmp_path,
        browser=browser,
        create_invocation=False,
    )
    try:
        invocations.reserve_start(
            idempotency_key="crashed-preflight-start",
            request_hash=hashlib.sha256(
                b"crashed-preflight-start"
            ).hexdigest(),
            job_id=JOB_ID,
            access_window_id=window_id,
            now=NOW,
        )
        ready = control.get(SESSION_ID)
        control.acquire_automated(
            session_id=SESSION_ID,
            instance_id=INSTANCE_ID,
            worker_id="crashed-preflight-worker",
            job_id=JOB_ID,
            expected_record_version=ready.record_version,
            now=NOW,
            ttl=datetime.resolution * 600_000_000,
        )

        assert executor.reconcile_terminal_or_expired() == (JOB_ID,)

        assert access.get(window_id).consumed_at == NOW
        stopped = control.get(SESSION_ID)
        assert stopped.browser_lifecycle == "stopped"
        assert stopped.browser_control_mode == "idle"
        assert browser.running is False
        assert invocations.orphaned_start_job_ids() == (JOB_ID,)
    finally:
        runtime.close()
