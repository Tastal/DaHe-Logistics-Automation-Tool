from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from dahe.adapters.chengfeng.browser_runtime import BrowserRuntimeError
from dahe.adapters.files.shadow_selection_manifest import (
    FormalShadowSelectionStoreError,
    FormalShadowSelectionTransientStoreError,
)
from dahe.application.chengfeng.access_window import AccessWindowError
from dahe.application.chengfeng.settlement_live_execution import (
    SettlementCaptureLiveStageExecutor,
    _browser_runtime_diagnostic,
)
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.jobs.settlement_capture_execution import (
    SETTLEMENT_CAPTURE_STAGE,
    SettlementCaptureStageWork,
)
from dahe.ports.chengfeng import BrowserContextClosedError, ChengfengStage

NOW = datetime(2026, 7, 30, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    ("worker_code", "expected"),
    [
        (
            "browser_session_settlement_scope_control_unavailable",
            "CF-SETTLEMENT-SCOPE-CONTROL-UNAVAILABLE",
        ),
        (
            "browser_session_fixed_values_rejected",
            "CF-SETTLEMENT-FIXED-VALUES-REJECTED",
        ),
        (
            "browser_operational_query_contract_changed",
            "CF-SETTLEMENT-OPERATIONAL-CONTRACT-CHANGED",
        ),
        (
            "browser_operational_cache_refresh_failed",
            "CF-SETTLEMENT-CACHE-REFRESH-FAILED",
        ),
        (
            "unreviewed_private_worker_code",
            "CF-SETTLEMENT-BROWSER-RUNTIME-FAILED",
        ),
    ],
)
def test_browser_runtime_diagnostic_exposes_only_reviewed_codes(
    worker_code: str,
    expected: str,
) -> None:
    error = BrowserRuntimeError("private worker detail", code=worker_code)

    assert _browser_runtime_diagnostic(error) == expected


class _InvocationStore:
    def __init__(self) -> None:
        self.blocked_diagnostic: str | None = None
        self.current = SimpleNamespace(
            invocation_id="invocation-one",
            record_version=2,
            status="sealed",
            diagnostic_code=None,
        )

    def load_manifest(self, _invocation_id: str) -> SimpleNamespace:
        return SimpleNamespace(
            canonical_sha256="a" * 64,
            identity_context_sha256="b" * 64,
            source_build_sha256="c" * 64,
            contract_canonical_sha256="d" * 64,
            contract_selection_sha256="e" * 64,
        )

    def target_kind(
        self,
        _invocation_id: str,
    ) -> ShadowBatchTargetKind:
        return ShadowBatchTargetKind.CURRENT_LOCKED_50

    def block_selection(
        self,
        *,
        diagnostic_code: str,
        **_values: object,
    ) -> SimpleNamespace:
        self.blocked_diagnostic = diagnostic_code
        self.current = SimpleNamespace(
            invocation_id="invocation-one",
            record_version=3,
            status="selection_blocked",
            diagnostic_code=diagnostic_code,
        )
        return self.current

    def get(self, _invocation_id: str) -> SimpleNamespace:
        return self.current


class _BrokenSelectionStore:
    def select(self, **_values: object) -> object:
        raise FormalShadowSelectionStoreError(
            "formal selection manifest integrity is invalid"
        )


class _TransientSelectionStore:
    def select(self, **_values: object) -> object:
        raise FormalShadowSelectionTransientStoreError(
            "formal selection write was interrupted"
        )


class _CollectingInvocationStore:
    def __init__(
        self,
        target_kind: ShadowBatchTargetKind = (
            ShadowBatchTargetKind.REAL_SHADOW_30
        ),
    ) -> None:
        self.target_kind_value = target_kind
        self.current = SimpleNamespace(
            invocation_id="invocation-real-shadow",
            access_window_id="window-real-shadow",
            record_version=1,
            status="collecting",
            diagnostic_code=None,
        )

    def get_by_job(self, _job_id: str) -> SimpleNamespace:
        return self.current

    def target_kind(
        self,
        _invocation_id: str,
    ) -> ShadowBatchTargetKind:
        return self.target_kind_value


class _ExpiredAccessRepository:
    def authorize(self, **_values: object) -> object:
        raise AccessWindowError("access window is expired")


def _verified_exclusions(_capture: object) -> SimpleNamespace:
    return SimpleNamespace(
        authority_sha256="1" * 64,
        child_index_head_sha256="2" * 64,
        source_boundary_sha256="3" * 64,
        source_inventory_high_watermark=1,
        identity_context_sha256="b" * 64,
        expected_current_build_sha256="c" * 64,
        expected_settlement_contract_sha256="d" * 64,
        expected_settlement_selection_sha256="e" * 64,
        excluded_platform_identity_sha256s=(),
        excluded_image_sha256s=(),
        excluded_scope_exclusion_tokens=(),
        excluded_perceptual_fingerprints=(),
    )


def test_deterministic_selection_store_error_is_terminally_blocked() -> None:
    invocations = _InvocationStore()
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._invocations = invocations
    executor._selections = _BrokenSelectionStore()
    executor._exclusion_snapshot_loader = _verified_exclusions
    executor._pipeline_fingerprint = "f" * 64
    executor._clock = lambda: NOW
    work = SettlementCaptureStageWork(
        stage_attempt_id="attempt-one",
        job_id="job-one",
        work_item_id="item-one",
        stage=SETTLEMENT_CAPTURE_STAGE,
    )

    result = executor._finalize_selection(
        work,
        invocation=invocations.current,
        platform_read_performed=False,
        checkpoint_revision=None,
    )

    assert result.outcome == "failed"
    assert result.next_stage is None
    assert invocations.current.status == "selection_blocked"
    assert invocations.blocked_diagnostic == (
        "SETTLEMENT-SELECTION-DETERMINISTIC-BLOCKED"
    )


def test_transient_selection_io_retries_only_within_fixed_budget() -> None:
    invocations = _InvocationStore()
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._invocations = invocations
    executor._selections = _TransientSelectionStore()
    executor._exclusion_snapshot_loader = _verified_exclusions
    executor._pipeline_fingerprint = "f" * 64
    executor._clock = lambda: NOW

    retry = executor._finalize_selection(
        SettlementCaptureStageWork(
            stage_attempt_id="attempt-one",
            job_id="job-one",
            work_item_id="item-one",
            stage=SETTLEMENT_CAPTURE_STAGE,
            attempt_count=0,
        ),
        invocation=invocations.current,
        platform_read_performed=False,
        checkpoint_revision=None,
    )
    assert retry.outcome == "retry"
    assert invocations.blocked_diagnostic is None

    exhausted = executor._finalize_selection(
        SettlementCaptureStageWork(
            stage_attempt_id="attempt-three",
            job_id="job-one",
            work_item_id="item-one",
            stage=SETTLEMENT_CAPTURE_STAGE,
            attempt_count=2,
        ),
        invocation=invocations.current,
        platform_read_performed=False,
        checkpoint_revision=None,
    )
    assert exhausted.outcome == "failed"
    assert exhausted.next_stage is None
    assert invocations.blocked_diagnostic == (
        "SETTLEMENT-SELECTION-TRANSIENT-RETRY-EXHAUSTED"
    )


def test_real_shadow_gate_is_checked_before_platform_read() -> None:
    invocations = _CollectingInvocationStore()
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._invocations = invocations
    executor._validation_authority_gate = lambda: True
    validated: list[ShadowBatchTargetKind] = []

    def reject(target_kind: ShadowBatchTargetKind) -> None:
        validated.append(target_kind)
        raise FormalShadowSelectionStoreError(
            "current locked gate authority is unavailable"
        )

    executor._target_prerequisite_validator = reject
    work = SettlementCaptureStageWork(
        stage_attempt_id="attempt-real-shadow",
        job_id="job-real-shadow",
        work_item_id="item-real-shadow",
        stage=SETTLEMENT_CAPTURE_STAGE,
    )

    result = executor(work)

    assert validated == [ShadowBatchTargetKind.REAL_SHADOW_30]
    assert result.outcome == "failed"
    assert result.platform_read_performed is False
    assert result.diagnostic_code == "SETTLEMENT-LOCKED-GATE-REQUIRED"


def test_contract_validation_gate_is_checked_before_any_platform_read() -> None:
    invocations = _CollectingInvocationStore(
        ShadowBatchTargetKind.CURRENT_LOCKED_50
    )
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._invocations = invocations
    executor._validation_authority_gate = lambda: False
    target_checks: list[ShadowBatchTargetKind] = []
    executor._target_prerequisite_validator = target_checks.append
    work = SettlementCaptureStageWork(
        stage_attempt_id="attempt-locked-validation",
        job_id="job-locked-validation",
        work_item_id="item-locked-validation",
        stage=SETTLEMENT_CAPTURE_STAGE,
    )

    result = executor(work)

    assert target_checks == []
    assert result.outcome == "failed"
    assert result.platform_read_performed is False
    assert result.diagnostic_code == (
        "SETTLEMENT-VALIDATION-GATE-REQUIRED"
    )


def test_expired_window_waits_for_external_rollover_without_reading() -> None:
    invocations = _CollectingInvocationStore(
        ShadowBatchTargetKind.CURRENT_LOCKED_50
    )
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._invocations = invocations
    executor._validation_authority_gate = lambda: True
    executor._target_prerequisite_validator = lambda _target: None
    executor._access = _ExpiredAccessRepository()
    executor._session_id = "session-one"
    executor._build_sha256 = "a" * 64
    executor._clock = lambda: NOW
    work = SettlementCaptureStageWork(
        stage_attempt_id="attempt-expired-window",
        job_id="job-expired-window",
        work_item_id="item-expired-window",
        stage=SETTLEMENT_CAPTURE_STAGE,
    )

    result = executor(work)

    assert result.outcome == "waiting_external"
    assert result.next_stage == SETTLEMENT_CAPTURE_STAGE
    assert result.platform_read_performed is False
    assert result.diagnostic_code == (
        "CF-SETTLEMENT-ACCESS-WINDOW-EXPIRED"
    )


def test_operational_browser_close_retries_without_requesting_login() -> None:
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._operational_browser_recovery_counts = {}
    work = SettlementCaptureStageWork(
        stage_attempt_id="attempt-browser-closed",
        job_id="operational-job",
        work_item_id="operational-item",
        stage=SETTLEMENT_CAPTURE_STAGE,
    )
    error = BrowserContextClosedError(stage=ChengfengStage.DETAIL_QUERY)

    result = executor._operational_browser_recovery_execution(
        work,
        diagnostic_code=error.diagnostic_code,
    )

    assert result.outcome == "retry"
    assert result.next_stage == SETTLEMENT_CAPTURE_STAGE
    assert result.diagnostic_code == "CF-BROWSER-CLOSED"


def test_repeated_operational_browser_close_stops_after_bounded_retries() -> None:
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._operational_browser_recovery_counts = {}
    work = SettlementCaptureStageWork(
        stage_attempt_id="attempt-browser-closed",
        job_id="operational-job",
        work_item_id="operational-item",
        stage=SETTLEMENT_CAPTURE_STAGE,
    )

    first = executor._operational_browser_recovery_execution(
        work,
        diagnostic_code="CF-BROWSER-CLOSED",
    )
    exhausted = executor._operational_browser_recovery_execution(
        work,
        diagnostic_code="CF-BROWSER-CLOSED",
    )

    assert first.outcome == "retry"
    assert exhausted.outcome == "failed"
    assert exhausted.diagnostic_code == "CF-BROWSER-CLOSED"


def test_capture_scope_is_bound_by_target_and_invocation() -> None:
    assert SettlementCaptureLiveStageExecutor._scope_for_target(
        ShadowBatchTargetKind.CURRENT_LOCKED_50,
        "current",
    ) == "current"
    assert SettlementCaptureLiveStageExecutor._scope_for_target(
        ShadowBatchTargetKind.CURRENT_LOCKED_50,
        "settled_history",
    ) == "settled_history"
    assert SettlementCaptureLiveStageExecutor._scope_for_target(
        ShadowBatchTargetKind.REAL_SHADOW_30,
        "current",
    ) == "current"
    with pytest.raises(ValueError, match="source scope"):
        SettlementCaptureLiveStageExecutor._scope_for_target(
            ShadowBatchTargetKind.REAL_SHADOW_30,
            "settled_history",
        )


class _OperationalTerminalInvocationStore:
    def __init__(
        self,
        *,
        status: str = "operational_ready",
        business_session_binding: bool = True,
    ) -> None:
        self.retired: list[str] = []
        self.status = status
        self.business_session_binding = business_session_binding
        self._access_active = True

    def get_by_job(self, job_id: str) -> SimpleNamespace:
        assert job_id == "operational-job"
        return SimpleNamespace(
            invocation_id="operational-invocation",
            access_window_id="operational-window",
            status=self.status,
        )

    def target_kind(
        self,
        invocation_id: str,
    ) -> ShadowBatchTargetKind:
        assert invocation_id == "operational-invocation"
        return ShadowBatchTargetKind.OPERATIONAL_COMPAT

    def retire_terminal_access(self, *, job_id: str, now: datetime) -> bool:
        assert now == NOW
        self.retired.append(job_id)
        if not self._access_active:
            return False
        self._access_active = False
        return True

    def has_business_session_binding(self, job_id: str) -> bool:
        assert job_id == "operational-job"
        return self.business_session_binding


class _OperationalBrowserControl:
    def __init__(self) -> None:
        self.acquired: list[dict[str, object]] = []
        self.released: list[dict[str, object]] = []

    def get(self, session_id: str) -> SimpleNamespace:
        assert session_id == "platform-session"
        return SimpleNamespace(
            browser_control_mode="idle",
            browser_lifecycle="ready",
            holder_kind=None,
            holder_id=None,
            job_id=None,
            instance_id=None,
            worker_id=None,
            control_epoch=9,
            record_version=5,
        )

    def acquire_human_session_control(
        self,
        **values: object,
    ) -> tuple[SimpleNamespace, bool]:
        self.acquired.append(values)
        return SimpleNamespace(browser_control_mode="human_handoff"), False

    def release_automated(self, **values: object) -> None:
        self.released.append(values)


class _OperationalBrowserRuntime:
    running = True

    def __init__(self, *, fail_handoff: bool = False) -> None:
        self.fail_handoff = fail_handoff
        self.handoff_count = 0
        self.close_count = 0
        self.park_count = 0

    def handoff_operational_session(self) -> None:
        self.handoff_count += 1
        if self.fail_handoff:
            raise BrowserRuntimeError(
                "handoff failed",
                code="browser_operational_handoff_failed",
            )

    def close(self) -> None:
        self.close_count += 1

    def park_operational_session(self) -> None:
        self.park_count += 1


class _MissingOperationalRuntime(_OperationalBrowserRuntime):
    running = False


class _StaleAutomatedBrowserControl(_OperationalBrowserControl):
    def __init__(self) -> None:
        super().__init__()
        self.recovery_calls: list[dict[str, object]] = []
        self._record = SimpleNamespace(
            browser_control_mode="automated",
            browser_lifecycle="ready",
            holder_kind="worker",
            holder_id="old-attempt",
            job_id="operational-job",
            instance_id="old-instance",
            worker_id="old-worker",
            control_epoch=12,
            record_version=7,
        )

    def get(self, session_id: str) -> SimpleNamespace:
        assert session_id == "platform-session"
        return self._record

    def begin_automatic_recovery(self, **values: object) -> SimpleNamespace:
        self.recovery_calls.append(values)
        self._record = SimpleNamespace(
            browser_control_mode="idle",
            browser_lifecycle="recovering",
            holder_kind=None,
            holder_id=None,
            job_id="operational-job",
            instance_id=None,
            worker_id=None,
            control_epoch=13,
            record_version=8,
        )
        return self._record


class _OperationalPrepareRuntime:
    running = True

    def __init__(self) -> None:
        self.prepare_count = 0

    def prepare_operational_compat(
        self,
        _contract_subject_code: str = "shanxi_guienbo",
    ) -> None:
        self.prepare_count += 1


def test_fast_operational_capture_confirms_preparation_for_each_stage() -> None:
    runtime = _OperationalPrepareRuntime()
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._browser_runtime = runtime
    executor._pending_operational_handoffs = set()

    executor._ensure_operational_browser_prepared("operational-job")
    executor._ensure_operational_browser_prepared("operational-job")

    assert runtime.prepare_count == 2
    assert executor._pending_operational_handoffs == {"operational-job"}


def test_fast_operational_capture_reprepares_after_owned_browser_restart() -> None:
    runtime = _OperationalPrepareRuntime()
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    executor._browser_runtime = runtime
    executor._pending_operational_handoffs = {"operational-job"}

    executor._pending_operational_handoffs.discard("operational-job")
    executor._ensure_operational_browser_prepared("operational-job")

    assert runtime.prepare_count == 1


class _OperationalRetryableHandoffRuntime(_OperationalBrowserRuntime):
    def handoff_operational_session(self) -> None:
        self.handoff_count += 1
        if self.handoff_count == 1:
            raise BrowserRuntimeError(
                "handoff failed once",
                code="browser_operational_handoff_failed",
            )


def _operational_terminal_executor(
    *,
    runtime: _OperationalBrowserRuntime,
    invocation_status: str = "operational_ready",
    business_session_binding: bool = True,
) -> tuple[
    SettlementCaptureLiveStageExecutor,
    _OperationalTerminalInvocationStore,
    _OperationalBrowserControl,
    list[str],
]:
    executor = SettlementCaptureLiveStageExecutor.__new__(
        SettlementCaptureLiveStageExecutor
    )
    invocations = _OperationalTerminalInvocationStore(
        status=invocation_status,
        business_session_binding=business_session_binding,
    )
    control = _OperationalBrowserControl()
    materialized: list[str] = []
    executor._invocations = invocations
    executor._operational_materializer = materialized.append
    executor._browser_lifecycle = SimpleNamespace(hold=nullcontext)
    executor._browser_control = control
    executor._browser_runtime = runtime
    executor._session_id = "platform-session"
    executor._materialized_operational_jobs = set()
    executor._pending_operational_handoffs = {"operational-job"}
    executor._clock = lambda: NOW
    return executor, invocations, control, materialized


def test_fast_operational_capture_parks_browser_before_offline_materialization() -> None:
    runtime = _OperationalBrowserRuntime()
    executor, invocations, _control, _materialized = (
        _operational_terminal_executor(
            runtime=runtime,
            business_session_binding=False,
        )
    )
    observed_park_counts: list[int] = []
    executor._operational_materializer = (
        lambda _job_id: observed_park_counts.append(runtime.park_count)
    )
    executor._stop_browser = lambda **_values: None

    executor.close_terminal_job("operational-job")

    assert invocations.retired == ["operational-job"]
    assert runtime.close_count == 0
    assert runtime.park_count == 1
    assert observed_park_counts == [1]


def test_operational_terminal_capture_hands_the_clean_window_to_people() -> None:
    runtime = _OperationalBrowserRuntime()
    executor, invocations, control, materialized = (
        _operational_terminal_executor(runtime=runtime)
    )

    executor.close_terminal_job("operational-job")

    assert materialized == ["operational-job"]
    assert invocations.retired == ["operational-job"]
    assert runtime.handoff_count == 1
    assert runtime.close_count == 0
    assert len(control.acquired) == 1
    assert control.acquired[0]["control_mode"] == "human_handoff"
    assert control.acquired[0]["human_session_id"] == "operational-window"


def test_operational_failed_capture_still_hands_the_clean_window_to_people() -> None:
    runtime = _OperationalBrowserRuntime()
    executor, invocations, control, materialized = (
        _operational_terminal_executor(
            runtime=runtime,
            invocation_status="collecting",
        )
    )

    executor.close_terminal_job("operational-job")

    assert materialized == []
    assert invocations.retired == ["operational-job"]
    assert runtime.handoff_count == 1
    assert runtime.close_count == 0
    assert len(control.acquired) == 1
    assert control.acquired[0]["control_mode"] == "human_handoff"


def test_operational_stage_failure_releases_control_without_closing_browser() -> None:
    runtime = _OperationalBrowserRuntime()
    executor, _invocations, control, _materialized = (
        _operational_terminal_executor(
            runtime=runtime,
            invocation_status="collecting",
        )
    )
    executor._instance_id = "instance-one"
    acquired = SimpleNamespace(
        control_epoch=9,
        fencing_token="fencing-token",
    )
    work = SettlementCaptureStageWork(
        stage_attempt_id="attempt-operational-failure",
        job_id="operational-job",
        work_item_id="operational-item",
        stage=SETTLEMENT_CAPTURE_STAGE,
    )

    executor._release_after_failed_execution(
        work=work,
        invocation=SimpleNamespace(access_window_id="operational-window"),
        acquired=acquired,
        worker_id="settlement-capture-attempt-operational-failure",
        is_operational=True,
    )

    assert len(control.released) == 1
    assert runtime.close_count == 0


def test_operational_handoff_failure_closes_only_the_owned_browser() -> None:
    runtime = _OperationalBrowserRuntime(fail_handoff=True)
    executor, _invocations, _control, _materialized = (
        _operational_terminal_executor(runtime=runtime)
    )
    stopped: list[dict[str, object]] = []
    executor._stop_browser = lambda **values: stopped.append(values)

    with pytest.raises(
        RuntimeError,
        match="operational browser handoff did not complete",
    ):
        executor.close_terminal_job("operational-job")

    assert runtime.close_count == 1
    assert stopped == [
        {
            "access_window_id": "operational-window",
            "job_id": "operational-job",
            "expected_record_version": 5,
        }
    ]


def test_operational_terminal_retry_does_not_materialize_twice() -> None:
    runtime = _OperationalRetryableHandoffRuntime()
    executor, invocations, control, materialized = (
        _operational_terminal_executor(runtime=runtime)
    )
    executor._stop_browser = lambda **_values: None

    with pytest.raises(
        RuntimeError,
        match="operational browser handoff did not complete",
    ):
        executor.close_terminal_job("operational-job")

    runtime.running = True
    executor.close_terminal_job("operational-job")

    assert materialized == ["operational-job"]
    assert invocations.retired == ["operational-job", "operational-job"]
    assert runtime.handoff_count == 2
    assert len(control.acquired) == 1


def test_stale_operational_terminal_cannot_close_a_new_browser_session() -> None:
    runtime = _OperationalBrowserRuntime(fail_handoff=True)
    executor, invocations, control, materialized = (
        _operational_terminal_executor(runtime=runtime)
    )
    executor._pending_operational_handoffs.clear()

    executor.close_terminal_job("operational-job")

    assert materialized == ["operational-job"]
    assert invocations.retired == ["operational-job"]
    assert runtime.handoff_count == 0
    assert runtime.close_count == 0
    assert control.acquired == []


def test_terminal_operational_holder_with_missing_runtime_is_recovered() -> None:
    runtime = _MissingOperationalRuntime()
    executor, invocations, _control, materialized = (
        _operational_terminal_executor(runtime=runtime)
    )
    control = _StaleAutomatedBrowserControl()
    executor._browser_control = control
    executor._pending_operational_handoffs.clear()
    stopped: list[dict[str, object]] = []
    executor._stop_browser = lambda **values: stopped.append(values)

    executor.close_terminal_job("operational-job")

    assert invocations.retired == ["operational-job"]
    assert materialized == ["operational-job"]
    assert len(control.recovery_calls) == 1
    assert stopped == [
        {
            "access_window_id": "operational-window",
            "job_id": "operational-job",
            "expected_record_version": 8,
        }
    ]
