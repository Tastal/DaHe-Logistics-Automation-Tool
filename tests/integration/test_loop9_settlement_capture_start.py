from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from sqlalchemy import update

from dahe.adapters.sqlite.browser_control import BrowserControlStore
from dahe.adapters.sqlite.platform_access import (
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import JOBS
from dahe.adapters.sqlite.settlement_capture import (
    SettlementCaptureStoreConflictError,
    SqliteSettlementCaptureStore,
)
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.application.chengfeng.shadow_batch import (
    ShadowBatchTargetKind,
)
from dahe.jobs.scheduler import CooperativeScheduler
from dahe.jobs.settlement_capture_execution import (
    SETTLEMENT_CAPTURE_STAGE,
    AsyncSettlementCaptureExecutionBackend,
    SettlementCaptureStageExecution,
    SettlementCaptureStageWork,
)
from dahe.ports.jobs import IdempotencyConflictError

PROJECT_ROOT = Path(__file__).parents[2]
NOW = datetime.now(UTC).replace(microsecond=0)
BUILD_SHA = hashlib.sha256(b"loop9-start-build").hexdigest()
CONTRACT_SHA = hashlib.sha256(b"loop9-start-contract").hexdigest()
CONTRACT_FILE_SHA = hashlib.sha256(
    b"loop9-start-contract-file"
).hexdigest()
CONTRACT_SELECTION_SHA = hashlib.sha256(
    b"loop9-start-contract-selection"
).hexdigest()
IDENTITY_CONTEXT_SHA = hashlib.sha256(
    b"loop9-start-identity"
).hexdigest()


def _runtime(tmp_path: Path) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="loop9-start-test",
    )


def _start(
    store: SqliteSettlementCaptureStore,
    *,
    target_kind: ShadowBatchTargetKind = (
        ShadowBatchTargetKind.CURRENT_LOCKED_50
    ),
    key: str = "start-locked-50",
    request_hash: str | None = None,
    duration_minutes: int = 60,
    source_scope: str = "current",
):
    return store.create_start(
        target_kind=target_kind,
        source_scope=source_scope,
        session_id="chengfeng-shadow-v1",
        source_build_sha256=BUILD_SHA,
        contract_canonical_sha256=CONTRACT_SHA,
        contract_file_sha256=CONTRACT_FILE_SHA,
        contract_selection_sha256=CONTRACT_SELECTION_SHA,
        identity_context_sha256=IDENTITY_CONTEXT_SHA,
        duration_minutes=duration_minutes,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        idempotency_key=key,
        request_hash=request_hash or hashlib.sha256(key.encode()).hexdigest(),
        now=NOW,
    )


def test_atomic_start_creates_job_window_and_invocation_before_replay(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteSettlementCaptureStore(runtime)
        created = _start(store)

        assert created.created is True
        assert (
            created.access_window.purpose
            is AccessPurpose.FORMAL_LOCKED_SET
        )
        assert created.access_window.job_id == created.job_id
        assert created.invocation.job_id == created.job_id
        assert (
            created.invocation.access_window_id
            == created.access_window.access_window_id
        )
        assert created.invocation.status == "collecting"
        assert created.invocation.scope == "current"
        assert created.invocation.page_size == 50

        replay = _start(store)
        assert replay.created is False
        assert replay.job_id == created.job_id
        assert replay.work_item_id == created.work_item_id
        assert (
            replay.invocation.invocation_id
            == created.invocation.invocation_id
        )
        assert replay.access_window.token == ""
    finally:
        runtime.close()


def test_atomic_start_maps_each_target_to_its_fixed_purpose(
    tmp_path: Path,
) -> None:
    locked_runtime = _runtime(tmp_path / "locked")
    try:
        locked = _start(
            SqliteSettlementCaptureStore(locked_runtime),
            target_kind=ShadowBatchTargetKind.CURRENT_LOCKED_50,
        )
        assert (
            locked.access_window.purpose
            is AccessPurpose.FORMAL_LOCKED_SET
        )
    finally:
        locked_runtime.close()

    shadow_runtime = _runtime(tmp_path / "shadow")
    try:
        shadow = _start(
            SqliteSettlementCaptureStore(shadow_runtime),
            target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
            key="start-shadow-30",
        )
        assert (
            shadow.access_window.purpose
            is AccessPurpose.PRODUCTION_SHADOW
        )
        assert shadow.invocation.scope == "current"
        assert shadow.invocation.page_size == 50
    finally:
        shadow_runtime.close()


def test_locked_start_can_freeze_bounded_settled_history_scope(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        created = _start(
            SqliteSettlementCaptureStore(runtime),
            source_scope="settled_history",
        )

        assert created.invocation.scope == "settled_history"
        assert created.invocation.page_size == 100
    finally:
        runtime.close()


def test_locked_start_replay_cannot_change_its_source_scope(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteSettlementCaptureStore(runtime)
        _start(store)

        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="source scope replay changed",
        ):
            _start(store, source_scope="settled_history")
    finally:
        runtime.close()


@pytest.mark.parametrize(
    "target_kind",
    [
        ShadowBatchTargetKind.REAL_SHADOW_30,
        ShadowBatchTargetKind.OPERATIONAL_COMPAT,
    ],
)
def test_non_locked_targets_reject_settled_history_scope(
    tmp_path: Path,
    target_kind: ShadowBatchTargetKind,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="source scope",
        ):
            _start(
                SqliteSettlementCaptureStore(runtime),
                target_kind=target_kind,
                key=f"reject-history-{target_kind.value}",
                source_scope="settled_history",
            )
    finally:
        runtime.close()


def test_operational_start_uses_workday_window_and_distinct_run_mode(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id=None,
    )
    try:
        store = SqliteSettlementCaptureStore(runtime)
        created = _start(
            store,
            target_kind=ShadowBatchTargetKind.OPERATIONAL_COMPAT,
            key="start-operational-compat",
            duration_minutes=720,
        )

        assert (
            created.access_window.purpose
            is AccessPurpose.PRODUCTION_SHADOW
        )
        assert created.invocation.status == "collecting"
        assert created.invocation.scope == "current"
        assert created.invocation.page_size == 50
        assert (
            created.access_window.expires_at
            - created.access_window.issued_at
            == timedelta(hours=12)
        )
        assert (
            store.target_kind(created.invocation.invocation_id)
            is ShadowBatchTargetKind.OPERATIONAL_COMPAT
        )
        assert (
            repository.get_job(created.job_id).run_mode == "operational"
        )
    finally:
        repository.close()


def test_atomic_start_rejects_changed_replay_and_short_window(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        store = SqliteSettlementCaptureStore(runtime)
        _start(store)
        with pytest.raises(IdempotencyConflictError):
            _start(
                store,
                request_hash=hashlib.sha256(b"changed").hexdigest(),
            )
        with pytest.raises(
            SettlementCaptureStoreConflictError,
            match="60 and 120",
        ):
            store.create_start(
                target_kind=ShadowBatchTargetKind.REAL_SHADOW_30,
                session_id="chengfeng-shadow-v1",
                source_build_sha256=BUILD_SHA,
                contract_canonical_sha256=CONTRACT_SHA,
                contract_file_sha256=CONTRACT_FILE_SHA,
                contract_selection_sha256=CONTRACT_SELECTION_SHA,
                identity_context_sha256=IDENTITY_CONTEXT_SHA,
                duration_minutes=59,
                legacy_idle_confirmed=True,
                no_settlement_or_payment_confirmed=True,
                same_account_session_risk_accepted=True,
                idempotency_key="short-window",
                request_hash=hashlib.sha256(b"short").hexdigest(),
                now=NOW,
            )
    finally:
        runtime.close()


def test_scheduler_cannot_claim_capture_until_browser_is_ready_and_idle(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    calls: list[SettlementCaptureStageWork] = []

    def execute(
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        calls.append(work)
        return SettlementCaptureStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="retry",
            completed_stage=SETTLEMENT_CAPTURE_STAGE,
            next_stage=SETTLEMENT_CAPTURE_STAGE,
            platform_read_performed=False,
            checkpoint_revision=None,
            manifest_sha256=None,
            diagnostic_code="TEST-RETRY",
        )

    backend = AsyncSettlementCaptureExecutionBackend(execute=execute)
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id=None,
        settlement_capture_execution_backend=backend,
    )
    try:
        control = BrowserControlStore(
            runtime.engine,
            runtime.commit_gate,
        )
        initial = control.initialize(
            session_id="chengfeng-shadow-v1",
            now=NOW,
        )
        created = _start(SqliteSettlementCaptureStore(runtime))
        scheduler = CooperativeScheduler(repository)

        scheduler.tick()
        assert calls == []
        assert repository.get_job(created.job_id).status.value in {
            "queued",
            "waiting_resource",
        }

        control.mark_ready(
            session_id=initial.session_id,
            expected_record_version=initial.record_version,
            now=NOW,
        )
        for _ in range(30):
            scheduler.tick()
            if calls:
                break
            time.sleep(0.002)
        assert len(calls) == 1
    finally:
        repository.close()


def test_cancelled_capture_retires_its_access_window_after_commit(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    access = SqlitePlatformAccessRepository(runtime)
    cleanup_calls: list[str] = []

    def execute(
        work: SettlementCaptureStageWork,
    ) -> SettlementCaptureStageExecution:
        raise AssertionError(
            f"cancelled capture must not execute: {work.stage_attempt_id}"
        )

    def retire(job_id: str) -> None:
        cleanup_calls.append(job_id)
        SqliteSettlementCaptureStore(runtime).retire_terminal_access(
            job_id=job_id,
            now=NOW,
        )

    backend = AsyncSettlementCaptureExecutionBackend(
        execute=execute,
        reconcile_terminal=retire,
    )
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id=None,
        settlement_capture_execution_backend=backend,
    )
    try:
        created = _start(SqliteSettlementCaptureStore(runtime))
        requested, replayed = repository.request_job_control(
            job_id=created.job_id,
            action="cancel",
            expected_record_version=1,
            idempotency_key="cancel-settlement-capture",
            request_hash=hashlib.sha256(
                b"cancel-settlement-capture"
            ).hexdigest(),
        )
        assert replayed is False
        assert requested.status.value == "cancel_requested"

        CooperativeScheduler(repository).tick()

        assert repository.get_job(created.job_id).status.value == "cancelled"
        assert cleanup_calls == [created.job_id]
        assert (
            access.get(created.access_window.access_window_id).consumed_at
            is not None
        )
    finally:
        repository.close()


def test_restart_reconciles_persisted_terminal_capture_window(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    first = SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id="loop9-start-before-restart",
    )
    created = _start(SqliteSettlementCaptureStore(first))
    with first.commit_gate.transaction(first.engine) as connection:
        connection.execute(
            update(JOBS)
            .where(JOBS.c.job_id == created.job_id)
            .values(status="cancelled", record_version=2)
        )
    first.close()

    restarted = SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id="loop9-start-after-restart",
    )
    try:
        store = SqliteSettlementCaptureStore(restarted)
        assert store.reconcile_terminal_or_expired_access(now=NOW) == (
            created.job_id,
        )
        access = SqlitePlatformAccessRepository(restarted)
        assert (
            access.get(created.access_window.access_window_id).consumed_at
            == NOW
        )
        assert store.reconcile_terminal_or_expired_access(now=NOW) == ()
    finally:
        restarted.close()
