from __future__ import annotations

from sqlalchemy.engine import Engine

from dahe.adapters.sqlite.loop3_job_store import SqliteLoop3JobStore
from dahe.adapters.sqlite.loop3_query_store import SqliteLoop3QueryStore
from dahe.adapters.sqlite.loop3_resource_store import SqliteLoop3ResourceStore
from dahe.adapters.sqlite.loop3_scheduler_store import SqliteLoop3SchedulerStore
from dahe.adapters.sqlite.loop3_support import AppendEvent, GetJob
from dahe.adapters.sqlite.loop4_recovery_store import (
    SharedWorkRetryResult,
    SqliteLoop4RecoveryStore,
)
from dahe.adapters.sqlite.runtime import ShortTransactionCommitGate
from dahe.jobs.audit_execution import LocalAuditEvaluator
from dahe.jobs.daily_execution import AsyncDailyExecutionBackend
from dahe.jobs.models import JobRecord
from dahe.jobs.ocr_execution import AsyncOcrExecutionBackend
from dahe.jobs.settlement_capture_execution import (
    AsyncSettlementCaptureExecutionBackend,
)
from dahe.jobs.specs import ScheduledJobSpec


class SqliteLoop3Store:
    """Explicit composition facade for Loop 3 persistence responsibilities."""

    def __init__(
        self,
        engine: Engine,
        commit_gate: ShortTransactionCommitGate,
        get_job: GetJob,
        append_event: AppendEvent,
        *,
        instance_id: str | None,
        ocr_execution_backend: AsyncOcrExecutionBackend | None = None,
        daily_execution_backend: AsyncDailyExecutionBackend | None = None,
        settlement_capture_execution_backend: (
            AsyncSettlementCaptureExecutionBackend | None
        ) = None,
        local_audit_evaluator: LocalAuditEvaluator | None = None,
    ) -> None:
        self._jobs = SqliteLoop3JobStore(
            engine,
            commit_gate,
            get_job,
            append_event,
        )
        self._queries = SqliteLoop3QueryStore(engine)
        self._resources = SqliteLoop3ResourceStore(
            engine,
            append_event,
            instance_id=instance_id,
            ocr_execution_backend=ocr_execution_backend,
            daily_execution_enabled=daily_execution_backend is not None,
            settlement_capture_execution_enabled=(
                settlement_capture_execution_backend is not None
            ),
        )
        self._scheduler = SqliteLoop3SchedulerStore(
            engine,
            commit_gate,
            append_event,
            self._resources,
            ocr_execution_backend=ocr_execution_backend,
            daily_execution_backend=daily_execution_backend,
            settlement_capture_execution_backend=(
                settlement_capture_execution_backend
            ),
            local_audit_evaluator=local_audit_evaluator,
        )
        self._recovery = SqliteLoop4RecoveryStore(engine, commit_gate)
        self._ocr_execution_backend = ocr_execution_backend
        self._daily_execution_backend = daily_execution_backend
        self._settlement_capture_execution_backend = (
            settlement_capture_execution_backend
        )

    def close(self) -> None:
        first_failure: BaseException | None = None
        for backend in (
            self._ocr_execution_backend,
            self._daily_execution_backend,
            self._settlement_capture_execution_backend,
        ):
            if backend is None:
                continue
            try:
                backend.close()
            except BaseException as exc:
                if first_failure is None:
                    first_failure = exc
        if first_failure is not None:
            raise first_failure

    def create_scheduled_job(
        self,
        *,
        fixture: ScheduledJobSpec,
        scope_label: str,
        idempotency_key: str,
        request_hash: str,
        expected_record_version: int,
    ) -> tuple[JobRecord, bool]:
        return self._jobs.create_scheduled_job(
            fixture=fixture,
            scope_label=scope_label,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            expected_record_version=expected_record_version,
        )

    def fixture_start_state(self, conflict_key: str) -> tuple[bool, int]:
        return self._jobs.fixture_start_state(conflict_key)

    def link_active_scheduled_job(
        self,
        *,
        conflict_key: str,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        return self._jobs.link_active_scheduled_job(
            conflict_key=conflict_key,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )

    def request_job_control(
        self,
        *,
        job_id: str,
        action: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        return self._jobs.request_job_control(
            job_id=job_id,
            action=action,
            expected_record_version=expected_record_version,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )

    def list_stage_attempts(self) -> list[dict[str, object]]:
        return self._queries.list_stage_attempts()

    def count_stage_attempts(self, *, job_id: str, stage: str) -> int:
        return self._queries.count_stage_attempts(job_id=job_id, stage=stage)

    def list_shared_evidence_work(self) -> list[dict[str, object]]:
        return self._queries.list_shared_evidence_work()

    def scheduler_tick(self, failure_image_hashes: set[str]) -> bool:
        return self._scheduler.scheduler_tick(failure_image_hashes)

    def has_automatic_work(self) -> bool:
        return self._resources.has_automatic_work()

    def automatic_poll_interval_seconds(self) -> float:
        return self._resources.automatic_poll_interval_seconds()

    def maintain_automatic_work(self) -> bool:
        return self._scheduler.maintain_automatic_work()

    def runtime_projection(self, job_id: str) -> dict[str, object]:
        return self._queries.runtime_projection(job_id)

    def resources_projection(self) -> list[dict[str, object]]:
        return self._queries.resources_projection()

    def recover_abandoned_attempts(self, *, recovering_instance_id: str) -> int:
        return self._recovery.recover_abandoned_attempts(
            recovering_instance_id=recovering_instance_id
        )

    def abandon_instance_attempts(self, *, instance_id: str) -> int:
        return self._recovery.abandon_instance_attempts(instance_id=instance_id)

    def propagate_shared_failure_once(
        self,
        *,
        shared_work_id: str,
        diagnostic_code: str,
    ) -> int:
        return self._recovery.propagate_shared_failure_once(
            shared_work_id=shared_work_id,
            diagnostic_code=diagnostic_code,
        )

    def safe_retry_shared_work(
        self,
        *,
        shared_work_id: str,
        expected_record_version: int,
        idempotency_key: str,
    ) -> SharedWorkRetryResult:
        return self._recovery.safe_retry_shared_work(
            shared_work_id=shared_work_id,
            expected_record_version=expected_record_version,
            idempotency_key=idempotency_key,
        )
