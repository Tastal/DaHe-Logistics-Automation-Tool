from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.engine import Connection, RowMapping

from dahe.adapters.sqlite.loop3_repository import SqliteLoop3Store
from dahe.adapters.sqlite.loop4_recovery_store import SharedWorkRetryResult
from dahe.adapters.sqlite.runtime import DatabaseMigrationError, SqliteRuntime
from dahe.adapters.sqlite.schema import (
    IDEMPOTENCY_RECORDS,
    JOBS,
    OUTBOX,
    WORK_ITEMS,
)
from dahe.jobs.audit_execution import LocalAuditEvaluator
from dahe.jobs.daily_execution import AsyncDailyExecutionBackend
from dahe.jobs.models import JobRecord, JobStatus, WorkItemRecord, WorkItemStatus
from dahe.jobs.ocr_execution import AsyncOcrExecutionBackend
from dahe.jobs.settlement_capture_execution import (
    AsyncSettlementCaptureExecutionBackend,
)
from dahe.jobs.specs import ScheduledJobSpec
from dahe.ports.jobs import (
    ActiveScopeConflictError,
    IdempotencyConflictError,
    JobNotFoundError,
)

ACTIVE_STATUSES = tuple(
    status.value
    for status in JobStatus
    if status not in {JobStatus.CANCELLED, JobStatus.SUCCEEDED, JobStatus.FAILED}
)
TemporarySchemaMismatchError = DatabaseMigrationError


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _scope_fingerprint(task_type: str, fixture_id: str) -> str:
    return hashlib.sha256(f"{task_type}:{fixture_id}".encode()).hexdigest()


def _job_from_row(row: RowMapping) -> JobRecord:
    return JobRecord(
        job_id=str(row["job_id"]),
        task_type=str(row["task_type"]),
        scope_label=str(row["scope_label"]),
        scope_fixture_id=str(row["scope_fixture_id"]),
        scope_fingerprint=str(row["scope_fingerprint"]),
        run_mode=str(row["run_mode"]),
        status=JobStatus(str(row["status"])),
        current_stage=(None if row["current_stage"] is None else str(row["current_stage"])),
        diagnostic_code=(None if row["diagnostic_code"] is None else str(row["diagnostic_code"])),
        record_version=int(row["record_version"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
        job_kind=str(row["job_kind"]),
        conflict_key=(None if row["conflict_key"] is None else str(row["conflict_key"])),
        created_sequence=int(row["created_sequence"]),
    )


def _item_from_row(row: RowMapping) -> WorkItemRecord:
    return WorkItemRecord(
        work_item_id=str(row["work_item_id"]),
        job_id=str(row["job_id"]),
        record_version=int(row["record_version"]),
        waybill_number=str(row["waybill_number"]),
        vehicle_number=str(row["vehicle_number"]),
        status=WorkItemStatus(str(row["status"])),
        current_stage=str(row["current_stage"]),
        business_outcome=(
            None if row["business_outcome"] is None else str(row["business_outcome"])
        ),
        platform_loading_net=(
            None if row["platform_loading_net"] is None else str(row["platform_loading_net"])
        ),
        platform_unloading_net=(
            None if row["platform_unloading_net"] is None else str(row["platform_unloading_net"])
        ),
        ticket_loading_net=(
            None if row["ticket_loading_net"] is None else str(row["ticket_loading_net"])
        ),
        ticket_unloading_net=(
            None if row["ticket_unloading_net"] is None else str(row["ticket_unloading_net"])
        ),
        decision=None if row["decision"] is None else str(row["decision"]),
        review_reason=(None if row["review_reason"] is None else str(row["review_reason"])),
        item_index=int(row["item_index"]),
        end_reason=None if row["end_reason"] is None else str(row["end_reason"]),
        waiting_reason_kind=(
            None if row["waiting_reason_kind"] is None else str(row["waiting_reason_kind"])
        ),
        waiting_reason=(None if row["waiting_reason"] is None else str(row["waiting_reason"])),
        attempt_count=int(row["attempt_count"]),
        diagnostic_code=(None if row["diagnostic_code"] is None else str(row["diagnostic_code"])),
        loading_image_sha256=(
            None if row["loading_image_sha256"] is None else str(row["loading_image_sha256"])
        ),
        unloading_image_sha256=(
            None if row["unloading_image_sha256"] is None else str(row["unloading_image_sha256"])
        ),
        pipeline_fingerprint=(
            None if row["pipeline_fingerprint"] is None else str(row["pipeline_fingerprint"])
        ),
        fixture_outcome=(None if row["fixture_outcome"] is None else str(row["fixture_outcome"])),
        fixture_review_reason=(
            None if row["fixture_review_reason"] is None else str(row["fixture_review_reason"])
        ),
        download_complete=bool(row["download_complete"]),
        loading_ocr_complete=bool(row["loading_ocr_complete"]),
        unloading_ocr_complete=bool(row["unloading_ocr_complete"]),
        ready_sequence=int(row["ready_sequence"]),
        loading_image_relative_path=(
            None
            if row["loading_image_relative_path"] is None
            else str(row["loading_image_relative_path"])
        ),
        unloading_image_relative_path=(
            None
            if row["unloading_image_relative_path"] is None
            else str(row["unloading_image_relative_path"])
        ),
        ocr_generation_id=(
            None
            if row["ocr_generation_id"] is None
            else str(row["ocr_generation_id"])
        ),
    )


class SqliteJobRepository:
    """Durable Alembic-managed repository for task and audit state."""

    def __init__(
        self,
        runtime: SqliteRuntime,
        *,
        scheduler_instance_id: str | None,
        ocr_execution_backend: AsyncOcrExecutionBackend | None = None,
        daily_execution_backend: AsyncDailyExecutionBackend | None = None,
        settlement_capture_execution_backend: (
            AsyncSettlementCaptureExecutionBackend | None
        ) = None,
        local_audit_evaluator: LocalAuditEvaluator | None = None,
    ) -> None:
        self.instance_id = runtime.instance_id
        self.scheduler_instance_id = scheduler_instance_id
        self.project_root = runtime.project_root
        self._runtime = runtime
        self.database_path = self._runtime.database_path
        self.engine = self._runtime.engine
        self.commit_gate = self._runtime.commit_gate
        self._loop3 = SqliteLoop3Store(
            self.engine,
            self.commit_gate,
            self._get_job,
            self._append_event,
            instance_id=scheduler_instance_id,
            ocr_execution_backend=ocr_execution_backend,
            daily_execution_backend=daily_execution_backend,
            settlement_capture_execution_backend=(
                settlement_capture_execution_backend
            ),
            local_audit_evaluator=local_audit_evaluator,
        )

    def close(self) -> None:
        try:
            self._loop3.close()
        finally:
            self._runtime.close()

    def stop_ocr_execution(self) -> None:
        """Stop owned OCR workers before fencing uncommitted stage attempts."""
        self._loop3.close()

    def create_job(
        self,
        *,
        task_type: str,
        scope_label: str,
        scope_fixture_id: str,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        operation = "POST:/api/v1/jobs"
        now = _utc_now()
        with self.commit_gate.transaction(self.engine) as connection:
            replay = (
                connection.execute(
                    select(IDEMPOTENCY_RECORDS).where(
                        IDEMPOTENCY_RECORDS.c.operation == operation,
                        IDEMPOTENCY_RECORDS.c.idempotency_key == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if replay["request_hash"] != request_hash:
                    raise IdempotencyConflictError(
                        "the idempotency key belongs to a different request"
                    )
                return self._get_job(connection, str(replay["job_id"])), False

            active = connection.execute(
                select(JOBS.c.job_id).where(
                    JOBS.c.task_type == task_type,
                    JOBS.c.scope_fixture_id == scope_fixture_id,
                    JOBS.c.status.in_(ACTIVE_STATUSES),
                )
            ).first()
            if active is not None:
                raise ActiveScopeConflictError("an active audit job already owns this scope")

            job_id = uuid4().hex
            work_item_id = uuid4().hex
            fingerprint = _scope_fingerprint(task_type, scope_fixture_id)
            connection.execute(
                JOBS.insert().values(
                    job_id=job_id,
                    task_type=task_type,
                    scope_label=scope_label,
                    scope_fixture_id=scope_fixture_id,
                    scope_fingerprint=fingerprint,
                    run_mode="shadow",
                    status=JobStatus.QUEUED.value,
                    current_stage="audit.acquire_list",
                    record_version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                WORK_ITEMS.insert().values(
                    work_item_id=work_item_id,
                    job_id=job_id,
                    record_version=1,
                    waybill_number="待获取",
                    vehicle_number="待获取",
                    status=WorkItemStatus.QUEUED.value,
                    current_stage="audit.acquire_list",
                )
            )
            connection.execute(
                IDEMPOTENCY_RECORDS.insert().values(
                    operation=operation,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    job_id=job_id,
                    created_at=now,
                )
            )
            self._append_event(
                connection,
                event_type="job.queued",
                aggregate_id=job_id,
                record_version=1,
                payload={"job_id": job_id, "job_status": JobStatus.QUEUED.value},
                created_at=now,
            )
            return self._get_job(connection, job_id), True

    def _get_job(self, connection: Connection, job_id: str) -> JobRecord:
        row = (
            connection.execute(select(JOBS).where(JOBS.c.job_id == job_id)).mappings().one_or_none()
        )
        if row is None:
            raise JobNotFoundError(job_id)
        return _job_from_row(row)

    def get_job(self, job_id: str) -> JobRecord:
        with self.engine.connect() as connection:
            return self._get_job(connection, job_id)

    def list_jobs(self) -> Sequence[JobRecord]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(JOBS).order_by(JOBS.c.created_at, JOBS.c.job_id)
            ).mappings()
            return tuple(_job_from_row(row) for row in rows)

    def snapshot(
        self,
    ) -> tuple[tuple[tuple[JobRecord, tuple[WorkItemRecord, ...]], ...], int]:
        """Read the event cursor and matching projections from one DB snapshot."""
        with self.engine.connect() as connection, connection.begin():
            cursor_value = connection.execute(select(func.max(OUTBOX.c.event_id))).scalar_one()
            job_rows = tuple(
                connection.execute(
                    select(JOBS).order_by(JOBS.c.created_at, JOBS.c.job_id)
                ).mappings()
            )
            item_rows = tuple(
                connection.execute(
                    select(WORK_ITEMS).order_by(
                        WORK_ITEMS.c.job_id,
                        WORK_ITEMS.c.item_index,
                        WORK_ITEMS.c.work_item_id,
                    )
                ).mappings()
            )
            items_by_job: dict[str, list[WorkItemRecord]] = {}
            for row in item_rows:
                item = _item_from_row(row)
                items_by_job.setdefault(item.job_id, []).append(item)
            bundles = tuple(
                (
                    _job_from_row(row),
                    tuple(items_by_job.get(str(row["job_id"]), ())),
                )
                for row in job_rows
            )
            return bundles, int(cursor_value or 0)

    def list_jobs_with_status(self, status: JobStatus) -> Sequence[JobRecord]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(JOBS)
                .where(JOBS.c.status == status.value)
                .order_by(JOBS.c.created_at, JOBS.c.job_id)
            ).mappings()
            return tuple(_job_from_row(row) for row in rows)

    def list_items(self, job_id: str) -> Sequence[WorkItemRecord]:
        with self.engine.connect() as connection:
            if (
                connection.execute(select(JOBS.c.job_id).where(JOBS.c.job_id == job_id)).first()
                is None
            ):
                raise JobNotFoundError(job_id)
            rows = connection.execute(
                select(WORK_ITEMS)
                .where(WORK_ITEMS.c.job_id == job_id)
                .order_by(WORK_ITEMS.c.item_index, WORK_ITEMS.c.work_item_id)
            ).mappings()
            return tuple(_item_from_row(row) for row in rows)

    def has_active_scope(self, fixture_id: str) -> bool:
        with self.engine.connect() as connection:
            return (
                connection.execute(
                    select(JOBS.c.job_id).where(
                        JOBS.c.task_type == "audit",
                        JOBS.c.scope_fixture_id == fixture_id,
                        JOBS.c.status.in_(ACTIVE_STATUSES),
                    )
                ).first()
                is not None
            )

    def transition(
        self,
        job_id: str,
        *,
        status: JobStatus,
        current_stage: str,
        work_item_status: WorkItemStatus,
        waybill_number: str | None = None,
        vehicle_number: str | None = None,
    ) -> JobRecord:
        now = _utc_now()
        with self.commit_gate.transaction(self.engine) as connection:
            job = self._get_job(connection, job_id)
            item_row = (
                connection.execute(select(WORK_ITEMS).where(WORK_ITEMS.c.job_id == job_id))
                .mappings()
                .one()
            )
            job_version = job.record_version + 1
            item_version = int(item_row["record_version"]) + 1
            job_result = connection.execute(
                update(JOBS)
                .where(
                    JOBS.c.job_id == job_id,
                    JOBS.c.record_version == job.record_version,
                )
                .values(
                    status=status.value,
                    current_stage=current_stage,
                    record_version=job_version,
                    updated_at=now,
                )
            )
            if job_result.rowcount != 1:
                raise RuntimeError("stale job transition")
            item_values: dict[str, object] = {
                "status": work_item_status.value,
                "current_stage": current_stage,
                "record_version": item_version,
            }
            if waybill_number is not None:
                item_values["waybill_number"] = waybill_number
            if vehicle_number is not None:
                item_values["vehicle_number"] = vehicle_number
            item_result = connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == item_row["work_item_id"],
                    WORK_ITEMS.c.record_version == item_row["record_version"],
                )
                .values(**item_values)
            )
            if item_result.rowcount != 1:
                raise RuntimeError("stale work item transition")
            self._append_event(
                connection,
                event_type="job.changed",
                aggregate_id=job_id,
                record_version=job_version,
                payload={
                    "job_id": job_id,
                    "job_status": status.value,
                    "current_stage": current_stage,
                },
                created_at=now,
            )
            return self._get_job(connection, job_id)

    def complete_normal(
        self,
        job_id: str,
        *,
        platform_loading_net: str,
        platform_unloading_net: str,
        ticket_loading_net: str,
        ticket_unloading_net: str,
        decision: str,
        business_outcome: str,
    ) -> JobRecord:
        now = _utc_now()
        with self.commit_gate.transaction(self.engine) as connection:
            job = self._get_job(connection, job_id)
            item_row = (
                connection.execute(select(WORK_ITEMS).where(WORK_ITEMS.c.job_id == job_id))
                .mappings()
                .one()
            )
            job_version = job.record_version + 1
            item_version = int(item_row["record_version"]) + 1
            job_result = connection.execute(
                update(JOBS)
                .where(
                    JOBS.c.job_id == job_id,
                    JOBS.c.record_version == job.record_version,
                )
                .values(
                    status=JobStatus.SUCCEEDED.value,
                    current_stage="audit.finalize",
                    record_version=job_version,
                    updated_at=now,
                )
            )
            if job_result.rowcount != 1:
                raise RuntimeError("stale job completion")
            item_result = connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == item_row["work_item_id"],
                    WORK_ITEMS.c.record_version == item_row["record_version"],
                )
                .values(
                    record_version=item_version,
                    status=WorkItemStatus.SUCCEEDED.value,
                    current_stage="audit.finalize",
                    business_outcome=business_outcome,
                    platform_loading_net=platform_loading_net,
                    platform_unloading_net=platform_unloading_net,
                    ticket_loading_net=ticket_loading_net,
                    ticket_unloading_net=ticket_unloading_net,
                    decision=decision,
                    review_reason=None,
                )
            )
            if item_result.rowcount != 1:
                raise RuntimeError("stale work item completion")
            self._append_event(
                connection,
                event_type="job.succeeded",
                aggregate_id=job_id,
                record_version=job_version,
                payload={
                    "job_id": job_id,
                    "job_status": JobStatus.SUCCEEDED.value,
                    "business_outcome": business_outcome,
                },
                created_at=now,
            )
            return self._get_job(connection, job_id)

    def fail_job(self, job_id: str, diagnostic_code: str) -> JobRecord:
        now = _utc_now()
        with self.commit_gate.transaction(self.engine) as connection:
            job = self._get_job(connection, job_id)
            item_row = (
                connection.execute(select(WORK_ITEMS).where(WORK_ITEMS.c.job_id == job_id))
                .mappings()
                .one()
            )
            job_version = job.record_version + 1
            item_version = int(item_row["record_version"]) + 1
            job_result = connection.execute(
                update(JOBS)
                .where(
                    JOBS.c.job_id == job_id,
                    JOBS.c.record_version == job.record_version,
                )
                .values(
                    status=JobStatus.FAILED.value,
                    diagnostic_code=diagnostic_code,
                    record_version=job_version,
                    updated_at=now,
                )
            )
            if job_result.rowcount != 1:
                raise RuntimeError("stale job failure")
            item_result = connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == item_row["work_item_id"],
                    WORK_ITEMS.c.record_version == item_row["record_version"],
                )
                .values(
                    status=WorkItemStatus.FAILED.value,
                    record_version=item_version,
                    review_reason=None,
                )
            )
            if item_result.rowcount != 1:
                raise RuntimeError("stale work item failure")
            self._append_event(
                connection,
                event_type="job.failed",
                aggregate_id=job_id,
                record_version=job_version,
                payload={
                    "job_id": job_id,
                    "job_status": JobStatus.FAILED.value,
                    "diagnostic_code": diagnostic_code,
                },
                created_at=now,
            )
            return self._get_job(connection, job_id)

    def create_scheduled_job(
        self,
        *,
        fixture: ScheduledJobSpec,
        scope_label: str,
        idempotency_key: str,
        request_hash: str,
        expected_record_version: int,
    ) -> tuple[JobRecord, bool]:
        return self._loop3.create_scheduled_job(
            fixture=fixture,
            scope_label=scope_label,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
            expected_record_version=expected_record_version,
        )

    def active_job_for_conflict_key(
        self,
        conflict_key: str,
    ) -> JobRecord | None:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(JOBS)
                    .where(
                        JOBS.c.conflict_key == conflict_key,
                        JOBS.c.status.in_(ACTIVE_STATUSES),
                    )
                    .order_by(JOBS.c.created_sequence.desc())
                    .limit(1)
                )
                .mappings()
                .one_or_none()
            )
        return None if row is None else _job_from_row(row)

    def fixture_start_state(self, conflict_key: str) -> tuple[bool, int]:
        return self._loop3.fixture_start_state(conflict_key)

    def link_active_scheduled_job(
        self,
        *,
        conflict_key: str,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        return self._loop3.link_active_scheduled_job(
            conflict_key=conflict_key,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )

    def resume_platform_waiting_job(
        self,
        *,
        job_id: str,
        allowed_diagnostic_codes: frozenset[str],
    ) -> JobRecord:
        """Resume only a platform job paused for reviewed login reasons."""

        now = _utc_now()
        with self.commit_gate.transaction(self.engine) as connection:
            job = self._get_job(connection, job_id)
            waiting_item_diagnostics = {
                str(value)
                for value in connection.execute(
                    select(WORK_ITEMS.c.diagnostic_code).where(
                        WORK_ITEMS.c.job_id == job_id,
                        WORK_ITEMS.c.status
                        == WorkItemStatus.WAITING_EXTERNAL.value,
                        WORK_ITEMS.c.diagnostic_code.is_not(None),
                    )
                ).scalars()
            }
            effective_diagnostic = job.diagnostic_code
            if effective_diagnostic is None and len(
                waiting_item_diagnostics
            ) == 1:
                effective_diagnostic = next(iter(waiting_item_diagnostics))
            if (
                job.status
                not in {JobStatus.PAUSED, JobStatus.WAITING_EXTERNAL}
                or effective_diagnostic not in allowed_diagnostic_codes
            ):
                return job
            next_version = job.record_version + 1
            result = connection.execute(
                update(JOBS)
                .where(
                    JOBS.c.job_id == job_id,
                    JOBS.c.record_version == job.record_version,
                )
                .values(
                    status=JobStatus.QUEUED.value,
                    diagnostic_code=None,
                    record_version=next_version,
                    updated_at=now,
                )
            )
            if result.rowcount != 1:
                return self._get_job(connection, job_id)
            connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.job_id == job_id,
                    WORK_ITEMS.c.status
                    == WorkItemStatus.WAITING_EXTERNAL.value,
                )
                .values(
                    status=WorkItemStatus.QUEUED.value,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    diagnostic_code=None,
                    record_version=WORK_ITEMS.c.record_version + 1,
                )
            )
            self._append_event(
                connection,
                event_type="job.external_wait_resolved",
                aggregate_id=job_id,
                record_version=next_version,
                payload={"status": JobStatus.QUEUED.value},
                created_at=now,
            )
            return self._get_job(connection, job_id)

    def request_job_control(
        self,
        *,
        job_id: str,
        action: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        return self._loop3.request_job_control(
            job_id=job_id,
            action=action,
            expected_record_version=expected_record_version,
            idempotency_key=idempotency_key,
            request_hash=request_hash,
        )

    def list_stage_attempts(self) -> list[dict[str, object]]:
        return self._loop3.list_stage_attempts()

    def count_stage_attempts(self, *, job_id: str, stage: str) -> int:
        return self._loop3.count_stage_attempts(job_id=job_id, stage=stage)

    def list_shared_evidence_work(self) -> list[dict[str, object]]:
        return self._loop3.list_shared_evidence_work()

    def scheduler_tick(self, failure_image_hashes: set[str]) -> bool:
        if self.scheduler_instance_id is not None:
            self.recover_abandoned_attempts(recovering_instance_id=self.scheduler_instance_id)
        return self._loop3.scheduler_tick(failure_image_hashes)

    def has_automatic_work(self) -> bool:
        return self._loop3.has_automatic_work()

    def automatic_poll_interval_seconds(self) -> float:
        return self._loop3.automatic_poll_interval_seconds()

    def maintain_automatic_work(self) -> bool:
        return self._loop3.maintain_automatic_work()

    def runtime_projection(self, job_id: str) -> dict[str, object]:
        return self._loop3.runtime_projection(job_id)

    def resources_projection(self) -> list[dict[str, object]]:
        return self._loop3.resources_projection()

    def recover_abandoned_attempts(self, *, recovering_instance_id: str) -> int:
        return self._loop3.recover_abandoned_attempts(recovering_instance_id=recovering_instance_id)

    def abandon_instance_attempts(self, *, instance_id: str) -> int:
        return self._loop3.abandon_instance_attempts(instance_id=instance_id)

    def propagate_shared_failure_once(
        self,
        *,
        shared_work_id: str,
        diagnostic_code: str,
    ) -> int:
        return self._loop3.propagate_shared_failure_once(
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
        return self._loop3.safe_retry_shared_work(
            shared_work_id=shared_work_id,
            expected_record_version=expected_record_version,
            idempotency_key=idempotency_key,
        )

    @staticmethod
    def _append_event(
        connection: Connection,
        *,
        event_type: str,
        aggregate_id: str,
        record_version: int,
        payload: dict[str, object],
        created_at: str,
        aggregate_type: str = "job",
    ) -> None:
        connection.execute(
            OUTBOX.insert().values(
                event_type=event_type,
                aggregate_type=aggregate_type,
                aggregate_id=aggregate_id,
                record_version=record_version,
                payload_json=json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                created_at=created_at,
            )
        )

    def event_cursor(self) -> int:
        with self.engine.connect() as connection:
            value = connection.execute(select(func.max(OUTBOX.c.event_id))).scalar_one()
            return int(value or 0)

    def events_after(self, cursor: int, limit: int = 100) -> list[dict[str, object]]:
        with self.engine.connect() as connection:
            rows = connection.execute(
                select(OUTBOX)
                .where(OUTBOX.c.event_id > cursor)
                .order_by(OUTBOX.c.event_id)
                .limit(limit)
            ).mappings()
            return [
                {
                    "event_id": int(row["event_id"]),
                    "event_type": str(row["event_type"]),
                    "aggregate_type": str(row["aggregate_type"]),
                    "aggregate_id": str(row["aggregate_id"]),
                    "record_version": int(row["record_version"]),
                    "payload": json.loads(str(row["payload_json"])),
                    "created_at": str(row["created_at"]),
                }
                for row in rows
            ]


class TemporarySqliteJobRepository(SqliteJobRepository):
    """Compatibility constructor backed by the same durable repository and schema."""

    def __init__(
        self,
        data_root: Path,
        *,
        project_root: Path | None = None,
        instance_id: str | None = None,
        scheduler_instance_id: str | None = None,
        ocr_execution_backend: AsyncOcrExecutionBackend | None = None,
        settlement_capture_execution_backend: (
            AsyncSettlementCaptureExecutionBackend | None
        ) = None,
        local_audit_evaluator: LocalAuditEvaluator | None = None,
    ) -> None:
        resolved_project_root = (
            Path(__file__).resolve().parents[4] if project_root is None else project_root.resolve()
        )
        super().__init__(
            SqliteRuntime(
                data_root=data_root,
                project_root=resolved_project_root,
                instance_id=instance_id or f"repository-{uuid4().hex}",
            ),
            scheduler_instance_id=scheduler_instance_id,
            ocr_execution_backend=ocr_execution_backend,
            settlement_capture_execution_backend=(
                settlement_capture_execution_backend
            ),
            local_audit_evaluator=local_audit_evaluator,
        )
