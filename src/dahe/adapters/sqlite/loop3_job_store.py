from __future__ import annotations

import hashlib
from dataclasses import replace
from datetime import UTC, datetime
from threading import Lock
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.engine import Connection, Engine

from dahe.adapters.sqlite.loop3_support import AppendEvent, GetJob, next_sequence
from dahe.adapters.sqlite.runtime import ShortTransactionCommitGate
from dahe.adapters.sqlite.schema import (
    CONFLICT_KEYS,
    CONTROL_IDEMPOTENCY,
    IDEMPOTENCY_RECORDS,
    JOBS,
    SHARED_EVIDENCE_CONSUMERS,
    SHARED_EVIDENCE_WORK,
    WORK_ITEMS,
)
from dahe.jobs.models import JobRecord, JobStatus, WorkItemStatus
from dahe.jobs.shared_evidence import shared_evidence_fingerprint
from dahe.jobs.specs import ScheduledJobSpec
from dahe.ports.jobs import (
    ActiveScopeConflictError,
    IdempotencyConflictError,
    JobControlError,
    RecordVersionConflictError,
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _scope_fingerprint(task_type: str, fixture_id: str) -> str:
    return hashlib.sha256(f"{task_type}:{fixture_id}".encode()).hexdigest()


def _initial_stage(task_type: str) -> str:
    if task_type == "loading_probe":
        return "loading_probe.query"
    if task_type == "daily":
        return "daily.list_page"
    if task_type == "settlement_capture":
        return "settlement_capture.read"
    return "audit.download_evidence"


def register_shared_consumer(
    connection: Connection,
    *,
    work_item_id: str,
    image_role: str,
    image_sha256: str,
    pipeline_fingerprint: str,
    execution_mode: str,
    image_relative_path: str | None = None,
    runtime_kind: str | None = None,
    profile_id: str | None = None,
    runtime_fingerprint: str | None = None,
) -> str | None:
    """Register one consumer against one immutable image/pipeline identity."""
    item_status = connection.execute(
        select(WORK_ITEMS.c.status).where(WORK_ITEMS.c.work_item_id == work_item_id)
    ).scalar_one()
    if WorkItemStatus(str(item_status)).is_terminal:
        return None
    fingerprint = shared_evidence_fingerprint(
        image_sha256,
        pipeline_fingerprint,
    )
    row = (
        connection.execute(
            select(SHARED_EVIDENCE_WORK).where(
                SHARED_EVIDENCE_WORK.c.fingerprint == fingerprint
            )
        )
        .mappings()
        .one_or_none()
    )
    expected_identity = (
        execution_mode,
        image_sha256,
        pipeline_fingerprint,
        runtime_kind,
        profile_id,
        runtime_fingerprint,
    )
    if row is None:
        shared_work_id = uuid4().hex
        connection.execute(
            SHARED_EVIDENCE_WORK.insert().values(
                shared_work_id=shared_work_id,
                fingerprint=fingerprint,
                image_sha256=image_sha256,
                pipeline_fingerprint=pipeline_fingerprint,
                image_relative_path=image_relative_path,
                execution_mode=execution_mode,
                runtime_kind=runtime_kind,
                profile_id=profile_id,
                runtime_fingerprint=runtime_fingerprint,
                status="queued",
                reference_count=1,
                runnable_consumer_count=1,
            )
        )
    else:
        shared_work_id = str(row["shared_work_id"])
        actual_identity = (
            str(row["execution_mode"]),
            str(row["image_sha256"]),
            str(row["pipeline_fingerprint"]),
            None if row["runtime_kind"] is None else str(row["runtime_kind"]),
            None if row["profile_id"] is None else str(row["profile_id"]),
            (
                None
                if row["runtime_fingerprint"] is None
                else str(row["runtime_fingerprint"])
            ),
        )
        if actual_identity != expected_identity:
            raise RuntimeError("shared OCR fingerprint resolved to a different identity")
        if row["status"] == "failed":
            connection.execute(
                SHARED_EVIDENCE_CONSUMERS.insert().values(
                    shared_work_id=shared_work_id,
                    work_item_id=work_item_id,
                    image_role=image_role,
                    status="failed",
                )
            )
            connection.execute(
                update(SHARED_EVIDENCE_CONSUMERS)
                .where(
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id == work_item_id,
                    SHARED_EVIDENCE_CONSUMERS.c.status.in_(("waiting", "paused")),
                )
                .values(status="cancelled")
            )
            item = (
                connection.execute(
                    select(WORK_ITEMS).where(
                        WORK_ITEMS.c.work_item_id == work_item_id
                    )
                )
                .mappings()
                .one()
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == work_item_id)
                .values(
                    status=WorkItemStatus.FAILED.value,
                    business_outcome=None,
                    review_reason=None,
                    diagnostic_code=(
                        str(row["diagnostic_code"])
                        if row["diagnostic_code"] is not None
                        else "LOOP3-SHARED-OCR-FAILED"
                    ),
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    record_version=int(item["record_version"]) + 1,
                )
            )
            return shared_work_id
        connection.execute(
            update(SHARED_EVIDENCE_WORK)
            .where(SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id)
            .values(
                reference_count=int(row["reference_count"]) + 1,
                runnable_consumer_count=int(row["runnable_consumer_count"]) + 1,
            )
        )
    connection.execute(
        SHARED_EVIDENCE_CONSUMERS.insert().values(
            shared_work_id=shared_work_id,
            work_item_id=work_item_id,
            image_role=image_role,
            status="waiting",
        )
    )
    return shared_work_id


class SqliteLoop3JobStore:
    """Persist scheduled Job creation, controls, and shared registration."""

    def __init__(
        self,
        engine: Engine,
        commit_gate: ShortTransactionCommitGate,
        get_job: GetJob,
        append_event: AppendEvent,
    ) -> None:
        self.engine = engine
        self._commit_gate = commit_gate
        self._get_job = get_job
        self._append_event = append_event
        self._conflict_locks: dict[str, Lock] = {}

    def create_scheduled_job(
        self,
        *,
        fixture: ScheduledJobSpec,
        scope_label: str,
        idempotency_key: str,
        request_hash: str,
        expected_record_version: int,
    ) -> tuple[JobRecord, bool]:
        conflict_lock = self._conflict_locks.setdefault(
            fixture.conflict_key,
            Lock(),
        )
        with conflict_lock:
            return self._create_scheduled_job_locked(
                fixture=fixture,
                scope_label=scope_label,
                idempotency_key=idempotency_key,
                request_hash=request_hash,
                expected_record_version=expected_record_version,
            )

    def link_active_scheduled_job(
        self,
        *,
        conflict_key: str,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        """Attach a new source identity to one identical active job."""

        conflict_lock = self._conflict_locks.setdefault(conflict_key, Lock())
        with conflict_lock:
            operation = "POST:/api/v1/jobs"
            now = _utc_now()
            with self._commit_gate.transaction(self.engine) as connection:
                replay = (
                    connection.execute(
                        select(IDEMPOTENCY_RECORDS).where(
                            IDEMPOTENCY_RECORDS.c.operation == operation,
                            IDEMPOTENCY_RECORDS.c.idempotency_key
                            == idempotency_key,
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
                    return (
                        self._get_job(connection, str(replay["job_id"])),
                        False,
                    )

                conflict = (
                    connection.execute(
                        select(CONFLICT_KEYS.c.job_id, CONFLICT_KEYS.c.active)
                        .where(CONFLICT_KEYS.c.conflict_key == conflict_key)
                    )
                    .mappings()
                    .one_or_none()
                )
                if conflict is None or not bool(conflict["active"]):
                    raise ActiveScopeConflictError(
                        "no active job owns this conflict key"
                    )
                job_id = str(conflict["job_id"])
                connection.execute(
                    IDEMPOTENCY_RECORDS.insert().values(
                        operation=operation,
                        idempotency_key=idempotency_key,
                        request_hash=request_hash,
                        job_id=job_id,
                        created_at=now,
                    )
                )
                return self._get_job(connection, job_id), True

    def _create_scheduled_job_locked(
        self,
        *,
        fixture: ScheduledJobSpec,
        scope_label: str,
        idempotency_key: str,
        request_hash: str,
        expected_record_version: int,
    ) -> tuple[JobRecord, bool]:
        operation = "POST:/api/v1/jobs"
        now = _utc_now()
        with self._commit_gate.transaction(self.engine) as connection:
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

            conflict = (
                connection.execute(
                    select(
                        CONFLICT_KEYS.c.job_id,
                        CONFLICT_KEYS.c.active,
                        JOBS.c.record_version,
                        JOBS.c.status,
                    )
                    .join(JOBS, JOBS.c.job_id == CONFLICT_KEYS.c.job_id)
                    .where(CONFLICT_KEYS.c.conflict_key == fixture.conflict_key)
                )
                .mappings()
                .one_or_none()
            )
            if conflict is not None and bool(conflict["active"]):
                owner_status = JobStatus(str(conflict["status"]))
                if not owner_status.is_terminal:
                    raise ActiveScopeConflictError(
                        "an active job already owns this conflict key"
                    )
                connection.execute(
                    update(CONFLICT_KEYS)
                    .where(
                        CONFLICT_KEYS.c.conflict_key
                        == fixture.conflict_key
                    )
                    .values(active=0)
                )
            current_start_version = 0 if conflict is None else int(conflict["record_version"])
            if current_start_version != expected_record_version:
                raise RecordVersionConflictError("fixture start action record version is stale")

            sequence = next_sequence(connection)
            job_id = uuid4().hex
            initial_stage = _initial_stage(fixture.task_type)
            connection.execute(
                JOBS.insert().values(
                    job_id=job_id,
                    task_type=fixture.task_type,
                    scope_label=scope_label,
                    scope_fixture_id=fixture.fixture_id,
                    scope_fingerprint=_scope_fingerprint(
                        fixture.task_type,
                        fixture.fixture_id,
                    ),
                    run_mode=fixture.run_mode,
                    status=JobStatus.QUEUED.value,
                    current_stage=initial_stage,
                    diagnostic_code=None,
                    job_kind=fixture.job_kind,
                    ocr_execution_mode=fixture.ocr_execution_mode,
                    conflict_key=fixture.conflict_key,
                    created_sequence=sequence,
                    record_version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            if conflict is None:
                connection.execute(
                    CONFLICT_KEYS.insert().values(
                        conflict_key=fixture.conflict_key,
                        job_id=job_id,
                        active=1,
                    )
                )
            else:
                connection.execute(
                    update(CONFLICT_KEYS)
                    .where(CONFLICT_KEYS.c.conflict_key == fixture.conflict_key)
                    .values(job_id=job_id, active=1)
                )
            for item_index, fixture_item in enumerate(fixture.items):
                work_item_id = uuid4().hex
                connection.execute(
                    WORK_ITEMS.insert().values(
                        work_item_id=work_item_id,
                        job_id=job_id,
                        record_version=1,
                        waybill_number=fixture_item.item_key,
                        vehicle_number=(
                            fixture_item.vehicle_number
                            or (
                                "调度探针"
                                if fixture.task_type == "loading_probe"
                                else (
                                    "装卸车采集"
                                    if fixture.task_type == "daily"
                                    else (
                                        "待结算采集"
                                        if fixture.task_type
                                        == "settlement_capture"
                                        else f"测试车辆{item_index + 1:02d}"
                                    )
                                )
                            )
                        ),
                        status=WorkItemStatus.QUEUED.value,
                        current_stage=initial_stage,
                        item_index=item_index,
                        attempt_count=0,
                        loading_image_sha256=fixture_item.loading_image_sha256,
                        unloading_image_sha256=fixture_item.unloading_image_sha256,
                        loading_image_relative_path=(
                            fixture_item.loading_image_relative_path
                        ),
                        unloading_image_relative_path=(
                            fixture_item.unloading_image_relative_path
                        ),
                        pipeline_fingerprint=(
                            fixture.pipeline_fingerprint if fixture.task_type == "audit" else None
                        ),
                        fixture_outcome=fixture_item.expected_outcome,
                        fixture_review_reason=fixture_item.review_reason,
                        fixture_platform_loading_net=(
                            fixture_item.platform_loading_net
                        ),
                        fixture_platform_unloading_net=(
                            fixture_item.platform_unloading_net
                        ),
                        fixture_ticket_loading_net=(
                            fixture_item.ticket_loading_net
                        ),
                        fixture_ticket_unloading_net=(
                            fixture_item.ticket_unloading_net
                        ),
                        fixture_diagnostic_code=fixture_item.diagnostic_code,
                        download_complete=int(fixture_item.evidence_preloaded),
                        loading_ocr_complete=0,
                        unloading_ocr_complete=0,
                        ready_sequence=sequence,
                    )
                )
                if (
                    fixture.task_type == "audit"
                    and fixture.ocr_execution_mode == "fake"
                ):
                    assert fixture_item.loading_image_sha256 is not None
                    assert fixture_item.unloading_image_sha256 is not None
                    assert fixture.pipeline_fingerprint is not None
                    register_shared_consumer(
                        connection,
                        work_item_id=work_item_id,
                        image_role="loading",
                        image_sha256=fixture_item.loading_image_sha256,
                        pipeline_fingerprint=fixture.pipeline_fingerprint,
                        execution_mode="fake",
                    )
                    register_shared_consumer(
                        connection,
                        work_item_id=work_item_id,
                        image_role="unloading",
                        image_sha256=fixture_item.unloading_image_sha256,
                        pipeline_fingerprint=fixture.pipeline_fingerprint,
                        execution_mode="fake",
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

    def fixture_start_state(self, conflict_key: str) -> tuple[bool, int]:
        with self.engine.connect() as connection:
            row = (
                connection.execute(
                    select(
                        CONFLICT_KEYS.c.active,
                        JOBS.c.record_version,
                        JOBS.c.status,
                    )
                    .join(JOBS, JOBS.c.job_id == CONFLICT_KEYS.c.job_id)
                    .where(CONFLICT_KEYS.c.conflict_key == conflict_key)
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return False, 0
            active = bool(row["active"]) and not JobStatus(
                str(row["status"])
            ).is_terminal
            return active, int(row["record_version"])

    def request_job_control(
        self,
        *,
        job_id: str,
        action: str,
        expected_record_version: int,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]:
        operation = f"POST:/api/v1/jobs/{job_id}/{action}"
        now = _utc_now()
        with self._commit_gate.transaction(self.engine) as connection:
            replay = (
                connection.execute(
                    select(CONTROL_IDEMPOTENCY).where(
                        CONTROL_IDEMPOTENCY.c.operation == operation,
                        CONTROL_IDEMPOTENCY.c.idempotency_key == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if replay["request_hash"] != request_hash:
                    raise IdempotencyConflictError(
                        "the idempotency key belongs to a different control request"
                    )
                current = self._get_job(connection, job_id)
                return (
                    replace(
                        current,
                        status=JobStatus(str(replay["result_status"])),
                        record_version=int(replay["result_record_version"]),
                    ),
                    True,
                )

            job = self._get_job(connection, job_id)
            if job.record_version != expected_record_version:
                raise RecordVersionConflictError("job record version is stale")
            if action == "pause":
                if job.status is JobStatus.WAITING_USER:
                    raise JobControlError("waiting-user jobs cannot be paused")
                if job.status not in {
                    JobStatus.QUEUED,
                    JobStatus.RUNNING,
                    JobStatus.WAITING_RESOURCE,
                }:
                    raise JobControlError("job cannot be paused from this state")
                target_status = JobStatus.PAUSE_REQUESTED
            elif action == "resume":
                if job.status is not JobStatus.PAUSED:
                    raise JobControlError("only paused jobs can resume")
                target_status = JobStatus.QUEUED
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
                        record_version=(
                            WORK_ITEMS.c.record_version + 1
                        ),
                    )
                )
                connection.execute(
                    update(SHARED_EVIDENCE_CONSUMERS)
                    .where(
                        SHARED_EVIDENCE_CONSUMERS.c.work_item_id.in_(
                            select(WORK_ITEMS.c.work_item_id).where(WORK_ITEMS.c.job_id == job_id)
                        ),
                        SHARED_EVIDENCE_CONSUMERS.c.status == "paused",
                    )
                    .values(status="waiting")
                )
            elif action == "cancel":
                if job.status.is_terminal:
                    raise JobControlError("terminal jobs cannot be cancelled")
                target_status = JobStatus.CANCEL_REQUESTED
            else:
                raise JobControlError("unknown job control")

            next_version = job.record_version + 1
            result = connection.execute(
                update(JOBS)
                .where(
                    JOBS.c.job_id == job_id,
                    JOBS.c.record_version == expected_record_version,
                )
                .values(
                    status=target_status.value,
                    record_version=next_version,
                    updated_at=now,
                )
            )
            if result.rowcount != 1:
                raise RecordVersionConflictError("job record version is stale")
            connection.execute(
                CONTROL_IDEMPOTENCY.insert().values(
                    operation=operation,
                    idempotency_key=idempotency_key,
                    request_hash=request_hash,
                    job_id=job_id,
                    result_record_version=next_version,
                    result_status=target_status.value,
                )
            )
            self._append_event(
                connection,
                event_type=f"job.{action}_requested",
                aggregate_id=job_id,
                record_version=next_version,
                payload={
                    "job_id": job_id,
                    "job_status": target_status.value,
                },
                created_at=now,
            )
            return self._get_job(connection, job_id), False
