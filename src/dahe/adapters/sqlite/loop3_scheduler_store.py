from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.engine import Connection, Engine, RowMapping

from dahe.adapters.sqlite.loop3_job_store import register_shared_consumer
from dahe.adapters.sqlite.loop3_resource_store import (
    SchedulerLeaseFencingError,
    SchedulerLeaseGrant,
    SqliteLoop3ResourceStore,
)
from dahe.adapters.sqlite.loop3_support import (
    AppendEvent,
    attempt_number,
    next_sequence,
)
from dahe.adapters.sqlite.loop4_recovery_store import (
    propagate_shared_failure_once_in_transaction,
)
from dahe.adapters.sqlite.runtime import ShortTransactionCommitGate
from dahe.adapters.sqlite.schema import (
    CHECKPOINTS,
    CONFLICT_KEYS,
    DAILY_CAPTURE_INVOCATIONS,
    JOBS,
    LEASES,
    OCR_RUN_GENERATIONS,
    PLATFORM_ACCESS_EVENTS,
    PLATFORM_ACCESS_WINDOWS,
    SETTLEMENT_CAPTURE_INVOCATIONS,
    SHARED_EVIDENCE_CONSUMERS,
    SHARED_EVIDENCE_WORK,
    STAGE_ATTEMPTS,
    WORK_ITEMS,
)
from dahe.jobs.audit_execution import (
    LocalAuditEvaluationInput,
    LocalAuditEvaluator,
    LocalAuditTechnicalError,
)
from dahe.jobs.daily_execution import (
    AsyncDailyExecutionBackend,
    DailyStageExecution,
    DailyStageWork,
)
from dahe.jobs.models import JobStatus, WorkItemStatus
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageWork,
    OcrRuntimeIdentity,
    OcrStageExecution,
    OcrStageWork,
)
from dahe.jobs.settlement_capture_execution import (
    SETTLEMENT_CAPTURE_STAGE,
    AsyncSettlementCaptureExecutionBackend,
    SettlementCaptureStageExecution,
    SettlementCaptureStageWork,
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _external_waiting_reason(diagnostic_code: str | None) -> str:
    if diagnostic_code == "CF-CREDENTIAL-REQUIRED":
        return "credential_required"
    if diagnostic_code in {
        "CF-LOGIN-INTERVENTION-REQUIRED",
        "CF-LOGIN-REQUIRED",
    }:
        return "login_required"
    return "access_window_expired"


class SqliteLoop3SchedulerStore:
    """Commit one cooperative scheduler quantum per short transaction."""

    def __init__(
        self,
        engine: Engine,
        commit_gate: ShortTransactionCommitGate,
        append_event: AppendEvent,
        resource_store: SqliteLoop3ResourceStore,
        ocr_execution_backend: AsyncOcrExecutionBackend | None = None,
        daily_execution_backend: AsyncDailyExecutionBackend | None = None,
        settlement_capture_execution_backend: (
            AsyncSettlementCaptureExecutionBackend | None
        ) = None,
        local_audit_evaluator: LocalAuditEvaluator | None = None,
    ) -> None:
        self.engine = engine
        self._commit_gate = commit_gate
        self._append_event = append_event
        self._resource_store = resource_store
        self._ocr_execution_backend = ocr_execution_backend
        self._daily_execution_backend = daily_execution_backend
        self._settlement_capture_execution_backend = (
            settlement_capture_execution_backend
        )
        self._local_audit_evaluator = local_audit_evaluator
        self._completed_ocr_results: dict[str, OcrStageExecution] = {}
        self._completed_daily_results: dict[
            str,
            DailyStageExecution,
        ] = {}
        self._completed_settlement_capture_results: dict[
            str,
            SettlementCaptureStageExecution,
        ] = {}

    @staticmethod
    def _work_item_event_state(
        connection: Connection,
    ) -> dict[str, tuple[int, str]]:
        return {
            str(row["work_item_id"]): (
                int(row["record_version"]),
                str(row["job_id"]),
            )
            for row in connection.execute(
                select(
                    WORK_ITEMS.c.work_item_id,
                    WORK_ITEMS.c.record_version,
                    WORK_ITEMS.c.job_id,
                )
            ).mappings()
        }

    @staticmethod
    def _save_checkpoint(
        connection: Connection,
        *,
        owner_kind: str,
        owner_id: str,
        job_id: str | None,
        work_item_id: str | None,
        stage: str,
        sequence: int,
        payload: dict[str, object],
    ) -> None:
        connection.execute(
            CHECKPOINTS.insert().values(
                checkpoint_id=uuid4().hex,
                owner_kind=owner_kind,
                owner_id=owner_id,
                job_id=job_id,
                work_item_id=work_item_id,
                stage=stage,
                sequence=sequence,
                payload_json=json.dumps(
                    payload,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )

    @classmethod
    def _insert_completed_attempt(
        cls,
        connection: Connection,
        *,
        owner_kind: str,
        owner_id: str,
        consumer_job_id: str | None,
        work_item_id: str | None,
        stage: str,
        sequence: int,
        diagnostic_code: str | None = None,
    ) -> None:
        connection.execute(
            STAGE_ATTEMPTS.insert().values(
                stage_attempt_id=uuid4().hex,
                owner_kind=owner_kind,
                owner_id=owner_id,
                consumer_job_id=consumer_job_id,
                work_item_id=work_item_id,
                stage=stage,
                status="failed" if diagnostic_code is not None else "succeeded",
                resource_name=None,
                attempt_number=attempt_number(
                    connection,
                    owner_kind=owner_kind,
                    owner_id=owner_id,
                    stage=stage,
                ),
                started_sequence=sequence,
                finished_sequence=sequence,
                diagnostic_code=diagnostic_code,
            )
        )

    def scheduler_tick(self, failure_image_hashes: set[str]) -> bool:
        now = _utc_now()
        acquired_grants: list[SchedulerLeaseGrant] = []
        ocr_submissions: list[OcrStageWork] = []
        daily_submissions: list[DailyStageWork] = []
        settlement_capture_submissions: list[
            SettlementCaptureStageWork
        ] = []
        completed_attempt_ids: tuple[str, ...] = ()
        terminal_daily_job_ids: tuple[str, ...] = ()
        terminal_settlement_job_ids: tuple[str, ...] = ()
        pending_cleanup_before = bool(
            self._resource_store.pending_daily_terminal_cleanup()
            or self._resource_store.pending_settlement_terminal_cleanup()
        )
        if self._ocr_execution_backend is not None:
            self._completed_ocr_results.update(
                self._ocr_execution_backend.pop_completed()
            )
        if self._daily_execution_backend is not None:
            self._completed_daily_results.update(
                self._daily_execution_backend.pop_completed()
            )
        if self._settlement_capture_execution_backend is not None:
            self._completed_settlement_capture_results.update(
                self._settlement_capture_execution_backend.pop_completed()
            )
        try:
            with self._commit_gate.transaction(self.engine) as connection:
                sequence = next_sequence(connection)
                resources_before = self._resource_store.event_state(connection)
                work_items_before = self._work_item_event_state(connection)
                (
                    completed_attempt_ids,
                    terminal_daily_from_attempts,
                    terminal_settlement_from_attempts,
                ) = self._finish_running_attempts(
                    connection,
                    sequence=sequence,
                    failure_image_hashes=failure_image_hashes,
                    now=now,
                )
                self._resource_store.heartbeat_pending_async_grants(
                    connection,
                    completed_attempt_ids=completed_attempt_ids,
                    now=now,
                )
                terminal_daily_from_recovery = (
                    self._reconcile_daily_invocations(
                        connection,
                        sequence=sequence,
                        now=now,
                    )
                )
                terminal_settlement_from_recovery = (
                    self._reconcile_settlement_capture_invocations(
                        connection,
                        sequence=sequence,
                    )
                )
                (
                    terminal_daily_from_control,
                    terminal_settlement_from_control,
                ) = self._apply_control_boundaries(
                    connection,
                    sequence=sequence,
                    now=now,
                )
                terminal_daily_job_ids = tuple(
                    sorted(
                        {
                            *terminal_daily_from_attempts,
                            *terminal_daily_from_recovery,
                            *terminal_daily_from_control,
                        }
                    )
                )
                terminal_settlement_job_ids = tuple(
                    sorted(
                        {
                            *terminal_settlement_from_attempts,
                            *terminal_settlement_from_recovery,
                            *terminal_settlement_from_control,
                        }
                    )
                )
                self._prepare_ocr_generations(
                    connection,
                    now=now,
                    sequence=sequence,
                )
                self._refresh_shared_counts(connection)
                self._consume_completed_shared_work(
                    connection,
                    sequence=sequence,
                    now=now,
                )
                self._finalize_ready_audit_items(
                    connection,
                    sequence=sequence,
                )
                self._finalize_local_business_audit_items(
                    connection,
                    sequence=sequence,
                )
                if self._ocr_execution_backend is not None:
                    self._finalize_runtime_only_items(
                        connection,
                        sequence=sequence,
                    )
                resource_names = ["platform_browser", "gpu_ocr_slot"]
                if (
                    pending_cleanup_before
                    or terminal_daily_job_ids
                    or terminal_settlement_job_ids
                ):
                    resource_names.remove("platform_browser")
                if self._ocr_execution_backend is not None:
                    resource_names.append("cpu_ocr_slot")
                for resource_name in resource_names:
                    grant = self._resource_store.start_resource_attempt(
                        connection,
                        resource_name=resource_name,
                        sequence=sequence,
                    )
                    if grant is not None:
                        acquired_grants.append(grant)
                        if grant.execution_kind == "ocr_image":
                            ocr_submissions.append(
                                self._build_ocr_stage_work(
                                    connection,
                                    grant=grant,
                                )
                            )
                        elif grant.execution_kind == "daily_capture":
                            daily_submissions.append(
                                self._build_daily_stage_work(
                                    connection,
                                    grant=grant,
                                )
                            )
                        elif grant.execution_kind == "settlement_capture":
                            settlement_capture_submissions.append(
                                self._build_settlement_capture_stage_work(
                                    connection,
                                    grant=grant,
                                )
                            )
                self._resource_store.refresh_job_aggregates(connection, now=now)
                resources_after = self._resource_store.event_state(connection)
                work_items_after = self._work_item_event_state(connection)
                for work_item_id, (record_version, job_id) in sorted(work_items_after.items()):
                    if work_items_before.get(work_item_id) == (
                        record_version,
                        job_id,
                    ):
                        continue
                    self._append_event(
                        connection,
                        event_type="work_item.changed",
                        aggregate_type="work_item",
                        aggregate_id=work_item_id,
                        record_version=record_version,
                        payload={
                            "job_id": job_id,
                            "work_item_id": work_item_id,
                        },
                        created_at=now,
                    )
                for resource_name in sorted(resources_after.keys() | resources_before.keys()):
                    if resources_before.get(resource_name) == resources_after.get(resource_name):
                        continue
                    self._append_event(
                        connection,
                        event_type="resource.changed",
                        aggregate_type="resource",
                        aggregate_id=resource_name,
                        record_version=sequence,
                        payload={"resource_name": resource_name},
                        created_at=now,
                    )
                # Publish before commit so no committed active lease can exist
                # without its raw grant in this live process.
                self._resource_store.remember_process_grants(tuple(acquired_grants))
        except BaseException:
            grants_to_reconcile = (
                self._resource_store.process_grants()
                if completed_attempt_ids
                else tuple(acquired_grants)
            )
            self._resource_store.reconcile_process_grants(grants_to_reconcile)
            raise
        self._resource_store.forget_process_grants(completed_attempt_ids)
        if (
            self._daily_execution_backend is not None
            and terminal_daily_job_ids
        ):
            self._resource_store.queue_daily_terminal_cleanup(
                terminal_daily_job_ids
            )
        if (
            self._settlement_capture_execution_backend is not None
            and terminal_settlement_job_ids
        ):
            self._resource_store.queue_settlement_terminal_cleanup(
                terminal_settlement_job_ids
            )
        for stage_attempt_id in completed_attempt_ids:
            self._completed_ocr_results.pop(stage_attempt_id, None)
            self._completed_daily_results.pop(stage_attempt_id, None)
            self._completed_settlement_capture_results.pop(
                stage_attempt_id,
                None,
            )
        if self._ocr_execution_backend is not None:
            for work in ocr_submissions:
                self._ocr_execution_backend.submit(work)
        if self._daily_execution_backend is not None:
            for daily_work in daily_submissions:
                self._daily_execution_backend.submit(daily_work)
            self._reconcile_pending_daily_terminal_cleanup()
        if self._settlement_capture_execution_backend is not None:
            for capture_work in settlement_capture_submissions:
                self._settlement_capture_execution_backend.submit(
                    capture_work
                )
            self._reconcile_pending_settlement_terminal_cleanup()
        return True

    def maintain_automatic_work(self) -> bool:
        """Heartbeat an in-flight browser stage without a full scheduler scan.

        Returning ``True`` asks the runner to perform a full tick. Explicit API
        control actions bypass this method because they wake the runner directly.
        """

        grants = self._resource_store.process_grants()
        if not grants:
            return True
        execution_kinds = {grant.execution_kind for grant in grants}
        external_kinds = {"daily_capture", "settlement_capture"}
        if execution_kinds - external_kinds:
            return True
        if (
            "daily_capture" in execution_kinds
            and (
                self._daily_execution_backend is None
                or not self._daily_execution_backend.has_pending()
                or self._daily_execution_backend.has_completed()
            )
        ):
            return True
        if (
            "settlement_capture" in execution_kinds
            and (
                self._settlement_capture_execution_backend is None
                or not self._settlement_capture_execution_backend.has_pending()
                or self._settlement_capture_execution_backend.has_completed()
            )
        ):
            return True
        with self._commit_gate.transaction(self.engine) as connection:
            self._resource_store.heartbeat_pending_async_grants(
                connection,
                completed_attempt_ids=(),
                now=_utc_now(),
            )
        return False

    def _reconcile_pending_daily_terminal_cleanup(self) -> None:
        assert self._daily_execution_backend is not None
        for job_id in (
            self._resource_store.pending_daily_terminal_cleanup()
        ):
            try:
                self._daily_execution_backend.reconcile_terminal(job_id)
            except Exception:
                continue
            self._resource_store.finish_daily_terminal_cleanup(job_id)

    def _reconcile_pending_settlement_terminal_cleanup(self) -> None:
        assert self._settlement_capture_execution_backend is not None
        for job_id in (
            self._resource_store.pending_settlement_terminal_cleanup()
        ):
            try:
                self._settlement_capture_execution_backend.reconcile_terminal(
                    job_id
                )
            except Exception:
                continue
            self._resource_store.finish_settlement_terminal_cleanup(job_id)

    def _finish_running_attempts(
        self,
        connection: Connection,
        *,
        sequence: int,
        failure_image_hashes: set[str],
        now: str,
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        completed_attempt_ids: list[str] = []
        terminal_daily_job_ids: list[str] = []
        terminal_settlement_job_ids: list[str] = []
        pending: list[tuple[SchedulerLeaseGrant, RowMapping]] = []
        for grant in self._resource_store.process_grants():
            attempt = (
                connection.execute(
                    select(STAGE_ATTEMPTS).where(
                        STAGE_ATTEMPTS.c.stage_attempt_id == grant.stage_attempt_id,
                        STAGE_ATTEMPTS.c.status == "running",
                    )
                )
                .mappings()
                .one_or_none()
            )
            if attempt is None:
                raise SchedulerLeaseFencingError(
                    "scheduler result stage attempt is no longer running"
                )
            if (
                grant.execution_kind == "ocr_image"
                and grant.stage_attempt_id not in self._completed_ocr_results
            ):
                continue
            if (
                grant.execution_kind == "daily_capture"
                and grant.stage_attempt_id
                not in self._completed_daily_results
            ):
                continue
            if (
                grant.execution_kind == "settlement_capture"
                and grant.stage_attempt_id
                not in self._completed_settlement_capture_results
            ):
                continue
            pending.append((grant, attempt))
        pending.sort(
            key=lambda pair: (
                0 if pair[1]["owner_kind"] == "shared_evidence" else 1,
                pair[0].stage_attempt_id,
            )
        )
        for grant, attempt in pending:
            self._resource_store.release_result_grant(
                connection,
                grant=grant,
                sequence=sequence,
                now=now,
            )
            if grant.execution_kind == "ocr_image":
                result = self._completed_ocr_results[grant.stage_attempt_id]
                self._finish_ocr_image_attempt(
                    connection,
                    grant=grant,
                    attempt=attempt,
                    result=result,
                    sequence=sequence,
                    now=now,
                )
                completed_attempt_ids.append(grant.stage_attempt_id)
                continue
            if grant.execution_kind == "daily_capture":
                daily_result = self._completed_daily_results[
                    grant.stage_attempt_id
                ]
                self._finish_daily_attempt(
                    connection,
                    grant=grant,
                    attempt=attempt,
                    result=daily_result,
                    sequence=sequence,
                    now=now,
                )
                if (
                    daily_result.outcome == "failed"
                    or (
                        daily_result.outcome == "succeeded"
                        and daily_result.next_stage is None
                    )
                ):
                    terminal_daily_job_ids.append(grant.job_id)
                completed_attempt_ids.append(grant.stage_attempt_id)
                continue
            if grant.execution_kind == "settlement_capture":
                capture_result = (
                    self._completed_settlement_capture_results[
                        grant.stage_attempt_id
                    ]
                )
                self._finish_settlement_capture_attempt(
                    connection,
                    grant=grant,
                    attempt=attempt,
                    result=capture_result,
                    sequence=sequence,
                )
                if (
                    capture_result.outcome == "failed"
                    or (
                        capture_result.outcome == "succeeded"
                        and capture_result.next_stage is None
                    )
                ):
                    terminal_settlement_job_ids.append(grant.job_id)
                completed_attempt_ids.append(grant.stage_attempt_id)
                continue
            diagnostic_code: str | None = None
            if attempt["owner_kind"] == "shared_evidence":
                shared = (
                    connection.execute(
                        select(SHARED_EVIDENCE_WORK).where(
                            SHARED_EVIDENCE_WORK.c.shared_work_id == attempt["owner_id"]
                        )
                    )
                    .mappings()
                    .one()
                )
                if str(shared["image_sha256"]) in failure_image_hashes:
                    diagnostic_code = "LOOP3-FAKE-OCR-FAILURE"
            finished = connection.execute(
                update(STAGE_ATTEMPTS)
                .where(
                    STAGE_ATTEMPTS.c.stage_attempt_id == attempt["stage_attempt_id"],
                    STAGE_ATTEMPTS.c.status == "running",
                )
                .values(
                    status="failed" if diagnostic_code else "succeeded",
                    finished_sequence=sequence,
                    diagnostic_code=diagnostic_code,
                )
            )
            if finished.rowcount != 1:
                raise SchedulerLeaseFencingError(
                    "scheduler result stage attempt changed before commit"
                )
            if attempt["owner_kind"] == "work_item":
                self._finish_work_item_attempt(
                    connection,
                    attempt=attempt,
                    sequence=sequence,
                )
            else:
                self._finish_shared_attempt(
                    connection,
                    shared_work_id=str(attempt["owner_id"]),
                    sequence=sequence,
                    diagnostic_code=diagnostic_code,
                )
            completed_attempt_ids.append(grant.stage_attempt_id)
        return (
            tuple(completed_attempt_ids),
            tuple(terminal_daily_job_ids),
            tuple(terminal_settlement_job_ids),
        )

    @staticmethod
    def _daily_checkpoint_revision(invocation: RowMapping) -> int | None:
        raw = invocation["checkpoint_json"]
        if raw is None:
            return None
        try:
            payload = json.loads(str(raw))
            revision = payload["revision"]
        except (KeyError, TypeError, ValueError) as exc:
            raise SchedulerLeaseFencingError(
                "daily invocation checkpoint is invalid"
            ) from exc
        if type(revision) is not int or revision < 1:
            raise SchedulerLeaseFencingError(
                "daily invocation checkpoint revision is invalid"
            )
        return revision

    @staticmethod
    def _build_daily_stage_work(
        connection: Connection,
        *,
        grant: SchedulerLeaseGrant,
    ) -> DailyStageWork:
        if (
            grant.owner_kind != "work_item"
            or grant.execution_kind != "daily_capture"
            or not grant.stage.startswith("daily.")
        ):
            raise RuntimeError("claimed daily work identity is invalid")
        item = (
            connection.execute(
                select(
                    WORK_ITEMS,
                    JOBS.c.task_type,
                    JOBS.c.status.label("job_status"),
                    JOBS.c.record_version.label(
                        "job_record_version"
                    ),
                    JOBS.c.current_stage.label(
                        "job_current_stage"
                    ),
                )
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(
                    WORK_ITEMS.c.work_item_id == grant.work_item_id,
                    WORK_ITEMS.c.job_id == grant.job_id,
                )
            )
            .mappings()
            .one()
        )
        invocation = (
            connection.execute(
                select(DAILY_CAPTURE_INVOCATIONS).where(
                    DAILY_CAPTURE_INVOCATIONS.c.job_id == grant.job_id
                )
            )
            .mappings()
            .one()
        )
        if (
            item["task_type"] != "daily"
            or item["status"] != WorkItemStatus.RUNNING.value
            or item["current_stage"] != grant.stage
            or invocation["status"] != "ready"
            or invocation["next_stage"] != grant.stage
        ):
            raise RuntimeError(
                "claimed daily work changed before submission"
            )
        return DailyStageWork(
            stage_attempt_id=grant.stage_attempt_id,
            job_id=grant.job_id,
            work_item_id=grant.work_item_id,
            stage=grant.stage,
        )

    def _finish_daily_attempt(
        self,
        connection: Connection,
        *,
        grant: SchedulerLeaseGrant,
        attempt: RowMapping,
        result: DailyStageExecution,
        sequence: int,
        now: str,
    ) -> None:
        if (
            result.stage_attempt_id != grant.stage_attempt_id
            or grant.owner_kind != "work_item"
            or attempt["owner_id"] != grant.work_item_id
            or attempt["consumer_job_id"] != grant.job_id
            or result.completed_stage != grant.stage
            or attempt["stage"] != result.completed_stage
        ):
            raise SchedulerLeaseFencingError(
                "daily result identity does not match its fenced attempt"
            )
        item = (
            connection.execute(
                select(
                    WORK_ITEMS,
                    JOBS.c.task_type,
                    JOBS.c.status.label("job_status"),
                    JOBS.c.record_version.label(
                        "job_record_version"
                    ),
                    JOBS.c.current_stage.label(
                        "job_current_stage"
                    ),
                )
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(
                    WORK_ITEMS.c.work_item_id == grant.work_item_id,
                    WORK_ITEMS.c.job_id == grant.job_id,
                )
            )
            .mappings()
            .one()
        )
        invocation = (
            connection.execute(
                select(DAILY_CAPTURE_INVOCATIONS).where(
                    DAILY_CAPTURE_INVOCATIONS.c.job_id == grant.job_id
                )
            )
            .mappings()
            .one()
        )
        if (
            item["task_type"] != "daily"
            or item["status"] != WorkItemStatus.RUNNING.value
            or item["current_stage"] != result.completed_stage
        ):
            raise SchedulerLeaseFencingError(
                "daily work item changed before result commit"
            )

        attempt_status = "succeeded"
        diagnostic_code: str | None = None
        next_item_status = WorkItemStatus.QUEUED
        next_stage = result.completed_stage
        item_diagnostic: str | None = None
        item_waiting_reason_kind: str | None = None
        item_waiting_reason: str | None = None
        checkpoint_revision = self._daily_checkpoint_revision(invocation)

        if result.outcome == "succeeded":
            expected_next_stage = (
                "daily.complete"
                if result.next_stage is None
                else result.next_stage
            )
            expected_invocation_status = (
                "succeeded"
                if result.next_stage is None
                else "ready"
            )
            if (
                result.checkpoint_revision is None
                or checkpoint_revision != result.checkpoint_revision
                or invocation["next_stage"] != expected_next_stage
                or invocation["status"] != expected_invocation_status
                or invocation["diagnostic_code"] is not None
            ):
                raise SchedulerLeaseFencingError(
                    "daily checkpoint does not match the completed result"
                )
            next_stage = expected_next_stage
            next_item_status = (
                WorkItemStatus.SUCCEEDED
                if result.next_stage is None
                else WorkItemStatus.QUEUED
            )
        elif result.outcome == "retry":
            if (
                result.checkpoint_revision != checkpoint_revision
                or result.next_stage != result.completed_stage
                or invocation["status"] != "ready"
                or invocation["next_stage"] != result.completed_stage
            ):
                raise SchedulerLeaseFencingError(
                    "daily retry changed its committed checkpoint"
                )
            attempt_status = "failed"
            diagnostic_code = result.diagnostic_code
        elif result.outcome == "waiting_external":
            if (
                result.checkpoint_revision != checkpoint_revision
                or result.next_stage != result.completed_stage
                or invocation["status"] != "ready"
                or invocation["next_stage"] != result.completed_stage
            ):
                raise SchedulerLeaseFencingError(
                    "daily external wait changed its committed checkpoint"
                )
            attempt_status = "failed"
            diagnostic_code = result.diagnostic_code
            next_item_status = WorkItemStatus.WAITING_EXTERNAL
            item_diagnostic = result.diagnostic_code
            item_waiting_reason_kind = "external"
            item_waiting_reason = _external_waiting_reason(
                result.diagnostic_code
            )
        else:
            if (
                result.checkpoint_revision != checkpoint_revision
                or result.next_stage is not None
                or invocation["status"] == "succeeded"
            ):
                raise SchedulerLeaseFencingError(
                    "daily failure conflicts with invocation state"
                )
            diagnostic_code = result.diagnostic_code
            assert diagnostic_code is not None
            attempt_status = "failed"
            next_item_status = WorkItemStatus.FAILED
            item_diagnostic = diagnostic_code
            if invocation["status"] == "failed":
                if invocation["diagnostic_code"] != diagnostic_code:
                    raise SchedulerLeaseFencingError(
                        "daily failure diagnostic changed before commit"
                    )
            else:
                updated_invocation = connection.execute(
                    update(DAILY_CAPTURE_INVOCATIONS)
                    .where(
                        DAILY_CAPTURE_INVOCATIONS.c.job_id == grant.job_id,
                        DAILY_CAPTURE_INVOCATIONS.c.record_version
                        == invocation["record_version"],
                        DAILY_CAPTURE_INVOCATIONS.c.status.in_(
                            ("ready", "running")
                        ),
                    )
                    .values(
                        status="failed",
                        diagnostic_code=diagnostic_code,
                        record_version=int(
                            invocation["record_version"]
                        )
                        + 1,
                        updated_at=now,
                    )
                )
                if updated_invocation.rowcount != 1:
                    raise SchedulerLeaseFencingError(
                        "daily invocation changed before failure commit"
                    )

        finished = connection.execute(
            update(STAGE_ATTEMPTS)
            .where(
                STAGE_ATTEMPTS.c.stage_attempt_id
                == attempt["stage_attempt_id"],
                STAGE_ATTEMPTS.c.status == "running",
            )
            .values(
                status=attempt_status,
                finished_sequence=sequence,
                diagnostic_code=diagnostic_code,
            )
        )
        if finished.rowcount != 1:
            raise SchedulerLeaseFencingError(
                "daily stage attempt changed before result commit"
            )
        updated_item = connection.execute(
            update(WORK_ITEMS)
            .where(
                WORK_ITEMS.c.work_item_id == grant.work_item_id,
                WORK_ITEMS.c.record_version == item["record_version"],
            )
            .values(
                status=next_item_status.value,
                current_stage=next_stage,
                business_outcome=None,
                decision=None,
                review_reason=None,
                diagnostic_code=item_diagnostic,
                waiting_reason_kind=item_waiting_reason_kind,
                waiting_reason=item_waiting_reason,
                attempt_count=int(item["attempt_count"]) + 1,
                ready_sequence=sequence,
                record_version=int(item["record_version"]) + 1,
            )
        )
        if updated_item.rowcount != 1:
            raise SchedulerLeaseFencingError(
                "daily work item changed before result commit"
            )
        if result.outcome == "waiting_external":
            waiting_reason = _external_waiting_reason(
                result.diagnostic_code
            )
            next_job_version = int(item["job_record_version"]) + 1
            paused = connection.execute(
                update(JOBS)
                .where(
                    JOBS.c.job_id == grant.job_id,
                    JOBS.c.record_version
                    == item["job_record_version"],
                    JOBS.c.status == item["job_status"],
                )
                .values(
                    status=JobStatus.PAUSED.value,
                    diagnostic_code=result.diagnostic_code,
                    record_version=next_job_version,
                    updated_at=now,
                )
            )
            if paused.rowcount != 1:
                raise SchedulerLeaseFencingError(
                    "daily external wait changed concurrently"
                )
            self._append_event(
                connection,
                event_type="job.paused",
                aggregate_id=grant.job_id,
                record_version=next_job_version,
                payload={
                    "job_id": grant.job_id,
                    "job_status": JobStatus.PAUSED.value,
                    "current_stage": item["job_current_stage"],
                    "waiting_reason": waiting_reason,
                },
                created_at=now,
            )
        self._save_checkpoint(
            connection,
            owner_kind="work_item",
            owner_id=grant.work_item_id,
            job_id=grant.job_id,
            work_item_id=grant.work_item_id,
            stage=result.completed_stage,
            sequence=sequence,
            payload={
                "checkpoint_revision": result.checkpoint_revision,
                "diagnostic_code": result.diagnostic_code,
                "next_stage": result.next_stage,
                "outcome": result.outcome,
            },
        )

    def _reconcile_daily_invocations(
        self,
        connection: Connection,
        *,
        sequence: int,
        now: str,
    ) -> tuple[str, ...]:
        terminal_job_ids: list[str] = []
        rows = tuple(
            connection.execute(
                select(
                    WORK_ITEMS,
                    JOBS.c.status.label("job_status"),
                    DAILY_CAPTURE_INVOCATIONS.c.next_stage.label(
                        "invocation_next_stage"
                    ),
                    DAILY_CAPTURE_INVOCATIONS.c.status.label(
                        "invocation_status"
                    ),
                    DAILY_CAPTURE_INVOCATIONS.c.diagnostic_code.label(
                        "invocation_diagnostic_code"
                    ),
                    DAILY_CAPTURE_INVOCATIONS.c.checkpoint_json,
                )
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .join(
                    DAILY_CAPTURE_INVOCATIONS,
                    DAILY_CAPTURE_INVOCATIONS.c.job_id
                    == WORK_ITEMS.c.job_id,
                )
                .where(
                    JOBS.c.task_type == "daily",
                    JOBS.c.status.in_(
                        (
                            JobStatus.QUEUED.value,
                            JobStatus.RUNNING.value,
                            JobStatus.WAITING_RESOURCE.value,
                            JobStatus.PAUSE_REQUESTED.value,
                            JobStatus.CANCEL_REQUESTED.value,
                        )
                    ),
                    WORK_ITEMS.c.status.in_(
                        (
                            WorkItemStatus.QUEUED.value,
                            WorkItemStatus.WAITING_RESOURCE.value,
                        )
                    ),
                )
            ).mappings()
        )
        for row in rows:
            invocation_status = str(row["invocation_status"])
            invocation_stage = str(row["invocation_next_stage"])
            current_stage = str(row["current_stage"])
            if (
                invocation_status == "ready"
                and invocation_stage == current_stage
            ):
                continue
            if invocation_status == "succeeded":
                target_status = WorkItemStatus.SUCCEEDED
                target_stage = "daily.complete"
                diagnostic_code = None
                terminal_job_ids.append(str(row["job_id"]))
            elif invocation_status == "failed":
                target_status = WorkItemStatus.FAILED
                target_stage = current_stage
                diagnostic_code = (
                    None
                    if row["invocation_diagnostic_code"] is None
                    else str(row["invocation_diagnostic_code"])
                )
                if diagnostic_code is None:
                    raise SchedulerLeaseFencingError(
                        "failed daily invocation has no diagnostic"
                    )
                terminal_job_ids.append(str(row["job_id"]))
            elif invocation_status == "ready":
                if not invocation_stage.startswith("daily."):
                    raise SchedulerLeaseFencingError(
                        "daily invocation stage is invalid"
                    )
                target_status = WorkItemStatus.QUEUED
                target_stage = invocation_stage
                diagnostic_code = None
            else:
                continue
            revision = self._daily_checkpoint_revision(row)
            if revision is None and invocation_status != "failed":
                raise SchedulerLeaseFencingError(
                    "advanced daily invocation has no checkpoint"
                )
            updated = connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == row["work_item_id"],
                    WORK_ITEMS.c.record_version == row["record_version"],
                )
                .values(
                    status=target_status.value,
                    current_stage=target_stage,
                    business_outcome=None,
                    decision=None,
                    review_reason=None,
                    diagnostic_code=diagnostic_code,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    attempt_count=int(row["attempt_count"]) + 1,
                    ready_sequence=sequence,
                    record_version=int(row["record_version"]) + 1,
                )
            )
            if updated.rowcount != 1:
                raise SchedulerLeaseFencingError(
                    "daily work item changed during checkpoint recovery"
                )
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=str(row["work_item_id"]),
                job_id=str(row["job_id"]),
                work_item_id=str(row["work_item_id"]),
                stage=current_stage,
                sequence=sequence,
                payload={
                    "checkpoint_revision": revision,
                    "diagnostic_code": diagnostic_code,
                    "next_stage": (
                        None
                        if target_stage == "daily.complete"
                        else target_stage
                    ),
                    "outcome": "recovered",
                },
            )
        return tuple(terminal_job_ids)

    @staticmethod
    def _build_settlement_capture_stage_work(
        connection: Connection,
        *,
        grant: SchedulerLeaseGrant,
    ) -> SettlementCaptureStageWork:
        if (
            grant.owner_kind != "work_item"
            or grant.execution_kind != "settlement_capture"
            or grant.stage != SETTLEMENT_CAPTURE_STAGE
        ):
            raise RuntimeError(
                "claimed settlement capture identity is invalid"
            )
        item = (
            connection.execute(
                select(WORK_ITEMS, JOBS.c.task_type)
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(
                    WORK_ITEMS.c.work_item_id == grant.work_item_id,
                    WORK_ITEMS.c.job_id == grant.job_id,
                )
            )
            .mappings()
            .one()
        )
        invocation = (
            connection.execute(
                select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                    == grant.job_id
                )
            )
            .mappings()
            .one()
        )
        if (
            item["task_type"] != "settlement_capture"
            or item["status"] != WorkItemStatus.RUNNING.value
            or item["current_stage"] != SETTLEMENT_CAPTURE_STAGE
            or invocation["status"] not in {"collecting", "sealed"}
        ):
            raise RuntimeError(
                "claimed settlement capture changed before submission"
            )
        return SettlementCaptureStageWork(
            stage_attempt_id=grant.stage_attempt_id,
            job_id=grant.job_id,
            work_item_id=grant.work_item_id,
            stage=SETTLEMENT_CAPTURE_STAGE,
            attempt_count=int(item["attempt_count"]),
        )

    def _finish_settlement_capture_attempt(
        self,
        connection: Connection,
        *,
        grant: SchedulerLeaseGrant,
        attempt: RowMapping,
        result: SettlementCaptureStageExecution,
        sequence: int,
    ) -> None:
        if (
            result.stage_attempt_id != grant.stage_attempt_id
            or grant.owner_kind != "work_item"
            or grant.execution_kind != "settlement_capture"
            or attempt["owner_id"] != grant.work_item_id
            or attempt["consumer_job_id"] != grant.job_id
            or result.completed_stage != SETTLEMENT_CAPTURE_STAGE
            or attempt["stage"] != result.completed_stage
            or (
                result.platform_read_performed
                and result.checkpoint_revision is None
            )
        ):
            raise SchedulerLeaseFencingError(
                "settlement capture result does not match its fenced attempt"
            )
        item = (
            connection.execute(
                select(
                    WORK_ITEMS,
                    JOBS.c.task_type,
                    JOBS.c.status.label("job_status"),
                    JOBS.c.record_version.label(
                        "job_record_version"
                    ),
                    JOBS.c.current_stage.label(
                        "job_current_stage"
                    ),
                )
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(
                    WORK_ITEMS.c.work_item_id == grant.work_item_id,
                    WORK_ITEMS.c.job_id == grant.job_id,
                )
            )
            .mappings()
            .one()
        )
        invocation = (
            connection.execute(
                select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                    == grant.job_id
                )
            )
            .mappings()
            .one()
        )
        if (
            item["task_type"] != "settlement_capture"
            or item["status"] != WorkItemStatus.RUNNING.value
            or item["current_stage"] != SETTLEMENT_CAPTURE_STAGE
        ):
            raise SchedulerLeaseFencingError(
                "settlement capture work item changed before result commit"
            )

        attempt_status = "succeeded"
        attempt_diagnostic: str | None = None
        item_status = WorkItemStatus.QUEUED
        item_stage = SETTLEMENT_CAPTURE_STAGE
        item_diagnostic: str | None = None
        item_waiting_reason_kind: str | None = None
        item_waiting_reason: str | None = None

        if result.outcome == "succeeded":
            if result.next_stage is None:
                formal_matches = bool(
                    invocation["status"] == "selected"
                    and invocation["manifest_sha256"]
                    == result.manifest_sha256
                    and invocation["selection_manifest_sha256"]
                    == result.selection_manifest_sha256
                    and invocation["batch_manifest_sha256"]
                    == result.batch_manifest_sha256
                    and result.operational_capture_sha256 is None
                )
                operational_matches = bool(
                    invocation["status"] == "operational_ready"
                    and invocation["manifest_sha256"]
                    == result.operational_capture_sha256
                    and invocation["selection_manifest_sha256"] is None
                    and invocation["batch_manifest_sha256"] is None
                    and result.manifest_sha256 is None
                    and result.selection_manifest_sha256 is None
                    and result.batch_manifest_sha256 is None
                )
                if (
                    formal_matches == operational_matches
                    or invocation["diagnostic_code"] is not None
                ):
                    raise SchedulerLeaseFencingError(
                        "terminal capture does not match its result"
                    )
                item_status = WorkItemStatus.SUCCEEDED
                item_stage = "settlement_capture.complete"
            elif (
                result.next_stage != SETTLEMENT_CAPTURE_STAGE
                or invocation["status"] != "collecting"
                or result.manifest_sha256 is not None
                or result.selection_manifest_sha256 is not None
                or result.batch_manifest_sha256 is not None
                or result.operational_capture_sha256 is not None
            ):
                raise SchedulerLeaseFencingError(
                    "partial capture changed its invocation authority"
                )
        elif result.outcome == "retry":
            if (
                result.next_stage != SETTLEMENT_CAPTURE_STAGE
                or invocation["status"] not in {"collecting", "sealed"}
                or result.manifest_sha256 is not None
                or result.selection_manifest_sha256 is not None
                or result.batch_manifest_sha256 is not None
                or result.operational_capture_sha256 is not None
            ):
                raise SchedulerLeaseFencingError(
                    "capture retry changed its invocation authority"
                )
            attempt_status = "failed"
            attempt_diagnostic = result.diagnostic_code
        elif result.outcome == "waiting_external":
            if (
                result.next_stage != SETTLEMENT_CAPTURE_STAGE
                or invocation["status"] != "collecting"
                or result.manifest_sha256 is not None
                or result.selection_manifest_sha256 is not None
                or result.batch_manifest_sha256 is not None
                or result.operational_capture_sha256 is not None
            ):
                raise SchedulerLeaseFencingError(
                    "capture external wait changed its invocation authority"
                )
            attempt_status = "failed"
            attempt_diagnostic = result.diagnostic_code
            item_status = WorkItemStatus.WAITING_EXTERNAL
            item_diagnostic = result.diagnostic_code
            item_waiting_reason_kind = "external"
            item_waiting_reason = _external_waiting_reason(
                result.diagnostic_code
            )
        else:
            if (
                result.next_stage is not None
                or invocation["status"]
                in {"sealed", "selected", "operational_ready"}
                or result.manifest_sha256 is not None
                or result.selection_manifest_sha256 is not None
                or result.batch_manifest_sha256 is not None
                or result.operational_capture_sha256 is not None
            ):
                raise SchedulerLeaseFencingError(
                    "capture failure conflicts with sealed evidence"
                )
            attempt_status = "failed"
            attempt_diagnostic = result.diagnostic_code
            item_status = WorkItemStatus.FAILED
            item_diagnostic = result.diagnostic_code
            if invocation["status"] in {
                "failed",
                "selection_blocked",
            } and (
                invocation["diagnostic_code"] != result.diagnostic_code
            ):
                raise SchedulerLeaseFencingError(
                    "capture failure diagnostic changed before commit"
                )

        finished = connection.execute(
            update(STAGE_ATTEMPTS)
            .where(
                STAGE_ATTEMPTS.c.stage_attempt_id
                == attempt["stage_attempt_id"],
                STAGE_ATTEMPTS.c.status == "running",
            )
            .values(
                status=attempt_status,
                finished_sequence=sequence,
                diagnostic_code=attempt_diagnostic,
                output_fingerprint=(
                    result.selection_manifest_sha256
                    or result.manifest_sha256
                    or result.operational_capture_sha256
                ),
            )
        )
        if finished.rowcount != 1:
            raise SchedulerLeaseFencingError(
                "settlement capture attempt changed before result commit"
            )
        updated_item = connection.execute(
            update(WORK_ITEMS)
            .where(
                WORK_ITEMS.c.work_item_id == grant.work_item_id,
                WORK_ITEMS.c.record_version == item["record_version"],
            )
            .values(
                status=item_status.value,
                current_stage=item_stage,
                business_outcome=None,
                decision=None,
                review_reason=None,
                diagnostic_code=item_diagnostic,
                waiting_reason_kind=item_waiting_reason_kind,
                waiting_reason=item_waiting_reason,
                attempt_count=int(item["attempt_count"]) + 1,
                ready_sequence=sequence,
                record_version=int(item["record_version"]) + 1,
            )
        )
        if updated_item.rowcount != 1:
            raise SchedulerLeaseFencingError(
                "settlement capture item changed before result commit"
            )
        if result.outcome == "waiting_external":
            waiting_reason = _external_waiting_reason(
                result.diagnostic_code
            )
            next_job_version = int(item["job_record_version"]) + 1
            paused = connection.execute(
                update(JOBS)
                .where(
                    JOBS.c.job_id == grant.job_id,
                    JOBS.c.record_version
                    == item["job_record_version"],
                    JOBS.c.status == item["job_status"],
                )
                .values(
                    status=JobStatus.PAUSED.value,
                    diagnostic_code=result.diagnostic_code,
                    record_version=next_job_version,
                    updated_at=_utc_now(),
                )
            )
            if paused.rowcount != 1:
                raise SchedulerLeaseFencingError(
                    "settlement capture external wait changed concurrently"
                )
            self._append_event(
                connection,
                event_type="job.paused",
                aggregate_id=grant.job_id,
                record_version=next_job_version,
                payload={
                    "job_id": grant.job_id,
                    "job_status": JobStatus.PAUSED.value,
                    "current_stage": item["job_current_stage"],
                    "waiting_reason": waiting_reason,
                },
                created_at=_utc_now(),
            )
        if (
            result.outcome == "failed"
            or (
                result.outcome == "succeeded"
                and result.next_stage is None
            )
        ):
            self._retire_settlement_access(
                connection,
                job_id=grant.job_id,
                now=_utc_now(),
            )
        self._save_checkpoint(
            connection,
            owner_kind="work_item",
            owner_id=grant.work_item_id,
            job_id=grant.job_id,
            work_item_id=grant.work_item_id,
            stage=SETTLEMENT_CAPTURE_STAGE,
            sequence=sequence,
            payload={
                "checkpoint_revision": result.checkpoint_revision,
                "diagnostic_code": result.diagnostic_code,
                "manifest_sha256": result.manifest_sha256,
                "selection_manifest_sha256": (
                    result.selection_manifest_sha256
                ),
                "batch_manifest_sha256": (
                    result.batch_manifest_sha256
                ),
                "operational_capture_sha256": (
                    result.operational_capture_sha256
                ),
                "next_stage": result.next_stage,
                "outcome": result.outcome,
                "platform_read_performed": (
                    result.platform_read_performed
                ),
            },
        )

    def _reconcile_settlement_capture_invocations(
        self,
        connection: Connection,
        *,
        sequence: int,
    ) -> tuple[str, ...]:
        terminal_job_ids: list[str] = []
        rows = tuple(
            connection.execute(
                select(
                    WORK_ITEMS,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.status.label(
                        "invocation_status"
                    ),
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.manifest_sha256,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.selection_manifest_sha256,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.batch_manifest_sha256,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.diagnostic_code.label(
                        "invocation_diagnostic_code"
                    ),
                )
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .join(
                    SETTLEMENT_CAPTURE_INVOCATIONS,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                    == WORK_ITEMS.c.job_id,
                )
                .where(
                    JOBS.c.task_type == "settlement_capture",
                    JOBS.c.status.in_(
                        (
                            JobStatus.QUEUED.value,
                            JobStatus.RUNNING.value,
                            JobStatus.WAITING_RESOURCE.value,
                            JobStatus.PAUSE_REQUESTED.value,
                            JobStatus.CANCEL_REQUESTED.value,
                        )
                    ),
                    WORK_ITEMS.c.status.in_(
                        (
                            WorkItemStatus.QUEUED.value,
                            WorkItemStatus.WAITING_RESOURCE.value,
                        )
                    ),
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.status.in_(
                        (
                            "selected",
                            "operational_ready",
                            "selection_blocked",
                            "failed",
                        )
                    ),
                )
            ).mappings()
        )
        for row in rows:
            invocation_status = str(row["invocation_status"])
            selection_manifest_sha256: object | None = None
            batch_manifest_sha256: object | None = None
            if invocation_status in {
                "selected",
                "operational_ready",
            }:
                manifest_sha256 = row["manifest_sha256"]
                selection_manifest_sha256 = row[
                    "selection_manifest_sha256"
                ]
                batch_manifest_sha256 = row[
                    "batch_manifest_sha256"
                ]
                if manifest_sha256 is None or (
                    invocation_status == "selected"
                    and (
                        selection_manifest_sha256 is None
                        or batch_manifest_sha256 is None
                    )
                ) or (
                    invocation_status == "operational_ready"
                    and (
                        selection_manifest_sha256 is not None
                        or batch_manifest_sha256 is not None
                    )
                ):
                    raise SchedulerLeaseFencingError(
                        "terminal settlement capture has invalid evidence"
                    )
                target_status = WorkItemStatus.SUCCEEDED
                target_stage = "settlement_capture.complete"
                diagnostic_code = None
            else:
                manifest_sha256 = None
                target_status = WorkItemStatus.FAILED
                target_stage = SETTLEMENT_CAPTURE_STAGE
                raw_diagnostic = row["invocation_diagnostic_code"]
                if raw_diagnostic is None:
                    raise SchedulerLeaseFencingError(
                        "failed settlement capture has no diagnostic"
                    )
                diagnostic_code = str(raw_diagnostic)
            updated = connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == row["work_item_id"],
                    WORK_ITEMS.c.record_version == row["record_version"],
                )
                .values(
                    status=target_status.value,
                    current_stage=target_stage,
                    business_outcome=None,
                    decision=None,
                    review_reason=None,
                    diagnostic_code=diagnostic_code,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    attempt_count=int(row["attempt_count"]) + 1,
                    ready_sequence=sequence,
                    record_version=int(row["record_version"]) + 1,
                )
            )
            if updated.rowcount != 1:
                raise SchedulerLeaseFencingError(
                    "settlement capture changed during terminal recovery"
                )
            self._retire_settlement_access(
                connection,
                job_id=str(row["job_id"]),
                now=_utc_now(),
            )
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=str(row["work_item_id"]),
                job_id=str(row["job_id"]),
                work_item_id=str(row["work_item_id"]),
                stage=SETTLEMENT_CAPTURE_STAGE,
                sequence=sequence,
                payload={
                    "checkpoint_revision": None,
                    "diagnostic_code": diagnostic_code,
                    "manifest_sha256": manifest_sha256,
                    "selection_manifest_sha256": (
                        selection_manifest_sha256
                    ),
                    "batch_manifest_sha256": batch_manifest_sha256,
                    "operational_capture_sha256": (
                        manifest_sha256
                        if invocation_status
                        == "operational_ready"
                        else None
                    ),
                    "next_stage": None,
                    "outcome": "recovered",
                    "platform_read_performed": False,
                },
            )
            terminal_job_ids.append(str(row["job_id"]))
        return tuple(terminal_job_ids)

    def _prepare_ocr_generations(
        self,
        connection: Connection,
        *,
        now: str,
        sequence: int,
    ) -> None:
        rows = tuple(
            connection.execute(
                select(WORK_ITEMS, JOBS.c.status.label("job_status"))
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(
                    JOBS.c.task_type == "audit",
                    JOBS.c.ocr_execution_mode == "local",
                    JOBS.c.status.in_(
                        (
                            JobStatus.QUEUED.value,
                            JobStatus.RUNNING.value,
                            JobStatus.WAITING_RESOURCE.value,
                        )
                    ),
                    WORK_ITEMS.c.download_complete == 1,
                    WORK_ITEMS.c.loading_ocr_complete == 0,
                    WORK_ITEMS.c.unloading_ocr_complete == 0,
                    WORK_ITEMS.c.ocr_generation_id.is_(None),
                    WORK_ITEMS.c.status.in_(
                        (
                            WorkItemStatus.QUEUED.value,
                            WorkItemStatus.WAITING_RESOURCE.value,
                        )
                    ),
                )
            ).mappings()
        )
        for item in rows:
            missing_evidence = (
                item["loading_image_sha256"] is None
                or item["unloading_image_sha256"] is None
                or item["loading_image_relative_path"] is None
                or item["unloading_image_relative_path"] is None
            )
            if (
                missing_evidence
                and item["fixture_outcome"] == "awaiting_review"
                and item["fixture_review_reason"] == "missing_ticket"
            ):
                work_item_id = str(item["work_item_id"])
                job_id = str(item["job_id"])
                self._insert_completed_attempt(
                    connection,
                    owner_kind="work_item",
                    owner_id=work_item_id,
                    consumer_job_id=job_id,
                    work_item_id=work_item_id,
                    stage="audit.compare",
                    sequence=sequence,
                )
                self._insert_completed_attempt(
                    connection,
                    owner_kind="work_item",
                    owner_id=work_item_id,
                    consumer_job_id=job_id,
                    work_item_id=work_item_id,
                    stage="audit.finalize",
                    sequence=sequence,
                )
                result = connection.execute(
                    update(WORK_ITEMS)
                    .where(
                        WORK_ITEMS.c.work_item_id == work_item_id,
                        WORK_ITEMS.c.record_version
                        == item["record_version"],
                    )
                    .values(
                        status=WorkItemStatus.WAITING_USER.value,
                        current_stage="audit.finalize",
                        business_outcome="awaiting_review",
                        decision="review",
                        review_reason="missing_ticket",
                        diagnostic_code=None,
                        platform_loading_net=(
                            item["fixture_platform_loading_net"]
                        ),
                        platform_unloading_net=(
                            item["fixture_platform_unloading_net"]
                        ),
                        ticket_loading_net=None,
                        ticket_unloading_net=None,
                        waiting_reason_kind="user",
                        waiting_reason="missing_ticket",
                        attempt_count=int(item["attempt_count"]) + 1,
                        record_version=int(item["record_version"]) + 1,
                    )
                )
                if result.rowcount != 1:
                    raise RuntimeError(
                        "missing-ticket work item changed during scheduling"
                    )
                self._save_checkpoint(
                    connection,
                    owner_kind="work_item",
                    owner_id=work_item_id,
                    job_id=job_id,
                    work_item_id=work_item_id,
                    stage="audit.finalize",
                    sequence=sequence,
                    payload={
                        "business_outcome": "awaiting_review",
                        "committed": True,
                        "decision": "review",
                        "review_reason": "missing_ticket",
                    },
                )
                continue
            pipeline_fingerprint = item["pipeline_fingerprint"]
            if self._ocr_execution_backend is None:
                connection.execute(
                    update(WORK_ITEMS)
                    .where(WORK_ITEMS.c.work_item_id == item["work_item_id"])
                    .values(
                        status=WorkItemStatus.FAILED.value,
                        business_outcome=None,
                        review_reason=None,
                        diagnostic_code="OCR-LOCAL-RUNTIME-UNAVAILABLE",
                        record_version=int(item["record_version"]) + 1,
                    )
                )
                continue
            if (
                pipeline_fingerprint is None
                or item["loading_image_sha256"] is None
                or item["unloading_image_sha256"] is None
                or item["loading_image_relative_path"] is None
                or item["unloading_image_relative_path"] is None
            ):
                connection.execute(
                    update(WORK_ITEMS)
                    .where(WORK_ITEMS.c.work_item_id == item["work_item_id"])
                    .values(
                        status=WorkItemStatus.FAILED.value,
                        business_outcome=None,
                        review_reason=None,
                        diagnostic_code="OCR-EVIDENCE-INPUT-INCOMPLETE",
                        record_version=int(item["record_version"]) + 1,
                    )
                )
                continue
            generation_id = uuid4().hex
            runtime_kind = self._ocr_execution_backend.primary_runtime_kind
            identity = self._ocr_execution_backend.identity_for(runtime_kind)
            runtime_pipeline_fingerprint = (
                self._ocr_execution_backend.pipeline_fingerprint_for(
                    runtime_kind,
                    pipeline_contract_fingerprint=str(pipeline_fingerprint),
                )
            )
            connection.execute(
                OCR_RUN_GENERATIONS.insert().values(
                    generation_id=generation_id,
                    work_item_id=item["work_item_id"],
                    pipeline_fingerprint=runtime_pipeline_fingerprint,
                    primary_runtime_kind=runtime_kind,
                    next_runtime_kind=runtime_kind,
                    status="queued",
                    record_version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == item["work_item_id"])
                .values(
                    ocr_generation_id=generation_id,
                    current_stage="audit.recognize",
                    ready_sequence=WORK_ITEMS.c.ready_sequence + 1,
                    record_version=int(item["record_version"]) + 1,
                )
            )
            register_shared_consumer(
                connection,
                work_item_id=str(item["work_item_id"]),
                image_role="loading",
                image_sha256=str(item["loading_image_sha256"]),
                image_relative_path=str(item["loading_image_relative_path"]),
                pipeline_fingerprint=runtime_pipeline_fingerprint,
                execution_mode="local",
                runtime_kind=identity.runtime_kind,
                profile_id=identity.profile_id,
                runtime_fingerprint=identity.runtime_fingerprint,
            )
            register_shared_consumer(
                connection,
                work_item_id=str(item["work_item_id"]),
                image_role="unloading",
                image_sha256=str(item["unloading_image_sha256"]),
                image_relative_path=str(item["unloading_image_relative_path"]),
                pipeline_fingerprint=runtime_pipeline_fingerprint,
                execution_mode="local",
                runtime_kind=identity.runtime_kind,
                profile_id=identity.profile_id,
                runtime_fingerprint=identity.runtime_fingerprint,
            )

    @staticmethod
    def _build_ocr_stage_work(
        connection: Connection,
        *,
        grant: SchedulerLeaseGrant,
    ) -> OcrStageWork:
        shared = (
            connection.execute(
                select(SHARED_EVIDENCE_WORK).where(
                    SHARED_EVIDENCE_WORK.c.shared_work_id == grant.owner_id
                )
            )
            .mappings()
            .one()
        )
        required_values = (
            grant.runtime_kind,
            grant.profile_id,
            grant.runtime_fingerprint,
            grant.pipeline_fingerprint,
            shared["image_sha256"],
            shared["image_relative_path"],
        )
        if any(value is None for value in required_values):
            raise RuntimeError("claimed OCR work is missing frozen identity")
        identity = OcrRuntimeIdentity(
            runtime_kind=str(grant.runtime_kind),  # type: ignore[arg-type]
            profile_id=str(grant.profile_id),
            runtime_fingerprint=str(grant.runtime_fingerprint),
        )
        if (
            grant.owner_kind != "shared_evidence"
            or shared["execution_mode"] != "local"
            or shared["runtime_kind"] != identity.runtime_kind
            or shared["profile_id"] != identity.profile_id
            or shared["runtime_fingerprint"] != identity.runtime_fingerprint
            or shared["pipeline_fingerprint"] != grant.pipeline_fingerprint
        ):
            raise RuntimeError("claimed shared OCR identity changed before submission")
        return OcrStageWork(
            stage_attempt_id=grant.stage_attempt_id,
            shared_work_id=str(shared["shared_work_id"]),
            pipeline_fingerprint=str(grant.pipeline_fingerprint),
            identity=identity,
            image=OcrImageWork(
                image_sha256=str(shared["image_sha256"]),
                relative_path=str(shared["image_relative_path"]),
            ),
        )

    def _finish_ocr_image_attempt(
        self,
        connection: Connection,
        *,
        grant: SchedulerLeaseGrant,
        attempt: RowMapping,
        result: OcrStageExecution,
        sequence: int,
        now: str,
    ) -> None:
        if (
            result.stage_attempt_id != grant.stage_attempt_id
            or result.shared_work_id != grant.owner_id
            or result.identity.runtime_kind != grant.runtime_kind
            or result.identity.profile_id != grant.profile_id
            or result.identity.runtime_fingerprint != grant.runtime_fingerprint
            or result.pipeline_fingerprint != grant.pipeline_fingerprint
        ):
            raise SchedulerLeaseFencingError(
                "OCR result identity does not match its fenced stage attempt"
            )
        shared = (
            connection.execute(
                select(SHARED_EVIDENCE_WORK).where(
                    SHARED_EVIDENCE_WORK.c.shared_work_id
                    == result.shared_work_id
                )
            )
            .mappings()
            .one()
        )
        if (
            shared["status"] != "running"
            or shared["execution_mode"] != "local"
            or shared["image_sha256"] != result.image.image_sha256
            or shared["pipeline_fingerprint"] != result.pipeline_fingerprint
            or shared["runtime_kind"] != result.identity.runtime_kind
            or shared["profile_id"] != result.identity.profile_id
            or shared["runtime_fingerprint"]
            != result.identity.runtime_fingerprint
        ):
            raise SchedulerLeaseFencingError(
                "shared OCR identity changed before commit"
            )
        if result.succeeded:
            assert result.output is not None
            connection.execute(
                update(STAGE_ATTEMPTS)
                .where(
                    STAGE_ATTEMPTS.c.stage_attempt_id
                    == attempt["stage_attempt_id"],
                    STAGE_ATTEMPTS.c.status == "running",
                )
                .values(
                    status="succeeded",
                    finished_sequence=sequence,
                    output_fingerprint=result.output.output_fingerprint,
                    discarded=0,
                    diagnostic_code=None,
                    error_kind=None,
                )
            )
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(
                    SHARED_EVIDENCE_WORK.c.shared_work_id
                    == result.shared_work_id,
                    SHARED_EVIDENCE_WORK.c.record_version
                    == shared["record_version"],
                )
                .values(
                    status="succeeded",
                    artifact_ref=f"local-ocr:{result.shared_work_id}",
                    output_json=result.output.output_json,
                    output_fingerprint=result.output.output_fingerprint,
                    diagnostic_code=None,
                    record_version=int(shared["record_version"]) + 1,
                    attempt_count=int(shared["attempt_count"]) + 1,
                )
            )
        else:
            assert result.error_kind is not None
            fallback_allowed = (
                result.identity.runtime_kind == "gpu"
                and result.error_kind.gpu_fallback_allowed
                and self._ocr_execution_backend is not None
                and self._ocr_execution_backend.has_runtime("cpu")
            )
            connection.execute(
                update(STAGE_ATTEMPTS)
                .where(
                    STAGE_ATTEMPTS.c.stage_attempt_id
                    == attempt["stage_attempt_id"],
                    STAGE_ATTEMPTS.c.status == "running",
                )
                .values(
                    status="failed",
                    finished_sequence=sequence,
                    discarded=1,
                    diagnostic_code=result.diagnostic_code,
                    error_kind=result.error_kind.value,
                )
            )
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(
                    SHARED_EVIDENCE_WORK.c.shared_work_id
                    == result.shared_work_id,
                    SHARED_EVIDENCE_WORK.c.record_version
                    == shared["record_version"],
                )
                .values(
                    status="failed",
                    artifact_ref=None,
                    output_json=None,
                    output_fingerprint=None,
                    diagnostic_code=result.diagnostic_code,
                    record_version=int(shared["record_version"]) + 1,
                    attempt_count=int(shared["attempt_count"]) + 1,
                    retry_generation=shared["retry_budget"],
                )
            )
            if fallback_allowed:
                self._restart_consumers_on_cpu(
                    connection,
                    failed_shared_work_id=result.shared_work_id,
                    failed_pipeline_fingerprint=result.pipeline_fingerprint,
                    diagnostic_code=result.diagnostic_code,
                    sequence=sequence,
                    now=now,
                )
            else:
                propagate_shared_failure_once_in_transaction(
                    connection,
                    shared_work_id=result.shared_work_id,
                    diagnostic_code=(
                        result.diagnostic_code or "OCR-TECHNICAL-FAILURE"
                    ),
                )
        self._save_checkpoint(
            connection,
            owner_kind="shared_evidence",
            owner_id=result.shared_work_id,
            job_id=None,
            work_item_id=None,
            stage="audit.recognize",
            sequence=sequence,
            payload={
                "committed": result.succeeded,
                "diagnostic_code": result.diagnostic_code,
                "discarded": not result.succeeded,
                "image_sha256": result.image.image_sha256,
                "pipeline_fingerprint": result.pipeline_fingerprint,
                "profile_id": result.identity.profile_id,
                "runtime_fingerprint": result.identity.runtime_fingerprint,
                "runtime_kind": result.identity.runtime_kind,
            },
        )

    def _restart_consumers_on_cpu(
        self,
        connection: Connection,
        *,
        failed_shared_work_id: str,
        failed_pipeline_fingerprint: str,
        diagnostic_code: str | None,
        sequence: int,
        now: str,
    ) -> None:
        assert self._ocr_execution_backend is not None
        cpu_identity = self._ocr_execution_backend.identity_for("cpu")
        consumers = tuple(
            connection.execute(
                select(
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                    WORK_ITEMS,
                    OCR_RUN_GENERATIONS,
                )
                .join(
                    WORK_ITEMS,
                    WORK_ITEMS.c.work_item_id
                    == SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                )
                .join(
                    OCR_RUN_GENERATIONS,
                    OCR_RUN_GENERATIONS.c.work_item_id
                    == WORK_ITEMS.c.work_item_id,
                )
                .where(
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id
                    == failed_shared_work_id,
                    SHARED_EVIDENCE_CONSUMERS.c.status.in_(("waiting", "paused")),
                    OCR_RUN_GENERATIONS.c.next_runtime_kind == "gpu",
                    OCR_RUN_GENERATIONS.c.pipeline_fingerprint
                    == failed_pipeline_fingerprint,
                    OCR_RUN_GENERATIONS.c.status.in_(("queued", "running")),
                )
            ).mappings()
        )
        seen_work_items: set[str] = set()
        for row in consumers:
            work_item_id = str(row["work_item_id"])
            if work_item_id in seen_work_items:
                continue
            seen_work_items.add(work_item_id)
            contract_fingerprint = str(row["pipeline_fingerprint"])
            cpu_pipeline_fingerprint = (
                self._ocr_execution_backend.pipeline_fingerprint_for(
                    "cpu",
                    pipeline_contract_fingerprint=contract_fingerprint,
                )
            )
            completed_images = [
                role
                for role, output in (
                    ("loading", row["loading_output_json"]),
                    ("unloading", row["unloading_output_json"]),
                )
                if output is not None
            ]
            local_gpu_shared_ids = select(
                SHARED_EVIDENCE_WORK.c.shared_work_id
            ).where(
                SHARED_EVIDENCE_WORK.c.execution_mode == "local",
                SHARED_EVIDENCE_WORK.c.runtime_kind == "gpu",
            )
            connection.execute(
                update(SHARED_EVIDENCE_CONSUMERS)
                .where(
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id == work_item_id,
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id.in_(
                        local_gpu_shared_ids
                    ),
                    SHARED_EVIDENCE_CONSUMERS.c.status.in_(
                        ("waiting", "paused", "consumed")
                    ),
                )
                .values(status="cancelled")
            )
            connection.execute(
                update(OCR_RUN_GENERATIONS)
                .where(
                    OCR_RUN_GENERATIONS.c.generation_id
                    == row["generation_id"],
                    OCR_RUN_GENERATIONS.c.record_version
                    == row["record_version_1"],
                )
                .values(
                    pipeline_fingerprint=cpu_pipeline_fingerprint,
                    next_runtime_kind="cpu",
                    status="fallback_wait",
                    committed_runtime_kind=None,
                    committed_profile_id=None,
                    committed_runtime_fingerprint=None,
                    loading_output_json=None,
                    unloading_output_json=None,
                    loading_output_fingerprint=None,
                    unloading_output_fingerprint=None,
                    diagnostic_code=diagnostic_code,
                    record_version=int(row["record_version_1"]) + 1,
                    updated_at=now,
                )
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == work_item_id,
                    WORK_ITEMS.c.record_version == row["record_version"],
                )
                .values(
                    status=WorkItemStatus.QUEUED.value,
                    current_stage="audit.recognize.loading",
                    loading_ocr_complete=0,
                    unloading_ocr_complete=0,
                    attempt_count=int(row["attempt_count"]) + 1,
                    diagnostic_code=None,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    ready_sequence=sequence,
                    record_version=int(row["record_version"]) + 1,
                )
            )
            register_shared_consumer(
                connection,
                work_item_id=work_item_id,
                image_role="loading",
                image_sha256=str(row["loading_image_sha256"]),
                image_relative_path=str(row["loading_image_relative_path"]),
                pipeline_fingerprint=cpu_pipeline_fingerprint,
                execution_mode="local",
                runtime_kind="cpu",
                profile_id=cpu_identity.profile_id,
                runtime_fingerprint=cpu_identity.runtime_fingerprint,
            )
            register_shared_consumer(
                connection,
                work_item_id=work_item_id,
                image_role="unloading",
                image_sha256=str(row["unloading_image_sha256"]),
                image_relative_path=str(row["unloading_image_relative_path"]),
                pipeline_fingerprint=cpu_pipeline_fingerprint,
                execution_mode="local",
                runtime_kind="cpu",
                profile_id=cpu_identity.profile_id,
                runtime_fingerprint=cpu_identity.runtime_fingerprint,
            )
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=work_item_id,
                job_id=str(row["job_id"]),
                work_item_id=work_item_id,
                stage="audit.recognize.fallback",
                sequence=sequence,
                payload={
                    "completed_images": completed_images,
                    "discarded": True,
                    "from_pipeline_fingerprint": failed_pipeline_fingerprint,
                    "from_runtime_kind": "gpu",
                    "generation_id": str(row["generation_id"]),
                    "to_pipeline_fingerprint": cpu_pipeline_fingerprint,
                    "to_runtime_kind": "cpu",
                },
            )

    def _finalize_runtime_only_items(
        self,
        connection: Connection,
        *,
        sequence: int,
    ) -> None:
        rows = tuple(
            connection.execute(
                select(WORK_ITEMS, JOBS.c.job_kind)
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .join(
                    OCR_RUN_GENERATIONS,
                    OCR_RUN_GENERATIONS.c.work_item_id
                    == WORK_ITEMS.c.work_item_id,
                )
                .where(
                    JOBS.c.job_kind.in_(
                        ("test_fixture", "observation")
                    ),
                    JOBS.c.ocr_execution_mode == "local",
                    OCR_RUN_GENERATIONS.c.status == "succeeded",
                    WORK_ITEMS.c.loading_ocr_complete == 1,
                    WORK_ITEMS.c.unloading_ocr_complete == 1,
                    WORK_ITEMS.c.status.in_(
                        (
                            WorkItemStatus.QUEUED.value,
                            WorkItemStatus.WAITING_RESOURCE.value,
                        )
                    ),
                )
            ).mappings()
        )
        for item in rows:
            connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == item["work_item_id"],
                    WORK_ITEMS.c.record_version == item["record_version"],
                )
                .values(
                    status=WorkItemStatus.SUCCEEDED.value,
                    current_stage="audit.recognize.complete",
                    business_outcome=None,
                    decision=None,
                    review_reason=None,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    record_version=int(item["record_version"]) + 1,
                )
            )
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=str(item["work_item_id"]),
                job_id=str(item["job_id"]),
                work_item_id=str(item["work_item_id"]),
                stage="audit.recognize.complete",
                sequence=sequence,
                payload={
                    "business_outcome": None,
                    "committed": True,
                    "runtime_only": True,
                },
            )

    def _finalize_local_business_audit_items(
        self,
        connection: Connection,
        *,
        sequence: int,
    ) -> None:
        rows = tuple(
            connection.execute(
                select(
                    WORK_ITEMS,
                    OCR_RUN_GENERATIONS.c.loading_output_json.label(
                        "generation_loading_output_json"
                    ),
                    OCR_RUN_GENERATIONS.c.unloading_output_json.label(
                        "generation_unloading_output_json"
                    ),
                    OCR_RUN_GENERATIONS.c.committed_runtime_fingerprint.label(
                        "generation_runtime_fingerprint"
                    ),
                )
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .join(
                    OCR_RUN_GENERATIONS,
                    OCR_RUN_GENERATIONS.c.work_item_id
                    == WORK_ITEMS.c.work_item_id,
                )
                .where(
                    JOBS.c.job_kind == "business",
                    JOBS.c.task_type == "audit",
                    JOBS.c.ocr_execution_mode == "local",
                    OCR_RUN_GENERATIONS.c.status == "succeeded",
                    WORK_ITEMS.c.loading_ocr_complete == 1,
                    WORK_ITEMS.c.unloading_ocr_complete == 1,
                    WORK_ITEMS.c.status.in_(
                        (
                            WorkItemStatus.QUEUED.value,
                            WorkItemStatus.WAITING_RESOURCE.value,
                        )
                    ),
                )
            ).mappings()
        )
        for item in rows:
            work_item_id = str(item["work_item_id"])
            job_id = str(item["job_id"])
            diagnostic_code: str | None = None
            evaluation = None
            try:
                if self._local_audit_evaluator is None:
                    raise LocalAuditTechnicalError(
                        "local audit evaluator is unavailable",
                        diagnostic_code="AUDIT-LOCAL-EVALUATOR-UNAVAILABLE",
                    )
                required_values = {
                    "loading image": item["loading_image_sha256"],
                    "unloading image": item["unloading_image_sha256"],
                    "platform loading weight": item[
                        "fixture_platform_loading_net"
                    ],
                    "platform unloading weight": item[
                        "fixture_platform_unloading_net"
                    ],
                    "pipeline": item["pipeline_fingerprint"],
                    "runtime": item["generation_runtime_fingerprint"],
                    "loading OCR": item["generation_loading_output_json"],
                    "unloading OCR": item[
                        "generation_unloading_output_json"
                    ],
                }
                if any(value is None for value in required_values.values()):
                    raise LocalAuditTechnicalError(
                        "local audit committed evidence is incomplete",
                        diagnostic_code="AUDIT-LOCAL-EVIDENCE-INCOMPLETE",
                    )
                evaluation = self._local_audit_evaluator.evaluate(
                    LocalAuditEvaluationInput(
                        work_item_id=work_item_id,
                        snapshot_id=f"{job_id}:{work_item_id}",
                        loading_image_sha256=str(
                            required_values["loading image"]
                        ),
                        unloading_image_sha256=str(
                            required_values["unloading image"]
                        ),
                        platform_loading_net=str(
                            required_values["platform loading weight"]
                        ),
                        platform_unloading_net=str(
                            required_values["platform unloading weight"]
                        ),
                        pipeline_fingerprint=str(
                            required_values["pipeline"]
                        ),
                        runtime_fingerprint=str(required_values["runtime"]),
                        loading_output_json=str(
                            required_values["loading OCR"]
                        ),
                        unloading_output_json=str(
                            required_values["unloading OCR"]
                        ),
                    )
                )
            except LocalAuditTechnicalError as exc:
                diagnostic_code = exc.diagnostic_code
            except Exception:
                diagnostic_code = "AUDIT-LOCAL-EVALUATION-FAILED"

            if diagnostic_code is not None:
                self._insert_completed_attempt(
                    connection,
                    owner_kind="work_item",
                    owner_id=work_item_id,
                    consumer_job_id=job_id,
                    work_item_id=work_item_id,
                    stage="audit.role_validate",
                    sequence=sequence,
                    diagnostic_code=diagnostic_code,
                )
                connection.execute(
                    update(WORK_ITEMS)
                    .where(
                        WORK_ITEMS.c.work_item_id == work_item_id,
                        WORK_ITEMS.c.record_version
                        == item["record_version"],
                    )
                    .values(
                        status=WorkItemStatus.FAILED.value,
                        current_stage="audit.role_validate",
                        business_outcome=None,
                        decision="failed",
                        review_reason=None,
                        ticket_loading_net=None,
                        ticket_unloading_net=None,
                        diagnostic_code=diagnostic_code,
                        attempt_count=int(item["attempt_count"]) + 1,
                        waiting_reason_kind=None,
                        waiting_reason=None,
                        record_version=int(item["record_version"]) + 1,
                    )
                )
                self._save_checkpoint(
                    connection,
                    owner_kind="work_item",
                    owner_id=work_item_id,
                    job_id=job_id,
                    work_item_id=work_item_id,
                    stage="audit.role_validate",
                    sequence=sequence,
                    payload={
                        "business_outcome": None,
                        "committed": True,
                        "diagnostic_code": diagnostic_code,
                    },
                )
                continue

            assert evaluation is not None
            for stage in (
                "audit.role_validate",
                "audit.compare",
                "audit.finalize",
            ):
                self._insert_completed_attempt(
                    connection,
                    owner_kind="work_item",
                    owner_id=work_item_id,
                    consumer_job_id=job_id,
                    work_item_id=work_item_id,
                    stage=stage,
                    sequence=sequence,
                )
            waiting_user = evaluation.business_outcome == "awaiting_review"
            connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == work_item_id,
                    WORK_ITEMS.c.record_version == item["record_version"],
                )
                .values(
                    status=(
                        WorkItemStatus.WAITING_USER.value
                        if waiting_user
                        else WorkItemStatus.SUCCEEDED.value
                    ),
                    current_stage="audit.finalize",
                    business_outcome=evaluation.business_outcome,
                    platform_loading_net=str(
                        item["fixture_platform_loading_net"]
                    ),
                    platform_unloading_net=str(
                        item["fixture_platform_unloading_net"]
                    ),
                    ticket_loading_net=evaluation.ticket_loading_net,
                    ticket_unloading_net=evaluation.ticket_unloading_net,
                    decision=evaluation.decision,
                    review_reason=evaluation.review_reason,
                    diagnostic_code=None,
                    attempt_count=int(item["attempt_count"]) + 3,
                    waiting_reason_kind="user" if waiting_user else None,
                    waiting_reason=(
                        evaluation.review_reason if waiting_user else None
                    ),
                    record_version=int(item["record_version"]) + 1,
                )
            )
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=work_item_id,
                job_id=job_id,
                work_item_id=work_item_id,
                stage="audit.finalize",
                sequence=sequence,
                payload={
                    "business_outcome": evaluation.business_outcome,
                    "committed": True,
                    "decision": evaluation.decision,
                    "review_reason": evaluation.review_reason,
                },
            )

    def _finish_work_item_attempt(
        self,
        connection: Connection,
        *,
        attempt: RowMapping,
        sequence: int,
    ) -> None:
        work_item_id = str(attempt["owner_id"])
        item = (
            connection.execute(select(WORK_ITEMS).where(WORK_ITEMS.c.work_item_id == work_item_id))
            .mappings()
            .one()
        )
        job_id = str(item["job_id"])
        if WorkItemStatus(str(item["status"])).is_terminal:
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=work_item_id,
                job_id=job_id,
                work_item_id=work_item_id,
                stage=str(attempt["stage"]),
                sequence=sequence,
                payload={
                    "committed": False,
                    "ignored_for_terminal_item": True,
                },
            )
            return
        if attempt["stage"] == "audit.download_evidence":
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == work_item_id)
                .values(
                    status=WorkItemStatus.QUEUED.value,
                    current_stage="audit.recognize.loading",
                    download_complete=1,
                    attempt_count=int(item["attempt_count"]) + 1,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    ready_sequence=sequence,
                    record_version=int(item["record_version"]) + 1,
                )
            )
        elif attempt["stage"] == "loading_probe.query":
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == work_item_id)
                .values(
                    status=WorkItemStatus.SUCCEEDED.value,
                    current_stage="loading_probe.complete",
                    attempt_count=int(item["attempt_count"]) + 1,
                    waiting_reason_kind=None,
                    waiting_reason=None,
                    record_version=int(item["record_version"]) + 1,
                )
            )
        self._save_checkpoint(
            connection,
            owner_kind="work_item",
            owner_id=work_item_id,
            job_id=job_id,
            work_item_id=work_item_id,
            stage=str(attempt["stage"]),
            sequence=sequence,
            payload={"committed": True},
        )

    def _finish_shared_attempt(
        self,
        connection: Connection,
        *,
        shared_work_id: str,
        sequence: int,
        diagnostic_code: str | None,
    ) -> None:
        shared = (
            connection.execute(
                select(SHARED_EVIDENCE_WORK).where(
                    SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id
                )
            )
            .mappings()
            .one()
        )
        if diagnostic_code is None:
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id)
                .values(
                    status="succeeded",
                    artifact_ref=f"fake-ocr:{shared_work_id}",
                    diagnostic_code=None,
                )
            )
        elif int(shared["retry_generation"]) < int(shared["retry_budget"]):
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id)
                .values(
                    status="queued",
                    artifact_ref=None,
                    diagnostic_code=None,
                    record_version=int(shared["record_version"]) + 1,
                    retry_generation=int(shared["retry_generation"]) + 1,
                    attempt_count=int(shared["attempt_count"]) + 1,
                    failure_propagation_id=None,
                )
            )
            retry_attempt_id = uuid4().hex
            connection.execute(
                STAGE_ATTEMPTS.insert().values(
                    stage_attempt_id=retry_attempt_id,
                    owner_kind="shared_evidence",
                    owner_id=shared_work_id,
                    consumer_job_id=None,
                    work_item_id=None,
                    stage="audit.recognize",
                    status="queued",
                    resource_name=None,
                    attempt_number=attempt_number(
                        connection,
                        owner_kind="shared_evidence",
                        owner_id=shared_work_id,
                        stage="audit.recognize",
                    ),
                    started_sequence=sequence,
                )
            )
            running_consumers = tuple(
                connection.execute(
                    select(WORK_ITEMS)
                    .join(
                        SHARED_EVIDENCE_CONSUMERS,
                        SHARED_EVIDENCE_CONSUMERS.c.work_item_id == WORK_ITEMS.c.work_item_id,
                    )
                    .where(
                        SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == shared_work_id,
                        SHARED_EVIDENCE_CONSUMERS.c.status == "waiting",
                        WORK_ITEMS.c.status == WorkItemStatus.RUNNING.value,
                    )
                ).mappings()
            )
            for item in running_consumers:
                if not bool(item["loading_ocr_complete"]):
                    current_stage = "audit.recognize.loading"
                elif not bool(item["unloading_ocr_complete"]):
                    current_stage = "audit.recognize.unloading"
                else:
                    current_stage = "audit.compare"
                connection.execute(
                    update(WORK_ITEMS)
                    .where(
                        WORK_ITEMS.c.work_item_id == item["work_item_id"],
                        WORK_ITEMS.c.record_version == item["record_version"],
                        WORK_ITEMS.c.status == WorkItemStatus.RUNNING.value,
                    )
                    .values(
                        status=WorkItemStatus.QUEUED.value,
                        current_stage=current_stage,
                        waiting_reason_kind=None,
                        waiting_reason=None,
                        ready_sequence=sequence,
                        record_version=int(item["record_version"]) + 1,
                    )
                )
        else:
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id)
                .values(
                    status="failed",
                    diagnostic_code=diagnostic_code,
                    attempt_count=int(shared["attempt_count"]) + 1,
                )
            )
            propagate_shared_failure_once_in_transaction(
                connection,
                shared_work_id=shared_work_id,
                diagnostic_code=diagnostic_code,
            )
        self._save_checkpoint(
            connection,
            owner_kind="shared_evidence",
            owner_id=shared_work_id,
            job_id=None,
            work_item_id=None,
            stage="audit.recognize",
            sequence=sequence,
            payload={
                "committed": diagnostic_code is None,
                "diagnostic_code": diagnostic_code,
            },
        )

    def _apply_control_boundaries(
        self,
        connection: Connection,
        *,
        sequence: int,
        now: str,
    ) -> tuple[tuple[str, ...], tuple[str, ...]]:
        terminal_daily_job_ids: list[str] = []
        terminal_settlement_job_ids: list[str] = []
        controlled_jobs = tuple(
            connection.execute(
                select(JOBS).where(
                    JOBS.c.status.in_(
                        (
                            JobStatus.PAUSE_REQUESTED.value,
                            JobStatus.CANCEL_REQUESTED.value,
                        )
                    )
                )
            ).mappings()
        )
        for job in controlled_jobs:
            job_id = str(job["job_id"])
            active_attempt = connection.execute(
                select(LEASES.c.lease_id).where(
                    LEASES.c.job_id == job_id,
                    LEASES.c.status == "active",
                )
            ).first()
            if active_attempt is not None:
                continue
            if job["status"] == JobStatus.CANCEL_REQUESTED.value:
                items = tuple(
                    connection.execute(
                        select(WORK_ITEMS).where(WORK_ITEMS.c.job_id == job_id)
                    ).mappings()
                )
                for item in items:
                    if item["status"] in {
                        WorkItemStatus.SUCCEEDED.value,
                        WorkItemStatus.FAILED.value,
                        WorkItemStatus.CANCELLED.value,
                    }:
                        continue
                    connection.execute(
                        update(WORK_ITEMS)
                        .where(WORK_ITEMS.c.work_item_id == item["work_item_id"])
                        .values(
                            status=WorkItemStatus.CANCELLED.value,
                            end_reason=(
                                "not_processed"
                                if int(item["attempt_count"]) == 0
                                else "cancelled_by_user"
                            ),
                            waiting_reason_kind=None,
                            waiting_reason=None,
                            record_version=int(item["record_version"]) + 1,
                        )
                    )
                connection.execute(
                    update(SHARED_EVIDENCE_CONSUMERS)
                    .where(
                        SHARED_EVIDENCE_CONSUMERS.c.work_item_id.in_(
                            select(WORK_ITEMS.c.work_item_id).where(WORK_ITEMS.c.job_id == job_id)
                        ),
                        SHARED_EVIDENCE_CONSUMERS.c.status.in_(("waiting", "paused")),
                    )
                    .values(status="cancelled")
                )
                target_status = JobStatus.CANCELLED
                checkpoint_stage = "job.cancelled"
            else:
                connection.execute(
                    update(WORK_ITEMS)
                    .where(
                        WORK_ITEMS.c.job_id == job_id,
                        WORK_ITEMS.c.status.in_(
                            (
                                WorkItemStatus.RUNNING.value,
                                WorkItemStatus.WAITING_RESOURCE.value,
                            )
                        ),
                    )
                    .values(
                        status=WorkItemStatus.QUEUED.value,
                        waiting_reason_kind=None,
                        waiting_reason=None,
                        ready_sequence=sequence,
                        record_version=WORK_ITEMS.c.record_version + 1,
                    )
                )
                connection.execute(
                    update(SHARED_EVIDENCE_CONSUMERS)
                    .where(
                        SHARED_EVIDENCE_CONSUMERS.c.work_item_id.in_(
                            select(WORK_ITEMS.c.work_item_id).where(WORK_ITEMS.c.job_id == job_id)
                        ),
                        SHARED_EVIDENCE_CONSUMERS.c.status == "waiting",
                    )
                    .values(status="paused")
                )
                target_status = JobStatus.PAUSED
                checkpoint_stage = "job.paused"
            next_version = int(job["record_version"]) + 1
            connection.execute(
                update(JOBS)
                .where(JOBS.c.job_id == job_id)
                .values(
                    status=target_status.value,
                    record_version=next_version,
                    updated_at=now,
                )
            )
            if target_status is JobStatus.CANCELLED:
                connection.execute(
                    update(CONFLICT_KEYS).where(CONFLICT_KEYS.c.job_id == job_id).values(active=0)
                )
                if job["task_type"] == "daily":
                    terminal_daily_job_ids.append(job_id)
                elif job["task_type"] == "settlement_capture":
                    terminal_settlement_job_ids.append(job_id)
                    self._retire_settlement_access(
                        connection,
                        job_id=job_id,
                        now=now,
                    )
            self._append_event(
                connection,
                event_type=(
                    "job.cancelled" if target_status is JobStatus.CANCELLED else "job.paused"
                ),
                aggregate_id=job_id,
                record_version=next_version,
                payload={
                    "job_id": job_id,
                    "job_status": target_status.value,
                    "current_stage": str(job["current_stage"]),
                },
                created_at=now,
            )
            self._save_checkpoint(
                connection,
                owner_kind="job",
                owner_id=job_id,
                job_id=job_id,
                work_item_id=None,
                stage=checkpoint_stage,
                sequence=sequence,
                payload={"status": target_status.value},
            )
        return (
            tuple(terminal_daily_job_ids),
            tuple(terminal_settlement_job_ids),
        )

    @staticmethod
    def _retire_settlement_access(
        connection: Connection,
        *,
        job_id: str,
        now: str,
    ) -> None:
        access = (
            connection.execute(
                select(PLATFORM_ACCESS_WINDOWS).join(
                    SETTLEMENT_CAPTURE_INVOCATIONS,
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.access_window_id
                    == PLATFORM_ACCESS_WINDOWS.c.access_window_id,
                ).where(
                    SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id == job_id
                )
            )
            .mappings()
            .one_or_none()
        )
        if access is None or access["consumed_at"] is not None:
            return
        access_window_id = str(access["access_window_id"])
        record_version = int(access["record_version"])
        retired = connection.execute(
            update(PLATFORM_ACCESS_WINDOWS)
            .where(
                PLATFORM_ACCESS_WINDOWS.c.access_window_id
                == access_window_id,
                PLATFORM_ACCESS_WINDOWS.c.record_version
                == record_version,
                PLATFORM_ACCESS_WINDOWS.c.consumed_at.is_(None),
            )
            .values(
                consumed_at=now,
                record_version=record_version + 1,
                updated_at=now,
            )
        )
        if retired.rowcount != 1:
            raise SchedulerLeaseFencingError(
                "settlement capture access changed during terminal cleanup"
            )
        connection.execute(
            PLATFORM_ACCESS_EVENTS.insert().values(
                access_window_id=access_window_id,
                event_type="consumed",
                record_version=record_version + 1,
                created_at=now,
            )
        )

    @staticmethod
    def _refresh_shared_counts(connection: Connection) -> None:
        rows = tuple(connection.execute(select(SHARED_EVIDENCE_WORK)).mappings())
        for row in rows:
            consumers = tuple(
                connection.execute(
                    select(SHARED_EVIDENCE_CONSUMERS.c.status).where(
                        SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == row["shared_work_id"]
                    )
                )
            )
            statuses = [str(status) for (status,) in consumers]
            reference_count = sum(status != "cancelled" for status in statuses)
            runnable_count = sum(status == "waiting" for status in statuses)
            status = str(row["status"])
            if status in {"queued", "paused", "cancelled"}:
                if reference_count == 0:
                    status = "cancelled"
                elif runnable_count == 0:
                    status = "paused"
                else:
                    status = "queued"
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(SHARED_EVIDENCE_WORK.c.shared_work_id == row["shared_work_id"])
                .values(
                    reference_count=reference_count,
                    runnable_consumer_count=runnable_count,
                    status=status,
                )
            )

    def _consume_completed_shared_work(
        self,
        connection: Connection,
        *,
        sequence: int,
        now: str,
    ) -> None:
        rows = tuple(
            connection.execute(
                select(
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id,
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                    SHARED_EVIDENCE_CONSUMERS.c.image_role,
                    WORK_ITEMS.c.job_id,
                    WORK_ITEMS.c.record_version,
                    WORK_ITEMS.c.attempt_count,
                    WORK_ITEMS.c.loading_ocr_complete,
                    WORK_ITEMS.c.unloading_ocr_complete,
                    JOBS.c.ocr_execution_mode,
                    JOBS.c.status.label("job_status"),
                )
                .join(
                    SHARED_EVIDENCE_WORK,
                    SHARED_EVIDENCE_WORK.c.shared_work_id
                    == SHARED_EVIDENCE_CONSUMERS.c.shared_work_id,
                )
                .join(
                    WORK_ITEMS,
                    WORK_ITEMS.c.work_item_id == SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                )
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(
                    SHARED_EVIDENCE_CONSUMERS.c.status == "waiting",
                    SHARED_EVIDENCE_WORK.c.status == "succeeded",
                    WORK_ITEMS.c.status.in_(
                        (
                            WorkItemStatus.QUEUED.value,
                            WorkItemStatus.RUNNING.value,
                            WorkItemStatus.WAITING_RESOURCE.value,
                        )
                    ),
                    JOBS.c.status.not_in(
                        (
                            JobStatus.PAUSED.value,
                            JobStatus.PAUSE_REQUESTED.value,
                            JobStatus.CANCEL_REQUESTED.value,
                            JobStatus.CANCELLED.value,
                        )
                    ),
                )
            ).mappings()
        )
        for row in rows:
            role = str(row["image_role"])
            item = (
                connection.execute(
                    select(WORK_ITEMS).where(
                        WORK_ITEMS.c.work_item_id == row["work_item_id"]
                    )
                )
                .mappings()
                .one()
            )
            consumer_status = connection.execute(
                select(SHARED_EVIDENCE_CONSUMERS.c.status).where(
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id
                    == row["shared_work_id"],
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id
                    == row["work_item_id"],
                    SHARED_EVIDENCE_CONSUMERS.c.image_role == role,
                )
            ).scalar_one()
            if consumer_status != "waiting":
                continue
            shared = (
                connection.execute(
                    select(SHARED_EVIDENCE_WORK).where(
                        SHARED_EVIDENCE_WORK.c.shared_work_id
                        == row["shared_work_id"]
                    )
                )
                .mappings()
                .one()
            )
            values: dict[str, object] = {
                "status": WorkItemStatus.QUEUED.value,
                "attempt_count": int(item["attempt_count"]) + 1,
                "record_version": int(item["record_version"]) + 1,
                "waiting_reason_kind": None,
                "waiting_reason": None,
                "ready_sequence": sequence,
            }
            is_local = row["ocr_execution_mode"] == "local"
            generation: RowMapping | None = None
            if is_local:
                generation = (
                    connection.execute(
                        select(OCR_RUN_GENERATIONS).where(
                            OCR_RUN_GENERATIONS.c.work_item_id
                            == row["work_item_id"]
                        )
                    )
                    .mappings()
                    .one()
                )
                if (
                    shared["execution_mode"] != "local"
                    or shared["output_json"] is None
                    or shared["output_fingerprint"] is None
                    or generation["pipeline_fingerprint"]
                    != shared["pipeline_fingerprint"]
                    or generation["next_runtime_kind"]
                    != shared["runtime_kind"]
                ):
                    raise SchedulerLeaseFencingError(
                        "completed shared OCR artifact does not match its generation"
                    )
            if role == "loading":
                values["loading_ocr_complete"] = 1
                values["current_stage"] = "audit.recognize.unloading"
            else:
                values["unloading_ocr_complete"] = 1
                values["current_stage"] = (
                    "audit.compare"
                    if bool(item["loading_ocr_complete"])
                    else "audit.recognize.loading"
                )
            if generation is not None:
                generation_values: dict[str, object] = {
                    "status": "running",
                    "record_version": int(generation["record_version"]) + 1,
                    "updated_at": now,
                }
                if role == "loading":
                    generation_values["loading_output_json"] = shared[
                        "output_json"
                    ]
                    generation_values["loading_output_fingerprint"] = shared[
                        "output_fingerprint"
                    ]
                    pair_complete = generation["unloading_output_json"] is not None
                else:
                    generation_values["unloading_output_json"] = shared[
                        "output_json"
                    ]
                    generation_values["unloading_output_fingerprint"] = shared[
                        "output_fingerprint"
                    ]
                    pair_complete = generation["loading_output_json"] is not None
                if pair_complete:
                    generation_values.update(
                        status="succeeded",
                        committed_runtime_kind=shared["runtime_kind"],
                        committed_profile_id=shared["profile_id"],
                        committed_runtime_fingerprint=shared[
                            "runtime_fingerprint"
                        ],
                        diagnostic_code=None,
                    )
                    values["current_stage"] = "audit.recognize.complete"
                updated_generation = connection.execute(
                    update(OCR_RUN_GENERATIONS)
                    .where(
                        OCR_RUN_GENERATIONS.c.generation_id
                        == generation["generation_id"],
                        OCR_RUN_GENERATIONS.c.record_version
                        == generation["record_version"],
                    )
                    .values(**generation_values)
                )
                if updated_generation.rowcount != 1:
                    raise SchedulerLeaseFencingError(
                        "OCR generation changed before image checkpoint"
                    )
            connection.execute(
                update(WORK_ITEMS)
                .where(
                    WORK_ITEMS.c.work_item_id == row["work_item_id"],
                    WORK_ITEMS.c.record_version == item["record_version"],
                )
                .values(**values)
            )
            connection.execute(
                update(SHARED_EVIDENCE_CONSUMERS)
                .where(
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == row["shared_work_id"],
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id == row["work_item_id"],
                    SHARED_EVIDENCE_CONSUMERS.c.image_role == role,
                )
                .values(status="consumed")
            )
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=str(row["work_item_id"]),
                job_id=str(row["job_id"]),
                work_item_id=str(row["work_item_id"]),
                stage=f"audit.recognize.{role}",
                sequence=sequence,
                payload={
                    "committed": True,
                    "generation_id": (
                        None
                        if generation is None
                        else str(generation["generation_id"])
                    ),
                    "output_fingerprint": shared["output_fingerprint"],
                    "pipeline_fingerprint": shared["pipeline_fingerprint"],
                    "profile_id": shared["profile_id"],
                    "runtime_fingerprint": shared["runtime_fingerprint"],
                    "runtime_kind": shared["runtime_kind"],
                    "shared_work_id": str(row["shared_work_id"]),
                },
            )

    def _finalize_ready_audit_items(
        self,
        connection: Connection,
        *,
        sequence: int,
    ) -> None:
        rows = tuple(
            connection.execute(
                select(WORK_ITEMS, JOBS.c.job_kind)
                .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
                .where(
                    JOBS.c.ocr_execution_mode == "fake",
                    WORK_ITEMS.c.download_complete == 1,
                    WORK_ITEMS.c.loading_ocr_complete == 1,
                    WORK_ITEMS.c.unloading_ocr_complete == 1,
                    WORK_ITEMS.c.status.in_(
                        (
                            WorkItemStatus.QUEUED.value,
                            WorkItemStatus.WAITING_RESOURCE.value,
                        )
                    ),
                )
            ).mappings()
        )
        for item in rows:
            work_item_id = str(item["work_item_id"])
            job_id = str(item["job_id"])
            self._insert_completed_attempt(
                connection,
                owner_kind="work_item",
                owner_id=work_item_id,
                consumer_job_id=job_id,
                work_item_id=work_item_id,
                stage="audit.compare",
                sequence=sequence,
            )
            self._insert_completed_attempt(
                connection,
                owner_kind="work_item",
                owner_id=work_item_id,
                consumer_job_id=job_id,
                work_item_id=work_item_id,
                stage="audit.finalize",
                sequence=sequence,
            )
            outcome = str(item["fixture_outcome"])
            if item["fixture_diagnostic_code"] is not None:
                connection.execute(
                    update(WORK_ITEMS)
                    .where(WORK_ITEMS.c.work_item_id == work_item_id)
                    .values(
                        status=WorkItemStatus.FAILED.value,
                        current_stage="audit.recognize",
                        business_outcome=None,
                        decision="failed",
                        review_reason=None,
                        diagnostic_code=str(item["fixture_diagnostic_code"]),
                        attempt_count=int(item["attempt_count"]) + 2,
                        waiting_reason_kind=None,
                        waiting_reason=None,
                        record_version=int(item["record_version"]) + 1,
                    )
                )
                self._save_checkpoint(
                    connection,
                    owner_kind="work_item",
                    owner_id=work_item_id,
                    job_id=job_id,
                    work_item_id=work_item_id,
                    stage="audit.recognize",
                    sequence=sequence,
                    payload={
                        "committed": True,
                        "diagnostic_code": str(
                            item["fixture_diagnostic_code"]
                        ),
                    },
                )
                continue
            waiting_user = outcome == "awaiting_review"
            is_test_fixture = item["job_kind"] == "test_fixture"
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == work_item_id)
                .values(
                    status=(
                        WorkItemStatus.WAITING_USER.value
                        if waiting_user
                        else WorkItemStatus.SUCCEEDED.value
                    ),
                    current_stage="audit.finalize",
                    business_outcome=None if is_test_fixture else outcome,
                    platform_loading_net=(
                        item["fixture_platform_loading_net"] or "30.00"
                    ),
                    platform_unloading_net=(
                        item["fixture_platform_unloading_net"] or "29.80"
                    ),
                    ticket_loading_net=(
                        item["fixture_ticket_loading_net"] or "30.00"
                    ),
                    ticket_unloading_net=(
                        item["fixture_ticket_unloading_net"]
                        or (
                            "29.70"
                            if item["fixture_review_reason"]
                            == "numeric_mismatch"
                            else "29.80"
                        )
                    ),
                    decision="review" if waiting_user else "pass",
                    review_reason=item["fixture_review_reason"],
                    attempt_count=int(item["attempt_count"]) + 2,
                    waiting_reason_kind="user" if waiting_user else None,
                    waiting_reason=(str(item["fixture_review_reason"]) if waiting_user else None),
                    record_version=int(item["record_version"]) + 1,
                )
            )
            self._save_checkpoint(
                connection,
                owner_kind="work_item",
                owner_id=work_item_id,
                job_id=job_id,
                work_item_id=work_item_id,
                stage="audit.finalize",
                sequence=sequence,
                payload={
                    "fixture_result": outcome,
                    "business_outcome": (None if is_test_fixture else outcome),
                },
            )
