from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import select, text, update
from sqlalchemy.engine import Connection, Engine

from dahe.adapters.sqlite.loop3_support import attempt_number, next_sequence
from dahe.adapters.sqlite.runtime import ShortTransactionCommitGate
from dahe.adapters.sqlite.schema import (
    LEASES,
    OCR_RUN_GENERATIONS,
    SHARED_EVIDENCE_CONSUMERS,
    SHARED_EVIDENCE_WORK,
    SHARED_WORK_RETRY_REQUESTS,
    STAGE_ATTEMPTS,
    WORK_ITEMS,
)
from dahe.jobs.models import WorkItemStatus
from dahe.ports.jobs import IdempotencyConflictError

ABANDONED_ATTEMPT_CODE = "LOOP4-ATTEMPT-ABANDONED"
ACTIVE_CONSUMER_STATUSES = ("waiting", "paused")
ACTIVE_RETRY_ATTEMPT_STATUSES = ("queued", "running")


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True, slots=True)
class SharedWorkRetryResult:
    stage_attempt_id: str
    created: bool


class SharedWorkNotFoundError(LookupError):
    """Raised when a shared evidence identifier does not exist."""


class SharedWorkStateConflictError(RuntimeError):
    """Raised when a shared evidence transition is no longer safe."""


def propagate_shared_failure_once_in_transaction(
    connection: Connection,
    *,
    shared_work_id: str,
    diagnostic_code: str,
) -> int:
    """Fail active consumers only after the shared retry budget is exhausted."""
    shared = (
        connection.execute(
            select(SHARED_EVIDENCE_WORK).where(
                SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id
            )
        )
        .mappings()
        .one_or_none()
    )
    if shared is None:
        raise SharedWorkNotFoundError(shared_work_id)
    if shared["status"] != "failed":
        raise SharedWorkStateConflictError("shared evidence is not in failed state")
    if int(shared["retry_generation"]) < int(shared["retry_budget"]):
        raise SharedWorkStateConflictError("shared evidence retry budget is not exhausted")
    existing_code = shared["diagnostic_code"]
    if existing_code is not None and str(existing_code) != diagnostic_code:
        raise SharedWorkStateConflictError("diagnostic code does not match the committed failure")
    if shared["failure_propagation_id"] is None:
        connection.execute(
            update(SHARED_EVIDENCE_WORK)
            .where(
                SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id,
                SHARED_EVIDENCE_WORK.c.failure_propagation_id.is_(None),
            )
            .values(
                failure_propagation_id=uuid4().hex,
                diagnostic_code=diagnostic_code,
                record_version=SHARED_EVIDENCE_WORK.c.record_version + 1,
            )
        )

    propagated_count = 0
    consumers = tuple(
        connection.execute(
            select(
                SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
                SHARED_EVIDENCE_CONSUMERS.c.image_role,
            ).where(
                SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == shared_work_id,
                SHARED_EVIDENCE_CONSUMERS.c.status.in_(ACTIVE_CONSUMER_STATUSES),
            )
        ).mappings()
    )
    for consumer in consumers:
        work_item_id = str(consumer["work_item_id"])
        item = (
            connection.execute(select(WORK_ITEMS).where(WORK_ITEMS.c.work_item_id == work_item_id))
            .mappings()
            .one()
        )
        item_status = WorkItemStatus(str(item["status"]))
        if item_status.is_terminal:
            connection.execute(
                update(SHARED_EVIDENCE_CONSUMERS)
                .where(
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == shared_work_id,
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id == work_item_id,
                    SHARED_EVIDENCE_CONSUMERS.c.image_role == consumer["image_role"],
                    SHARED_EVIDENCE_CONSUMERS.c.status.in_(ACTIVE_CONSUMER_STATUSES),
                )
                .values(status="cancelled")
            )
            continue

        consumer_result = connection.execute(
            update(SHARED_EVIDENCE_CONSUMERS)
            .where(
                SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == shared_work_id,
                SHARED_EVIDENCE_CONSUMERS.c.work_item_id == work_item_id,
                SHARED_EVIDENCE_CONSUMERS.c.image_role == consumer["image_role"],
                SHARED_EVIDENCE_CONSUMERS.c.status.in_(ACTIVE_CONSUMER_STATUSES),
            )
            .values(status="failed")
        )
        if consumer_result.rowcount != 1:
            continue
        item_result = connection.execute(
            update(WORK_ITEMS)
            .where(
                WORK_ITEMS.c.work_item_id == work_item_id,
                WORK_ITEMS.c.record_version == item["record_version"],
                WORK_ITEMS.c.status == item["status"],
            )
            .values(
                status=WorkItemStatus.FAILED.value,
                business_outcome=None,
                review_reason=None,
                diagnostic_code=diagnostic_code,
                waiting_reason_kind=None,
                waiting_reason=None,
                attempt_count=int(item["attempt_count"]) + 1,
                record_version=int(item["record_version"]) + 1,
            )
        )
        if item_result.rowcount != 1:
            raise SharedWorkStateConflictError(
                f"work item changed during failure propagation: {work_item_id}"
            )
        propagated_count += 1
    return propagated_count


class SqliteLoop4RecoveryStore:
    """Atomic restart and shared-work transitions for Loop 4."""

    def __init__(
        self,
        engine: Engine,
        commit_gate: ShortTransactionCommitGate,
    ) -> None:
        self.engine = engine
        self._commit_gate = commit_gate

    @contextmanager
    def _immediate_transaction(self) -> Iterator[Connection]:
        """Serialize compare-and-set transitions before their first read."""
        with self._commit_gate, self.engine.connect() as connection:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def recover_abandoned_attempts(self, *, recovering_instance_id: str) -> int:
        """Fence unfinished attempts left by an earlier application instance.

        This method is a startup boundary: call it before the recovering
        instance starts any scheduler work. No business-stage checkpoint is
        written because the abandoned atomic step never committed a result.
        """
        if not recovering_instance_id.strip():
            raise ValueError("recovering_instance_id must not be empty")

        recovered_count = 0
        with self._immediate_transaction() as connection:
            sequence = next_sequence(connection)
            now = datetime.now(UTC)
            attempts = tuple(
                connection.execute(
                    select(STAGE_ATTEMPTS).where(STAGE_ATTEMPTS.c.status == "running")
                ).mappings()
            )
            for attempt in attempts:
                lease = (
                    connection.execute(
                        select(LEASES).where(
                            LEASES.c.stage_attempt_id == attempt["stage_attempt_id"],
                            LEASES.c.status == "active",
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if lease is not None:
                    owner_instance_id = lease["instance_id"]
                    if owner_instance_id == recovering_instance_id:
                        continue
                    if owner_instance_id is not None:
                        owner_status = connection.execute(
                            text(
                                """
                                SELECT status FROM application_instances
                                WHERE instance_id = :instance_id
                                """
                            ),
                            {"instance_id": owner_instance_id},
                        ).scalar_one_or_none()
                        expires_at = lease["expires_at"]
                        if owner_status not in {"stopped", "crashed"}:
                            continue
                        if expires_at is None:
                            continue
                        expires = datetime.fromisoformat(str(expires_at))
                        if expires.tzinfo is None or expires.astimezone(UTC) > now:
                            continue
                result = connection.execute(
                    update(STAGE_ATTEMPTS)
                    .where(
                        STAGE_ATTEMPTS.c.stage_attempt_id == attempt["stage_attempt_id"],
                        STAGE_ATTEMPTS.c.status == "running",
                    )
                    .values(
                        status="abandoned",
                        finished_sequence=sequence,
                        diagnostic_code=ABANDONED_ATTEMPT_CODE,
                        discarded=1,
                        error_kind="worker_crashed",
                    )
                )
                if result.rowcount != 1:
                    continue
                recovered_count += 1
                connection.execute(
                    update(LEASES)
                    .where(
                        LEASES.c.stage_attempt_id == attempt["stage_attempt_id"],
                        LEASES.c.status == "active",
                    )
                    .values(
                        status="released",
                        released_sequence=sequence,
                        released_at=now.isoformat(),
                        release_reason="abandoned_attempt_recovered",
                    )
                )
                work_item_id = attempt["work_item_id"]
                if work_item_id is not None:
                    connection.execute(
                        update(WORK_ITEMS)
                        .where(
                            WORK_ITEMS.c.work_item_id == work_item_id,
                            WORK_ITEMS.c.status == WorkItemStatus.RUNNING.value,
                        )
                        .values(
                            status=WorkItemStatus.QUEUED.value,
                            current_stage=str(attempt["stage"]),
                            waiting_reason_kind=None,
                            waiting_reason=None,
                            ready_sequence=sequence,
                            record_version=WORK_ITEMS.c.record_version + 1,
                        )
                    )
                if attempt["owner_kind"] == "shared_evidence":
                    connection.execute(
                        update(SHARED_EVIDENCE_WORK)
                        .where(
                            SHARED_EVIDENCE_WORK.c.shared_work_id == attempt["owner_id"],
                            SHARED_EVIDENCE_WORK.c.status == "running",
                        )
                        .values(
                            status="queued",
                            diagnostic_code=None,
                            record_version=(SHARED_EVIDENCE_WORK.c.record_version + 1),
                        )
                    )
                elif attempt["generation_id"] is not None:
                    connection.execute(
                        update(OCR_RUN_GENERATIONS)
                        .where(
                            OCR_RUN_GENERATIONS.c.generation_id
                            == attempt["generation_id"],
                            OCR_RUN_GENERATIONS.c.status == "running",
                        )
                        .values(
                            status="queued",
                            diagnostic_code=None,
                            record_version=(
                                OCR_RUN_GENERATIONS.c.record_version + 1
                            ),
                            updated_at=now.isoformat(),
                        )
                    )
        return recovered_count

    def abandon_instance_attempts(self, *, instance_id: str) -> int:
        """Discard only uncommitted attempts owned by a cleanly stopping instance."""
        if not instance_id.strip():
            raise ValueError("instance_id must not be empty")
        abandoned_count = 0
        with self._immediate_transaction() as connection:
            sequence = next_sequence(connection)
            now = datetime.now(UTC).isoformat()
            attempts = tuple(
                connection.execute(
                    select(STAGE_ATTEMPTS)
                    .join(
                        LEASES,
                        LEASES.c.stage_attempt_id == STAGE_ATTEMPTS.c.stage_attempt_id,
                    )
                    .where(
                        STAGE_ATTEMPTS.c.status == "running",
                        LEASES.c.status == "active",
                        LEASES.c.instance_id == instance_id,
                    )
                ).mappings()
            )
            for attempt in attempts:
                attempt_result = connection.execute(
                    update(STAGE_ATTEMPTS)
                    .where(
                        STAGE_ATTEMPTS.c.stage_attempt_id == attempt["stage_attempt_id"],
                        STAGE_ATTEMPTS.c.status == "running",
                    )
                    .values(
                        status="abandoned",
                        finished_sequence=sequence,
                        diagnostic_code=ABANDONED_ATTEMPT_CODE,
                        discarded=1,
                        error_kind="worker_crashed",
                    )
                )
                if attempt_result.rowcount != 1:
                    continue
                abandoned_count += 1
                connection.execute(
                    update(LEASES)
                    .where(
                        LEASES.c.stage_attempt_id == attempt["stage_attempt_id"],
                        LEASES.c.instance_id == instance_id,
                        LEASES.c.status == "active",
                    )
                    .values(
                        status="released",
                        released_sequence=sequence,
                        released_at=now,
                        release_reason="instance_stopping",
                    )
                )
                work_item_id = attempt["work_item_id"]
                if work_item_id is not None:
                    connection.execute(
                        update(WORK_ITEMS)
                        .where(
                            WORK_ITEMS.c.work_item_id == work_item_id,
                            WORK_ITEMS.c.status == WorkItemStatus.RUNNING.value,
                        )
                        .values(
                            status=WorkItemStatus.QUEUED.value,
                            current_stage=str(attempt["stage"]),
                            waiting_reason_kind=None,
                            waiting_reason=None,
                            ready_sequence=sequence,
                            record_version=WORK_ITEMS.c.record_version + 1,
                        )
                    )
                if attempt["owner_kind"] == "shared_evidence":
                    connection.execute(
                        update(SHARED_EVIDENCE_WORK)
                        .where(
                            SHARED_EVIDENCE_WORK.c.shared_work_id == attempt["owner_id"],
                            SHARED_EVIDENCE_WORK.c.status == "running",
                        )
                        .values(
                            status="queued",
                            diagnostic_code=None,
                            record_version=SHARED_EVIDENCE_WORK.c.record_version + 1,
                        )
                    )
                elif attempt["generation_id"] is not None:
                    connection.execute(
                        update(OCR_RUN_GENERATIONS)
                        .where(
                            OCR_RUN_GENERATIONS.c.generation_id
                            == attempt["generation_id"],
                            OCR_RUN_GENERATIONS.c.status == "running",
                        )
                        .values(
                            status="queued",
                            diagnostic_code=None,
                            record_version=(
                                OCR_RUN_GENERATIONS.c.record_version + 1
                            ),
                            updated_at=now,
                        )
                    )
        return abandoned_count

    def propagate_shared_failure_once(
        self,
        *,
        shared_work_id: str,
        diagnostic_code: str,
    ) -> int:
        """Fail each still-active consumer exactly once."""
        if not diagnostic_code.strip():
            raise ValueError("diagnostic_code must not be empty")

        with self._immediate_transaction() as connection:
            return propagate_shared_failure_once_in_transaction(
                connection,
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
        """Create or attach to one queued retry using a record-version CAS."""
        if not idempotency_key.strip():
            raise ValueError("idempotency_key must not be empty")

        with self._immediate_transaction() as connection:
            replay = (
                connection.execute(
                    select(SHARED_WORK_RETRY_REQUESTS).where(
                        SHARED_WORK_RETRY_REQUESTS.c.shared_work_id == shared_work_id,
                        SHARED_WORK_RETRY_REQUESTS.c.idempotency_key == idempotency_key,
                    )
                )
                .mappings()
                .one_or_none()
            )
            if replay is not None:
                if int(replay["expected_record_version"]) != expected_record_version:
                    raise IdempotencyConflictError(
                        "the idempotency key belongs to a different retry request"
                    )
                return SharedWorkRetryResult(
                    stage_attempt_id=str(replay["stage_attempt_id"]),
                    created=False,
                )

            shared = (
                connection.execute(
                    select(SHARED_EVIDENCE_WORK).where(
                        SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id
                    )
                )
                .mappings()
                .one_or_none()
            )
            if shared is None:
                raise SharedWorkNotFoundError(shared_work_id)

            stage_attempt_id: str
            created = False
            if (
                int(shared["record_version"]) == expected_record_version
                and shared["status"] == "failed"
            ):
                if int(shared["retry_generation"]) >= int(shared["retry_budget"]):
                    raise SharedWorkStateConflictError("shared evidence retry budget is exhausted")
                transition = connection.execute(
                    update(SHARED_EVIDENCE_WORK)
                    .where(
                        SHARED_EVIDENCE_WORK.c.shared_work_id == shared_work_id,
                        SHARED_EVIDENCE_WORK.c.record_version == expected_record_version,
                        SHARED_EVIDENCE_WORK.c.status == "failed",
                    )
                    .values(
                        status="queued",
                        artifact_ref=None,
                        diagnostic_code=None,
                        record_version=expected_record_version + 1,
                        retry_generation=(SHARED_EVIDENCE_WORK.c.retry_generation + 1),
                        attempt_count=SHARED_EVIDENCE_WORK.c.attempt_count + 1,
                        failure_propagation_id=None,
                    )
                )
                if transition.rowcount != 1:
                    raise SharedWorkStateConflictError("shared evidence changed during retry")
                sequence = next_sequence(connection)
                stage_attempt_id = uuid4().hex
                connection.execute(
                    STAGE_ATTEMPTS.insert().values(
                        stage_attempt_id=stage_attempt_id,
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
                created = True
            else:
                prior_request = (
                    connection.execute(
                        select(SHARED_WORK_RETRY_REQUESTS).where(
                            SHARED_WORK_RETRY_REQUESTS.c.shared_work_id == shared_work_id,
                            SHARED_WORK_RETRY_REQUESTS.c.expected_record_version
                            == expected_record_version,
                        )
                    )
                    .mappings()
                    .first()
                )
                if prior_request is None:
                    raise SharedWorkStateConflictError("shared evidence record version is stale")
                stage_attempt_id = str(prior_request["stage_attempt_id"])
                active_attempt = connection.execute(
                    select(STAGE_ATTEMPTS.c.stage_attempt_id).where(
                        STAGE_ATTEMPTS.c.stage_attempt_id == stage_attempt_id,
                        STAGE_ATTEMPTS.c.status.in_(ACTIVE_RETRY_ATTEMPT_STATUSES),
                    )
                ).scalar_one_or_none()
                if active_attempt is None:
                    raise SharedWorkStateConflictError(
                        "the matching retry attempt is no longer active"
                    )

            connection.execute(
                SHARED_WORK_RETRY_REQUESTS.insert().values(
                    shared_work_id=shared_work_id,
                    idempotency_key=idempotency_key,
                    expected_record_version=expected_record_version,
                    stage_attempt_id=stage_attempt_id,
                    created_at=_utc_now(),
                )
            )
            return SharedWorkRetryResult(
                stage_attempt_id=stage_attempt_id,
                created=created,
            )
