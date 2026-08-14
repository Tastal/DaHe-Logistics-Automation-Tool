from __future__ import annotations

import hashlib
import json
import secrets
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select, text, update
from sqlalchemy.engine import Connection, Engine

from dahe.adapters.sqlite.loop3_support import AppendEvent, attempt_number
from dahe.adapters.sqlite.schema import (
    CONFLICT_KEYS,
    DAILY_CAPTURE_INVOCATIONS,
    JOBS,
    LEASES,
    OCR_RUN_GENERATIONS,
    PLATFORM_ACCESS_WINDOWS,
    RESOURCE_SLOTS,
    SETTLEMENT_CAPTURE_INVOCATIONS,
    SETTLEMENT_CAPTURE_STRATEGIES,
    SHARED_EVIDENCE_CONSUMERS,
    SHARED_EVIDENCE_WORK,
    STAGE_ATTEMPTS,
    WORK_ITEMS,
)
from dahe.jobs.models import JobStatus, WorkItemStatus
from dahe.jobs.ocr_execution import AsyncOcrExecutionBackend
from dahe.jobs.scheduler import choose_candidate


class SchedulerLeaseFencingError(RuntimeError):
    """Raised when an atomic result no longer owns its exact resource lease."""


@dataclass(frozen=True, slots=True)
class SchedulerLeaseGrant:
    """Process-local authority for one scheduler atomic stage."""

    lease_id: str
    stage_attempt_id: str
    generation: int
    instance_id: str | None
    worker_id: str | None
    fencing_token: str
    resource_name: str
    owner_kind: str
    owner_id: str
    job_id: str
    work_item_id: str
    stage: str
    execution_kind: str = "cooperative_fake"
    generation_id: str | None = None
    runtime_kind: str | None = None
    profile_id: str | None = None
    runtime_fingerprint: str | None = None
    pipeline_fingerprint: str | None = None


def _fencing_token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class SqliteLoop3ResourceStore:
    """Grant resource leases and maintain aggregate scheduler state."""

    def __init__(
        self,
        engine: Engine,
        append_event: AppendEvent,
        *,
        instance_id: str | None,
        ocr_execution_backend: AsyncOcrExecutionBackend | None = None,
        daily_execution_enabled: bool = False,
        settlement_capture_execution_enabled: bool = False,
    ) -> None:
        self.engine = engine
        self._append_event = append_event
        self._instance_id = instance_id
        self._worker_id = None if instance_id is None else f"scheduler:{instance_id}"
        self._ocr_execution_backend = ocr_execution_backend
        self._daily_execution_enabled = daily_execution_enabled
        self._settlement_capture_execution_enabled = (
            settlement_capture_execution_enabled
        )
        self._grant_lock = threading.RLock()
        self._process_grants: dict[str, SchedulerLeaseGrant] = {}
        self._pending_daily_terminal_cleanup: set[str] = set()
        self._pending_settlement_terminal_cleanup: set[str] = set()

    @staticmethod
    def _needs_waiting_resource_transition(
        item: Mapping[Any, Any],
        *,
        resource_name: str,
    ) -> bool:
        expected_reason = f"resource:{resource_name}"
        return not (
            item.get("status") == WorkItemStatus.WAITING_RESOURCE.value
            and item.get("waiting_reason_kind") == "resource"
            and item.get("waiting_reason") == expected_reason
        )

    @property
    def instance_id(self) -> str | None:
        return self._instance_id

    def process_grants(self) -> tuple[SchedulerLeaseGrant, ...]:
        """Return only grants acquired by this live repository instance."""
        with self._grant_lock:
            return tuple(self._process_grants.values())

    def automatic_poll_interval_seconds(self) -> float:
        """Use a low-overhead cadence while a browser quantum is in flight."""
        with self._grant_lock:
            execution_kinds = {
                grant.execution_kind for grant in self._process_grants.values()
            }
        if execution_kinds & {"daily_capture", "settlement_capture"}:
            # Browser quanta can run for minutes, but their completion and
            # external-login outcomes must become visible promptly.  This
            # cadence only checks the owned async lease; it does not restore
            # the removed UI-wide job polling.
            return 1.0
        return 0.25

    def queue_daily_terminal_cleanup(
        self,
        job_ids: tuple[str, ...],
    ) -> None:
        with self._grant_lock:
            self._pending_daily_terminal_cleanup.update(job_ids)

    def pending_daily_terminal_cleanup(self) -> tuple[str, ...]:
        with self._grant_lock:
            return tuple(sorted(self._pending_daily_terminal_cleanup))

    def finish_daily_terminal_cleanup(self, job_id: str) -> None:
        with self._grant_lock:
            self._pending_daily_terminal_cleanup.discard(job_id)

    def queue_settlement_terminal_cleanup(
        self,
        job_ids: tuple[str, ...],
    ) -> None:
        with self._grant_lock:
            self._pending_settlement_terminal_cleanup.update(job_ids)

    def pending_settlement_terminal_cleanup(self) -> tuple[str, ...]:
        with self._grant_lock:
            return tuple(
                sorted(self._pending_settlement_terminal_cleanup)
            )

    def finish_settlement_terminal_cleanup(self, job_id: str) -> None:
        with self._grant_lock:
            self._pending_settlement_terminal_cleanup.discard(job_id)

    def remember_process_grants(
        self,
        grants: tuple[SchedulerLeaseGrant, ...],
    ) -> None:
        """Pre-publish raw grants before transaction exit; reconcile on failure."""
        with self._grant_lock:
            for grant in grants:
                self._process_grants[grant.stage_attempt_id] = grant

    def forget_process_grants(self, stage_attempt_ids: tuple[str, ...]) -> None:
        """Discard raw grants only after the matching result transaction commits."""
        with self._grant_lock:
            for stage_attempt_id in stage_attempt_ids:
                self._process_grants.pop(stage_attempt_id, None)

    def reconcile_process_grants(
        self,
        grants: tuple[SchedulerLeaseGrant, ...],
    ) -> None:
        """Reconcile pre-published grants to DB truth after transaction exit fails."""
        if not grants:
            return
        with self.engine.connect() as connection:
            committed_ids = {
                grant.stage_attempt_id
                for grant in grants
                if connection.execute(
                    select(LEASES.c.lease_id).where(
                        LEASES.c.lease_id == grant.lease_id,
                        LEASES.c.stage_attempt_id == grant.stage_attempt_id,
                        LEASES.c.status == "active",
                        LEASES.c.generation == grant.generation,
                        LEASES.c.instance_id == grant.instance_id,
                        LEASES.c.worker_id == grant.worker_id,
                        LEASES.c.fencing_token == _fencing_token_digest(grant.fencing_token),
                    )
                ).first()
                is not None
            }
        self.forget_process_grants(
            tuple(
                grant.stage_attempt_id
                for grant in grants
                if grant.stage_attempt_id not in committed_ids
            )
        )

    def release_result_grant(
        self,
        connection: Connection,
        *,
        grant: SchedulerLeaseGrant,
        sequence: int,
        now: str,
    ) -> None:
        """Validate and consume the exact lease grant in the result transaction."""
        if (
            grant.instance_id != self._instance_id
            or grant.worker_id != self._worker_id
            or not grant.fencing_token
        ):
            raise SchedulerLeaseFencingError(
                "scheduler result grant does not belong to this process"
            )
        row = (
            connection.execute(select(LEASES).where(LEASES.c.lease_id == grant.lease_id))
            .mappings()
            .one_or_none()
        )
        expected_digest = _fencing_token_digest(grant.fencing_token)
        if (
            row is None
            or row["status"] != "active"
            or row["stage_attempt_id"] != grant.stage_attempt_id
            or int(row["generation"]) != grant.generation
            or row["instance_id"] != grant.instance_id
            or row["worker_id"] != grant.worker_id
            or row["fencing_token"] != expected_digest
        ):
            raise SchedulerLeaseFencingError(
                "scheduler result lease or fencing token is no longer active"
            )
        expires_at = row["expires_at"]
        if expires_at is None:
            raise SchedulerLeaseFencingError("scheduler result lease has no expiry")
        expiry = datetime.fromisoformat(str(expires_at))
        if expiry.tzinfo is None or expiry.astimezone(UTC) <= datetime.fromisoformat(now):
            raise SchedulerLeaseFencingError("scheduler result lease has expired")
        released = connection.execute(
            update(LEASES)
            .where(
                LEASES.c.lease_id == grant.lease_id,
                LEASES.c.stage_attempt_id == grant.stage_attempt_id,
                LEASES.c.status == "active",
                LEASES.c.generation == grant.generation,
                LEASES.c.instance_id == grant.instance_id,
                LEASES.c.worker_id == grant.worker_id,
                LEASES.c.fencing_token == expected_digest,
            )
            .values(
                status="released",
                released_sequence=sequence,
                released_at=now,
                release_reason="atomic_stage_completed",
            )
        )
        if released.rowcount != 1:
            raise SchedulerLeaseFencingError("scheduler result lease changed before commit")

    def heartbeat_pending_async_grants(
        self,
        connection: Connection,
        *,
        completed_attempt_ids: tuple[str, ...],
        now: str,
    ) -> None:
        """Keep only this process's unfinished async leases renewable."""
        completed = set(completed_attempt_ids)
        heartbeat = datetime.fromisoformat(now)
        for grant in self.process_grants():
            if (
                grant.execution_kind
                not in {
                    "ocr_image",
                    "daily_capture",
                    "settlement_capture",
                }
                or grant.stage_attempt_id in completed
            ):
                continue
            refreshed = connection.execute(
                update(LEASES)
                .where(
                    LEASES.c.lease_id == grant.lease_id,
                    LEASES.c.stage_attempt_id == grant.stage_attempt_id,
                    LEASES.c.status == "active",
                    LEASES.c.generation == grant.generation,
                    LEASES.c.instance_id == grant.instance_id,
                    LEASES.c.worker_id == grant.worker_id,
                    LEASES.c.fencing_token
                    == _fencing_token_digest(grant.fencing_token),
                )
                .values(
                    heartbeat_at=heartbeat.isoformat(),
                    expires_at=(heartbeat + timedelta(seconds=30)).isoformat(),
                )
            )
            if refreshed.rowcount != 1:
                raise SchedulerLeaseFencingError(
                    "pending async lease lost its fencing authority"
                )

    @staticmethod
    def event_state(
        connection: Connection,
    ) -> dict[str, tuple[object, ...]]:
        """Return the externally visible resource state in stable order."""
        slots = connection.execute(
            select(RESOURCE_SLOTS).order_by(RESOURCE_SLOTS.c.resource_name)
        ).mappings()
        state: dict[str, tuple[object, ...]] = {}
        for slot in slots:
            resource_name = str(slot["resource_name"])
            leases = tuple(
                (
                    str(row["lease_id"]),
                    None if row["job_id"] is None else str(row["job_id"]),
                    (None if row["work_item_id"] is None else str(row["work_item_id"])),
                    str(row["stage_attempt_id"]),
                )
                for row in connection.execute(
                    select(LEASES)
                    .where(
                        LEASES.c.resource_name == resource_name,
                        LEASES.c.status == "active",
                    )
                    .order_by(LEASES.c.lease_id)
                ).mappings()
            )
            waiting = tuple(
                (
                    str(row["job_id"]),
                    str(row["work_item_id"]),
                    str(row["waiting_reason"]),
                )
                for row in connection.execute(
                    select(
                        WORK_ITEMS.c.job_id,
                        WORK_ITEMS.c.work_item_id,
                        WORK_ITEMS.c.waiting_reason,
                    )
                    .where(
                        WORK_ITEMS.c.status == WorkItemStatus.WAITING_RESOURCE.value,
                        WORK_ITEMS.c.waiting_reason == f"resource:{resource_name}",
                    )
                    .order_by(WORK_ITEMS.c.work_item_id)
                ).mappings()
            )
            state[resource_name] = (
                int(slot["capacity"]),
                int(slot["grant_sequence"]),
                leases,
                waiting,
            )
        return state

    def start_resource_attempt(
        self,
        connection: Connection,
        *,
        resource_name: str,
        sequence: int,
    ) -> SchedulerLeaseGrant | None:
        active = connection.execute(
            select(LEASES.c.lease_id).where(
                LEASES.c.resource_name == resource_name,
                LEASES.c.status == "active",
            )
        ).first()
        if active is not None:
            return None
        slot = (
            connection.execute(
                select(RESOURCE_SLOTS).where(RESOURCE_SLOTS.c.resource_name == resource_name)
            )
            .mappings()
            .one()
        )
        if resource_name == "platform_browser":
            candidates = self._browser_candidates(connection)
        else:
            candidates = self._ocr_candidates(
                connection,
                resource_name=resource_name,
            )
        last_grants = {
            str(job_id): int(last_sequence)
            for job_id, last_sequence in connection.execute(
                select(
                    STAGE_ATTEMPTS.c.consumer_job_id,
                    func.max(STAGE_ATTEMPTS.c.started_sequence),
                )
                .where(
                    STAGE_ATTEMPTS.c.resource_name == resource_name,
                    STAGE_ATTEMPTS.c.consumer_job_id.is_not(None),
                )
                .group_by(STAGE_ATTEMPTS.c.consumer_job_id)
            )
        }
        for candidate in candidates:
            candidate["last_granted_sequence"] = last_grants.get(
                str(candidate["job_id"]),
                0,
            )
        selected = choose_candidate(
            candidates,
            last_granted_job_id=(
                None if slot["last_granted_job_id"] is None else str(slot["last_granted_job_id"])
            ),
            sequence=sequence,
        )
        for candidate in candidates:
            if selected is not None and candidate["work_item_id"] == selected["work_item_id"]:
                continue
            item = (
                connection.execute(
                    select(WORK_ITEMS).where(WORK_ITEMS.c.work_item_id == candidate["work_item_id"])
                )
                .mappings()
                .one()
            )
            if item["status"] in {
                WorkItemStatus.QUEUED.value,
                WorkItemStatus.WAITING_RESOURCE.value,
            } and self._needs_waiting_resource_transition(
                item,
                resource_name=resource_name,
            ):
                connection.execute(
                    update(WORK_ITEMS)
                    .where(WORK_ITEMS.c.work_item_id == candidate["work_item_id"])
                    .values(
                        status=WorkItemStatus.WAITING_RESOURCE.value,
                        waiting_reason_kind="resource",
                        waiting_reason=f"resource:{resource_name}",
                        record_version=int(item["record_version"]) + 1,
                    )
                )
        if selected is None:
            return None
        owner_kind = str(selected["owner_kind"])
        owner_id = str(selected["owner_id"])
        stage = str(selected["stage"])
        job_id = str(selected["job_id"])
        work_item_id = str(selected["work_item_id"])
        execution_kind = str(
            selected.get("execution_kind", "cooperative_fake")
        )
        generation_id = (
            None
            if selected.get("generation_id") is None
            else str(selected["generation_id"])
        )
        runtime_kind = (
            None
            if selected.get("runtime_kind") is None
            else str(selected["runtime_kind"])
        )
        identity = (
            None
            if (
                execution_kind != "ocr_image"
                or runtime_kind is None
                or self._ocr_execution_backend is None
            )
            else self._ocr_execution_backend.identity_for(runtime_kind)  # type: ignore[arg-type]
        )
        pipeline_fingerprint = (
            None
            if selected.get("pipeline_fingerprint") is None
            else str(selected["pipeline_fingerprint"])
        )
        input_fingerprint = None
        if execution_kind == "ocr_image":
            input_fingerprint = hashlib.sha256(
                json.dumps(
                    {
                        "image_sha256": selected.get("image_sha256"),
                        "pipeline_fingerprint": pipeline_fingerprint,
                        "profile_id": (
                            None if identity is None else identity.profile_id
                        ),
                        "runtime_fingerprint": (
                            None
                            if identity is None
                            else identity.runtime_fingerprint
                        ),
                        "runtime_kind": runtime_kind,
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
        queued_attempt = (
            connection.execute(
                select(STAGE_ATTEMPTS).where(
                    STAGE_ATTEMPTS.c.owner_kind == owner_kind,
                    STAGE_ATTEMPTS.c.owner_id == owner_id,
                    STAGE_ATTEMPTS.c.stage == stage,
                    STAGE_ATTEMPTS.c.status == "queued",
                )
            )
            .mappings()
            .one_or_none()
        )
        if queued_attempt is None:
            stage_attempt_id = uuid4().hex
            connection.execute(
                STAGE_ATTEMPTS.insert().values(
                    stage_attempt_id=stage_attempt_id,
                    owner_kind=owner_kind,
                    owner_id=owner_id,
                    consumer_job_id=job_id,
                    work_item_id=work_item_id,
                    stage=stage,
                    status="running",
                    resource_name=resource_name,
                    attempt_number=attempt_number(
                        connection,
                        owner_kind=owner_kind,
                        owner_id=owner_id,
                        stage=stage,
                    ),
                    started_sequence=sequence,
                    generation_id=generation_id,
                    runtime_kind=runtime_kind,
                    profile_id=None if identity is None else identity.profile_id,
                    runtime_fingerprint=(
                        None if identity is None else identity.runtime_fingerprint
                    ),
                    pipeline_fingerprint=pipeline_fingerprint,
                    input_fingerprint=input_fingerprint,
                    discarded=0,
                )
            )
        else:
            stage_attempt_id = str(queued_attempt["stage_attempt_id"])
            promoted = connection.execute(
                update(STAGE_ATTEMPTS)
                .where(
                    STAGE_ATTEMPTS.c.stage_attempt_id == stage_attempt_id,
                    STAGE_ATTEMPTS.c.status == "queued",
                )
                .values(
                    consumer_job_id=job_id,
                    work_item_id=work_item_id,
                    status="running",
                    resource_name=resource_name,
                    started_sequence=sequence,
                    generation_id=generation_id,
                    runtime_kind=runtime_kind,
                    profile_id=None if identity is None else identity.profile_id,
                    runtime_fingerprint=(
                        None if identity is None else identity.runtime_fingerprint
                    ),
                    pipeline_fingerprint=pipeline_fingerprint,
                    input_fingerprint=input_fingerprint,
                    discarded=0,
                )
            )
            if promoted.rowcount != 1:
                raise RuntimeError("queued stage attempt changed before promotion")
        acquired_at = datetime.now(UTC)
        raw_fencing_token = secrets.token_urlsafe(32)
        grant = SchedulerLeaseGrant(
            lease_id=uuid4().hex,
            stage_attempt_id=stage_attempt_id,
            generation=1,
            instance_id=self._instance_id,
            worker_id=self._worker_id,
            fencing_token=raw_fencing_token,
            resource_name=resource_name,
            owner_kind=owner_kind,
            owner_id=owner_id,
            job_id=job_id,
            work_item_id=work_item_id,
            stage=stage,
            execution_kind=execution_kind,
            generation_id=generation_id,
            runtime_kind=runtime_kind,
            profile_id=None if identity is None else identity.profile_id,
            runtime_fingerprint=(
                None if identity is None else identity.runtime_fingerprint
            ),
            pipeline_fingerprint=pipeline_fingerprint,
        )
        connection.execute(
            LEASES.insert().values(
                lease_id=grant.lease_id,
                resource_name=resource_name,
                slot_index=0,
                holder_kind="system" if owner_kind == "shared_evidence" else "worker",
                holder_id=owner_id,
                job_id=job_id,
                work_item_id=work_item_id,
                stage_attempt_id=stage_attempt_id,
                instance_id=grant.instance_id,
                worker_id=grant.worker_id,
                acquired_sequence=sequence,
                acquired_at=acquired_at.isoformat(),
                heartbeat_at=acquired_at.isoformat(),
                expires_at=(acquired_at + timedelta(seconds=30)).isoformat(),
                generation=grant.generation,
                fencing_token=_fencing_token_digest(raw_fencing_token),
                status="active",
            )
        )
        connection.execute(
            update(RESOURCE_SLOTS)
            .where(RESOURCE_SLOTS.c.resource_name == resource_name)
            .values(
                last_granted_job_id=job_id,
                grant_sequence=int(slot["grant_sequence"]) + 1,
            )
        )
        item = (
            connection.execute(select(WORK_ITEMS).where(WORK_ITEMS.c.work_item_id == work_item_id))
            .mappings()
            .one()
        )
        connection.execute(
            update(WORK_ITEMS)
            .where(WORK_ITEMS.c.work_item_id == work_item_id)
            .values(
                status=WorkItemStatus.RUNNING.value,
                current_stage=stage,
                waiting_reason_kind=None,
                waiting_reason=None,
                record_version=int(item["record_version"]) + 1,
            )
        )
        if owner_kind == "shared_evidence":
            connection.execute(
                update(SHARED_EVIDENCE_WORK)
                .where(SHARED_EVIDENCE_WORK.c.shared_work_id == owner_id)
                    .values(status="running")
            )
            if execution_kind == "ocr_image":
                consumer_items = select(
                    SHARED_EVIDENCE_CONSUMERS.c.work_item_id
                ).where(
                    SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == owner_id,
                    SHARED_EVIDENCE_CONSUMERS.c.status == "waiting",
                )
                connection.execute(
                    update(OCR_RUN_GENERATIONS)
                    .where(
                        OCR_RUN_GENERATIONS.c.work_item_id.in_(consumer_items),
                        OCR_RUN_GENERATIONS.c.pipeline_fingerprint
                        == pipeline_fingerprint,
                        OCR_RUN_GENERATIONS.c.status.in_(
                            ("queued", "fallback_wait")
                        ),
                    )
                    .values(status="running")
                )
        return grant

    def _browser_candidates(
        self,
        connection: Connection,
    ) -> list[dict[str, object]]:
        rows = connection.execute(
            select(
                WORK_ITEMS,
                JOBS.c.task_type,
                JOBS.c.job_kind,
                JOBS.c.status.label("job_status"),
            )
            .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
            .where(
                JOBS.c.status.in_(
                    (
                        JobStatus.QUEUED.value,
                        JobStatus.RUNNING.value,
                        JobStatus.WAITING_RESOURCE.value,
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
        candidates: list[dict[str, object]] = []
        for row in rows:
            task_type = str(row["task_type"])
            if task_type == "audit" and bool(row["download_complete"]):
                continue
            if task_type not in {
                "audit",
                "loading_probe",
                "daily",
                "settlement_capture",
            }:
                continue
            if task_type == "daily":
                if not self._daily_execution_enabled:
                    continue
                invocation = (
                    connection.execute(
                        select(DAILY_CAPTURE_INVOCATIONS).where(
                            DAILY_CAPTURE_INVOCATIONS.c.job_id
                            == row["job_id"],
                            DAILY_CAPTURE_INVOCATIONS.c.status == "ready",
                            DAILY_CAPTURE_INVOCATIONS.c.next_stage
                            == row["current_stage"],
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if invocation is None:
                    continue
            if task_type == "settlement_capture":
                if not self._settlement_capture_execution_enabled:
                    continue
                invocation = (
                    connection.execute(
                        select(SETTLEMENT_CAPTURE_INVOCATIONS).where(
                            SETTLEMENT_CAPTURE_INVOCATIONS.c.job_id
                            == row["job_id"],
                            SETTLEMENT_CAPTURE_INVOCATIONS.c.status.in_(
                                ("collecting", "sealed")
                            ),
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if (
                    invocation is None
                    or row["current_stage"]
                    != "settlement_capture.read"
                ):
                    continue
                if invocation["status"] == "collecting":
                    access = (
                        connection.execute(
                            select(PLATFORM_ACCESS_WINDOWS).where(
                                PLATFORM_ACCESS_WINDOWS.c.access_window_id
                                == invocation["access_window_id"]
                            )
                        )
                        .mappings()
                        .one_or_none()
                    )
                    if (
                        access is None
                        or access["consumed_at"] is not None
                        or datetime.fromisoformat(
                            str(access["expires_at"])
                        )
                        <= datetime.now(UTC)
                    ):
                        continue
                    strategy = connection.execute(
                        select(
                            SETTLEMENT_CAPTURE_STRATEGIES.c.strategy
                        ).where(
                            SETTLEMENT_CAPTURE_STRATEGIES.c.job_id
                            == row["job_id"]
                        )
                    ).scalar_one_or_none()
                    # Whole-run operational reads own browser startup inside
                    # the scheduled task. Only the legacy capture path still
                    # requires a pre-established ready browser session.
                    if strategy not in {"batch_v1", "whole_run_v1"}:
                        control = (
                            connection.execute(
                                text(
                                    "SELECT browser_lifecycle, "
                                    "browser_control_mode "
                                    "FROM browser_control_sessions "
                                    "WHERE session_id = :session_id"
                                ),
                                {
                                    "session_id": str(
                                        access["session_id"]
                                    )
                                },
                            )
                            .mappings()
                            .one_or_none()
                        )
                        if (
                            control is None
                            or control["browser_lifecycle"] != "ready"
                            or control["browser_control_mode"] != "idle"
                        ):
                            continue
            candidates.append(
                {
                    "owner_kind": "work_item",
                    "owner_id": str(row["work_item_id"]),
                    "work_item_id": str(row["work_item_id"]),
                    "job_id": str(row["job_id"]),
                    "job_kind": str(row["job_kind"]),
                    "ready_sequence": int(row["ready_sequence"]),
                    "item_index": int(row["item_index"]),
                    "stage": (
                        "audit.download_evidence"
                        if task_type == "audit"
                        else (
                            "loading_probe.query"
                            if task_type == "loading_probe"
                            else str(row["current_stage"])
                        )
                    ),
                    "execution_kind": (
                        "daily_capture"
                        if task_type == "daily"
                        else (
                            "settlement_capture"
                            if task_type == "settlement_capture"
                            else "cooperative_fake"
                        )
                    ),
                }
            )
        return candidates

    def _ocr_candidates(
        self,
        connection: Connection,
        *,
        resource_name: str,
    ) -> list[dict[str, object]]:
        if resource_name not in {"gpu_ocr_slot", "cpu_ocr_slot"}:
            return []
        return self._shared_ocr_candidates(
            connection,
            resource_name=resource_name,
        )

    def _shared_ocr_candidates(
        self,
        connection: Connection,
        *,
        resource_name: str,
    ) -> list[dict[str, object]]:
        rows = connection.execute(
            select(
                SHARED_EVIDENCE_WORK.c.shared_work_id,
                SHARED_EVIDENCE_WORK.c.status.label("shared_status"),
                SHARED_EVIDENCE_WORK.c.execution_mode,
                SHARED_EVIDENCE_WORK.c.runtime_kind,
                SHARED_EVIDENCE_WORK.c.pipeline_fingerprint,
                SHARED_EVIDENCE_WORK.c.image_sha256,
                SHARED_EVIDENCE_CONSUMERS.c.image_role,
                WORK_ITEMS,
                JOBS.c.job_kind,
                JOBS.c.status.label("job_status"),
            )
            .join(
                SHARED_EVIDENCE_CONSUMERS,
                SHARED_EVIDENCE_CONSUMERS.c.shared_work_id == SHARED_EVIDENCE_WORK.c.shared_work_id,
            )
            .join(
                WORK_ITEMS,
                WORK_ITEMS.c.work_item_id == SHARED_EVIDENCE_CONSUMERS.c.work_item_id,
            )
            .join(JOBS, JOBS.c.job_id == WORK_ITEMS.c.job_id)
            .where(
                SHARED_EVIDENCE_WORK.c.status == "queued",
                SHARED_EVIDENCE_CONSUMERS.c.status == "waiting",
                WORK_ITEMS.c.download_complete == 1,
                WORK_ITEMS.c.status.in_(
                    (
                        WorkItemStatus.QUEUED.value,
                        WorkItemStatus.WAITING_RESOURCE.value,
                    )
                ),
                JOBS.c.status.in_(
                    (
                        JobStatus.QUEUED.value,
                        JobStatus.RUNNING.value,
                        JobStatus.WAITING_RESOURCE.value,
                    )
                ),
            )
        ).mappings()
        candidates: list[dict[str, object]] = []
        seen_shared: set[str] = set()
        for row in rows:
            role = str(row["image_role"])
            already_complete = (
                bool(row["loading_ocr_complete"])
                if role == "loading"
                else bool(row["unloading_ocr_complete"])
            )
            shared_work_id = str(row["shared_work_id"])
            if already_complete or shared_work_id in seen_shared:
                continue
            execution_mode = str(row["execution_mode"])
            runtime_kind = (
                None
                if row["runtime_kind"] is None
                else str(row["runtime_kind"])
            )
            if execution_mode == "fake":
                if resource_name != "gpu_ocr_slot":
                    continue
                execution_kind = "cooperative_fake"
            else:
                if (
                    self._ocr_execution_backend is None
                    or runtime_kind is None
                    or resource_name != f"{runtime_kind}_ocr_slot"
                ):
                    continue
                execution_kind = "ocr_image"
            seen_shared.add(shared_work_id)
            candidates.append(
                {
                    "owner_kind": "shared_evidence",
                    "owner_id": shared_work_id,
                    "work_item_id": str(row["work_item_id"]),
                    "job_id": str(row["job_id"]),
                    "job_kind": str(row["job_kind"]),
                    "ready_sequence": int(row["ready_sequence"]),
                    "item_index": int(row["item_index"]),
                    "stage": "audit.recognize",
                    "execution_kind": execution_kind,
                    "runtime_kind": runtime_kind,
                    "pipeline_fingerprint": str(
                        row["pipeline_fingerprint"]
                    ),
                    "image_sha256": str(row["image_sha256"]),
                }
            )
        return candidates

    def refresh_job_aggregates(
        self,
        connection: Connection,
        *,
        now: str,
    ) -> None:
        jobs = tuple(connection.execute(select(JOBS)).mappings())
        for job in jobs:
            current_status = JobStatus(str(job["status"]))
            if current_status in {
                JobStatus.PAUSE_REQUESTED,
                JobStatus.PAUSED,
                JobStatus.CANCEL_REQUESTED,
                JobStatus.CANCELLED,
            }:
                continue
            items = tuple(
                connection.execute(
                    select(WORK_ITEMS)
                    .where(WORK_ITEMS.c.job_id == job["job_id"])
                    .order_by(WORK_ITEMS.c.item_index)
                ).mappings()
            )
            statuses = [WorkItemStatus(str(item["status"])) for item in items]
            if any(status is WorkItemStatus.RUNNING for status in statuses):
                aggregate = JobStatus.RUNNING
            elif any(status is WorkItemStatus.QUEUED for status in statuses):
                aggregate = JobStatus.QUEUED
            elif any(status is WorkItemStatus.WAITING_RESOURCE for status in statuses):
                aggregate = JobStatus.WAITING_RESOURCE
            elif (
                job["scope_fixture_id"] != "loop8-offline-v1"
                and any(
                    status is WorkItemStatus.FAILED for status in statuses
                )
            ):
                aggregate = JobStatus.FAILED
            elif all(
                status
                in {
                    WorkItemStatus.FAILED,
                    WorkItemStatus.SUCCEEDED,
                    WorkItemStatus.WAITING_USER,
                }
                for status in statuses
            ) and any(status is WorkItemStatus.WAITING_USER for status in statuses):
                aggregate = JobStatus.WAITING_USER
            elif any(status is WorkItemStatus.FAILED for status in statuses):
                aggregate = JobStatus.FAILED
            elif all(status is WorkItemStatus.SUCCEEDED for status in statuses):
                aggregate = JobStatus.SUCCEEDED
            else:
                aggregate = JobStatus.QUEUED
            active_item = next(
                (
                    item
                    for item in items
                    if WorkItemStatus(str(item["status"]))
                    not in {
                        WorkItemStatus.SUCCEEDED,
                        WorkItemStatus.CANCELLED,
                    }
                ),
                items[-1] if items else None,
            )
            current_stage = None if active_item is None else str(active_item["current_stage"])
            diagnostic_code = next(
                (
                    str(item["diagnostic_code"])
                    for item in items
                    if item["diagnostic_code"] is not None
                ),
                None,
            )
            if (
                aggregate.value != job["status"]
                or current_stage != job["current_stage"]
                or diagnostic_code != job["diagnostic_code"]
            ):
                next_version = int(job["record_version"]) + 1
                connection.execute(
                    update(JOBS)
                    .where(JOBS.c.job_id == job["job_id"])
                    .values(
                        status=aggregate.value,
                        current_stage=current_stage,
                        diagnostic_code=diagnostic_code,
                        record_version=next_version,
                        updated_at=now,
                    )
                )
                self._append_event(
                    connection,
                    event_type="job.changed",
                    aggregate_id=str(job["job_id"]),
                    record_version=next_version,
                    payload={
                        "job_id": str(job["job_id"]),
                        "job_status": aggregate.value,
                        "current_stage": current_stage,
                    },
                    created_at=now,
                )
            if aggregate.is_terminal:
                connection.execute(
                    update(CONFLICT_KEYS)
                    .where(CONFLICT_KEYS.c.job_id == job["job_id"])
                    .values(active=0)
                )

    def has_automatic_work(self) -> bool:
        with self._grant_lock:
            if (
                self._pending_daily_terminal_cleanup
                or self._pending_settlement_terminal_cleanup
            ):
                return True
        with self.engine.connect() as connection:
            if (
                connection.execute(
                    select(LEASES.c.lease_id).where(LEASES.c.status == "active")
                ).first()
                is not None
            ):
                return True
            return (
                connection.execute(
                    select(JOBS.c.job_id).where(
                        JOBS.c.status.in_(
                            (
                                JobStatus.QUEUED.value,
                                JobStatus.RUNNING.value,
                                JobStatus.WAITING_RESOURCE.value,
                                JobStatus.PAUSE_REQUESTED.value,
                                JobStatus.CANCEL_REQUESTED.value,
                            )
                        ),
                    )
                ).first()
                is not None
            )
