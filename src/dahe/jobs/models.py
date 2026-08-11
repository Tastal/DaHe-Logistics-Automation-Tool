from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class JobStatus(StrEnum):
    CREATED = "created"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_RESOURCE = "waiting_resource"
    WAITING_USER = "waiting_user"
    WAITING_EXTERNAL = "waiting_external"
    RETRY_WAIT = "retry_wait"
    PAUSE_REQUESTED = "pause_requested"
    PAUSED = "paused"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in {self.CANCELLED, self.SUCCEEDED, self.FAILED}


class WorkItemStatus(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    WAITING_RESOURCE = "waiting_resource"
    WAITING_USER = "waiting_user"
    WAITING_EXTERNAL = "waiting_external"
    RETRY_WAIT = "retry_wait"
    CANCELLED = "cancelled"
    SUCCEEDED = "succeeded"
    FAILED = "failed"

    @property
    def is_terminal(self) -> bool:
        return self in {self.CANCELLED, self.SUCCEEDED, self.FAILED}


@dataclass(frozen=True, slots=True)
class JobRecord:
    job_id: str
    task_type: str
    scope_label: str
    scope_fixture_id: str
    scope_fingerprint: str
    run_mode: str
    status: JobStatus
    current_stage: str | None
    diagnostic_code: str | None
    record_version: int
    created_at: str
    updated_at: str
    job_kind: str = "business"
    conflict_key: str | None = None
    created_sequence: int = 0


@dataclass(frozen=True, slots=True)
class WorkItemRecord:
    work_item_id: str
    job_id: str
    record_version: int
    waybill_number: str
    vehicle_number: str
    status: WorkItemStatus
    current_stage: str
    business_outcome: str | None
    platform_loading_net: str | None
    platform_unloading_net: str | None
    ticket_loading_net: str | None
    ticket_unloading_net: str | None
    decision: str | None
    review_reason: str | None
    item_index: int = 0
    end_reason: str | None = None
    waiting_reason_kind: str | None = None
    waiting_reason: str | None = None
    attempt_count: int = 0
    diagnostic_code: str | None = None
    loading_image_sha256: str | None = None
    unloading_image_sha256: str | None = None
    pipeline_fingerprint: str | None = None
    fixture_outcome: str | None = None
    fixture_review_reason: str | None = None
    download_complete: bool = False
    loading_ocr_complete: bool = False
    unloading_ocr_complete: bool = False
    ready_sequence: int = 0
    loading_image_relative_path: str | None = None
    unloading_image_relative_path: str | None = None
    ocr_generation_id: str | None = None


@dataclass(frozen=True, slots=True)
class StageAttemptRecord:
    stage_attempt_id: str
    owner_kind: str
    owner_id: str
    consumer_job_id: str | None
    work_item_id: str | None
    stage: str
    status: str
    resource_name: str | None
    attempt_number: int
    started_sequence: int
    finished_sequence: int | None
    diagnostic_code: str | None
    generation_id: str | None = None
    runtime_kind: str | None = None
    profile_id: str | None = None
    runtime_fingerprint: str | None = None
    pipeline_fingerprint: str | None = None
    input_fingerprint: str | None = None
    output_fingerprint: str | None = None
    discarded: bool = False
    error_kind: str | None = None


@dataclass(frozen=True, slots=True)
class CheckpointRecord:
    checkpoint_id: str
    owner_kind: str
    owner_id: str
    job_id: str | None
    work_item_id: str | None
    stage: str
    sequence: int
    payload_json: str


@dataclass(frozen=True, slots=True)
class ResourceSlotRecord:
    resource_name: str
    capacity: int
    last_granted_job_id: str | None
    grant_sequence: int


@dataclass(frozen=True, slots=True)
class LeaseRecord:
    lease_id: str
    resource_name: str
    holder_kind: str
    holder_id: str
    job_id: str | None
    work_item_id: str | None
    stage_attempt_id: str
    acquired_sequence: int
    released_sequence: int | None
    status: str


@dataclass(frozen=True, slots=True)
class ConflictKeyRecord:
    conflict_key: str
    job_id: str
    active: bool


@dataclass(frozen=True, slots=True)
class DependencyRecord:
    dependency_id: str
    job_id: str
    depends_on_job_id: str | None
    frozen_result_ref: str | None
    status: str


@dataclass(frozen=True, slots=True)
class SharedEvidenceWorkRecord:
    shared_work_id: str
    fingerprint: str
    image_sha256: str
    pipeline_fingerprint: str
    status: str
    artifact_ref: str | None
    reference_count: int
    runnable_consumer_count: int
    diagnostic_code: str | None
