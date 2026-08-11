from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from dahe.jobs.models import JobRecord, JobStatus, WorkItemRecord, WorkItemStatus


class IdempotencyConflictError(RuntimeError):
    """Raised when one idempotency key is reused for a different request."""


class ActiveScopeConflictError(RuntimeError):
    """Raised when a second active job targets the same Loop 2 scope."""


class JobNotFoundError(LookupError):
    """Raised when the requested job does not exist."""


class RecordVersionConflictError(RuntimeError):
    """Raised when a local write uses a stale expected record version."""


class JobControlError(RuntimeError):
    """Raised when a requested control is unsafe for the current state."""


class JobRepository(Protocol):
    def create_job(
        self,
        *,
        task_type: str,
        scope_label: str,
        scope_fixture_id: str,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[JobRecord, bool]: ...

    def get_job(self, job_id: str) -> JobRecord: ...

    def list_jobs(self) -> Sequence[JobRecord]: ...

    def list_items(self, job_id: str) -> Sequence[WorkItemRecord]: ...

    def list_jobs_with_status(self, status: JobStatus) -> Sequence[JobRecord]: ...

    def has_active_scope(self, fixture_id: str) -> bool: ...

    def event_cursor(self) -> int: ...

    def snapshot(
        self,
    ) -> tuple[
        tuple[tuple[JobRecord, tuple[WorkItemRecord, ...]], ...],
        int,
    ]: ...

    def transition(
        self,
        job_id: str,
        *,
        status: JobStatus,
        current_stage: str,
        work_item_status: WorkItemStatus,
        waybill_number: str | None = None,
        vehicle_number: str | None = None,
    ) -> JobRecord: ...

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
    ) -> JobRecord: ...

    def fail_job(self, job_id: str, diagnostic_code: str) -> JobRecord: ...
