from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from dahe.application.audit.service import Loop2AuditService
from dahe.jobs.models import JobRecord, JobStatus


def test_failure_persistence_error_is_not_silenced() -> None:
    repository = MagicMock()
    repository.get_job.return_value = JobRecord(
        job_id="job-persistence-failure",
        task_type="audit",
        scope_label="Failure persistence fixture",
        scope_fixture_id="audit-normal-001",
        scope_fingerprint="scope-fingerprint",
        run_mode="fake",
        status=JobStatus.QUEUED,
        current_stage=None,
        diagnostic_code=None,
        record_version=1,
        created_at="2026-07-25T00:00:00+08:00",
        updated_at="2026-07-25T00:00:00+08:00",
    )
    repository.transition.return_value = repository.get_job.return_value
    repository.fail_job.side_effect = OSError("injected database write failure")

    audit_source = MagicMock()
    audit_source.acquire.side_effect = RuntimeError("injected source failure")

    service = Loop2AuditService(
        repository=repository,
        audit_source=audit_source,
        evidence_extractor=MagicMock(),
        stage_delay_seconds=0,
    )

    with pytest.raises(
        RuntimeError,
        match=r"failed to persist the Loop 2 job failure \(LOOP2-RUNTIMEERROR\)",
    ):
        service.run("job-persistence-failure")

    repository.fail_job.assert_called_once_with(
        "job-persistence-failure",
        "LOOP2-RUNTIMEERROR",
    )
