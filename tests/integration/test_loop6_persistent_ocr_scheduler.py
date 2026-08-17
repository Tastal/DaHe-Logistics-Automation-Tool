from __future__ import annotations

import json
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest
from sqlalchemy import text

from dahe.adapters.fake.loop3 import get_loop3_fixture
from dahe.adapters.ocr.errors import OcrErrorKind
from dahe.adapters.ocr.scheduled_gateway import NdjsonOcrRuntimeGateway
from dahe.adapters.ocr.worker_session import SupervisedNdjsonWorker
from dahe.adapters.sqlite.loop3_resource_store import (
    SchedulerLeaseFencingError,
)
from dahe.adapters.sqlite.repository import TemporarySqliteJobRepository
from dahe.jobs.audit_execution import (
    LocalAuditEvaluation,
    LocalAuditEvaluationInput,
)
from dahe.jobs.models import JobStatus, WorkItemStatus
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageExecution,
    OcrImageExecutionError,
    OcrImageWork,
    OcrRuntimeIdentity,
)
from dahe.jobs.scheduler import CooperativeScheduler
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform != "win32",
        reason="DaHeLogistics OCR worker supervision is Windows-only",
    ),
]

LOADING_SHA256 = "1" * 64
UNLOADING_SHA256 = "2" * 64
PIPELINE_SHA256 = "3" * 64
GPU_RUNTIME_SHA256 = "4" * 64
CPU_RUNTIME_SHA256 = "5" * 64


class _ForbiddenFakeFixtureGateway:
    def __init__(self) -> None:
        self.calls = 0
        self._identity = OcrRuntimeIdentity(
            runtime_kind="gpu",
            profile_id="must-not-receive-fake-fixtures",
            runtime_fingerprint=GPU_RUNTIME_SHA256,
        )

    @property
    def identity(self) -> OcrRuntimeIdentity:
        return self._identity

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        self.calls += 1
        raise AssertionError(
            f"fake fixture reached local OCR protocol: {image} {pipeline_fingerprint}"
        )

    def close(self) -> None:
        return None


def _worker(
    project_root: Path,
    runtime_dir: Path,
    worker_id: str,
    *,
    idle_timeout_seconds: float | None = None,
) -> SupervisedNdjsonWorker:
    return SupervisedNdjsonWorker(
        worker_id=worker_id,
        argv=(
            sys.executable,
            "-I",
            str(project_root / "tests" / "fixtures" / "ocr" / "fake_scheduled_ndjson_worker.py"),
        ),
        runtime_dir=runtime_dir,
        idle_timeout_seconds=idle_timeout_seconds,
    )


def _backend(
    project_root: Path,
    tmp_path: Path,
    *,
    gpu_profile: str = "gpu-fail-second",
    cpu_profile: str = "cpu-qualified",
) -> AsyncOcrExecutionBackend:
    gpu_identity = OcrRuntimeIdentity(
        runtime_kind="gpu",
        profile_id=gpu_profile,
        runtime_fingerprint=GPU_RUNTIME_SHA256,
    )
    cpu_identity = OcrRuntimeIdentity(
        runtime_kind="cpu",
        profile_id=cpu_profile,
        runtime_fingerprint=CPU_RUNTIME_SHA256,
    )
    return AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={
            "gpu": NdjsonOcrRuntimeGateway(
                identity=gpu_identity,
                worker=_worker(project_root, tmp_path / "gpu", "loop6-scheduler-gpu"),
                timeout_seconds=3,
            ),
            "cpu": NdjsonOcrRuntimeGateway(
                identity=cpu_identity,
                worker=_worker(project_root, tmp_path / "cpu", "loop6-scheduler-cpu"),
                timeout_seconds=3,
            ),
        },
    )


def _gpu_only_backend(
    project_root: Path,
    tmp_path: Path,
) -> AsyncOcrExecutionBackend:
    gpu_identity = OcrRuntimeIdentity(
        runtime_kind="gpu",
        profile_id="gpu-fail-second",
        runtime_fingerprint=GPU_RUNTIME_SHA256,
    )
    return AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={
            "gpu": NdjsonOcrRuntimeGateway(
                identity=gpu_identity,
                worker=_worker(
                    project_root,
                    tmp_path / "gpu",
                    "loop6-scheduler-gpu-only",
                ),
                timeout_seconds=3,
            ),
        },
    )


def test_gateway_output_fingerprint_excludes_worker_session_noise(
    project_root: Path,
    tmp_path: Path,
) -> None:
    identity = OcrRuntimeIdentity(
        runtime_kind="cpu",
        profile_id="cpu-qualified",
        runtime_fingerprint=CPU_RUNTIME_SHA256,
    )
    gateway = NdjsonOcrRuntimeGateway(
        identity=identity,
        worker=_worker(project_root, tmp_path / "worker", "stable-output"),
        timeout_seconds=3,
    )
    try:
        image = OcrImageWork(
            image_sha256=LOADING_SHA256,
            relative_path="evidence/loading.png",
        )
        first = gateway.extract(image, pipeline_fingerprint=PIPELINE_SHA256)
        second = gateway.extract(image, pipeline_fingerprint=PIPELINE_SHA256)
    finally:
        gateway.close()

    assert first.output_fingerprint == second.output_fingerprint
    assert (
        json.loads(first.output_json)["command_id"] != json.loads(second.output_json)["command_id"]
    )


def test_gateway_replaces_a_crashed_worker_before_the_next_image(
    project_root: Path,
    tmp_path: Path,
) -> None:
    identity = OcrRuntimeIdentity(
        runtime_kind="gpu",
        profile_id="test-crash-once",
        runtime_fingerprint=GPU_RUNTIME_SHA256,
    )
    worker = _worker(
        project_root,
        tmp_path / "worker",
        "replace-after-crash",
    )
    gateway = NdjsonOcrRuntimeGateway(
        identity=identity,
        worker=worker,
        timeout_seconds=3,
    )
    first_pid = worker.identity.pid
    image = OcrImageWork(
        image_sha256=LOADING_SHA256,
        relative_path="evidence/loading.png",
    )
    try:
        with pytest.raises(OcrImageExecutionError) as captured:
            gateway.extract(
                image,
                pipeline_fingerprint=PIPELINE_SHA256,
            )
        replacement_pid = worker.identity.pid
        recovered = gateway.extract(
            image,
            pipeline_fingerprint=PIPELINE_SHA256,
        )
    finally:
        gateway.close()

    assert captured.value.error_kind is OcrErrorKind.WORKER_CRASHED
    assert replacement_pid != first_pid
    assert recovered.image_sha256 == LOADING_SHA256


def test_idle_worker_releases_memory_and_restarts_before_the_next_image(
    project_root: Path,
    tmp_path: Path,
) -> None:
    identity = OcrRuntimeIdentity(
        runtime_kind="gpu",
        profile_id="gpu-qualified",
        runtime_fingerprint=GPU_RUNTIME_SHA256,
    )
    worker = _worker(
        project_root,
        tmp_path / "worker",
        "idle-release",
        idle_timeout_seconds=0.05,
    )
    gateway = NdjsonOcrRuntimeGateway(
        identity=identity,
        worker=worker,
        timeout_seconds=3,
    )
    image = OcrImageWork(
        image_sha256=LOADING_SHA256,
        relative_path="evidence/loading.png",
    )
    try:
        gateway.extract(image, pipeline_fingerprint=PIPELINE_SHA256)
        first_pid = worker.identity.pid
        deadline = time.monotonic() + 2
        while worker.is_alive and time.monotonic() < deadline:
            time.sleep(0.05)
        assert worker.is_alive is False
        recovered = gateway.extract(image, pipeline_fingerprint=PIPELINE_SHA256)
        replacement_pid = worker.identity.pid
        gateway.set_cpu_thread_limit(2)
        assert worker.is_alive is False
        gateway.extract(image, pipeline_fingerprint=PIPELINE_SHA256)
        limited_pid = worker.identity.pid
    finally:
        gateway.close()

    assert replacement_pid != first_pid
    assert limited_pid != replacement_pid
    assert recovered.image_sha256 == LOADING_SHA256


def test_gpu_only_policy_does_not_queue_an_unavailable_cpu_fallback(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _gpu_only_backend(project_root, tmp_path / "workers")
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(repository, _audit_spec("loop6-no-fallback"))
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.FAILED,
        )
        attempts = _rows(
            repository,
            "SELECT runtime_kind, status, error_kind FROM stage_attempts "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}') AND stage = 'audit.recognize' "
            "ORDER BY started_sequence",
        )
        leases = _rows(
            repository,
            "SELECT resource_name FROM leases "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}') "
            "AND resource_name IN ('gpu_ocr_slot', 'cpu_ocr_slot')",
        )
    finally:
        backend.close()
        repository.close()

    assert attempts == [
        {
            "runtime_kind": "gpu",
            "status": "failed",
            "error_kind": "out_of_memory",
        },
    ]
    assert leases == [{"resource_name": "gpu_ocr_slot"}]


def test_backend_presence_never_routes_fake_pipeline_ids_to_local_protocol(
    tmp_path: Path,
) -> None:
    gateway = _ForbiddenFakeFixtureGateway()
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="gpu",
        gateways={"gpu": gateway},
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(
            repository,
            get_loop3_fixture("audit-batch-short-002"),
        )
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.SUCCEEDED,
        )
        attempts = _rows(
            repository,
            "SELECT runtime_kind, pipeline_fingerprint "
            "FROM stage_attempts WHERE stage = 'audit.recognize'",
        )
    finally:
        repository.close()

    assert gateway.calls == 0
    assert attempts
    assert all(row["runtime_kind"] is None for row in attempts)
    assert {row["pipeline_fingerprint"] for row in attempts} == {
        get_loop3_fixture("audit-batch-short-002").pipeline_fingerprint
    }


def test_explicit_local_job_fails_as_system_error_without_composed_runtime(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path / "data")
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(repository, _audit_spec("loop6-runtime-missing"))
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.FAILED,
        )
        item = repository.list_items(job_id)[0]
    finally:
        repository.close()

    assert item.diagnostic_code == "OCR-LOCAL-RUNTIME-UNAVAILABLE"
    assert item.business_outcome is None
    assert item.review_reason is None


def test_daily_observation_job_commits_runtime_output_without_finance_review(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-qualified",
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    spec = replace(
        _audit_spec("daily-observation-runtime"),
        job_kind="observation",
        run_mode="operational",
    )
    try:
        job_id = _create(repository, spec)
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.SUCCEEDED,
        )
        item = repository.list_items(job_id)[0]
    finally:
        repository.close()
        backend.close()

    assert item.status is WorkItemStatus.SUCCEEDED
    assert item.business_outcome is None
    assert item.review_reason is None
    assert item.diagnostic_code is None


def test_one_vehicle_uses_one_batch_stage_and_commits_both_images(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-qualified",
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(repository, _audit_spec("loop18-vehicle-batch"))
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.SUCCEEDED,
        )
        attempts = _rows(
            repository,
            "SELECT status, runtime_kind, input_fingerprint, output_fingerprint "
            "FROM stage_attempts WHERE owner_kind = 'shared_evidence' "
            "AND work_item_id = "
            "(SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}') AND stage = 'audit.recognize'",
        )
        shared = _rows(
            repository,
            "SELECT image_sha256, status, output_fingerprint "
            "FROM shared_evidence_work WHERE execution_mode = 'local' "
            "ORDER BY image_sha256",
        )
        generation = _rows(
            repository,
            "SELECT status, committed_runtime_kind, loading_output_json, "
            "unloading_output_json FROM ocr_run_generations WHERE work_item_id = "
            "(SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}')",
        )
    finally:
        backend.close()
        repository.close()

    assert len(attempts) == 1
    assert attempts[0]["status"] == "succeeded"
    assert attempts[0]["runtime_kind"] == "gpu"
    assert attempts[0]["input_fingerprint"]
    assert attempts[0]["output_fingerprint"]
    assert shared == [
        {
            "image_sha256": LOADING_SHA256,
            "status": "succeeded",
            "output_fingerprint": shared[0]["output_fingerprint"],
        },
        {
            "image_sha256": UNLOADING_SHA256,
            "status": "succeeded",
            "output_fingerprint": shared[1]["output_fingerprint"],
        },
    ]
    assert all(row["output_fingerprint"] for row in shared)
    assert generation[0]["status"] == "succeeded"
    assert generation[0]["committed_runtime_kind"] == "gpu"
    assert generation[0]["loading_output_json"]
    assert generation[0]["unloading_output_json"]


def test_vehicle_batches_publish_a_contiguous_prefix_in_frozen_order(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-qualified-slow",
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    base = _audit_spec("loop18-vehicle-prefix")
    spec = replace(
        base,
        items=tuple(
            replace(
                base.items[0],
                item_key=f"loop18-vehicle-prefix-{index}",
                loading_image_sha256=str(index * 2 + 1) * 64,
                unloading_image_sha256=str(index * 2 + 2) * 64,
                loading_image_relative_path=f"evidence/{index}/loading.png",
                unloading_image_relative_path=f"evidence/{index}/unloading.png",
            )
            for index in range(3)
        ),
    )
    observed_prefixes: list[int] = []
    try:
        job_id = _create(repository, spec)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            scheduler.tick()
            items = repository.list_items(job_id)
            prefix = 0
            for item in items:
                if item.status is not WorkItemStatus.SUCCEEDED:
                    break
                prefix += 1
            if not observed_prefixes or observed_prefixes[-1] != prefix:
                observed_prefixes.append(prefix)
            if repository.get_job(job_id).status is JobStatus.SUCCEEDED:
                break
            time.sleep(0.01)
        attempts = _rows(
            repository,
            "SELECT COUNT(*) AS count FROM stage_attempts "
            "WHERE consumer_job_id = "
            f"'{job_id}' AND stage = 'audit.recognize'",
        )
    finally:
        backend.close()
        repository.close()

    assert observed_prefixes == [0, 1, 2, 3]
    assert attempts == [{"count": 3}]


def _audit_spec(fixture_id: str) -> ScheduledJobSpec:
    return ScheduledJobSpec(
        fixture_id=fixture_id,
        job_kind="test_fixture",
        task_type="audit",
        scope_label=fixture_id,
        conflict_key=f"audit:{fixture_id}",
        pipeline_fingerprint=PIPELINE_SHA256,
        ocr_execution_mode="local",
        items=(
            ScheduledWorkItemSpec(
                item_key=f"{fixture_id}-001",
                expected_outcome=None,
                loading_image_sha256=LOADING_SHA256,
                unloading_image_sha256=UNLOADING_SHA256,
                loading_image_relative_path="evidence/loading.png",
                unloading_image_relative_path="evidence/unloading.png",
            ),
        ),
    )


class _ReviewLocalAuditEvaluator:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.calls: list[LocalAuditEvaluationInput] = []

    def evaluate(
        self,
        request: LocalAuditEvaluationInput,
    ) -> LocalAuditEvaluation:
        self.calls.append(request)
        if self.fail:
            raise RuntimeError("synthetic evaluator failure")
        return LocalAuditEvaluation(
            business_outcome="awaiting_review",
            decision="review",
            review_reason="role_unknown",
            ticket_loading_net="12.34",
            ticket_unloading_net="12.34",
        )


def _business_audit_spec(fixture_id: str) -> ScheduledJobSpec:
    fixture = _audit_spec(fixture_id)
    return ScheduledJobSpec(
        fixture_id=fixture.fixture_id,
        job_kind="business",
        task_type=fixture.task_type,
        scope_label=fixture.scope_label,
        conflict_key=fixture.conflict_key,
        items=tuple(
            replace(
                item,
                platform_loading_net="12.34",
                platform_unloading_net="12.34",
            )
            for item in fixture.items
        ),
        pipeline_fingerprint=fixture.pipeline_fingerprint,
        ocr_execution_mode=fixture.ocr_execution_mode,
    )


def _missing_ticket_business_spec(fixture_id: str) -> ScheduledJobSpec:
    return ScheduledJobSpec(
        fixture_id=fixture_id,
        job_kind="business",
        task_type="audit",
        scope_label=fixture_id,
        conflict_key=f"audit:{fixture_id}",
        items=(
            ScheduledWorkItemSpec(
                item_key=f"{fixture_id}-001",
                expected_outcome="awaiting_review",
                review_reason="missing_ticket",
                loading_image_sha256=LOADING_SHA256,
                loading_image_relative_path="evidence/loading.png",
                platform_loading_net="12.34",
                platform_unloading_net="12.34",
            ),
        ),
        pipeline_fingerprint=PIPELINE_SHA256,
        ocr_execution_mode="local",
    )


def test_platform_missing_unloading_ticket_ocr_reads_existing_loading_ticket(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-qualified",
    )
    evaluator = _ReviewLocalAuditEvaluator()
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
        local_audit_evaluator=evaluator,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(
            repository,
            _missing_ticket_business_spec("loop6-platform-missing-ticket"),
        )
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.WAITING_USER,
        )
        item = repository.list_items(job_id)[0]
        with repository._runtime.engine.connect() as connection:
            generation = connection.execute(
                text(
                    "SELECT loading_output_json, unloading_output_json, status "
                    "FROM ocr_run_generations WHERE work_item_id = :work_item_id"
                ),
                {"work_item_id": item.work_item_id},
            ).mappings().one()
    finally:
        backend.close()
        repository.close()

    assert item.status is WorkItemStatus.WAITING_USER
    assert item.business_outcome == "awaiting_review"
    assert item.review_reason == "missing_ticket"
    assert item.diagnostic_code is None
    assert item.loading_ocr_complete is True
    assert item.unloading_ocr_complete is True
    assert generation["loading_output_json"] is not None
    assert generation["unloading_output_json"] is None
    assert generation["status"] == "succeeded"
    assert evaluator.calls == []


def test_local_business_job_finishes_with_domain_evaluator_result(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-qualified",
    )
    evaluator = _ReviewLocalAuditEvaluator()
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
        local_audit_evaluator=evaluator,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(
            repository,
            _business_audit_spec("loop9-local-business-review"),
        )
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.WAITING_USER,
        )
        item = repository.list_items(job_id)[0]
    finally:
        backend.close()
        repository.close()

    assert len(evaluator.calls) == 1
    assert evaluator.calls[0].snapshot_id == f"{job_id}:{item.work_item_id}"
    assert item.status.value == "waiting_user"
    assert item.business_outcome == "awaiting_review"
    assert item.review_reason == "role_unknown"
    assert item.diagnostic_code is None


def test_local_business_evaluator_failure_is_technical_not_human_review(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-qualified",
    )
    evaluator = _ReviewLocalAuditEvaluator(fail=True)
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
        local_audit_evaluator=evaluator,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(
            repository,
            _business_audit_spec("loop9-local-business-failure"),
        )
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.FAILED,
        )
        item = repository.list_items(job_id)[0]
    finally:
        backend.close()
        repository.close()

    assert item.status.value == "failed"
    assert item.business_outcome is None
    assert item.review_reason is None
    assert item.diagnostic_code == "AUDIT-LOCAL-EVALUATION-FAILED"


def _probe_spec(fixture_id: str) -> ScheduledJobSpec:
    return ScheduledJobSpec(
        fixture_id=fixture_id,
        job_kind="test_fixture",
        task_type="loading_probe",
        scope_label=fixture_id,
        conflict_key=f"test_fixture:{fixture_id}",
        items=(
            ScheduledWorkItemSpec(
                item_key=f"{fixture_id}-001",
                expected_outcome=None,
                required_resource="platform_browser",
            ),
        ),
    )


def _create(
    repository: TemporarySqliteJobRepository,
    spec: ScheduledJobSpec,
) -> str:
    job, created = repository.create_scheduled_job(
        fixture=spec,
        scope_label=spec.scope_label,
        idempotency_key=f"create-{spec.fixture_id}",
        request_hash=f"request-{spec.fixture_id}",
        expected_record_version=0,
    )
    assert created is True
    return job.job_id


def _drive_until(
    scheduler: CooperativeScheduler,
    predicate: object,
    *,
    timeout_seconds: float = 5,
) -> None:
    assert callable(predicate)
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        scheduler.tick()
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError("scheduler condition was not reached")


def _rows(
    repository: TemporarySqliteJobRepository,
    sql: str,
) -> list[dict[str, object]]:
    with repository.engine.connect() as connection:
        return [dict(row) for row in connection.execute(text(sql)).mappings()]


def test_vehicle_gpu_failure_releases_gpu_and_cpu_restarts_both_images(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(project_root, tmp_path / "workers")
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(repository, _audit_spec("loop6-fallback"))
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.SUCCEEDED,
        )

        attempts = _rows(
            repository,
            "SELECT stage_attempt_id, status, resource_name, generation_id, "
            "runtime_kind, profile_id, runtime_fingerprint, pipeline_fingerprint, "
            "input_fingerprint, output_fingerprint, discarded, error_kind "
            "FROM stage_attempts "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}') AND stage = 'audit.recognize' "
            "ORDER BY started_sequence",
        )
        generation = _rows(
            repository,
            "SELECT * FROM ocr_run_generations "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}')",
        )
        leases = _rows(
            repository,
            "SELECT resource_name, status, release_reason FROM leases "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}') "
            "AND resource_name IN ('gpu_ocr_slot', 'cpu_ocr_slot') "
            "ORDER BY acquired_sequence",
        )
        checkpoints = _rows(
            repository,
            "SELECT stage, payload_json FROM checkpoints "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}') ORDER BY sequence",
        )
        shared_work = _rows(
            repository,
            "SELECT image_sha256, pipeline_fingerprint, runtime_kind, "
            "runtime_fingerprint, status, output_fingerprint "
            "FROM shared_evidence_work WHERE execution_mode = 'local' "
            "ORDER BY rowid",
        )
    finally:
        backend.close()
        repository.close()

    assert len(generation) == 1
    assert generation[0]["status"] == "succeeded"
    assert generation[0]["committed_runtime_kind"] == "cpu"
    assert len(attempts) == 2
    assert [row["resource_name"] for row in attempts] == [
        "gpu_ocr_slot",
        "cpu_ocr_slot",
    ]
    assert [row["status"] for row in attempts] == [
        "failed",
        "succeeded",
    ]
    assert attempts[0]["discarded"] == 1
    assert attempts[0]["error_kind"] == "out_of_memory"
    assert attempts[1]["discarded"] == 0
    assert {row["generation_id"] for row in attempts} == {None}
    assert attempts[0]["runtime_fingerprint"] == GPU_RUNTIME_SHA256
    assert attempts[1]["runtime_fingerprint"] == CPU_RUNTIME_SHA256
    gpu_pipeline = str(attempts[0]["pipeline_fingerprint"])
    cpu_pipeline = str(attempts[1]["pipeline_fingerprint"])
    assert gpu_pipeline != cpu_pipeline
    assert len(gpu_pipeline) == len(cpu_pipeline) == 64
    assert generation[0]["pipeline_fingerprint"] == cpu_pipeline
    assert all(row["input_fingerprint"] for row in attempts)
    assert attempts[0]["output_fingerprint"] is None
    assert attempts[1]["output_fingerprint"]
    assert [(row["resource_name"], row["status"]) for row in leases] == [
        ("gpu_ocr_slot", "released"),
        ("cpu_ocr_slot", "released"),
    ]
    assert len(shared_work) == 4
    assert [row["runtime_kind"] for row in shared_work] == [
        "gpu",
        "gpu",
        "cpu",
        "cpu",
    ]
    assert {row["pipeline_fingerprint"] for row in shared_work[:2]} == {gpu_pipeline}
    assert {row["pipeline_fingerprint"] for row in shared_work[2:]} == {cpu_pipeline}
    assert {row["status"] for row in shared_work[:2]} == {"failed", "cancelled"}
    assert all(row["output_fingerprint"] is None for row in shared_work[:2])
    assert all(row["status"] == "succeeded" for row in shared_work[2:])
    assert all(row["output_fingerprint"] for row in shared_work[2:])
    payloads = [json.loads(str(row["payload_json"])) for row in checkpoints]
    assert any(row["stage"] == "audit.download_evidence" for row in checkpoints)
    assert any(
        payload.get("discarded") is True and payload.get("completed_images") == []
        for payload in payloads
    )
    committed = [payload for payload in payloads if payload.get("committed") is True]
    assert any(payload.get("runtime_kind") == "cpu" for payload in committed)
    assert all(payload.get("business_outcome") is None for payload in committed)
    loading_output = json.loads(str(generation[0]["loading_output_json"]))
    unloading_output = json.loads(str(generation[0]["unloading_output_json"]))
    assert loading_output["verified_image_sha256"] == LOADING_SHA256
    assert unloading_output["verified_image_sha256"] == UNLOADING_SHA256
    assert loading_output["runtime_fingerprint"] == CPU_RUNTIME_SHA256
    assert unloading_output["runtime_fingerprint"] == CPU_RUNTIME_SHA256


def test_two_jobs_share_each_runtime_aware_image_artifact_once(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(project_root, tmp_path / "workers")
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        first_job_id = _create(repository, _audit_spec("loop6-shared-first"))
        second_job_id = _create(
            repository,
            _audit_spec("loop6-shared-second"),
        )
        _drive_until(
            scheduler,
            lambda: all(
                repository.get_job(job_id).status is JobStatus.SUCCEEDED
                for job_id in (first_job_id, second_job_id)
            ),
        )
        attempts = _rows(
            repository,
            "SELECT runtime_kind, status, COUNT(*) AS count "
            "FROM stage_attempts WHERE owner_kind = 'shared_evidence' "
            "AND stage = 'audit.recognize' "
            "GROUP BY runtime_kind, status ORDER BY runtime_kind, status",
        )
        shared_work = _rows(
            repository,
            "SELECT runtime_kind, image_sha256, pipeline_fingerprint, "
            "reference_count, status FROM shared_evidence_work "
            "WHERE execution_mode = 'local' ORDER BY runtime_kind, image_sha256",
        )
    finally:
        repository.close()

    assert attempts == [
        {"runtime_kind": "cpu", "status": "succeeded", "count": 1},
        {"runtime_kind": "gpu", "status": "failed", "count": 1},
    ]
    assert len(shared_work) == 4
    cpu_rows = [row for row in shared_work if row["runtime_kind"] == "cpu"]
    gpu_rows = [row for row in shared_work if row["runtime_kind"] == "gpu"]
    assert {row["image_sha256"] for row in cpu_rows} == {
        LOADING_SHA256,
        UNLOADING_SHA256,
    }
    assert {row["image_sha256"] for row in gpu_rows} == {
        LOADING_SHA256,
        UNLOADING_SHA256,
    }
    assert {row["pipeline_fingerprint"] for row in cpu_rows}.isdisjoint(
        {row["pipeline_fingerprint"] for row in gpu_rows}
    )
    assert {row["reference_count"] for row in cpu_rows} == {2}


def test_pending_ocr_does_not_block_other_job_and_cancel_waits_for_safe_boundary(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-fail-second-slow",
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        audit_job_id = _create(repository, _audit_spec("loop6-cancel"))
        _drive_until(
            scheduler,
            lambda: bool(
                _rows(
                    repository,
                    "SELECT lease_id FROM leases "
                    "WHERE resource_name = 'gpu_ocr_slot' AND status = 'active'",
                )
            ),
        )
        audit = repository.get_job(audit_job_id)
        repository.request_job_control(
            job_id=audit_job_id,
            action="cancel",
            expected_record_version=audit.record_version,
            idempotency_key="cancel-loop6-running",
            request_hash="cancel-loop6-running-request",
        )
        probe_job_id = _create(repository, _probe_spec("loop6-probe"))

        _drive_until(
            scheduler,
            lambda: repository.get_job(probe_job_id).status is JobStatus.SUCCEEDED,
            timeout_seconds=1,
        )
        assert repository.get_job(audit_job_id).status is JobStatus.CANCEL_REQUESTED

        _drive_until(
            scheduler,
            lambda: repository.get_job(audit_job_id).status is JobStatus.CANCELLED,
        )
        audit_item = repository.list_items(audit_job_id)[0]
        leases = _rows(
            repository,
            "SELECT resource_name, status FROM leases "
            "WHERE job_id = :job_id "
            "AND resource_name IN ('gpu_ocr_slot', 'cpu_ocr_slot') "
            "ORDER BY acquired_sequence".replace(":job_id", f"'{audit_job_id}'"),
        )
    finally:
        backend.close()
        repository.close()

    assert audit_item.business_outcome is None
    assert audit_item.review_reason is None
    assert audit_item.download_complete is True
    assert leases == [{"resource_name": "gpu_ocr_slot", "status": "released"}]


def test_pause_waits_for_image_checkpoint_and_resume_does_not_redownload(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-success-slow",
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(repository, _audit_spec("loop6-pause"))
        _drive_until(
            scheduler,
            lambda: bool(
                _rows(
                    repository,
                    "SELECT lease_id FROM leases "
                    "WHERE resource_name = 'gpu_ocr_slot' AND status = 'active'",
                )
            ),
        )
        running = repository.get_job(job_id)
        repository.request_job_control(
            job_id=job_id,
            action="pause",
            expected_record_version=running.record_version,
            idempotency_key="pause-loop6-running",
            request_hash="pause-loop6-running-request",
        )
        scheduler.tick()
        assert repository.get_job(job_id).status is JobStatus.PAUSE_REQUESTED

        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.PAUSED,
        )
        paused_item = repository.list_items(job_id)[0]
        ocr_attempts_before = repository.count_stage_attempts(
            job_id=job_id,
            stage="audit.recognize",
        )
        download_attempts_before = repository.count_stage_attempts(
            job_id=job_id,
            stage="audit.download_evidence",
        )
        paused = repository.get_job(job_id)
        repository.request_job_control(
            job_id=job_id,
            action="resume",
            expected_record_version=paused.record_version,
            idempotency_key="resume-loop6-running",
            request_hash="resume-loop6-running-request",
        )
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.SUCCEEDED,
        )
        completed_item = repository.list_items(job_id)[0]
        download_attempts_after = repository.count_stage_attempts(
            job_id=job_id,
            stage="audit.download_evidence",
        )
        ocr_attempts_after = repository.count_stage_attempts(
            job_id=job_id,
            stage="audit.recognize",
        )
    finally:
        backend.close()
        repository.close()

    assert paused_item.download_complete is True
    assert paused_item.loading_ocr_complete is False
    assert paused_item.unloading_ocr_complete is False
    assert completed_item.ocr_generation_id == paused_item.ocr_generation_id
    assert download_attempts_before == download_attempts_after == 1
    assert ocr_attempts_before == 1
    assert ocr_attempts_after == 1


def test_stale_ocr_lease_cannot_commit_worker_result(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        gpu_profile="gpu-success-slow",
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(repository, _audit_spec("loop6-fenced"))
        _drive_until(
            scheduler,
            lambda: bool(
                _rows(
                    repository,
                    "SELECT lease_id FROM leases "
                    "WHERE resource_name = 'gpu_ocr_slot' AND status = 'active'",
                )
            ),
        )
        with repository.commit_gate.transaction(repository.engine) as connection:
            connection.execute(
                text(
                    "UPDATE leases SET fencing_token = :token "
                    "WHERE resource_name = 'gpu_ocr_slot' AND status = 'active'"
                ),
                {"token": "invalidated-by-test"},
            )
        time.sleep(0.4)
        with pytest.raises(SchedulerLeaseFencingError):
            scheduler.tick()
        generation = _rows(
            repository,
            "SELECT status FROM ocr_run_generations "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}')",
        )
        attempts = _rows(
            repository,
            "SELECT status FROM stage_attempts "
            "WHERE work_item_id = (SELECT work_item_id FROM work_items "
            f"WHERE job_id = '{job_id}') AND stage = 'audit.recognize'",
        )
    finally:
        backend.close()
        repository.close()

    assert generation == [{"status": "running"}]
    assert attempts == [{"status": "running"}]


def test_cpu_technical_failure_is_failed_not_human_review(
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = _backend(
        project_root,
        tmp_path / "workers",
        cpu_profile="cpu-fail",
    )
    repository = TemporarySqliteJobRepository(
        tmp_path / "data",
        ocr_execution_backend=backend,
    )
    scheduler = CooperativeScheduler(repository)
    try:
        job_id = _create(repository, _audit_spec("loop6-cpu-failure"))
        _drive_until(
            scheduler,
            lambda: repository.get_job(job_id).status is JobStatus.FAILED,
        )
        item = repository.list_items(job_id)[0]
    finally:
        backend.close()
        repository.close()

    assert item.status.value == "failed"
    assert item.business_outcome is None
    assert item.review_reason is None
    assert item.diagnostic_code
