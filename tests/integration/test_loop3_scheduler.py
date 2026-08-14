from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Iterator
from datetime import date, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dahe import __version__
from dahe.adapters.fake.loop3 import (
    LOOP3_PIPELINE_FINGERPRINT,
    SHARED_LOADING_IMAGE_SHA256,
    SHORT_UNLOADING_IMAGE_SHA256,
)
from dahe.adapters.sqlite.daily_invocation_store import (
    SqliteDailyInvocationStore,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.platform_access import (
    SqlitePlatformAccessRepository,
)
from dahe.adapters.sqlite.recovery import PersistentRecoveryStore
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.api.app import create_app as create_application
from dahe.application.chengfeng.access_window import AccessPurpose
from dahe.application.daily.capture import (
    DailyCaptureRequest,
    DailyCaptureService,
    DailyCaptureStage,
)
from dahe.domain.daily.calendar import SHANGHAI, CandidateQueryWindow
from dahe.domain.daily.models import DailyCandidate
from dahe.jobs.daily_execution import (
    AsyncDailyExecutionBackend,
    DailyStageExecution,
    DailyStageWork,
)
from dahe.jobs.models import JobStatus, WorkItemStatus
from dahe.jobs.scheduler import CooperativeScheduler
from dahe.jobs.shared_evidence import shared_evidence_fingerprint
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.ports.daily import (
    DailyDetailEvidence,
    DailyWaybillPage,
)
from dahe.ports.jobs import IdempotencyConflictError
from dahe.system.instance_lifecycle import data_root_identity

CLIENT_VERSION = __version__
ORIGIN = "http://127.0.0.1:8877"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def create_app(**values: Any) -> FastAPI:
    return create_application(
        project_root=PROJECT_ROOT,
        instance_id=f"test-{uuid4().hex}",
        **values,
    )


def _read_headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": CLIENT_VERSION,
    }


def _session(client: TestClient) -> str:
    response = client.get("/api/v1/session", headers=_read_headers())
    assert response.status_code == 200
    return str(response.json()["csrf_token"])


def _write_headers(csrf: str, key: str) -> dict[str, str]:
    return {
        **_read_headers(),
        "X-CSRF-Token": csrf,
        "X-Idempotency-Key": key,
    }


@pytest.fixture
def loop3_app(tmp_path: Path) -> Iterator[tuple[FastAPI, TestClient, str]]:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_test_fixtures=True,
    )
    with TestClient(app) as client:
        yield app, client, _session(client)


def _create_job(
    client: TestClient,
    csrf: str,
    fixture_id: str,
    *,
    key: str,
    task_type: str = "audit",
    job_kind: str = "test_fixture",
) -> dict[str, Any]:
    response = client.post(
        "/api/v1/jobs",
        json={
            "task_type": task_type,
            "job_kind": job_kind,
            "scope": {
                "label": fixture_id,
                "fixture_id": fixture_id,
            },
            "expected_record_version": 0,
        },
        headers=_write_headers(csrf, key),
    )
    assert response.status_code == 200, response.text
    return dict(response.json()["job"])


def _control(
    client: TestClient,
    csrf: str,
    job: dict[str, Any],
    action: str,
    *,
    key: str,
) -> tuple[int, dict[str, Any]]:
    response = client.post(
        f"/api/v1/jobs/{job['job_id']}/{action}",
        json={"expected_record_version": job["record_version"]},
        headers=_write_headers(csrf, key),
    )
    return response.status_code, dict(response.json())


def _scheduler(app: FastAPI) -> CooperativeScheduler:
    scheduler = app.state.scheduler
    assert isinstance(scheduler, CooperativeScheduler)
    return scheduler


def _job(client: TestClient, job_id: str) -> dict[str, Any]:
    response = client.get(f"/api/v1/jobs/{job_id}", headers=_read_headers())
    assert response.status_code == 200
    return dict(response.json())


def _items(client: TestClient, job_id: str) -> list[dict[str, Any]]:
    response = client.get(
        f"/api/v1/jobs/{job_id}/items",
        headers=_read_headers(),
    )
    assert response.status_code == 200
    return list(response.json()["items"])


class _EmptyDailyPlatform:
    def list_waybills(
        self,
        *,
        query_window: CandidateQueryWindow,
        receive_place: str,
        page_number: int,
        page_size: int,
    ) -> DailyWaybillPage:
        assert query_window.business_date == date(2026, 7, 29)
        assert receive_place == "Test receiving place"
        assert page_number == 1
        return DailyWaybillPage(
            page_number=page_number,
            page_size=page_size,
            total=0,
            items=(),
        )


class _NoDailyDetails:
    def observe(
        self,
        *,
        candidate: DailyCandidate,
    ) -> DailyDetailEvidence:
        raise AssertionError(
            f"empty daily page must not read detail: {candidate}"
        )


class _DailyExecutor:
    def __init__(
        self,
        *,
        service: DailyCaptureService,
        invocations: SqliteDailyInvocationStore,
        scripted_outcomes: list[str] | None = None,
        block_first: bool = False,
    ) -> None:
        self._service = service
        self._invocations = invocations
        self._scripted_outcomes = list(scripted_outcomes or ())
        self._block_first = block_first
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls: list[DailyStageWork] = []

    def __call__(self, work: DailyStageWork) -> DailyStageExecution:
        self.calls.append(work)
        if self._block_first and len(self.calls) == 1:
            self.started.set()
            if not self.release.wait(timeout=5):
                raise TimeoutError("daily scheduler test did not release stage")
        scripted = (
            self._scripted_outcomes.pop(0)
            if self._scripted_outcomes
            else "succeeded"
        )
        invocation = self._invocations.get_by_job(work.job_id)
        assert invocation.next_stage is not None
        assert invocation.next_stage.value == work.stage
        if scripted == "retry":
            return DailyStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="retry",
                completed_stage=work.stage,
                next_stage=work.stage,
                checkpoint_revision=None,
                diagnostic_code="CF-DAILY-TRANSIENT",
            )
        if scripted == "failed":
            self._invocations.fail(
                job_id=work.job_id,
                expected_record_version=invocation.record_version,
                diagnostic_code="CF-DAILY-TECHNICAL-FAILURE",
            )
            return DailyStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="failed",
                completed_stage=work.stage,
                next_stage=None,
                checkpoint_revision=(
                    None
                    if invocation.checkpoint is None
                    else invocation.checkpoint.revision
                ),
                diagnostic_code="CF-DAILY-TECHNICAL-FAILURE",
            )
        if scripted == "waiting_external":
            return DailyStageExecution(
                stage_attempt_id=work.stage_attempt_id,
                outcome="waiting_external",
                completed_stage=work.stage,
                next_stage=work.stage,
                checkpoint_revision=(
                    None
                    if invocation.checkpoint is None
                    else invocation.checkpoint.revision
                ),
                diagnostic_code=(
                    "CF-DAILY-ACCESS-WINDOW-INVALID"
                ),
            )
        step = self._service.advance(
            request=invocation.request,
            checkpoint=invocation.checkpoint,
        )
        committed = self._invocations.commit_checkpoint(
            job_id=work.job_id,
            expected_record_version=invocation.record_version,
            checkpoint=step.checkpoint,
            next_stage=step.next_stage,
            completed=not step.has_more,
        )
        assert committed.checkpoint is not None
        return DailyStageExecution(
            stage_attempt_id=work.stage_attempt_id,
            outcome="succeeded",
            completed_stage=work.stage,
            next_stage=(
                None
                if step.next_stage is None
                else step.next_stage.value
            ),
            checkpoint_revision=committed.checkpoint.revision,
            diagnostic_code=None,
        )


class _TerminalCleanupRecorder:
    def __init__(self, *, failures: int = 0) -> None:
        self._failures = failures
        self.calls: list[str] = []

    def __call__(self, job_id: str) -> None:
        self.calls.append(job_id)
        if self._failures > 0:
            self._failures -= 1
            raise RuntimeError("injected daily terminal cleanup failure")


def _daily_repository(
    data_root: Path,
    *,
    instance_id: str,
    scripted_outcomes: list[str] | None = None,
    block_first: bool = False,
    terminal_cleanup: _TerminalCleanupRecorder | None = None,
) -> tuple[
    SqliteJobRepository,
    SqliteDailyInvocationStore,
    _DailyExecutor,
    SqlitePlatformAccessRepository,
]:
    runtime = SqliteRuntime(
        data_root=data_root,
        project_root=PROJECT_ROOT,
        instance_id=instance_id,
    )
    PersistentRecoveryStore(
        runtime.engine,
        runtime.commit_gate,
    ).register_instance(
        instance_id=instance_id,
        data_root_identity=data_root_identity(data_root),
        pid=1,
        process_started_at="2026-07-29T00:00:00+00:00",
        application_version=__version__,
        port=8877,
        now=datetime(2026, 7, 29, tzinfo=SHANGHAI),
    )
    store = SqliteDailyStore(runtime)
    invocations = SqliteDailyInvocationStore(runtime)
    access = SqlitePlatformAccessRepository(runtime)
    executor = _DailyExecutor(
        service=DailyCaptureService(
            platform=_EmptyDailyPlatform(),
            detail_evidence=_NoDailyDetails(),
            store=store,
            clock=lambda: datetime(
                2026,
                7,
                29,
                20,
                1,
                tzinfo=SHANGHAI,
            ),
        ),
        invocations=invocations,
        scripted_outcomes=scripted_outcomes,
        block_first=block_first,
    )
    backend = AsyncDailyExecutionBackend(
        execute=executor,
        reconcile_terminal=terminal_cleanup,
    )
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id=instance_id,
        daily_execution_backend=backend,
    )
    return repository, invocations, executor, access


def _create_daily_job(
    repository: SqliteJobRepository,
    invocations: SqliteDailyInvocationStore,
    access: SqlitePlatformAccessRepository,
    *,
    suffix: str,
) -> str:
    job, created = repository.create_scheduled_job(
        fixture=ScheduledJobSpec(
            fixture_id=f"daily-{suffix}",
            job_kind="business",
            task_type="daily",
            scope_label=f"Daily {suffix}",
            conflict_key=f"daily:2026-07-29:{suffix}",
            items=(
                ScheduledWorkItemSpec(
                    item_key=f"daily-{suffix}",
                    expected_outcome=None,
                    required_resource="platform_browser",
                ),
            ),
        ),
        scope_label=f"Daily {suffix}",
        idempotency_key=f"daily-create-{suffix}",
        request_hash=sha256(
            f"daily-create-{suffix}".encode()
        ).hexdigest(),
        expected_record_version=0,
    )
    assert created is True
    access_key = f"daily-window-{suffix}"
    grant, replayed = access.issue(
        purpose=AccessPurpose.PRODUCTION_SHADOW,
        job_id=job.job_id,
        session_id=f"daily-session-{suffix}",
        build_sha256=sha256(b"loop3-daily-build").hexdigest(),
        duration_minutes=60,
        legacy_idle_confirmed=True,
        no_settlement_or_payment_confirmed=True,
        same_account_session_risk_accepted=True,
        run_mode="shadow",
        idempotency_key=access_key,
        request_hash=sha256(access_key.encode()).hexdigest(),
        now=datetime.now(SHANGHAI),
    )
    assert replayed is False
    invocations.create(
        job_id=job.job_id,
        access_window_id=grant.access_window_id,
        request=DailyCaptureRequest(
            invocation_id=f"daily-invocation-{suffix}",
            business_date=date(2026, 7, 29),
            receive_place="Test receiving place",
            now=datetime(2026, 7, 29, 20, 0, tzinfo=SHANGHAI),
            source_contract_sha256=sha256(
                b"daily-contract"
            ).hexdigest(),
            page_size=10,
        ),
    )
    return job.job_id


def _tick_until(
    scheduler: CooperativeScheduler,
    predicate: Any,
    *,
    maximum: int = 200,
) -> None:
    for _ in range(maximum):
        scheduler.tick()
        if predicate():
            return
        time.sleep(0.002)
    raise AssertionError("daily scheduler did not reach expected state")


def _active_leases(repository: SqliteJobRepository) -> list[dict[str, Any]]:
    return [
        lease
        for resource in repository.resources_projection()
        for lease in resource["active_leases"]
    ]


def test_durable_alembic_schema_persists_all_scheduler_models(
    tmp_path: Path,
) -> None:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app):
        pass

    database_path = tmp_path / "database" / "dahe.sqlite3"
    with sqlite3.connect(database_path) as connection:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        migration_revision = connection.execute(
            "SELECT version_num FROM alembic_version"
        ).fetchone()
        resources = list(
            connection.execute(
                "SELECT resource_name, capacity FROM resource_slots ORDER BY resource_name"
            )
        )

    assert {
        "jobs",
        "work_items",
        "stage_attempts",
        "checkpoints",
        "resource_slots",
        "leases",
        "conflict_keys",
        "dependencies",
        "shared_evidence_work",
        "shared_evidence_consumers",
        "shared_work_retry_requests",
        "ocr_run_generations",
        "application_instances",
        "browser_control_sessions",
        "evidence_blobs",
        "settlement_capture_invocations",
        "settlement_capture_identities",
        "loop9_exclusion_authority_anchors",
        "platform_credential_config",
        "platform_credential_idempotency",
        "settlement_capture_strategies",
        "operational_capture_runs",
        "daily_operational_ocr_batches",
    } <= tables
    assert migration_revision == (
        "0041_contract_subject_scope",
    )
    assert resources == [
        ("cpu_ocr_slot", 1),
        ("db_commit_gate", 1),
        ("gpu_ocr_slot", 1),
        ("maintenance_exclusive", 1),
        ("platform_browser", 1),
    ]


def test_identical_active_audit_job_can_be_linked_to_a_new_capture(
    tmp_path: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id="materialized-link-test",
    )
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="materialized-link-test",
    )
    spec = ScheduledJobSpec(
        fixture_id="operational-batch-fixture",
        job_kind="business",
        task_type="audit",
        scope_label="Chengfeng settlement",
        conflict_key=f"audit:chengfeng-operational:{sha256(b'batch').hexdigest()}",
        items=(
            ScheduledWorkItemSpec(
                item_key="SXYD-LINK-001",
                expected_outcome="normal_ready",
                loading_image_sha256=SHARED_LOADING_IMAGE_SHA256,
                unloading_image_sha256=SHORT_UNLOADING_IMAGE_SHA256,
            ),
        ),
        pipeline_fingerprint=LOOP3_PIPELINE_FINGERPRINT,
        run_mode="operational",
    )
    original, created = repository.create_scheduled_job(
        fixture=spec,
        scope_label=spec.scope_label,
        idempotency_key="original-materialization",
        request_hash=sha256(b"original-materialization").hexdigest(),
        expected_record_version=0,
    )
    request_hash = sha256(b"new-capture-link").hexdigest()

    linked, link_created = repository.link_active_scheduled_job(
        conflict_key=spec.conflict_key,
        idempotency_key="operational-materialize:new-capture:batch:1:fixture",
        request_hash=request_hash,
    )
    replayed, replay_created = repository.link_active_scheduled_job(
        conflict_key=spec.conflict_key,
        idempotency_key="operational-materialize:new-capture:batch:1:fixture",
        request_hash=request_hash,
    )

    with pytest.raises(IdempotencyConflictError):
        repository.link_active_scheduled_job(
            conflict_key=spec.conflict_key,
            idempotency_key=(
                "operational-materialize:new-capture:batch:1:fixture"
            ),
            request_hash=sha256(b"different-capture-link").hexdigest(),
        )

    assert created is True
    assert linked.job_id == original.job_id
    assert link_created is True
    assert replayed.job_id == original.job_id
    assert replay_created is False
    repository.close()


def test_terminal_job_with_stale_active_conflict_key_can_restart(
    tmp_path: Path,
) -> None:
    runtime = SqliteRuntime(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id="stale-terminal-conflict-test",
    )
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="stale-terminal-conflict-test",
    )
    spec = ScheduledJobSpec(
        fixture_id="stale-terminal-conflict-v1",
        job_kind="business",
        task_type="daily",
        scope_label="stale terminal conflict",
        conflict_key="daily:2026-08-13",
        items=(
            ScheduledWorkItemSpec(
                item_key="daily:2026-08-13",
                expected_outcome=None,
                required_resource="platform_browser",
            ),
        ),
        run_mode="operational",
    )
    first, created = repository.create_scheduled_job(
        fixture=spec,
        scope_label=spec.scope_label,
        idempotency_key="stale-terminal-first",
        request_hash=sha256(b"stale-terminal-first").hexdigest(),
        expected_record_version=0,
    )
    assert created is True
    failed = repository.fail_job(first.job_id, "TEST-START-FAILED")
    with runtime.engine.begin() as connection:
        connection.exec_driver_sql(
            "UPDATE conflict_keys SET active = 1 WHERE conflict_key = ?",
            (spec.conflict_key,),
        )

    active, start_version = repository.fixture_start_state(
        spec.conflict_key
    )
    assert active is False
    assert start_version == failed.record_version
    second, created = repository.create_scheduled_job(
        fixture=spec,
        scope_label=spec.scope_label,
        idempotency_key="stale-terminal-second",
        request_hash=sha256(b"stale-terminal-second").hexdigest(),
        expected_record_version=start_version,
    )

    assert created is True
    assert second.job_id != first.job_id
    assert repository.fixture_start_state(spec.conflict_key)[0] is True
    repository.close()


def test_conflict_key_rejects_duplicate_but_unrelated_three_jobs_coexist(
    loop3_app: tuple[FastAPI, TestClient, str],
) -> None:
    _, client, csrf = loop3_app
    long_job = _create_job(
        client,
        csrf,
        "audit-batch-long-001",
        key="loop3-long",
    )
    short_job = _create_job(
        client,
        csrf,
        "audit-batch-short-002",
        key="loop3-short",
    )
    probe_job = _create_job(
        client,
        csrf,
        "loading-probe-001",
        key="loop3-probe",
        task_type="loading_probe",
        job_kind="test_fixture",
    )
    duplicate = client.post(
        "/api/v1/jobs",
        json={
            "task_type": "audit",
            "job_kind": "test_fixture",
            "scope": {
                "label": "duplicate",
                "fixture_id": "audit-batch-long-001",
            },
            "expected_record_version": 0,
        },
        headers=_write_headers(csrf, "loop3-long-duplicate"),
    )
    snapshot = client.get("/api/v1/jobs", headers=_read_headers())

    assert duplicate.status_code == 409
    assert duplicate.json()["error"]["code"] == "active_scope_conflict"
    assert {job["job_id"] for job in snapshot.json()["jobs"]} >= {
        long_job["job_id"],
        short_job["job_id"],
        probe_job["job_id"],
    }


def test_scheduler_runs_independent_resources_fairly_and_isolates_review_items(
    loop3_app: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_app
    long_job = _create_job(
        client,
        csrf,
        "audit-batch-long-001",
        key="loop3-fair-long",
    )
    short_job = _create_job(
        client,
        csrf,
        "audit-batch-short-002",
        key="loop3-fair-short",
    )
    probe_job = _create_job(
        client,
        csrf,
        "loading-probe-001",
        key="loop3-fair-probe",
        task_type="loading_probe",
        job_kind="test_fixture",
    )
    scheduler = _scheduler(app)

    saw_parallel_resources = False
    for _ in range(80):
        scheduler.tick()
        resources = client.get("/api/v1/resources", headers=_read_headers()).json()
        active = {
            resource["resource_name"]: resource["active_leases"]
            for resource in resources["resources"]
        }
        if active["gpu_ocr_slot"] and active["platform_browser"]:
            saw_parallel_resources = True
        if not scheduler.has_automatic_work():
            break
    else:
        raise AssertionError("deterministic scheduler did not become quiescent")

    long_items = _items(client, long_job["job_id"])
    short_items = _items(client, short_job["job_id"])
    probe_items = _items(client, probe_job["job_id"])
    attempts = app.state.repository.list_stage_attempts()
    shared = app.state.repository.list_shared_evidence_work()

    assert saw_parallel_resources is True
    assert all(item["business_outcome"] is None for item in long_items)
    assert [item["review_reason"] for item in long_items] == [
        None,
        "suspected_swapped",
        "numeric_mismatch",
        None,
        None,
        None,
    ]
    assert [item["status"] for item in long_items] == [
        "succeeded",
        "waiting_user",
        "waiting_user",
        "succeeded",
        "succeeded",
        "succeeded",
    ]
    assert short_items[0]["status"] == "succeeded"
    assert all(item["status"] == "succeeded" for item in probe_items)
    assert _job(client, long_job["job_id"])["job_status"] == "waiting_user"
    assert _job(client, short_job["job_id"])["job_status"] == "succeeded"
    assert _job(client, probe_job["job_id"])["job_status"] == "succeeded"

    shared_fingerprint = shared_evidence_fingerprint(
        SHARED_LOADING_IMAGE_SHA256,
        LOOP3_PIPELINE_FINGERPRINT,
    )
    matching_shared = [work for work in shared if work["fingerprint"] == shared_fingerprint]
    assert len(matching_shared) == 1
    shared_id = matching_shared[0]["shared_work_id"]
    assert (
        sum(
            attempt["owner_kind"] == "shared_evidence"
            and attempt["owner_id"] == shared_id
            and attempt["stage"] == "audit.recognize"
            for attempt in attempts
        )
        == 1
    )

    gpu_job_order = [
        attempt["consumer_job_id"]
        for attempt in attempts
        if attempt["resource_name"] == "gpu_ocr_slot"
    ]
    assert short_job["job_id"] in gpu_job_order
    assert gpu_job_order.index(short_job["job_id"]) < max(
        index for index, job_id in enumerate(gpu_job_order) if job_id == long_job["job_id"]
    )


def test_pause_finishes_atomic_ocr_releases_lease_and_resume_skips_download(
    loop3_app: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_app
    job = _create_job(
        client,
        csrf,
        "audit-batch-long-001",
        key="loop3-pause-create",
    )
    scheduler = _scheduler(app)

    for _ in range(20):
        scheduler.tick()
        current = _job(client, job["job_id"])
        resources = client.get("/api/v1/resources", headers=_read_headers()).json()
        gpu_leases = next(
            resource["active_leases"]
            for resource in resources["resources"]
            if resource["resource_name"] == "gpu_ocr_slot"
        )
        if gpu_leases:
            break
    else:
        raise AssertionError("audit never reached a visible GPU boundary")

    downloaded_item_ids = {
        attempt["work_item_id"]
        for attempt in app.state.repository.list_stage_attempts()
        if attempt["consumer_job_id"] == job["job_id"]
        and attempt["stage"] == "audit.download_evidence"
    }
    status, paused_request = _control(
        client,
        csrf,
        current,
        "pause",
        key="loop3-pause-request",
    )
    assert status == 200
    assert paused_request["job"]["job_status"] == "pause_requested"

    items_before_pause = {
        item["work_item_id"]: (item["status"], item["record_version"])
        for item in _items(client, job["job_id"])
    }
    pause_cursor = app.state.repository.event_cursor()
    scheduler.tick()
    paused = _job(client, job["job_id"])
    items_after_pause = {
        item["work_item_id"]: (item["status"], item["record_version"])
        for item in _items(client, job["job_id"])
    }
    changed_item_ids = {
        work_item_id
        for work_item_id, (status_before, _) in items_before_pause.items()
        if items_after_pause[work_item_id][0] != status_before
    }
    changed_event_ids = {
        event["aggregate_id"]
        for event in app.state.repository.events_after(pause_cursor)
        if event["event_type"] == "work_item.changed"
    }
    assert changed_item_ids
    assert changed_item_ids <= changed_event_ids
    assert all(
        items_after_pause[work_item_id][1] > items_before_pause[work_item_id][1]
        for work_item_id in changed_item_ids
    )
    resources = client.get("/api/v1/resources", headers=_read_headers()).json()
    assert paused["job_status"] == "paused"
    assert paused["checkpoint"] is not None
    assert all(
        lease["job_id"] != job["job_id"]
        for resource in resources["resources"]
        for lease in resource["active_leases"]
    )

    status, resumed_response = _control(
        client,
        csrf,
        paused,
        "resume",
        key="loop3-resume-request",
    )
    assert status == 200
    assert resumed_response["job"]["job_id"] == job["job_id"]
    for _ in range(4):
        scheduler.tick()
    download_attempts_after = [
        attempt
        for attempt in app.state.repository.list_stage_attempts()
        if attempt["consumer_job_id"] == job["job_id"]
        and attempt["stage"] == "audit.download_evidence"
        and attempt["work_item_id"] in downloaded_item_ids
    ]
    assert len(download_attempts_after) == len(downloaded_item_ids)


def test_control_writes_are_idempotent_and_reject_stale_versions(
    loop3_app: tuple[FastAPI, TestClient, str],
) -> None:
    _, client, csrf = loop3_app
    job = _create_job(
        client,
        csrf,
        "audit-batch-short-002",
        key="loop3-control-create",
    )
    status, first = _control(
        client,
        csrf,
        job,
        "pause",
        key="loop3-control-pause",
    )
    status_replay, replay = _control(
        client,
        csrf,
        job,
        "pause",
        key="loop3-control-pause",
    )
    stale = client.post(
        f"/api/v1/jobs/{job['job_id']}/cancel",
        json={"expected_record_version": job["record_version"]},
        headers=_write_headers(csrf, "loop3-control-stale"),
    )

    assert status == 200
    assert status_replay == 200
    assert first["job"]["record_version"] == replay["job"]["record_version"]
    assert replay["idempotent_replay"] is True
    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "record_version_conflict"


def test_pause_then_cancel_preserves_results_and_does_not_stop_shared_work(
    loop3_app: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_app
    long_job = _create_job(
        client,
        csrf,
        "audit-batch-long-001",
        key="loop3-cancel-long",
    )
    short_job = _create_job(
        client,
        csrf,
        "audit-batch-short-002",
        key="loop3-cancel-short",  # gitleaks:allow
    )
    scheduler = _scheduler(app)

    for _ in range(30):
        scheduler.tick()
        shared = app.state.repository.list_shared_evidence_work()
        target = next(
            (work for work in shared if work["image_sha256"] == SHARED_LOADING_IMAGE_SHA256),
            None,
        )
        if target is not None and target["status"] == "running":
            break
    else:
        raise AssertionError("shared OCR work did not start")

    current_long = _job(client, long_job["job_id"])
    status, pause_response = _control(
        client,
        csrf,
        current_long,
        "pause",
        key="loop3-cancel-pause",
    )
    assert status == 200
    status, _ = _control(
        client,
        csrf,
        pause_response["job"],
        "cancel",
        key="loop3-cancel-after-pause",  # gitleaks:allow
    )
    assert status == 200

    scheduler.run_until_quiescent(max_ticks=80)
    cancelled_items = _items(client, long_job["job_id"])
    short_items = _items(client, short_job["job_id"])
    target = next(
        work
        for work in app.state.repository.list_shared_evidence_work()
        if work["image_sha256"] == SHARED_LOADING_IMAGE_SHA256
    )

    assert _job(client, long_job["job_id"])["job_status"] == "cancelled"
    assert any(item["attempt_count"] > 0 for item in cancelled_items)
    assert all(
        item["end_reason"] == "not_processed"
        for item in cancelled_items
        if item["status"] == "cancelled" and item["attempt_count"] == 0
    )
    assert short_items[0]["status"] == "succeeded"
    assert target["status"] == "succeeded"


def test_injected_technical_ocr_failure_never_enters_human_review(
    loop3_app: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_app
    job = _create_job(
        client,
        csrf,
        "audit-batch-short-002",
        key="loop3-failure-create",
    )
    scheduler = _scheduler(app)
    scheduler.inject_ocr_failure(SHORT_UNLOADING_IMAGE_SHA256)
    scheduler.run_until_quiescent(max_ticks=30)

    failed_job = _job(client, job["job_id"])
    item = _items(client, job["job_id"])[0]

    assert failed_job["job_status"] == "failed"
    assert failed_job["counts"]["waiting_user"] == 0
    assert item["status"] == "failed"
    assert item["business_outcome"] is None
    assert item["review_reason"] is None
    assert item["diagnostic_code"] == "LOOP3-FAKE-OCR-FAILURE"


def test_loading_probe_requires_explicit_test_fixture_gate(tmp_path: Path) -> None:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        csrf = _session(client)
        response = client.post(
            "/api/v1/jobs",
            json={
                "task_type": "loading_probe",
                "job_kind": "test_fixture",
                "scope": {
                    "label": "forbidden probe",
                    "fixture_id": "loading-probe-001",
                },
            },
            headers=_write_headers(csrf, "loop3-probe-forbidden"),
        )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "test_fixture_disabled"


def test_daily_capture_advances_checkpoints_and_releases_browser_lease(
    tmp_path: Path,
) -> None:
    cleanup = _TerminalCleanupRecorder()
    repository, invocations, executor, access = _daily_repository(
        tmp_path,
        instance_id="daily-success",
        terminal_cleanup=cleanup,
    )
    try:
        job_id = _create_daily_job(
            repository,
            invocations,
            access,
            suffix="success",
        )
        scheduler = CooperativeScheduler(repository)

        _tick_until(
            scheduler,
            lambda: repository.get_job(job_id).status.is_terminal,
        )

        job = repository.get_job(job_id)
        item = repository.list_items(job_id)[0]
        invocation = invocations.get_by_job(job_id)
        attempts = [
            attempt
            for attempt in repository.list_stage_attempts()
            if attempt["consumer_job_id"] == job_id
        ]

        assert job.status is JobStatus.SUCCEEDED
        assert job.current_stage == "daily.complete"
        assert item.status is WorkItemStatus.SUCCEEDED
        assert item.current_stage == "daily.complete"
        assert item.business_outcome is None
        assert item.review_reason is None
        assert item.diagnostic_code is None
        assert invocation.status == "succeeded"
        assert invocation.next_stage is None
        assert invocation.checkpoint is not None
        assert invocation.checkpoint.revision == 3
        assert len(invocation.checkpoint.pages) == 1
        assert len(invocation.checkpoint.verification_pages) == 1
        assert [call.stage for call in executor.calls] == [
            "daily.list_page",
            "daily.list_page",
            "daily.save_snapshot",
        ]
        assert [
            (attempt["stage"], attempt["status"], attempt["resource_name"])
            for attempt in attempts
        ] == [
            ("daily.list_page", "succeeded", "platform_browser"),
            ("daily.list_page", "succeeded", "platform_browser"),
            ("daily.save_snapshot", "succeeded", "platform_browser"),
        ]
        assert _active_leases(repository) == []
        assert cleanup.calls == [job_id]
    finally:
        repository.close()


def test_daily_external_wait_pauses_job_without_business_review(
    tmp_path: Path,
) -> None:
    cleanup = _TerminalCleanupRecorder()
    repository, invocations, _, access = _daily_repository(
        tmp_path,
        instance_id="daily-external-wait",
        scripted_outcomes=["waiting_external"],
        terminal_cleanup=cleanup,
    )
    try:
        job_id = _create_daily_job(
            repository,
            invocations,
            access,
            suffix="external-wait",
        )
        scheduler = CooperativeScheduler(repository)
        _tick_until(
            scheduler,
            lambda: repository.get_job(job_id).status
            is JobStatus.PAUSED,
        )

        job = repository.get_job(job_id)
        item = repository.list_items(job_id)[0]
        invocation = invocations.get_by_job(job_id)
        assert job.status is JobStatus.PAUSED
        assert item.status is WorkItemStatus.WAITING_EXTERNAL
        assert item.waiting_reason_kind == "external"
        assert item.waiting_reason == "access_window_expired"
        assert item.business_outcome is None
        assert item.review_reason is None
        assert item.diagnostic_code == (
            "CF-DAILY-ACCESS-WINDOW-INVALID"
        )
        assert invocation.status == "ready"
        assert invocation.next_stage is DailyCaptureStage.LIST_PAGE
        assert cleanup.calls == []
        assert _active_leases(repository) == []
    finally:
        repository.close()


def test_daily_retry_and_technical_failure_never_enter_review(
    tmp_path: Path,
) -> None:
    retry_cleanup = _TerminalCleanupRecorder()
    retry_repository, retry_invocations, _, retry_access = _daily_repository(
        tmp_path / "retry",
        instance_id="daily-retry",
        scripted_outcomes=["retry"],
        terminal_cleanup=retry_cleanup,
    )
    try:
        retry_job_id = _create_daily_job(
            retry_repository,
            retry_invocations,
            retry_access,
            suffix="retry",
        )
        retry_scheduler = CooperativeScheduler(retry_repository)
        _tick_until(
            retry_scheduler,
            lambda: retry_repository.get_job(
                retry_job_id
            ).status.is_terminal,
        )

        retry_job = retry_repository.get_job(retry_job_id)
        retry_item = retry_repository.list_items(retry_job_id)[0]
        retry_attempts = [
            attempt
            for attempt in retry_repository.list_stage_attempts()
            if attempt["consumer_job_id"] == retry_job_id
        ]
        assert retry_job.status is JobStatus.SUCCEEDED
        assert retry_item.status is WorkItemStatus.SUCCEEDED
        assert retry_item.business_outcome is None
        assert retry_item.review_reason is None
        assert retry_item.diagnostic_code is None
        assert [
            (attempt["stage"], attempt["status"], attempt["diagnostic_code"])
            for attempt in retry_attempts
        ] == [
            (
                "daily.list_page",
                "failed",
                "CF-DAILY-TRANSIENT",
            ),
            ("daily.list_page", "succeeded", None),
            ("daily.list_page", "succeeded", None),
            ("daily.save_snapshot", "succeeded", None),
        ]
        assert _active_leases(retry_repository) == []
        assert retry_cleanup.calls == [retry_job_id]
    finally:
        retry_repository.close()

    failed_cleanup = _TerminalCleanupRecorder()
    failed_repository, failed_invocations, _, failed_access = _daily_repository(
        tmp_path / "failed",
        instance_id="daily-failed",
        scripted_outcomes=["succeeded", "failed"],
        terminal_cleanup=failed_cleanup,
    )
    try:
        failed_job_id = _create_daily_job(
            failed_repository,
            failed_invocations,
            failed_access,
            suffix="failed",
        )
        failed_scheduler = CooperativeScheduler(failed_repository)
        _tick_until(
            failed_scheduler,
            lambda: failed_repository.get_job(
                failed_job_id
            ).status.is_terminal,
        )

        failed_job = failed_repository.get_job(failed_job_id)
        failed_item = failed_repository.list_items(failed_job_id)[0]
        failed_invocation = failed_invocations.get_by_job(
            failed_job_id
        )
        assert failed_job.status is JobStatus.FAILED
        assert failed_item.status is WorkItemStatus.FAILED
        assert failed_item.business_outcome is None
        assert failed_item.review_reason is None
        assert (
            failed_item.diagnostic_code
            == "CF-DAILY-TECHNICAL-FAILURE"
        )
        assert failed_invocation.status == "failed"
        assert failed_invocation.checkpoint is not None
        assert failed_invocation.checkpoint.revision == 1
        assert _active_leases(failed_repository) == []
        assert failed_cleanup.calls == [failed_job_id]
    finally:
        failed_repository.close()


def test_daily_pause_then_cancel_waits_for_atomic_checkpoint_and_releases_lease(
    tmp_path: Path,
) -> None:
    cleanup = _TerminalCleanupRecorder()
    repository, invocations, executor, access = _daily_repository(
        tmp_path,
        instance_id="daily-pause",
        block_first=True,
        terminal_cleanup=cleanup,
    )
    try:
        job_id = _create_daily_job(
            repository,
            invocations,
            access,
            suffix="pause",
        )
        scheduler = CooperativeScheduler(repository)
        scheduler.tick()
        assert executor.started.wait(timeout=5)

        current = repository.get_job(job_id)
        paused, replay = repository.request_job_control(
            job_id=job_id,
            action="pause",
            expected_record_version=current.record_version,
            idempotency_key="daily-pause-control",
            request_hash=sha256(b"daily-pause-control").hexdigest(),
        )
        assert replay is False
        assert paused.status is JobStatus.PAUSE_REQUESTED

        executor.release.set()
        _tick_until(
            scheduler,
            lambda: repository.get_job(job_id).status
            is JobStatus.PAUSED,
        )

        paused_item = repository.list_items(job_id)[0]
        paused_invocation = invocations.get_by_job(job_id)
        assert paused_item.status is WorkItemStatus.QUEUED
        assert paused_item.current_stage == "daily.list_page"
        assert paused_invocation.checkpoint is not None
        assert paused_invocation.checkpoint.revision == 1
        assert len(paused_invocation.checkpoint.pages) == 1
        assert paused_invocation.checkpoint.verification_pages == ()
        assert paused_invocation.checkpoint.snapshot is None
        assert _active_leases(repository) == []
        assert cleanup.calls == []

        paused_job = repository.get_job(job_id)
        cancelled, replay = repository.request_job_control(
            job_id=job_id,
            action="cancel",
            expected_record_version=paused_job.record_version,
            idempotency_key="daily-cancel-control",
            request_hash=sha256(b"daily-cancel-control").hexdigest(),
        )
        assert replay is False
        assert cancelled.status is JobStatus.CANCEL_REQUESTED
        _tick_until(
            scheduler,
            lambda: repository.get_job(job_id).status
            is JobStatus.CANCELLED,
        )

        cancelled_item = repository.list_items(job_id)[0]
        final_invocation = invocations.get_by_job(job_id)
        assert cancelled_item.status is WorkItemStatus.CANCELLED
        assert cancelled_item.business_outcome is None
        assert cancelled_item.review_reason is None
        assert final_invocation.checkpoint is not None
        assert final_invocation.checkpoint.revision == 1
        assert _active_leases(repository) == []
        assert cleanup.calls == [job_id]
    finally:
        executor.release.set()
        repository.close()


def test_daily_cancel_retries_terminal_cleanup_without_changing_outcome(
    tmp_path: Path,
) -> None:
    cleanup = _TerminalCleanupRecorder(failures=1)
    repository, invocations, _, access = _daily_repository(
        tmp_path,
        instance_id="daily-cancel-cleanup",
        terminal_cleanup=cleanup,
    )
    try:
        job_id = _create_daily_job(
            repository,
            invocations,
            access,
            suffix="cancel-cleanup",
        )
        scheduler = CooperativeScheduler(repository)
        current = repository.get_job(job_id)
        requested, replay = repository.request_job_control(
            job_id=job_id,
            action="cancel",
            expected_record_version=current.record_version,
            idempotency_key="daily-cancel-cleanup-control",
            request_hash=sha256(
                b"daily-cancel-cleanup-control"
            ).hexdigest(),
        )
        assert replay is False
        assert requested.status is JobStatus.CANCEL_REQUESTED

        scheduler.tick()

        cancelled = repository.get_job(job_id)
        cancelled_item = repository.list_items(job_id)[0]
        assert cancelled.status is JobStatus.CANCELLED
        assert cancelled_item.status is WorkItemStatus.CANCELLED
        assert cancelled_item.business_outcome is None
        assert cancelled_item.review_reason is None
        assert cleanup.calls == [job_id]
        assert scheduler.has_automatic_work() is True
        assert _active_leases(repository) == []

        scheduler.tick()

        unchanged = repository.get_job(job_id)
        assert unchanged.status is JobStatus.CANCELLED
        assert unchanged.record_version == cancelled.record_version
        assert cleanup.calls == [job_id, job_id]
        assert scheduler.has_automatic_work() is False
        assert _active_leases(repository) == []
    finally:
        repository.close()


def test_daily_restart_resumes_each_pagination_pass_without_duplication(
    tmp_path: Path,
) -> None:
    repository, invocations, executor, access = _daily_repository(
        tmp_path,
        instance_id="daily-before-restart",
        block_first=True,
    )
    job_id = _create_daily_job(
        repository,
        invocations,
        access,
        suffix="restart",
    )
    scheduler = CooperativeScheduler(repository)
    scheduler.tick()
    assert executor.started.wait(timeout=5)
    current = repository.get_job(job_id)
    repository.request_job_control(
        job_id=job_id,
        action="pause",
        expected_record_version=current.record_version,
        idempotency_key="daily-restart-pause",
        request_hash=sha256(b"daily-restart-pause").hexdigest(),
    )
    executor.release.set()
    _tick_until(
        scheduler,
        lambda: repository.get_job(job_id).status is JobStatus.PAUSED,
    )
    record = invocations.get_by_job(job_id)
    assert record.checkpoint is not None
    assert record.checkpoint.revision == 1
    assert len(record.checkpoint.pages) == 1
    assert record.checkpoint.verification_pages == ()
    assert record.checkpoint.snapshot is None
    assert not _active_leases(repository)
    assert [call.stage for call in executor.calls] == ["daily.list_page"]
    assert repository.list_items(job_id)[0].current_stage == (
        "daily.list_page"
    )
    repository.close()

    verifying, verifying_invocations, verifying_executor, _ = (
        _daily_repository(
            tmp_path,
            instance_id="daily-verification-restart",
            block_first=True,
        )
    )
    verifying_scheduler = CooperativeScheduler(verifying)
    paused = verifying.get_job(job_id)
    resumed, replay = verifying.request_job_control(
        job_id=job_id,
        action="resume",
        expected_record_version=paused.record_version,
        idempotency_key="daily-verification-resume",
        request_hash=sha256(b"daily-verification-resume").hexdigest(),
    )
    assert replay is False
    assert resumed.status is JobStatus.QUEUED
    verifying_scheduler.tick()
    assert verifying_executor.started.wait(timeout=5)
    current = verifying.get_job(job_id)
    verifying.request_job_control(
        job_id=job_id,
        action="pause",
        expected_record_version=current.record_version,
        idempotency_key="daily-verification-pause",
        request_hash=sha256(b"daily-verification-pause").hexdigest(),
    )
    verifying_executor.release.set()
    _tick_until(
        verifying_scheduler,
        lambda: verifying.get_job(job_id).status is JobStatus.PAUSED,
    )
    verified_record = verifying_invocations.get_by_job(job_id)
    assert verified_record.checkpoint is not None
    assert verified_record.checkpoint.revision == 2
    assert len(verified_record.checkpoint.pages) == 1
    assert len(verified_record.checkpoint.verification_pages) == 1
    assert verified_record.checkpoint.snapshot is None
    assert [call.stage for call in verifying_executor.calls] == [
        "daily.list_page"
    ]
    assert verifying.list_items(job_id)[0].current_stage == (
        "daily.save_snapshot"
    )
    assert not _active_leases(verifying)
    verifying.close()

    restarted, restarted_invocations, restarted_executor, _ = (
        _daily_repository(
            tmp_path,
            instance_id="daily-after-verification-restart",
        )
    )
    try:
        restarted_scheduler = CooperativeScheduler(restarted)
        paused = restarted.get_job(job_id)
        resumed, replay = restarted.request_job_control(
            job_id=job_id,
            action="resume",
            expected_record_version=paused.record_version,
            idempotency_key="daily-restart-resume",
            request_hash=sha256(b"daily-restart-resume").hexdigest(),
        )
        assert replay is False
        assert resumed.status is JobStatus.QUEUED
        _tick_until(
            restarted_scheduler,
            lambda: restarted.get_job(job_id).status.is_terminal,
        )

        final = restarted_invocations.get_by_job(job_id)
        attempts = [
            attempt
            for attempt in restarted.list_stage_attempts()
            if attempt["consumer_job_id"] == job_id
        ]
        assert restarted.get_job(job_id).status is JobStatus.SUCCEEDED
        assert final.checkpoint is not None
        assert final.checkpoint.revision == 3
        assert len(final.checkpoint.pages) == 1
        assert len(final.checkpoint.verification_pages) == 1
        assert [call.stage for call in restarted_executor.calls] == [
            "daily.save_snapshot"
        ]
        assert [
            attempt["stage"]
            for attempt in attempts
            if attempt["status"] == "succeeded"
        ] == [
            "daily.list_page",
            "daily.list_page",
            "daily.save_snapshot",
        ]
        assert _active_leases(restarted) == []
    finally:
        restarted.close()
