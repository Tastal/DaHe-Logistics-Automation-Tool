from __future__ import annotations

import time
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier
from typing import Any
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dahe import __version__
from dahe.adapters.fake.loop3 import (
    SHARED_LOADING_IMAGE_SHA256,
    get_loop3_fixture,
)
from dahe.adapters.sqlite.repository import TemporarySqliteJobRepository
from dahe.api.app import create_app as create_application
from dahe.jobs.scheduler import CooperativeScheduler
from dahe.ports.jobs import (
    ActiveScopeConflictError,
    RecordVersionConflictError,
)

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


def _write_headers(csrf: str, key: str) -> dict[str, str]:
    return {
        **_read_headers(),
        "X-CSRF-Token": csrf,
        "X-Idempotency-Key": key,
    }


@pytest.fixture
def loop3_client(tmp_path: Path) -> Iterator[tuple[FastAPI, TestClient, str]]:
    app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_test_fixtures=True,
    )
    with TestClient(app) as client:
        session = client.get("/api/v1/session", headers=_read_headers())
        assert session.status_code == 200
        yield app, client, str(session.json()["csrf_token"])


def _create_fixture(
    client: TestClient,
    csrf: str,
    fixture_id: str,
    *,
    key: str,
    expected_record_version: int,
) -> dict[str, Any]:
    task_type = "loading_probe" if fixture_id == "loading-probe-001" else "audit"
    response = client.post(
        "/api/v1/jobs",
        json={
            "task_type": task_type,
            "job_kind": "test_fixture",
            "scope": {
                "label": fixture_id,
                "fixture_id": fixture_id,
            },
            "expected_record_version": expected_record_version,
        },
        headers=_write_headers(csrf, key),
    )
    assert response.status_code == 200, response.text
    return dict(response.json()["job"])


def test_operator_contract_exposes_versioned_starts_controls_and_resources(
    loop3_client: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_client
    initial = client.get("/api/v1/jobs", headers=_read_headers()).json()

    assert {
        "start_audit_long",
        "start_audit_short",
        "start_loading_probe",
    } <= initial["start_actions"].keys()
    assert all(
        initial["start_actions"][action_id]["expected_record_version"] == 0
        for action_id in (
            "start_audit_long",
            "start_audit_short",
            "start_loading_probe",
        )
    )

    long_job = _create_fixture(
        client,
        csrf,
        "audit-batch-long-001",
        key="contract-long",
        expected_record_version=0,
    )
    short_job = _create_fixture(
        client,
        csrf,
        "audit-batch-short-002",
        key="contract-short",
        expected_record_version=0,
    )

    assert long_job["job_kind"] == "test_fixture"
    assert short_job["job_kind"] == "test_fixture"
    assert long_job["actions"]["pause"]["expected_record_version"] == (
        long_job["record_version"]
    )
    assert isinstance(long_job["current_stage_label"], str)
    assert isinstance(long_job["active_stage_labels"], list)
    assert isinstance(long_job["active_resources"], list)
    assert "waiting_reason" in long_job
    assert "latest_checkpoint_label" in long_job

    app.state.scheduler.tick()
    resources = client.get(
        "/api/v1/resources",
        headers=_read_headers(),
    ).json()["resources"]
    required_resource_fields = {
        "resource_id",
        "display_name",
        "status_label",
        "capacity",
        "in_use",
        "waiting_jobs",
        "holder_label",
    }
    assert resources
    assert all(required_resource_fields <= resource.keys() for resource in resources)
    assert any(resource["in_use"] == 1 for resource in resources)
    assert all(resource["resource_id"] for resource in resources)

    refreshed = client.get(
        f"/api/v1/jobs/{long_job['job_id']}",
        headers=_read_headers(),
    ).json()
    assert refreshed["active_resources"]
    assert all(
        resource["display_name"] != resource["resource_id"]
        for resource in refreshed["active_resources"]
    )


def test_fixture_start_version_is_scoped_and_reusable_after_terminal_job(
    loop3_client: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_client
    first = _create_fixture(
        client,
        csrf,
        "audit-batch-short-002",
        key="restart-first",
        expected_record_version=0,
    )
    app.state.scheduler.run_until_quiescent(max_ticks=30)

    snapshot = client.get("/api/v1/jobs", headers=_read_headers()).json()
    restart_action = snapshot["start_actions"]["start_audit_short"]
    assert restart_action["enabled"] is True
    assert restart_action["expected_record_version"] > 0

    stale = client.post(
        "/api/v1/jobs",
        json={
            "task_type": "audit",
            "job_kind": "test_fixture",
            "scope": {
                "label": "stale restart",
                "fixture_id": "audit-batch-short-002",
            },
            "expected_record_version": 0,
        },
        headers=_write_headers(csrf, "restart-stale"),
    )
    second = _create_fixture(
        client,
        csrf,
        "audit-batch-short-002",
        key="restart-second",
        expected_record_version=restart_action["expected_record_version"],
    )

    assert stale.status_code == 409
    assert stale.json()["error"]["code"] == "record_version_conflict"
    assert second["job_id"] != first["job_id"]


def test_conflict_creation_and_control_cas_are_atomic_under_threads(
    tmp_path: Path,
) -> None:
    repository = TemporarySqliteJobRepository(tmp_path)
    fixture = get_loop3_fixture("audit-batch-short-002")
    create_barrier = Barrier(2)

    def create(index: int) -> str:
        create_barrier.wait()
        try:
            job, _ = repository.create_scheduled_job(
                fixture=fixture,
                scope_label=f"parallel-{index}",
                idempotency_key=f"parallel-create-{index}",
                request_hash=f"parallel-create-hash-{index}",
                expected_record_version=0,
            )
        except (ActiveScopeConflictError, RecordVersionConflictError):
            return "conflict"
        return job.job_id

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            create_results = list(executor.map(create, range(2)))
        created_ids = [result for result in create_results if result != "conflict"]
        assert len(created_ids) == 1
        assert create_results.count("conflict") == 1

        job = repository.get_job(created_ids[0])
        repository.request_job_control(
            job_id=job.job_id,
            action="pause",
            expected_record_version=job.record_version,
            idempotency_key="parallel-pause",
            request_hash="parallel-pause-hash",
        )
        scheduler = CooperativeScheduler(repository)
        scheduler.tick()
        paused = repository.get_job(job.job_id)
        assert paused.status.value == "paused"

        control_barrier = Barrier(2)

        def control(action: str) -> str:
            control_barrier.wait()
            try:
                repository.request_job_control(
                    job_id=job.job_id,
                    action=action,
                    expected_record_version=paused.record_version,
                    idempotency_key=f"parallel-{action}",
                    request_hash=f"parallel-{action}-hash",
                )
            except RecordVersionConflictError:
                return "conflict"
            return action

        with ThreadPoolExecutor(max_workers=2) as executor:
            control_results = list(executor.map(control, ("resume", "cancel")))
        assert control_results.count("conflict") == 1
        assert len([result for result in control_results if result != "conflict"]) == 1
    finally:
        repository.close()


def test_control_boundary_emits_final_paused_and_cancelled_events(
    loop3_client: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_client
    job = _create_fixture(
        client,
        csrf,
        "audit-batch-short-002",
        key="boundary-create",
        expected_record_version=0,
    )
    pause = client.post(
        f"/api/v1/jobs/{job['job_id']}/pause",
        json={"expected_record_version": job["record_version"]},
        headers=_write_headers(csrf, "boundary-pause"),
    )
    assert pause.status_code == 200
    pause_request_cursor = app.state.repository.event_cursor()

    app.state.scheduler.tick()
    paused_events = app.state.repository.events_after(pause_request_cursor)
    assert [event["event_type"] for event in paused_events] == ["job.paused"]
    paused = client.get(
        f"/api/v1/jobs/{job['job_id']}",
        headers=_read_headers(),
    ).json()

    resume = client.post(
        f"/api/v1/jobs/{job['job_id']}/resume",
        json={"expected_record_version": paused["record_version"]},
        headers=_write_headers(csrf, "boundary-resume"),
    )
    assert resume.status_code == 200
    resumed = resume.json()["job"]
    cancel = client.post(
        f"/api/v1/jobs/{job['job_id']}/cancel",
        json={"expected_record_version": resumed["record_version"]},
        headers=_write_headers(csrf, "boundary-cancel"),
    )
    assert cancel.status_code == 200
    cancel_request_cursor = app.state.repository.event_cursor()

    app.state.scheduler.tick()
    cancelled_events = app.state.repository.events_after(cancel_request_cursor)
    assert [event["event_type"] for event in cancelled_events] == [
        "job.cancelled",
        "work_item.changed",
    ]
    cancelled = client.get(
        f"/api/v1/jobs/{job['job_id']}",
        headers=_read_headers(),
    ).json()
    assert cancelled["counts"] == {
        "total": 1,
        "processed": 0,
        "remaining": 1,
        "waiting_user": 0,
        "failed": 0,
    }
    assert cancelled["progress_label"] == (
        "任务已取消；已处理 0/1，1 项未处理"  # noqa: RUF001
    )


def test_every_resource_projection_change_advances_the_event_cursor(
    loop3_client: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_client
    _create_fixture(
        client,
        csrf,
        "audit-batch-long-001",
        key="resource-events-long",
        expected_record_version=0,
    )
    _create_fixture(
        client,
        csrf,
        "audit-batch-short-002",
        key="resource-events-short",
        expected_record_version=0,
    )

    changed_ticks = 0
    for _ in range(15):
        before = app.state.repository.resources_projection()
        cursor = app.state.repository.event_cursor()
        app.state.scheduler.tick()
        after = app.state.repository.resources_projection()
        if after == before:
            continue
        changed_ticks += 1
        events = app.state.repository.events_after(cursor)
        assert any(
            event["event_type"] == "resource.changed"
            and event["aggregate_type"] == "resource"
            for event in events
        )
        assert any(
            event["event_type"] == "work_item.changed"
            and event["aggregate_type"] == "work_item"
            for event in events
        )

    assert changed_ticks > 0


def test_failed_shared_work_fails_future_consumer_without_human_review(
    loop3_client: tuple[FastAPI, TestClient, str],
) -> None:
    app, client, csrf = loop3_client
    long_job = _create_fixture(
        client,
        csrf,
        "audit-batch-long-001",
        key="shared-failure-long",
        expected_record_version=0,
    )
    scheduler = app.state.scheduler
    scheduler.inject_ocr_failure(SHARED_LOADING_IMAGE_SHA256)
    scheduler.run_until_quiescent(max_ticks=80)
    assert client.get(
        f"/api/v1/jobs/{long_job['job_id']}",
        headers=_read_headers(),
    ).json()["job_status"] == "failed"

    short_job = _create_fixture(
        client,
        csrf,
        "audit-batch-short-002",
        key="shared-failure-short",
        expected_record_version=0,
    )
    scheduler.run_until_quiescent(max_ticks=10)
    failed = client.get(
        f"/api/v1/jobs/{short_job['job_id']}",
        headers=_read_headers(),
    ).json()
    item = client.get(
        f"/api/v1/jobs/{short_job['job_id']}/items",
        headers=_read_headers(),
    ).json()["items"][0]

    assert failed["job_status"] == "failed"
    assert failed["counts"]["waiting_user"] == 0
    assert item["business_outcome"] is None
    assert item["review_reason"] is None
    assert item["diagnostic_code"] == "LOOP3-FAKE-OCR-FAILURE"


def test_restart_keeps_one_scheduler_owner_for_queued_loop3_job(
    tmp_path: Path,
) -> None:
    first_app = create_app(
        data_root=tmp_path,
        auto_run_jobs=False,
        stage_delay_seconds=0,
        enable_test_fixtures=True,
    )
    with TestClient(first_app) as first_client:
        session = first_client.get(
            "/api/v1/session",
            headers=_read_headers(),
        )
        job = _create_fixture(
            first_client,
            str(session.json()["csrf_token"]),
            "audit-batch-short-002",
            key="restart-owner-create",
            expected_record_version=0,
        )

    second_app = create_app(
        data_root=tmp_path,
        auto_run_jobs=True,
        stage_delay_seconds=0,
        enable_test_fixtures=True,
    )
    with TestClient(second_app) as second_client:
        session = second_client.get(
            "/api/v1/session",
            headers=_read_headers(),
        )
        assert session.status_code == 200
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            restored = second_client.get(
                f"/api/v1/jobs/{job['job_id']}",
                headers=_read_headers(),
            ).json()
            if restored["job_status"] in {"succeeded", "failed"}:
                break
            time.sleep(0.01)
        else:
            raise AssertionError("restored job did not become quiescent")

    assert restored["job_status"] == "succeeded"
    assert restored["diagnostic_code"] is None
    assert not hasattr(second_app.state, "runner")
