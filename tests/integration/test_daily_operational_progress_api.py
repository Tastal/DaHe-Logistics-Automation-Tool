from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import update

from dahe import __version__
from dahe.adapters.sqlite.schema import (
    JOBS,
    OPERATIONAL_CAPTURE_RUNS,
    OPERATIONAL_REVIEW_LINKS,
    WORK_ITEMS,
)
from dahe.api.app import create_app
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec

PROJECT_ROOT = Path(__file__).parents[2]
ORIGIN = "http://127.0.0.1:8877"


def _headers() -> dict[str, str]:
    return {
        "Host": "127.0.0.1:8877",
        "Origin": ORIGIN,
        "X-DaHe-Client-Version": __version__,
    }


def _create_job(repository: object, spec: ScheduledJobSpec) -> str:
    job, created = repository.create_scheduled_job(
        fixture=spec,
        scope_label=spec.scope_label,
        idempotency_key=f"test:{spec.fixture_id}",
        request_hash=hashlib.sha256(
            spec.fixture_id.encode("utf-8")
        ).hexdigest(),
        expected_record_version=0,
    )
    assert created is True
    return job.job_id


def test_daily_progress_reconciles_fetch_ocr_missing_and_failure_counts(
    tmp_path: Path,
) -> None:
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=uuid4().hex,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        repository = app.state.repository
        daily_job_id = _create_job(
            repository,
            ScheduledJobSpec(
                fixture_id="daily-operational-batch-v1:2026-08-01",
                job_kind="business",
                task_type="daily",
                scope_label="装卸车明细 2026-08-01",
                conflict_key="daily:2026-08-01",
                items=(
                    ScheduledWorkItemSpec(
                        item_key="daily:2026-08-01",
                        expected_outcome=None,
                    ),
                ),
                run_mode="operational",
            ),
        )
        ocr_job_id = _create_job(
            repository,
            ScheduledJobSpec(
                fixture_id="daily-observation:test:1",
                job_kind="observation",
                task_type="audit",
                scope_label="装卸车识别 2026-08-01 第 1 批",
                conflict_key="daily-ocr:test:1",
                items=tuple(
                    ScheduledWorkItemSpec(
                        item_key=f"YD-{index}",
                        expected_outcome=None,
                        loading_image_sha256="a" * 64,
                        unloading_image_sha256="b" * 64,
                        loading_image_relative_path="evidence/a.blob",
                        unloading_image_relative_path="evidence/b.blob",
                        evidence_preloaded=True,
                    )
                    for index in range(2)
                ),
                pipeline_fingerprint="c" * 64,
                ocr_execution_mode="local",
                run_mode="operational",
            ),
        )
        runtime = app.state.sqlite_runtime
        persisted_items = tuple(repository.list_items(ocr_job_id))
        assert all(item.download_complete for item in persisted_items)
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                OPERATIONAL_CAPTURE_RUNS.insert().values(
                    job_id=daily_job_id,
                    scope="daily:2026-08-01",
                    total=20,
                    items_json="[]",
                    items_sha256="d" * 64,
                    next_item_index=15,
                    committed_batch_count=1,
                    batch_size=15,
                    detail_concurrency=4,
                    image_concurrency=6,
                    status="collecting",
                    record_version=2,
                    created_at="2026-08-01T10:00:00+00:00",
                    updated_at="2026-08-01T10:00:00+00:00",
                )
            )
            items = tuple(repository.list_items(ocr_job_id))
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == items[0].work_item_id)
                .values(status="succeeded")
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.work_item_id == items[1].work_item_id)
                .values(status="failed")
            )
        app.state.daily_operational_ocr_store.register_batch(
            daily_job_id=daily_job_id,
            batch_number=1,
            ocr_job_id=ocr_job_id,
            eligible_item_count=2,
            missing_ticket_count=1,
        )

        session = client.get("/api/v1/session", headers=_headers())
        assert session.status_code == 200
        response = client.get(
            f"/api/v1/platform/business-reads/{daily_job_id}/progress",
            headers=_headers(),
        )

    assert response.status_code == 200
    payload = response.json()
    assert {
        key: payload[key]
        for key in (
            "job_id",
            "total",
            "fetched",
            "recognized",
            "missing_fields",
            "technical_failed",
            "committed_batches",
        )
    } == {
        "job_id": daily_job_id,
        "total": 20,
        "fetched": 15,
        "recognized": 1,
        "missing_fields": 1,
        "technical_failed": 1,
        "committed_batches": 1,
    }
    assert payload["phase"] == "download"
    assert payload["phase_label"] == "正在下载磅单"
    assert payload["progress_current"] == 15
    assert payload["progress_total"] == 20
    assert payload["estimate_state"] in {"estimating", "estimated"}
    assert payload["elapsed_seconds"] >= 0


@pytest.mark.parametrize(
    ("transient_phase", "completed", "total", "expected_phase", "label"),
    (
        ("detail", 51, 68, "read", "正在读取运单"),
        ("image", 100, 136, "download", "正在下载磅单"),
    ),
)
def test_daily_progress_uses_the_transient_phase_unit_without_mixing_totals(
    tmp_path: Path,
    transient_phase: str,
    completed: int,
    total: int,
    expected_phase: str,
    label: str,
) -> None:
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=uuid4().hex,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        job_id = _create_job(
            app.state.repository,
            ScheduledJobSpec(
                fixture_id="daily-operational-batch-v1:2026-08-08",
                job_kind="business",
                task_type="daily",
                scope_label="装卸车明细 2026-08-08",
                conflict_key="daily:2026-08-08",
                items=(
                    ScheduledWorkItemSpec(
                        item_key="daily:2026-08-08",
                        expected_outcome=None,
                    ),
                ),
                run_mode="operational",
            ),
        )
        app.state.transient_business_progress_store.publish(
            job_id,
            transient_phase,
            completed,
            total,
        )
        session = client.get("/api/v1/session", headers=_headers())
        assert session.status_code == 200
        response = client.get(
            f"/api/v1/platform/business-reads/{job_id}/progress",
            headers=_headers(),
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["phase"] == expected_phase
    assert payload["phase_label"] == label
    assert payload["progress_current"] == completed
    assert payload["progress_total"] == total
    assert payload["progress_current"] <= payload["progress_total"]


def test_zero_result_success_freezes_terminal_timing(tmp_path: Path) -> None:
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=uuid4().hex,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        job_id = _create_job(
            app.state.repository,
            ScheduledJobSpec(
                fixture_id="daily-operational-batch-v1:2026-08-01",
                job_kind="business",
                task_type="daily",
                scope_label="装卸车明细 2026-08-01",
                conflict_key="daily:2026-08-01",
                items=(
                    ScheduledWorkItemSpec(
                        item_key="daily:2026-08-01",
                        expected_outcome=None,
                    ),
                ),
                run_mode="operational",
            ),
        )
        terminal_at = "2026-08-01T10:00:18+00:00"
        with app.state.sqlite_runtime.commit_gate.transaction(
            app.state.sqlite_runtime.engine
        ) as connection:
            connection.execute(
                update(JOBS)
                .where(JOBS.c.job_id == job_id)
                .values(status="succeeded", updated_at=terminal_at)
            )
        session = client.get("/api/v1/session", headers=_headers())
        assert session.status_code == 200
        first = client.get(
            f"/api/v1/platform/business-reads/{job_id}/progress",
            headers=_headers(),
        ).json()
        second = client.get(
            f"/api/v1/platform/business-reads/{job_id}/progress",
            headers=_headers(),
        ).json()

    assert first["phase"] == "complete"
    assert first["progress_current"] == 0
    assert first["progress_total"] == 0
    assert first["is_terminal"] is True
    assert first["finished_at"] == terminal_at
    assert first["estimate_state"] == "complete"
    assert first["estimated_remaining_seconds"] == 0
    assert second["elapsed_seconds"] == first["elapsed_seconds"]


@pytest.mark.parametrize(
    ("review_status", "item_status", "expected_phase"),
    (
        ("waiting_user", "waiting_user", "complete"),
        ("failed", "failed", "incomplete"),
    ),
)
def test_whole_run_daily_progress_distinguishes_human_review_from_failure(
    tmp_path: Path,
    review_status: str,
    item_status: str,
    expected_phase: str,
) -> None:
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=uuid4().hex,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        repository = app.state.repository
        daily_job_id = _create_job(
            repository,
            ScheduledJobSpec(
                fixture_id="daily-operational-whole-run-v1:2026-08-09",
                job_kind="business",
                task_type="daily",
                scope_label="daily whole run",
                conflict_key="daily:2026-08-09",
                items=(
                    ScheduledWorkItemSpec(
                        item_key="daily:2026-08-09",
                        expected_outcome=None,
                    ),
                ),
                run_mode="operational",
            ),
        )
        review_job_id = _create_job(
            repository,
            ScheduledJobSpec(
                fixture_id="daily-observation-whole-run-v1:test",
                job_kind="observation",
                task_type="audit",
                scope_label="daily review whole run",
                conflict_key="daily-review:2026-08-09",
                    items=(
                        ScheduledWorkItemSpec(
                            item_key="YD-WHOLE-001",
                            expected_outcome=None,
                            loading_image_sha256="a" * 64,
                            unloading_image_sha256="b" * 64,
                        ),
                    ),
                    pipeline_fingerprint="c" * 64,
                    run_mode="operational",
            ),
        )
        with app.state.sqlite_runtime.commit_gate.transaction(
            app.state.sqlite_runtime.engine
        ) as connection:
            connection.execute(
                update(JOBS)
                .where(JOBS.c.job_id == daily_job_id)
                .values(status="succeeded")
            )
            connection.execute(
                update(JOBS)
                .where(JOBS.c.job_id == review_job_id)
                .values(status=review_status)
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.job_id == review_job_id)
                .values(status=item_status)
            )
            connection.execute(
                OPERATIONAL_CAPTURE_RUNS.insert().values(
                    job_id=daily_job_id,
                    scope="daily:2026-08-09",
                    total=1,
                    items_json="[]",
                    items_sha256="d" * 64,
                    next_item_index=1,
                    committed_batch_count=1,
                    capture_mode="whole_run_v1",
                    batch_size=1,
                    detail_concurrency=4,
                    image_concurrency=6,
                    status="complete",
                    record_version=2,
                    metadata_checked_count=1,
                    reused_count=0,
                    images_downloaded_count=2,
                    created_at="2026-08-09T10:00:00+00:00",
                    updated_at="2026-08-09T10:01:00+00:00",
                )
            )
            connection.execute(
                OPERATIONAL_REVIEW_LINKS.insert().values(
                    source_job_id=daily_job_id,
                    business_kind="daily",
                    review_job_id=review_job_id,
                    eligible_item_count=1,
                    missing_item_count=0,
                    source_manifest_sha256="e" * 64,
                    created_at="2026-08-09T10:01:00+00:00",
                )
            )
        session = client.get("/api/v1/session", headers=_headers())
        assert session.status_code == 200
        payload = client.get(
            f"/api/v1/platform/business-reads/{daily_job_id}/progress",
            headers=_headers(),
        ).json()

    assert payload["phase"] == expected_phase
    assert payload["is_terminal"] is True
    assert payload["visible_prefix_count"] == 1


@pytest.mark.parametrize("terminal_status", ("failed", "cancelled"))
def test_terminal_failure_or_cancel_freezes_timing(
    tmp_path: Path,
    terminal_status: str,
) -> None:
    app = create_app(
        data_root=tmp_path,
        project_root=PROJECT_ROOT,
        instance_id=uuid4().hex,
        auto_run_jobs=False,
        stage_delay_seconds=0,
    )
    with TestClient(app) as client:
        job_id = _create_job(
            app.state.repository,
            ScheduledJobSpec(
                fixture_id=f"daily-operational-batch-v1:{terminal_status}",
                job_kind="business",
                task_type="daily",
                scope_label="装卸车明细终态测试",
                conflict_key=f"daily:{terminal_status}",
                items=(
                    ScheduledWorkItemSpec(
                        item_key=f"daily:{terminal_status}",
                        expected_outcome=None,
                    ),
                ),
                run_mode="operational",
            ),
        )
        terminal_at = "2026-08-01T10:00:18+00:00"
        with app.state.sqlite_runtime.commit_gate.transaction(
            app.state.sqlite_runtime.engine
        ) as connection:
            connection.execute(
                update(JOBS)
                .where(JOBS.c.job_id == job_id)
                .values(status=terminal_status, updated_at=terminal_at)
            )
        session = client.get("/api/v1/session", headers=_headers())
        assert session.status_code == 200
        first = client.get(
            f"/api/v1/platform/business-reads/{job_id}/progress",
            headers=_headers(),
        ).json()
        second = client.get(
            f"/api/v1/platform/business-reads/{job_id}/progress",
            headers=_headers(),
        ).json()

    assert first["phase"] == "incomplete"
    assert first["is_terminal"] is True
    assert first["finished_at"] == terminal_at
    assert first["estimate_state"] == "complete"
    assert first["estimated_remaining_seconds"] == 0
    assert second["elapsed_seconds"] == first["elapsed_seconds"]
