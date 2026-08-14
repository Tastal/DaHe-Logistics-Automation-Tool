# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import select, update

from dahe.adapters.sqlite.daily_items import (
    DailySourceContext,
    SqliteDailyItemRepository,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import (
    DAILY_REPORTS,
    JOBS,
    OPERATIONAL_CAPTURE_RUNS,
    OPERATIONAL_REVIEW_LINKS,
    WORK_ITEMS,
)
from dahe.api.daily_items import build_daily_item_router
from dahe.api.errors import ApiError
from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyWaybillObservation,
)
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec

PROJECT_ROOT = Path(__file__).parents[2]
HASH_A = hashlib.sha256(b"daily-item-a").hexdigest()
HASH_B = hashlib.sha256(b"daily-item-b").hexdigest()
HASH_C = hashlib.sha256(b"daily-item-c").hexdigest()


def _fixture(
    tmp_path: Path,
    *,
    item_count: int = 1,
    missing_unloading_time: bool = False,
) -> tuple[TestClient, SqliteRuntime, SqliteDailyStore]:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="daily-items-api",
    )
    store = SqliteDailyStore(runtime)
    captured_at = datetime(2026, 8, 5, 20, 0, tzinfo=SHANGHAI)
    store.save_snapshot(
        DailyCandidateSnapshot(
            snapshot_id="daily-items-snapshot",
            target_business_date=date(2026, 8, 5),
            receive_place="榆林",
            query_window=candidate_query_window(date(2026, 8, 5), now=captured_at),
            source_contract_sha256=HASH_A,
            candidates=tuple(
                DailyCandidate(f"platform-{index}", f"YD-{index:03d}")
                for index in range(1, item_count + 1)
            ),
            captured_at=captured_at,
        )
    )
    for index in range(1, item_count + 1):
        store.save_observation(
            DailyWaybillObservation(
                observation_id=f"daily-items-observation-{index}",
                snapshot_id="daily-items-snapshot",
                platform_waybill_id=f"platform-{index}",
                waybill_number=f"YD-{index:03d}",
                fields=DailyObservationFields(
                    shipping_mine="金鸡滩煤矿",
                    planned_date=date(2026, 8, 5),
                    loading_time=datetime(2026, 8, 5, 18, 57, 54, tzinfo=SHANGHAI),
                    vehicle_number="陕A12345",
                    loading_net_tonnes=Decimal("33.08"),
                    unloading_net_tonnes=Decimal("33.04"),
                    coal_type="兖矿陕动四号（5600）",
                    unloading_place="象道货22",
                    unloading_time=(
                        None
                        if missing_unloading_time
                        else datetime(2026, 8, 5, 19, 42, 27, tzinfo=SHANGHAI)
                    ),
                ),
                loading_ticket_sha256=HASH_B,
                unloading_ticket_sha256=HASH_C,
                source_detail_sha256=HASH_A,
                observed_at=captured_at,
            )
        )
    repository = SqliteDailyItemRepository(runtime, store)

    def require_session() -> None:
        return None

    def require_write(idempotency_key: str = Header(alias="Idempotency-Key")) -> str:
        return idempotency_key

    app = FastAPI()

    @app.exception_handler(ApiError)
    async def handle_api_error(_, exc: ApiError):  # type: ignore[no-untyped-def]
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    app.include_router(
        build_daily_item_router(
            enabled=True,
            repository=repository,
            require_session=require_session,
            require_write=require_write,
        )
    )
    return TestClient(app), runtime, store


@pytest.mark.integration
def test_saved_business_day_lists_all_70_items_without_a_new_capture(
    tmp_path: Path,
) -> None:
    client, runtime, _ = _fixture(tmp_path, item_count=70)
    try:
        response = client.get("/api/v1/daily/items?business_date=2026-08-05")
        assert response.status_code == 200
        assert response.json()["counts"] == {
            "all": 70,
            "needs_review": 0,
            "reviewed": 70,
            "complete": 70,
        }
        assert all(item["review_state"] == "reviewed" for item in response.json()["items"])
        assert all(item["materialized_at"] for item in response.json()["items"])
        identities = [item["waybill_number"] for item in response.json()["items"]]
        assert len(set(identities)) == 70
        repeated = client.get("/api/v1/daily/items?business_date=2026-08-05")
        assert [item["waybill_number"] for item in repeated.json()["items"]] == identities
    finally:
        runtime.close()


@pytest.mark.integration
def test_whole_run_projects_unchanged_current_observation_without_duplicate_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, runtime, store = _fixture(tmp_path)
    repository = SqliteJobRepository(
        runtime,
        scheduler_instance_id="daily-items-whole-run",
    )
    captured_at = datetime(2026, 8, 5, 20, 30, tzinfo=SHANGHAI)
    source_job, _ = repository.create_scheduled_job(
        fixture=ScheduledJobSpec(
            fixture_id="daily-operational-whole-run-v1:2026-08-05",
            job_kind="business",
            task_type="daily",
            scope_label="daily whole run",
            conflict_key="daily:2026-08-05:whole-run",
            items=(
                ScheduledWorkItemSpec(
                    item_key="daily:2026-08-05",
                    expected_outcome=None,
                ),
            ),
            run_mode="operational",
        ),
        scope_label="daily whole run",
        idempotency_key="daily-whole-run-source",
        request_hash=HASH_A,
        expected_record_version=0,
    )
    review_job, _ = repository.create_scheduled_job(
        fixture=ScheduledJobSpec(
            fixture_id="daily-observation-whole-run-v1:unchanged",
            job_kind="observation",
            task_type="audit",
            scope_label="daily whole-run review",
            conflict_key="daily-review:2026-08-05:unchanged",
            items=(
                ScheduledWorkItemSpec(
                    item_key="YD-001",
                    expected_outcome=None,
                    loading_image_sha256=HASH_B,
                    unloading_image_sha256=HASH_C,
                ),
            ),
            pipeline_fingerprint=HASH_A,
            run_mode="operational",
        ),
        scope_label="daily whole-run review",
        idempotency_key="daily-whole-run-review",
        request_hash=HASH_B,
        expected_record_version=0,
    )
    try:
        store.save_snapshot(
            DailyCandidateSnapshot(
                snapshot_id=source_job.job_id,
                target_business_date=date(2026, 8, 5),
                receive_place="current-source",
                query_window=candidate_query_window(
                    date(2026, 8, 5), now=captured_at
                ),
                source_contract_sha256=HASH_A,
                candidates=(DailyCandidate("platform-1", "YD-001"),),
                captured_at=captured_at,
            )
        )
        original = store.list_revisions("platform-1")[-1]
        saved = store.save_observation(
            DailyWaybillObservation(
                observation_id="daily-items-current-observation",
                snapshot_id=source_job.job_id,
                platform_waybill_id="platform-1",
                waybill_number="YD-001",
                fields=original.fields,
                loading_ticket_sha256=original.loading_ticket_sha256,
                unloading_ticket_sha256=original.unloading_ticket_sha256,
                source_detail_sha256=HASH_A,
                observed_at=captured_at,
            )
        )
        assert saved.revision_appended is False
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                update(JOBS)
                .where(JOBS.c.job_id.in_((source_job.job_id, review_job.job_id)))
                .values(status="succeeded")
            )
            connection.execute(
                update(WORK_ITEMS)
                .where(WORK_ITEMS.c.job_id == review_job.job_id)
                .values(status="succeeded")
            )
            connection.execute(
                OPERATIONAL_CAPTURE_RUNS.insert().values(
                    job_id=source_job.job_id,
                    scope="daily:2026-08-05",
                    total=1,
                    items_json='[{"waybill_number":"YD-001"}]',
                    items_sha256=HASH_C,
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
                    created_at=captured_at.isoformat(),
                    updated_at=captured_at.isoformat(),
                )
            )
            connection.execute(
                OPERATIONAL_REVIEW_LINKS.insert().values(
                    source_job_id=source_job.job_id,
                    business_kind="daily",
                    review_job_id=review_job.job_id,
                    eligible_item_count=1,
                    missing_item_count=0,
                    source_manifest_sha256=HASH_A,
                    created_at=captured_at.isoformat(),
                )
            )
        monkeypatch.setattr(
            SqliteDailyItemRepository,
            "latest_source_context",
            lambda _self, _date, **_kwargs: DailySourceContext(
                source_job_id=source_job.job_id,
                source_record_version=2,
                capture_mode="whole_run_v1",
                online_capture_complete=True,
            ),
        )
        monkeypatch.setattr(
            SqliteDailyItemRepository,
            "_load_materialized_observations",
            lambda _self, revisions, **_kwargs: {
                revision.observation_id: captured_at.isoformat()
                for revision in revisions
            },
        )

        response = client.get("/api/v1/daily/items?business_date=2026-08-05")

        assert response.status_code == 200
        assert response.json()["counts"]["all"] == 1
        assert [item["waybill_number"] for item in response.json()["items"]] == [
            "YD-001"
        ]
        assert len(store.list_revisions("platform-1")) == 1
    finally:
        runtime.close()


@pytest.mark.integration
def test_daily_item_revision_is_append_only_idempotent_and_keeps_seconds(
    tmp_path: Path,
) -> None:
    client, runtime, _ = _fixture(tmp_path)
    try:
        listed = client.get("/api/v1/daily/items?business_date=2026-08-05")
        assert listed.status_code == 200
        assert listed.json()["counts"] == {
            "all": 1,
            "needs_review": 0,
            "reviewed": 1,
            "complete": 1,
        }
        version = listed.json()["items"][0]["record_version"]
        payload = {
            "business_date": "2026-08-05",
            "expected_record_version": version,
            "changes": {
                "loading_net_tonnes": "33.10",
                "unloading_time": "2026-08-05T19:42:47+08:00",
            },
        }
        saved = client.post(
            "/api/v1/daily/items/platform-1/revisions",
            headers={"Idempotency-Key": "daily-revision-1"},
            json=payload,
        )
        replay = client.post(
            "/api/v1/daily/items/platform-1/revisions",
            headers={"Idempotency-Key": "daily-revision-1"},
            json=payload,
        )
        assert saved.status_code == 200
        assert replay.status_code == 200
        assert replay.json()["idempotent_replay"] is True
        item = saved.json()["item"]
        assert item["effective_fields"]["loading_net_tonnes"] == "33.10"
        assert item["effective_fields"]["unloading_time"].endswith("19:42:47+08:00")
        assert item["field_sources"]["loading_net_tonnes"] == "manual"

        stale = client.post(
            "/api/v1/daily/items/platform-1/revisions",
            headers={"Idempotency-Key": "daily-revision-stale"},
            json={
                "business_date": "2026-08-05",
                "expected_record_version": version,
                "changes": {"loading_net_tonnes": "33.11"},
            },
        )
        assert stale.status_code == 409
    finally:
        runtime.close()


@pytest.mark.integration
def test_missing_machine_field_is_reviewed_only_after_manual_resolution(
    tmp_path: Path,
) -> None:
    client, runtime, _ = _fixture(tmp_path, missing_unloading_time=True)
    try:
        listed = client.get(
            "/api/v1/daily/items?business_date=2026-08-05&view=needs_review"
        )
        assert listed.status_code == 200
        body = listed.json()
        assert body["counts"] == {
            "all": 1,
            "needs_review": 1,
            "reviewed": 0,
            "complete": 0,
        }
        item = body["items"][0]
        assert item["review_state"] == "needs_review"
        assert item["time_prefill"]["unloading_date"] == "2026-08-05"

        saved = client.post(
            "/api/v1/daily/items/platform-1/revisions",
            headers={"Idempotency-Key": "daily-resolve-blank"},
            json={
                "business_date": "2026-08-05",
                "expected_record_version": item["record_version"],
                "changes": {"unloading_time": None},
            },
        )
        assert saved.status_code == 200
        assert saved.json()["business_date"] == "2026-08-05"
        assert saved.json()["counts"] == {
            "all": 1,
            "needs_review": 0,
            "reviewed": 1,
            "complete": 1,
        }
        assert saved.json()["item"]["review_state"] == "reviewed"

        reviewed = client.get(
            "/api/v1/daily/items?business_date=2026-08-05&view=reviewed"
        ).json()
        assert reviewed["counts"]["reviewed"] == 1
        assert [entry["platform_waybill_id"] for entry in reviewed["items"]] == ["platform-1"]
        assert client.get(
            "/api/v1/daily/items?business_date=2026-08-05&view=needs_review"
        ).json()["items"] == []
    finally:
        runtime.close()


@pytest.mark.integration
def test_explicit_blank_survives_until_the_corresponding_ticket_changes(
    tmp_path: Path,
) -> None:
    client, runtime, store = _fixture(tmp_path)
    try:
        initial = client.get("/api/v1/daily/items?business_date=2026-08-05").json()["items"][0]
        saved = client.post(
            "/api/v1/daily/items/platform-1/revisions",
            headers={"Idempotency-Key": "daily-blank"},
            json={
                "business_date": "2026-08-05",
                "expected_record_version": initial["record_version"],
                "changes": {
                    "loading_net_tonnes": None,
                    "unloading_net_tonnes": "32.90",
                },
            },
        )
        assert saved.status_code == 200
        assert saved.json()["item"]["effective_fields"]["loading_net_tonnes"] is None

        original = store.list_revisions("platform-1")[-1]
        store.save_observation(
            DailyWaybillObservation(
                observation_id="daily-items-observation-2",
                snapshot_id="daily-items-snapshot",
                platform_waybill_id="platform-1",
                waybill_number="YD-001",
                fields=original.fields,
                loading_ticket_sha256=HASH_A,
                unloading_ticket_sha256=HASH_C,
                source_detail_sha256=HASH_B,
                observed_at=datetime(2026, 8, 5, 20, 30, tzinfo=SHANGHAI),
            )
        )
        current = client.get("/api/v1/daily/items?business_date=2026-08-05").json()["items"][0]
        assert current["effective_fields"]["loading_net_tonnes"] == "33.08"
        assert current["field_sources"]["loading_net_tonnes"] == "machine"
        assert current["effective_fields"]["unloading_net_tonnes"] == "32.90"
        assert current["field_sources"]["unloading_net_tonnes"] == "manual"
    finally:
        runtime.close()


@pytest.mark.integration
def test_manual_revision_marks_existing_report_stale(tmp_path: Path) -> None:
    client, runtime, _ = _fixture(tmp_path)
    try:
        with runtime.commit_gate.transaction(runtime.engine) as connection:
            connection.execute(
                DAILY_REPORTS.insert().values(
                    report_id="report-1",
                    business_date="2026-08-05",
                    contract_subject_code="shanxi_guienbo",
                    status="confirmed",
                    settings_record_version=1,
                    output_directory=str(tmp_path),
                    file_name="report.xlsx",
                    file_sha256=HASH_A,
                    data_snapshot_sha256=HASH_B,
                    data_json="[]",
                    row_count=1,
                    loading_net_total="33.08",
                    record_version=2,
                    created_at="2026-08-05T20:00:00+00:00",
                    confirmed_at="2026-08-05T20:01:00+00:00",
                    stale=0,
                )
            )
        version = client.get("/api/v1/daily/items?business_date=2026-08-05").json()["items"][0][
            "record_version"
        ]
        response = client.post(
            "/api/v1/daily/items/platform-1/revisions",
            headers={"Idempotency-Key": "daily-stale-report"},
            json={
                "business_date": "2026-08-05",
                "expected_record_version": version,
                "changes": {"loading_time": "2026-08-05T18:58:00+08:00"},
            },
        )
        assert response.status_code == 200
        with runtime.engine.connect() as connection:
            row = connection.execute(select(DAILY_REPORTS)).mappings().one()
        assert row["stale"] == 1
        assert row["record_version"] == 3
    finally:
        runtime.close()


@pytest.mark.integration
def test_daily_revision_rejects_a_different_business_date(tmp_path: Path) -> None:
    client, runtime, _ = _fixture(tmp_path, missing_unloading_time=True)
    try:
        item = client.get(
            "/api/v1/daily/items?business_date=2026-08-05"
        ).json()["items"][0]
        response = client.post(
            "/api/v1/daily/items/platform-1/revisions",
            headers={"Idempotency-Key": "daily-wrong-date"},
            json={
                "business_date": "2026-08-06",
                "expected_record_version": item["record_version"],
                "changes": {"unloading_time": None},
            },
        )
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "daily_item_business_date_conflict"
    finally:
        runtime.close()
