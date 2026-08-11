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
from sqlalchemy import select

from dahe.adapters.sqlite.daily_items import SqliteDailyItemRepository
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.schema import DAILY_REPORTS
from dahe.api.daily_items import build_daily_item_router
from dahe.api.errors import ApiError
from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyWaybillObservation,
)

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
                "expected_record_version": item["record_version"],
                "changes": {"unloading_time": None},
            },
        )
        assert saved.status_code == 200
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
