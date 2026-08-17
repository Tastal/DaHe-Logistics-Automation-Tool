# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest
from fastapi import FastAPI, Header
from fastapi.testclient import TestClient

from dahe.adapters.sqlite.daily_reports import SqliteDailyReportRepository
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.api.daily_reports import build_daily_report_router
from dahe.api.errors import ApiError
from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyRecordRevision,
    DailyWaybillObservation,
)

PROJECT_ROOT = Path(__file__).parents[2]
HASH = hashlib.sha256(b"daily-report-api").hexdigest()


class _TrustedDailyItems:
    """Test authority that marks the seeded business time as already validated."""

    def __init__(self, store: SqliteDailyStore) -> None:
        self._store = store

    def effective_revisions(
        self,
        *,
        business_date: date,
        receive_place_keyword: str,
        contract_subject_code: str,
    ) -> tuple[DailyRecordRevision, ...]:
        return self._store.list_latest_revisions_for_business_date(
            business_date=business_date,
            receive_place_keyword=receive_place_keyword,
            contract_subject_code=contract_subject_code,
        )

    @staticmethod
    def primary_loading_time_ids(
        revisions: tuple[DailyRecordRevision, ...],
        **_kwargs: object,
    ) -> frozenset[str]:
        return frozenset(revision.platform_waybill_id for revision in revisions)

    @staticmethod
    def manual_loading_time_ids(
        _revisions: tuple[DailyRecordRevision, ...],
        **_kwargs: object,
    ) -> frozenset[str]:
        return frozenset()


def _client(
    tmp_path: Path,
    opened_directories: list[Path] | None = None,
) -> tuple[TestClient, SqliteRuntime]:
    runtime = SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="daily-report-api",
    )
    daily = SqliteDailyStore(runtime)
    captured = datetime(2026, 8, 1, 18, 0, tzinfo=SHANGHAI)
    daily.save_snapshot(
        DailyCandidateSnapshot(
            snapshot_id="api-snapshot",
            target_business_date=date(2026, 8, 1),
            receive_place="榆林",
            query_window=candidate_query_window(date(2026, 8, 1), now=captured),
            source_contract_sha256=HASH,
            candidates=(
                DailyCandidate(
                    "api-platform-1",
                    "API-001",
                    platform_loading_time=datetime(
                        2026, 8, 1, 15, 0, tzinfo=SHANGHAI
                    ),
                ),
            ),
            captured_at=captured,
        )
    )
    daily.save_observation(
        DailyWaybillObservation(
            observation_id="api-observation",
            snapshot_id="api-snapshot",
            platform_waybill_id="api-platform-1",
            waybill_number="API-001",
            fields=DailyObservationFields(
                shipping_mine=None,
                planned_date=None,
                loading_time=datetime(2026, 8, 1, 15, 0, tzinfo=SHANGHAI),
                vehicle_number="陕A12345",
                loading_net_tonnes=Decimal("32.80"),
                unloading_net_tonnes=Decimal("32.76"),
                coal_type=None,
                unloading_place=None,
                unloading_time=None,
            ),
            loading_ticket_sha256=HASH,
            unloading_ticket_sha256=HASH,
            source_detail_sha256=HASH,
            observed_at=captured,
        )
    )
    repository = SqliteDailyReportRepository(
        runtime=runtime,
        daily_store=daily,
        daily_items=_TrustedDailyItems(daily),  # type: ignore[arg-type]
        default_output_directory=(tmp_path / "reports").resolve(),
    )

    def require_session() -> None:
        return None

    def require_write(
        idempotency_key: str = Header(alias="Idempotency-Key"),
    ) -> str:
        return idempotency_key

    app = FastAPI()

    @app.exception_handler(ApiError)
    async def handle_api_error(_, exc: ApiError):  # type: ignore[no-untyped-def]
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=exc.status_code,
            content={"error": {"code": exc.code, "message": exc.message}},
        )

    app.include_router(
        build_daily_report_router(
            enabled=True,
            repository=repository,
            require_session=require_session,
            require_write=require_write,
            open_directory=(
                None if opened_directories is None else lambda path: opened_directories.append(path)
            ),
        )
    )
    return TestClient(app), runtime


@pytest.mark.integration
def test_report_api_saves_settings_and_creates_idempotently(tmp_path: Path) -> None:
    opened_directories: list[Path] = []
    client, runtime = _client(tmp_path, opened_directories)
    try:
        initial = client.get("/api/v1/daily/report-settings")
        assert initial.status_code == 200
        assert initial.json()["confirmed"] is True
        assert initial.json()["capture_start_time"] == "14:00:00"
        assert initial.json()["capture_end_mode"] == "system_current_time"
        assert initial.json()["capture_range_covers_report_window"] is True

        payload = {
            "shipping_mine": "金鸡滩煤矿",
            "coal_type": "兖矿陕动四号（5600）",
            "unloading_place": "象道货22",
            "query_place_keyword": "榆林",
            "output_directory": str((tmp_path / "reports").resolve()),
            "confirmed": True,
            "capture_start_time": "13:45:00",
            "capture_end_mode": "fixed_time",
            "capture_fixed_end_day_offset": 1,
            "capture_fixed_end_time": "14:15:00",
            "expected_record_version": 0,
        }
        saved = client.put(
            "/api/v1/daily/report-settings",
            headers={"Idempotency-Key": "settings-1"},
            json=payload,
        )
        replay = client.put(
            "/api/v1/daily/report-settings",
            headers={"Idempotency-Key": "settings-1"},
            json=payload,
        )
        assert saved.status_code == 200
        assert replay.status_code == 200
        assert saved.json() == replay.json()
        assert saved.json()["capture_start_time"] == "13:45:00"
        assert saved.json()["capture_end_mode"] == "fixed_time"
        assert saved.json()["capture_range_covers_report_window"] is True

        created = client.post(
            "/api/v1/daily/reports",
            headers={"Idempotency-Key": "report-1"},
            json={
                "business_date": "2026-08-01",
                "expected_settings_version": 1,
            },
        )
        assert created.status_code == 200
        assert created.json()["report"]["row_count"] == 1
        assert created.json()["report"]["candidate_count"] == 1
        assert created.json()["report"]["window_excluded_count"] == 0
        assert created.json()["report"]["missing_effective_time_count"] == 0
        assert created.json()["report"]["status"] == "confirmed"
        assert created.json()["report"]["file_name"] == (
            "20260801-山西贵恩博-金鸡滩煤矿装卸车明细.xlsx"
        )
        opened = client.post(
            f"/api/v1/daily/reports/{created.json()['report']['report_id']}/open-folder",
            headers={"Idempotency-Key": "open-report-folder-1"},
            json={"expected_record_version": created.json()["report"]["record_version"]},
        )
        assert opened.status_code == 200
        assert opened.json() == {"opened": True}
        assert opened_directories == [(tmp_path / "reports").resolve()]
    finally:
        runtime.close()


@pytest.mark.integration
def test_report_range_settings_warn_and_reject_stale_versions(tmp_path: Path) -> None:
    client, runtime = _client(tmp_path)
    try:
        payload = {
            "shipping_mine": "金鸡滩煤矿",
            "coal_type": "兖矿陕动四号（5600）",
            "unloading_place": "象道货22",
            "query_place_keyword": "榆林",
            "output_directory": str((tmp_path / "reports").resolve()),
            "confirmed": True,
            "capture_start_time": "14:30:00",
            "capture_end_mode": "fixed_time",
            "capture_fixed_end_day_offset": 0,
            "capture_fixed_end_time": "20:00:00",
            "expected_record_version": 0,
        }
        saved = client.put(
            "/api/v1/daily/report-settings",
            headers={"Idempotency-Key": "narrow-range"},
            json=payload,
        )
        stale = client.put(
            "/api/v1/daily/report-settings",
            headers={"Idempotency-Key": "stale-range"},
            json={**payload, "capture_start_time": "14:00:00"},
        )

        assert saved.status_code == 200
        assert saved.json()["capture_range_covers_report_window"] is False
        assert stale.status_code == 409
        assert stale.json()["error"]["code"] == "record_version_conflict"
    finally:
        runtime.close()


@pytest.mark.integration
def test_report_api_creates_directly_with_unconfirmed_legacy_settings(
    tmp_path: Path,
) -> None:
    client, runtime = _client(tmp_path)
    try:
        settings = client.put(
            "/api/v1/daily/report-settings",
            headers={"Idempotency-Key": "legacy-unconfirmed-settings"},
            json={
                "shipping_mine": "金鸡滩煤矿",
                "coal_type": "兖矿陕动四号（5600）",
                "unloading_place": "象道货22",
                "query_place_keyword": "榆林",
                "output_directory": str((tmp_path / "reports").resolve()),
                "confirmed": False,
                "expected_record_version": 0,
            },
        )
        assert settings.status_code == 200
        assert settings.json()["confirmed"] is False
        assert settings.json()["record_version"] == 1

        created = client.post(
            "/api/v1/daily/reports",
            headers={"Idempotency-Key": "report-default-settings"},
            json={
                "business_date": "2026-08-01",
                "expected_settings_version": 1,
            },
        )
        assert created.status_code == 200
        assert created.json()["report"]["row_count"] == 1
        assert created.json()["report"]["status"] == "confirmed"
    finally:
        runtime.close()


@pytest.mark.integration
def test_report_api_rejects_unknown_write_fields(tmp_path: Path) -> None:
    client, runtime = _client(tmp_path)
    try:
        response = client.post(
            "/api/v1/daily/reports",
            headers={"Idempotency-Key": "report-unknown"},
            json={
                "business_date": "2026-08-01",
                "expected_settings_version": 1,
                "operator": "forbidden",
            },
        )
        assert response.status_code == 422
    finally:
        runtime.close()


@pytest.mark.integration
def test_report_settings_reject_mojibake_before_creating_output_directory(
    tmp_path: Path,
) -> None:
    client, runtime = _client(tmp_path)
    mojibake = "成丰装卸车明细".encode().decode("latin-1")
    corrupted_output = (tmp_path / mojibake).resolve()
    try:
        response = client.put(
            "/api/v1/daily/report-settings",
            headers={"Idempotency-Key": "settings-mojibake"},
            json={
                "shipping_mine": "金鸡滩煤矿",
                "coal_type": "兖矿陕动四号（5600）",
                "unloading_place": "象道货22",
                "query_place_keyword": "榆林",
                "output_directory": str(corrupted_output),
                "confirmed": True,
                "expected_record_version": 0,
            },
        )

        assert response.status_code == 422
        assert "text encoding" in response.text
        assert not corrupted_output.exists()
        assert client.get("/api/v1/daily/report-settings").json()["record_version"] == 0
    finally:
        runtime.close()


@pytest.mark.integration
def test_report_settings_reject_windows_invalid_output_directory(
    tmp_path: Path,
) -> None:
    client, runtime = _client(tmp_path)
    corrupted_output = tmp_path / "???????"
    try:
        response = client.put(
            "/api/v1/daily/report-settings",
            headers={"Idempotency-Key": "settings-invalid-path"},
            json={
                "shipping_mine": "金鸡滩煤矿",
                "coal_type": "兖矿陕动四号（5600）",
                "unloading_place": "象道货22",
                "query_place_keyword": "榆林",
                "output_directory": str(corrupted_output),
                "confirmed": True,
                "expected_record_version": 0,
            },
        )

        assert response.status_code == 422
        assert "invalid Windows path" in response.text
        assert not corrupted_output.exists()
        assert client.get("/api/v1/daily/report-settings").json()["record_version"] == 0
    finally:
        runtime.close()
