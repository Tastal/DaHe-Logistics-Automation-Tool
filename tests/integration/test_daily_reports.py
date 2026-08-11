# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from dahe.adapters.sqlite.daily_reports import (
    DailyReportConflictError,
    SqliteDailyReportRepository,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyWaybillObservation,
)

PROJECT_ROOT = Path(__file__).parents[2]
HASH = hashlib.sha256(b"daily-report").hexdigest()


def _runtime(tmp_path: Path) -> SqliteRuntime:
    return SqliteRuntime(
        data_root=tmp_path / "data",
        project_root=PROJECT_ROOT,
        instance_id="daily-report-test",
    )


def _seed(store: SqliteDailyStore) -> None:
    captured_at = datetime(2026, 8, 1, 18, 0, tzinfo=SHANGHAI)
    store.save_snapshot(
        DailyCandidateSnapshot(
            snapshot_id="daily-report-snapshot",
            target_business_date=date(2026, 8, 1),
            receive_place="榆林",
            query_window=candidate_query_window(
                date(2026, 8, 1),
                now=captured_at,
            ),
            source_contract_sha256=HASH,
            candidates=(DailyCandidate("platform-1", "WB-001"),),
            captured_at=captured_at,
        )
    )
    store.save_observation(
        DailyWaybillObservation(
            observation_id="daily-report-observation",
            snapshot_id="daily-report-snapshot",
            platform_waybill_id="platform-1",
            waybill_number="WB-001",
            fields=DailyObservationFields(
                shipping_mine=None,
                planned_date=None,
                loading_time=datetime(2026, 8, 1, 15, 0, 1, tzinfo=SHANGHAI),
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
            observed_at=captured_at,
        )
    )


@pytest.mark.integration
def test_settings_must_be_confirmed_before_first_report(tmp_path: Path) -> None:
    runtime = _runtime(tmp_path)
    try:
        repository = SqliteDailyReportRepository(
            runtime=runtime,
            daily_store=SqliteDailyStore(runtime),
            default_output_directory=(tmp_path / "reports").resolve(),
        )
        settings = repository.get_settings()
        assert settings.confirmed is False
        assert settings.record_version == 0
        with pytest.raises(DailyReportConflictError, match="confirmed"):
            repository.create_report(
                business_date=date(2026, 8, 1),
                expected_settings_version=0,
                idempotency_key="report-before-confirmation",
                request_hash=HASH,
            )
    finally:
        runtime.close()


@pytest.mark.integration
def test_report_generation_is_idempotent_and_directly_formal(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        daily = SqliteDailyStore(runtime)
        _seed(daily)
        repository = SqliteDailyReportRepository(
            runtime=runtime,
            daily_store=daily,
            default_output_directory=(tmp_path / "reports").resolve(),
        )
        settings = repository.save_settings(
            shipping_mine="金鸡滩煤矿",
            coal_type="兖矿陕动四号（5600）",
            unloading_place="象道货22",
            query_place_keyword="榆林",
            output_directory=(tmp_path / "reports").resolve(),
            confirmed=True,
            expected_record_version=0,
        )
        report, replayed = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="create-report-1",
            request_hash=HASH,
        )
        replay, replayed_again = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="create-report-1",
            request_hash=HASH,
        )
        assert replayed is False
        assert replayed_again is True
        assert replay.report_id == report.report_id
        assert report.status == "confirmed"
        assert report.row_count == 1
        assert report.path.name == "20260801-金鸡滩煤矿装卸车明细.xlsx"
        assert report.path.is_file()

        replaced, replaced_replay = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="create-report-1-replacement",
            request_hash=HASH,
        )
        assert replaced_replay is False
        assert replaced.report_id != report.report_id
        assert replaced.path == report.path
        assert replaced.path.is_file()
    finally:
        runtime.close()


@pytest.mark.integration
def test_direct_generation_overwrites_an_external_edit_and_keeps_history(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        daily = SqliteDailyStore(runtime)
        _seed(daily)
        repository = SqliteDailyReportRepository(
            runtime=runtime,
            daily_store=daily,
            default_output_directory=(tmp_path / "reports").resolve(),
        )
        settings = repository.save_settings(
            shipping_mine="金鸡滩煤矿",
            coal_type="兖矿陕动四号（5600）",
            unloading_place="象道货22",
            query_place_keyword="榆林",
            output_directory=(tmp_path / "reports").resolve(),
            confirmed=True,
            expected_record_version=0,
        )
        report, _ = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="create-report-2",
            request_hash=HASH,
        )
        original_sha = report.file_sha256
        report.path.write_bytes(b"external-edit")

        replacement, replayed = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="replace-report-2",
            request_hash=HASH,
        )
        assert replayed is False
        assert replacement.status == "confirmed"
        assert replacement.path == report.path
        assert replacement.path.read_bytes() != b"external-edit"
        assert replacement.file_sha256 == original_sha
        assert repository.get_report(report.report_id).file_sha256 == original_sha
    finally:
        runtime.close()
