# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from dahe.adapters.sqlite.contract_subjects import SqliteContractSubjectStore
from dahe.adapters.sqlite.daily_reports import (
    SqliteDailyReportRepository,
)
from dahe.adapters.sqlite.daily_store import SqliteDailyStore
from dahe.adapters.sqlite.repository import SqliteJobRepository
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.domain.daily.calendar import SHANGHAI, candidate_query_window
from dahe.domain.daily.models import (
    DailyCandidate,
    DailyCandidateSnapshot,
    DailyObservationFields,
    DailyWaybillObservation,
)
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec

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
            candidates=(
                DailyCandidate(
                    "platform-1",
                    "WB-001",
                    platform_loading_time=datetime(
                        2026, 8, 1, 15, 0, 1, tzinfo=SHANGHAI
                    ),
                ),
            ),
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
                vehicle_number="TEST-001",
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


def _seed_subject(
    *,
    runtime: SqliteRuntime,
    store: SqliteDailyStore,
    subject_code: str,
    marker: str,
) -> None:
    jobs = SqliteJobRepository(runtime=runtime, scheduler_instance_id=None)
    try:
        job, _ = jobs.create_scheduled_job(
            fixture=ScheduledJobSpec(
                fixture_id=f"subject-report-{marker}",
                job_kind="business",
                task_type="daily",
                scope_label=f"subject report {marker}",
                conflict_key=f"daily:{subject_code}:2026-08-01",
                items=(
                    ScheduledWorkItemSpec(
                        item_key=f"subject-report-{marker}",
                        expected_outcome=None,
                    ),
                ),
                run_mode="operational",
            ),
            scope_label=f"subject report {marker}",
            idempotency_key=f"subject-report-{marker}",
            request_hash=hashlib.sha256(marker.encode()).hexdigest(),
            expected_record_version=0,
        )
        SqliteContractSubjectStore(runtime).bind_job(
            job_id=job.job_id,
            subject_code=subject_code,
        )
        captured_at = datetime(2026, 8, 1, 18, 0, tzinfo=SHANGHAI)
        store.save_snapshot(
            DailyCandidateSnapshot(
                snapshot_id=job.job_id,
                target_business_date=date(2026, 8, 1),
                receive_place="榆林",
                query_window=candidate_query_window(
                    date(2026, 8, 1), now=captured_at
                ),
                source_contract_sha256=HASH,
                candidates=(
                    DailyCandidate(
                        "shared-platform-id",
                        f"WB-{marker}",
                        platform_loading_time=datetime(
                            2026, 8, 1, 15, 0, 1, tzinfo=SHANGHAI
                        ),
                    ),
                ),
                captured_at=captured_at,
            )
        )
        store.save_observation(
            DailyWaybillObservation(
                observation_id=f"subject-observation-{marker}",
                snapshot_id=job.job_id,
                platform_waybill_id="shared-platform-id",
                waybill_number=f"WB-{marker}",
                fields=DailyObservationFields(
                    shipping_mine=None,
                    planned_date=None,
                    loading_time=datetime(
                        2026, 8, 1, 15, 0, 1, tzinfo=SHANGHAI
                    ),
                    vehicle_number=f"TEST-{marker}",
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
    finally:
        jobs.close()


@pytest.mark.integration
def test_unconfirmed_legacy_settings_allow_direct_report(tmp_path: Path) -> None:
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
            confirmed=False,
            expected_record_version=0,
        )
        assert settings.confirmed is False
        assert settings.record_version == 1
        report, replayed = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=1,
            idempotency_key="report-with-legacy-settings",
            request_hash=HASH,
        )
        assert replayed is False
        assert report.status == "confirmed"
        assert report.row_count == 1
        assert report.path.is_file()
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
        assert report.path.name == "装卸车明细-山西贵恩博-2026-08-01.xlsx"
        assert report.path.is_file()

        replaced, replaced_replay = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="create-report-1-replacement",
            request_hash=HASH,
        )
        assert replaced_replay is False
        assert replaced.report_id == report.report_id
        assert replaced.record_version == report.record_version + 1
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


@pytest.mark.integration
def test_same_waybill_and_business_date_are_isolated_by_contract_subject(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        daily = SqliteDailyStore(runtime)
        _seed_subject(
            runtime=runtime,
            store=daily,
            subject_code="shanxi_guienbo",
            marker="shanxi",
        )
        _seed_subject(
            runtime=runtime,
            store=daily,
            subject_code="shanghai_jinyisheng",
            marker="shanghai",
        )
        repository = SqliteDailyReportRepository(
            runtime=runtime,
            daily_store=daily,
            default_output_directory=(tmp_path / "reports").resolve(),
        )
        settings = repository.save_settings(
            shipping_mine="Test mine",
            coal_type="Test coal",
            unloading_place="Test unloading place",
            query_place_keyword="榆林",
            output_directory=(tmp_path / "reports").resolve(),
            confirmed=True,
            expected_record_version=0,
        )
        shanxi, _ = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="same-cross-subject-key",
            request_hash=HASH,
            contract_subject_code="shanxi_guienbo",
        )
        shanghai, _ = repository.create_report(
            business_date=date(2026, 8, 1),
            expected_settings_version=settings.record_version,
            idempotency_key="same-cross-subject-key",
            request_hash=HASH,
            contract_subject_code="shanghai_jinyisheng",
        )

        assert shanxi.report_id != shanghai.report_id
        assert shanxi.file_name != shanghai.file_name
        assert shanxi.row_count == shanghai.row_count == 1
        assert daily.list_revisions(
            "shared-platform-id", "shanxi_guienbo"
        )[0].waybill_number == "WB-shanxi"
        assert daily.list_revisions(
            "shared-platform-id", "shanghai_jinyisheng"
        )[0].waybill_number == "WB-shanghai"
    finally:
        runtime.close()
