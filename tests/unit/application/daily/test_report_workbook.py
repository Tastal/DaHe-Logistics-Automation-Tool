# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
import zipfile
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from xml.etree import ElementTree

import pytest

from dahe.application.daily.report_workbook import (
    DailyReportSettings,
    DailyReportWorkbook,
    build_daily_report_result,
    build_daily_report_rows,
)
from dahe.domain.daily.calendar import SHANGHAI
from dahe.domain.daily.models import DailyObservationFields, DailyRecordRevision


def _revision(
    *,
    identity: str,
    loading_time: datetime | None,
    unloading_time: datetime | None,
    vehicle: str | None,
    loading: Decimal | None,
    unloading: Decimal | None,
    loading_ticket: bool = True,
    unloading_ticket: bool = True,
) -> DailyRecordRevision:
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return DailyRecordRevision(
        revision_id=digest[:32],
        platform_waybill_id=identity,
        revision_number=1,
        observation_id=f"observation-{identity}",
        field_fingerprint=digest,
        fields=DailyObservationFields(
            shipping_mine=None,
            planned_date=None,
            loading_time=loading_time,
            vehicle_number=vehicle,
            loading_net_tonnes=loading,
            unloading_net_tonnes=unloading,
            coal_type=None,
            unloading_place=None,
            unloading_time=unloading_time,
        ),
        waybill_number=f"WB-{identity}",
        loading_ticket_sha256=digest if loading_ticket else None,
        unloading_ticket_sha256=digest if unloading_ticket else None,
        created_at=datetime(2026, 8, 2, 15, 0, tzinfo=SHANGHAI),
    )


def _settings(output_directory: Path) -> DailyReportSettings:
    return DailyReportSettings(
        shipping_mine="金鸡滩煤矿",
        coal_type="兖矿陕动四号（5600）",
        unloading_place="象道货22",
        query_place_keyword="榆林",
        output_directory=output_directory,
        confirmed=True,
        record_version=1,
    )


def test_report_settings_reject_utf8_text_decoded_as_latin1(
    tmp_path: Path,
) -> None:
    mojibake = "成丰装卸车明细".encode().decode("latin-1")
    corrupted_output = tmp_path / mojibake

    with pytest.raises(ValueError, match="text encoding"):
        _settings(corrupted_output)

    assert not corrupted_output.exists()


def test_report_settings_reject_windows_invalid_output_directory(
    tmp_path: Path,
) -> None:
    corrupted_output = tmp_path / "???????"

    with pytest.raises(ValueError, match="invalid Windows path"):
        _settings(corrupted_output)

    assert not corrupted_output.exists()


@pytest.mark.parametrize(
    "field",
    (
        "shipping_mine",
        "coal_type",
        "unloading_place",
        "query_place_keyword",
    ),
)
def test_report_settings_reject_mojibake_business_text(
    tmp_path: Path,
    field: str,
) -> None:
    values = {
        "shipping_mine": "金鸡滩煤矿",
        "coal_type": "兖矿陕动四号（5600）",
        "unloading_place": "象道货22",
        "query_place_keyword": "榆林",
    }
    values[field] = "成丰".encode().decode("latin-1")

    with pytest.raises(ValueError, match="text encoding"):
        DailyReportSettings(
            **values,
            output_directory=tmp_path,
            confirmed=True,
            record_version=1,
        )


def test_report_rows_use_business_defaults_and_preserve_missing_values(
    tmp_path: Path,
) -> None:
    rows = build_daily_report_rows(
        business_date=date(2026, 8, 1),
        settings=_settings(tmp_path),
        revisions=(
            _revision(
                identity="2",
                loading_time=None,
                unloading_time=None,
                vehicle=None,
                loading=None,
                unloading=None,
            ),
            _revision(
                identity="1",
                loading_time=datetime(2026, 8, 1, 15, 1, 2, tzinfo=SHANGHAI),
                unloading_time=datetime(2026, 8, 1, 16, 2, 59, tzinfo=SHANGHAI),
                vehicle="陕A12345",
                loading=Decimal("32.80"),
                unloading=Decimal("32.76"),
            ),
        ),
        primary_loading_time_ids=frozenset({"1"}),
    )

    assert [row.sequence for row in rows] == [1]
    assert rows[0].vehicle_number == "陕A12345"
    assert rows[0].planned_date == date(2026, 8, 1)
    assert rows[0].loading_time == datetime(2026, 8, 1, 15, 1, 2)
    assert rows[0].unloading_time == datetime(2026, 8, 1, 16, 2)


def test_report_strictly_filters_effective_loading_time_and_keeps_fallback_blank(
    tmp_path: Path,
) -> None:
    early = _revision(
        identity="early",
        loading_time=datetime(2026, 8, 1, 13, 59, 59, tzinfo=SHANGHAI),
        unloading_time=None,
        vehicle="A",
        loading=Decimal("31"),
        unloading=None,
    )
    inside = _revision(
        identity="inside",
        loading_time=datetime(2026, 8, 1, 14, 0, tzinfo=SHANGHAI),
        unloading_time=None,
        vehicle="B",
        loading=Decimal("32"),
        unloading=None,
    )
    fallback = _revision(
        identity="fallback",
        loading_time=None,
        unloading_time=None,
        vehicle="C",
        loading=Decimal("33"),
        unloading=None,
    )
    late = _revision(
        identity="late",
        loading_time=datetime(2026, 8, 2, 14, 0, tzinfo=SHANGHAI),
        unloading_time=None,
        vehicle="D",
        loading=Decimal("34"),
        unloading=None,
    )
    missing = _revision(
        identity="missing",
        loading_time=None,
        unloading_time=None,
        vehicle="E",
        loading=Decimal("35"),
        unloading=None,
    )

    result = build_daily_report_result(
        business_date=date(2026, 8, 1),
        settings=_settings(tmp_path),
        revisions=(early, inside, fallback, late, missing),
        platform_loading_times={
            "fallback": datetime(2026, 8, 2, 13, 0, tzinfo=SHANGHAI),
        },
        primary_loading_time_ids=frozenset(
            {"early", "inside", "fallback", "late"}
        ),
        manual_loading_time_ids=frozenset({"fallback"}),
    )

    assert [row.platform_waybill_id for row in result.rows] == ["inside", "fallback"]
    assert result.rows[1].loading_time is None
    assert result.candidate_count == 5
    assert result.window_excluded_count == 2
    assert result.missing_effective_time_count == 1


def test_workbook_is_written_formally_then_reopened_and_validated(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    rows = build_daily_report_rows(
        business_date=date(2026, 8, 1),
        settings=settings,
        revisions=(
            _revision(
                identity="1",
                loading_time=datetime(2026, 8, 1, 15, 1, 2, tzinfo=SHANGHAI),
                unloading_time=datetime(2026, 8, 1, 16, 2, 59, tzinfo=SHANGHAI),
                vehicle="陕A12345",
                loading=Decimal("32.80"),
                unloading=Decimal("32.76"),
            ),
        ),
        primary_loading_time_ids=frozenset({"1"}),
    )

    result = DailyReportWorkbook().write_pending(
        business_date=date(2026, 8, 1),
        settings=settings,
        rows=rows,
    )

    assert result.path.name == "20260801-山西贵恩博-金鸡滩煤矿装卸车明细.xlsx"
    assert result.path.is_file()
    assert result.row_count == 1
    assert result.loading_net_total == Decimal("32.80")
    assert len(result.file_sha256) == 64
    assert len(result.data_snapshot_sha256) == 64
    with zipfile.ZipFile(result.path) as archive:
        core_properties = archive.read("docProps/core.xml").decode("utf-8")
        assert core_properties.count("2000-01-01T00:00:00Z") == 2
        root = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
        namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
        assert root.find("x:autoFilter", namespace).attrib["ref"] == "A1:J2"
        rows_xml = root.findall("x:sheetData/x:row", namespace)
        assert len(rows_xml) == 3
        assert root.find("x:dimension", namespace).attrib["ref"] == "A1:J3"
        assert all(
            "style" not in column.attrib
            for column in root.findall("x:cols/x:col", namespace)
        )
        assert {
            cell.attrib["r"]
            for cell in root.findall("x:sheetData/x:row/x:c", namespace)
        } <= {
            f"{column}{row}"
            for column in "ABCDEFGHIJ"
            for row in range(1, 4)
        }


def test_workbook_keeps_manually_confirmed_missing_values_truly_blank(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    built = build_daily_report_result(
        business_date=date(2026, 8, 1),
        settings=settings,
        revisions=(
            _revision(
                identity="blank",
                loading_time=None,
                unloading_time=None,
                vehicle="陕A00001",
                loading=None,
                unloading=None,
            ),
        ),
        platform_loading_times={
            "blank": datetime(2026, 8, 1, 15, 0, tzinfo=SHANGHAI),
        },
        primary_loading_time_ids=frozenset({"blank"}),
        manual_loading_time_ids=frozenset({"blank"}),
    )

    assert len(built.rows) == 1
    assert built.rows[0].loading_time is None
    result = DailyReportWorkbook().write_pending(
        business_date=date(2026, 8, 1),
        settings=settings,
        rows=built.rows,
    )

    with zipfile.ZipFile(result.path) as archive:
        root = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
    namespace = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
    cells = {
        cell.attrib["r"]: cell
        for cell in root.findall("x:sheetData/x:row/x:c", namespace)
    }
    for coordinate in ("D2", "F2", "G2", "J2"):
        assert coordinate in cells
        assert cells[coordinate].find("x:v", namespace) is None
        assert cells[coordinate].find("x:is", namespace) is None


def test_workbook_atomically_replaces_an_existing_formal_file(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    path = tmp_path / "20260801-山西贵恩博-金鸡滩煤矿装卸车明细.xlsx"
    path.write_bytes(b"manual edit")

    result = DailyReportWorkbook().write_pending(
        business_date=date(2026, 8, 1),
        settings=settings,
        rows=(),
    )

    assert result.path == path
    assert path.read_bytes() != b"manual edit"
    DailyReportWorkbook().validate_existing(path, row_count=0)


def test_platform_time_never_decides_report_inclusion_or_business_time(
    tmp_path: Path,
) -> None:
    platform_only = _revision(
        identity="platform-only",
        loading_time=None,
        unloading_time=None,
        vehicle="B",
        loading=Decimal("32.00"),
        unloading=Decimal("31.90"),
    )

    result = build_daily_report_result(
        business_date=date(2026, 8, 1),
        settings=_settings(tmp_path),
        revisions=(platform_only,),
        platform_loading_times={
            "platform-only": datetime(2026, 8, 1, 15, 0, tzinfo=SHANGHAI)
        },
    )

    assert result.rows == ()
    assert result.window_excluded_count == 0
    assert result.missing_effective_time_count == 1


def test_report_sort_uses_platform_time_only_when_both_business_times_are_blank(
    tmp_path: Path,
) -> None:
    loading = _revision(
        identity="loading",
        loading_time=datetime(2026, 8, 1, 15, 0, tzinfo=SHANGHAI),
        unloading_time=datetime(2026, 8, 1, 16, 0, tzinfo=SHANGHAI),
        vehicle="A",
        loading=Decimal("32.00"),
        unloading=Decimal("31.90"),
    )
    unloading_only = _revision(
        identity="unloading-only",
        loading_time=None,
        unloading_time=datetime(2026, 8, 2, 7, 21, tzinfo=SHANGHAI),
        vehicle="B",
        loading=Decimal("33.00"),
        unloading=Decimal("32.90"),
    )
    blank_late = _revision(
        identity="blank-late",
        loading_time=None,
        unloading_time=None,
        vehicle="C",
        loading=Decimal("34.00"),
        unloading=Decimal("33.90"),
    )
    blank_early = _revision(
        identity="blank-early",
        loading_time=None,
        unloading_time=None,
        vehicle="D",
        loading=Decimal("35.00"),
        unloading=Decimal("34.90"),
    )

    kwargs = {
        "business_date": date(2026, 8, 1),
        "settings": _settings(tmp_path),
        "revisions": (blank_late, unloading_only, blank_early, loading),
        "primary_loading_time_ids": frozenset(
            {"loading", "unloading-only", "blank-late", "blank-early"}
        ),
        "manual_loading_time_ids": frozenset(
            {"unloading-only", "blank-late", "blank-early"}
        ),
    }
    first = build_daily_report_result(
        **kwargs,
        platform_loading_times={
            "blank-late": datetime(2026, 8, 2, 13, 0, tzinfo=SHANGHAI),
            "blank-early": datetime(2026, 8, 2, 12, 0, tzinfo=SHANGHAI),
        },
    )
    second = build_daily_report_result(
        **kwargs,
        platform_loading_times={
            "blank-late": datetime(2026, 8, 2, 11, 0, tzinfo=SHANGHAI),
            "blank-early": datetime(2026, 8, 2, 13, 0, tzinfo=SHANGHAI),
        },
    )

    assert [row.platform_waybill_id for row in first.rows] == [
        "loading",
        "unloading-only",
        "blank-early",
        "blank-late",
    ]
    assert [row.platform_waybill_id for row in second.rows] == [
        "loading",
        "unloading-only",
        "blank-late",
        "blank-early",
    ]
    assert {
        row.platform_waybill_id: row.values()[1:] for row in first.rows
    } == {
        row.platform_waybill_id: row.values()[1:] for row in second.rows
    }


def test_pending_unloading_is_exported_as_zero_weight_and_blank_time(
    tmp_path: Path,
) -> None:
    pending = _revision(
        identity="pending",
        loading_time=datetime(2026, 8, 1, 15, 0, tzinfo=SHANGHAI),
        unloading_time=datetime(2026, 8, 1, 16, 0, tzinfo=SHANGHAI),
        vehicle="A",
        loading=Decimal("32.00"),
        unloading=None,
        unloading_ticket=False,
    )

    rows = build_daily_report_rows(
        business_date=date(2026, 8, 1),
        settings=_settings(tmp_path),
        revisions=(pending,),
        primary_loading_time_ids=frozenset({"pending"}),
    )

    assert rows[0].unloading_net_tonnes == Decimal("0.00")
    assert rows[0].unloading_time is None
