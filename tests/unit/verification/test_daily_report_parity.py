# ruff: noqa: RUF001

from __future__ import annotations

import zipfile
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path
from xml.etree import ElementTree

import pytest

from dahe.application.daily.report_workbook import (
    DailyReportRow,
    DailyReportSettings,
    DailyReportWorkbook,
)
from dahe.verification.daily_report_parity import (
    DailyReportParityError,
    verify_daily_report_parity,
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


def _row(sequence: int) -> DailyReportRow:
    return DailyReportRow(
        sequence=sequence,
        platform_waybill_id=f"waybill-{sequence}",
        source_revision_id=f"revision-{sequence}",
        shipping_mine="金鸡滩煤矿",
        planned_date=date(2026, 7, 23),
        loading_time=datetime(2026, 7, 23, 14, 1, sequence),
        vehicle_number=f"陕A{sequence:05d}",
        loading_net_tonnes=Decimal("32.80"),
        unloading_net_tonnes=Decimal("32.76"),
        coal_type="兖矿陕动四号（5600）",
        unloading_place="象道货22",
        unloading_time=datetime(2026, 7, 23, 15, 2),
    )


def _write_report(directory: Path, row_count: int) -> Path:
    result = DailyReportWorkbook().write_report(
        business_date=date(2026, 7, 23),
        settings=_settings(directory),
        rows=tuple(_row(index) for index in range(1, row_count + 1)),
    )
    return result.path


def test_parity_ignores_data_row_count_but_preserves_format_roles(
    tmp_path: Path,
) -> None:
    reference = _write_report(tmp_path / "reference", 2)
    candidate = _write_report(tmp_path / "candidate", 5)

    result = verify_daily_report_parity(reference=reference, candidate=candidate)

    assert result.reference_contract == result.candidate_contract
    assert result.reference_contract.filter_range == "A1:JLAST_DATA"
    assert result.reference_contract.merge_ranges == ("ASUMMARY:ESUMMARY",)


def test_parity_rejects_a_changed_column_width(tmp_path: Path) -> None:
    reference = _write_report(tmp_path / "reference", 2)
    candidate = _write_report(tmp_path / "candidate", 2)
    altered = tmp_path / "altered.xlsx"
    namespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

    with zipfile.ZipFile(candidate) as source, zipfile.ZipFile(
        altered,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as target:
        for item in source.infolist():
            payload = source.read(item.filename)
            if item.filename == "xl/worksheets/sheet1.xml":
                root = ElementTree.fromstring(payload)
                columns = root.find(f"{{{namespace}}}cols")
                assert columns is not None
                columns[0].set("width", "99")
                payload = ElementTree.tostring(
                    root,
                    encoding="utf-8",
                    xml_declaration=True,
                )
            target.writestr(item, payload)

    with pytest.raises(DailyReportParityError, match="differs"):
        verify_daily_report_parity(reference=reference, candidate=altered)
