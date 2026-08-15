# ruff: noqa: RUF001

from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
import zipfile
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from decimal import Decimal
from pathlib import Path, PureWindowsPath
from typing import Literal
from uuid import uuid4
from xml.etree import ElementTree

import xlsxwriter  # type: ignore[import-untyped]

from dahe.domain.daily.calendar import SHANGHAI
from dahe.domain.daily.models import DailyRecordRevision

REPORT_HEADERS = (
    "序号",
    "发运煤矿",
    "计划日期",
    "出矿时间",
    "车牌号",
    "出矿净重（吨）",
    "收货净重（吨）",
    "煤种",
    "卸货地点",
    "卸车时间",
)

_PATH_SEPARATOR_PATTERN = re.compile(r"[\\/]")
_WINDOWS_INVALID_PATH_CHARACTERS = frozenset('<>:"|?*')
_WINDOWS_RESERVED_PATH_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{index}" for index in range(1, 10)}
    | {f"LPT{index}" for index in range(1, 10)}
)


def _is_reversible_utf8_mojibake(value: str) -> bool:
    for encoding in ("latin-1", "cp1252"):
        try:
            repaired = value.encode(encoding).decode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            continue
        if repaired != value:
            return True
    return False


def validate_report_text(value: str, *, field: str) -> None:
    """Reject corrupted settings before they can become paths or evidence."""
    if any(
        character == "\ufffd"
        or unicodedata.category(character) in {"Cc", "Cs"}
        for character in value
    ):
        raise ValueError(f"{field} contains invalid text encoding")
    if any(
        _is_reversible_utf8_mojibake(fragment)
        for fragment in _PATH_SEPARATOR_PATTERN.split(value)
        if fragment
    ):
        raise ValueError(f"{field} contains invalid text encoding")


def validate_report_output_directory(value: Path) -> None:
    """Reject Windows paths that cannot safely name the report directory."""
    if not value.is_absolute():
        raise ValueError("output_directory must be absolute")
    validate_report_text(str(value), field="output_directory")

    windows_path = PureWindowsPath(str(value))
    for part in windows_path.parts:
        if part == windows_path.anchor:
            continue
        reserved_name = part.rstrip(" .").split(".", maxsplit=1)[0].upper()
        if (
            any(character in _WINDOWS_INVALID_PATH_CHARACTERS for character in part)
            or part.endswith((" ", "."))
            or reserved_name in _WINDOWS_RESERVED_PATH_NAMES
        ):
            raise ValueError("output_directory contains an invalid Windows path")


class DailyReportWorkbookError(RuntimeError):
    """Raised when a formal report cannot be created without data loss."""


@dataclass(frozen=True, slots=True)
class DailyReportSettings:
    shipping_mine: str
    coal_type: str
    unloading_place: str
    query_place_keyword: str
    output_directory: Path
    confirmed: bool
    record_version: int
    capture_start_time: time = time(14, 0)
    capture_end_mode: Literal["system_current_time", "fixed_time"] = (
        "system_current_time"
    )
    capture_fixed_end_day_offset: int = 1
    capture_fixed_end_time: time = time(14, 30)

    def __post_init__(self) -> None:
        for value, field in (
            (self.shipping_mine, "shipping_mine"),
            (self.coal_type, "coal_type"),
            (self.unloading_place, "unloading_place"),
            (self.query_place_keyword, "query_place_keyword"),
        ):
            if not value.strip():
                raise ValueError(f"{field} is required")
            validate_report_text(value, field=field)
        validate_report_output_directory(self.output_directory)
        if self.record_version < 0:
            raise ValueError("record_version cannot be negative")
        if self.capture_start_time.tzinfo is not None:
            raise ValueError("capture_start_time must be a local wall-clock time")
        if self.capture_end_mode not in {"system_current_time", "fixed_time"}:
            raise ValueError("capture_end_mode is invalid")
        if self.capture_fixed_end_day_offset not in {0, 1}:
            raise ValueError("capture_fixed_end_day_offset is invalid")
        if self.capture_fixed_end_time.tzinfo is not None:
            raise ValueError("capture_fixed_end_time must be a local wall-clock time")

    def report_window_is_fully_covered(self) -> bool:
        if self.capture_start_time > time(14, 0):
            return False
        if self.capture_end_mode == "system_current_time":
            return True
        return (
            self.capture_fixed_end_day_offset == 1
            and self.capture_fixed_end_time >= time(14, 0)
        )


@dataclass(frozen=True, slots=True)
class DailyReportRow:
    sequence: int
    shipping_mine: str
    planned_date: date
    loading_time: datetime | None
    vehicle_number: str | None
    loading_net_tonnes: Decimal | None
    unloading_net_tonnes: Decimal | None
    coal_type: str
    unloading_place: str
    unloading_time: datetime | None
    platform_waybill_id: str
    source_revision_id: str

    def values(self) -> tuple[object | None, ...]:
        return (
            self.sequence,
            self.shipping_mine,
            self.planned_date,
            self.loading_time,
            self.vehicle_number,
            self.loading_net_tonnes,
            self.unloading_net_tonnes,
            self.coal_type,
            self.unloading_place,
            self.unloading_time,
        )

    def evidence_payload(self) -> dict[str, object]:
        return {
            "platform_waybill_id": self.platform_waybill_id,
            "source_revision_id": self.source_revision_id,
            "values": [
                value.isoformat() if isinstance(value, date) else (
                    format(value, "f") if isinstance(value, Decimal) else value
                )
                for value in self.values()
            ],
        }


@dataclass(frozen=True, slots=True)
class DailyReportWorkbookResult:
    path: Path
    file_sha256: str
    data_snapshot_sha256: str
    row_count: int
    loading_net_total: Decimal


@dataclass(frozen=True, slots=True)
class DailyReportBuildResult:
    rows: tuple[DailyReportRow, ...]
    candidate_count: int
    window_excluded_count: int
    missing_effective_time_count: int


def _format_datetime(
    value: datetime | None,
    *,
    minutes_only: bool,
) -> datetime | None:
    if value is None:
        return None
    local = value.astimezone(SHANGHAI).replace(tzinfo=None)
    return local.replace(second=0, microsecond=0) if minutes_only else local


def build_daily_report_rows(
    *,
    business_date: date,
    settings: DailyReportSettings,
    revisions: tuple[DailyRecordRevision, ...],
    platform_loading_times: dict[str, datetime | None] | None = None,
    primary_loading_time_ids: frozenset[str] = frozenset(),
) -> tuple[DailyReportRow, ...]:
    return build_daily_report_result(
        business_date=business_date,
        settings=settings,
        revisions=revisions,
        platform_loading_times=platform_loading_times,
        primary_loading_time_ids=primary_loading_time_ids,
    ).rows


def build_daily_report_result(
    *,
    business_date: date,
    settings: DailyReportSettings,
    revisions: tuple[DailyRecordRevision, ...],
    platform_loading_times: dict[str, datetime | None] | None = None,
    primary_loading_time_ids: frozenset[str] = frozenset(),
) -> DailyReportBuildResult:
    platform_times = platform_loading_times or {}
    window_start = datetime.combine(business_date, time(14, 0), tzinfo=SHANGHAI)
    window_end = window_start + timedelta(days=1)
    included: list[tuple[DailyRecordRevision, datetime, datetime | None]] = []
    outside = 0
    missing = 0
    for revision in revisions:
        image_or_manual_time = (
            revision.fields.loading_time
            if revision.platform_waybill_id in primary_loading_time_ids
            else None
        )
        effective_time = image_or_manual_time or platform_times.get(
            revision.platform_waybill_id
        )
        if effective_time is None:
            missing += 1
            continue
        local_effective = effective_time.astimezone(SHANGHAI)
        if not window_start <= local_effective < window_end:
            outside += 1
            continue
        included.append((revision, local_effective, image_or_manual_time))

    ordered = sorted(
        included,
        key=lambda value: (
            value[1],
            value[0].fields.vehicle_number or "",
            value[0].platform_waybill_id,
        ),
    )
    rows = tuple(
        DailyReportRow(
            sequence=index,
            shipping_mine=settings.shipping_mine,
            planned_date=business_date,
            loading_time=_format_datetime(primary_time, minutes_only=False),
            vehicle_number=revision.fields.vehicle_number,
            loading_net_tonnes=revision.fields.loading_net_tonnes,
            unloading_net_tonnes=revision.fields.unloading_net_tonnes,
            coal_type=settings.coal_type,
            unloading_place=settings.unloading_place,
            unloading_time=_format_datetime(
                revision.fields.unloading_time,
                minutes_only=True,
            ),
            platform_waybill_id=revision.platform_waybill_id,
            source_revision_id=revision.revision_id,
        )
        for index, (revision, _effective_time, primary_time) in enumerate(
            ordered, start=1
        )
    )
    return DailyReportBuildResult(
        rows=rows,
        candidate_count=len(revisions),
        window_excluded_count=outside,
        missing_effective_time_count=missing,
    )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _data_snapshot_sha256(
    *,
    business_date: date,
    contract_subject_code: str,
    settings: DailyReportSettings,
    rows: tuple[DailyReportRow, ...],
) -> str:
    payload = {
        "business_date": business_date.isoformat(),
        "contract_subject_code": contract_subject_code,
        "rows": [row.evidence_payload() for row in rows],
        "schema_version": 1,
        "settings": {
            "coal_type": settings.coal_type,
            "query_place_keyword": settings.query_place_keyword,
            "shipping_mine": settings.shipping_mine,
            "unloading_place": settings.unloading_place,
        },
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


_REFERENCE_COLUMN_WIDTHS = (
    7.0,
    13.0,
    14.1015625,
    28.734375,
    13.05078125,
    17.0,
    17.0,
    23.1015625,
    11.0,
    28.0,
)
_DETERMINISTIC_WORKBOOK_CREATED_AT = datetime(2000, 1, 1)


class DailyReportWorkbook:
    """Write, validate, and atomically replace one formal XLSX report."""

    def write_report(
        self,
        *,
        business_date: date,
        settings: DailyReportSettings,
        rows: tuple[DailyReportRow, ...],
        contract_subject_code: str = "shanxi_guienbo",
        contract_subject_label: str = "山西贵恩博",
    ) -> DailyReportWorkbookResult:
        output_directory = settings.output_directory.resolve()
        output_directory.mkdir(parents=True, exist_ok=True)
        final = output_directory / (
            f"装卸车明细-{contract_subject_label}-{business_date:%Y-%m-%d}.xlsx"
        )
        temporary = output_directory / f".{final.name}.{uuid4().hex}.tmp.xlsx"
        loading_total = sum(
            (row.loading_net_tonnes or Decimal("0") for row in rows),
            Decimal("0"),
        )
        try:
            self._write(temporary, rows)
            self._patch_reference_dimensions(temporary)
            self._validate(temporary, row_count=len(rows))
            try:
                os.replace(temporary, final)
            except PermissionError as exc:
                raise DailyReportWorkbookError(
                    "请关闭正在使用该报表的 Excel 窗口后重试。"
                ) from exc
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return DailyReportWorkbookResult(
            path=final,
            file_sha256=_sha256_file(final),
            data_snapshot_sha256=_data_snapshot_sha256(
                business_date=business_date,
                contract_subject_code=contract_subject_code,
                settings=settings,
                rows=rows,
            ),
            row_count=len(rows),
            loading_net_total=loading_total,
        )

    def write_pending(
        self,
        *,
        business_date: date,
        settings: DailyReportSettings,
        rows: tuple[DailyReportRow, ...],
        contract_subject_code: str = "shanxi_guienbo",
        contract_subject_label: str = "山西贵恩博",
    ) -> DailyReportWorkbookResult:
        """Keep the historical method callable while using the formal flow."""

        return self.write_report(
            business_date=business_date,
            settings=settings,
            rows=rows,
            contract_subject_code=contract_subject_code,
            contract_subject_label=contract_subject_label,
        )

    def validate_existing(self, path: Path, *, row_count: int) -> None:
        self._validate(path.resolve(strict=True), row_count=row_count)

    @staticmethod
    def _write(path: Path, rows: tuple[DailyReportRow, ...]) -> None:
        workbook = xlsxwriter.Workbook(path, {"constant_memory": True})
        try:
            workbook.set_properties(
                {"created": _DETERMINISTIC_WORKBOOK_CREATED_AT}
            )
            sheet = workbook.add_worksheet("Sheet1")
            shared = {
                "align": "center",
                "border": 1,
                "font_name": "宋体",
                "font_size": 11,
                "valign": "vcenter",
            }
            header = workbook.add_format(shared)
            text = workbook.add_format(
                shared
            )
            date_format = workbook.add_format(
                {
                    **shared,
                    "num_format": r"yyyy\.m\.d",
                }
            )
            loading_time_format = workbook.add_format(
                {
                    **shared,
                    "num_format": 'yyyy"年"m"月"d"日"h"时"mm"分"ss"秒"',
                }
            )
            unloading_time_format = workbook.add_format(
                {
                    **shared,
                    "num_format": 'yyyy"年"m"月"d"日"h"时"mm"分"',
                }
            )
            weight = workbook.add_format(
                {
                    **shared,
                    "num_format": "0.00",
                }
            )
            summary_total = workbook.add_format(
                {**shared, "bold": True, "num_format": "0.00"}
            )
            summary_label = workbook.add_format({**shared, "bold": True})
            sheet.set_default_row(14.4)
            for column, width in enumerate(_REFERENCE_COLUMN_WIDTHS):
                sheet.set_column(column, column, max(1.0, width - 0.8))
            sheet.set_portrait()
            for column, header_value in enumerate(REPORT_HEADERS):
                sheet.write(0, column, header_value, header)
            for row_index, row in enumerate(rows, start=1):
                values = row.values()
                for column, cell_value in enumerate(values):
                    if cell_value is None:
                        sheet.write_blank(row_index, column, None, text)
                    elif isinstance(cell_value, datetime):
                        sheet.write_datetime(
                            row_index,
                            column,
                            cell_value,
                            (
                                unloading_time_format
                                if column == 9
                                else loading_time_format
                            ),
                        )
                    elif isinstance(cell_value, date):
                        sheet.write_datetime(
                            row_index,
                            column,
                            datetime(
                                cell_value.year,
                                cell_value.month,
                                cell_value.day,
                            ),
                            date_format,
                        )
                    elif isinstance(cell_value, Decimal):
                        sheet.write_number(
                            row_index,
                            column,
                            float(cell_value),
                            weight,
                        )
                    else:
                        sheet.write(row_index, column, cell_value, text)
            summary_row = len(rows) + 1
            for column in range(len(REPORT_HEADERS)):
                sheet.write_blank(summary_row, column, None, text)
            sheet.merge_range(
                summary_row,
                0,
                summary_row,
                4,
                f"{len(rows)}车",
                summary_label,
            )
            loading_total = sum(
                (row.loading_net_tonnes or Decimal("0") for row in rows),
                Decimal("0"),
            )
            sheet.write_number(
                summary_row,
                5,
                float(loading_total),
                summary_total,
            )
            sheet.autofilter(0, 0, len(rows), len(REPORT_HEADERS) - 1)
        finally:
            workbook.close()

    @staticmethod
    def _patch_reference_dimensions(path: Path) -> None:
        """Preserve exact reference widths that XlsxWriter rounds internally."""

        temporary = path.with_name(f".{path.name}.{uuid4().hex}.zip")
        namespace = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        ElementTree.register_namespace("", namespace)
        try:
            with zipfile.ZipFile(path, "r") as source, zipfile.ZipFile(
                temporary,
                "w",
            ) as target:
                for member in source.infolist():
                    data = source.read(member.filename)
                    if member.filename == "xl/worksheets/sheet1.xml":
                        root = ElementTree.fromstring(data)
                        columns_parent = root.find(f"{{{namespace}}}cols")
                        columns = (
                            []
                            if columns_parent is None
                            else list(columns_parent)
                        )
                        if not columns or columns_parent is None:
                            raise DailyReportWorkbookError(
                                "report column layout changed"
                            )
                        attributes_by_index: dict[int, dict[str, str]] = {}
                        for column in columns:
                            start = int(column.attrib["min"])
                            end = int(column.attrib["max"])
                            for index in range(start, end + 1):
                                attributes_by_index[index] = dict(column.attrib)
                            columns_parent.remove(column)
                        for index, width in enumerate(
                            _REFERENCE_COLUMN_WIDTHS,
                            start=1,
                        ):
                            attributes = attributes_by_index.get(index)
                            if attributes is None:
                                raise DailyReportWorkbookError(
                                    "report column layout changed"
                                )
                            attributes.update(
                                {
                                    "customWidth": "1",
                                    "max": str(index),
                                    "min": str(index),
                                    "width": format(width, ".10g"),
                                }
                            )
                            ElementTree.SubElement(
                                columns_parent,
                                f"{{{namespace}}}col",
                                attributes,
                            )
                        data = ElementTree.tostring(
                            root,
                            encoding="utf-8",
                            xml_declaration=True,
                        )
                    target.writestr(member, data)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _validate(path: Path, *, row_count: int) -> None:
        try:
            with zipfile.ZipFile(path) as archive:
                if archive.testzip() is not None:
                    raise DailyReportWorkbookError("report archive is corrupt")
                sheet = ElementTree.fromstring(
                    archive.read("xl/worksheets/sheet1.xml")
                )
                styles = archive.read("xl/styles.xml").decode("utf-8")
                workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
        except (KeyError, OSError, zipfile.BadZipFile) as exc:
            raise DailyReportWorkbookError("report cannot be reopened") from exc
        namespace = {
            "x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        }
        rows = sheet.findall("x:sheetData/x:row", namespace)
        auto_filter = sheet.find("x:autoFilter", namespace)
        panes = sheet.findall("x:sheetViews/x:sheetView/x:pane", namespace)
        merges = {
            item.attrib.get("ref")
            for item in sheet.findall("x:mergeCells/x:mergeCell", namespace)
        }
        columns = sheet.findall("x:cols/x:col", namespace)
        cells = sheet.findall("x:sheetData/x:row/x:c", namespace)
        dimension = sheet.find("x:dimension", namespace)
        workbook_namespace = {
            "x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
        }
        sheet_names = [
            item.attrib.get("name")
            for item in workbook.findall("x:sheets/x:sheet", workbook_namespace)
        ]
        expected_filter = f"A1:J{row_count + 1}"
        if (
            len(rows) != row_count + 2
            or auto_filter is None
            or auto_filter.attrib.get("ref") != expected_filter
            or "宋体" not in styles
            or sheet_names != ["Sheet1"]
            or panes
            or merges != {f"A{row_count + 2}:E{row_count + 2}"}
            or len(columns) != len(_REFERENCE_COLUMN_WIDTHS)
            or dimension is None
            or dimension.attrib.get("ref") != f"A1:J{row_count + 2}"
            or any("style" in column.attrib for column in columns)
            or any(
                not _cell_reference_within_report(
                    cell.attrib.get("r", ""),
                    last_row=row_count + 2,
                )
                for cell in cells
            )
            or any(
                abs(float(column.attrib["width"]) - expected) > 0.000001
                for column, expected in zip(
                    columns,
                    _REFERENCE_COLUMN_WIDTHS,
                    strict=True,
                )
            )
        ):
            raise DailyReportWorkbookError("report validation failed")


def _cell_reference_within_report(reference: str, *, last_row: int) -> bool:
    """Reject styled or populated cells outside the locked A:J report range."""

    match = re.fullmatch(r"([A-Z]+)([1-9][0-9]*)", reference)
    if match is None:
        return False
    column, row_text = match.groups()
    return len(column) == 1 and "A" <= column <= "J" and int(row_text) <= last_row
