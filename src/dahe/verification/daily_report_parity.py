from __future__ import annotations

import hashlib
import re
import zipfile
from dataclasses import dataclass, replace
from pathlib import Path
from xml.etree import ElementTree

_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CELL_REFERENCE = re.compile(r"^([A-Z]+)([1-9][0-9]*)$")


class DailyReportParityError(RuntimeError):
    pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _tag(name: str) -> str:
    return f"{{{_MAIN}}}{name}"


def _attribute(node: ElementTree.Element | None, name: str) -> str | None:
    return None if node is None else node.attrib.get(name)


def _font_contract(font: ElementTree.Element) -> tuple[object, ...]:
    return (
        _attribute(font.find(_tag("name")), "val"),
        _attribute(font.find(_tag("sz")), "val"),
        font.find(_tag("b")) is not None,
        font.find(_tag("i")) is not None,
        font.find(_tag("u")) is not None,
    )


def _border_contract(border: ElementTree.Element) -> tuple[str | None, ...]:
    return tuple(
        _attribute(border.find(_tag(side)), "style")
        for side in ("left", "right", "top", "bottom")
    )


def _style_contract(
    *,
    xf: ElementTree.Element,
    fonts: list[ElementTree.Element],
    borders: list[ElementTree.Element],
    number_formats: dict[int, str],
) -> tuple[object, ...]:
    font_id = int(xf.attrib.get("fontId", "0"))
    border_id = int(xf.attrib.get("borderId", "0"))
    number_format_id = int(xf.attrib.get("numFmtId", "0"))
    alignment = xf.find(_tag("alignment"))
    normalized_number_format = number_formats.get(number_format_id)
    if normalized_number_format is None:
        normalized_number_format = {
            0: "general",
            2: "0.00",
        }.get(number_format_id, f"builtin:{number_format_id}")
    return (
        _font_contract(fonts[font_id]),
        _border_contract(borders[border_id]),
        normalized_number_format,
        _attribute(alignment, "horizontal"),
        _attribute(alignment, "vertical"),
        _attribute(alignment, "wrapText"),
    )


def _normalized_range(reference: str, *, summary_row: int) -> str:
    parts = reference.split(":")
    normalized: list[str] = []
    for part in parts:
        match = _CELL_REFERENCE.fullmatch(part)
        if match is None:
            raise DailyReportParityError(f"invalid spreadsheet range: {reference}")
        column, row_text = match.groups()
        row = int(row_text)
        if row == summary_row:
            row_text = "SUMMARY"
        elif row == summary_row - 1:
            row_text = "LAST_DATA"
        normalized.append(f"{column}{row_text}")
    return ":".join(normalized)


@dataclass(frozen=True, slots=True)
class DailyReportFormatContract:
    sheet_names: tuple[str, ...]
    column_widths: tuple[float, ...]
    default_row_height: float
    freeze_pane_count: int
    orientation: str
    filter_range: str
    merge_ranges: tuple[str, ...]
    style_roles: tuple[tuple[str, tuple[object, ...]], ...]
    numeric_roles: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        return {
            "sheet_names": list(self.sheet_names),
            "column_widths": list(self.column_widths),
            "default_row_height": self.default_row_height,
            "freeze_pane_count": self.freeze_pane_count,
            "orientation": self.orientation,
            "filter_range": self.filter_range,
            "merge_ranges": list(self.merge_ranges),
            "style_roles": [
                [name, list(value)] for name, value in self.style_roles
            ],
            "numeric_roles": list(self.numeric_roles),
        }


@dataclass(frozen=True, slots=True)
class DailyReportParityResult:
    reference_sha256: str
    candidate_sha256: str
    reference_contract: DailyReportFormatContract
    candidate_contract: DailyReportFormatContract
    allowed_differences: tuple[str, ...]


def inspect_daily_report_format(path: Path) -> DailyReportFormatContract:
    resolved = path.resolve(strict=True)
    try:
        with zipfile.ZipFile(resolved) as archive:
            workbook = ElementTree.fromstring(archive.read("xl/workbook.xml"))
            sheet = ElementTree.fromstring(archive.read("xl/worksheets/sheet1.xml"))
            styles = ElementTree.fromstring(archive.read("xl/styles.xml"))
    except (OSError, KeyError, zipfile.BadZipFile) as exc:
        raise DailyReportParityError("workbook cannot be inspected") from exc

    sheets = workbook.find(_tag("sheets"))
    if sheets is None:
        raise DailyReportParityError("workbook has no worksheets")
    sheet_names = tuple(item.attrib.get("name", "") for item in sheets)
    if not sheet_names:
        raise DailyReportParityError("workbook has no worksheet names")

    rows_parent = sheet.find(_tag("sheetData"))
    rows = [] if rows_parent is None else list(rows_parent)
    if len(rows) < 3:
        raise DailyReportParityError("workbook needs a header, data, and summary row")
    summary_row = int(rows[-1].attrib["r"])
    data_row = int(rows[1].attrib["r"])

    columns_parent = sheet.find(_tag("cols"))
    columns = [] if columns_parent is None else list(columns_parent)
    widths_by_index: dict[int, float] = {}
    for column in columns:
        start = int(column.attrib["min"])
        end = int(column.attrib["max"])
        for index in range(start, end + 1):
            widths_by_index[index] = float(column.attrib["width"])
    if set(widths_by_index) != set(range(1, 11)):
        raise DailyReportParityError("workbook must define exactly ten columns")

    sheet_format = sheet.find(_tag("sheetFormatPr"))
    default_row_height = float(
        "0" if sheet_format is None else sheet_format.attrib.get("defaultRowHeight", "0")
    )
    panes = sheet.findall(f"{_tag('sheetViews')}/{_tag('sheetView')}/{_tag('pane')}")
    page_setup = sheet.find(_tag("pageSetup"))
    orientation = "portrait" if page_setup is None else page_setup.attrib.get(
        "orientation", "portrait"
    )
    auto_filter = sheet.find(_tag("autoFilter"))
    if auto_filter is None or "ref" not in auto_filter.attrib:
        raise DailyReportParityError("workbook has no autofilter")
    merges_parent = sheet.find(_tag("mergeCells"))
    merge_ranges = tuple(
        sorted(
            _normalized_range(item.attrib["ref"], summary_row=summary_row)
            for item in ([] if merges_parent is None else list(merges_parent))
        )
    )

    fonts_parent = styles.find(_tag("fonts"))
    borders_parent = styles.find(_tag("borders"))
    xfs_parent = styles.find(_tag("cellXfs"))
    if fonts_parent is None or borders_parent is None or xfs_parent is None:
        raise DailyReportParityError("workbook styles are incomplete")
    fonts = list(fonts_parent)
    borders = list(borders_parent)
    xfs = list(xfs_parent)
    number_formats_parent = styles.find(_tag("numFmts"))
    number_formats = {
        int(item.attrib["numFmtId"]): item.attrib["formatCode"]
        for item in ([] if number_formats_parent is None else list(number_formats_parent))
    }

    cells: dict[str, ElementTree.Element] = {}
    for row in rows:
        for cell in row.findall(_tag("c")):
            reference = cell.attrib.get("r")
            if reference is not None:
                cells[reference] = cell

    role_references = {
        "header": "A1",
        "body_text": f"A{data_row}",
        "planned_date": f"C{data_row}",
        "loading_time": f"D{data_row}",
        "weight": f"F{data_row}",
        "unloading_time": f"J{data_row}",
        "summary_label": f"A{summary_row}",
        "summary_total": f"F{summary_row}",
        "summary_blank": f"G{summary_row}",
    }
    role_styles: list[tuple[str, tuple[object, ...]]] = []
    for role, reference in role_references.items():
        role_cell = cells.get(reference)
        if role_cell is None:
            raise DailyReportParityError(f"workbook is missing the {role} cell")
        style_id = int(role_cell.attrib.get("s", "0"))
        role_styles.append(
            (
                role,
                _style_contract(
                    xf=xfs[style_id],
                    fonts=fonts,
                    borders=borders,
                    number_formats=number_formats,
                ),
            )
        )

    numeric_roles = tuple(
        role
        for role in ("planned_date", "loading_time", "weight", "unloading_time")
        if cells[role_references[role]].attrib.get("t") in {None, "n", "d"}
    )
    return DailyReportFormatContract(
        sheet_names=sheet_names,
        column_widths=tuple(widths_by_index[index] for index in range(1, 11)),
        default_row_height=default_row_height,
        freeze_pane_count=len(panes),
        orientation=orientation,
        filter_range=_normalized_range(
            auto_filter.attrib["ref"], summary_row=summary_row
        ),
        merge_ranges=merge_ranges,
        style_roles=tuple(role_styles),
        numeric_roles=numeric_roles,
    )


def verify_daily_report_parity(
    *,
    reference: Path,
    candidate: Path,
) -> DailyReportParityResult:
    reference_contract = inspect_daily_report_format(reference)
    candidate_contract = inspect_daily_report_format(candidate)
    allowed_differences: list[str] = []
    comparison_reference = reference_contract
    if "planned_date" not in reference_contract.numeric_roles:
        allowed_differences.append(
            "The locked reference stores planned dates as text; the generated report "
            "uses true Excel dates as required by the current product contract."
        )
        comparison_reference = replace(
            comparison_reference,
            numeric_roles=(
                "planned_date",
                "loading_time",
                "weight",
                "unloading_time",
            ),
        )
    if candidate_contract != comparison_reference:
        raise DailyReportParityError("candidate report format differs from the reference")
    return DailyReportParityResult(
        reference_sha256=_sha256(reference),
        candidate_sha256=_sha256(candidate),
        reference_contract=reference_contract,
        candidate_contract=candidate_contract,
        allowed_differences=tuple(allowed_differences),
    )
