from __future__ import annotations

import json
import re
from datetime import datetime, timedelta

from dahe.domain.daily.calendar import SHANGHAI

_FULL_DATE_TIME = re.compile(
    r"(?P<year>20\d{2})\D{0,3}(?P<month>\d{1,2})\D{0,3}(?P<day>\d{1,2})"
    r"\D{0,6}(?P<hour>\d{1,2})[\uff1a:](?P<minute>\d{1,2})"
    r"(?:[\uff1a:;\uff1b](?P<second>\d{1,2}))?"
)
_COMPACT_DATE_TIME = re.compile(
    r"(?<!\d)(?P<year>20\d{2})(?P<month>\d{2})(?P<day>\d{2})"
    r"(?P<hour>\d{2})(?P<minute>\d{2})(?P<second>\d{2})(?!\d)"
)
_TIME_ONLY = re.compile(
    r"(?<!\d)(?P<hour>[01]?\d|2[0-3])[\uff1a:](?P<minute>[0-5]?\d)"
    r"(?:[\uff1a:](?P<second>[0-5]?\d))?(?!\d)"
)
_TARGET_LABELS = ("皮重时间", "回皮时间")
_EXCLUDED_LABELS = ("打印时间", "毛重时间")
_PRINT_LABELS = ("打印时间", "T时间")
_LOADING_TARGET_LABELS = ("过磅时间", "装车时间", "毛重时间")
_LOADING_EXCLUDED_LABELS = ("打印时间", "皮重时间", "回皮时间")
_STANDARD_LOADING_WEIGHT_FIELDS = frozenset(("gross", "tare", "ordinary_net"))
_LABEL_SEPARATORS = re.compile(r"[\s\uff1a:_\-—]+")


def extract_loading_time(
    output_json: str | None,
) -> datetime | None:
    """Extract the loading weigh time from a committed local OCR result."""

    if not output_json:
        return None
    try:
        payload = json.loads(output_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None

    candidates: set[datetime] = set()
    fields = payload.get("fields")
    if isinstance(fields, dict):
        value = fields.get("loading_weigh_time")
        raw_text = value.get("raw_text") if isinstance(value, dict) else value
        if isinstance(raw_text, str):
            parsed = _parse_candidate(
                raw_text,
                loading_time=None,
            )
            if parsed is not None:
                candidates.add(parsed)

    text_lines = payload.get("text_lines")
    if not isinstance(text_lines, list):
        return next(iter(candidates)) if len(candidates) == 1 else None
    lines = [
        str(line.get("text", "")).strip()
        for line in text_lines
        if isinstance(line, dict) and str(line.get("text", "")).strip()
    ]
    for index in _label_anchor_indexes(lines, labels=_LOADING_TARGET_LABELS):
        context = " ".join(lines[index : index + 3])
        normalized_context = _normalize_label_context(context)
        if any(label in normalized_context for label in _LOADING_EXCLUDED_LABELS):
            continue
        parsed = _parse_candidate(
            context,
            loading_time=None,
        )
        if parsed is not None:
            candidates.add(parsed)
    if candidates:
        return next(iter(candidates)) if len(candidates) == 1 else None
    # The standard mine ticket can be photographed with its left edge cropped,
    # causing OCR to lose the first character of `过磅时间`. The weight-role
    # triplet is established by the OCR template itself (never by platform
    # weights), so one unique full datetime remains qualified for that layout.
    # Non-standard documents and conflicting timestamps still require review.
    if _is_standard_loading_ticket(fields):
        for line in lines:
            normalized = _normalize_label_context(line)
            if any(label in normalized for label in _LOADING_EXCLUDED_LABELS):
                continue
            match = _FULL_DATE_TIME.search(line) or _COMPACT_DATE_TIME.search(line)
            if match is not None:
                parsed = _build_datetime(match)
                if parsed is not None:
                    candidates.add(parsed)
    return next(iter(candidates)) if len(candidates) == 1 else None


def extract_unloading_time(
    output_json: str | None,
    *,
    loading_time: datetime | None,
) -> datetime | None:
    """Extract the unloading tare time from a committed local OCR result."""

    if not output_json:
        return None
    try:
        payload = json.loads(output_json)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        return None

    candidates: set[datetime] = set()
    fields = payload.get("fields")
    if isinstance(fields, dict):
        value = fields.get("unloading_tare_time")
        raw_text = value.get("raw_text") if isinstance(value, dict) else value
        if isinstance(raw_text, str):
            parsed = _parse_candidate(
                raw_text,
                loading_time=loading_time,
            )
            if parsed is not None:
                candidates.add(parsed)

    text_lines = payload.get("text_lines")
    if not isinstance(text_lines, list):
        return next(iter(candidates)) if len(candidates) == 1 else None
    lines = [
        str(line.get("text", "")).strip()
        for line in text_lines
        if isinstance(line, dict) and str(line.get("text", "")).strip()
    ]
    standard_table_time = _standard_unloading_table_time(lines)
    if standard_table_time is not None:
        candidates.add(standard_table_time)
        return next(iter(candidates)) if len(candidates) == 1 else None
    for index in _label_anchor_indexes(lines, labels=_TARGET_LABELS):
        parsed = _parse_value_near_label(
            lines,
            anchor=index,
            loading_time=loading_time,
        )
        if parsed is not None:
            candidates.add(parsed)
    return next(iter(candidates)) if len(candidates) == 1 else None


def _standard_unloading_table_time(lines: list[str]) -> datetime | None:
    """Resolve gross/tare table rows whose OCR reading order lost the columns."""

    normalized_lines = tuple(_normalize_label_context(line) for line in lines)
    if not any(
        label in line for line in normalized_lines for label in _TARGET_LABELS
    ):
        return None
    if not any("毛重时间" in line for line in normalized_lines):
        return None
    candidates = {
        parsed
        for line, normalized in zip(lines, normalized_lines, strict=True)
        if not any(label in normalized for label in _PRINT_LABELS)
        for parsed in (_parse_full_candidate(line),)
        if parsed is not None
    }
    if len(candidates) != 2:
        return None
    # A completed unloading ticket records gross weighing before tare weighing.
    # Selecting the later OCR timestamp is safe only under the exact two-label,
    # two-value table contract above; any extra or conflicting time stays review.
    return max(candidates)


def _normalize_label_context(value: str) -> str:
    return _LABEL_SEPARATORS.sub("", value)


def _label_anchor_indexes(
    lines: list[str],
    *,
    labels: tuple[str, ...],
) -> tuple[int, ...]:
    """Locate labels without allowing a preceding value to borrow the label."""

    anchors: list[int] = []
    for index, line in enumerate(lines):
        current = _normalize_label_context(line)
        if any(label in current for label in labels):
            anchors.append(index)
            continue
        if not current or index + 1 >= len(lines):
            continue
        combined = current + _normalize_label_context(lines[index + 1])
        if any(label.startswith(current) and label in combined for label in labels):
            anchors.append(index)
    return tuple(anchors)


def _parse_value_near_label(
    lines: list[str],
    *,
    anchor: int,
    loading_time: datetime | None,
) -> datetime | None:
    """Read one table value without crossing another business-time label."""

    parsed = _parse_candidate(lines[anchor], loading_time=loading_time)
    if parsed is not None:
        return parsed
    all_time_labels = _TARGET_LABELS + _EXCLUDED_LABELS
    for distance in range(1, 5):
        index = anchor + distance
        if index >= len(lines):
            break
        normalized = _normalize_label_context(lines[index])
        if any(label in normalized for label in all_time_labels):
            break
        parsed = _parse_candidate(lines[index], loading_time=loading_time)
        if parsed is not None:
            return parsed
    preceding: datetime | None = None
    for distance in range(1, 5):
        index = anchor - distance
        if index < 0:
            break
        normalized = _normalize_label_context(lines[index])
        if any(label in normalized for label in all_time_labels):
            break
        parsed = _parse_candidate(lines[index], loading_time=loading_time)
        if parsed is not None:
            preceding = parsed
            break
    if preceding is None:
        return None
    non_print_times = {
        parsed
        for line in lines
        if not any(
            label in _normalize_label_context(line) for label in _PRINT_LABELS
        )
        for parsed in (_parse_candidate(line, loading_time=loading_time),)
        if parsed is not None
    }
    if len(non_print_times) < 2 or preceding != max(non_print_times):
        return None
    return preceding


def _is_standard_loading_ticket(fields: object) -> bool:
    if not isinstance(fields, dict):
        return False
    if not _STANDARD_LOADING_WEIGHT_FIELDS.issubset(fields):
        return False
    return all(
        isinstance(fields[field], dict)
        and fields[field].get("amount") not in (None, "")
        for field in _STANDARD_LOADING_WEIGHT_FIELDS
    )


def _parse_candidate(
    value: str,
    *,
    loading_time: datetime | None,
) -> datetime | None:
    normalized = value.replace("年", "-").replace("月", "-").replace("日", " ")
    match = _FULL_DATE_TIME.search(normalized) or _COMPACT_DATE_TIME.search(normalized)
    if match is not None:
        return _build_datetime(match)
    match = _TIME_ONLY.search(normalized)
    if match is None:
        return None
    if loading_time is None:
        return None
    base_date = loading_time.astimezone(SHANGHAI).date()
    candidate = datetime(
        base_date.year,
        base_date.month,
        base_date.day,
        int(match.group("hour")),
        int(match.group("minute")),
        int(match.group("second") or 0),
        tzinfo=SHANGHAI,
    )
    if loading_time is not None:
        normalized_loading = loading_time.astimezone(SHANGHAI)
        if candidate < normalized_loading:
            candidate += timedelta(days=1)
    return candidate


def _parse_full_candidate(value: str) -> datetime | None:
    normalized = value.replace("年", "-").replace("月", "-").replace("日", " ")
    match = _FULL_DATE_TIME.search(normalized) or _COMPACT_DATE_TIME.search(normalized)
    return None if match is None else _build_datetime(match)


def _build_datetime(match: re.Match[str]) -> datetime | None:
    try:
        return datetime(
            int(match.group("year")),
            int(match.group("month")),
            int(match.group("day")),
            int(match.group("hour")),
            int(match.group("minute")),
            int(match.group("second") or 0),
            tzinfo=SHANGHAI,
        )
    except ValueError:
        return None
