from __future__ import annotations

import json
import re
from datetime import date, datetime, timedelta

from dahe.domain.daily.calendar import SHANGHAI

_FULL_DATE_TIME = re.compile(
    r"(?P<year>20\d{2})\D{0,3}(?P<month>\d{1,2})\D{0,3}(?P<day>\d{1,2})"
    r"\D{0,6}(?P<hour>\d{1,2})[\uff1a:](?P<minute>\d{1,2})"
    r"(?:[\uff1a:](?P<second>\d{1,2}))?"
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
_LABEL_SEPARATORS = re.compile(r"[\s\uff1a:_\-—]+")


def extract_unloading_time(
    output_json: str | None,
    *,
    loading_time: datetime | None,
    planned_date: date | None,
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

    fields = payload.get("fields")
    if isinstance(fields, dict):
        value = fields.get("unloading_tare_time")
        raw_text = value.get("raw_text") if isinstance(value, dict) else value
        if isinstance(raw_text, str):
            parsed = _parse_candidate(
                raw_text,
                loading_time=loading_time,
                planned_date=planned_date,
            )
            if parsed is not None:
                return parsed

    text_lines = payload.get("text_lines")
    if not isinstance(text_lines, list):
        return None
    lines = [
        str(line.get("text", "")).strip()
        for line in text_lines
        if isinstance(line, dict) and str(line.get("text", "")).strip()
    ]
    for index in range(len(lines)):
        context = " ".join(lines[index : index + 3])
        normalized_context = _normalize_label_context(context)
        if not any(label in normalized_context for label in _TARGET_LABELS):
            continue
        if any(label in normalized_context for label in _EXCLUDED_LABELS):
            context = lines[index]
        parsed = _parse_candidate(
            context,
            loading_time=loading_time,
            planned_date=planned_date,
        )
        if parsed is not None:
            return parsed
    return None


def _normalize_label_context(value: str) -> str:
    return _LABEL_SEPARATORS.sub("", value)


def _parse_candidate(
    value: str,
    *,
    loading_time: datetime | None,
    planned_date: date | None,
) -> datetime | None:
    normalized = value.replace("年", "-").replace("月", "-").replace("日", " ")
    match = _FULL_DATE_TIME.search(normalized) or _COMPACT_DATE_TIME.search(normalized)
    if match is not None:
        return _build_datetime(match)
    match = _TIME_ONLY.search(normalized)
    if match is None:
        return None
    base_date = loading_time.astimezone(SHANGHAI).date() if loading_time else planned_date
    if base_date is None:
        return None
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
