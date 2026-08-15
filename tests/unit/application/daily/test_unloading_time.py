from __future__ import annotations

import json
from datetime import date, datetime

from dahe.application.daily.unloading_time import (
    extract_loading_time,
    extract_unloading_time,
)
from dahe.domain.daily.calendar import SHANGHAI


def _output(*, field: str | None = None, lines: tuple[str, ...] = ()) -> str:
    return json.dumps(
        {
            "status": "ok",
            "fields": (
                {}
                if field is None
                else {"unloading_tare_time": {"raw_text": field}}
            ),
            "text_lines": [{"text": value} for value in lines],
        },
        ensure_ascii=False,
    )


def test_extracts_full_unloading_tare_time_field() -> None:
    assert extract_unloading_time(
        _output(field="皮重时间 2026-08-07 19:33:24"),
        loading_time=None,
        planned_date=date(2026, 8, 7),
    ) == datetime(2026, 8, 7, 19, 33, 24, tzinfo=SHANGHAI)


def test_extracts_labeled_time_only_and_rolls_over_midnight() -> None:
    assert extract_unloading_time(
        _output(lines=("回皮时间", "00:12:03")),
        loading_time=datetime(2026, 8, 7, 23, 50, tzinfo=SHANGHAI),
        planned_date=date(2026, 8, 7),
    ) == datetime(2026, 8, 8, 0, 12, 3, tzinfo=SHANGHAI)


def test_extracts_spaced_or_split_unloading_labels() -> None:
    assert extract_unloading_time(
        _output(lines=("皮 重 时 间\uff1a", "2026 / 08 / 07 19:33:24")),
        loading_time=datetime(2026, 8, 7, 18, 0, tzinfo=SHANGHAI),
        planned_date=date(2026, 8, 7),
    ) == datetime(2026, 8, 7, 19, 33, 24, tzinfo=SHANGHAI)
    assert extract_unloading_time(
        _output(lines=("回皮", "时间", "20\uff1a05\uff1a06")),
        loading_time=datetime(2026, 8, 7, 18, 0, tzinfo=SHANGHAI),
        planned_date=date(2026, 8, 7),
    ) == datetime(2026, 8, 7, 20, 5, 6, tzinfo=SHANGHAI)


def test_extracts_direct_string_field_value() -> None:
    payload = json.dumps(
        {
            "status": "ok",
            "fields": {"unloading_tare_time": "2026-08-07 19:33:24"},
            "text_lines": [],
        },
        ensure_ascii=False,
    )
    assert extract_unloading_time(
        payload,
        loading_time=None,
        planned_date=date(2026, 8, 7),
    ) == datetime(2026, 8, 7, 19, 33, 24, tzinfo=SHANGHAI)


def test_ignores_print_and_gross_times_without_unloading_label() -> None:
    assert (
        extract_unloading_time(
            _output(lines=("打印时间 2026-08-07 19:33:24", "毛重时间 18:01:02")),
            loading_time=datetime(2026, 8, 7, 17, 0, tzinfo=SHANGHAI),
            planned_date=date(2026, 8, 7),
        )
        is None
    )


def test_invalid_or_failed_output_is_not_a_business_value() -> None:
    assert extract_unloading_time("{invalid", loading_time=None, planned_date=None) is None
    assert (
        extract_unloading_time(
            json.dumps({"status": "error", "fields": {}, "text_lines": []}),
            loading_time=None,
            planned_date=None,
        )
        is None
    )


def test_extracts_loading_time_from_field_or_labeled_text() -> None:
    field_payload = json.dumps(
        {
            "status": "ok",
            "fields": {
                "loading_weigh_time": {
                    "raw_text": "过磅时间 2026-08-13 13:59:58"
                }
            },
            "text_lines": [],
        },
        ensure_ascii=False,
    )
    assert extract_loading_time(
        field_payload,
        platform_loading_time=datetime(
            2026, 8, 13, 14, 5, tzinfo=SHANGHAI
        ),
        planned_date=None,
    ) == datetime(2026, 8, 13, 13, 59, 58, tzinfo=SHANGHAI)

    assert extract_loading_time(
        _output(lines=("过 磅 时 间", "14:06:07")),
        platform_loading_time=datetime(
            2026, 8, 13, 14, 5, tzinfo=SHANGHAI
        ),
        planned_date=None,
    ) == datetime(2026, 8, 13, 14, 6, 7, tzinfo=SHANGHAI)


def test_loading_time_does_not_use_unloading_or_print_labels() -> None:
    assert (
        extract_loading_time(
            _output(
                lines=(
                    "打印时间 2026-08-13 14:06:07",
                    "皮重时间 2026-08-13 16:07:08",
                )
            ),
            platform_loading_time=datetime(
                2026, 8, 13, 14, 5, tzinfo=SHANGHAI
            ),
            planned_date=None,
        )
        is None
    )
