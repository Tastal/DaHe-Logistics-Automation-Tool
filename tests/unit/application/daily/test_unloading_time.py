from __future__ import annotations

import json
from datetime import datetime

from dahe.application.daily.unloading_time import (
    extract_loading_time,
    extract_unloading_time,
)
from dahe.domain.daily.calendar import SHANGHAI


def _output(
    *,
    field: str | None = None,
    lines: tuple[str, ...] = (),
    standard_loading_ticket: bool = False,
) -> str:
    fields: dict[str, object] = (
        {
            "gross": {"amount": "48.50", "unit": "t"},
            "tare": {"amount": "15.92", "unit": "t"},
            "ordinary_net": {"amount": "32.58", "unit": "t"},
        }
        if standard_loading_ticket
        else {}
    )
    if field is not None:
        fields["unloading_tare_time"] = {"raw_text": field}
    return json.dumps(
        {
            "status": "ok",
            "fields": fields,
            "text_lines": [{"text": value} for value in lines],
        },
        ensure_ascii=False,
    )


def test_extracts_full_unloading_tare_time_field() -> None:
    assert extract_unloading_time(
        _output(field="皮重时间 2026-08-07 19:33:24"),
        loading_time=None,
    ) == datetime(2026, 8, 7, 19, 33, 24, tzinfo=SHANGHAI)


def test_extracts_labeled_time_only_and_rolls_over_midnight() -> None:
    assert extract_unloading_time(
        _output(lines=("回皮时间", "00:12:03")),
        loading_time=datetime(2026, 8, 7, 23, 50, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 8, 0, 12, 3, tzinfo=SHANGHAI)


def test_extracts_spaced_or_split_unloading_labels() -> None:
    assert extract_unloading_time(
        _output(lines=("皮 重 时 间\uff1a", "2026 / 08 / 07 19:33:24")),
        loading_time=datetime(2026, 8, 7, 18, 0, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 7, 19, 33, 24, tzinfo=SHANGHAI)
    assert extract_unloading_time(
        _output(lines=("回皮", "时间", "20\uff1a05\uff1a06")),
        loading_time=datetime(2026, 8, 7, 18, 0, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 7, 20, 5, 6, tzinfo=SHANGHAI)


def test_unloading_label_does_not_qualify_a_time_before_the_label() -> None:
    assert extract_unloading_time(
        _output(
            lines=(
                "毛重时间",
                "2026-08-16 14:10:58",
                "到达站",
                "皮重时间",
                "2026-08-16 14:39:08",
            )
        ),
        loading_time=datetime(2026, 8, 16, 13, 54, 42, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 16, 14, 39, 8, tzinfo=SHANGHAI)


def test_extracts_table_value_rendered_immediately_before_unloading_label() -> None:
    assert extract_unloading_time(
        _output(
            lines=(
                "毛重时间",
                "2026-08-16 11:29:03",
                "收货单位",
                "2026-08-16 12:00:40",
                "皮重时间",
            )
        ),
        loading_time=datetime(2026, 8, 16, 11, 10, 39, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 16, 12, 0, 40, tzinfo=SHANGHAI)


def test_standard_unloading_table_uses_tare_time_when_values_precede_labels() -> None:
    assert extract_unloading_time(
        _output(
            standard_loading_ticket=True,
            lines=(
                "2026-08-15 23:26:26",
                "毛重时间",
                "2026-08-15 23:39:58",
                "皮重时间",
            ),
        ),
        loading_time=datetime(2026, 8, 15, 22, 13, 37, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 15, 23, 39, 58, tzinfo=SHANGHAI)


def test_standard_unloading_table_uses_later_tare_time_after_both_labels() -> None:
    assert extract_unloading_time(
        _output(
            lines=(
                "打印时间\uFF1A2026-08-15 23:40:16",
                "毛重时间",
                "榆林南磅6号-出",
                "皮重时间",
                "2026-08-15 23:26:26",
                "50.00",
                "2026-08-15 23:39:58",
            ),
        ),
        loading_time=datetime(2026, 8, 15, 23, 5, 1, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 15, 23, 39, 58, tzinfo=SHANGHAI)


def test_excludes_a_cropped_print_label_from_table_time_candidates() -> None:
    assert extract_unloading_time(
        _output(
            lines=(
                "T时间\uFF1A2026-08-15 23:35:49",
                "毛重时间",
                "2026-08-15 23:15:48",
                "2026-08-15 23:35:27",
                "皮重时间",
            )
        ),
        loading_time=datetime(2026, 8, 15, 22, 13, 37, tzinfo=SHANGHAI),
    ) == datetime(2026, 8, 15, 23, 35, 27, tzinfo=SHANGHAI)


def test_unloading_label_does_not_reach_back_across_gross_time_label() -> None:
    assert (
        extract_unloading_time(
            _output(
                lines=(
                    "打印时间 2026-08-16 12:01:00",
                    "毛重时间",
                    "2026-08-16 11:29:03",
                    "收货单位",
                    "皮重时间",
                )
            ),
            loading_time=datetime(2026, 8, 16, 11, 10, 39, tzinfo=SHANGHAI),
        )
        is None
    )


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
    ) == datetime(2026, 8, 7, 19, 33, 24, tzinfo=SHANGHAI)


def test_ignores_print_and_gross_times_without_unloading_label() -> None:
    assert (
        extract_unloading_time(
            _output(lines=("打印时间 2026-08-07 19:33:24", "毛重时间 18:01:02")),
            loading_time=datetime(2026, 8, 7, 17, 0, tzinfo=SHANGHAI),
        )
        is None
    )


def test_invalid_or_failed_output_is_not_a_business_value() -> None:
    assert extract_unloading_time("{invalid", loading_time=None) is None
    assert (
        extract_unloading_time(
            json.dumps({"status": "error", "fields": {}, "text_lines": []}),
            loading_time=None,
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
    assert extract_loading_time(field_payload) == datetime(
        2026, 8, 13, 13, 59, 58, tzinfo=SHANGHAI
    )

    assert extract_loading_time(
        _output(lines=("过 磅 时 间", "2026-08-13 14:06:07")),
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
        )
        is None
    )


def test_loading_time_only_is_not_completed_without_an_ocr_date() -> None:
    assert (
        extract_loading_time(
            _output(lines=("过磅时间", "14:06:07")),
        )
        is None
    )


def test_loading_time_rejects_conflicting_qualified_candidates() -> None:
    assert (
        extract_loading_time(
            _output(
                lines=(
                    "过磅时间 2026-08-13 14:06:07",
                    "装车时间 2026-08-13 14:16:07",
                )
            ),
        )
        is None
    )


def test_loading_time_accepts_unique_datetime_from_standard_ticket_layout() -> None:
    assert extract_loading_time(
        _output(
            standard_loading_ticket=True,
            lines=(
                "毛重 48.50",
                "皮重 15.92",
                "净重 32.58",
                "时间",
                "2026-08-15 21:44:56",
            ),
        )
    ) == datetime(2026, 8, 15, 21, 44, 56, tzinfo=SHANGHAI)


def test_loading_time_accepts_ocr_semicolon_as_second_separator() -> None:
    assert extract_loading_time(
        _output(
            standard_loading_ticket=True,
            lines=(
                "毛重 48.50",
                "皮重 15.92",
                "净重 32.58",
                "过磅时间 2026-08-16 07:48;39",
            ),
        )
    ) == datetime(2026, 8, 16, 7, 48, 39, tzinfo=SHANGHAI)


def test_loading_time_rejects_unlabeled_datetime_on_nonstandard_ticket() -> None:
    assert (
        extract_loading_time(
            _output(lines=("时间", "2026-08-16 10:17:35")),
        )
        is None
    )


def test_loading_time_rejects_conflicting_datetimes_on_standard_ticket() -> None:
    assert (
        extract_loading_time(
            _output(
                standard_loading_ticket=True,
                lines=(
                    "2026-08-15 21:44:56",
                    "2026-08-15 21:45:56",
                ),
            )
        )
        is None
    )


def test_labeled_loading_time_wins_over_camera_overlay_on_standard_ticket() -> None:
    assert extract_loading_time(
        _output(
            standard_loading_ticket=True,
            lines=(
                "过磅时间",
                "2026-08-16 12:02:41",
                "2026-08-16 12:04:25",
            ),
        )
    ) == datetime(2026, 8, 16, 12, 2, 41, tzinfo=SHANGHAI)


def test_unloading_time_only_is_not_completed_without_loading_time() -> None:
    assert (
        extract_unloading_time(
            _output(lines=("皮重时间", "19:33:24")),
            loading_time=None,
        )
        is None
    )


def test_unloading_time_rejects_conflicting_qualified_candidates() -> None:
    assert (
        extract_unloading_time(
            _output(
                lines=(
                    "皮重时间 2026-08-13 19:33:24",
                    "回皮时间 2026-08-13 19:43:24",
                )
            ),
            loading_time=None,
        )
        is None
    )
