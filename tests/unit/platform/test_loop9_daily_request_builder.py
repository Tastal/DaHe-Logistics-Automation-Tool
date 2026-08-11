from __future__ import annotations

from datetime import date, datetime

import pytest

from dahe.adapters.chengfeng.daily_request_builder import (
    ChengfengDailyRequestBuilder,
    DailyRequestBuilderError,
)
from dahe.domain.daily.calendar import candidate_query_window
from tests.unit.platform.test_loop9_daily_manifest import daily_manifest


def test_daily_request_is_derived_from_frozen_query_window_and_empty_baseline() -> None:
    request = ChengfengDailyRequestBuilder(daily_manifest()).list_waybills(
        query_window=candidate_query_window(
            date(2026, 7, 28),
            now=datetime.fromisoformat("2026-07-28T20:15:00+08:00"),
        ),
        receive_place="榆林",
        page_number=2,
        page_size=100,
    )

    assert request.operation == "list_daily_waybills"
    assert request.method == "POST"
    assert request.url == (
        "https://pc.chengfengkuaiyun.com/api/hz/orderItem/queryOrderItemListPC"
    )
    assert request.parameters_location == "json"
    assert dict(request.parameters) == {
        "carNumber": "",
        "filterParamList": (),
        "loadEndTime": "2026-07-28 20:15:00",
        "loadStartTime": "2026-07-28 14:00:00",
        "pageNumber": 2,
        "pageSize": 100,
        "receivePlace": "榆林",
        "remarks": None,
    }

    with pytest.raises(TypeError):
        request.parameters["carNumber"] = "changed"  # type: ignore[index]


@pytest.mark.parametrize(
    ("query_window", "receive_place", "page_number", "page_size"),
    [
        (datetime(2026, 7, 28, 0, 0), "榆林", 1, 100),
        (
            candidate_query_window(
                date(2026, 7, 28),
                now=datetime.fromisoformat("2026-07-28T20:15:00+08:00"),
            ),
            "",
            1,
            100,
        ),
        (
            candidate_query_window(
                date(2026, 7, 28),
                now=datetime.fromisoformat("2026-07-28T20:15:00+08:00"),
            ),
            " 榆林",
            1,
            100,
        ),
        (
            candidate_query_window(
                date(2026, 7, 28),
                now=datetime.fromisoformat("2026-07-28T20:15:00+08:00"),
            ),
            "https://example.invalid",
            1,
            100,
        ),
        (
            candidate_query_window(
                date(2026, 7, 28),
                now=datetime.fromisoformat("2026-07-28T20:15:00+08:00"),
            ),
            "榆林",
            0,
            100,
        ),
        (
            candidate_query_window(
                date(2026, 7, 28),
                now=datetime.fromisoformat("2026-07-28T20:15:00+08:00"),
            ),
            "榆林",
            1,
            0,
        ),
        (
            candidate_query_window(
                date(2026, 7, 28),
                now=datetime.fromisoformat("2026-07-28T20:15:00+08:00"),
            ),
            "榆林",
            1,
            101,
        ),
    ],
)
def test_daily_request_rejects_untrusted_or_unbounded_inputs(
    query_window: object,
    receive_place: str,
    page_number: int,
    page_size: int,
) -> None:
    with pytest.raises(DailyRequestBuilderError):
        ChengfengDailyRequestBuilder(daily_manifest()).list_waybills(
            query_window=query_window,  # type: ignore[arg-type]
            receive_place=receive_place,
            page_number=page_number,
            page_size=page_size,
        )
