from __future__ import annotations

import json
from datetime import datetime

import pytest

from dahe.adapters.chengfeng.daily_payload import (
    DailyPayloadError,
    collect_daily_waybill_pages,
    decode_daily_waybill_page,
)
from dahe.domain.daily.calendar import SHANGHAI


def _bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def _page(
    *,
    total: int,
    rows: list[dict[str, object]],
    page_number: int = 1,
    page_size: int = 100,
):
    return decode_daily_waybill_page(
        _bytes({"code": 200, "success": True, "data": {"total": total, "list": rows}}),
        expected_page_number=page_number,
        requested_page_size=page_size,
    )


def test_daily_payload_emits_only_four_normalized_business_fields() -> None:
    page = _page(
        total=2,
        rows=[
            {
                "id": 900000001,
                "orderItemSn": "YD20260729000000000001",
                "carNumber": "陕A00000",
                "originalDate": "2026-07-29 13:59:58",
                "driverPhone": "must not propagate",
            },
            {
                "id": "670112229",
                "orderItemSn": "YD20260729000000000002",
                "carNumber": "",
                "originalDate": None,
            },
        ],
    )

    first, second = page.items
    assert first.platform_waybill_id == "900000001"
    assert first.waybill_number == "YD20260729000000000001"
    assert first.vehicle_number == "陕A00000"
    assert first.platform_loading_time == datetime(
        2026,
        7,
        29,
        13,
        59,
        58,
        tzinfo=SHANGHAI,
    )
    assert second.vehicle_number is None
    assert second.platform_loading_time is None
    assert "driverPhone" not in repr(page)
    assert "must not propagate" not in repr(page)


@pytest.mark.parametrize(
    "body",
    [
        {"data": {"total": 1, "list": []}},
        {
            "data": {
                "total": 0,
                "list": [
                    {
                        "id": "1",
                        "orderItemSn": "YD-1",
                        "carNumber": "",
                        "originalDate": None,
                    }
                ],
            }
        },
        {
            "data": {
                "total": 2,
                "list": [
                    {
                        "id": "1",
                        "orderItemSn": "YD-1",
                        "carNumber": "",
                        "originalDate": None,
                    },
                    {
                        "id": "1",
                        "orderItemSn": "YD-2",
                        "carNumber": "",
                        "originalDate": None,
                    },
                ],
            }
        },
        {
            "data": {
                "total": 2,
                "list": [
                    {
                        "id": "1",
                        "orderItemSn": "YD-1",
                        "carNumber": "",
                        "originalDate": None,
                    },
                    {
                        "id": "2",
                        "orderItemSn": "YD-1",
                        "carNumber": "",
                        "originalDate": None,
                    },
                ],
            }
        },
    ],
)
def test_daily_payload_rejects_count_and_identity_ambiguity(
    body: dict[str, object],
) -> None:
    with pytest.raises(DailyPayloadError):
        decode_daily_waybill_page(
            _bytes(body),
            expected_page_number=1,
            requested_page_size=100,
        )


@pytest.mark.parametrize(
    "value",
    [
        "2026/07/29 13:59:58",
        "2026-07-29T13:59:58Z",
        "2026-02-30 13:59:58",
        20260729135958,
    ],
)
def test_daily_payload_rejects_ambiguous_loading_time(value: object) -> None:
    with pytest.raises(DailyPayloadError):
        _page(
            total=1,
            rows=[
                {
                    "id": "1",
                    "orderItemSn": "YD-1",
                    "carNumber": "",
                    "originalDate": value,
                }
            ],
        )


def test_daily_page_collection_requires_stable_total_order_and_exact_coverage() -> None:
    first = _page(
        total=3,
        page_number=1,
        page_size=2,
        rows=[
            {
                "id": "1",
                "orderItemSn": "YD-1",
                "carNumber": "",
                "originalDate": None,
            },
            {
                "id": "2",
                "orderItemSn": "YD-2",
                "carNumber": "",
                "originalDate": None,
            },
        ],
    )
    second = _page(
        total=3,
        page_number=2,
        page_size=2,
        rows=[
            {
                "id": "3",
                "orderItemSn": "YD-3",
                "carNumber": "",
                "originalDate": None,
            }
        ],
    )

    assert tuple(item.waybill_number for item in collect_daily_waybill_pages((first, second))) == (
        "YD-1",
        "YD-2",
        "YD-3",
    )

    with pytest.raises(DailyPayloadError):
        collect_daily_waybill_pages((second, first))
    with pytest.raises(DailyPayloadError):
        collect_daily_waybill_pages((first,))
    with pytest.raises(DailyPayloadError):
        collect_daily_waybill_pages((first, first))
