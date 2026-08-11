from __future__ import annotations

import json

import pytest

from dahe.adapters.chengfeng.live_payload import (
    LivePayloadError,
    decode_live_settled_waybill_page,
    decode_live_waybill_detail,
    decode_live_waybill_page,
)


def _bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False).encode("utf-8")


def test_live_list_decoder_emits_only_the_normalized_business_page() -> None:
    page = decode_live_waybill_page(
        _bytes(
            {
                "code": 200,
                "data": {
                    "pageNo": 1,
                    "pageSize": 30,
                    "total": 2,
                    "list": [
                        {
                            "id": "900000001",
                            "orderItemSn": "WB-001",
                            "carNumber": "TEST-01",
                            "unrelated": "not propagated",
                        },
                        {
                            "id": "670112229",
                            "orderItemSn": "WB-002",
                            "carNumber": "",
                        },
                    ],
                },
            }
        ),
        expected_page_number=1,
        maximum_page_size=30,
    )

    assert page.total == 2
    assert page.items[0].platform_waybill_id == "900000001"
    assert page.items[0].vehicle_number == "TEST-01"
    assert page.items[1].vehicle_number is None
    assert "unrelated" not in repr(page)


def test_live_list_repairs_latin1_decoded_gbk_vehicle_number() -> None:
    page = decode_live_waybill_page(
        _bytes(
            {
                "data": {
                    "pageNo": 1,
                    "pageSize": 30,
                    "total": 1,
                    "list": [
                        {
                            "id": "900000001",
                            "orderItemSn": "YD-001",
                            "carNumber": "\u00c9\u00c2KK5743",
                        }
                    ],
                }
            }
        ),
        expected_page_number=1,
        maximum_page_size=30,
    )

    assert page.items[0].vehicle_number == "\u9655KK5743"


@pytest.mark.parametrize(
    "data",
    [
        {"pageNo": 2, "pageSize": 30, "total": 0, "list": []},
        {"pageNo": 1, "pageSize": 31, "total": 0, "list": []},
        {
            "pageNo": 1,
            "pageSize": 30,
            "total": 1,
            "list": [
                {"id": "one", "orderItemSn": "WB-1", "carNumber": ""},
                {"id": "two", "orderItemSn": "WB-2", "carNumber": ""},
            ],
        },
        {
            "pageNo": 1,
            "pageSize": 30,
            "total": 2,
            "list": [
                {"id": "one", "orderItemSn": "WB-1", "carNumber": ""},
                {"id": "one", "orderItemSn": "WB-1", "carNumber": ""},
            ],
        },
    ],
)
def test_live_list_decoder_rejects_pagination_and_count_mismatches(
    data: dict[str, object],
) -> None:
    with pytest.raises(LivePayloadError):
        decode_live_waybill_page(
            _bytes({"data": data}),
            expected_page_number=1,
            maximum_page_size=30,
        )


def test_live_list_normalizes_zero_based_platform_page_number() -> None:
    page = decode_live_waybill_page(
        _bytes(
            {
                "data": {
                    "pageNo": 0,
                    "pageSize": 20,
                    "total": 0,
                    "list": [],
                }
            }
        ),
        expected_page_number=1,
        maximum_page_size=20,
    )

    assert page.page_number == 1
    assert page.page_size == 20


def test_live_list_normalizes_zero_platform_page_size_to_request_limit() -> None:
    page = decode_live_waybill_page(
        _bytes(
            {
                "data": {
                    "pageNo": 0,
                    "pageSize": 0,
                    "total": 1,
                    "list": [
                        {
                            "id": "one",
                            "orderItemSn": "WB-1",
                            "carNumber": "",
                        }
                    ],
                }
            }
        ),
        expected_page_number=1,
        maximum_page_size=20,
    )

    assert page.page_number == 1
    assert page.page_size == 20
    assert len(page.items) == 1


@pytest.mark.parametrize("expected_page_number", [1, 2])
def test_live_list_normalizes_platform_reversed_request_pagination(
    expected_page_number: int,
) -> None:
    page = decode_live_waybill_page(
        _bytes(
            {
                "data": {
                    "pageNo": 30,
                    "pageSize": expected_page_number,
                    "total": 32,
                    "list": [
                        {
                            "id": f"id-{expected_page_number}-1",
                            "orderItemSn": f"WB-{expected_page_number}-1",
                            "carNumber": "",
                        },
                        {
                            "id": f"id-{expected_page_number}-2",
                            "orderItemSn": f"WB-{expected_page_number}-2",
                            "carNumber": "",
                        },
                    ],
                }
            }
        ),
        expected_page_number=expected_page_number,
        maximum_page_size=30,
    )

    assert page.page_number == expected_page_number
    assert page.page_size == 30
    assert len(page.items) == 2


def test_live_list_normalizes_reversed_pagination_on_partial_last_page() -> None:
    page = decode_live_waybill_page(
        _bytes(
            {
                "data": {
                    "pageNo": 50,
                    "pageSize": 7,
                    "total": 315,
                    "list": [
                        {
                            "id": f"id-7-{index}",
                            "orderItemSn": f"WB-7-{index}",
                            "carNumber": "",
                        }
                        for index in range(15)
                    ],
                }
            }
        ),
        expected_page_number=7,
        maximum_page_size=50,
    )

    assert page.page_number == 7
    assert page.page_size == 50
    assert page.total == 315
    assert len(page.items) == 15


def test_historical_list_decoder_uses_string_total_and_order_item_identity() -> None:
    page = decode_live_settled_waybill_page(
        _bytes(
            {
                "data": {
                    "total": "2",
                    "list": [
                        {
                            "orderItemId": "670112228",
                            "orderItemSn": "YD-001",
                            "carNumber": "陕A00001",
                            "unrelated": "not propagated",
                        },
                        {
                            "orderItemId": "670112229",
                            "orderItemSn": "YD-002",
                            "carNumber": "",
                        },
                    ],
                }
            }
        ),
        expected_page_number=2,
        maximum_page_size=100,
    )

    assert page.page_number == 2
    assert page.page_size == 100
    assert page.total == 2
    assert page.items[0].platform_waybill_id == "670112228"
    assert page.items[0].waybill_number == "YD-001"
    assert page.items[0].vehicle_number == "陕A00001"
    assert page.items[1].vehicle_number is None
    assert "unrelated" not in repr(page)


@pytest.mark.parametrize(
    "data",
    [
        {"total": 1, "list": []},
        {"total": "-1", "list": []},
        {"total": "01", "list": []},
        {"total": "not-a-number", "list": []},
        {
            "total": "1",
            "list": [
                {
                    "orderItemId": "one",
                    "orderItemSn": "YD-1",
                    "carNumber": "",
                },
                {
                    "orderItemId": "two",
                    "orderItemSn": "YD-2",
                    "carNumber": "",
                },
            ],
        },
        {
            "total": "2",
            "list": [
                {
                    "orderItemId": "one",
                    "orderItemSn": "YD-1",
                    "carNumber": "",
                },
                {
                    "orderItemId": "one",
                    "orderItemSn": "YD-1",
                    "carNumber": "",
                },
            ],
        },
        {
            "total": "1",
            "list": [
                {
                    "orderItemSn": "YD-1",
                    "carNumber": "",
                }
            ],
        },
    ],
)
def test_historical_list_decoder_fails_closed_on_shape_or_count_changes(
    data: dict[str, object],
) -> None:
    with pytest.raises(LivePayloadError):
        decode_live_settled_waybill_page(
            _bytes({"data": data}),
            expected_page_number=1,
            maximum_page_size=100,
        )


@pytest.mark.parametrize(
    "payload,expected_code",
    [
        (
            {"data": None},
            "data_object_expected_null_status_missing",
        ),
        (
            {"code": 401, "message": "must never be logged", "data": None},
            "data_object_expected_null_status_auth",
        ),
    ],
)
def test_live_list_decoder_reports_only_safe_shape_and_status_category(
    payload: dict[str, object],
    expected_code: str,
) -> None:
    with pytest.raises(LivePayloadError) as captured:
        decode_live_waybill_page(
            _bytes(payload),
            expected_page_number=1,
            maximum_page_size=30,
        )

    assert captured.value.code == expected_code
    assert "None" not in str(captured.value)
    assert "must never be logged" not in captured.value.code


def test_live_detail_decoder_replaces_signed_urls_with_opaque_references() -> None:
    seen: list[tuple[str, str]] = []

    def register(slot: str, url: str) -> str:
        seen.append((slot, url))
        return f"ticket-{slot}"

    detail = decode_live_waybill_detail(
        _bytes(
            {
                "data": [
                    {
                        "id": "900000001",
                        "sn": "WB-001",
                        "carNumber": "TEST-01",
                        "originalTon": "33.08",
                        "currentTon": "33.04",
                        "originalTonImageUrl": (
                            "https://images.example.invalid/loading.jpg"
                            "?Signature=secret-one"
                        ),
                        "image": (
                            "https://images.example.invalid/unloading.jpg"
                            "?Signature=secret-two"
                        ),
                        "unrelated": "not propagated",
                    }
                ]
            }
        ),
        expected_platform_waybill_id="900000001",
        ticket_reference=register,
    )

    assert detail.loading_net == "33.08"
    assert detail.unloading_net == "33.04"
    assert tuple(ticket.ticket_ref for ticket in detail.tickets) == (
        "ticket-loading",
        "ticket-unloading",
    )
    assert len(seen) == 2
    assert "Signature" not in repr(detail)
    assert "secret-one" not in repr(detail)


def test_live_detail_decoder_rejects_identity_change_and_multiple_rows() -> None:
    for payload in (
        {"data": []},
        {
            "data": [
                {
                    "id": "other",
                    "sn": "WB-001",
                    "carNumber": "",
                    "originalTon": "1",
                    "currentTon": "1",
                    "originalTonImageUrl": "",
                    "image": "",
                }
            ]
        },
    ):
        with pytest.raises(LivePayloadError):
            decode_live_waybill_detail(
                _bytes(payload),
                expected_platform_waybill_id="900000001",
                ticket_reference=lambda slot, url: f"{slot}-{len(url)}",
            )
