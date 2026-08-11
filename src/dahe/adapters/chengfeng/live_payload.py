from __future__ import annotations

import json
from collections.abc import Callable, Mapping

from dahe.ports.chengfeng import (
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)

from .vehicle_number import normalize_chengfeng_vehicle_number


class LivePayloadError(ValueError):
    """Raised when a real Chengfeng response no longer matches the frozen shape."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def decode_live_waybill_page(
    content: bytes,
    *,
    expected_page_number: int,
    maximum_page_size: int,
) -> WaybillPage:
    payload = _object(_json(content), path="$")
    data = _object(
        payload.get("data"),
        path="$.data",
        status_category=_wrapper_status_category(payload),
    )
    response_page_number = _non_negative_integer(
        data.get("pageNo"),
        path="$.data.pageNo",
    )
    response_page_size = _non_negative_integer(
        data.get("pageSize"),
        path="$.data.pageSize",
    )
    raw_items = data.get("list")
    reversed_request_pagination = (
        isinstance(raw_items, list)
        and bool(raw_items)
        and response_page_number == maximum_page_size
        and response_page_size == expected_page_number
    )
    page_size = (
        maximum_page_size
        if response_page_size == 0 or reversed_request_pagination
        else response_page_size
    )
    total = _non_negative_integer(data.get("total"), path="$.data.total")
    accepted_response_pages = {
        expected_page_number,
        expected_page_number - 1,
    }
    if reversed_request_pagination:
        accepted_response_pages.add(maximum_page_size)
    if (
        response_page_number not in accepted_response_pages
        or page_size > maximum_page_size
    ):
        raise LivePayloadError(
            "pagination_mismatch",
            "list response pagination does not match the request",
        )
    if not isinstance(raw_items, list):
        raise LivePayloadError("list_not_array", "$.data.list must be an array")
    items: list[WaybillSummary] = []
    identities: set[tuple[str, str]] = set()
    for index, raw_item in enumerate(raw_items):
        item = _object(raw_item, path=f"$.data.list[{index}]")
        platform_id = _non_empty_string(
            item.get("id"),
            path=f"$.data.list[{index}].id",
        )
        waybill_number = _non_empty_string(
            item.get("orderItemSn"),
            path=f"$.data.list[{index}].orderItemSn",
        )
        identity = platform_id, waybill_number
        if identity in identities:
            raise LivePayloadError(
                "duplicate_waybill",
                "list response contains a duplicate waybill",
            )
        identities.add(identity)
        items.append(
            WaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=_vehicle_number(
                    item.get("carNumber"), path=f"$.data.list[{index}].carNumber"
                ),
            )
        )
    if len(items) > page_size or (total == 0 and items) or total < len(items):
        raise LivePayloadError(
            "list_counts_inconsistent",
            "list response counts are inconsistent",
        )
    return WaybillPage(
        page_number=expected_page_number,
        page_size=page_size,
        total=total,
        items=tuple(items),
    )


def decode_live_settled_waybill_page(
    content: bytes,
    *,
    expected_page_number: int,
    maximum_page_size: int,
) -> WaybillPage:
    """Decode the distinct historical-settlement response without guessing."""

    if (
        type(expected_page_number) is not int
        or expected_page_number < 1
        or type(maximum_page_size) is not int
        or not 1 <= maximum_page_size <= 100
    ):
        raise LivePayloadError(
            "pagination_mismatch",
            "historical list request pagination is invalid",
        )
    payload = _object(_json(content), path="$")
    data = _object(
        payload.get("data"),
        path="$.data",
        status_category=_wrapper_status_category(payload),
    )
    total = _canonical_non_negative_integer_string(
        data.get("total"),
        path="$.data.total",
        maximum=10_000_000,
    )
    raw_items = data.get("list")
    if not isinstance(raw_items, list):
        raise LivePayloadError("list_not_array", "$.data.list must be an array")
    items: list[WaybillSummary] = []
    identities: set[tuple[str, str]] = set()
    for index, raw_item in enumerate(raw_items):
        item = _object(raw_item, path=f"$.data.list[{index}]")
        platform_id = _non_empty_string(
            item.get("orderItemId"),
            path=f"$.data.list[{index}].orderItemId",
        )
        waybill_number = _non_empty_string(
            item.get("orderItemSn"),
            path=f"$.data.list[{index}].orderItemSn",
        )
        identity = platform_id, waybill_number
        if identity in identities:
            raise LivePayloadError(
                "duplicate_waybill",
                "historical list response contains a duplicate waybill",
            )
        identities.add(identity)
        items.append(
            WaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=_vehicle_number(
                    item.get("carNumber"), path=f"$.data.list[{index}].carNumber"
                ),
            )
        )
    if (
        len(items) > maximum_page_size
        or total < len(items)
        or (total == 0 and items)
    ):
        raise LivePayloadError(
            "list_counts_inconsistent",
            "historical list response counts are inconsistent",
        )
    return WaybillPage(
        page_number=expected_page_number,
        page_size=maximum_page_size,
        total=total,
        items=tuple(items),
    )


def decode_live_waybill_detail(
    content: bytes,
    *,
    expected_platform_waybill_id: str,
    ticket_reference: Callable[[str, str], str],
) -> WaybillDetail:
    payload = _object(_json(content), path="$")
    raw_data = payload.get("data")
    if not isinstance(raw_data, list) or len(raw_data) != 1:
        raise LivePayloadError(
            "detail_cardinality_invalid",
            "$.data must contain exactly one detail object",
        )
    detail = _object(raw_data[0], path="$.data[0]")
    platform_id = _non_empty_string(detail.get("id"), path="$.data[0].id")
    if platform_id != expected_platform_waybill_id:
        raise LivePayloadError(
            "detail_identity_mismatch",
            "detail response identity does not match the request",
        )
    waybill_number = _non_empty_string(detail.get("sn"), path="$.data[0].sn")
    tickets: list[TicketReference] = []
    for slot, field_name in (
        ("loading", "originalTonImageUrl"),
        ("unloading", "image"),
    ):
        image_url = _optional_string(
            detail.get(field_name),
            path=f"$.data[0].{field_name}",
        )
        if image_url is None:
            continue
        reference = ticket_reference(slot, image_url)
        if not reference:
            raise LivePayloadError(
                "ticket_reference_empty",
                "ticket reference factory returned an empty identity",
            )
        tickets.append(
            TicketReference(
                slot=slot,
                ticket_ref=reference,
                media_type="application/octet-stream",
            )
        )
    return WaybillDetail(
        platform_waybill_id=platform_id,
        waybill_number=waybill_number,
        vehicle_number=_vehicle_number(
            detail.get("carNumber"), path="$.data[0].carNumber"
        ),
        loading_net=_optional_string(
            detail.get("originalTon"),
            path="$.data[0].originalTon",
        ),
        unloading_net=_optional_string(
            detail.get("currentTon"),
            path="$.data[0].currentTon",
        ),
        tickets=tuple(tickets),
    )


def _json(content: bytes) -> object:
    if not content or len(content) > 2 * 1024 * 1024:
        raise LivePayloadError(
            "response_size_invalid",
            "live response size is invalid",
        )
    try:
        return json.loads(content.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LivePayloadError(
            "response_json_invalid",
            "live response must be UTF-8 JSON",
        ) from exc


def _vehicle_number(value: object, *, path: str) -> str | None:
    normalized = _optional_string(value, path=path)
    return (
        None
        if normalized is None
        else normalize_chengfeng_vehicle_number(normalized)
    )


def _object(
    value: object,
    *,
    path: str,
    status_category: str | None = None,
) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        if path == "$":
            location = "root"
        elif path == "$.data":
            location = "data"
        elif path.startswith("$.data.list["):
            location = "list_item"
        elif path == "$.data[0]":
            location = "detail_item"
        else:
            location = "nested"
        status_suffix = (
            f"_status_{status_category}"
            if path == "$.data" and status_category is not None
            else ""
        )
        raise LivePayloadError(
            (
                f"{location}_object_expected_{_value_kind(value)}"
                f"{status_suffix}"
            ),
            f"{path} must be an object",
        )
    return value


def _value_kind(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, list):
        return "array"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    return "unsupported"


def _wrapper_status_category(payload: Mapping[str, object]) -> str:
    marker: object | None = None
    for name in ("code", "status", "statusCode", "success"):
        if name in payload:
            marker = payload[name]
            break
    if marker is None:
        return "missing"
    if isinstance(marker, bool):
        return "success" if marker else "failure"
    if isinstance(marker, (int, str)) and marker in {
        0,
        200,
        "0",
        "200",
        "00000",
    }:
        return "success"
    normalized = marker.casefold() if isinstance(marker, str) else marker
    if isinstance(normalized, (int, str)) and normalized in {
        401,
        403,
        "401",
        "403",
        "unauthorized",
        "forbidden",
    }:
        return "auth"
    if isinstance(marker, int) and not isinstance(marker, bool):
        if 400 <= marker < 500:
            return "client_error"
        if marker >= 500:
            return "server_error"
    return "other"


def _non_empty_string(value: object, *, path: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise LivePayloadError(
            "non_empty_string_expected",
            f"{path} must be a non-empty string",
        )
    return value


def _optional_string(value: object, *, path: str) -> str | None:
    if value is None or value == "":
        return None
    return _non_empty_string(value, path=path)


def _non_negative_integer(value: object, *, path: str) -> int:
    if type(value) is not int or value < 0:
        raise LivePayloadError(
            "non_negative_integer_expected",
            f"{path} must be a non-negative integer",
        )
    return value


def _canonical_non_negative_integer_string(
    value: object,
    *,
    path: str,
    maximum: int,
) -> int:
    if (
        type(value) is not str
        or not value
        or not value.isascii()
        or not value.isdigit()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise LivePayloadError(
            "non_negative_integer_string_expected",
            f"{path} must be a canonical non-negative integer string",
        )
    result = int(value)
    if result > maximum:
        raise LivePayloadError(
            "non_negative_integer_string_expected",
            f"{path} exceeds the allowed maximum",
        )
    return result
