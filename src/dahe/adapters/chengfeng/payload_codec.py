from __future__ import annotations

import json
from collections.abc import Mapping

from dahe.ports.chengfeng import (
    TicketReference,
    WaybillDetail,
    WaybillPage,
    WaybillSummary,
)


class ConnectorPayloadError(ValueError):
    """A verified connector payload does not match the typed read contract."""


def encode_waybill_page(page: WaybillPage) -> bytes:
    return _encode_json(
        {
            "page_number": page.page_number,
            "page_size": page.page_size,
            "total": page.total,
            "items": [
                {
                    "platform_waybill_id": item.platform_waybill_id,
                    "waybill_number": item.waybill_number,
                    "vehicle_number": item.vehicle_number,
                }
                for item in page.items
            ],
        }
    )


def encode_waybill_detail(detail: WaybillDetail) -> bytes:
    return _encode_json(
        {
            "platform_waybill_id": detail.platform_waybill_id,
            "waybill_number": detail.waybill_number,
            "vehicle_number": detail.vehicle_number,
            "loading_net": detail.loading_net,
            "unloading_net": detail.unloading_net,
            "tickets": [
                {
                    "slot": ticket.slot,
                    "ticket_ref": ticket.ticket_ref,
                    "media_type": ticket.media_type,
                }
                for ticket in detail.tickets
            ],
        }
    )


def decode_waybill_page(content: bytes) -> WaybillPage:
    payload = _decode_object(content)
    _require_exact_fields(
        payload,
        {
            "page_number",
            "page_size",
            "total",
            "items",
        },
        path="waybill_page",
    )
    raw_items = payload["items"]
    if not isinstance(raw_items, list):
        raise ConnectorPayloadError("waybill_page.items must be an array")
    items: list[WaybillSummary] = []
    for index, raw_item in enumerate(raw_items):
        item = _require_object(raw_item, path=f"waybill_page.items[{index}]")
        _require_exact_fields(
            item,
            {"platform_waybill_id", "waybill_number", "vehicle_number"},
            path=f"waybill_page.items[{index}]",
        )
        items.append(
            WaybillSummary(
                platform_waybill_id=_require_string(
                    item["platform_waybill_id"],
                    path=f"waybill_page.items[{index}].platform_waybill_id",
                ),
                waybill_number=_require_string(
                    item["waybill_number"],
                    path=f"waybill_page.items[{index}].waybill_number",
                ),
                vehicle_number=_require_optional_string(
                    item["vehicle_number"],
                    path=f"waybill_page.items[{index}].vehicle_number",
                ),
            )
        )
    return WaybillPage(
        page_number=_require_non_negative_integer(
            payload["page_number"],
            path="waybill_page.page_number",
            allow_zero=False,
        ),
        page_size=_require_non_negative_integer(
            payload["page_size"],
            path="waybill_page.page_size",
            allow_zero=False,
        ),
        total=_require_non_negative_integer(
            payload["total"],
            path="waybill_page.total",
            allow_zero=True,
        ),
        items=tuple(items),
    )


def decode_waybill_detail(content: bytes) -> WaybillDetail:
    payload = _decode_object(content)
    _require_exact_fields(
        payload,
        {
            "platform_waybill_id",
            "waybill_number",
            "vehicle_number",
            "loading_net",
            "unloading_net",
            "tickets",
        },
        path="waybill_detail",
    )
    raw_tickets = payload["tickets"]
    if not isinstance(raw_tickets, list):
        raise ConnectorPayloadError("waybill_detail.tickets must be an array")
    tickets: list[TicketReference] = []
    for index, raw_ticket in enumerate(raw_tickets):
        ticket = _require_object(raw_ticket, path=f"waybill_detail.tickets[{index}]")
        _require_exact_fields(
            ticket,
            {"slot", "ticket_ref", "media_type"},
            path=f"waybill_detail.tickets[{index}]",
        )
        tickets.append(
            TicketReference(
                slot=_require_string(
                    ticket["slot"],
                    path=f"waybill_detail.tickets[{index}].slot",
                ),
                ticket_ref=_require_string(
                    ticket["ticket_ref"],
                    path=f"waybill_detail.tickets[{index}].ticket_ref",
                ),
                media_type=_require_string(
                    ticket["media_type"],
                    path=f"waybill_detail.tickets[{index}].media_type",
                ),
            )
        )
    return WaybillDetail(
        platform_waybill_id=_require_string(
            payload["platform_waybill_id"],
            path="waybill_detail.platform_waybill_id",
        ),
        waybill_number=_require_string(
            payload["waybill_number"],
            path="waybill_detail.waybill_number",
        ),
        vehicle_number=_require_optional_string(
            payload["vehicle_number"],
            path="waybill_detail.vehicle_number",
        ),
        loading_net=_require_optional_string(
            payload["loading_net"],
            path="waybill_detail.loading_net",
        ),
        unloading_net=_require_optional_string(
            payload["unloading_net"],
            path="waybill_detail.unloading_net",
        ),
        tickets=tuple(tickets),
    )


def _encode_json(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _decode_object(content: bytes) -> dict[str, object]:
    try:
        payload = json.loads(content.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConnectorPayloadError("connector payload must be valid UTF-8 JSON") from error
    return _require_object(payload, path="connector_payload")


def _require_object(value: object, *, path: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ConnectorPayloadError(f"{path} must be an object with string keys")
    return value


def _require_exact_fields(
    value: Mapping[str, object],
    expected: set[str],
    *,
    path: str,
) -> None:
    actual = set(value)
    if actual != expected:
        raise ConnectorPayloadError(f"{path} fields do not match the connector schema")


def _require_string(value: object, *, path: str) -> str:
    if not isinstance(value, str) or not value:
        raise ConnectorPayloadError(f"{path} must be a non-empty string")
    return value


def _require_optional_string(value: object, *, path: str) -> str | None:
    if value is None:
        return None
    return _require_string(value, path=path)


def _require_non_negative_integer(
    value: object,
    *,
    path: str,
    allow_zero: bool,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConnectorPayloadError(f"{path} must be an integer")
    minimum = 0 if allow_zero else 1
    if value < minimum:
        raise ConnectorPayloadError(f"{path} is below its allowed minimum")
    return value
