from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import TypedDict

from dahe.domain.daily.calendar import SHANGHAI
from dahe.ports.daily import DailyWaybillPage, DailyWaybillSummary

from .vehicle_number import normalize_chengfeng_vehicle_number


class DailyPayloadError(ValueError):
    """Raised when a daily list response is incomplete or ambiguous."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class _DailyScopeEvidence(TypedDict):
    platform_display_total: int | None
    response_total: int
    response_page_count: int
    query_scope_sha256: str | None
    scope_complete: bool
    scope_diagnostic_code: str | None


def decode_daily_waybill_page(
    content: bytes,
    *,
    expected_page_number: int,
    requested_page_size: int,
) -> DailyWaybillPage:
    if (
        type(expected_page_number) is not int
        or not 1 <= expected_page_number <= 10_000
        or type(requested_page_size) is not int
        or not 1 <= requested_page_size <= 100
    ):
        raise DailyPayloadError(
            "request_pagination_invalid",
            "requested pagination is outside the daily contract",
        )
    payload = _object(_json(content), path="$")
    _validate_wrapper(payload)
    data = _object(payload.get("data"), path="$.data")
    total = _non_negative_integer(data.get("total"), path="$.data.total")
    raw_items = data.get("list")
    if not isinstance(raw_items, list):
        raise DailyPayloadError("list_not_array", "$.data.list must be an array")
    if len(raw_items) > requested_page_size:
        raise DailyPayloadError(
            "page_size_exceeded",
            "daily response contains more rows than requested",
        )

    items: list[DailyWaybillSummary] = []
    platform_ids: set[str] = set()
    waybill_numbers: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        path = f"$.data.list[{index}]"
        item = _object(raw_item, path=path)
        platform_id = _platform_identity(item.get("id"), path=f"{path}.id")
        waybill_number = _non_empty_string(
            item.get("orderItemSn"),
            path=f"{path}.orderItemSn",
        )
        if platform_id in platform_ids or waybill_number in waybill_numbers:
            raise DailyPayloadError(
                "duplicate_waybill_identity",
                "daily response contains an ambiguous waybill identity",
            )
        platform_ids.add(platform_id)
        waybill_numbers.add(waybill_number)
        items.append(
            DailyWaybillSummary(
                platform_waybill_id=platform_id,
                waybill_number=waybill_number,
                vehicle_number=_vehicle_number(
                    item.get("carNumber"), path=f"{path}.carNumber"
                ),
                platform_loading_time=_optional_loading_time(
                    item.get("originalDate"),
                    path=f"{path}.originalDate",
                ),
            )
        )

    if total < len(items) or (total == 0 and items) or (total > 0 and not items):
        raise DailyPayloadError(
            "list_counts_inconsistent",
            "daily list count and rows are inconsistent",
        )
    scope = _daily_scope(
        payload,
        response_total=total,
        requested_page_size=requested_page_size,
    )
    return DailyWaybillPage(
        page_number=expected_page_number,
        page_size=requested_page_size,
        total=total,
        items=tuple(items),
        platform_display_total=scope["platform_display_total"],
        response_total=scope["response_total"],
        response_page_count=scope["response_page_count"],
        query_scope_sha256=scope["query_scope_sha256"],
        scope_complete=scope["scope_complete"],
        scope_diagnostic_code=scope["scope_diagnostic_code"],
    )


def collect_daily_waybill_pages(
    pages: Sequence[DailyWaybillPage],
) -> tuple[DailyWaybillSummary, ...]:
    if not pages:
        raise DailyPayloadError(
            "pagination_empty",
            "at least one daily response page is required",
        )
    total = pages[0].total
    page_size = pages[0].page_size
    collected: list[DailyWaybillSummary] = []
    platform_ids: set[str] = set()
    waybill_numbers: set[str] = set()
    for expected_page, page in enumerate(pages, start=1):
        if page.page_number != expected_page or page.page_size != page_size or page.total != total:
            raise DailyPayloadError(
                "pagination_changed",
                "daily pagination changed while collecting the snapshot",
            )
        if expected_page < len(pages) and len(page.items) != page_size:
            raise DailyPayloadError(
                "pagination_gap",
                "a nonfinal daily page is not full",
            )
        for item in page.items:
            if item.platform_waybill_id in platform_ids or item.waybill_number in waybill_numbers:
                raise DailyPayloadError(
                    "pagination_duplicate",
                    "daily pages contain a duplicate waybill identity",
                )
            platform_ids.add(item.platform_waybill_id)
            waybill_numbers.add(item.waybill_number)
            collected.append(item)
    if len(collected) != total:
        raise DailyPayloadError(
            "pagination_incomplete",
            "daily pages do not exactly reconcile to the reported total",
        )
    return tuple(collected)


def _vehicle_number(value: object, *, path: str) -> str | None:
    normalized = _optional_string(value, path=path)
    return (
        None
        if normalized is None
        else normalize_chengfeng_vehicle_number(normalized)
    )


def _json(content: bytes) -> object:
    if not content or len(content) > 2 * 1024 * 1024:
        raise DailyPayloadError("response_size_invalid", "daily response size is invalid")
    try:
        return json.loads(content.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DailyPayloadError(
            "response_json_invalid",
            "daily response must be UTF-8 JSON",
        ) from exc


def _object(value: object, *, path: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise DailyPayloadError("object_expected", f"{path} must be an object")
    return value


def _validate_wrapper(payload: Mapping[str, object]) -> None:
    code = payload.get("code")
    if code is not None and code not in {200, "200"}:
        raise DailyPayloadError(
            "platform_status_failure",
            "daily response reported a failed status",
        )
    success = payload.get("success")
    if success is not None and success is not True:
        raise DailyPayloadError(
            "platform_status_failure",
            "daily response reported a failed status",
        )


def _daily_scope(
    payload: Mapping[str, object],
    *,
    response_total: int,
    requested_page_size: int,
) -> _DailyScopeEvidence:
    """Read sanitized scope evidence produced by the isolated browser worker."""

    raw = payload.get("_dahe_scope")
    if raw is None:
        return {
            "platform_display_total": None,
            "response_total": response_total,
            "response_page_count": max(
                1,
                (response_total + requested_page_size - 1)
                // requested_page_size,
            ),
            "query_scope_sha256": None,
            "scope_complete": True,
            "scope_diagnostic_code": None,
        }
    scope = _object(raw, path="$._dahe_scope")
    allowed = {
        "platform_display_total",
        "response_total",
        "response_page_count",
        "query_scope_sha256",
        "scope_complete",
        "scope_diagnostic_code",
    }
    legacy_allowed = allowed - {"response_page_count"}
    if frozenset(scope) not in {
        frozenset(allowed),
        frozenset(legacy_allowed),
    }:
        raise DailyPayloadError(
            "scope_fields_invalid",
            "$._dahe_scope fields are outside the daily contract",
        )
    platform_display_total = scope.get("platform_display_total")
    if platform_display_total is not None:
        platform_display_total = _non_negative_integer(
            platform_display_total,
            path="$._dahe_scope.platform_display_total",
        )
    normalized_response_total = _non_negative_integer(
        scope.get("response_total"),
        path="$._dahe_scope.response_total",
    )
    if normalized_response_total != response_total:
        raise DailyPayloadError(
            "scope_response_total_changed",
            "daily scope response total does not match the response",
        )
    response_page_count = (
        max(
            1,
            (response_total + requested_page_size - 1)
            // requested_page_size,
        )
        if "response_page_count" not in scope
        else _non_negative_integer(
            scope.get("response_page_count"),
            path="$._dahe_scope.response_page_count",
        )
    )
    if response_page_count < 1:
        raise DailyPayloadError(
            "scope_page_count_invalid",
            "$._dahe_scope.response_page_count must be positive",
        )
    query_scope_sha256 = scope.get("query_scope_sha256")
    if (
        type(query_scope_sha256) is not str
        or re.fullmatch(r"[0-9a-f]{64}", query_scope_sha256) is None
    ):
        raise DailyPayloadError(
            "scope_sha256_invalid",
            "$._dahe_scope.query_scope_sha256 must be one SHA-256 digest",
        )
    scope_complete = scope.get("scope_complete")
    if type(scope_complete) is not bool:
        raise DailyPayloadError(
            "scope_complete_invalid",
            "$._dahe_scope.scope_complete must be a boolean",
        )
    diagnostic = scope.get("scope_diagnostic_code")
    if diagnostic is not None:
        diagnostic = _non_empty_string(
            diagnostic,
            path="$._dahe_scope.scope_diagnostic_code",
        )
    if scope_complete and diagnostic is not None:
        raise DailyPayloadError(
            "scope_diagnostic_invalid",
            "a complete daily scope cannot contain a diagnostic code",
        )
    if not scope_complete and diagnostic is None:
        raise DailyPayloadError(
            "scope_diagnostic_missing",
            "an incomplete daily scope requires a diagnostic code",
        )
    return {
        "platform_display_total": platform_display_total,
        "response_total": normalized_response_total,
        "response_page_count": response_page_count,
        "query_scope_sha256": query_scope_sha256,
        "scope_complete": scope_complete,
        "scope_diagnostic_code": diagnostic,
    }


def _non_negative_integer(value: object, *, path: str) -> int:
    if type(value) is not int or value < 0:
        raise DailyPayloadError(
            "non_negative_integer_expected",
            f"{path} must be a non-negative integer",
        )
    return value


def _platform_identity(value: object, *, path: str) -> str:
    if type(value) is int and value > 0:
        return str(value)
    if (
        type(value) is str
        and value
        and value == value.strip()
        and value.isascii()
        and value.isdigit()
        and len(value) <= 64
    ):
        return value
    raise DailyPayloadError(
        "platform_identity_invalid",
        f"{path} must be one numeric platform identity",
    )


def _non_empty_string(value: object, *, path: str) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > 100
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise DailyPayloadError(
            "non_empty_string_expected",
            f"{path} must be a non-empty string",
        )
    return value


def _optional_string(value: object, *, path: str) -> str | None:
    if value is None or value == "":
        return None
    return _non_empty_string(value, path=path)


def _optional_loading_time(value: object, *, path: str) -> datetime | None:
    if value is None or value == "":
        return None
    if type(value) is not str or value != value.strip():
        raise DailyPayloadError(
            "loading_time_invalid",
            f"{path} must be a platform local timestamp",
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise DailyPayloadError(
            "loading_time_invalid",
            f"{path} must be a platform local timestamp",
        ) from exc
    return parsed.replace(tzinfo=SHANGHAI)
