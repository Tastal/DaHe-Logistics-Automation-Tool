from __future__ import annotations

import json

import pytest

from dahe.adapters.chengfeng.contract_freezer import (
    DETAIL_PATH,
    LIST_PATH,
    RESPONSE_DERIVED_IMAGE_PATH,
)
from dahe.adapters.chengfeng.live_manifest import LiveReadContractManifest
from dahe.adapters.chengfeng.live_request_builder import (
    HISTORICAL_SETTLED_LIST_PATH,
    ChengfengLiveRequestBuilder,
    LiveRequestBuilderError,
)


def _manifest() -> LiveReadContractManifest:
    payload = {
        "schema_version": 1,
        "contract_kind": "loop9_read_only",
        "run_mode": "shadow",
        "origin": "https://pc.chengfengkuaiyun.com",
        "image_origins": ["https://images.example.invalid"],
        "source_discovery_sha256": "a" * 64,
        "source_observation_count": 5,
        "requests": [
            {
                "operation": "list_waybills",
                "method": "POST",
                "path": LIST_PATH,
                "parameters_location": "json",
                "parameters": {
                    "carNumber": {"type": "string", "allow_empty": True},
                    "order": {"type": "string", "allow_empty": True},
                    "pageNumber": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10_000,
                    },
                    "pageSize": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 100,
                    },
                    "settleQueryType": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 10_000,
                    },
                    "sns": {"type": "empty_list"},
                },
                "response_fields": [
                    {"path": "$.data.list[].id", "types": ["string"]},
                    {"path": "$.data.total", "types": ["integer"]},
                ],
            },
            {
                "operation": "get_waybill_detail",
                "method": "POST",
                "path": DETAIL_PATH,
                "parameters_location": "form",
                "parameters": {"id": {"type": "string"}},
                "response_fields": [
                    {"path": "$.data[].id", "types": ["string"]},
                ],
            },
            {
                "operation": "download_ticket_image",
                "method": "GET",
                "path": RESPONSE_DERIVED_IMAGE_PATH,
                "parameters_location": "query",
                "parameters": {"ticket_ref": {"type": "string"}},
                "response_fields": [],
            },
        ],
    }
    return LiveReadContractManifest.model_validate_json(
        json.dumps(payload),
        strict=True,
    )


def test_builder_constructs_only_the_current_pending_settlement_list() -> None:
    request = ChengfengLiveRequestBuilder(_manifest()).list_waybills(
        scope="current",
        page_number=2,
        page_size=30,
    )

    assert request.operation == "list_waybills"
    assert request.request.url == f"https://pc.chengfengkuaiyun.com{LIST_PATH}"
    assert request.request.method == "POST"
    assert request.request.parameters_location == "json"
    assert dict(request.request.parameters) == {
        "carNumber": "",
        "order": "desc",
        "pageNumber": 2,
        "pageSize": 30,
        "settleQueryType": 1,
        "sns": (),
    }


def test_builder_constructs_the_distinct_historical_settled_list() -> None:
    request = ChengfengLiveRequestBuilder(_manifest()).list_waybills(
        scope="settled_history",
        page_number=2,
        page_size=100,
    )

    assert request.operation == "list_waybills"
    assert request.request.url == (
        "https://pc.chengfengkuaiyun.com"
        f"{HISTORICAL_SETTLED_LIST_PATH}"
    )
    assert request.request.method == "POST"
    assert request.request.parameters_location == "json"
    assert dict(request.request.parameters) == {
        "deptCode": "",
        "pageNumber": 2,
        "pageSize": 100,
        "sortParams": (),
    }
    assert {
        field.path: field.types
        for field in request.declaration.response_fields
    } == {
        "$.data.list[].carNumber": ("string",),
        "$.data.list[].orderItemId": ("string",),
        "$.data.list[].orderItemSn": ("string",),
        "$.data.total": ("string",),
    }


@pytest.mark.parametrize(
    "scope,page_number,page_size",
    [
        ("all_history", 1, 30),
        ("current", 0, 30),
        ("current", 1, 101),
    ],
)
def test_builder_rejects_other_scopes_and_out_of_range_pages(
    scope: str,
    page_number: int,
    page_size: int,
) -> None:
    with pytest.raises(LiveRequestBuilderError):
        ChengfengLiveRequestBuilder(_manifest()).list_waybills(
            scope=scope,
            page_number=page_number,
            page_size=page_size,
        )


def test_builder_accepts_only_numeric_detail_identity() -> None:
    builder = ChengfengLiveRequestBuilder(_manifest())
    request = builder.get_waybill_detail(platform_waybill_id="900000001")
    assert request.operation == "get_waybill_detail"
    assert request.request.url == f"https://pc.chengfengkuaiyun.com{DETAIL_PATH}"
    assert request.request.parameters_location == "form"
    assert dict(request.request.parameters) == {"id": "900000001"}

    for invalid in ("", "abc", "1?token=secret", "\uff11"):
        with pytest.raises(LiveRequestBuilderError):
            builder.get_waybill_detail(platform_waybill_id=invalid)
