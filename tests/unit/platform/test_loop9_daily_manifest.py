from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from dahe.adapters.chengfeng.daily_manifest import (
    DAILY_LIST_PATH,
    DAILY_ORIGIN,
    DailyReadContractManifest,
)


def daily_manifest_document() -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract_kind": "loop9_daily_read_only",
        "run_mode": "shadow",
        "origin": DAILY_ORIGIN,
        "method": "POST",
        "path": DAILY_LIST_PATH,
        "parameters_location": "json",
        "source_discovery_sha256": "a" * 64,
        "source_observation_count": 1,
        "request_fields": {
            "carNumber": {"type": "string"},
            "filterParamList": {"type": "empty_array"},
            "loadEndTime": {"type": "string"},
            "loadStartTime": {"type": "string"},
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
            "receivePlace": {"type": "string"},
            "remarks": {"type": "null"},
        },
        "response_fields": [
            {"path": "$.data.list[].carNumber", "types": ["null", "string"]},
            {"path": "$.data.list[].id", "types": ["integer", "string"]},
            {
                "path": "$.data.list[].loadPunchDate",
                "types": ["null", "string"],
            },
            {"path": "$.data.list[].sn", "types": ["string"]},
            {"path": "$.data.total", "types": ["integer"]},
        ],
    }


def daily_manifest() -> DailyReadContractManifest:
    return DailyReadContractManifest.model_validate_json(
        json.dumps(daily_manifest_document()),
        strict=True,
    )


def test_daily_manifest_is_one_exact_read_surface() -> None:
    manifest = daily_manifest()

    assert manifest.origin == "https://pc.chengfengkuaiyun.com"
    assert manifest.path == "/api/hz/orderItem/queryOrderItemListPC"
    assert manifest.operation == "list_daily_waybills"
    assert manifest.canonical_document == daily_manifest_document()
    assert len(manifest.canonical_sha256) == 64


@pytest.mark.parametrize(
    ("field_name", "field_rule"),
    [
        ("status", {"type": "integer", "minimum": 0, "maximum": 10}),
        ("enabled", {"type": "boolean"}),
        ("criteria", {"type": "object"}),
    ],
)
def test_daily_manifest_rejects_nonempty_baseline_field_types(
    field_name: str,
    field_rule: dict[str, object],
) -> None:
    document = daily_manifest_document()
    request_fields = dict(document["request_fields"])  # type: ignore[arg-type]
    request_fields[field_name] = field_rule
    document["request_fields"] = request_fields

    with pytest.raises(ValidationError):
        DailyReadContractManifest.model_validate(document, strict=True)


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("origin", "https://example.invalid"),
        ("path", "/api/hz/orderItem/deleteOrderItem"),
        ("method", "GET"),
        ("parameters_location", "query"),
    ],
)
def test_daily_manifest_rejects_any_other_network_surface(
    name: str,
    value: str,
) -> None:
    document = daily_manifest_document()
    document[name] = value

    with pytest.raises(ValidationError):
        DailyReadContractManifest.model_validate(document, strict=True)


def test_daily_manifest_requires_the_complete_controlled_input_set() -> None:
    for missing in (
        "loadStartTime",
        "loadEndTime",
        "receivePlace",
        "pageNumber",
        "pageSize",
    ):
        document = daily_manifest_document()
        request_fields = dict(document["request_fields"])  # type: ignore[arg-type]
        request_fields.pop(missing)
        document["request_fields"] = request_fields

        with pytest.raises(ValidationError):
            DailyReadContractManifest.model_validate(document, strict=True)
