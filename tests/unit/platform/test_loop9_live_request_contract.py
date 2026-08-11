from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.live_manifest import (
    ImageReadCapabilityPolicy,
    LiveContractError,
    LiveReadContractManifest,
    LiveReadOnlyRequestFirewall,
)
from dahe.adapters.chengfeng.policy import ReadRequest, RequestDeniedError


def _manifest_payload() -> dict[str, object]:
    return {
        "schema_version": 1,
        "contract_kind": "loop9_read_only",
        "run_mode": "shadow",
        "origin": "https://platform.example.invalid",
        "image_origins": ["https://images.example.invalid"],
        "source_discovery_sha256": "a" * 64,
        "source_observation_count": 3,
        "requests": [
            {
                "operation": "list_waybills",
                "method": "POST",
                "path": "/shadow-api/waybills/list",
                "parameters_location": "json",
                "parameters": {
                    "page_number": {"type": "integer"},
                    "page_size": {"type": "integer", "maximum": 100},
                    "scope": {"type": "string", "constant": "current"},
                },
                "response_fields": [
                    {"path": "$.data.items[].id", "types": ["string"]},
                    {"path": "$.data.total", "types": ["integer"]},
                ],
            },
            {
                "operation": "get_waybill_detail",
                "method": "POST",
                "path": "/shadow-api/waybills/detail",
                "parameters_location": "json",
                "parameters": {
                    "platform_waybill_id": {"type": "string"},
                },
                "response_fields": [
                    {"path": "$.data.id", "types": ["string"]},
                ],
            },
            {
                "operation": "download_ticket_image",
                "method": "GET",
                "path": "/shadow-api/tickets/image",
                "parameters_location": "query",
                "parameters": {"ticket_ref": {"type": "string"}},
                "response_fields": [],
            },
        ],
    }


def _manifest() -> LiveReadContractManifest:
    return LiveReadContractManifest.model_validate_json(
        json.dumps(_manifest_payload()),
        strict=True,
    )


def test_live_contract_accepts_only_the_three_read_operations() -> None:
    manifest = _manifest()
    assert tuple(request.operation for request in manifest.requests) == (
        "list_waybills",
        "get_waybill_detail",
        "download_ticket_image",
    )


def test_live_contract_accepts_form_encoding_only_for_detail_reads() -> None:
    payload = _manifest_payload()
    detail = payload["requests"][1]  # type: ignore[index]
    detail["parameters_location"] = "form"  # type: ignore[index]
    manifest = LiveReadContractManifest.model_validate_json(
        json.dumps(payload),
        strict=True,
    )
    assert manifest.requests[1].parameters_location == "form"

    list_request = payload["requests"][0]  # type: ignore[index]
    list_request["parameters_location"] = "form"  # type: ignore[index]
    with pytest.raises(ValueError):
        LiveReadContractManifest.model_validate_json(
            json.dumps(payload),
            strict=True,
        )


def test_live_contract_rejects_non_https_credentials_queries_and_ip_hosts() -> None:
    for origin in (
        "http://platform.example.invalid",
        "https://user:password@platform.example.invalid",
        "https://platform.example.invalid?token=secret",
        "https://127.0.0.1",
    ):
        payload = _manifest_payload()
        payload["origin"] = origin
        with pytest.raises(ValueError):
            LiveReadContractManifest.model_validate(payload, strict=True)


def test_live_firewall_requires_exact_origin_path_method_keys_and_types() -> None:
    firewall = LiveReadOnlyRequestFirewall(_manifest())
    valid = ReadRequest(
        operation="list_waybills",
        method="POST",
        url="https://platform.example.invalid/shadow-api/waybills/list",
        parameters_location="json",
        parameters={"page_number": 1, "page_size": 30, "scope": "current"},
    )
    assert firewall.authorize(valid).operation == "list_waybills"

    invalid = (
        replace(valid, method="GET"),
        replace(valid, url=f"{valid.url}?token=secret"),
        replace(
            valid,
            parameters={"page_number": "1", "page_size": 30, "scope": "current"},
        ),
        replace(
            valid,
            parameters={"page_number": 1, "page_size": 30, "scope": "other"},
        ),
        replace(valid, parameters={**valid.parameters, "extra": 1}),
    )
    for request in invalid:
        with pytest.raises(RequestDeniedError):
            firewall.authorize(request)


def test_live_firewall_rejects_every_redirect_and_write_operation() -> None:
    firewall = LiveReadOnlyRequestFirewall(_manifest())
    request = ReadRequest(
        operation="list_waybills",
        method="POST",
        url="https://platform.example.invalid/shadow-api/waybills/list",
        parameters_location="json",
        parameters={"page_number": 1, "page_size": 30, "scope": "current"},
    )
    with pytest.raises(RequestDeniedError):
        firewall.authorize_redirect(request, location=request.url)
    with pytest.raises(RequestDeniedError):
        firewall.authorize(
            ReadRequest(
                operation="confirm_settlement",
                method="POST",
                url="https://platform.example.invalid/shadow-api/settlement/confirm",
                parameters_location="json",
                parameters={"id": "one"},
            )
        )
    with pytest.raises(RequestDeniedError):
        firewall.authorize(
            ReadRequest(
                operation="download_ticket_image",
                method="GET",
                url="https://platform.example.invalid/shadow-api/tickets/image",
                parameters_location="query",
                parameters={"ticket_ref": "ticket-one"},
            )
        )


def test_live_firewall_accepts_declared_empty_filter_lists_only() -> None:
    payload = _manifest_payload()
    list_request = payload["requests"][0]  # type: ignore[index]
    list_request["parameters"]["sns"] = {"type": "empty_list"}  # type: ignore[index]
    manifest = LiveReadContractManifest.model_validate_json(
        json.dumps(payload),
        strict=True,
    )
    firewall = LiveReadOnlyRequestFirewall(manifest)

    request = ReadRequest(
        operation="list_waybills",
        method="POST",
        url="https://platform.example.invalid/shadow-api/waybills/list",
        parameters_location="json",
        parameters={
            "page_number": 1,
            "page_size": 30,
            "scope": "current",
            "sns": [],
        },
    )
    assert firewall.authorize(request).operation == "list_waybills"
    with pytest.raises(RequestDeniedError):
        firewall.authorize(replace(request, parameters={**request.parameters, "sns": ["one"]}))


def test_live_contract_loader_requires_absolute_nonsymlink_path_and_expected_hash(
    tmp_path: Path,
) -> None:
    contract_path = tmp_path / "contract.json"
    contract_path.write_text(
        json.dumps(_manifest_payload(), sort_keys=True),
        encoding="utf-8",
    )
    expected = LiveReadContractManifest.file_sha256(contract_path)
    loaded = LiveReadContractManifest.load(
        contract_path,
        allowed_root=tmp_path,
        expected_sha256=expected,
    )
    assert loaded.canonical_sha256

    with pytest.raises(LiveContractError, match="absolute"):
        LiveReadContractManifest.load(
            Path("contract.json"),
            allowed_root=tmp_path,
            expected_sha256=expected,
        )
    with pytest.raises(LiveContractError, match="SHA-256"):
        LiveReadContractManifest.load(
            contract_path,
            allowed_root=tmp_path,
            expected_sha256="0" * 64,
        )


def test_checked_in_contract_fixture_is_sanitized_and_non_routable() -> None:
    path = Path("fixtures/chengfeng/loop9-read-only.invalid.json")
    manifest = LiveReadContractManifest.model_validate_json(
        path.read_bytes(),
        strict=True,
    )
    assert manifest.origin.endswith(".invalid")
    assert "chengfengkuaiyun.com" not in path.read_text(encoding="utf-8")


def test_detail_bound_image_capability_allows_only_the_exact_short_lived_url() -> None:
    firewall = LiveReadOnlyRequestFirewall(_manifest())
    detail = firewall.authorize(
        ReadRequest(
            operation="get_waybill_detail",
            method="POST",
            url="https://platform.example.invalid/shadow-api/waybills/detail",
            parameters_location="json",
            parameters={"platform_waybill_id": "waybill-one"},
        )
    )
    policy = ImageReadCapabilityPolicy(
        allowed_origins=("https://images.example.invalid",),
        maximum_lifetime=timedelta(minutes=5),
    )
    issued_at = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    image_url = (
        "https://images.example.invalid/evidence/ticket.jpg"
        "?Expires=60&Signature=secret-value"
    )
    capability = policy.issue(
        source_request=detail,
        image_url=image_url,
        validated_response_sha256="1" * 64,
        issued_at=issued_at,
        lifetime=timedelta(minutes=2),
    )

    authorized = policy.authorize(
        capability=capability,
        request=ReadRequest(
            operation="download_ticket_image",
            method="GET",
            url=image_url,
            parameters_location="query",
            parameters={},
        ),
        now=issued_at + timedelta(minutes=1),
    )

    assert authorized.operation == "download_ticket_image"
    assert authorized.url_sha256 == capability.url_sha256
    assert "secret-value" not in repr(capability)


def test_image_capability_rejects_untrusted_source_expiry_changes_and_redirects() -> None:
    firewall = LiveReadOnlyRequestFirewall(_manifest())
    list_request = firewall.authorize(
        ReadRequest(
            operation="list_waybills",
            method="POST",
            url="https://platform.example.invalid/shadow-api/waybills/list",
            parameters_location="json",
            parameters={"page_number": 1, "page_size": 30, "scope": "current"},
        )
    )
    policy = ImageReadCapabilityPolicy(
        allowed_origins=("https://images.example.invalid",),
        maximum_lifetime=timedelta(minutes=5),
    )
    issued_at = datetime(2026, 7, 28, 12, 0, tzinfo=UTC)
    image_url = "https://images.example.invalid/evidence/ticket.jpg?signature=secret"

    with pytest.raises(RequestDeniedError):
        policy.issue(
            source_request=list_request,
            image_url=image_url,
            validated_response_sha256="2" * 64,
            issued_at=issued_at,
            lifetime=timedelta(minutes=2),
        )

    detail = firewall.authorize(
        ReadRequest(
            operation="get_waybill_detail",
            method="POST",
            url="https://platform.example.invalid/shadow-api/waybills/detail",
            parameters_location="json",
            parameters={"platform_waybill_id": "waybill-one"},
        )
    )
    capability = policy.issue(
        source_request=detail,
        image_url=image_url,
        validated_response_sha256="2" * 64,
        issued_at=issued_at,
        lifetime=timedelta(minutes=2),
    )
    base_request = ReadRequest(
        operation="download_ticket_image",
        method="GET",
        url=image_url,
        parameters_location="query",
        parameters={},
    )
    for request, now in (
        (replace(base_request, method="POST"), issued_at + timedelta(minutes=1)),
        (
            replace(base_request, url=f"{image_url}x"),
            issued_at + timedelta(minutes=1),
        ),
        (base_request, issued_at + timedelta(minutes=2)),
    ):
        with pytest.raises(RequestDeniedError):
            policy.authorize(capability=capability, request=request, now=now)

    with pytest.raises(RequestDeniedError):
        policy.authorize_redirect(capability, location=image_url)
