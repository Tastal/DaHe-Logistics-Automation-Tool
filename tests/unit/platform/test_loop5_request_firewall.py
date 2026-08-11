from __future__ import annotations

import importlib
from pathlib import Path
from urllib.parse import urljoin

import pytest

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "chengfeng" / "loop5-synthetic-v1"


def _types() -> tuple[type, type, type, object]:
    manifest_module = importlib.import_module("dahe.adapters.chengfeng.manifest")
    policy_module = importlib.import_module("dahe.adapters.chengfeng.policy")
    manifest = manifest_module.FrozenContractManifest.load(FIXTURE_ROOT)
    return (
        policy_module.ReadOnlyRequestFirewall,
        policy_module.ReadRequest,
        policy_module.RequestDeniedError,
        manifest,
    )


def _request(request_type: type, manifest: object, frozen_request: object) -> object:
    return request_type(
        operation=frozen_request.operation,
        method=frozen_request.method,
        url=urljoin(f"{manifest.origin}/", frozen_request.path.lstrip("/")),
        parameters_location=frozen_request.parameters_location,
        parameters=dict(frozen_request.parameters),
    )


def test_every_frozen_request_is_authorized_by_exact_contract() -> None:
    firewall_type, request_type, _, manifest = _types()
    firewall = firewall_type(manifest)

    authorized = [
        firewall.authorize(_request(request_type, manifest, frozen_request))
        for frozen_request in manifest.requests
    ]

    assert len(authorized) == 7
    assert all(result.operation in manifest.allowed_operations for result in authorized)


def test_origin_rejects_scheme_port_userinfo_suffix_subdomain_ip_and_trailing_dot() -> None:
    firewall_type, request_type, denied_type, manifest = _types()
    firewall = firewall_type(manifest)
    frozen_request = manifest.requests[0]
    valid = _request(request_type, manifest, frozen_request)
    invalid_urls = (
        valid.url.replace("https://", "http://"),
        valid.url.replace(".invalid", ".invalid:444"),
        valid.url.replace("https://", "https://user@"),
        valid.url.replace(".invalid", ".invalid.attacker.test"),
        valid.url.replace("contract.", "sub.contract."),
        valid.url.replace("contract.chengfeng.invalid", "127.0.0.1"),
        valid.url.replace(".invalid/", ".invalid./"),
    )

    for invalid_url in invalid_urls:
        with pytest.raises(denied_type):
            firewall.authorize(
                request_type(
                    operation=valid.operation,
                    method=valid.method,
                    url=invalid_url,
                    parameters_location=valid.parameters_location,
                    parameters=valid.parameters,
                )
            )


def test_path_rejects_aliases_traversal_encoding_and_near_matches() -> None:
    firewall_type, request_type, denied_type, manifest = _types()
    firewall = firewall_type(manifest)
    frozen_request = manifest.requests[0]
    valid = _request(request_type, manifest, frozen_request)
    invalid_paths = (
        f"{frozen_request.path}/",
        frozen_request.path.replace("/waybills/", "//waybills/"),
        "/shadow-api/../shadow-api/waybills/list",
        frozen_request.path.replace("/list", "%2flist"),
        frozen_request.path.replace("/list", "%5clist"),
        frozen_request.path.upper(),
        f"{frozen_request.path}-export",
    )

    for invalid_path in invalid_paths:
        with pytest.raises(denied_type):
            firewall.authorize(
                request_type(
                    operation=valid.operation,
                    method=valid.method,
                    url=f"{manifest.origin}{invalid_path}",
                    parameters_location=valid.parameters_location,
                    parameters=valid.parameters,
                )
            )


def test_method_and_parameter_location_must_match_the_operation_contract() -> None:
    firewall_type, request_type, denied_type, manifest = _types()
    firewall = firewall_type(manifest)
    frozen_request = manifest.requests[0]
    valid = _request(request_type, manifest, frozen_request)

    for method in ("GET", "PUT", "PATCH", "DELETE", "OPTIONS"):
        with pytest.raises(denied_type):
            firewall.authorize(
                request_type(
                    operation=valid.operation,
                    method=method,
                    url=valid.url,
                    parameters_location=valid.parameters_location,
                    parameters=valid.parameters,
                )
            )
    with pytest.raises(denied_type):
        firewall.authorize(
            request_type(
                operation=valid.operation,
                method=valid.method,
                url=valid.url,
                parameters_location="query",
                parameters=valid.parameters,
            )
        )


def test_payload_is_key_order_independent_but_rejects_missing_extra_null_and_wrong_type() -> None:
    firewall_type, request_type, denied_type, manifest = _types()
    firewall = firewall_type(manifest)
    frozen_request = manifest.requests[0]
    valid = _request(request_type, manifest, frozen_request)
    reordered = dict(reversed(tuple(valid.parameters.items())))

    firewall.authorize(
        request_type(
            operation=valid.operation,
            method=valid.method,
            url=valid.url,
            parameters_location=valid.parameters_location,
            parameters=reordered,
        )
    )
    invalid_payloads = (
        {"scope": "loop5-synthetic-scope", "page_number": 1},
        {**valid.parameters, "unexpected": True},
        {**valid.parameters, "page_size": None},
        {**valid.parameters, "page_number": "1"},
        {**valid.parameters, "scope": {"value": "loop5-synthetic-scope"}},
    )
    for payload in invalid_payloads:
        with pytest.raises(denied_type):
            firewall.authorize(
                request_type(
                    operation=valid.operation,
                    method=valid.method,
                    url=valid.url,
                    parameters_location=valid.parameters_location,
                    parameters=payload,
                )
            )


def test_unknown_operations_redirects_and_named_write_requests_are_denied() -> None:
    firewall_type, request_type, denied_type, manifest = _types()
    firewall = firewall_type(manifest)
    frozen_request = manifest.requests[0]
    valid = _request(request_type, manifest, frozen_request)

    rejected = (
        request_type(
            operation="raw_request",
            method="POST",
            url=valid.url,
            parameters_location="json",
            parameters=valid.parameters,
        ),
        request_type(
            operation="confirm_settlement",
            method="POST",
            url=f"{manifest.origin}/settlement/confirm",
            parameters_location="json",
            parameters={},
        ),
        request_type(
            operation="payment",
            method="POST",
            url=f"{manifest.origin}/payment",
            parameters_location="json",
            parameters={},
        ),
        request_type(
            operation="cancel_receipt",
            method="POST",
            url=f"{manifest.origin}/receipt/cancel",
            parameters_location="json",
            parameters={},
        ),
    )
    for request in rejected:
        with pytest.raises(denied_type):
            firewall.authorize(request)

    with pytest.raises(denied_type):
        firewall.authorize_redirect(
            valid,
            location="https://attacker.test/collect",
        )
