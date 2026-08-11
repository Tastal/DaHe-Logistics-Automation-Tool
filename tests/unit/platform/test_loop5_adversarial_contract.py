from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from dahe.adapters.chengfeng.frozen import (
    FrozenChengfengAdapter,
    FrozenFault,
    FrozenTransport,
)
from dahe.adapters.chengfeng.manifest import (
    FrozenContractManifest,
    ManifestValidationError,
)
from dahe.adapters.chengfeng.policy import (
    ReadOnlyRequestFirewall,
    ReadRequest,
    RequestDeniedError,
)
from dahe.ports.chengfeng import (
    PageContractChangedError,
    TransientNetworkError,
)

FIXTURE_ROOT = Path(__file__).resolve().parents[2] / "fixtures" / "chengfeng" / "loop5-synthetic-v1"


@dataclass(frozen=True, slots=True)
class _InjectedResponse:
    status_code: int
    media_type: str
    content: bytes


class _FailingDnsProbe:
    def check_dns(self) -> bool:
        raise OSError("synthetic DNS diagnostic failure")


def _load_manifest() -> FrozenContractManifest:
    return FrozenContractManifest.load(FIXTURE_ROOT)


def _adapter(
    manifest: FrozenContractManifest | None = None,
) -> tuple[FrozenChengfengAdapter, FrozenTransport]:
    selected = manifest or _load_manifest()
    transport = FrozenTransport(manifest=selected)
    return (
        FrozenChengfengAdapter(manifest=selected, transport=transport),
        transport,
    )


def _list_request(
    manifest: FrozenContractManifest,
    *,
    url: str | None = None,
    parameters: dict[str, object] | None = None,
) -> ReadRequest:
    declared = manifest.request_for(
        "list_waybills",
        {
            "scope": "loop5-synthetic-scope",
            "page_number": 1,
            "page_size": 50,
        },
    )
    return ReadRequest(
        operation=declared.operation,
        method=declared.method,
        url=url or f"{manifest.origin}{declared.path}",
        parameters_location=declared.parameters_location,
        parameters=parameters or dict(declared.parameters),
    )


def _rewrite_list_fixture(root: Path, mutation: dict[str, Any]) -> None:
    list_path = root / "list.json"
    payload = json.loads(list_path.read_text(encoding="utf-8"))
    payload["data"].update(mutation)
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    list_path.write_bytes(raw)

    manifest_path = root / "manifest.json"
    manifest_payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    response = next(
        request["response"]
        for request in manifest_payload["requests"]
        if request["operation"] == "list_waybills"
    )
    response["file_size"] = len(raw)
    response["file_sha256"] = hashlib.sha256(raw).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest_payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def test_loaded_manifest_and_authorized_payload_are_deeply_frozen() -> None:
    manifest = _load_manifest()
    request_parameters = {
        "scope": "loop5-synthetic-scope",
        "page_number": 1,
        "page_size": 50,
    }
    authorized = ReadOnlyRequestFirewall(manifest).authorize(
        _list_request(manifest, parameters=request_parameters)
    )

    request_parameters["page_size"] = 1

    assert authorized.parameters["page_size"] == 50
    with pytest.raises(TypeError):
        manifest.requests[0].parameters["page_size"] = 1
    with pytest.raises(TypeError):
        authorized.parameters["page_size"] = 1
    with pytest.raises(TypeError):
        manifest.fault_responses["login_required"] = manifest.fault_responses[
            "page_contract_changed"
        ]


def test_fixture_changed_after_manifest_load_is_reverified_before_replay(
    tmp_path: Path,
) -> None:
    copied_root = tmp_path / "contract"
    shutil.copytree(FIXTURE_ROOT, copied_root)
    manifest = FrozenContractManifest.load(copied_root)
    adapter, _ = _adapter(manifest)
    (copied_root / "list.json").write_text("{}", encoding="utf-8")

    with pytest.raises(ManifestValidationError, match=r"(?i)(size|sha-?256|hash)"):
        adapter.list_waybills(
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )


def test_transport_rejects_authority_from_a_different_response_contract(
    tmp_path: Path,
) -> None:
    alternate_root = tmp_path / "alternate-contract"
    shutil.copytree(FIXTURE_ROOT, alternate_root)
    _rewrite_list_fixture(alternate_root, {"server_note": "alternate response identity"})

    manifest = _load_manifest()
    alternate_manifest = FrozenContractManifest.load(alternate_root)
    crossed_transport = FrozenTransport(manifest=alternate_manifest)
    adapter = FrozenChengfengAdapter(
        manifest=manifest,
        transport=crossed_transport,
    )

    with pytest.raises(RuntimeError, match="not part of this frozen transport"):
        adapter.list_waybills(
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )


@pytest.mark.parametrize(
    "mutation",
    [
        {"token": "synthetic-secret-value"},
        {"server_note": "contact 13800138000"},
        {
            "items": [
                {
                    "platform_waybill_id": "production-waybill-123",
                    "waybill_number": "SYN-WB-001",
                    "vehicle_number": "SYN-A001",
                }
            ]
        },
    ],
)
def test_safety_flags_are_verified_against_sanitized_fixture_content(
    tmp_path: Path,
    mutation: dict[str, Any],
) -> None:
    copied_root = tmp_path / "unsafe-contract"
    shutil.copytree(FIXTURE_ROOT, copied_root)
    _rewrite_list_fixture(copied_root, mutation)

    with pytest.raises(ManifestValidationError, match=r"(?i)(sensitive|production-like)"):
        FrozenContractManifest.load(copied_root)


@pytest.mark.parametrize(
    "host_or_url",
    [
        "https://contract.chengfeng.invalid@attacker.test",
        "https://contract.chengfeng.invalid.attacker.test",
        "https://contract.chengfeng.invalid%2eattacker.test",
        "https://contract.chengfeng.invalid.",
        "https://contract。chengfeng.invalid",
        "https://attacker.test/https://contract.chengfeng.invalid",
    ],
)
def test_firewall_rejects_same_origin_deception(host_or_url: str) -> None:
    manifest = _load_manifest()
    declared = manifest.requests[0]
    deceptive_url = f"{host_or_url}{declared.path}"

    with pytest.raises(RequestDeniedError):
        ReadOnlyRequestFirewall(manifest).authorize(_list_request(manifest, url=deceptive_url))


@pytest.mark.parametrize(
    "payload",
    [
        b"not-json",
        b'{"ok":1,"data":{}}',
        (b'{"ok":true,"data":{"page_number":2,"page_size":50,"total":0,"items":[]}}'),
        (
            b'{"ok":true,"data":{"page_number":1,"page_size":50,"total":2,'
            b'"items":[{"platform_waybill_id":"duplicate","waybill_number":"A",'
            b'"vehicle_number":null},{"platform_waybill_id":"duplicate",'
            b'"waybill_number":"B","vehicle_number":null}]}}'
        ),
    ],
)
def test_adapter_rejects_non_json_and_critical_list_mismatches(
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    adapter, transport = _adapter()
    monkeypatch.setattr(
        transport,
        "send",
        lambda _request: _InjectedResponse(
            status_code=200,
            media_type="application/json",
            content=payload,
        ),
    )

    with pytest.raises(PageContractChangedError):
        adapter.list_waybills(
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )


def test_dns_probe_exception_cannot_block_the_business_request() -> None:
    manifest = _load_manifest()
    transport = FrozenTransport(manifest=manifest)
    adapter = FrozenChengfengAdapter(
        manifest=manifest,
        transport=transport,
        diagnostic_probe=_FailingDnsProbe(),
    )

    page = adapter.list_waybills(
        scope="loop5-synthetic-scope",
        page_number=1,
        page_size=50,
    )

    assert page.total == 2
    assert transport.request_count("list_waybills") == 1


def test_fault_queue_is_ordered_and_each_failure_is_consumed_once() -> None:
    adapter, transport = _adapter()
    transport.fail_next(
        operation="list_waybills",
        fault=FrozenFault.NETWORK_TRANSIENT,
    )

    with pytest.raises(TransientNetworkError):
        adapter.list_waybills(
            scope="loop5-synthetic-scope",
            page_number=1,
            page_size=50,
        )

    page = adapter.list_waybills(
        scope="loop5-synthetic-scope",
        page_number=1,
        page_size=50,
    )

    assert page.total == 2
    assert transport.request_count("list_waybills") == 2
