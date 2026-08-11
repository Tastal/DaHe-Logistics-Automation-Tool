from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.contract_freezer import (
    DETAIL_PATH,
    LIST_PATH,
    LiveContractFreezeError,
    freeze_live_read_contract,
    rollover_live_detail_encoding_contract,
    rollover_live_list_request_contract,
)
from dahe.adapters.chengfeng.discovery import DiscoveryEvidenceStore
from dahe.adapters.chengfeng.live_contract_selection import (
    load_selected_live_read_contract,
    select_live_read_contract,
)
from dahe.adapters.chengfeng.live_manifest import LiveReadContractManifest

PLATFORM_ORIGIN = "https://pc.chengfengkuaiyun.com"


def _json_observation(
    *,
    path: str,
    request_fields: list[dict[str, str]],
    response_fields: list[dict[str, str]],
) -> dict[str, object]:
    return {
        "method": "POST",
        "origin": PLATFORM_ORIGIN,
        "path": path,
        "path_sha256": None,
        "query_keys": ["t"],
        "request_fields": request_fields,
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": response_fields,
    }


def _list_observation() -> dict[str, object]:
    return _json_observation(
        path=LIST_PATH,
        request_fields=[
            {"path": "$.carNumber", "type": "string"},
            {"path": "$.pageNumber", "type": "integer"},
            {"path": "$.pageSize", "type": "integer"},
            {"path": "$.settleQueryType", "type": "integer"},
            {"path": "$.sns[]", "type": "empty_array"},
        ],
        response_fields=[
            {"path": "$.data.list[].id", "type": "string"},
            {"path": "$.data.list[].orderItemSn", "type": "string"},
            {"path": "$.data.list[].carNumber", "type": "string"},
            {"path": "$.data.pageNo", "type": "integer"},
            {"path": "$.data.pageSize", "type": "integer"},
            {"path": "$.data.total", "type": "integer"},
        ],
    )


def _detail_observation() -> dict[str, object]:
    return _json_observation(
        path=DETAIL_PATH,
        request_fields=[{"path": "$.id", "type": "string"}],
        response_fields=[
            {"path": "$.data[].id", "type": "string"},
            {"path": "$.data[].sn", "type": "string"},
            {"path": "$.data[].carNumber", "type": "string"},
            {"path": "$.data[].originalTon", "type": "string"},
            {"path": "$.data[].currentTon", "type": "string"},
            {"path": "$.data[].originalTonImageUrl", "type": "string"},
            {"path": "$.data[].image", "type": "string"},
        ],
    )


def _image_observation(origin: str, path_sha256: str) -> dict[str, object]:
    return {
        "method": "GET",
        "origin": origin,
        "path": None,
        "path_sha256": path_sha256,
        "query_keys": ["Expires", "Signature"],
        "request_fields": [],
        "resource_kind": "image",
        "response_status": 200,
        "content_kind": "image",
        "response_fields": [],
    }


def _seal(
    data_root: Path,
    *,
    include_images: bool = True,
) -> Path:
    observations = [
        _list_observation(),
        _detail_observation(),
        _json_observation(
            path="/api/example/updateGuide",
            request_fields=[{"path": "$.status", "type": "integer"}],
            response_fields=[{"path": "$.code", "type": "integer"}],
        ),
    ]
    if include_images:
        observations.extend(
            [
                _image_observation("https://images-a.example.invalid", "1" * 64),
                _image_observation("https://images-b.example.invalid", "2" * 64),
            ]
        )
    result = DiscoveryEvidenceStore(data_root).seal(
        observations=observations,
        build_sha256="a" * 64,
        access_window_id="window-one",
        captured_at=datetime(2026, 7, 29, 5, 0, tzinfo=UTC),
    )
    return result.path


def _seal_reset_request_structure(data_root: Path) -> Path:
    result = DiscoveryEvidenceStore(data_root).seal(
        observations=[
            {
                "method": "POST",
                "origin": PLATFORM_ORIGIN,
                "path": LIST_PATH,
                "path_sha256": None,
                "query_keys": ["t"],
                "request_fields": [
                    {"path": "$.order", "type": "string"},
                    {"path": "$.pageNumber", "type": "integer"},
                    {"path": "$.pageSize", "type": "integer"},
                    {"path": "$.queryType", "type": "string"},
                    {"path": "$.settleQueryType", "type": "integer"},
                    {"path": "$.weightNumber", "type": "string"},
                ],
                "resource_kind": "json_api",
                "response_status": None,
                "content_kind": None,
                "response_fields": [],
            }
        ],
        build_sha256="b" * 64,
        access_window_id="window-two",
        captured_at=datetime(2026, 7, 29, 6, 0, tzinfo=UTC),
    )
    return result.path


def _seal_reset_request_structure_diagnostic(
    data_root: Path,
    *,
    parent_contract_sha256: str,
) -> Path:
    discovery = json.loads(
        _seal_reset_request_structure(data_root).read_text(encoding="utf-8")
    )
    body = {
        "schema_version": 1,
        "kind": "chengfeng_reset_list_structure_diagnostic",
        "classification": "development_only",
        "created_at": "2026-07-29T06:00:00+00:00",
        "parent_contract_canonical_sha256": parent_contract_sha256,
        "observation": discovery["observations"][0],
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    canonical = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    root = data_root / "platform-contract-diagnostics"
    root.mkdir()
    path = root / f"{digest}.json"
    path.write_text(
        json.dumps(
            {**body, "canonical_sha256": digest},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def test_freezer_selects_only_exact_reads_and_is_idempotent(tmp_path: Path) -> None:
    discovery_path = _seal(tmp_path)

    first = freeze_live_read_contract(
        discovery_evidence_path=discovery_path,
        data_root=tmp_path,
    )
    second = freeze_live_read_contract(
        discovery_evidence_path=discovery_path,
        data_root=tmp_path,
    )

    assert second == first
    assert first.selected_observation_count == 4
    assert first.excluded_observation_count == 1
    assert first.potentially_mutating_observation_count == 1
    manifest = LiveReadContractManifest.model_validate_json(
        first.contract_path.read_bytes(),
        strict=True,
    )
    assert manifest.source_discovery_sha256 == discovery_path.stem
    assert manifest.image_origins == (
        "https://images-a.example.invalid",
        "https://images-b.example.invalid",
    )
    assert tuple(request.operation for request in manifest.requests) == (
        "list_waybills",
        "get_waybill_detail",
        "download_ticket_image",
    )
    detail = next(
        request
        for request in manifest.requests
        if request.operation == "get_waybill_detail"
    )
    assert detail.parameters_location == "json"
    assert "updateGuide" not in first.contract_path.read_text(encoding="utf-8")
    evidence = json.loads(first.evidence_path.read_text(encoding="utf-8"))
    assert evidence["platform_write_authorization"] is False
    assert evidence["request_values_retained"] is False
    assert evidence["response_values_retained"] is False


def test_detail_encoding_rollover_is_content_addressed_and_selectable(
    tmp_path: Path,
) -> None:
    frozen = freeze_live_read_contract(
        discovery_evidence_path=_seal(tmp_path),
        data_root=tmp_path,
    )
    parent = select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=frozen.contract_canonical_sha256,
        contract_file_sha256=frozen.contract_file_sha256,
        freeze_evidence_sha256=frozen.freeze_evidence_sha256,
    )

    rolled = rollover_live_detail_encoding_contract(data_root=tmp_path)
    selected = select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=rolled.contract_canonical_sha256,
        contract_file_sha256=rolled.contract_file_sha256,
        freeze_evidence_sha256=rolled.freeze_evidence_sha256,
    )
    retried = rollover_live_detail_encoding_contract(data_root=tmp_path)

    assert retried == rolled
    assert selected.manifest.canonical_sha256 != (
        parent.manifest.canonical_sha256
    )
    before = {
        request.operation: request
        for request in parent.manifest.requests
    }
    after = {
        request.operation: request
        for request in selected.manifest.requests
    }
    assert after["list_waybills"] == before["list_waybills"]
    assert after["download_ticket_image"] == before["download_ticket_image"]
    assert before["get_waybill_detail"].parameters_location == "json"
    assert after["get_waybill_detail"].parameters_location == "form"
    assert (
        after["get_waybill_detail"].model_copy(
            update={"parameters_location": "json"}
        )
        == before["get_waybill_detail"]
    )


def test_freezer_rejects_tampered_discovery_evidence(tmp_path: Path) -> None:
    discovery_path = _seal(tmp_path)
    document = json.loads(discovery_path.read_text(encoding="utf-8"))
    document["observation_count"] = 999
    discovery_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(LiveContractFreezeError, match="integrity"):
        freeze_live_read_contract(
            discovery_evidence_path=discovery_path,
            data_root=tmp_path,
        )


def test_freezer_rejects_missing_signed_ticket_image_shape(tmp_path: Path) -> None:
    discovery_path = _seal(tmp_path, include_images=False)

    with pytest.raises(LiveContractFreezeError, match="ticket-image"):
        freeze_live_read_contract(
            discovery_evidence_path=discovery_path,
            data_root=tmp_path,
        )


def test_list_request_rollover_is_idempotent_and_requires_live_validation(
    tmp_path: Path,
) -> None:
    original = freeze_live_read_contract(
        discovery_evidence_path=_seal(tmp_path),
        data_root=tmp_path,
    )
    select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=original.contract_canonical_sha256,
        contract_file_sha256=original.contract_file_sha256,
        freeze_evidence_sha256=original.freeze_evidence_sha256,
    )
    structure_path = _seal_reset_request_structure(tmp_path)

    first = rollover_live_list_request_contract(
        request_structure_evidence_path=structure_path,
        data_root=tmp_path,
    )
    second = rollover_live_list_request_contract(
        request_structure_evidence_path=structure_path,
        data_root=tmp_path,
    )

    assert second == first
    selected = select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=first.contract_canonical_sha256,
        contract_file_sha256=first.contract_file_sha256,
        freeze_evidence_sha256=first.freeze_evidence_sha256,
    )
    loaded = load_selected_live_read_contract(tmp_path)
    assert loaded == selected
    declaration = next(
        item
        for item in loaded.manifest.requests
        if item.operation == "list_waybills"
    )
    assert set(declaration.parameters) == {
        "order",
        "pageNumber",
        "pageSize",
        "queryType",
        "settleQueryType",
        "weightNumber",
    }
    freeze_evidence = json.loads(
        first.evidence_path.read_text(encoding="utf-8")
    )
    assert freeze_evidence["requires_live_validation"] is True
    assert freeze_evidence["response_contract_inherited"] is True
    assert freeze_evidence["platform_write_authorization"] is False


def test_list_request_rollover_accepts_only_matching_safe_diagnostic(
    tmp_path: Path,
) -> None:
    original = freeze_live_read_contract(
        discovery_evidence_path=_seal(tmp_path),
        data_root=tmp_path,
    )
    select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=original.contract_canonical_sha256,
        contract_file_sha256=original.contract_file_sha256,
        freeze_evidence_sha256=original.freeze_evidence_sha256,
    )
    diagnostic = _seal_reset_request_structure_diagnostic(
        tmp_path,
        parent_contract_sha256=original.contract_canonical_sha256,
    )

    result = rollover_live_list_request_contract(
        request_structure_evidence_path=diagnostic,
        data_root=tmp_path,
    )

    evidence = json.loads(result.evidence_path.read_text(encoding="utf-8"))
    assert evidence["parent_contract_canonical_sha256"] == (
        original.contract_canonical_sha256
    )
    assert evidence["request_values_retained"] is False
    assert evidence["response_values_retained"] is False
