from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.daily_contract_freezer import (
    DailyContractFreezeError,
    freeze_daily_read_contract,
)
from dahe.adapters.chengfeng.daily_manifest import (
    DAILY_LIST_PATH,
    DAILY_ORIGIN,
    DailyReadContractManifest,
)
from dahe.adapters.chengfeng.discovery import DiscoveryEvidenceStore


def _observation(
    *,
    path: str = DAILY_LIST_PATH,
    include_active_integer: bool = False,
) -> dict[str, object]:
    request_fields: list[dict[str, str]] = [
        {"path": "$.carNumber", "type": "string"},
        {"path": "$.filterParamList", "type": "empty_array"},
        {"path": "$.loadEndTime", "type": "string"},
        {"path": "$.loadStartTime", "type": "string"},
        {"path": "$.pageNumber", "type": "integer"},
        {"path": "$.pageSize", "type": "integer"},
        {"path": "$.receivePlace", "type": "string"},
        {"path": "$.remarks", "type": "null"},
    ]
    if include_active_integer:
        request_fields.append({"path": "$.status", "type": "integer"})
    return {
        "method": "POST",
        "origin": DAILY_ORIGIN,
        "path": path,
        "path_sha256": None,
        "query_keys": ["t"],
        "request_fields": request_fields,
        "resource_kind": "json_api",
        "response_status": 200,
        "content_kind": "json",
        "response_fields": [
            {"path": "$.data.list[].amount", "type": "string"},
            {"path": "$.data.list[].carNumber", "type": "string"},
            {"path": "$.data.list[].id", "type": "string"},
            {"path": "$.data.list[].loadPunchDate", "type": "string"},
            {"path": "$.data.list[].sn", "type": "string"},
            {"path": "$.data.total", "type": "integer"},
        ],
    }


def _seal(
    data_root: Path,
    *,
    observation: dict[str, object] | None = None,
) -> Path:
    return DiscoveryEvidenceStore(data_root).seal(
        observations=[observation or _observation()],
        build_sha256="b" * 64,
        access_window_id="daily-window",
        captured_at=datetime(2026, 7, 29, 7, 0, tzinfo=UTC),
    ).path


def test_daily_freezer_is_idempotent_and_retains_only_field_shapes(
    tmp_path: Path,
) -> None:
    discovery_path = _seal(tmp_path)

    first = freeze_daily_read_contract(
        discovery_evidence_path=discovery_path,
        data_root=tmp_path,
    )
    second = freeze_daily_read_contract(
        discovery_evidence_path=discovery_path,
        data_root=tmp_path,
    )

    assert second == first
    manifest = DailyReadContractManifest.model_validate_json(
        first.contract_path.read_bytes(),
        strict=True,
    )
    assert manifest.source_discovery_sha256 == discovery_path.stem
    assert set(manifest.request_fields) == {
        "carNumber",
        "filterParamList",
        "loadEndTime",
        "loadStartTime",
        "pageNumber",
        "pageSize",
        "receivePlace",
        "remarks",
    }
    assert {
        field.path: set(field.types)
        for field in manifest.response_fields
    } == {
        "$.data.list[].carNumber": {"null", "string"},
        "$.data.list[].id": {"integer", "string"},
        "$.data.list[].loadPunchDate": {"null", "string"},
        "$.data.list[].sn": {"string"},
        "$.data.total": {"integer"},
    }
    evidence = json.loads(first.evidence_path.read_text(encoding="utf-8"))
    assert evidence["request_values_retained"] is False
    assert evidence["response_values_retained"] is False
    assert evidence["credential_material_retained"] is False
    assert "daily-window" not in first.contract_path.read_text(encoding="utf-8")


def test_daily_freezer_rejects_tampering_wrong_endpoint_and_active_baselines(
    tmp_path: Path,
) -> None:
    discovery_path = _seal(tmp_path)
    document = json.loads(discovery_path.read_text(encoding="utf-8"))
    document["observation_count"] = 2
    discovery_path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(DailyContractFreezeError, match="integrity"):
        freeze_daily_read_contract(
            discovery_evidence_path=discovery_path,
            data_root=tmp_path,
        )

    wrong_root = tmp_path / "wrong"
    wrong_root.mkdir()
    with pytest.raises(DailyContractFreezeError, match="exact daily"):
        freeze_daily_read_contract(
            discovery_evidence_path=_seal(
                wrong_root,
                observation=_observation(path="/api/hz/orderItem/other"),
            ),
            data_root=wrong_root,
        )

    active_root = tmp_path / "active"
    active_root.mkdir()
    with pytest.raises(DailyContractFreezeError, match="safe empty baseline"):
        freeze_daily_read_contract(
            discovery_evidence_path=_seal(
                active_root,
                observation=_observation(include_active_integer=True),
            ),
            data_root=active_root,
        )
