from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.daily_contract_freezer import (
    DailyContractFreezeResult,
    freeze_daily_read_contract,
)
from dahe.adapters.chengfeng.daily_contract_selection import (
    DailyContractSelectionError,
    load_selected_daily_read_contract,
    rollover_daily_read_contract,
    select_daily_read_contract,
)
from dahe.adapters.chengfeng.daily_manifest import (
    DailyReadContractManifest,
)
from dahe.adapters.chengfeng.discovery import DiscoveryEvidenceStore
from tests.unit.platform.test_loop9_daily_contract_freezer import (
    _observation,
)


def _frozen(tmp_path: Path):
    evidence = DiscoveryEvidenceStore(tmp_path).seal(
        observations=[_observation()],
        build_sha256="b" * 64,
        access_window_id="daily-selection",
        captured_at=datetime(2026, 7, 29, 8, tzinfo=UTC),
    )
    return freeze_daily_read_contract(
        discovery_evidence_path=evidence.path,
        data_root=tmp_path,
    )


def test_daily_contract_selection_is_idempotent_and_reverified(
    tmp_path: Path,
) -> None:
    frozen = _frozen(tmp_path)

    first = select_daily_read_contract(data_root=tmp_path, frozen=frozen)
    replay = select_daily_read_contract(data_root=tmp_path, frozen=frozen)
    loaded = load_selected_daily_read_contract(tmp_path)

    assert replay == first
    assert loaded == first
    assert first.manifest.canonical_sha256 == frozen.contract_canonical_sha256
    assert len(first.selection_sha256) == 64


def test_daily_contract_selection_rejects_tampering_and_rollover(
    tmp_path: Path,
) -> None:
    frozen = _frozen(tmp_path)
    selected = select_daily_read_contract(data_root=tmp_path, frozen=frozen)
    document = json.loads(
        selected.selection_path.read_text(encoding="utf-8")
    )
    document["source_discovery_sha256"] = "0" * 64
    selected.selection_path.write_text(
        json.dumps(document),
        encoding="utf-8",
    )

    with pytest.raises(DailyContractSelectionError, match="integrity"):
        load_selected_daily_read_contract(tmp_path)

    other_root = tmp_path / "other"
    other_root.mkdir()
    other = _frozen(other_root)
    with pytest.raises(DailyContractSelectionError):
        select_daily_read_contract(data_root=tmp_path, frozen=other)


def test_daily_contract_rollover_preserves_old_selection_and_is_idempotent(
    tmp_path: Path,
) -> None:
    minimal = _frozen(tmp_path)
    minimal_manifest = DailyReadContractManifest.model_validate_json(
        minimal.contract_path.read_bytes(),
        strict=True,
    )
    expanded_manifest = DailyReadContractManifest.model_validate(
        {
            **minimal_manifest.canonical_document,
            "response_fields": tuple(
                {
                    "path": field["path"],
                    "types": tuple(field["types"]),
                }
                for field in sorted(
                    [
                        *minimal_manifest.canonical_document[
                            "response_fields"
                        ],
                        {
                            "path": (
                                "$.data.list[].legacyOptionalField"
                            ),
                            "types": ["string"],
                        },
                    ],
                    key=lambda field: field["path"],
                )
            ),
        },
        strict=True,
    )
    expanded = _write_frozen_manifest(
        tmp_path,
        manifest=expanded_manifest,
    )
    old = select_daily_read_contract(
        data_root=tmp_path,
        frozen=expanded,
    )

    result = rollover_daily_read_contract(
        data_root=tmp_path,
        frozen=minimal,
    )
    replay = rollover_daily_read_contract(
        data_root=tmp_path,
        frozen=minimal,
    )

    assert result.selected.manifest == minimal_manifest
    assert result.idempotent_replay is False
    assert replay.selected == result.selected
    assert replay.evidence_sha256 == result.evidence_sha256
    assert replay.idempotent_replay is True
    history = (
        tmp_path
        / "daily-platform-read-contract"
        / "selection-history"
        / f"{old.selection_sha256}.json"
    )
    assert history.read_bytes() != result.selected.selection_path.read_bytes()
    evidence = json.loads(
        result.evidence_path.read_text(encoding="utf-8")
    )
    assert evidence["previous_selection_sha256"] == old.selection_sha256
    assert (
        evidence["replacement_selection_sha256"]
        == result.selected.selection_sha256
    )
    assert evidence["platform_write_authorization"] is False


def _write_frozen_manifest(
    data_root: Path,
    *,
    manifest: DailyReadContractManifest,
) -> DailyContractFreezeResult:
    canonical = json.dumps(
        manifest.canonical_document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    contract_bytes = canonical + b"\n"
    contract_file_sha256 = hashlib.sha256(contract_bytes).hexdigest()
    contract_root = data_root / "daily-platform-read-contract"
    contract_root.mkdir(exist_ok=True)
    contract_path = contract_root / f"{manifest.canonical_sha256}.json"
    contract_path.write_bytes(contract_bytes)
    evidence_body = {
        "schema_version": 1,
        "kind": "loop9_daily_read_contract_freeze",
        "classification": "development_only",
        "source_discovery_sha256": manifest.source_discovery_sha256,
        "source_observation_count": manifest.source_observation_count,
        "contract_canonical_sha256": manifest.canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "request_field_count": len(manifest.request_fields),
        "response_field_count": len(manifest.response_fields),
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    evidence_canonical = json.dumps(
        evidence_body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    evidence_sha256 = hashlib.sha256(evidence_canonical).hexdigest()
    evidence_root = data_root / "daily-platform-read-contract-evidence"
    evidence_root.mkdir(exist_ok=True)
    evidence_path = evidence_root / f"{evidence_sha256}.json"
    evidence_path.write_text(
        json.dumps(
            {
                **evidence_body,
                "canonical_sha256": evidence_sha256,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    return DailyContractFreezeResult(
        contract_path=contract_path,
        contract_canonical_sha256=manifest.canonical_sha256,
        contract_file_sha256=contract_file_sha256,
        evidence_path=evidence_path,
        freeze_evidence_sha256=evidence_sha256,
        source_discovery_sha256=manifest.source_discovery_sha256,
    )
