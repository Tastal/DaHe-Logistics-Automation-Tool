from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.live_contract_selection import (
    LiveContractSelectionError,
    load_selected_live_read_contract,
    select_live_read_contract,
)
from dahe.adapters.chengfeng.live_manifest import LiveReadContractManifest


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def _candidate(data_root: Path) -> tuple[str, str, str]:
    directory = data_root / "platform-read-contract"
    directory.mkdir(parents=True)
    source = Path("fixtures/chengfeng/loop9-read-only.invalid.json").read_bytes()
    manifest = LiveReadContractManifest.model_validate_json(source, strict=True)
    canonical_sha256 = manifest.canonical_sha256
    contract_path = directory / f"{canonical_sha256}.json"
    contract_path.write_bytes(source)
    contract_file_sha256 = hashlib.sha256(source).hexdigest()
    freeze_body = {
        "schema_version": 1,
        "kind": "loop9_live_read_contract_freeze",
        "classification": "development_only",
        "source_discovery_sha256": manifest.source_discovery_sha256,
        "source_observation_count": manifest.source_observation_count,
        "contract_canonical_sha256": canonical_sha256,
        "contract_file_sha256": contract_file_sha256,
        "selected_observation_count": 3,
        "excluded_observation_count": 0,
        "potentially_mutating_observation_count": 0,
        "potentially_mutating_path_sha256s": [],
        "platform_write_authorization": False,
        "request_values_retained": False,
        "response_values_retained": False,
        "credential_material_retained": False,
    }
    freeze_sha256 = hashlib.sha256(_canonical(freeze_body)).hexdigest()
    (directory / f"{canonical_sha256}.freeze-evidence.json").write_bytes(
        _canonical({**freeze_body, "canonical_sha256": freeze_sha256}) + b"\n"
    )
    return canonical_sha256, contract_file_sha256, freeze_sha256


def test_selection_binds_and_reloads_one_exact_immutable_candidate(
    tmp_path: Path,
) -> None:
    canonical_sha256, file_sha256, freeze_sha256 = _candidate(tmp_path)

    selected = select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=canonical_sha256,
        contract_file_sha256=file_sha256,
        freeze_evidence_sha256=freeze_sha256,
    )
    replay = select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=canonical_sha256,
        contract_file_sha256=file_sha256,
        freeze_evidence_sha256=freeze_sha256,
    )
    loaded = load_selected_live_read_contract(tmp_path)

    assert selected.selection_sha256 == replay.selection_sha256
    assert loaded.selection_sha256 == selected.selection_sha256
    assert loaded.manifest.canonical_sha256 == canonical_sha256


def test_selection_rejects_contract_freeze_or_pointer_tampering(tmp_path: Path) -> None:
    canonical_sha256, file_sha256, freeze_sha256 = _candidate(tmp_path)
    selected = select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=canonical_sha256,
        contract_file_sha256=file_sha256,
        freeze_evidence_sha256=freeze_sha256,
    )

    pointer = selected.selection_path
    pointer.write_text("{}", encoding="utf-8")
    with pytest.raises(LiveContractSelectionError):
        load_selected_live_read_contract(tmp_path)


def test_selection_refuses_to_replace_a_different_candidate(tmp_path: Path) -> None:
    canonical_sha256, file_sha256, freeze_sha256 = _candidate(tmp_path)
    select_live_read_contract(
        data_root=tmp_path,
        contract_canonical_sha256=canonical_sha256,
        contract_file_sha256=file_sha256,
        freeze_evidence_sha256=freeze_sha256,
    )

    with pytest.raises(LiveContractSelectionError, match="different"):
        select_live_read_contract(
            data_root=tmp_path,
            contract_canonical_sha256=canonical_sha256,
            contract_file_sha256="0" * 64,
            freeze_evidence_sha256=freeze_sha256,
        )
