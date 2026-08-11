from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.verification.loop9_dataset_isolation import (
    Loop9DatasetIsolationError,
)
from tools import loop9_replay_dataset_isolation as module

EXPECTED_CURRENT_BUILD_SHA256 = "a" * 64
EXPECTED_SETTLEMENT_CONTRACT_SHA256 = "b" * 64
EXPECTED_DAILY_CONTRACT_SHA256 = "c" * 64
EXPECTED_SETTLEMENT_SELECTION_SHA256 = "f" * 64
EXPECTED_DAILY_SELECTION_SHA256 = "a" * 64


def _arguments(tmp_path: Path) -> list[str]:
    paths: dict[str, Path] = {}
    for name in (
        "discovery",
        "locked",
        "shadow",
        "daily",
        "source-authority",
        "evidence",
    ):
        path = (tmp_path / f"{name}.json").resolve()
        path.write_text("{}", encoding="utf-8")
        paths[name] = path
    return [
        "--data-root",
        str(tmp_path.resolve()),
        "--discovery-development",
        str(paths["discovery"]),
        "--current-locked-50",
        str(paths["locked"]),
        "--real-shadow-30",
        str(paths["shadow"]),
        "--daily-validation",
        str(paths["daily"]),
        "--source-development-authority",
        str(paths["source-authority"]),
        "--evidence",
        str(paths["evidence"]),
    ]


@dataclass(frozen=True)
class _FakeEvidence:
    canonical_sha256: str = "d" * 64
    full_history_exclusion_authority_sha256: str = "e" * 64

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "isolation_passed": True,
            "canonical_sha256": self.canonical_sha256,
        }


@dataclass(frozen=True)
class _FakeFullHistoryAuthority:
    development_exclusions: object = "development-from-authority"
    legacy_loop7_exclusions: object = "loop7-from-authority"


def _patch_authority(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: EXPECTED_CURRENT_BUILD_SHA256,
    )
    monkeypatch.setattr(
        module,
        "load_selected_live_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_SETTLEMENT_CONTRACT_SHA256
            ),
            selection_sha256=EXPECTED_SETTLEMENT_SELECTION_SHA256,
        ),
    )
    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256=EXPECTED_DAILY_CONTRACT_SHA256
            ),
            selection_sha256=EXPECTED_DAILY_SELECTION_SHA256,
        ),
    )


def test_cli_independently_replays_all_inputs_and_persisted_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    loaded_datasets: list[Path] = []
    loaded_authorities: list[Path] = []
    evidence_path: list[Path] = []
    received: dict[str, object] = {}
    expected = _FakeEvidence()
    source_authority = object()
    source_boundary = object()
    full_history = _FakeFullHistoryAuthority()

    def load_dataset(path: Path) -> object:
        loaded_datasets.append(path)
        return path.name

    def load_source_authority(path: Path) -> object:
        loaded_authorities.append(path)
        return source_authority

    def load_full_history(**values: object) -> _FakeFullHistoryAuthority:
        received["authority_loader"] = values
        return full_history

    def load_evidence(path: Path) -> _FakeEvidence:
        evidence_path.append(path)
        return expected

    def validate(**values: object) -> _FakeEvidence:
        received.update(values)
        return _FakeEvidence()

    monkeypatch.setattr(module, "load_loop9_dataset_manifest", load_dataset)
    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        load_source_authority,
    )
    monkeypatch.setattr(
        module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda value: source_boundary
        if value is source_authority
        else pytest.fail("unexpected source authority"),
    )
    monkeypatch.setattr(
        module,
        "load_stored_loop9_full_history_exclusion_authority",
        load_full_history,
    )
    monkeypatch.setattr(
        module,
        "load_loop9_dataset_isolation_evidence",
        load_evidence,
    )
    monkeypatch.setattr(module, "validate_loop9_dataset_isolation", validate)
    _patch_authority(monkeypatch)

    assert module.main(_arguments(tmp_path)) == 0

    stdout = json.loads(capsys.readouterr().out)
    assert len(loaded_datasets) == 4
    assert len(loaded_authorities) == 1
    assert len(evidence_path) == 1
    loader = received.pop("authority_loader")
    assert loader == {
        "authority_sha256": expected.full_history_exclusion_authority_sha256,
        "data_root": tmp_path.resolve(),
    }
    assert set(received) == {
        "current_locked_50",
        "daily_validation",
        "development_exclusions",
        "discovery_development",
        "legacy_loop7_exclusions",
        "real_shadow_30",
        "expected_current_build_sha256",
        "expected_daily_contract_sha256",
        "expected_daily_selection_sha256",
        "expected_settlement_selection_sha256",
        "expected_settlement_contract_sha256",
        "expected_exclusion_source_boundary",
        "full_history_exclusion_authority",
    }
    assert received["development_exclusions"] == (
        full_history.development_exclusions
    )
    assert received["legacy_loop7_exclusions"] == (
        full_history.legacy_loop7_exclusions
    )
    assert received["expected_exclusion_source_boundary"] is source_boundary
    assert received["full_history_exclusion_authority"] is full_history
    assert stdout == {
        "canonical_sha256": expected.canonical_sha256,
        "isolation_replayed": True,
    }


def test_cli_rejects_persisted_evidence_that_differs_from_replay(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        module,
        "load_loop9_dataset_manifest",
        lambda _path: object(),
    )
    full_history = _FakeFullHistoryAuthority()
    monkeypatch.setattr(
        module,
        "load_formal_development_authority",
        lambda _path: object(),
    )
    monkeypatch.setattr(
        module,
        "exclusion_source_boundary_from_formal_development_authority",
        lambda _value: object(),
    )
    monkeypatch.setattr(
        module,
        "load_stored_loop9_full_history_exclusion_authority",
        lambda **_values: full_history,
    )
    monkeypatch.setattr(
        module,
        "load_loop9_dataset_isolation_evidence",
        lambda _path: _FakeEvidence(canonical_sha256="e" * 64),
    )
    monkeypatch.setattr(
        module,
        "validate_loop9_dataset_isolation",
        lambda **_values: _FakeEvidence(),
    )
    _patch_authority(monkeypatch)

    with pytest.raises(Loop9DatasetIsolationError, match="does not match"):
        module.main(_arguments(tmp_path))


def test_cli_rejects_relative_paths_and_abbreviated_options(
    tmp_path: Path,
) -> None:
    relative = _arguments(tmp_path)
    relative[1] = "relative-discovery.json"
    with pytest.raises(SystemExit):
        module.main(relative)

    abbreviated = _arguments(tmp_path)
    abbreviated[0] = "--discovery"
    with pytest.raises(SystemExit):
        module.main(abbreviated)
