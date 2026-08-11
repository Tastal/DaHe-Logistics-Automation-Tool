from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from dahe.verification.loop9_dataset_isolation import Loop9DatasetIsolationError
from tools import loop9_validate_dataset_isolation as module

EXPECTED_CURRENT_BUILD_SHA256 = "a" * 64
EXPECTED_SETTLEMENT_CONTRACT_SHA256 = "b" * 64
EXPECTED_DAILY_CONTRACT_SHA256 = "c" * 64
EXPECTED_SETTLEMENT_SELECTION_SHA256 = "d" * 64
EXPECTED_DAILY_SELECTION_SHA256 = "e" * 64


def _arguments(tmp_path: Path) -> list[str]:
    paths: dict[str, Path] = {}
    for name in (
        "discovery",
        "locked",
        "shadow",
        "daily",
        "source-authority",
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
        "--output",
        str((tmp_path / "isolation-evidence.json").resolve()),
    ]


@dataclass(frozen=True)
class _FakeEvidence:
    canonical_sha256: str = "a" * 64

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


def test_cli_validates_all_six_inputs_and_writes_exclusive_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    loaded_datasets: list[Path] = []
    loaded_authorities: list[Path] = []
    received: dict[str, object] = {}
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
        "load_current_loop9_full_history_exclusion_authority",
        load_full_history,
    )
    persisted_authorities: list[dict[str, object]] = []
    monkeypatch.setattr(
        module,
        "persist_loop9_full_history_exclusion_authority",
        lambda **values: persisted_authorities.append(values)
        or (tmp_path / "authority.json"),
    )
    monkeypatch.setattr(module, "validate_loop9_dataset_isolation", validate)
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

    arguments = _arguments(tmp_path)
    assert module.main(arguments) == 0

    output_path = Path(arguments[-1])
    output = json.loads(output_path.read_text(encoding="utf-8"))
    stdout = json.loads(capsys.readouterr().out)
    assert len(loaded_datasets) == 4
    assert len(loaded_authorities) == 1
    loader = received.pop("authority_loader")
    assert isinstance(loader, dict)
    assert loader == {
        "data_root": tmp_path.resolve(),
        "expected_current_build_sha256": EXPECTED_CURRENT_BUILD_SHA256,
        "expected_daily_contract_sha256": EXPECTED_DAILY_CONTRACT_SHA256,
        "expected_daily_selection_sha256": EXPECTED_DAILY_SELECTION_SHA256,
        "expected_settlement_contract_sha256": (
            EXPECTED_SETTLEMENT_CONTRACT_SHA256
        ),
        "expected_settlement_selection_sha256": (
            EXPECTED_SETTLEMENT_SELECTION_SHA256
        ),
        "source_boundary": source_boundary,
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
    assert persisted_authorities == [
        {
            "authority": full_history,
            "data_root": tmp_path.resolve(),
        }
    ]
    assert (
        received["expected_current_build_sha256"]
        == EXPECTED_CURRENT_BUILD_SHA256
    )
    assert (
        received["expected_settlement_contract_sha256"]
        == EXPECTED_SETTLEMENT_CONTRACT_SHA256
    )
    assert (
        received["expected_daily_contract_sha256"]
        == EXPECTED_DAILY_CONTRACT_SHA256
    )
    assert (
        received["expected_settlement_selection_sha256"]
        == EXPECTED_SETTLEMENT_SELECTION_SHA256
    )
    assert (
        received["expected_daily_selection_sha256"]
        == EXPECTED_DAILY_SELECTION_SHA256
    )
    assert output["canonical_sha256"] == "a" * 64
    assert stdout == {
        "canonical_sha256": "a" * 64,
        "isolation_passed": True,
        "output": output_path.name,
    }

    with pytest.raises(Loop9DatasetIsolationError, match="already exists"):
        module.main(arguments)


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


def test_cli_rejects_caller_supplied_authority_sha256(
    tmp_path: Path,
) -> None:
    arguments = [
        *_arguments(tmp_path),
        "--expected-current-build-sha256",
        EXPECTED_CURRENT_BUILD_SHA256,
    ]

    with pytest.raises(SystemExit):
        module.main(arguments)
