from __future__ import annotations

import json
from pathlib import Path

import pytest

from dahe.adapters.chengfeng.daily_contract_selection import (
    load_selected_daily_read_contract,
    select_daily_read_contract,
)
from dahe.adapters.chengfeng.live_contract_selection import (
    load_selected_live_read_contract,
    select_live_read_contract,
)
from tests.unit.platform.test_loop9_daily_contract_selection import _frozen
from tests.unit.platform.test_loop9_live_contract_selection import _candidate
from tools import install_operational_read_contracts as module


def _selected_source(source_root: Path) -> None:
    canonical_sha256, file_sha256, freeze_sha256 = _candidate(source_root)
    select_live_read_contract(
        data_root=source_root,
        contract_canonical_sha256=canonical_sha256,
        contract_file_sha256=file_sha256,
        freeze_evidence_sha256=freeze_sha256,
    )
    select_daily_read_contract(
        data_root=source_root,
        frozen=_frozen(source_root),
    )


def _run(
    *,
    source_root: Path,
    target_root: Path,
    output: Path,
) -> int:
    return module.main(
        [
            "--source-root",
            str(source_root.resolve()),
            "--target-root",
            str(target_root.resolve()),
            "--output",
            str(output.resolve()),
        ]
    )


def test_installs_only_verified_contract_dependency_closure_and_replays(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_root = (tmp_path / "source").resolve()
    target_root = (tmp_path / "target").resolve()
    output = (target_root / "operational-contract-install.json").resolve()
    _selected_source(source_root)
    (source_root / "database").mkdir()
    (source_root / "database" / "must-not-copy.sqlite3").write_bytes(b"secret")

    assert _run(
        source_root=source_root,
        target_root=target_root,
        output=output,
    ) == 0
    first_stdout = json.loads(capsys.readouterr().out)
    first_bytes = output.read_bytes()
    assert _run(
        source_root=source_root,
        target_root=target_root,
        output=output,
    ) == 0
    replay_stdout = json.loads(capsys.readouterr().out)

    settlement = load_selected_live_read_contract(target_root)
    daily = load_selected_daily_read_contract(target_root)
    evidence = json.loads(output.read_text(encoding="utf-8"))
    assert first_stdout == replay_stdout
    assert first_bytes == output.read_bytes()
    assert evidence["classification"] == "operational_only"
    assert evidence["settlement_selection_sha256"] == settlement.selection_sha256
    assert evidence["daily_selection_sha256"] == daily.selection_sha256
    assert evidence["platform_write_authorization"] is False
    assert evidence["credential_material_retained"] is False
    assert evidence["copied_files"]
    assert not (target_root / "database" / "must-not-copy.sqlite3").exists()


def test_rejects_source_tampering_or_missing_dependency(tmp_path: Path) -> None:
    source_root = (tmp_path / "source").resolve()
    _selected_source(source_root)
    settlement = load_selected_live_read_contract(source_root)
    contract_path = (
        source_root
        / "platform-read-contract"
        / f"{settlement.manifest.canonical_sha256}.json"
    )
    contract_path.write_bytes(contract_path.read_bytes() + b"\n")
    with pytest.raises(module.OperationalContractInstallError):
        _run(
            source_root=source_root,
            target_root=(tmp_path / "target-one").resolve(),
            output=(tmp_path / "target-one" / "install.json").resolve(),
        )

    other_source = (tmp_path / "other-source").resolve()
    _selected_source(other_source)
    daily = load_selected_daily_read_contract(other_source)
    evidence_path = (
        other_source
        / "daily-platform-read-contract-evidence"
        / f"{daily.freeze_evidence_sha256}.json"
    )
    evidence_path.unlink()
    with pytest.raises(module.OperationalContractInstallError):
        _run(
            source_root=other_source,
            target_root=(tmp_path / "target-two").resolve(),
            output=(tmp_path / "target-two" / "install.json").resolve(),
        )


def test_rejects_conflicting_target_without_overwrite(tmp_path: Path) -> None:
    source_root = (tmp_path / "source").resolve()
    target_root = (tmp_path / "target").resolve()
    output = (target_root / "install.json").resolve()
    _selected_source(source_root)
    target_pointer = target_root / "platform-read-contract" / "active-candidate.json"
    target_pointer.parent.mkdir(parents=True)
    target_pointer.write_bytes(b"{}\n")

    with pytest.raises(module.OperationalContractInstallError, match="conflict"):
        _run(
            source_root=source_root,
            target_root=target_root,
            output=output,
        )
    assert target_pointer.read_bytes() == b"{}\n"
    assert not output.exists()


def test_rejects_relative_paths_and_reparse_points(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(SystemExit):
        module.main(
            [
                "--source-root",
                "relative",
                "--target-root",
                str((tmp_path / "target").resolve()),
                "--output",
                str((tmp_path / "output.json").resolve()),
            ]
        )

    source_root = (tmp_path / "source").resolve()
    target_root = (tmp_path / "target").resolve()
    _selected_source(source_root)
    original = module._is_reparse_point
    monkeypatch.setattr(
        module,
        "_is_reparse_point",
        lambda path: path == source_root or original(path),
    )
    with pytest.raises(module.OperationalContractInstallError, match="reparse"):
        _run(
            source_root=source_root,
            target_root=target_root,
            output=(target_root / "install.json").resolve(),
        )
