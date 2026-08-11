from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest

from tools import loop9_validate_daily_snapshots as module


@dataclass(frozen=True)
class _FakeRuntime:
    data_root: Path
    project_root: Path
    instance_id: str
    closed: list[bool]

    def close(self) -> None:
        self.closed.append(True)


def _successful_arguments(data_root: Path) -> list[str]:
    return [
        "--data-root",
        str(data_root),
        "--snapshot-id",
        "snapshot-1",
        "--snapshot-id",
        "snapshot-2",
        "--snapshot-id",
        "snapshot-3",
        "--output",
        str(data_root / "verification" / "daily-triplet.json"),
    ]


def _install_success_fakes(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[bool], list[str]]:
    closed: list[bool] = []
    loaded_ids: list[str] = []
    authorities = {
        snapshot_id: SimpleNamespace(
            snapshot=SimpleNamespace(
                source_contract_sha256="a" * 64,
            ),
        )
        for snapshot_id in ("snapshot-1", "snapshot-2", "snapshot-3")
    }

    def runtime_factory(
        *,
        data_root: Path,
        project_root: Path,
        instance_id: str,
    ) -> _FakeRuntime:
        assert data_root.is_absolute()
        assert project_root == module.ROOT
        assert instance_id.startswith("loop9-daily-validator-")
        return _FakeRuntime(
            data_root=data_root,
            project_root=project_root,
            instance_id=instance_id,
            closed=closed,
        )

    class FakeStore:
        def __init__(self, runtime: _FakeRuntime) -> None:
            assert runtime.data_root.is_absolute()

        def get_formal_snapshot_authority(
            self,
            snapshot_id: str,
        ) -> object:
            loaded_ids.append(snapshot_id)
            return authorities[snapshot_id]

    def validate(
        received: tuple[object, ...],
        *,
        build_sha256: str,
        expected_contract_sha256: str,
        contract_selection: object,
    ) -> dict[str, object]:
        assert received == tuple(authorities.values())
        assert build_sha256 == "b" * 64
        assert expected_contract_sha256 == "a" * 64
        assert contract_selection.to_payload() == {
            "contract_canonical_sha256": "a" * 64,
            "contract_file_sha256": "d" * 64,
            "freeze_evidence_sha256": "e" * 64,
            "selection_sha256": "f" * 64,
            "source_discovery_sha256": "1" * 64,
        }
        return {
            "candidate_count": 7,
            "canonical_sha256": "c" * 64,
            "snapshot_count": 3,
        }

    monkeypatch.setattr(module, "SqliteRuntime", runtime_factory)
    monkeypatch.setattr(module, "SqliteDailyStore", FakeStore)
    monkeypatch.setattr(module, "validate_daily_snapshot_triplet", validate)
    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        lambda _root: SimpleNamespace(
            manifest=SimpleNamespace(
                canonical_sha256="a" * 64,
                source_discovery_sha256="1" * 64,
            ),
            contract_file_sha256="d" * 64,
            freeze_evidence_sha256="e" * 64,
            selection_sha256="f" * 64,
        ),
    )
    monkeypatch.setattr(
        module,
        "current_loop9_build_sha256",
        lambda _root: "b" * 64,
    )
    return closed, loaded_ids


def test_cli_fails_closed_when_selected_daily_contract_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    opened = False

    def unavailable(_root: Path) -> object:
        raise module.DailyContractSelectionError(
            "daily contract selection is unavailable"
        )

    def forbidden_runtime(**_values: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("SQLite must not open without a selected contract")

    monkeypatch.setattr(
        module,
        "load_selected_daily_read_contract",
        unavailable,
    )
    monkeypatch.setattr(module, "SqliteRuntime", forbidden_runtime)

    with pytest.raises(
        module.DailySnapshotValidationToolError,
        match="selected daily contract",
    ):
        module.main(_successful_arguments(data_root))

    assert opened is False


def test_cli_writes_one_exclusive_evidence_file_inside_absolute_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    closed, loaded_ids = _install_success_fakes(monkeypatch)
    arguments = _successful_arguments(data_root)

    assert module.main(arguments) == 0

    output = data_root / "verification" / "daily-triplet.json"
    assert json.loads(output.read_text(encoding="utf-8")) == {
        "candidate_count": 7,
        "canonical_sha256": "c" * 64,
        "snapshot_count": 3,
    }
    assert loaded_ids == ["snapshot-1", "snapshot-2", "snapshot-3"]
    assert closed == [True]
    assert json.loads(capsys.readouterr().out) == {
        "candidate_count": 7,
        "evidence_sha256": "c" * 64,
        "output": "daily-triplet.json",
        "snapshot_count": 3,
    }


@pytest.mark.parametrize("snapshot_count", [0, 1, 2, 4])
def test_cli_requires_exactly_three_snapshot_ids_before_opening_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    snapshot_count: int,
) -> None:
    data_root = tmp_path.resolve()
    arguments = [
        "--data-root",
        str(data_root),
        "--output",
        str(data_root / "daily-triplet.json"),
    ]
    for index in range(snapshot_count):
        arguments[2:2] = ["--snapshot-id", f"snapshot-{index}"]
    opened = False

    def forbidden_runtime(**_values: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("SQLite must not open for an invalid ID count")

    monkeypatch.setattr(module, "SqliteRuntime", forbidden_runtime)

    expected = SystemExit if snapshot_count == 0 else module.DailySnapshotValidationToolError
    with pytest.raises(expected):
        module.main(arguments)
    assert opened is False


def test_cli_refuses_non_project_python_before_parsing_or_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path.resolve()
    output = data_root / "daily-triplet.json"
    monkeypatch.setattr(
        module.sys,
        "executable",
        str(tmp_path / "unrelated-python.exe"),
    )

    with pytest.raises(SystemExit, match=r"project \.venv Python"):
        module.main(_successful_arguments(data_root))

    assert not output.exists()


def test_cli_refuses_existing_output_without_opening_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path.resolve()
    output = data_root / "verification" / "daily-triplet.json"
    output.parent.mkdir()
    output.write_text("original", encoding="utf-8")
    opened = False

    def forbidden_runtime(**_values: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("SQLite must not open when output exists")

    monkeypatch.setattr(module, "SqliteRuntime", forbidden_runtime)

    with pytest.raises(
        module.DailySnapshotValidationToolError,
        match="already exists",
    ):
        module.main(_successful_arguments(data_root))

    assert output.read_text(encoding="utf-8") == "original"
    assert opened is False


def test_cli_refuses_output_outside_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    outside = (tmp_path / "outside" / "daily-triplet.json").resolve()
    data_root.mkdir()
    arguments = _successful_arguments(data_root)
    arguments[-1] = str(outside)
    opened = False

    def forbidden_runtime(**_values: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("SQLite must not open for an outside output")

    monkeypatch.setattr(module, "SqliteRuntime", forbidden_runtime)

    with pytest.raises(
        module.DailySnapshotValidationToolError,
        match="inside the data root",
    ):
        module.main(arguments)

    assert not outside.exists()
    assert opened is False


def test_cli_refuses_symlinked_data_root_before_opening_sqlite(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    data_root.mkdir()
    original_is_symlink = Path.is_symlink
    opened = False

    def report_data_root_as_symlink(path: Path) -> bool:
        return path == data_root or original_is_symlink(path)

    def forbidden_runtime(**_values: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("SQLite must not open for a symlinked root")

    monkeypatch.setattr(Path, "is_symlink", report_data_root_as_symlink)
    monkeypatch.setattr(module, "SqliteRuntime", forbidden_runtime)

    with pytest.raises(
        module.DailySnapshotValidationToolError,
        match="real directory",
    ):
        module.main(_successful_arguments(data_root))

    assert opened is False


def test_cli_refuses_symlinked_output_parent_when_supported(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    real_parent = (data_root / "real").resolve()
    linked_parent = data_root / "linked"
    real_parent.mkdir(parents=True)
    try:
        linked_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError as error:
        pytest.skip(f"directory symlinks are unavailable: {error}")
    arguments = _successful_arguments(data_root)
    arguments[-1] = str(linked_parent / "daily-triplet.json")
    opened = False

    def forbidden_runtime(**_values: object) -> object:
        nonlocal opened
        opened = True
        raise AssertionError("SQLite must not open for a symlinked output")

    monkeypatch.setattr(module, "SqliteRuntime", forbidden_runtime)

    with pytest.raises(
        module.DailySnapshotValidationToolError,
        match="real directory",
    ):
        module.main(arguments)

    assert not (real_parent / "daily-triplet.json").exists()
    assert opened is False


def test_atomic_publication_collision_never_replaces_racing_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "daily-triplet.json"
    original_link = os.link

    def collide(_temporary: Path, target: Path) -> None:
        Path(target).write_text("racing-writer", encoding="utf-8")
        raise FileExistsError

    monkeypatch.setattr(module.os, "link", collide)

    with pytest.raises(
        module.DailySnapshotValidationToolError,
        match="already exists",
    ):
        module._write_exclusive_atomic(
            output,
            {
                "canonical_sha256": "c" * 64,
            },
        )

    assert output.read_text(encoding="utf-8") == "racing-writer"
    assert tuple(tmp_path.glob(".*.tmp")) == ()
    assert os.link is not original_link


def test_cli_rejects_relative_data_root_and_output(
    tmp_path: Path,
) -> None:
    arguments = _successful_arguments(tmp_path.resolve())
    arguments[1] = "relative-data"
    with pytest.raises(SystemExit):
        module.main(arguments)

    arguments = _successful_arguments(tmp_path.resolve())
    arguments[-1] = "relative-output.json"
    with pytest.raises(SystemExit):
        module.main(arguments)
