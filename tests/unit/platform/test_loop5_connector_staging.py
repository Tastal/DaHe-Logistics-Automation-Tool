from __future__ import annotations

from pathlib import Path

import pytest

from dahe.adapters.chengfeng.connector_staging import (
    ConnectorStagingError,
    begin_command_staging,
    cleanup_command_staging,
    command_staging_directory_name,
    recover_connector_staging,
)


def _stage(data_root: Path, command_id: str, content: bytes = b"payload") -> Path:
    directory = (
        data_root
        / "connector-staging"
        / command_staging_directory_name(command_id)
    )
    directory.mkdir(parents=True)
    (directory / "payload.json").write_bytes(content)
    return directory


def test_command_cleanup_removes_only_the_named_command_directory(tmp_path: Path) -> None:
    first = _stage(tmp_path, "cmd-first")
    second = _stage(tmp_path, "cmd-second")

    assert cleanup_command_staging(data_root=tmp_path, command_id="cmd-first") is True

    assert not first.exists()
    assert second.is_dir()
    assert cleanup_command_staging(data_root=tmp_path, command_id="cmd-missing") is False


def test_startup_recovery_removes_safe_orphan_command_directories(tmp_path: Path) -> None:
    _stage(tmp_path, "cmd-orphan-one")
    _stage(tmp_path, "cmd-orphan-two", b"other")

    report = recover_connector_staging(tmp_path)

    assert report.removed_command_directories == 2
    assert report.retained_active_directories == 0
    assert tuple((tmp_path / "connector-staging").iterdir()) == ()


def test_recovery_retains_a_command_active_in_this_process(tmp_path: Path) -> None:
    active = begin_command_staging(data_root=tmp_path, command_id="cmd-active")
    (active / "payload.json").write_bytes(b"active")

    report = recover_connector_staging(tmp_path)

    assert report.removed_command_directories == 0
    assert report.retained_active_directories == 1
    assert active.is_dir()
    assert cleanup_command_staging(data_root=tmp_path, command_id="cmd-active") is True


def test_recovery_refuses_unknown_or_nested_staging_entries(tmp_path: Path) -> None:
    staging_root = tmp_path / "connector-staging"
    staging_root.mkdir(parents=True)
    (staging_root / "unknown.txt").write_text("keep", encoding="utf-8")

    with pytest.raises(ConnectorStagingError, match="unknown"):
        recover_connector_staging(tmp_path)
    assert (staging_root / "unknown.txt").is_file()

    (staging_root / "unknown.txt").unlink()
    command_directory = _stage(tmp_path, "cmd-nested")
    (command_directory / "unexpected").mkdir()
    with pytest.raises(ConnectorStagingError, match="unsafe"):
        recover_connector_staging(tmp_path)
    assert command_directory.is_dir()
