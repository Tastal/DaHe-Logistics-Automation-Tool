from __future__ import annotations

from pathlib import Path

import pytest

from dahe.config.paths import (
    ConfigurationPathError,
    prepare_application_paths,
    resolve_data_root,
    safe_child,
)
from dahe.config.schema import AppConfig, RuntimeProfile


def test_default_data_root_comes_only_from_local_app_data(tmp_path: Path) -> None:
    config = AppConfig()
    root = resolve_data_root(config, environ={"LOCALAPPDATA": str(tmp_path)})
    assert root == (tmp_path / "DaHeLogistics").resolve()


def test_missing_local_app_data_fails_without_cwd_fallback() -> None:
    with pytest.raises(ConfigurationPathError, match="LOCALAPPDATA"):
        resolve_data_root(AppConfig(), environ={})


def test_test_profile_uses_only_explicit_temporary_root(tmp_path: Path) -> None:
    config = AppConfig(runtime_profile=RuntimeProfile.TEST, data_root=tmp_path)
    assert resolve_data_root(config, environ={}) == tmp_path.resolve()


def test_application_paths_are_created_below_data_root(tmp_path: Path) -> None:
    paths = prepare_application_paths(tmp_path / "data")
    expected_names = {
        "database",
        "evidence",
        "browser-profile",
        "credentials",
        "logs",
        "backups",
        "quarantine",
        "runtime",
    }

    assert {path.name for path in paths.all_directories()} == expected_names
    assert all(path.is_dir() for path in paths.all_directories())
    assert all(path.is_relative_to(paths.root) for path in paths.all_directories())


def test_existing_file_cannot_be_used_as_data_root(tmp_path: Path) -> None:
    invalid_root = tmp_path / "not-a-directory"
    invalid_root.write_text("occupied", encoding="utf-8")

    with pytest.raises(ConfigurationPathError):
        prepare_application_paths(invalid_root)


@pytest.mark.parametrize("relative", ["../escape", "a/../../escape", "/absolute"])
def test_safe_child_rejects_path_escape(tmp_path: Path, relative: str) -> None:
    with pytest.raises(ConfigurationPathError):
        safe_child(tmp_path, relative)
