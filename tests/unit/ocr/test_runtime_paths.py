from __future__ import annotations

from pathlib import Path

import pytest

from dahe.adapters.ocr.runtime_paths import (
    OcrRuntimePathError,
    choose_ocr_runtime_root,
)


def test_ascii_repository_uses_ignored_local_runtime_by_default() -> None:
    root = choose_ocr_runtime_root(
        repository_root=Path("C:/work/DaHe"),
        environ={},
        windows=True,
    )

    assert root == Path("C:/work/DaHe/.runtime")


def test_unicode_repository_falls_back_to_ascii_local_app_install_root() -> None:
    root = choose_ocr_runtime_root(
        repository_root=Path("C:/work/开发/DaHe"),
        environ={"LOCALAPPDATA": "C:/Users/operator/AppData/Local"},
        windows=True,
    )

    assert root == Path(
        "C:/Users/operator/AppData/Local/Programs/DaHeLogistics/ocr-runtime"
    )


def test_runtime_consumer_skips_unpublished_repository_runtime(
    tmp_path: Path,
) -> None:
    repository_root = tmp_path / "release" / "DaHeLogistics"
    repository_root.mkdir(parents=True)
    local_app_data = tmp_path / "local-app-data"
    installed_runtime = (
        local_app_data / "Programs" / "DaHeLogistics" / "ocr-runtime"
    )
    installed_runtime.mkdir(parents=True)
    (installed_runtime / "active-composition.json").write_text(
        "{}",
        encoding="utf-8",
    )

    root = choose_ocr_runtime_root(
        repository_root=repository_root,
        environ={"LOCALAPPDATA": str(local_app_data)},
        windows=True,
        require_active_composition=True,
    )

    assert root == installed_runtime


def test_explicit_unicode_runtime_root_is_rejected_on_windows() -> None:
    with pytest.raises(OcrRuntimePathError, match="ASCII"):
        choose_ocr_runtime_root(
            repository_root=Path("C:/work/DaHe"),
            explicit_root=Path("C:/运行时"),
            environ={},
            windows=True,
        )


def test_no_portable_windows_root_requires_manual_selection() -> None:
    with pytest.raises(OcrRuntimePathError, match="--runtime-root"):
        choose_ocr_runtime_root(
            repository_root=Path("C:/开发/DaHe"),
            environ={"LOCALAPPDATA": "C:/用户/本地"},
            windows=True,
        )
