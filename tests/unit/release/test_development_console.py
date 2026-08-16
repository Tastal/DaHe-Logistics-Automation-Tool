from __future__ import annotations

from pathlib import Path

from dahe import __version__
from dahe.release.development_console import (
    _development_environment,
    _is_expected_development_service,
    _server_command,
)


def test_development_identity_accepts_only_ready_current_source() -> None:
    assert _is_expected_development_service(
        {
            "ready": True,
            "application_version": __version__,
            "build_git_commit": "development",
        }
    )
    assert not _is_expected_development_service(
        {
            "ready": True,
            "application_version": __version__,
            "build_git_commit": "a" * 40,
        }
    )
    assert not _is_expected_development_service(None)


def test_development_server_uses_fixed_read_only_profile(tmp_path: Path) -> None:
    project = tmp_path / "project"
    python = project / ".venv" / "Scripts" / "python.exe"
    python.parent.mkdir(parents=True)
    python.write_bytes(b"python")
    data_root = tmp_path / "data"

    command = _server_command(project_root=project, data_root=data_root)

    assert command[0] == str(python)
    assert "--production-read-only" in command
    assert command[-1] == "--no-browser"
    assert "--enable-chengfeng-shadow" not in command
    assert "--enable-test-fixtures" not in command


def test_development_environment_uses_only_isolated_runtime_roots(
    tmp_path: Path,
) -> None:
    environment = _development_environment(runtime_root=tmp_path / "runtimes")

    assert environment["DAHE_BROWSER_RUNTIME_ROOT"] == str(
        tmp_path / "runtimes" / "browser"
    )
    assert environment["DAHE_OCR_RUNTIME_ROOT"] == str(tmp_path / "runtimes")
