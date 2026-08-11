from __future__ import annotations

import socket
from pathlib import Path

import pytest

from dahe.bootstrap import run_startup_check
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.environment import VirtualEnvironmentError, assert_project_venv


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def test_startup_check_writes_only_below_explicit_test_root(
    project_root: Path,
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    config = AppConfig(
        runtime_profile=RuntimeProfile.TEST,
        data_root=data_root,
        port=_free_port(),
    )

    report = run_startup_check(config=config, project_root=project_root)

    assert report.application_id == "DaHeLogistics"
    assert report.real_platform_access is False
    assert report.external_connections == 0
    assert Path(report.data_root).resolve() == data_root.resolve()
    assert all(path.is_relative_to(data_root.resolve()) for path in data_root.rglob("*"))
    assert not list(project_root.glob("*.sqlite*"))


def test_startup_check_never_opens_outbound_connection(
    project_root: Path,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    attempts: list[object] = []

    def reject_connect(*args: object, **kwargs: object) -> None:
        attempts.append((args, kwargs))
        raise AssertionError("outbound connect is forbidden")

    monkeypatch.setattr(socket.socket, "connect", reject_connect)
    config = AppConfig(
        runtime_profile=RuntimeProfile.TEST,
        data_root=tmp_path / "data",
        port=_free_port(),
    )

    report = run_startup_check(config=config, project_root=project_root)
    assert report.external_connections == 0
    assert attempts == []


def test_project_entry_rejects_non_project_python(project_root: Path) -> None:
    with pytest.raises(VirtualEnvironmentError):
        assert_project_venv(
            project_root=project_root,
            executable=Path("C:/Python312/python.exe"),
        )
