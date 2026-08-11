from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from dahe.api.app import create_app
from dahe.bootstrap import StartupCheckError
from dahe.cli import run
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.server import run_local_console


def test_cli_wires_the_loop9_scheduler_probe_without_generic_fixtures(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    captured: list[dict[str, object]] = []

    def capture_console(**kwargs: object) -> None:
        captured.append(dict(kwargs))

    monkeypatch.setattr("dahe.server.run_local_console", capture_console)

    result = run(
        [
            "--serve",
            "--no-browser",
            "--data-root",
            str(tmp_path / "shadow-data"),
            "--enable-chengfeng-shadow",
            "--enable-loop9-scheduler-probe",
        ]
    )

    assert result == 0
    assert captured[0]["enable_chengfeng_shadow"] is True
    assert captured[0]["enable_loop9_scheduler_probe"] is True
    assert captured[0]["enable_test_fixtures"] is False


@pytest.mark.parametrize(
    ("arguments", "message"),
    [
        (
            [
                "--serve",
                "--data-root",
                "C:/loop9-probe",
                "--enable-loop9-scheduler-probe",
            ],
            "--enable-chengfeng-shadow",
        ),
        (
            [
                "--check",
                "--data-root",
                "C:/loop9-probe",
                "--enable-chengfeng-shadow",
                "--enable-loop9-scheduler-probe",
            ],
            "--serve",
        ),
        (
            [
                "--serve",
                "--enable-chengfeng-shadow",
                "--enable-loop9-scheduler-probe",
            ],
            "--data-root",
        ),
        (
            [
                "--serve",
                "--data-root",
                "C:/loop9-probe",
                "--enable-chengfeng-shadow",
                "--enable-loop9-scheduler-probe",
                "--enable-test-fixtures",
            ],
            "without test or maintenance modes",
        ),
        (
            [
                "--serve",
                "--data-root",
                "C:/loop9-probe",
                "--enable-chengfeng-shadow",
                "--enable-loop9-scheduler-probe",
                "--enable-template-studio",
            ],
            "without test or maintenance modes",
        ),
        (
            [
                "--serve",
                "--data-root",
                "C:/loop9-probe",
                "--enable-chengfeng-shadow",
                "--enable-loop9-scheduler-probe",
                "--enable-locked-set-review",
            ],
            "without test or maintenance modes",
        ),
    ],
)
def test_cli_rejects_unsafe_loop9_scheduler_probe_combinations(
    arguments: list[str],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as raised:
        run(arguments)

    assert raised.value.code == 2
    assert message in capsys.readouterr().err


def test_server_wires_probe_to_app_without_claiming_a_fixture_data_root(
    monkeypatch: pytest.MonkeyPatch,
    project_root: Path,
    tmp_path: Path,
) -> None:
    captured_app: list[dict[str, object]] = []
    fixture_root_modes: list[bool] = []

    class _InstanceGuard:
        instance_id = "loop9-scheduler-probe"
        previous_instance_id = None

        def __enter__(self) -> _InstanceGuard:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    class _Reservation:
        host = "127.0.0.1"
        port = 8877
        socket = object()

        def __enter__(self) -> _Reservation:
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setattr(
        "dahe.server.prepare_startup_environment",
        lambda config, root: tmp_path / "shadow-data",
    )
    monkeypatch.setattr(
        "dahe.server.SingleInstanceGuard",
        lambda *args, **kwargs: _InstanceGuard(),
    )
    monkeypatch.setattr(
        "dahe.server.reserve_loopback_port",
        lambda *args, **kwargs: _Reservation(),
    )
    monkeypatch.setattr(
        "dahe.server.enforce_test_fixture_root",
        lambda data_root, *, fixtures_enabled: fixture_root_modes.append(
            fixtures_enabled
        ),
    )
    monkeypatch.setattr(
        "dahe.server.runtime_loop9_build_sha256",
        lambda root: "a" * 64,
    )

    def capture_create_app(**kwargs: Any) -> object:
        captured_app.append(dict(kwargs))
        return object()

    monkeypatch.setattr("dahe.server.create_app", capture_create_app)
    monkeypatch.setattr(
        "dahe.server.uvicorn.Server",
        lambda config: SimpleNamespace(
            started=False,
            should_exit=False,
            run=lambda **kwargs: None,
        ),
    )
    monkeypatch.setattr(
        "dahe.server.uvicorn.Config",
        lambda *args, **kwargs: object(),
    )

    run_local_console(
        config=AppConfig(
            runtime_profile=RuntimeProfile.TEST,
            data_root=tmp_path / "shadow-data",
        ),
        project_root=project_root,
        open_browser=False,
        enable_chengfeng_shadow=True,
        enable_loop9_scheduler_probe=True,
    )

    assert fixture_root_modes == [False]
    assert captured_app[0]["enable_chengfeng_shadow"] is True
    assert captured_app[0]["enable_loop9_scheduler_probe"] is True
    assert captured_app[0]["enable_test_fixtures"] is False
    assert captured_app[0]["platform_build_sha256"] == "a" * 64


def test_server_rejects_probe_without_shadow_or_explicit_data_root(
    project_root: Path,
    tmp_path: Path,
) -> None:
    with pytest.raises(StartupCheckError, match="requires Chengfeng shadow"):
        run_local_console(
            config=AppConfig(
                runtime_profile=RuntimeProfile.TEST,
                data_root=tmp_path / "probe",
            ),
            project_root=project_root,
            open_browser=False,
            enable_loop9_scheduler_probe=True,
        )

    with pytest.raises(StartupCheckError, match="explicit data root"):
        run_local_console(
            config=AppConfig(runtime_profile=RuntimeProfile.DEVELOPMENT),
            project_root=project_root,
            open_browser=False,
            enable_chengfeng_shadow=True,
            enable_loop9_scheduler_probe=True,
        )


def test_app_rejects_probe_outside_exclusive_shadow_mode(
    project_root: Path,
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="requires Chengfeng shadow"):
        create_app(
            data_root=tmp_path / "data",
            project_root=project_root,
            instance_id="loop9-probe-invalid",
            auto_run_jobs=False,
            stage_delay_seconds=0,
            enable_loop9_scheduler_probe=True,
        )
    with pytest.raises(ValueError, match="generic test fixtures"):
        create_app(
            data_root=tmp_path / "data",
            project_root=project_root,
            instance_id="loop9-probe-invalid",
            auto_run_jobs=False,
            stage_delay_seconds=0,
            enable_chengfeng_shadow=True,
            enable_loop9_scheduler_probe=True,
            enable_test_fixtures=True,
            platform_build_sha256="a" * 64,
        )
