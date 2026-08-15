from __future__ import annotations

import sqlite3
from contextlib import AbstractContextManager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from dahe.api.app import create_app
from dahe.bootstrap import StartupCheckError
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrImageExecution,
    OcrImageWork,
    OcrRuntimeIdentity,
)
from dahe.server import _enforce_current_server_exit, run_local_console


@dataclass
class _InstanceGuard(AbstractContextManager["_InstanceGuard"]):
    instance_id: str = "loop6-standard-startup"
    previous_instance_id: str | None = None

    def __enter__(self) -> _InstanceGuard:
        return self

    def __exit__(self, *args: object) -> None:
        return None


@dataclass
class _Reservation(AbstractContextManager["_Reservation"]):
    host: str = "127.0.0.1"
    port: int = 8877
    socket: object = object()

    def __enter__(self) -> _Reservation:
        return self

    def __exit__(self, *args: object) -> None:
        return None


def test_shutdown_watchdog_hard_exits_only_a_still_running_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exit_codes: list[int] = []
    stopped_server = SimpleNamespace(started=False, force_exit=False)
    running_server = SimpleNamespace(started=True, force_exit=False)
    monkeypatch.setattr(
        "dahe.server.os._exit",
        lambda code: exit_codes.append(code),
    )

    _enforce_current_server_exit(stopped_server)
    assert stopped_server.force_exit is False
    assert exit_codes == []

    _enforce_current_server_exit(running_server)
    assert running_server.force_exit is True
    assert exit_codes == [0]


class _IdleGateway:
    def __init__(self) -> None:
        self.closed = False
        self._identity = OcrRuntimeIdentity(
            runtime_kind="cpu",
            profile_id="cpu-idle-test",
            runtime_fingerprint="a" * 64,
        )

    @property
    def identity(self) -> OcrRuntimeIdentity:
        return self._identity

    def extract(
        self,
        image: OcrImageWork,
        *,
        pipeline_fingerprint: str,
    ) -> OcrImageExecution:
        raise AssertionError(
            f"idle startup gateway unexpectedly received {image} {pipeline_fingerprint}"
        )

    def close(self) -> None:
        self.closed = True


def test_app_builds_backend_only_after_database_migration(
    project_root: Path,
    tmp_path: Path,
) -> None:
    gateway = _IdleGateway()
    backend = AsyncOcrExecutionBackend(
        primary_runtime_kind="cpu",
        gateways={"cpu": gateway},
    )
    factory_calls = 0

    def factory() -> AsyncOcrExecutionBackend:
        nonlocal factory_calls
        factory_calls += 1
        database = tmp_path / "database" / "dahe.sqlite3"
        with sqlite3.connect(database) as connection:
            revision = connection.execute("SELECT version_num FROM alembic_version").fetchone()
        assert revision == (
            "0042_daily_capture_range",
        )
        return backend

    app = create_app(
        data_root=tmp_path,
        project_root=project_root,
        instance_id="loop6-lazy-factory",
        auto_run_jobs=False,
        stage_delay_seconds=0,
        ocr_execution_backend_factory=factory,
    )
    with TestClient(app):
        meta_route = next(
            route for route in app.routes if getattr(route, "path", None) == "/api/v1/meta"
        )
        assert meta_route.endpoint()["ocr_adapter"] == "local"

    assert factory_calls == 1
    assert gateway.closed is True


def test_standard_console_composes_verified_local_ocr_backend(
    monkeypatch: pytest.MonkeyPatch,
    project_root: Path,
    tmp_path: Path,
) -> None:
    backend = object()
    calls: list[tuple[str, object]] = []
    app_state = SimpleNamespace(request_shutdown=None)
    servers: list[object] = []

    monkeypatch.setattr(
        "dahe.server.prepare_startup_environment",
        lambda config, root: tmp_path / "data",
    )
    monkeypatch.setattr(
        "dahe.server.SingleInstanceGuard",
        lambda *args, **kwargs: _InstanceGuard(),
    )
    monkeypatch.setattr(
        "dahe.server.reserve_loopback_port",
        lambda *args, **kwargs: _Reservation(),
    )

    def build_backend(**kwargs: object) -> object:
        calls.append(("build", kwargs))
        return backend

    def create_app(**kwargs: Any) -> object:
        factory = kwargs["ocr_execution_backend_factory"]
        calls.append(("factory", factory()))
        return SimpleNamespace(state=app_state)

    class _Server:
        started = False
        should_exit = False

        def __init__(self, config: object) -> None:
            calls.append(("server", config))
            servers.append(self)

        def run(self, *, sockets: list[object]) -> None:
            calls.append(("run", sockets))

    monkeypatch.setattr("dahe.server.build_ocr_execution_backend", build_backend)
    monkeypatch.setattr("dahe.server.create_app", create_app)
    monkeypatch.setattr("dahe.server.uvicorn.Server", _Server)
    monkeypatch.setattr(
        "dahe.server.uvicorn.Config",
        lambda *args, **kwargs: SimpleNamespace(args=args, kwargs=kwargs),
    )

    run_local_console(
        config=AppConfig(
            runtime_profile=RuntimeProfile.TEST,
            data_root=tmp_path / "data",
        ),
        project_root=project_root,
        open_browser=False,
    )

    assert [name for name, _ in calls].count("build") == 1
    assert ("factory", backend) in calls
    assert callable(app_state.request_shutdown)
    app_state.request_shutdown()
    assert servers[0].should_exit is True
    build_kwargs = next(value for name, value in calls if name == "build")
    assert isinstance(build_kwargs.pop("runtime_log_store"), RuntimeLogStore)
    assert build_kwargs == {
        "config": AppConfig(
            runtime_profile=RuntimeProfile.TEST,
            data_root=tmp_path / "data",
        ),
        "repository_root": project_root,
    }


def test_protected_fake_fixture_console_does_not_start_local_workers(
    monkeypatch: pytest.MonkeyPatch,
    project_root: Path,
    tmp_path: Path,
) -> None:
    captured_factory: list[object] = []

    monkeypatch.setattr(
        "dahe.server.prepare_startup_environment",
        lambda config, root: tmp_path / "data",
    )
    monkeypatch.setattr(
        "dahe.server.SingleInstanceGuard",
        lambda *args, **kwargs: _InstanceGuard(),
    )
    monkeypatch.setattr(
        "dahe.server.reserve_loopback_port",
        lambda *args, **kwargs: _Reservation(),
    )

    def capture_create_app(**kwargs: object) -> object:
        captured_factory.append(kwargs["ocr_execution_backend_factory"])
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
            data_root=tmp_path / "data",
        ),
        project_root=project_root,
        open_browser=False,
        enable_test_fixtures=True,
    )

    assert captured_factory == [None]


def test_locked_set_review_console_does_not_construct_an_ocr_backend(
    monkeypatch: pytest.MonkeyPatch,
    project_root: Path,
    tmp_path: Path,
) -> None:
    captured: list[dict[str, object]] = []

    monkeypatch.setattr(
        "dahe.server.prepare_startup_environment",
        lambda config, root: tmp_path / "data",
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
        "dahe.server.build_ocr_execution_backend",
        lambda **kwargs: pytest.fail(
            "locked-set review must not construct OCR"
        ),
    )

    def capture_create_app(**kwargs: object) -> object:
        captured.append(kwargs)
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
            data_root=tmp_path / "data",
        ),
        project_root=project_root,
        open_browser=False,
        enable_locked_set_review=True,
    )

    assert captured[0]["ocr_execution_backend_factory"] is None
    assert captured[0]["enable_locked_set_review"] is True
    assert "locked_set_reviewer_id" not in captured[0]


def test_loop9_review_console_is_offline_and_passes_only_its_package(
    monkeypatch: pytest.MonkeyPatch,
    project_root: Path,
    tmp_path: Path,
) -> None:
    captured: list[dict[str, object]] = []
    package_path = (tmp_path / "immutable-loop9-package").resolve()
    package_path.mkdir()

    monkeypatch.setattr(
        "dahe.server.prepare_startup_environment",
        lambda config, root: tmp_path / "data",
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
        "dahe.server.build_ocr_execution_backend",
        lambda **kwargs: pytest.fail(
            "Loop 9 offline review must not construct OCR"
        ),
    )

    def capture_create_app(**kwargs: object) -> object:
        captured.append(kwargs)
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
            data_root=tmp_path / "data",
        ),
        project_root=project_root,
        open_browser=False,
        loop9_review_package_path=package_path,
    )

    assert captured[0]["ocr_execution_backend_factory"] is None
    assert captured[0]["loop9_review_package_path"] == package_path
    assert captured[0]["enable_chengfeng_shadow"] is False


def test_loop9_review_console_rejects_chengfeng_shadow(
    project_root: Path,
    tmp_path: Path,
) -> None:
    with pytest.raises(StartupCheckError, match="must run alone"):
        run_local_console(
            config=AppConfig(
                runtime_profile=RuntimeProfile.TEST,
                data_root=tmp_path / "data",
            ),
            project_root=project_root,
            open_browser=False,
            enable_chengfeng_shadow=True,
            loop9_review_package_path=(
                tmp_path / "immutable-loop9-package"
            ).resolve(),
        )


def test_template_studio_uses_an_ephemeral_terminal_access_code(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    project_root: Path,
    tmp_path: Path,
) -> None:
    captured: list[dict[str, object]] = []

    monkeypatch.setattr(
        "dahe.server.prepare_startup_environment",
        lambda config, root: tmp_path / "data",
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
        "dahe.server.secrets.token_urlsafe",
        lambda length: f"ephemeral-{length}",
    )

    def capture_create_app(**kwargs: object) -> object:
        captured.append(kwargs)
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
            data_root=tmp_path / "data",
        ),
        project_root=project_root,
        open_browser=False,
        enable_template_studio=True,
    )

    assert captured[0]["developer_access_code"] == "ephemeral-8"
    assert "Template maintenance access code: ephemeral-8" in capsys.readouterr().out
