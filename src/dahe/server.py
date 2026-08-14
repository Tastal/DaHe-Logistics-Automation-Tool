from __future__ import annotations

import os
import secrets
import threading
import time
import webbrowser
from pathlib import Path

import uvicorn

from dahe import __version__
from dahe.adapters.ocr.runtime_factory import (
    OcrRuntimeCompositionError,
    build_ocr_execution_backend,
)
from dahe.adapters.sqlite.runtime import DatabaseMigrationError
from dahe.api.app import create_app
from dahe.bootstrap import StartupCheckError, prepare_startup_environment
from dahe.config.schema import AppConfig
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.release.update_service import UpdateService
from dahe.system.instance_lock import SingleInstanceGuard
from dahe.system.port_guard import reserve_loopback_port
from dahe.system.test_fixture_root import (
    FixtureDataRootError,
    enforce_test_fixture_root,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewPackageError,
)
from dahe.verification.loop9_build import runtime_loop9_build_sha256
from dahe.verification.loop9_human_review import Loop9HumanReviewError


def _open_default_browser_when_ready(server: uvicorn.Server, url: str) -> None:
    for _ in range(200):
        if server.started:
            webbrowser.open(url, new=2)
            return
        if server.should_exit:
            return
        time.sleep(0.05)


def _enforce_current_server_exit(server: uvicorn.Server) -> None:
    """Terminate only this DaHe server after graceful shutdown times out."""

    if not server.started:
        return
    server.force_exit = True
    os._exit(0)


def run_local_console(
    *,
    config: AppConfig,
    project_root: Path,
    open_browser: bool,
    enable_test_fixtures: bool = False,
    enable_template_studio: bool = False,
    enable_locked_set_review: bool = False,
    enable_chengfeng_shadow: bool = False,
    production_read_only: bool = False,
    enable_loop9_scheduler_probe: bool = False,
    loop9_review_package_path: Path | None = None,
) -> None:
    """Run the local console while retaining its instance and port guards."""
    if enable_loop9_scheduler_probe and not enable_chengfeng_shadow:
        raise StartupCheckError(
            "Loop 9 scheduler probe requires Chengfeng shadow mode"
        )
    if production_read_only and enable_chengfeng_shadow:
        raise StartupCheckError(
            "production read-only mode cannot enable strict shadow mode"
        )
    if production_read_only and config.runtime_profile.value != "production":
        raise StartupCheckError(
            "production read-only mode requires the production profile"
        )
    if enable_loop9_scheduler_probe and config.data_root is None:
        raise StartupCheckError(
            "Loop 9 scheduler probe requires an explicit data root"
        )
    if enable_chengfeng_shadow and enable_test_fixtures:
        raise StartupCheckError(
            "Chengfeng shadow mode cannot enable generic test fixtures"
        )
    if enable_locked_set_review and (
        enable_test_fixtures or enable_template_studio
    ):
        raise StartupCheckError(
            "locked-set review mode must run alone without tuning or test modes"
        )
    if loop9_review_package_path is not None and (
        enable_chengfeng_shadow
        or enable_loop9_scheduler_probe
        or enable_locked_set_review
        or enable_test_fixtures
        or enable_template_studio
    ):
        raise StartupCheckError(
            "Loop 9 review mode must run alone without Chengfeng or runtime modes"
        )
    if (
        loop9_review_package_path is not None
        and not loop9_review_package_path.is_absolute()
    ):
        raise StartupCheckError(
            "Loop 9 review package path must be absolute"
        )
    if loop9_review_package_path is not None and config.data_root is None:
        raise StartupCheckError(
            "Loop 9 review mode requires an explicit data root"
        )
    data_root = prepare_startup_environment(config, project_root)
    try:
        enforce_test_fixture_root(
            data_root,
            fixtures_enabled=enable_test_fixtures,
        )
    except FixtureDataRootError as exc:
        raise StartupCheckError(str(exc)) from None
    static_dir = project_root / "frontend" / "dist"
    if not (static_dir / "index.html").is_file():
        raise StartupCheckError(
            "operator console build is missing; run the authoritative checks first"
        )

    with (
        SingleInstanceGuard(
            data_root,
            config.port,
            __version__,
        ) as instance_guard,
        reserve_loopback_port(config.host, config.port) as reservation,
    ):
        try:
            runtime_log_store = RuntimeLogStore(data_root / "logs")
            backend_factory = (
                None
                if (
                    enable_test_fixtures
                    or enable_locked_set_review
                    or loop9_review_package_path is not None
                )
                else lambda: build_ocr_execution_backend(
                    config=config,
                    repository_root=project_root,
                    runtime_log_store=runtime_log_store,
                )
            )
            developer_access_code = (
                secrets.token_urlsafe(8) if enable_template_studio else None
            )
            install_root = Path(
                os.environ.get("DAHE_INSTALL_ROOT", os.fspath(project_root))
            ).resolve()
            versioned_updater = project_root / "DaHeUpdater.exe"
            updater_path = (
                versioned_updater
                if versioned_updater.is_file()
                else install_root / "DaHeUpdater.exe"
            )
            update_service = (
                UpdateService(
                    current_version=__version__,
                    updater_version=__version__,
                    data_root=data_root,
                    updater_path=updater_path,
                )
                if production_read_only
                else None
            )
            app = create_app(
                data_root=data_root,
                project_root=project_root,
                instance_id=instance_guard.instance_id,
                previous_instance_id=instance_guard.previous_instance_id,
                auto_run_jobs=True,
                stage_delay_seconds=0.08,
                static_dir=static_dir,
                host=reservation.host,
                port=reservation.port,
                enable_test_fixtures=enable_test_fixtures,
                developer_access_code=developer_access_code,
                ocr_execution_backend_factory=backend_factory,
                enable_locked_set_review=enable_locked_set_review,
                runtime_log_store=runtime_log_store,
                enable_chengfeng_shadow=enable_chengfeng_shadow,
                production_read_only=production_read_only,
                enable_loop9_scheduler_probe=enable_loop9_scheduler_probe,
                loop9_review_package_path=loop9_review_package_path,
                platform_build_sha256=(
                    runtime_loop9_build_sha256(project_root)
                    if (enable_chengfeng_shadow or production_read_only)
                    else None
                ),
                update_service=update_service,
            )
        except (
            DatabaseMigrationError,
            LockedSetReviewPackageError,
            Loop9HumanReviewError,
            OcrRuntimeCompositionError,
        ) as exc:
            raise StartupCheckError(str(exc)) from None
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=reservation.host,
                port=reservation.port,
                access_log=False,
                log_level="info",
            )
        )

        def request_shutdown() -> None:
            server.should_exit = True
            watchdog = threading.Timer(
                5.0,
                _enforce_current_server_exit,
                args=(server,),
            )
            watchdog.name = "dahe-shutdown-watchdog"
            watchdog.daemon = True
            watchdog.start()

        app_state = getattr(app, "state", None)
        if app_state is not None:
            app_state.request_shutdown = request_shutdown
        if developer_access_code is not None:
            print(
                "Template maintenance access code: "
                f"{developer_access_code}",
                flush=True,
            )
        if open_browser:
            url = f"http://{reservation.host}:{reservation.port}/"
            threading.Thread(
                target=_open_default_browser_when_ready,
                args=(server, url),
                name="dahe-open-default-browser",
                daemon=True,
            ).start()
        server.run(sockets=[reservation.socket])
