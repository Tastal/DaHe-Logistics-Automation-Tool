from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from pydantic import ValidationError

from dahe.bootstrap import StartupCheckError, run_startup_check
from dahe.config.paths import ConfigurationPathError
from dahe.config.schema import AppConfig, RuntimeProfile
from dahe.system.environment import VirtualEnvironmentError
from dahe.system.instance_lock import AlreadyRunningError, InstanceLockError
from dahe.system.port_guard import PortInUseError
from dahe.system.versioning import VersionManifestError


def _application_root(executable: Path | None = None) -> Path:
    """Resolve either the checked-out project or a self-contained local release."""

    selected_executable = Path(sys.executable if executable is None else executable).resolve()
    frozen_candidate = selected_executable.parent
    if (
        (frozen_candidate / "version-manifest.json").is_file()
        and (frozen_candidate / "frontend" / "dist" / "index.html").is_file()
        and (
            frozen_candidate
            / "src"
            / "dahe"
            / "adapters"
            / "sqlite"
            / "migrations"
        ).is_dir()
    ):
        return frozen_candidate
    release_candidate = selected_executable.parents[2]
    if (
        (release_candidate / "version-manifest.json").is_file()
        and (release_candidate / "frontend" / "dist" / "index.html").is_file()
        and (release_candidate / "src" / "dahe").is_dir()
    ):
        return release_candidate
    return Path(__file__).resolve().parents[2]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="dahe")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="run the offline startup preflight")
    mode.add_argument("--serve", action="store_true", help="open the local operator console")
    parser.add_argument("--data-root", type=Path)
    parser.add_argument("--port", type=int, default=8877)
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="do not open the system default browser",
    )
    parser.add_argument(
        "--enable-test-fixtures",
        action="store_true",
        help="enable protected Loop 3 fixtures with an explicit data root",
    )
    parser.add_argument(
        "--enable-template-studio",
        action="store_true",
        help="enable protected template maintenance with an explicit data root",
    )
    parser.add_argument(
        "--enable-locked-set-review",
        action="store_true",
        help="enable the offline locked-set review package with an explicit data root",
    )
    parser.add_argument(
        "--enable-chengfeng-shadow",
        action="store_true",
        help="enable the protected Chengfeng read-only shadow entry points",
    )
    parser.add_argument(
        "--production-read-only",
        action="store_true",
        help="run the fixed local read-only production profile",
    )
    parser.add_argument(
        "--enable-loop9-scheduler-probe",
        action="store_true",
        help="enable only the isolated Loop 9 loading scheduler probe",
    )
    parser.add_argument(
        "--loop9-review-package",
        type=Path,
        help="open one immutable Loop 9 package in isolated offline review mode",
    )
    return parser


def run(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    if arguments.production_read_only:
        if not arguments.serve:
            parser.error("--production-read-only requires --serve")
        if arguments.data_root is None:
            parser.error("--production-read-only requires an explicit --data-root")
        if not arguments.data_root.is_absolute():
            parser.error("--production-read-only requires an absolute --data-root")
        if arguments.port != 8877:
            parser.error("--production-read-only requires port 8877")
        if (
            arguments.enable_chengfeng_shadow
            or arguments.enable_loop9_scheduler_probe
            or arguments.enable_test_fixtures
            or arguments.enable_template_studio
            or arguments.enable_locked_set_review
            or arguments.loop9_review_package is not None
        ):
            parser.error("--production-read-only must run without development modes")
    if arguments.enable_locked_set_review and (
        arguments.enable_template_studio
        or arguments.enable_test_fixtures
    ):
        parser.error("--enable-locked-set-review must run alone")
    if (
        arguments.enable_loop9_scheduler_probe
        and not arguments.enable_chengfeng_shadow
    ):
        parser.error(
            "--enable-loop9-scheduler-probe requires "
            "--enable-chengfeng-shadow"
        )
    if arguments.enable_chengfeng_shadow and (
        arguments.enable_test_fixtures
        or arguments.enable_template_studio
        or arguments.enable_locked_set_review
    ):
        parser.error("--enable-chengfeng-shadow must run without test or maintenance modes")
    if arguments.loop9_review_package is not None and (
        arguments.enable_chengfeng_shadow
        or arguments.enable_loop9_scheduler_probe
        or arguments.enable_test_fixtures
        or arguments.enable_template_studio
        or arguments.enable_locked_set_review
    ):
        parser.error("--loop9-review-package must run alone in offline mode")
    if arguments.loop9_review_package is not None and not arguments.serve:
        parser.error("--loop9-review-package requires --serve")
    if (
        arguments.loop9_review_package is not None
        and arguments.data_root is None
    ):
        parser.error("--loop9-review-package requires an explicit --data-root")
    if (
        arguments.loop9_review_package is not None
        and not arguments.loop9_review_package.is_absolute()
    ):
        parser.error("--loop9-review-package requires an absolute path")
    if arguments.enable_chengfeng_shadow and not arguments.serve:
        parser.error("--enable-chengfeng-shadow requires --serve")
    if arguments.enable_chengfeng_shadow and arguments.data_root is None:
        parser.error("--enable-chengfeng-shadow requires an explicit --data-root")
    if arguments.enable_test_fixtures and not arguments.serve:
        parser.error("--enable-test-fixtures requires --serve")
    if arguments.enable_test_fixtures and arguments.data_root is None:
        parser.error("--enable-test-fixtures requires an explicit --data-root")
    if arguments.enable_template_studio and not arguments.serve:
        parser.error("--enable-template-studio requires --serve")
    if arguments.enable_template_studio and arguments.data_root is None:
        parser.error("--enable-template-studio requires an explicit --data-root")
    if arguments.enable_locked_set_review and not arguments.serve:
        parser.error("--enable-locked-set-review requires --serve")
    if (
        arguments.enable_locked_set_review
        and arguments.data_root is None
    ):
        parser.error(
            "--enable-locked-set-review requires an explicit --data-root"
        )
    project_root = _application_root()
    data_root = arguments.data_root.resolve() if arguments.data_root is not None else None
    try:
        config = (
            AppConfig.for_production_read_only(data_root=data_root)
            if arguments.production_read_only and data_root is not None
            else AppConfig(
                runtime_profile=(
                    RuntimeProfile.TEST
                    if arguments.data_root is not None
                    else RuntimeProfile.DEVELOPMENT
                ),
                data_root=data_root,
                port=arguments.port,
            )
        )
        if arguments.serve:
            from dahe.server import run_local_console

            run_local_console(
                config=config,
                project_root=project_root,
                open_browser=not arguments.no_browser,
                enable_test_fixtures=arguments.enable_test_fixtures,
                enable_template_studio=arguments.enable_template_studio,
                enable_locked_set_review=(
                    arguments.enable_locked_set_review
                ),
                enable_chengfeng_shadow=arguments.enable_chengfeng_shadow,
                production_read_only=arguments.production_read_only,
                enable_loop9_scheduler_probe=(
                    arguments.enable_loop9_scheduler_probe
                ),
                loop9_review_package_path=(
                    arguments.loop9_review_package
                ),
            )
            return 0
        report = run_startup_check(config=config, project_root=project_root)
    except (
        AlreadyRunningError,
        ConfigurationPathError,
        InstanceLockError,
        PortInUseError,
        StartupCheckError,
        ValidationError,
        VersionManifestError,
        VirtualEnvironmentError,
    ) as exc:
        print(f"startup check failed: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(report.as_dict(), ensure_ascii=False, sort_keys=True))
    return 0


def main() -> None:
    raise SystemExit(run())
