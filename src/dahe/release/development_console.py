from __future__ import annotations

import ctypes
import json
import os
import socket
import subprocess
import time
import urllib.error
import urllib.request
import webbrowser
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from dahe import __version__

_HOST = "127.0.0.1"
_PORT = 8877
_URL = f"http://{_HOST}:{_PORT}"
_CREATE_NO_WINDOW = 0x08000000
_CREATE_NEW_PROCESS_GROUP = 0x00000200


class DevelopmentConsoleLaunchError(RuntimeError):
    """Raised when the development console cannot be started safely."""


def _port_is_open(*, timeout_seconds: float = 0.5) -> bool:
    try:
        with socket.create_connection((_HOST, _PORT), timeout=timeout_seconds):
            return True
    except OSError:
        return False


def _read_readiness(*, timeout_seconds: float = 2.0) -> Mapping[str, Any] | None:
    request = urllib.request.Request(
        f"{_URL}/api/v1/system/readiness",
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError, TypeError, urllib.error.URLError):
        return None
    return payload if isinstance(payload, dict) else None


def _is_expected_development_service(payload: Mapping[str, Any] | None) -> bool:
    return bool(
        payload is not None
        and payload.get("ready") is True
        and payload.get("application_version") == __version__
        and payload.get("build_git_commit") == "development"
    )


def _server_command(*, project_root: Path, data_root: Path) -> tuple[str, ...]:
    python = project_root / ".venv" / "Scripts" / "python.exe"
    if not python.is_file():
        raise DevelopmentConsoleLaunchError("project .venv Python is unavailable")
    return (
        os.fspath(python),
        "-m",
        "dahe",
        "--serve",
        "--production-read-only",
        "--data-root",
        os.fspath(data_root),
        "--no-browser",
    )


def _development_environment(*, runtime_root: Path) -> dict[str, str]:
    environment = dict(os.environ)
    environment.update(
        {
            "DAHE_BROWSER_RUNTIME_ROOT": os.fspath(runtime_root / "browser"),
            "DAHE_OCR_RUNTIME_ROOT": os.fspath(runtime_root),
        }
    )
    return environment


def _show_error(message: str) -> None:
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            message,
            "大禾物流自动化平台",
            0x10,
        )
    except (AttributeError, OSError):
        print(message)


def launch_development_console(
    *,
    project_root: Path,
    local_app_data: Path,
    startup_timeout_seconds: float = 90.0,
) -> None:
    project_root = project_root.resolve(strict=True)
    runtime_root = (
        local_app_data / "DaHeLogisticsDevelopment" / "runtimes"
    ).resolve()
    data_root = (
        local_app_data / "DaHeLogisticsAutomationTool"
    ).resolve()
    readiness = _read_readiness()
    if readiness is not None:
        if not _is_expected_development_service(readiness):
            raise DevelopmentConsoleLaunchError(
                "8877 is occupied by a different DaHe build"
            )
        webbrowser.open(_URL, new=2)
        return
    if _port_is_open():
        raise DevelopmentConsoleLaunchError(
            "8877 is occupied by an unknown local process"
        )

    log_root = local_app_data / "DaHeLogisticsDevelopment" / "launcher"
    log_root.mkdir(parents=True, exist_ok=True)
    log_path = log_root / "development-console.log"
    command = _server_command(project_root=project_root, data_root=data_root)
    with log_path.open("ab") as log:
        subprocess.Popen(
            command,
            cwd=project_root,
            env=_development_environment(runtime_root=runtime_root),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            shell=False,
            close_fds=True,
            creationflags=_CREATE_NO_WINDOW | _CREATE_NEW_PROCESS_GROUP,
        )

    deadline = time.monotonic() + startup_timeout_seconds
    while time.monotonic() < deadline:
        readiness = _read_readiness(timeout_seconds=1.0)
        if _is_expected_development_service(readiness):
            webbrowser.open(_URL, new=2)
            return
        if readiness is not None:
            raise DevelopmentConsoleLaunchError(
                "8877 started with an unexpected DaHe identity"
            )
        time.sleep(0.25)
    raise DevelopmentConsoleLaunchError(
        "development console did not become ready within the startup window"
    )


def main() -> int:
    project_root = Path(__file__).resolve().parents[3]
    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data:
        _show_error("LOCALAPPDATA is unavailable; the development console was not started.")
        return 2
    try:
        launch_development_console(
            project_root=project_root,
            local_app_data=Path(local_app_data),
        )
    except (DevelopmentConsoleLaunchError, OSError) as exc:
        _show_error(str(exc))
        return 2
    return 0
