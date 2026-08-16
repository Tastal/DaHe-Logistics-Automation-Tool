from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
SHORTCUT_NAME = "大禾物流自动化平台.lnk"


def _desktop_root() -> Path:
    result = subprocess.run(
        (
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Environment]::GetFolderPath('Desktop')",
        ),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        shell=False,
    )
    path = Path(result.stdout.strip()).resolve()
    if not path.is_dir():
        raise RuntimeError("Windows desktop directory is unavailable")
    return path


def _shortcut_arguments(*, project_root: Path) -> str:
    python = project_root / ".venv" / "Scripts" / "python.exe"
    entrypoint = project_root / "tools" / "entrypoints" / "dahe_development_launcher.py"
    command = f"& '{python}' '{entrypoint}'"
    return (
        "-NoLogo -NoProfile -NonInteractive -WindowStyle Hidden "
        f'-ExecutionPolicy Bypass -Command "{command}"'
    )


def install_shortcut(*, project_root: Path, desktop_root: Path) -> Path:
    project_root = project_root.resolve(strict=True)
    desktop_root = desktop_root.resolve(strict=True)
    icon = project_root / "packaging" / "dahe-logo.ico"
    if not icon.is_file():
        raise RuntimeError("DaHe shortcut icon is unavailable")
    shortcut_path = desktop_root / SHORTCUT_NAME
    environment = dict(os.environ)
    environment.update(
        {
            "DAHE_SHORTCUT_PATH": os.fspath(shortcut_path),
            "DAHE_SHORTCUT_TARGET": (
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
            ),
            "DAHE_SHORTCUT_ARGUMENTS": _shortcut_arguments(
                project_root=project_root
            ),
            "DAHE_SHORTCUT_WORKING_DIRECTORY": os.fspath(project_root),
            "DAHE_SHORTCUT_ICON": f"{icon},0",
        }
    )
    script = (
        "$shell = New-Object -ComObject WScript.Shell; "
        "$shortcut = $shell.CreateShortcut($env:DAHE_SHORTCUT_PATH); "
        "$shortcut.TargetPath = $env:DAHE_SHORTCUT_TARGET; "
        "$shortcut.Arguments = $env:DAHE_SHORTCUT_ARGUMENTS; "
        "$shortcut.WorkingDirectory = $env:DAHE_SHORTCUT_WORKING_DIRECTORY; "
        "$shortcut.IconLocation = $env:DAHE_SHORTCUT_ICON; "
        "$shortcut.Description = '大禾物流自动化平台 - 开发版'; "
        "$shortcut.Save()"
    )
    subprocess.run(
        (
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            script,
        ),
        check=True,
        env=environment,
        shell=False,
    )
    if not shortcut_path.is_file():
        raise RuntimeError("development desktop shortcut was not created")
    legacy = desktop_root / "大禾物流.lnk"
    if legacy.is_file():
        legacy.unlink()
    return shortcut_path


def main() -> int:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit("run this tool with the project .venv Python")
    shortcut = install_shortcut(
        project_root=ROOT,
        desktop_root=_desktop_root(),
    )
    print(shortcut)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
