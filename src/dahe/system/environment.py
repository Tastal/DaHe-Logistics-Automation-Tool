from __future__ import annotations

import os
import sys
from pathlib import Path


class VirtualEnvironmentError(RuntimeError):
    """Raised when a project command is not running from the project venv."""


def assert_project_venv(
    project_root: Path,
    executable: Path | None = None,
) -> None:
    if executable is None and getattr(sys, "frozen", False):
        identity = project_root / "release-identity.json"
        if identity.is_file() and project_root == Path(sys.executable).resolve().parent:
            return
        raise VirtualEnvironmentError("frozen application identity is unavailable")
    actual = Path(sys.executable if executable is None else executable).resolve()
    expected = (project_root / ".venv" / "Scripts" / "python.exe").resolve()
    if os.path.normcase(actual) != os.path.normcase(expected):
        raise VirtualEnvironmentError(f"use the project interpreter: {expected}")
