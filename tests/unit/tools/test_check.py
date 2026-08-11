from __future__ import annotations

import os
from pathlib import Path

from tools import check as module


def test_authoritative_checks_build_frontend_before_backend_startup_tests(
    monkeypatch,
) -> None:
    python = Path(module.sys.executable).resolve()
    npm = r"C:\Program Files\nodejs\npm.cmd"
    commands: list[list[str]] = []
    monkeypatch.setattr(module, "EXPECTED_PYTHON", python)
    monkeypatch.setattr(module.shutil, "which", lambda name: npm)
    monkeypatch.setattr(module, "_run", commands.append)

    module.main()

    assert commands == [
        [os.fspath(python), "-m", "ruff", "check", "."],
        [os.fspath(python), "-m", "mypy", "src", "tools"],
        [npm, "--prefix", "frontend", "run", "check"],
        [os.fspath(python), "-m", "pytest"],
    ]
