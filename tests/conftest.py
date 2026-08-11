from __future__ import annotations

import sys
from pathlib import Path

import pytest


@pytest.fixture(scope="session")
def project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def test_suite_uses_project_virtual_environment(project_root: Path) -> None:
    expected = (project_root / ".venv" / "Scripts" / "python.exe").resolve()
    assert Path(sys.executable).resolve() == expected
    assert sys.prefix != sys.base_prefix
