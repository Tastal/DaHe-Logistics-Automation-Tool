from __future__ import annotations

from pathlib import Path

from tools.install_development_shortcut import _shortcut_arguments


def test_development_shortcut_runs_project_venv_without_visible_console(
    tmp_path: Path,
) -> None:
    arguments = _shortcut_arguments(project_root=tmp_path / "DaHe")

    assert "-WindowStyle Hidden" in arguments
    assert ".venv\\Scripts\\python.exe" in arguments
    assert "dahe_development_launcher.py" in arguments
    assert "--production-read-only" not in arguments
