from __future__ import annotations

import subprocess
from pathlib import Path


def test_operational_acceptance_cli_requires_absolute_paths(
    project_root: Path,
) -> None:
    python = project_root / ".venv" / "Scripts" / "python.exe"
    tool = project_root / "tools" / "loop9_operational_read_only_acceptance.py"
    help_result = subprocess.run(
        [str(python), str(tool), "--help"],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert help_result.returncode == 0
    assert "--release-manifest" in help_result.stdout
    assert "--daily-report-id" in help_result.stdout

    relative = subprocess.run(
        [str(python), str(tool), "--data-root", "relative"],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert relative.returncode == 2
    assert "absolute" in relative.stderr
