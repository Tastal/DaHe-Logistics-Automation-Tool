from __future__ import annotations

import subprocess
from pathlib import Path


def test_fault_injection_cli_accepts_only_an_absolute_data_root(
    project_root: Path,
) -> None:
    tool = project_root / "tools" / "loop9_run_fault_injections.py"
    completed = subprocess.run(
        [
            str(project_root / ".venv" / "Scripts" / "python.exe"),
            str(tool),
            "--help",
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert completed.returncode == 0
    assert "--data-root" in completed.stdout
    for forbidden in (
        "--attempt",
        "--checkpoint",
        "--count",
        "--duration",
        "--instance",
        "--job",
        "--passed",
        "--payload",
        "--run",
    ):
        assert forbidden not in completed.stdout

    relative = subprocess.run(
        [
            str(project_root / ".venv" / "Scripts" / "python.exe"),
            str(tool),
            "--data-root",
            "relative",
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    assert relative.returncode == 2
    assert "absolute" in relative.stderr
