from __future__ import annotations

import runpy
import subprocess
import sys
from pathlib import Path

import pytest


def test_formal_run_cli_help_exposes_only_technical_identities(
    project_root: Path,
) -> None:
    completed = subprocess.run(
        [
            str(project_root / ".venv" / "Scripts" / "python.exe"),
            str(
                project_root
                / "tools"
                / "loop9_build_operational_evidence.py"
            ),
            "--help",
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert completed.returncode == 0
    assert "--locked-job-id" in completed.stdout
    assert "--real-shadow-selection-sha256" in completed.stdout
    assert "--real-shadow-job-id" in completed.stdout
    assert "--browser-closed-run-id" in completed.stdout
    assert "--transient-network-failure-job-id" in completed.stdout
    assert "--passed" not in completed.stdout
    assert "--count" not in completed.stdout
    assert "--p50" not in completed.stdout
    assert "--p95" not in completed.stdout
    assert "--request-audit" not in completed.stdout
    assert "--output" not in completed.stdout


def test_formal_run_cli_exposes_only_technical_identities(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    tool = (
        Path(__file__).parents[3]
        / "tools"
        / "loop9_build_operational_evidence.py"
    )
    data_root = tmp_path.resolve()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            str(tool),
            "--data-root",
            str(data_root),
            "--passed",
            "true",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        runpy.run_path(str(tool), run_name="__main__")

    assert exc_info.value.code == 2
