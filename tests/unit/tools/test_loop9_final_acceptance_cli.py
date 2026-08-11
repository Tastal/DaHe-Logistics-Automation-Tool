from __future__ import annotations

import subprocess
from pathlib import Path


def test_cli_delegates_one_deep_replay_and_write_operation(
    project_root: Path,
) -> None:
    source = (
        project_root / "tools" / "loop9_final_acceptance.py"
    ).read_text(encoding="utf-8")

    assert "replay_loop9_final_acceptance" not in source
    assert "inputs=Loop9FinalAcceptanceInputs(" in source
    assert "replay=replay" not in source


def test_loop9_final_acceptance_help_uses_project_venv(
    project_root: Path,
) -> None:
    completed = subprocess.run(
        [
            str(project_root / ".venv" / "Scripts" / "python.exe"),
            str(project_root / "tools" / "loop9_final_acceptance.py"),
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
    assert "--ledger" in completed.stdout
    assert "--formal-run-evidence-sha256" in completed.stdout
    assert "--locked-job-id" in completed.stdout
    assert "--real-shadow-job-id" in completed.stdout
    assert "--browser-closed-run-id" in completed.stdout
    assert "--browser-closed-job-id" in completed.stdout
    assert "--gpu-worker-failure-run-id" in completed.stdout
    assert "--gpu-worker-failure-job-id" in completed.stdout
    assert "--main-application-restart-run-id" in completed.stdout
    assert "--main-application-restart-job-id" in completed.stdout
    assert "--transient-network-failure-run-id" in completed.stdout
    assert "--transient-network-failure-job-id" in completed.stdout
    assert "--operational-evidence" not in completed.stdout
    assert "--current-locked-request-audit" not in completed.stdout
    assert "--expected-ledger-revision" in completed.stdout


def test_loop9_final_acceptance_rejects_relative_paths(
    project_root: Path,
) -> None:
    completed = subprocess.run(
        [
            str(project_root / ".venv" / "Scripts" / "python.exe"),
            str(project_root / "tools" / "loop9_final_acceptance.py"),
            "--data-root",
            "relative",
            "--ledger",
            "relative",
            "--output-directory",
            "relative",
            "--read-contract-validation",
            "relative",
            "--current-locked-selection-sha256",
            "a" * 64,
            "--real-shadow-selection-sha256",
            "b" * 64,
            "--real-shadow-package",
            "relative",
            "--real-shadow-seal",
            "relative",
            "--real-shadow-machine-evaluation",
            "relative",
            "--daily-snapshot-validation",
            "relative",
            "--discovery-development",
            "relative",
            "--current-locked-50",
            "relative",
            "--real-shadow-30",
            "relative",
            "--daily-validation-dataset",
            "relative",
            "--source-development-authority",
            "relative",
            "--dataset-isolation",
            "relative",
            "--formal-run-evidence-sha256",
            "c" * 64,
            "--locked-job-id",
            "locked-job",
            "--real-shadow-job-id",
            "real-job",
            "--browser-closed-run-id",
            "browser-run",
            "--browser-closed-job-id",
            "browser-job",
            "--gpu-worker-failure-run-id",
            "gpu-run",
            "--gpu-worker-failure-job-id",
            "gpu-job",
            "--main-application-restart-run-id",
            "restart-run",
            "--main-application-restart-job-id",
            "restart-job",
            "--transient-network-failure-run-id",
            "network-run",
            "--transient-network-failure-job-id",
            "network-job",
            "--expected-ledger-revision",
            "1",
        ],
        cwd=project_root,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    assert completed.returncode != 0
    assert "path must be absolute" in completed.stderr
