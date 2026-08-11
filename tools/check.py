from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _run(command: list[str]) -> None:
    print(f"> {' '.join(command)}", flush=True)
    completed = subprocess.run(command, cwd=ROOT, check=False)
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def main() -> None:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit(f"Use the project interpreter: {EXPECTED_PYTHON}")

    npm = shutil.which("npm.cmd")
    if npm is None:
        raise SystemExit("npm.cmd was not found")

    python = os.fspath(EXPECTED_PYTHON)
    _run([python, "-m", "ruff", "check", "."])
    _run([python, "-m", "mypy", "src", "tools"])
    _run([npm, "--prefix", "frontend", "run", "check"])
    _run([python, "-m", "pytest"])


if __name__ == "__main__":
    main()
