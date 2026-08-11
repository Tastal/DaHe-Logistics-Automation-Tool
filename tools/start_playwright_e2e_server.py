from __future__ import annotations

import sys
import tempfile
from pathlib import Path

from dahe.cli import run

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def main() -> int:
    if Path(sys.executable).resolve() != EXPECTED_PYTHON:
        raise SystemExit("run Playwright E2E with the project .venv Python")
    with tempfile.TemporaryDirectory(prefix="DaHePlaywrightE2E-") as temporary:
        return run(
            [
                "--serve",
                "--data-root",
                str(Path(temporary).resolve()),
                "--enable-test-fixtures",
                "--port",
                "8899",
                "--no-browser",
            ]
        )


if __name__ == "__main__":
    raise SystemExit(main())
