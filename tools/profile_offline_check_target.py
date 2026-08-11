from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from dahe.cli import run

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--check", action="store_true", required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--pid-file", type=Path, required=True)
    return parser


def main() -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise RuntimeError("offline profile target requires the project .venv")
    args = _parser().parse_args()
    pid_file = args.pid_file.resolve()
    if not pid_file.is_absolute() or pid_file.exists():
        raise RuntimeError("offline profile PID file must be a new absolute path")
    descriptor = os.open(pid_file, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as stream:
        stream.write(f"{os.getpid()}\n")
        stream.flush()
        os.fsync(stream.fileno())
    result = run(
        [
            "--check",
            "--data-root",
            str(args.data_root.resolve()),
            "--port",
            str(args.port),
        ]
    )
    if result == 0:
        time.sleep(5)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
