from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import venv
from pathlib import Path
from uuid import uuid4

from dahe.adapters.chengfeng.browser_runtime import (
    BROWSER_PROTOCOL_VERSION,
)
from dahe.system.supervision import (
    SupervisedLineProcess,
    SupervisedLineProcessError,
)

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()


def _default_runtime_root() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data is None:
        raise SystemExit("LOCALAPPDATA is unavailable")
    return Path(local_app_data) / "DaHeLogistics" / "runtimes" / "browser"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build the isolated DaHe Playwright runtime."
    )
    parser.add_argument(
        "--runtime-root",
        type=Path,
        default=_default_runtime_root(),
    )
    parser.add_argument(
        "--install-chromium",
        action="store_true",
        help="Download the pinned Playwright Chromium into the isolated root.",
    )
    return parser


def _run(command: list[str], *, env: dict[str, str]) -> None:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        shell=False,
        check=False,
    )
    if completed.returncode != 0:
        raise SystemExit(completed.returncode)


def _worker_source_sha256() -> str:
    source_root = ROOT / "browser-runtime" / "src" / "dahe_browser_worker"
    digest = hashlib.sha256()
    for path in sorted(source_root.rglob("*.py")):
        digest.update(path.relative_to(source_root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _isolated_smoke(*, python: Path, runtime_root: Path) -> str:
    process = SupervisedLineProcess(
        worker_id="browser-bootstrap-smoke",
        argv=[os.fspath(python), "-I", "-m", "dahe_browser_worker"],
        runtime_dir=runtime_root / "smoke-runtime",
        max_request_bytes=16 * 1024,
        max_response_bytes=16 * 1024,
    )
    try:
        line = process.request_line(
            json.dumps(
                {
                    "schema_version": BROWSER_PROTOCOL_VERSION,
                    "command": "smoke",
                    "request_id": uuid4().hex,
                    "browser": "auto",
                    "browser_store": os.fspath(
                        (runtime_root / "smoke-browser-store").resolve()
                    ),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            timeout_seconds=30,
        )
        response = json.loads(line)
    except (SupervisedLineProcessError, json.JSONDecodeError) as exc:
        raise SystemExit("isolated browser smoke failed") from exc
    finally:
        process.close()
    selected = response.get("selected_browser") if isinstance(response, dict) else None
    if (
        not isinstance(response, dict)
        or response.get("schema_version") != BROWSER_PROTOCOL_VERSION
        or response.get("ok") is not True
        or selected not in {"chromium", "msedge"}
        or response.get("read_result") is not None
    ):
        raise SystemExit("isolated browser smoke returned an invalid result")
    return str(selected)


def main() -> int:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit("bootstrap_browser.py must run from the project .venv")
    args = _parser().parse_args()
    runtime_root = args.runtime_root.resolve()
    runtime_root.mkdir(parents=True, exist_ok=True)
    runtime_dir = runtime_root / "python"
    python = runtime_dir / "Scripts" / "python.exe"
    if not python.is_file():
        venv.EnvBuilder(with_pip=True, symlinks=False).create(runtime_dir)
    lock = ROOT / "browser-runtime" / "requirements.lock"
    for line in lock.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and line.count("==") != 1:
            raise SystemExit("browser runtime lock must contain exact pins only")
    env = dict(os.environ)
    browser_store = runtime_root / "browsers"
    env["PLAYWRIGHT_BROWSERS_PATH"] = os.fspath(browser_store)
    _run(
        [
            os.fspath(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--requirement",
            os.fspath(lock),
        ],
        env=env,
    )
    _run(
        [
            os.fspath(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--force-reinstall",
            "--no-deps",
            os.fspath(ROOT / "browser-runtime"),
        ],
        env=env,
    )
    if args.install_chromium:
        _run(
            [os.fspath(python), "-m", "playwright", "install", "chromium"],
            env=env,
        )
    inventory = subprocess.run(
        [os.fspath(python), "-m", "pip", "freeze", "--all"],
        cwd=ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    ).stdout.splitlines()
    smoke_selected_browser = _isolated_smoke(
        python=python,
        runtime_root=runtime_root,
    )
    manifest = {
        "schema_version": 1,
        "runtime_kind": "browser",
        "dependency_lock": "browser-runtime/requirements.lock",
        "dependency_lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
        "worker_source_sha256": _worker_source_sha256(),
        "packages": sorted(inventory, key=str.casefold),
        "chromium_provisioned": bool(args.install_chromium),
        "smoke_selected_browser": smoke_selected_browser,
    }
    target = runtime_root / "runtime-installation.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)
    print(target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
