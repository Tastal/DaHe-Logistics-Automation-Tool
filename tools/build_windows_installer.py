from __future__ import annotations

import argparse
import os
import re
import subprocess
from pathlib import Path

try:
    from tools.windows_release import ROOT, require_project_venv
except ModuleNotFoundError:
    from windows_release import (  # type: ignore[import-not-found,no-redef]
        ROOT,
        require_project_venv,
    )

NSI_PATH = (ROOT / "packaging" / "DaHeLogistics.nsi").resolve()
_VERSION = re.compile(r"^\d+\.\d+\.\d+$")


def installer_command(
    *,
    makensis: Path,
    payload_root: Path,
    output_root: Path,
    app_version: str,
    script_path: Path = NSI_PATH,
) -> list[str]:
    compiler = makensis.resolve(strict=True)
    payload = payload_root.resolve(strict=True)
    output = output_root.resolve(strict=True)
    script = script_path.resolve(strict=True)
    if not compiler.is_file() or compiler.is_symlink():
        raise ValueError("makensis must be a regular file")
    if not payload.is_dir() or payload.is_symlink():
        raise ValueError("payload root must be a regular directory")
    if not output.is_dir() or any(output.iterdir()):
        raise ValueError("installer output root must be an empty directory")
    if not script.is_file() or script.is_symlink():
        raise ValueError("NSIS script must be a regular file")
    if not _VERSION.fullmatch(app_version):
        raise ValueError("application version is invalid")
    for path in payload.rglob("*"):
        if path.is_symlink():
            raise ValueError("installer payload must not contain symbolic links")
    return [
        os.fspath(compiler),
        "/INPUTCHARSET",
        "UTF8",
        "/V2",
        f"/DAPP_VERSION={app_version}",
        f"/DPAYLOAD_ROOT={payload}",
        f"/DOUTPUT_ROOT={output}",
        os.fspath(script),
    ]


def main() -> int:
    require_project_venv()
    parser = argparse.ArgumentParser(description="Build the per-user DaHe NSIS installer")
    parser.add_argument("--makensis", type=Path, required=True)
    parser.add_argument("--payload-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--app-version", required=True)
    arguments = parser.parse_args()
    completed = subprocess.run(
        installer_command(
            makensis=arguments.makensis,
            payload_root=arguments.payload_root,
            output_root=arguments.output_root,
            app_version=arguments.app_version,
        ),
        check=False,
        shell=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
