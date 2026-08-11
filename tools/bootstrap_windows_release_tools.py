from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import urllib.request
import zipfile
from pathlib import Path

try:
    from tools.windows_release import (
        load_windows_release_manifest,
        makensis_path,
        nsis_archive_path,
        nsis_install_root,
        python_embed_archive_path,
        require_project_venv,
    )
except ModuleNotFoundError:
    from windows_release import (  # type: ignore[import-not-found,no-redef]
        load_windows_release_manifest,
        makensis_path,
        nsis_archive_path,
        nsis_install_root,
        python_embed_archive_path,
        require_project_venv,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def install_nsis() -> Path:
    manifest = load_windows_release_manifest()
    archive = nsis_archive_path(manifest)
    compiler = makensis_path(manifest)
    install_root = nsis_install_root(manifest)
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.is_file():
        with urllib.request.urlopen(manifest.nsis.url, timeout=60) as response:
            archive.write_bytes(response.read())
    if _sha256(archive) != manifest.nsis.asset_sha256:
        raise ValueError("NSIS archive SHA-256 does not match its pin")
    if not compiler.is_file():
        install_root.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(archive) as bundle:
            for member in bundle.infolist():
                logical = Path(member.filename)
                if (
                    logical.is_absolute()
                    or len(logical.parts) < 2
                    or logical.parts[0] != "nsis-3.12"
                    or ".." in logical.parts
                ):
                    raise ValueError("NSIS archive path is unsafe")
                target = install_root.joinpath(*logical.parts[1:])
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open("xb") as output:
                    output.write(source.read())
    version = subprocess.run(
        [os.fspath(compiler), "/VERSION"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
    )
    if version.returncode != 0 or "3.12" not in version.stdout:
        raise RuntimeError("NSIS compiler version is unexpected")
    evidence = {
        "schema_version": 1,
        "name": "NSIS",
        "version": "3.12",
        "archive_sha256": _sha256(archive),
        "compiler_version": version.stdout.strip(),
    }
    (install_root / "runtime-installation.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return compiler


def install_python_embed_archive() -> Path:
    manifest = load_windows_release_manifest()
    archive = python_embed_archive_path(manifest)
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.is_file():
        temporary = archive.with_suffix(archive.suffix + ".download")
        try:
            with urllib.request.urlopen(
                manifest.python_embed.url,
                timeout=60,
            ) as response, temporary.open("xb") as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
            if _sha256(temporary) != manifest.python_embed.asset_sha256:
                raise ValueError(
                    "CPython embed archive SHA-256 does not match its pin"
                )
            os.replace(temporary, archive)
        finally:
            if temporary.exists():
                temporary.unlink()
    if _sha256(archive) != manifest.python_embed.asset_sha256:
        raise ValueError(
            "CPython embed archive SHA-256 does not match its pin"
        )
    with zipfile.ZipFile(archive) as bundle:
        required = {
            "python.exe",
            "python3.dll",
            "python312.dll",
            "python312.zip",
            "python312._pth",
        }
        if not required.issubset(bundle.namelist()):
            raise ValueError("CPython embed archive is incomplete")
    return archive


def main() -> int:
    require_project_venv()
    parser = argparse.ArgumentParser(
        description="Install pinned Windows release tools"
    )
    parser.add_argument(
        "--tool",
        choices=("all", "nsis", "python-embed"),
        default="all",
    )
    arguments = parser.parse_args()
    installed: dict[str, str] = {}
    if arguments.tool in {"all", "nsis"}:
        installed["nsis"] = os.fspath(install_nsis())
    if arguments.tool in {"all", "python-embed"}:
        installed["python_embed"] = os.fspath(install_python_embed_archive())
    print(json.dumps(installed, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
