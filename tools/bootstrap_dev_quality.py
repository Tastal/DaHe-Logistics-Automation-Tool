from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import urllib.request
import venv
import zipfile
from pathlib import Path, PurePosixPath
from uuid import uuid4

try:
    from tools.dev_quality import (
        MANIFEST_PATH,
        ROOT,
        QualityManifest,
        gitleaks_executable,
        load_manifest,
        require_project_venv,
        tool_executable,
        tool_python,
    )
except ModuleNotFoundError:  # Direct execution puts tools/ on sys.path.
    from dev_quality import (  # type: ignore[import-not-found,no-redef]
        MANIFEST_PATH,
        ROOT,
        QualityManifest,
        gitleaks_executable,
        load_manifest,
        require_project_venv,
        tool_executable,
        tool_python,
    )

LOCK_PATH = ROOT / "dev-tools" / "quality-requirements.lock"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install pinned development quality tools outside the project runtime."
    )
    parser.add_argument(
        "--tool",
        choices=("all", "gitleaks", "pip-audit", "py-spy", "schemathesis"),
        default="all",
    )
    return parser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_sha256(path: Path, expected: str) -> str:
    actual = _sha256(path)
    if actual != expected:
        raise ValueError("downloaded archive SHA-256 does not match the approved release")
    return actual


def _validated_zip_member(member: str) -> PurePosixPath:
    normalized = member.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("archive member escapes the isolated runtime")
    return path


def _locked_python_requirements(manifest: QualityManifest) -> tuple[str, ...]:
    lines = tuple(
        line.strip()
        for line in LOCK_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    expected = tuple(
        f"{manifest.python_packages[name]}=={version}"
        for name, version in manifest.python_tools.items()
    )
    if lines != expected:
        raise ValueError("quality tool lock does not match the approved manifest")
    return lines


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        shell=False,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip()
        raise RuntimeError(message or f"tool command failed with {completed.returncode}")
    return completed


def _write_installation_manifest(
    *,
    runtime_root: Path,
    payload: dict[str, object],
) -> Path:
    target = runtime_root / "runtime-installation.json"
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)
    return target


def _install_python_tool(
    *,
    manifest: QualityManifest,
    name: str,
) -> Path:
    version = manifest.python_tools[name]
    runtime_root = tool_python(name, version).parents[2]
    runtime_root.mkdir(parents=True, exist_ok=True)
    python = tool_python(name, version)
    if not python.is_file():
        venv.EnvBuilder(with_pip=True, symlinks=False).create(runtime_root / "python")
    requirement = f"{manifest.python_packages[name]}=={version}"
    _run(
        [
            os.fspath(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--only-binary=:all:",
            requirement,
        ]
    )
    freeze = _run(
        [os.fspath(python), "-m", "pip", "freeze", "--all"]
    ).stdout.splitlines()
    if name in {"py-spy", "schemathesis"}:
        executable = tool_executable(name, version)
        version_output = _run([os.fspath(executable), "--version"]).stdout.strip()
    else:
        module = "pip_audit"
        executable = python
        version_output = _run(
            [os.fspath(python), "-I", "-m", module, "--version"]
        ).stdout.strip()
    return _write_installation_manifest(
        runtime_root=runtime_root,
        payload={
            "schema_version": 1,
            "kind": "isolated_development_quality_tool",
            "name": name,
            "version": version,
            "requested_requirement": requirement,
            "packages": sorted(freeze, key=str.casefold),
            "executable_sha256": _sha256(executable),
            "version_output": version_output,
            "source_manifest_sha256": _sha256(MANIFEST_PATH),
        },
    )


def _download(url: str, destination: Path) -> None:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "DaHeLogistics-development-bootstrap/1"},
    )
    with urllib.request.urlopen(request, timeout=60) as response, destination.open(
        "wb"
    ) as output:
        while chunk := response.read(1024 * 1024):
            output.write(chunk)


def _install_gitleaks(manifest: QualityManifest) -> Path:
    executable = gitleaks_executable(manifest)
    runtime_root = executable.parent
    runtime_root.mkdir(parents=True, exist_ok=True)
    archive = runtime_root / f".{manifest.gitleaks_archive}.{uuid4().hex}.tmp"
    extracted = runtime_root / f".{executable.name}.{uuid4().hex}.tmp"
    try:
        _download(manifest.gitleaks_url, archive)
        archive_sha256 = _verify_sha256(
            archive,
            manifest.gitleaks_archive_sha256,
        )
        with zipfile.ZipFile(archive) as package:
            matching = [
                info
                for info in package.infolist()
                if _validated_zip_member(info.filename).name.casefold() == "gitleaks.exe"
            ]
            if len(matching) != 1:
                raise ValueError("approved gitleaks archive has an invalid executable set")
            with package.open(matching[0]) as source, extracted.open("wb") as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
        os.replace(extracted, executable)
    finally:
        archive.unlink(missing_ok=True)
        extracted.unlink(missing_ok=True)
    version_output = _run([os.fspath(executable), "version"]).stdout.strip()
    return _write_installation_manifest(
        runtime_root=runtime_root,
        payload={
            "schema_version": 1,
            "kind": "isolated_development_quality_tool",
            "name": "gitleaks",
            "version": manifest.gitleaks_version,
            "archive": manifest.gitleaks_archive,
            "archive_sha256": archive_sha256,
            "executable_sha256": _sha256(executable),
            "version_output": version_output,
            "source_manifest_sha256": _sha256(MANIFEST_PATH),
        },
    )


def main() -> int:
    require_project_venv()
    args = _parser().parse_args()
    manifest = load_manifest()
    _locked_python_requirements(manifest)
    selected = (
        ("gitleaks", *manifest.python_tools)
        if args.tool == "all"
        else (args.tool,)
    )
    installations: list[Path] = []
    for name in selected:
        if name == "gitleaks":
            installations.append(_install_gitleaks(manifest))
        else:
            installations.append(_install_python_tool(manifest=manifest, name=name))
    for installation in installations:
        print(installation)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
