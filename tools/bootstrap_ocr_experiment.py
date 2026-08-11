from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import venv
from pathlib import Path
from uuid import uuid4

try:
    from tools.ocr_experiment import (
        MANIFEST_PATH,
        ExperimentManifest,
        load_experiment_manifest,
        require_project_venv,
        tool_python,
    )
except ModuleNotFoundError:  # Direct execution puts tools/ on sys.path.
    from ocr_experiment import (  # type: ignore[import-not-found,no-redef]
        MANIFEST_PATH,
        ExperimentManifest,
        load_experiment_manifest,
        require_project_venv,
        tool_python,
    )

ROOT = MANIFEST_PATH.parents[1]
PACKAGE_LOCKS = {
    "cleanvision": ROOT / "dev-tools" / "ocr-experiment-cleanvision.lock",
    "rapidocr": ROOT / "dev-tools" / "ocr-experiment-rapidocr.lock",
}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install isolated development-only OCR experiment tools."
    )
    parser.add_argument("--tool", choices=("all", "cleanvision", "rapidocr"), default="all")
    return parser


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def locked_requirements(manifest: ExperimentManifest) -> dict[str, str]:
    requirements = {
        name: f"{manifest.get(name).package}=={manifest.get(name).version}"
        for name in ("cleanvision", "rapidocr")
    }
    backend = manifest.rapidocr.runtime_backend
    if backend is None:
        raise ValueError("rapidocr runtime backend is missing")
    requirements["rapidocr_backend"] = f"{backend.package}=={backend.version}"
    return requirements


def locked_package_inventory(name: str) -> tuple[str, ...]:
    lock = PACKAGE_LOCKS[name]
    return tuple(
        line.strip()
        for line in lock.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _sanitized_freeze(lines: list[str], manifest: ExperimentManifest) -> tuple[str, ...]:
    replacements = {
        pin.package.casefold(): f"{pin.package}=={pin.version}"
        for pin in (manifest.cleanvision, manifest.rapidocr)
    }
    backend = manifest.rapidocr.runtime_backend
    if backend is not None:
        replacements[backend.package.casefold()] = f"{backend.package}=={backend.version}"
    sanitized: list[str] = []
    for line in lines:
        package_name = line.split("==", 1)[0].split(" @ ", 1)[0].strip()
        if package_name.casefold() == "pip":
            continue
        normalized = replacements.get(package_name.casefold(), line.strip())
        if " @ " in normalized or "file:" in normalized.casefold():
            raise ValueError("OCR experiment package inventory contains a local path")
        sanitized.append(normalized)
    return tuple(sorted(sanitized, key=str.casefold))


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
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


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _install(name: str, manifest: ExperimentManifest) -> Path:
    pin = manifest.get(name)
    python = tool_python(pin)
    runtime_root = python.parents[2]
    runtime_root.mkdir(parents=True, exist_ok=True)
    if not python.is_file():
        venv.EnvBuilder(with_pip=True, symlinks=False).create(runtime_root / "python")
    download_root = runtime_root / f".download-{uuid4().hex}"
    download_root.mkdir()
    try:
        requirement = f"{pin.package}=={pin.version}"
        _run(
            [
                os.fspath(python),
                "-m",
                "pip",
                "download",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                "--no-deps",
                "--dest",
                os.fspath(download_root),
                requirement,
            ]
        )
        wheels = list(download_root.glob("*.whl"))
        if len(wheels) != 1 or _sha256(wheels[0]) != pin.wheel_sha256:
            raise ValueError(f"{name} wheel SHA-256 does not match the approved release")
        _run(
            [
                os.fspath(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                os.fspath(wheels[0]),
            ]
        )
        backend = pin.runtime_backend
        if backend is not None:
            if os.name != "nt" or platform.machine().casefold() not in {"amd64", "x86_64"}:
                raise RuntimeError("the approved RapidOCR experiment backend requires Windows x64")
            _run(
                [
                    os.fspath(python),
                    "-m",
                    "pip",
                    "download",
                    "--disable-pip-version-check",
                    "--no-input",
                    "--only-binary=:all:",
                    "--no-deps",
                    "--dest",
                    os.fspath(download_root),
                    f"{backend.package}=={backend.version}",
                ]
            )
            backend_wheels = [
                wheel for wheel in download_root.glob("*.whl") if wheel not in wheels
            ]
            if len(backend_wheels) != 1 or _sha256(backend_wheels[0]) != backend.wheel_sha256:
                raise ValueError(
                    "RapidOCR backend wheel SHA-256 does not match the approved release"
                )
            _run(
                [
                    os.fspath(python),
                    "-m",
                    "pip",
                    "install",
                    "--disable-pip-version-check",
                    "--no-input",
                    "--only-binary=:all:",
                    os.fspath(backend_wheels[0]),
                ]
            )
        _run(
            [
                os.fspath(python),
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-input",
                "--only-binary=:all:",
                "--requirement",
                os.fspath(PACKAGE_LOCKS[name]),
            ]
        )
    finally:
        shutil.rmtree(download_root, ignore_errors=True)
    module_name = "cleanvision" if name == "cleanvision" else "rapidocr"
    smoke_code = (
        f"import importlib.metadata as m; import {module_name}; "
        f"print(m.version('{pin.package}'))"
    )
    smoke = _run(
        [
            os.fspath(python),
            "-I",
            "-c",
            smoke_code,
        ]
    ).stdout.strip()
    if smoke != pin.version:
        raise RuntimeError(f"{name} smoke check reported an unexpected version")
    freeze = _sanitized_freeze(
        _run([os.fspath(python), "-m", "pip", "freeze", "--all"]).stdout.splitlines(),
        manifest,
    )
    expected_inventory = tuple(sorted(locked_package_inventory(name), key=str.casefold))
    if freeze != expected_inventory:
        raise RuntimeError(f"{name} package inventory differs from the approved lock")
    installation = runtime_root / "runtime-installation.json"
    _atomic_json(
        installation,
        {
            "schema_version": 1,
            "kind": "isolated_development_ocr_experiment_tool",
            "name": name,
            "version": pin.version,
            "license": pin.license,
            "source": pin.source,
            "wheel_sha256": pin.wheel_sha256,
            "runtime_backend": (
                {
                    "package": pin.runtime_backend.package,
                    "version": pin.runtime_backend.version,
                    "license": pin.runtime_backend.license,
                    "source": pin.runtime_backend.source,
                    "platform": pin.runtime_backend.platform,
                    "wheel_sha256": pin.runtime_backend.wheel_sha256,
                }
                if pin.runtime_backend is not None
                else None
            ),
            "python_sha256": _sha256(python),
            "packages": list(freeze),
            "package_lock_sha256": _sha256(PACKAGE_LOCKS[name]),
            "source_manifest_sha256": _sha256(MANIFEST_PATH),
            "production_runtime": False,
        },
    )
    return installation


def main() -> int:
    require_project_venv()
    args = _parser().parse_args()
    manifest = load_experiment_manifest()
    selected = ("cleanvision", "rapidocr") if args.tool == "all" else (args.tool,)
    for name in selected:
        print(_install(name, manifest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
