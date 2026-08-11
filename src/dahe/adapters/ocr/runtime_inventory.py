from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

from dahe.adapters.ocr.profiles import RuntimeKind


class RuntimeInventoryError(RuntimeError):
    """Raised when an isolated OCR environment differs from its exact lock."""


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_exact_lock(path: Path) -> dict[str, str]:
    packages: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "--")):
            continue
        if line.count("==") != 1:
            raise RuntimeInventoryError(
                f"every OCR requirement must be exactly pinned: {line}"
            )
        raw_name, version = line.split("==", 1)
        name = normalize_package_name(raw_name)
        if not name or not version or name in packages:
            raise RuntimeInventoryError("OCR lock contains invalid or duplicate packages")
        packages[name] = version
    return packages


def query_installed_inventory(
    python: Path,
    *,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, str]:
    script = (
        "import importlib.metadata,json;"
        "items={};"
        "\nfor dist in importlib.metadata.distributions():\n"
        " name=dist.metadata.get('Name');"
        "\n if name: items[name]=dist.version\n"
        "print(json.dumps(items,sort_keys=True))"
    )
    completed = runner(
        (os.fspath(python), "-I", "-B", "-c", script),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    payload = json.loads(completed.stdout)
    if not isinstance(payload, dict):
        raise RuntimeInventoryError("OCR environment returned an invalid inventory")
    return {
        normalize_package_name(str(name)): str(version)
        for name, version in payload.items()
    }


def validate_runtime_inventory(
    *,
    runtime_kind: RuntimeKind,
    locked: dict[str, str],
    installed: dict[str, str],
    worker_version: str,
) -> None:
    if runtime_kind is RuntimeKind.CPU and (
        "paddlepaddle-gpu" in installed
        or any(package.startswith("nvidia-") for package in installed)
    ):
        raise RuntimeInventoryError("CPU OCR environment contains GPU packages")
    if runtime_kind is RuntimeKind.GPU and "paddlepaddle" in installed:
        raise RuntimeInventoryError("GPU OCR environment contains CPU Paddle")

    expected_names = set(locked) | {"pip", "dahe-ocr-worker"}
    unexpected = set(installed) - expected_names
    missing = expected_names - set(installed)
    if unexpected:
        raise RuntimeInventoryError(
            "OCR environment has unexpected packages: " + ", ".join(sorted(unexpected))
        )
    if missing:
        raise RuntimeInventoryError(
            "OCR environment is missing packages: " + ", ".join(sorted(missing))
        )
    for package, expected_version in locked.items():
        if installed[package] != expected_version:
            raise RuntimeInventoryError(
                f"OCR package version changed: {package}"
            )
    if installed["dahe-ocr-worker"] != worker_version:
        raise RuntimeInventoryError("OCR worker package version changed")


def inventory_sha256(inventory: dict[str, str]) -> str:
    payload = json.dumps(
        dict(sorted(inventory.items())),
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()
