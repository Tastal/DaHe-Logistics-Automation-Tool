from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

MAX_PYTHON_SOURCE_FILES = 1_000
MAX_PYTHON_SOURCE_BYTES = 16 * 1024 * 1024


class SourceFingerprintError(RuntimeError):
    """Raised when an OCR worker source tree cannot be fingerprinted safely."""


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _controlled_python_sources(root: Path) -> tuple[Path, ...]:
    paths: list[Path] = []
    total_bytes = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except OSError as exc:
            raise SourceFingerprintError(
                "OCR worker source cannot be inventoried"
            ) from exc
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink() or _is_reparse_point(path):
                raise SourceFingerprintError(
                    "OCR worker source contains a link or reparse point"
                )
            if entry.is_dir(follow_symlinks=False):
                if entry.name != "__pycache__":
                    pending.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise SourceFingerprintError(
                    "OCR worker source contains a special file"
                )
            if path.suffix != ".py":
                continue
            metadata = path.stat(follow_symlinks=False)
            if metadata.st_nlink != 1:
                raise SourceFingerprintError(
                    "OCR worker source contains a hard link"
                )
            paths.append(path)
            total_bytes += metadata.st_size
            if (
                len(paths) > MAX_PYTHON_SOURCE_FILES
                or total_bytes > MAX_PYTHON_SOURCE_BYTES
            ):
                raise SourceFingerprintError(
                    "OCR worker source exceeds its inventory limits"
                )
    return tuple(sorted(paths))


def python_source_tree_sha256(root: Path) -> str:
    """Hash only versionable Python source, never interpreter cache artifacts."""

    try:
        resolved_root = root.resolve(strict=True)
    except OSError as exc:
        raise SourceFingerprintError("OCR worker source is missing") from exc
    if not resolved_root.is_dir() or root.is_symlink():
        raise SourceFingerprintError("OCR worker source root is unsafe")
    if _is_reparse_point(resolved_root):
        raise SourceFingerprintError("OCR worker source root is unsafe")
    paths = _controlled_python_sources(resolved_root)
    if not paths:
        raise SourceFingerprintError("OCR worker source contains no Python files")

    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(resolved_root).as_posix()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        digest.update(b"\0")
    return digest.hexdigest()


def installed_worker_source_root(
    *,
    python: Path,
    runtime_dir: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> Path:
    """Locate the actual package imported by one isolated runtime."""

    script = (
        "import importlib.util,json;"
        "spec=importlib.util.find_spec('dahe_ocr_worker');"
        "locations=[] if spec is None or spec.submodule_search_locations is None "
        "else list(spec.submodule_search_locations);"
        "print(json.dumps(locations))"
    )
    try:
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
    except (
        json.JSONDecodeError,
        OSError,
        subprocess.SubprocessError,
        UnicodeError,
    ) as exc:
        raise SourceFingerprintError(
            "installed OCR worker source cannot be located"
        ) from exc
    if (
        not isinstance(payload, list)
        or len(payload) != 1
        or not isinstance(payload[0], str)
    ):
        raise SourceFingerprintError(
            "installed OCR worker package location is invalid"
        )
    try:
        resolved_runtime = runtime_dir.resolve(strict=True)
        source_root = Path(payload[0]).resolve(strict=True)
        source_root.relative_to(resolved_runtime)
    except (OSError, ValueError) as exc:
        raise SourceFingerprintError(
            "installed OCR worker package is outside its isolated runtime"
        ) from exc
    if not source_root.is_dir() or source_root.is_symlink() or _is_reparse_point(
        source_root
    ):
        raise SourceFingerprintError("installed OCR worker package is unsafe")
    return source_root


def installed_worker_source_sha256(
    *,
    python: Path,
    runtime_dir: Path,
    runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    return python_source_tree_sha256(
        installed_worker_source_root(
            python=python,
            runtime_dir=runtime_dir,
            runner=runner,
        )
    )
