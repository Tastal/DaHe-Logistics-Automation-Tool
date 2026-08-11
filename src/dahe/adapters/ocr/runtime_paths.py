from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path


class OcrRuntimePathError(RuntimeError):
    """Raised when no Windows-safe OCR runtime location is available."""


def _is_ascii_path(path: Path) -> bool:
    return os.fspath(path).isascii()


def _validate_explicit_root(path: Path, *, windows: bool) -> Path:
    if not path.is_absolute():
        raise OcrRuntimePathError("OCR runtime root must be an absolute path")
    if path == Path(path.anchor):
        raise OcrRuntimePathError("OCR runtime root cannot be a drive root")
    if windows and not _is_ascii_path(path):
        raise OcrRuntimePathError(
            "PaddleOCR on Windows requires an ASCII OCR runtime root"
        )
    return path


def choose_ocr_runtime_root(
    *,
    repository_root: Path,
    explicit_root: Path | None = None,
    environ: Mapping[str, str] | None = None,
    windows: bool | None = None,
    require_active_composition: bool = False,
) -> Path:
    """Choose a portable runtime root without persisting a machine path in source.

    Runtime creation may select a new location. Runtime consumers must request an
    active composition so a release-local placeholder cannot shadow an installed
    and qualified runtime.
    """

    is_windows = os.name == "nt" if windows is None else windows
    if explicit_root is not None:
        return _validate_explicit_root(explicit_root, windows=is_windows)

    environment = os.environ if environ is None else environ
    managed_runtime = environment.get("DAHE_OCR_RUNTIME_ROOT")
    candidates = (
        [Path(managed_runtime)]
        if managed_runtime
        else [repository_root / ".runtime"]
    )
    local_app_data = environment.get("LOCALAPPDATA")
    if local_app_data and not managed_runtime:
        candidates.append(
            Path(local_app_data)
            / "Programs"
            / "DaHeLogistics"
            / "ocr-runtime"
        )
    program_data = environment.get("PROGRAMDATA")
    if program_data and not managed_runtime:
        candidates.append(Path(program_data) / "DaHeLogistics" / "ocr-runtime")

    portable_candidates = [
        candidate
        for candidate in candidates
        if candidate.is_absolute() and (not is_windows or _is_ascii_path(candidate))
    ]
    if require_active_composition:
        for candidate in portable_candidates:
            if (candidate / "active-composition.json").is_file():
                return candidate
        raise OcrRuntimePathError(
            "No active OCR runtime composition was found in a Windows-safe location"
        )
    if portable_candidates:
        return portable_candidates[0]
    raise OcrRuntimePathError(
        "No Windows-safe OCR runtime root was found; choose an ASCII path "
        "with --runtime-root."
    )
