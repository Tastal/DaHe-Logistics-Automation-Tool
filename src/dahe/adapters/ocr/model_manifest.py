from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

SHA256_CHARS = frozenset("0123456789abcdef")
MAX_MODEL_FILE_COUNT = 10_000
MAX_RELATIVE_PATH_CHARS = 512
REQUIRED_MODELS = {
    "PP-OCRv6_medium_det": "text_detection",
    "PP-OCRv6_medium_rec": "text_recognition",
}


class ModelManifestVerificationError(RuntimeError):
    """Raised when a local OCR model set is incomplete, changed, or unsafe."""


@dataclass(frozen=True, slots=True)
class VerifiedModelManifest:
    model_set_id: str
    manifest_sha256: str
    models_dir: Path
    file_count: int
    total_size_bytes: int


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _safe_file(root: Path, relative_path: str) -> Path:
    if (
        not relative_path
        or len(relative_path) > MAX_RELATIVE_PATH_CHARS
        or "\\" in relative_path
        or ":" in relative_path
    ):
        raise ModelManifestVerificationError("model manifest path is invalid")
    portable = PurePosixPath(relative_path)
    if portable.is_absolute() or ".." in portable.parts or "." in portable.parts:
        raise ModelManifestVerificationError(
            "model manifest path escapes the model root"
        )
    if not portable.parts or portable.parts[0] not in REQUIRED_MODELS:
        raise ModelManifestVerificationError(
            "model manifest path is outside the required model set"
        )
    current = root
    for part in portable.parts:
        current /= part
        if current.is_symlink():
            raise ModelManifestVerificationError(
                "model manifest path uses a link or reparse point"
            )
        if not current.exists():
            raise ModelManifestVerificationError("model manifest entry is missing")
        if _is_reparse_point(current):
            raise ModelManifestVerificationError(
                "model manifest path uses a link or reparse point"
            )
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ModelManifestVerificationError(
            "model manifest path escapes the model root"
        ) from exc
    if not resolved.is_file():
        raise ModelManifestVerificationError("model manifest entry is not a file")
    if resolved.stat().st_nlink != 1:
        raise ModelManifestVerificationError("model manifest entry uses a hard link")
    return resolved


def _inventory_model_files(root: Path) -> set[str]:
    inventory: set[str] = set()
    for model_name in REQUIRED_MODELS:
        model_dir = root / model_name
        if (
            not model_dir.is_dir()
            or model_dir.is_symlink()
            or _is_reparse_point(model_dir)
        ):
            raise ModelManifestVerificationError(
                "required model directory is missing or unsafe"
            )
        pending = [model_dir]
        while pending:
            directory = pending.pop()
            for entry in os.scandir(directory):
                path = Path(entry.path)
                if entry.is_symlink() or _is_reparse_point(path):
                    raise ModelManifestVerificationError(
                        "model inventory contains a link or reparse point"
                    )
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ModelManifestVerificationError(
                        "model inventory contains a special file"
                    )
                if path.stat(follow_symlinks=False).st_nlink != 1:
                    raise ModelManifestVerificationError(
                        "model inventory contains a hard link"
                    )
                inventory.add(path.relative_to(root).as_posix())
                if len(inventory) > MAX_MODEL_FILE_COUNT:
                    raise ModelManifestVerificationError(
                        "model inventory exceeds the file-count limit"
                    )
    return inventory


def verify_model_manifest(
    *,
    models_dir: Path,
    manifest_path: Path,
) -> VerifiedModelManifest:
    """Independently verify the exact local model inventory before worker launch."""
    root = models_dir.resolve(strict=True)
    resolved_manifest = manifest_path.resolve(strict=True)
    if (
        resolved_manifest.parent != root
        or resolved_manifest.name != "model-manifest.json"
        or manifest_path.is_symlink()
        or _is_reparse_point(manifest_path)
        or resolved_manifest.stat().st_nlink != 1
    ):
        raise ModelManifestVerificationError("model manifest location is unsafe")
    try:
        manifest_bytes = resolved_manifest.read_bytes()
        manifest = json.loads(manifest_bytes.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelManifestVerificationError("model manifest is unreadable") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "model_set_id",
        "models",
        "files",
    }:
        raise ModelManifestVerificationError("model manifest fields are invalid")
    if manifest["schema_version"] != 1:
        raise ModelManifestVerificationError("model manifest version is unsupported")
    model_set_id = manifest["model_set_id"]
    if (
        not isinstance(model_set_id, str)
        or not model_set_id.strip()
        or len(model_set_id) > 128
    ):
        raise ModelManifestVerificationError("model manifest identity is invalid")
    models = manifest["models"]
    if not isinstance(models, list) or len(models) != len(REQUIRED_MODELS):
        raise ModelManifestVerificationError(
            "model manifest has no model directories"
        )
    declared_models: dict[str, str] = {}
    for item in models:
        if not isinstance(item, dict) or set(item) != {"name", "purpose"}:
            raise ModelManifestVerificationError(
                "model manifest model entry is invalid"
            )
        name = item["name"]
        purpose = item["purpose"]
        if (
            not isinstance(name, str)
            or not isinstance(purpose, str)
            or name in declared_models
        ):
            raise ModelManifestVerificationError(
                "model manifest model entry is invalid"
            )
        declared_models[name] = purpose
    if declared_models != REQUIRED_MODELS:
        raise ModelManifestVerificationError(
            "model manifest does not contain the required model set"
        )
    files = manifest["files"]
    if (
        not isinstance(files, list)
        or not files
        or len(files) > MAX_MODEL_FILE_COUNT
    ):
        raise ModelManifestVerificationError("model manifest has no files")

    declared_paths: set[str] = set()
    total_size = 0
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {
            "relative_path",
            "size_bytes",
            "sha256",
        }:
            raise ModelManifestVerificationError(
                "model manifest file entry is invalid"
            )
        relative_path = entry["relative_path"]
        expected_size = entry["size_bytes"]
        expected_sha = entry["sha256"]
        if (
            not isinstance(relative_path, str)
            or relative_path in declared_paths
            or not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or not isinstance(expected_sha, str)
            or len(expected_sha) != 64
            or any(character not in SHA256_CHARS for character in expected_sha)
        ):
            raise ModelManifestVerificationError(
                "model manifest file metadata is invalid"
            )
        declared_paths.add(relative_path)
        path = _safe_file(root, relative_path)
        if path.stat().st_size != expected_size:
            raise ModelManifestVerificationError(
                "model file size does not match its manifest"
            )
        if _sha256_file(path) != expected_sha:
            raise ModelManifestVerificationError(
                "model file hash does not match its manifest"
            )
        total_size += expected_size
    if _inventory_model_files(root) != declared_paths:
        raise ModelManifestVerificationError(
            "model inventory does not exactly match the manifest file set"
        )
    return VerifiedModelManifest(
        model_set_id=model_set_id,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        models_dir=root,
        file_count=len(declared_paths),
        total_size_bytes=total_size,
    )
