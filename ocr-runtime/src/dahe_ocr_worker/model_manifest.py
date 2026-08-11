from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path, PurePosixPath
from typing import Any

SHA256_LENGTH = 64
SHA256_CHARS = frozenset("0123456789abcdef")
MAX_MODEL_FILE_COUNT = 10_000
MAX_RELATIVE_PATH_CHARS = 512
REQUIRED_MODELS = {
    "PP-OCRv6_medium_det": "text_detection",
    "PP-OCRv6_medium_rec": "text_recognition",
}


class ModelManifestError(RuntimeError):
    """Raised when immutable local model assets do not match their manifest."""


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _safe_file(root: Path, relative_path: str) -> Path:
    if (
        not relative_path
        or len(relative_path) > MAX_RELATIVE_PATH_CHARS
        or "\\" in relative_path
        or ":" in relative_path
    ):
        raise ModelManifestError("model manifest path is invalid")
    portable = PurePosixPath(relative_path)
    if portable.is_absolute() or ".." in portable.parts or "." in portable.parts:
        raise ModelManifestError("model manifest path escapes the model root")
    relative = Path(*portable.parts)
    if not portable.parts or portable.parts[0] not in REQUIRED_MODELS:
        raise ModelManifestError("model manifest path is outside the required model set")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ModelManifestError("model manifest path uses a link or reparse point")
        if not current.exists():
            raise ModelManifestError("model manifest entry is missing")
        if _is_reparse_point(current):
            raise ModelManifestError("model manifest path uses a link or reparse point")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ModelManifestError("model manifest path escapes the model root") from exc
    if not resolved.is_file():
        raise ModelManifestError("model manifest entry is not a file")
    if resolved.stat().st_nlink != 1:
        raise ModelManifestError("model manifest entry uses a hard link")
    return resolved


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _inventory_model_files(root: Path) -> set[str]:
    inventory: set[str] = set()
    for model_name in REQUIRED_MODELS:
        model_dir = root / model_name
        if (
            not model_dir.is_dir()
            or model_dir.is_symlink()
            or _is_reparse_point(model_dir)
        ):
            raise ModelManifestError("required model directory is missing or unsafe")
        pending = [model_dir]
        while pending:
            directory = pending.pop()
            for entry in os.scandir(directory):
                path = Path(entry.path)
                if entry.is_symlink() or _is_reparse_point(path):
                    raise ModelManifestError("model inventory contains a link or reparse point")
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise ModelManifestError("model inventory contains a special file")
                if path.stat(follow_symlinks=False).st_nlink != 1:
                    raise ModelManifestError("model inventory contains a hard link")
                inventory.add(path.relative_to(root).as_posix())
                if len(inventory) > MAX_MODEL_FILE_COUNT:
                    raise ModelManifestError("model inventory exceeds the file-count limit")
    return inventory


def load_and_verify_model_manifest(
    *,
    models_dir: Path,
    manifest_path: Path,
) -> dict[str, Any]:
    root = models_dir.resolve(strict=True)
    resolved_manifest = manifest_path.resolve(strict=True)
    if (
        resolved_manifest.parent != root
        or resolved_manifest.name != "model-manifest.json"
        or manifest_path.is_symlink()
        or _is_reparse_point(manifest_path)
        or resolved_manifest.stat().st_nlink != 1
    ):
        raise ModelManifestError("model manifest location is unsafe")
    try:
        manifest = json.loads(resolved_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ModelManifestError("model manifest is unreadable") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema_version",
        "model_set_id",
        "models",
        "files",
    }:
        raise ModelManifestError("model manifest fields are invalid")
    if manifest["schema_version"] != 1:
        raise ModelManifestError("model manifest version is unsupported")
    if (
        not isinstance(manifest["model_set_id"], str)
        or not manifest["model_set_id"].strip()
        or len(manifest["model_set_id"]) > 128
    ):
        raise ModelManifestError("model manifest identity is invalid")
    models = manifest["models"]
    if not isinstance(models, list) or len(models) != len(REQUIRED_MODELS):
        raise ModelManifestError("model manifest has no model directories")
    declared_models: dict[str, str] = {}
    for item in models:
        if not isinstance(item, dict) or set(item) != {"name", "purpose"}:
            raise ModelManifestError("model manifest model entry is invalid")
        name = item["name"]
        purpose = item["purpose"]
        if (
            not isinstance(name, str)
            or not isinstance(purpose, str)
            or name in declared_models
        ):
            raise ModelManifestError("model manifest model entry is invalid")
        declared_models[name] = purpose
    if declared_models != REQUIRED_MODELS:
        raise ModelManifestError("model manifest does not contain the required model set")
    files = manifest["files"]
    if (
        not isinstance(files, list)
        or not files
        or len(files) > MAX_MODEL_FILE_COUNT
    ):
        raise ModelManifestError("model manifest has no files")
    seen: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {
            "relative_path",
            "size_bytes",
            "sha256",
        }:
            raise ModelManifestError("model manifest file entry is invalid")
        relative_path = entry["relative_path"]
        expected_size = entry["size_bytes"]
        expected_sha = entry["sha256"]
        if (
            not isinstance(relative_path, str)
            or relative_path in seen
            or not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size < 0
            or not isinstance(expected_sha, str)
            or len(expected_sha) != SHA256_LENGTH
            or any(character not in SHA256_CHARS for character in expected_sha)
        ):
            raise ModelManifestError("model manifest file metadata is invalid")
        seen.add(relative_path)
        path = _safe_file(root, relative_path)
        if path.stat().st_size != expected_size:
            raise ModelManifestError("model file size does not match its manifest")
        digest = _sha256_file(path)
        if digest != expected_sha:
            raise ModelManifestError("model file hash does not match its manifest")
    inventory = _inventory_model_files(root)
    if inventory != seen:
        raise ModelManifestError(
            "model inventory does not exactly match the manifest file set"
        )
    manifest["manifest_sha256"] = hashlib.sha256(
        resolved_manifest.read_bytes()
    ).hexdigest()
    manifest["models_dir"] = os.fspath(root)
    return manifest
