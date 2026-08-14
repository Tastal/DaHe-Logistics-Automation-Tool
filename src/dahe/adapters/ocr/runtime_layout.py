from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import uuid4

POINTER_SCHEMA_VERSION = 1
COMPOSITION_SCHEMA_VERSION = 1
FLAT_POINTER_SCHEMA_VERSION = 2
FLAT_COMPOSITION_SCHEMA_VERSION = 2
POINTER_NAME = "active-composition.json"
COMPOSITION_MANIFEST_NAME = "composition-manifest.json"
GENERATION_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class OcrRuntimeLayoutError(RuntimeError):
    """Raised when an OCR composition pointer or generation is unsafe."""


@dataclass(frozen=True, slots=True)
class ActiveOcrComposition:
    generation_id: str | None
    generation_dir: Path | None
    cpu_runtime: Path
    gpu_runtime: Path | None
    models_dir: Path
    qualification_path: Path


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except AttributeError:
        return path.is_symlink()
    except OSError:
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _safe_existing_root(path: Path, *, label: str) -> Path:
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise OcrRuntimeLayoutError(f"{label} is missing") from exc
    if not resolved.is_dir() or path.is_symlink() or _is_reparse_point(path):
        raise OcrRuntimeLayoutError(f"{label} is unsafe")
    return resolved


def _read_json(path: Path, *, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OcrRuntimeLayoutError(f"{label} is unreadable") from exc
    if not isinstance(payload, dict):
        raise OcrRuntimeLayoutError(f"{label} must be a JSON object")
    return payload


def _write_json_atomic(target: Path, payload: dict[str, Any]) -> None:
    temporary = target.with_name(f".{target.name}.{uuid4().hex}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(
                payload,
                stream,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()


def _safe_generation_child(
    generation_dir: Path,
    relative: str,
    *,
    kind: str,
) -> Path:
    if (
        not relative
        or "\\" in relative
        or ":" in relative
        or Path(relative).is_absolute()
    ):
        raise OcrRuntimeLayoutError("composition path is invalid")
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise OcrRuntimeLayoutError("composition path escapes its generation")
    current = generation_dir
    for part in parts:
        current /= part
        if current.is_symlink() or _is_reparse_point(current):
            raise OcrRuntimeLayoutError(
                "composition path uses a link or reparse point"
            )
        if not current.exists():
            raise OcrRuntimeLayoutError("composition entry is missing")
    try:
        resolved = current.resolve(strict=True)
        resolved.relative_to(generation_dir)
    except (OSError, ValueError) as exc:
        raise OcrRuntimeLayoutError(
            "composition path escapes its generation"
        ) from exc
    if kind == "directory" and not resolved.is_dir():
        raise OcrRuntimeLayoutError("composition directory is invalid")
    if kind == "file" and not resolved.is_file():
        raise OcrRuntimeLayoutError("composition file is invalid")
    return resolved


def _validate_generation_inventory(
    generation_dir: Path,
    *,
    gpu_present: bool,
) -> None:
    expected = {
        COMPOSITION_MANIFEST_NAME,
        "model-cache",
        "ocr-cpu",
        "qualification",
    }
    if gpu_present:
        expected.add("ocr-gpu")
    actual = {entry.name for entry in os.scandir(generation_dir)}
    if actual != expected:
        raise OcrRuntimeLayoutError(
            "composition generation has unexpected top-level entries"
        )
    model_cache_entries = {
        entry.name for entry in os.scandir(generation_dir / "model-cache")
    }
    if model_cache_entries != {"official_models"}:
        raise OcrRuntimeLayoutError(
            "composition model cache contains unexpected entries"
        )
    qualification_entries = {
        entry.name for entry in os.scandir(generation_dir / "qualification")
    }
    if qualification_entries != {"qualification.json"}:
        raise OcrRuntimeLayoutError(
            "composition qualification contains unexpected entries"
        )


def _load_generation(
    *,
    runtime_root: Path,
    generation_id: str,
    expected_manifest_sha256: str | None,
) -> ActiveOcrComposition:
    if GENERATION_ID_PATTERN.fullmatch(generation_id) is None:
        raise OcrRuntimeLayoutError("composition generation identity is invalid")
    generations_dir = _safe_existing_root(
        runtime_root / "generations",
        label="OCR composition generations directory",
    )
    if generations_dir.parent != runtime_root:
        raise OcrRuntimeLayoutError(
            "OCR composition generations directory escapes the runtime root"
        )
    generation_dir = _safe_existing_root(
        generations_dir / generation_id,
        label="OCR composition generation",
    )
    try:
        generation_dir.relative_to(runtime_root)
    except ValueError as exc:
        raise OcrRuntimeLayoutError(
            "OCR composition generation escapes the runtime root"
        ) from exc
    manifest_path = generation_dir / COMPOSITION_MANIFEST_NAME
    if (
        manifest_path.is_symlink()
        or _is_reparse_point(manifest_path)
        or not manifest_path.is_file()
    ):
        raise OcrRuntimeLayoutError("OCR composition manifest is unsafe")
    manifest_sha256 = _sha256_file(manifest_path)
    if (
        expected_manifest_sha256 is not None
        and manifest_sha256 != expected_manifest_sha256
    ):
        raise OcrRuntimeLayoutError("OCR composition manifest hash changed")
    manifest = _read_json(manifest_path, label="OCR composition manifest")
    if set(manifest) != {
        "schema_version",
        "generation_id",
        "cpu_runtime",
        "gpu_runtime",
        "models_dir",
        "qualification_path",
        "model_manifest_sha256",
        "qualification_sha256",
        "runtime_installation_sha256",
    }:
        raise OcrRuntimeLayoutError("OCR composition manifest fields are invalid")
    if (
        manifest["schema_version"] != COMPOSITION_SCHEMA_VERSION
        or manifest["generation_id"] != generation_id
        or manifest["cpu_runtime"] != "ocr-cpu"
        or manifest["models_dir"] != "model-cache/official_models"
        or manifest["qualification_path"] != "qualification/qualification.json"
        or manifest["gpu_runtime"] not in {None, "ocr-gpu"}
    ):
        raise OcrRuntimeLayoutError("OCR composition manifest is invalid")
    hashes = manifest["runtime_installation_sha256"]
    expected_runtime_keys = (
        {"cpu", "gpu"} if manifest["gpu_runtime"] is not None else {"cpu"}
    )
    if (
        not isinstance(hashes, dict)
        or set(hashes) != expected_runtime_keys
        or any(
            not isinstance(value, str)
            or SHA256_PATTERN.fullmatch(value) is None
            for value in hashes.values()
        )
    ):
        raise OcrRuntimeLayoutError(
            "OCR composition runtime hashes are invalid"
        )
    for name in ("model_manifest_sha256", "qualification_sha256"):
        value = manifest[name]
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise OcrRuntimeLayoutError("OCR composition hashes are invalid")

    cpu_runtime = _safe_generation_child(
        generation_dir,
        "ocr-cpu",
        kind="directory",
    )
    gpu_runtime = (
        None
        if manifest["gpu_runtime"] is None
        else _safe_generation_child(
            generation_dir,
            "ocr-gpu",
            kind="directory",
        )
    )
    models_dir = _safe_generation_child(
        generation_dir,
        "model-cache/official_models",
        kind="directory",
    )
    qualification_path = _safe_generation_child(
        generation_dir,
        "qualification/qualification.json",
        kind="file",
    )
    model_manifest = _safe_generation_child(
        generation_dir,
        "model-cache/official_models/model-manifest.json",
        kind="file",
    )
    runtime_manifests = {
        "cpu": _safe_generation_child(
            generation_dir,
            "ocr-cpu/runtime-installation.json",
            kind="file",
        )
    }
    if gpu_runtime is not None:
        runtime_manifests["gpu"] = _safe_generation_child(
            generation_dir,
            "ocr-gpu/runtime-installation.json",
            kind="file",
        )
    if _sha256_file(model_manifest) != manifest["model_manifest_sha256"]:
        raise OcrRuntimeLayoutError("active model manifest hash changed")
    if _sha256_file(qualification_path) != manifest["qualification_sha256"]:
        raise OcrRuntimeLayoutError("active qualification hash changed")
    qualification = _read_json(
        qualification_path,
        label="active OCR qualification",
    )
    reports = qualification.get("reports")
    if not isinstance(reports, list) or any(
        not isinstance(report, dict)
        or report.get("runtime_kind") not in {"cpu", "gpu"}
        for report in reports
    ):
        raise OcrRuntimeLayoutError(
            "active qualification runtime set is invalid"
        )
    qualified_runtime_kinds = {
        str(report["runtime_kind"])
        for report in reports
    }
    if qualified_runtime_kinds != expected_runtime_keys:
        raise OcrRuntimeLayoutError(
            "active qualification does not bind every runtime"
        )
    for kind, runtime_manifest in runtime_manifests.items():
        if _sha256_file(runtime_manifest) != hashes[kind]:
            raise OcrRuntimeLayoutError(
                "active runtime installation manifest hash changed"
            )
    _validate_generation_inventory(
        generation_dir,
        gpu_present=gpu_runtime is not None,
    )
    return ActiveOcrComposition(
        generation_id=generation_id,
        generation_dir=generation_dir,
        cpu_runtime=cpu_runtime,
        gpu_runtime=gpu_runtime,
        models_dir=models_dir,
        qualification_path=qualification_path,
    )


def _load_flat_composition(
    *,
    runtime_root: Path,
    generation_id: str,
    expected_manifest_sha256: str,
) -> ActiveOcrComposition:
    if GENERATION_ID_PATTERN.fullmatch(generation_id) is None:
        raise OcrRuntimeLayoutError("composition generation identity is invalid")
    manifest_path = runtime_root / COMPOSITION_MANIFEST_NAME
    if (
        manifest_path.is_symlink()
        or _is_reparse_point(manifest_path)
        or not manifest_path.is_file()
    ):
        raise OcrRuntimeLayoutError("OCR composition manifest is unsafe")
    if _sha256_file(manifest_path) != expected_manifest_sha256:
        raise OcrRuntimeLayoutError("OCR composition manifest hash changed")
    manifest = _read_json(manifest_path, label="OCR composition manifest")
    if set(manifest) != {
        "schema_version",
        "generation_id",
        "cpu_runtime",
        "gpu_runtime",
        "models_dir",
        "qualification_path",
        "model_manifest_sha256",
        "qualification_sha256",
        "runtime_installation_sha256",
    }:
        raise OcrRuntimeLayoutError("OCR composition manifest fields are invalid")
    if (
        manifest["schema_version"] != FLAT_COMPOSITION_SCHEMA_VERSION
        or manifest["generation_id"] != generation_id
        or manifest["cpu_runtime"] != "c"
        or manifest["gpu_runtime"] is not None
        or manifest["models_dir"] != "m/official_models"
        or manifest["qualification_path"] != "q/qualification.json"
    ):
        raise OcrRuntimeLayoutError("OCR composition manifest is invalid")
    hashes = manifest["runtime_installation_sha256"]
    if (
        not isinstance(hashes, dict)
        or set(hashes) != {"cpu"}
        or not isinstance(hashes["cpu"], str)
        or SHA256_PATTERN.fullmatch(hashes["cpu"]) is None
    ):
        raise OcrRuntimeLayoutError("OCR composition runtime hashes are invalid")
    for name in ("model_manifest_sha256", "qualification_sha256"):
        value = manifest[name]
        if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
            raise OcrRuntimeLayoutError("OCR composition hashes are invalid")

    expected_entries = {
        POINTER_NAME,
        COMPOSITION_MANIFEST_NAME,
        "c",
        "m",
        "q",
    }
    if {entry.name for entry in os.scandir(runtime_root)} != expected_entries:
        raise OcrRuntimeLayoutError(
            "flat composition contains unexpected top-level entries"
        )
    if {entry.name for entry in os.scandir(runtime_root / "m")} != {
        "official_models"
    }:
        raise OcrRuntimeLayoutError("flat model cache contains unexpected entries")
    if {entry.name for entry in os.scandir(runtime_root / "q")} != {
        "qualification.json"
    }:
        raise OcrRuntimeLayoutError(
            "flat qualification contains unexpected entries"
        )

    cpu_runtime = _safe_generation_child(runtime_root, "c", kind="directory")
    models_dir = _safe_generation_child(
        runtime_root,
        "m/official_models",
        kind="directory",
    )
    qualification_path = _safe_generation_child(
        runtime_root,
        "q/qualification.json",
        kind="file",
    )
    model_manifest = _safe_generation_child(
        runtime_root,
        "m/official_models/model-manifest.json",
        kind="file",
    )
    runtime_manifest = _safe_generation_child(
        runtime_root,
        "c/runtime-installation.json",
        kind="file",
    )
    if _sha256_file(model_manifest) != manifest["model_manifest_sha256"]:
        raise OcrRuntimeLayoutError("active model manifest hash changed")
    if _sha256_file(qualification_path) != manifest["qualification_sha256"]:
        raise OcrRuntimeLayoutError("active qualification hash changed")
    if _sha256_file(runtime_manifest) != hashes["cpu"]:
        raise OcrRuntimeLayoutError("active runtime installation manifest hash changed")
    qualification = _read_json(
        qualification_path,
        label="active OCR qualification",
    )
    reports = qualification.get("reports")
    if (
        not isinstance(reports, list)
        or any(
            not isinstance(report, dict)
            or report.get("runtime_kind") not in {"cpu", "gpu"}
            for report in reports
        )
        or {str(report["runtime_kind"]) for report in reports} != {"cpu"}
    ):
        raise OcrRuntimeLayoutError(
            "active qualification runtime set is invalid"
        )
    return ActiveOcrComposition(
        generation_id=generation_id,
        generation_dir=runtime_root,
        cpu_runtime=cpu_runtime,
        gpu_runtime=None,
        models_dir=models_dir,
        qualification_path=qualification_path,
    )


def write_flat_composition_manifest(
    *,
    runtime_root: Path,
    generation_id: str,
) -> Path:
    resolved_root = runtime_root.resolve(strict=True)
    if GENERATION_ID_PATTERN.fullmatch(generation_id) is None:
        raise OcrRuntimeLayoutError("composition generation identity is invalid")
    cpu_manifest = resolved_root / "c" / "runtime-installation.json"
    model_manifest = (
        resolved_root / "m" / "official_models" / "model-manifest.json"
    )
    qualification = resolved_root / "q" / "qualification.json"
    if any(
        not path.is_file()
        for path in (cpu_manifest, model_manifest, qualification)
    ):
        raise OcrRuntimeLayoutError(
            "flat composition cannot be sealed before every artifact exists"
        )
    payload = {
        "schema_version": FLAT_COMPOSITION_SCHEMA_VERSION,
        "generation_id": generation_id,
        "cpu_runtime": "c",
        "gpu_runtime": None,
        "models_dir": "m/official_models",
        "qualification_path": "q/qualification.json",
        "model_manifest_sha256": _sha256_file(model_manifest),
        "qualification_sha256": _sha256_file(qualification),
        "runtime_installation_sha256": {
            "cpu": _sha256_file(cpu_manifest),
        },
    }
    target = resolved_root / COMPOSITION_MANIFEST_NAME
    _write_json_atomic(target, payload)
    return target


def activate_flat_composition(
    *,
    runtime_root: Path,
    generation_id: str,
) -> ActiveOcrComposition:
    resolved_root = runtime_root.resolve(strict=True)
    manifest_path = resolved_root / COMPOSITION_MANIFEST_NAME
    if not manifest_path.is_file():
        raise OcrRuntimeLayoutError("flat OCR composition manifest is missing")
    manifest_sha256 = _sha256_file(manifest_path)
    pointer = {
        "schema_version": FLAT_POINTER_SCHEMA_VERSION,
        "generation_id": generation_id,
        "composition_manifest": COMPOSITION_MANIFEST_NAME,
        "composition_manifest_sha256": manifest_sha256,
    }
    _write_json_atomic(resolved_root / POINTER_NAME, pointer)
    return _load_flat_composition(
        runtime_root=resolved_root,
        generation_id=generation_id,
        expected_manifest_sha256=manifest_sha256,
    )


def write_composition_manifest(
    *,
    generation_dir: Path,
    generation_id: str,
    gpu_present: bool,
) -> Path:
    resolved_generation = generation_dir.resolve(strict=True)
    if (
        resolved_generation.name != generation_id
        or GENERATION_ID_PATTERN.fullmatch(generation_id) is None
    ):
        raise OcrRuntimeLayoutError("composition generation identity is invalid")
    cpu_manifest = resolved_generation / "ocr-cpu" / "runtime-installation.json"
    gpu_manifest = resolved_generation / "ocr-gpu" / "runtime-installation.json"
    model_manifest = (
        resolved_generation
        / "model-cache"
        / "official_models"
        / "model-manifest.json"
    )
    qualification = (
        resolved_generation / "qualification" / "qualification.json"
    )
    required = [cpu_manifest, model_manifest, qualification]
    if gpu_present:
        required.append(gpu_manifest)
    if any(not path.is_file() for path in required):
        raise OcrRuntimeLayoutError(
            "composition cannot be sealed before every artifact exists"
        )
    payload = {
        "schema_version": COMPOSITION_SCHEMA_VERSION,
        "generation_id": generation_id,
        "cpu_runtime": "ocr-cpu",
        "gpu_runtime": "ocr-gpu" if gpu_present else None,
        "models_dir": "model-cache/official_models",
        "qualification_path": "qualification/qualification.json",
        "model_manifest_sha256": _sha256_file(model_manifest),
        "qualification_sha256": _sha256_file(qualification),
        "runtime_installation_sha256": {
            "cpu": _sha256_file(cpu_manifest),
            **(
                {"gpu": _sha256_file(gpu_manifest)}
                if gpu_present
                else {}
            ),
        },
    }
    target = resolved_generation / COMPOSITION_MANIFEST_NAME
    _write_json_atomic(target, payload)
    return target


def activate_composition(
    *,
    runtime_root: Path,
    generation_id: str,
) -> ActiveOcrComposition:
    resolved_root = runtime_root.resolve(strict=True)
    candidate = _load_generation(
        runtime_root=resolved_root,
        generation_id=generation_id,
        expected_manifest_sha256=None,
    )
    assert candidate.generation_dir is not None
    manifest_path = candidate.generation_dir / COMPOSITION_MANIFEST_NAME
    pointer = {
        "schema_version": POINTER_SCHEMA_VERSION,
        "generation_id": generation_id,
        "composition_manifest": (
            f"generations/{generation_id}/{COMPOSITION_MANIFEST_NAME}"
        ),
        "composition_manifest_sha256": _sha256_file(manifest_path),
    }
    target = resolved_root / POINTER_NAME
    _write_json_atomic(target, pointer)
    return candidate


def _legacy_composition(runtime_root: Path) -> ActiveOcrComposition:
    cpu_runtime = _safe_existing_root(
        runtime_root / "ocr-cpu",
        label="legacy CPU OCR runtime",
    )
    legacy_gpu = runtime_root / "ocr-gpu"
    gpu_runtime = (
        _safe_existing_root(legacy_gpu, label="legacy GPU OCR runtime")
        if legacy_gpu.exists()
        else None
    )
    models_dir = _safe_existing_root(
        runtime_root / "model-cache" / "official_models",
        label="legacy OCR models",
    )
    qualification_path = (
        runtime_root / "qualification" / "qualification.json"
    )
    if (
        not qualification_path.is_file()
        or qualification_path.is_symlink()
        or _is_reparse_point(qualification_path)
    ):
        raise OcrRuntimeLayoutError("legacy OCR qualification is missing or unsafe")
    return ActiveOcrComposition(
        generation_id=None,
        generation_dir=None,
        cpu_runtime=cpu_runtime,
        gpu_runtime=gpu_runtime,
        models_dir=models_dir,
        qualification_path=qualification_path.resolve(),
    )


def resolve_active_composition(
    runtime_root: Path,
    *,
    allow_legacy: bool = True,
) -> ActiveOcrComposition:
    resolved_root = _safe_existing_root(
        runtime_root,
        label="OCR runtime root",
    )
    pointer_path = resolved_root / POINTER_NAME
    if not pointer_path.exists():
        if not allow_legacy:
            raise OcrRuntimeLayoutError("active OCR composition pointer is missing")
        return _legacy_composition(resolved_root)
    if pointer_path.is_symlink() or _is_reparse_point(pointer_path):
        raise OcrRuntimeLayoutError("active OCR composition pointer is unsafe")
    pointer = _read_json(pointer_path, label="active OCR composition pointer")
    if set(pointer) != {
        "schema_version",
        "generation_id",
        "composition_manifest",
        "composition_manifest_sha256",
    }:
        raise OcrRuntimeLayoutError(
            "active OCR composition pointer fields are invalid"
        )
    generation_id = pointer["generation_id"]
    manifest_sha256 = pointer["composition_manifest_sha256"]
    schema_version = pointer["schema_version"]
    if (
        not isinstance(generation_id, str)
        or GENERATION_ID_PATTERN.fullmatch(generation_id) is None
        or not isinstance(manifest_sha256, str)
        or SHA256_PATTERN.fullmatch(manifest_sha256) is None
    ):
        raise OcrRuntimeLayoutError("active OCR composition pointer is invalid")
    if schema_version == POINTER_SCHEMA_VERSION:
        expected_relative = (
            f"generations/{generation_id}/{COMPOSITION_MANIFEST_NAME}"
        )
        if pointer["composition_manifest"] != expected_relative:
            raise OcrRuntimeLayoutError(
                "active OCR composition pointer is invalid"
            )
        return _load_generation(
            runtime_root=resolved_root,
            generation_id=generation_id,
            expected_manifest_sha256=manifest_sha256,
        )
    if schema_version == FLAT_POINTER_SCHEMA_VERSION:
        if pointer["composition_manifest"] != COMPOSITION_MANIFEST_NAME:
            raise OcrRuntimeLayoutError(
                "active OCR composition pointer is invalid"
            )
        return _load_flat_composition(
            runtime_root=resolved_root,
            generation_id=generation_id,
            expected_manifest_sha256=manifest_sha256,
        )
    raise OcrRuntimeLayoutError("active OCR composition pointer is invalid")
