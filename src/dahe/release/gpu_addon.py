from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, cast
from uuid import uuid4

from dahe import __version__
from dahe.adapters.ocr.devices import DeviceDiscoveryError, discover_nvidia_devices
from dahe.adapters.ocr.profile_registry import (
    QualificationRegistryError,
    load_qualification_bundle,
)
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.runtime_layout import (
    ActiveOcrComposition,
    OcrRuntimeLayoutError,
    resolve_active_composition,
)
from dahe.release.launcher import read_version_pointer
from dahe.release.update_manifest import UpdateManifestError, parse_update_manifest

GPU_POINTER_NAME = "active-gpu-addon.json"
GPU_INTERNAL_MANIFEST_NAME = "gpu-addon-manifest.json"
GPU_RUNTIME_DIRECTORY = "g"
GPU_QUALIFICATION_DIRECTORY = "gq"
GPU_OVERLAY_SCHEMA_VERSION = 1
GPU_PACKAGE_SCHEMA_VERSION = 2
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GENERATION_ID = re.compile(r"^[0-9a-f]{32}$")
_MAX_ENTRIES = 100_000
_MAX_UNCOMPRESSED_BYTES = 16 * 1024**3


class GpuAddonError(RuntimeError):
    """Raised while leaving the verified CPU composition available."""

    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        stage: str,
        winerror: int | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code = error_code
        self.stage = stage
        self.winerror = winerror


@dataclass(frozen=True, slots=True)
class GpuAddonInstallResult:
    state: str
    package_version: str
    primary_runtime: str
    gpu_qualified: bool
    cpu_fallback_available: bool
    diagnostic_code: str | None


@dataclass(frozen=True, slots=True)
class GpuAddonStatus:
    state: str
    gpu_qualified: bool
    primary_runtime: str
    cpu_fallback_available: bool
    package_version: str | None
    diagnostic_code: str | None


class GpuQualifier(Protocol):
    def __call__(
        self,
        *,
        cpu_runtime_root: Path,
        gpu_runtime: Path,
        qualification_path: Path,
        source_root: Path,
        precision: str,
        batch_size: int,
        memory_safety_ratio: str,
    ) -> None: ...


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _atomic_json(path: Path, payload: dict[str, object]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid4().hex}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _is_link_or_reparse(path: Path) -> bool:
    if path.is_symlink():
        return True
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _read_json(path: Path, *, code: str, stage: str) -> dict[str, object]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GpuAddonError(
            "GPU add-on manifest is unreadable",
            error_code=code,
            stage=stage,
            winerror=getattr(exc, "winerror", None),
        ) from exc
    if not isinstance(payload, dict):
        raise GpuAddonError(
            "GPU add-on manifest is invalid",
            error_code=code,
            stage=stage,
        )
    return payload


def _safe_extract(package: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    total = 0
    seen: set[PurePosixPath] = set()
    try:
        with zipfile.ZipFile(package) as bundle:
            members = bundle.infolist()
            if not members or len(members) > _MAX_ENTRIES:
                raise GpuAddonError(
                    "GPU add-on archive entry count is invalid",
                    error_code="gpu_package_invalid",
                    stage="archive_inspect",
                )
            logical_members: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
            for member in members:
                logical = PurePosixPath(member.filename)
                if (
                    member.is_dir()
                    or logical.is_absolute()
                    or not logical.parts
                    or any(part in {"", ".", ".."} for part in logical.parts)
                    or "\\" in member.filename
                    or logical in seen
                    or (member.external_attr >> 16) & 0o170000 == 0o120000
                ):
                    raise GpuAddonError(
                        "GPU add-on archive contains an unsafe path",
                        error_code="gpu_package_unsafe",
                        stage="archive_inspect",
                    )
                if logical.parts[0] not in {
                    GPU_RUNTIME_DIRECTORY,
                    GPU_INTERNAL_MANIFEST_NAME,
                }:
                    raise GpuAddonError(
                        "GPU add-on archive inventory is invalid",
                        error_code="gpu_package_invalid",
                        stage="archive_inspect",
                    )
                if (
                    logical.parts[0] == GPU_INTERNAL_MANIFEST_NAME
                    and len(logical.parts) != 1
                ):
                    raise GpuAddonError(
                        "GPU add-on archive inventory is invalid",
                        error_code="gpu_package_invalid",
                        stage="archive_inspect",
                    )
                seen.add(logical)
                total += member.file_size
                if total > _MAX_UNCOMPRESSED_BYTES:
                    raise GpuAddonError(
                        "GPU add-on archive is too large",
                        error_code="gpu_package_invalid",
                        stage="archive_inspect",
                    )
                logical_members.append((member, logical))
            if shutil.disk_usage(destination.parent).free < total + 256 * 1024**2:
                raise GpuAddonError(
                    "GPU add-on installation needs more free disk space",
                    error_code="gpu_insufficient_space",
                    stage="disk_preflight",
                )
            for member, logical in logical_members:
                target = destination / Path(*logical.parts)
                if os.name == "nt" and len(os.fspath(target)) > 259:
                    raise GpuAddonError(
                        "GPU add-on path is unsupported on this Windows account",
                        error_code="gpu_path_unsupported",
                        stage="path_preflight",
                    )
                if os.name == "nt" and any(
                    len(os.fspath(parent)) > 247
                    for parent in target.parents
                    if parent != destination.parent
                ):
                    raise GpuAddonError(
                        "GPU add-on directory is unsupported on this Windows account",
                        error_code="gpu_path_unsupported",
                        stage="path_preflight",
                    )
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def _load_internal_manifest(path: Path) -> dict[str, object]:
    payload = _read_json(
        path,
        code="gpu_internal_manifest_invalid",
        stage="internal_manifest",
    )
    expected = {
        "schema_version",
        "layout",
        "application_version",
        "generation_id",
        "gpu_runtime",
        "runtime_installation_sha256",
        "cpu_runtime_installation_sha256",
        "model_manifest_sha256",
        "worker_source_sha256",
        "precision",
        "batch_size",
        "memory_safety_ratio",
    }
    if set(payload) != expected:
        raise GpuAddonError(
            "GPU add-on manifest fields are invalid",
            error_code="gpu_internal_manifest_invalid",
            stage="internal_manifest",
        )
    hashes = (
        payload["runtime_installation_sha256"],
        payload["cpu_runtime_installation_sha256"],
        payload["model_manifest_sha256"],
        payload["worker_source_sha256"],
    )
    if (
        payload["schema_version"] != GPU_PACKAGE_SCHEMA_VERSION
        or payload["layout"] != "gpu_overlay_v1"
        or payload["gpu_runtime"] != GPU_RUNTIME_DIRECTORY
        or not isinstance(payload["application_version"], str)
        or not isinstance(payload["generation_id"], str)
        or _GENERATION_ID.fullmatch(payload["generation_id"]) is None
        or any(not isinstance(value, str) or _SHA256.fullmatch(value) is None for value in hashes)
        or payload["precision"] not in {"fp32", "fp16"}
        or type(payload["batch_size"]) is not int
        or not 1 <= int(payload["batch_size"]) <= 64
        or payload["memory_safety_ratio"] not in {"0.80", "0.85", "0.90", "0.95"}
    ):
        raise GpuAddonError(
            "GPU add-on manifest is invalid",
            error_code="gpu_internal_manifest_invalid",
            stage="internal_manifest",
        )
    return payload


def _verify_cpu_binding(
    *,
    cpu_root: Path,
    internal: dict[str, object],
) -> ActiveOcrComposition:
    try:
        cpu = resolve_active_composition(cpu_root, allow_legacy=False)
    except OcrRuntimeLayoutError as exc:
        raise GpuAddonError(
            "CPU fallback composition is unavailable",
            error_code="gpu_cpu_composition_mismatch",
            stage="cpu_binding",
        ) from exc
    cpu_manifest = cpu.cpu_runtime / "runtime-installation.json"
    model_manifest = cpu.models_dir / "model-manifest.json"
    try:
        matches = (
            cpu.generation_id == internal["generation_id"]
            and _sha256_file(cpu_manifest)
            == internal["cpu_runtime_installation_sha256"]
            and _sha256_file(model_manifest) == internal["model_manifest_sha256"]
        )
        cpu_payload = json.loads(cpu_manifest.read_text(encoding="utf-8"))
        matches = matches and (
            isinstance(cpu_payload, dict)
            and cpu_payload.get("worker_source_sha256")
            == internal["worker_source_sha256"]
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise GpuAddonError(
            "CPU fallback composition cannot be verified",
            error_code="gpu_cpu_composition_mismatch",
            stage="cpu_binding",
        ) from exc
    if not matches:
        raise GpuAddonError(
            "GPU add-on does not match the installed CPU composition",
            error_code="gpu_cpu_composition_mismatch",
            stage="cpu_binding",
        )
    return cpu


def _pointer_payload(
    *,
    internal: dict[str, object],
    package_sha256: str,
    cpu_root: Path,
    gpu_runtime: Path,
    qualification_path: Path,
) -> dict[str, object]:
    return {
        "schema_version": GPU_OVERLAY_SCHEMA_VERSION,
        "application_version": internal["application_version"],
        "generation_id": internal["generation_id"],
        "package_sha256": package_sha256,
        "cpu_composition_manifest_sha256": _sha256_file(
            cpu_root / "composition-manifest.json"
        ),
        "gpu_runtime": GPU_RUNTIME_DIRECTORY,
        "gpu_runtime_installation_sha256": _sha256_file(
            gpu_runtime / "runtime-installation.json"
        ),
        "qualification_path": f"{GPU_QUALIFICATION_DIRECTORY}/qualification.json",
        "qualification_sha256": _sha256_file(qualification_path),
        "model_manifest_sha256": internal["model_manifest_sha256"],
        "worker_source_sha256": internal["worker_source_sha256"],
    }


def _source_root_for_install(install_root: Path, version: str) -> Path:
    version_root = install_root / "versions" / version
    return version_root if version_root.is_dir() else Path(__file__).resolve().parents[3]


def _default_qualifier(
    *,
    cpu_runtime_root: Path,
    gpu_runtime: Path,
    qualification_path: Path,
    source_root: Path,
    precision: str,
    batch_size: int,
    memory_safety_ratio: str,
) -> None:
    from dahe.adapters.ocr.installed_qualification import qualify_gpu_overlay

    qualify_gpu_overlay(
        cpu_runtime_root=cpu_runtime_root,
        gpu_runtime=gpu_runtime,
        qualification_path=qualification_path,
        source_root=source_root,
        precision=precision,
        batch_size=batch_size,
        memory_safety_ratio=memory_safety_ratio,
    )


def _qualification_matches_current_device(path: Path) -> bool:
    try:
        bundle = load_qualification_bundle(path)
        reports = {report.runtime_kind: report for report in bundle.reports}
        cpu = reports.get(RuntimeKind.CPU)
        gpu = reports.get(RuntimeKind.GPU)
        if (
            cpu is None
            or gpu is None
            or bundle.difference_report.sample_count < 2
            or not bundle.difference_report.all_critical_fields_match
        ):
            return False
        devices = discover_nvidia_devices()
    except (QualificationRegistryError, DeviceDiscoveryError, OSError):
        return False
    return any(
        device.stable_id == gpu.stable_device_id
        and device.driver_version == gpu.driver_version
        and device.memory_mib == gpu.memory_mib
        for device in devices
    )


def install_gpu_addon(
    *,
    manifest_path: Path,
    package_path: Path,
    install_root: Path,
    qualifier: GpuQualifier | Callable[..., None] | None = None,
) -> GpuAddonInstallResult:
    stage = "release_manifest"
    staging: Path | None = None
    activated_runtime = False
    activated_qualification = False
    root = install_root.resolve(strict=True)
    try:
        pointer = read_version_pointer(root)
        release = parse_update_manifest(
            manifest_path.resolve(strict=True).read_bytes(),
            current_version="0.0.0",
            updater_version=__version__,
        )
    except (OSError, UpdateManifestError, ValueError) as exc:
        raise GpuAddonError(
            "GPU release manifest is invalid",
            error_code="gpu_release_manifest_invalid",
            stage=stage,
            winerror=getattr(exc, "winerror", None),
        ) from exc
    if release.version != pointer.version:
        raise GpuAddonError(
            "GPU add-on version differs from the installed application",
            error_code="gpu_application_version_mismatch",
            stage=stage,
        )
    stage = "package_verify"
    try:
        package = package_path.resolve(strict=True)
        package_sha256 = _sha256_file(package)
        if (
            package.name != release.gpu_addon.file_name
            or package.stat().st_size != release.gpu_addon.size
            or package_sha256 != release.gpu_addon.sha256
        ):
            raise GpuAddonError(
                "GPU add-on size or SHA-256 differs from the release",
                error_code="gpu_package_invalid",
                stage=stage,
            )
    except OSError as exc:
        raise GpuAddonError(
            "GPU add-on package is missing or inaccessible",
            error_code="gpu_package_invalid",
            stage=stage,
            winerror=getattr(exc, "winerror", None),
        ) from exc
    existing = gpu_addon_status(root)
    if existing.state == "active":
        existing_pointer = _read_json(
            root / "runtimes" / GPU_POINTER_NAME,
            code="gpu_overlay_invalid",
            stage="status",
        )
        if existing_pointer.get("package_sha256") == package_sha256:
            return GpuAddonInstallResult(
                state="active",
                package_version=release.version,
                primary_runtime="gpu",
                gpu_qualified=True,
                cpu_fallback_available=True,
                diagnostic_code=None,
            )
        raise GpuAddonError(
            "a different GPU add-on is already active",
            error_code="gpu_target_conflict",
            stage="target",
        )
    if existing.diagnostic_code == "gpu_qualification_stale":
        stale_pointer = _read_json(
            root / "runtimes" / GPU_POINTER_NAME,
            code="gpu_overlay_invalid",
            stage="target",
        )
        if stale_pointer.get("package_sha256") != package_sha256:
            raise GpuAddonError(
                "stale GPU qualification belongs to another package",
                error_code="gpu_target_conflict",
                stage="target",
            )
        runtimes = root / "runtimes"
        (runtimes / GPU_POINTER_NAME).unlink(missing_ok=True)
        shutil.rmtree(runtimes / GPU_RUNTIME_DIRECTORY, ignore_errors=True)
        shutil.rmtree(runtimes / GPU_QUALIFICATION_DIRECTORY, ignore_errors=True)
    runtimes = root / "runtimes"
    runtimes.mkdir(parents=True, exist_ok=True)
    if any(
        (runtimes / name).exists()
        for name in (GPU_RUNTIME_DIRECTORY, GPU_QUALIFICATION_DIRECTORY)
    ):
        raise GpuAddonError(
            "GPU add-on target contains an unreferenced runtime",
            error_code="gpu_target_conflict",
            stage="target",
        )
    cpu_root = runtimes / "ocr-cpu"
    staging = runtimes / f".g-{uuid4().hex[:8]}"
    try:
        stage = "disk_preflight"
        free_bytes = shutil.disk_usage(runtimes).free
        required_bytes = release.gpu_addon.size * 3 + 256 * 1024**2
        if free_bytes < required_bytes:
            raise GpuAddonError(
                "GPU add-on installation needs more free disk space",
                error_code="gpu_insufficient_space",
                stage=stage,
            )
        stage = "extract"
        _safe_extract(package, staging)
        internal = _load_internal_manifest(staging / GPU_INTERNAL_MANIFEST_NAME)
        if internal["application_version"] != release.version:
            raise GpuAddonError(
                "GPU package version differs from the release",
                error_code="gpu_application_version_mismatch",
                stage="internal_manifest",
            )
        gpu_runtime = staging / GPU_RUNTIME_DIRECTORY
        runtime_manifest = gpu_runtime / "runtime-installation.json"
        if (
            not gpu_runtime.is_dir()
            or _is_link_or_reparse(gpu_runtime)
            or not runtime_manifest.is_file()
            or _sha256_file(runtime_manifest)
            != internal["runtime_installation_sha256"]
        ):
            raise GpuAddonError(
                "GPU runtime installation manifest is invalid",
                error_code="gpu_runtime_invalid",
                stage="runtime_verify",
            )
        _verify_cpu_binding(cpu_root=cpu_root, internal=internal)
        stage = "qualification"
        qualification = staging / GPU_QUALIFICATION_DIRECTORY / "qualification.json"
        source_root = _source_root_for_install(root, release.version)
        selected_qualifier = qualifier or _default_qualifier
        try:
            selected_qualifier(
                cpu_runtime_root=cpu_root,
                gpu_runtime=gpu_runtime,
                qualification_path=qualification,
                source_root=source_root,
                precision=cast(str, internal["precision"]),
                batch_size=cast(int, internal["batch_size"]),
                memory_safety_ratio=cast(str, internal["memory_safety_ratio"]),
            )
        except GpuAddonError:
            raise
        except Exception as exc:
            raise GpuAddonError(
                "GPU qualification failed on this computer",
                error_code="gpu_qualification_failed",
                stage=stage,
            ) from exc
        if not qualification.is_file():
            raise GpuAddonError(
                "GPU qualification did not produce evidence",
                error_code="gpu_qualification_failed",
                stage=stage,
            )
        final_gpu = runtimes / GPU_RUNTIME_DIRECTORY
        final_qualification_dir = runtimes / GPU_QUALIFICATION_DIRECTORY
        stage = "activate_runtime"
        gpu_runtime.rename(final_gpu)
        activated_runtime = True
        qualification.parent.rename(final_qualification_dir)
        activated_qualification = True
        pointer_payload = _pointer_payload(
            internal=internal,
            package_sha256=package_sha256,
            cpu_root=cpu_root,
            gpu_runtime=final_gpu,
            qualification_path=final_qualification_dir / "qualification.json",
        )
        stage = "activate_pointer"
        _atomic_json(runtimes / GPU_POINTER_NAME, pointer_payload)
        resolve_gpu_overlay_composition(cpu_root)
        return GpuAddonInstallResult(
            state="active",
            package_version=release.version,
            primary_runtime="gpu",
            gpu_qualified=True,
            cpu_fallback_available=True,
            diagnostic_code=None,
        )
    except Exception as exc:
        (runtimes / GPU_POINTER_NAME).unlink(missing_ok=True)
        if activated_qualification:
            shutil.rmtree(runtimes / GPU_QUALIFICATION_DIRECTORY, ignore_errors=True)
        if activated_runtime:
            shutil.rmtree(runtimes / GPU_RUNTIME_DIRECTORY, ignore_errors=True)
        if isinstance(exc, GpuAddonError):
            raise
        winerror = getattr(exc, "winerror", None)
        if isinstance(exc, (zipfile.BadZipFile, zipfile.LargeZipFile)):
            code = "gpu_package_invalid"
            message = "GPU add-on archive is unreadable"
        elif isinstance(exc, OSError):
            code = "gpu_io_blocked" if winerror in {2, 5, 32, 33} else "gpu_io_failed"
            message = "GPU add-on files were blocked or could not be written"
        else:
            code = "gpu_install_failed"
            message = "GPU add-on installation failed"
        raise GpuAddonError(
            message,
            error_code=code,
            stage=stage,
            winerror=winerror,
        ) from exc
    finally:
        if staging is not None:
            shutil.rmtree(staging, ignore_errors=True)


def _validated_pointer(cpu_root: Path) -> tuple[dict[str, object], Path, Path]:
    cpu = resolve_active_composition(cpu_root, allow_legacy=False)
    runtimes = cpu_root.resolve(strict=True).parent
    pointer_path = runtimes / GPU_POINTER_NAME
    pointer = _read_json(
        pointer_path,
        code="gpu_overlay_invalid",
        stage="status",
    )
    expected = {
        "schema_version",
        "application_version",
        "generation_id",
        "package_sha256",
        "cpu_composition_manifest_sha256",
        "gpu_runtime",
        "gpu_runtime_installation_sha256",
        "qualification_path",
        "qualification_sha256",
        "model_manifest_sha256",
        "worker_source_sha256",
    }
    if (
        set(pointer) != expected
        or pointer["schema_version"] != GPU_OVERLAY_SCHEMA_VERSION
        or pointer["generation_id"] != cpu.generation_id
        or pointer["gpu_runtime"] != GPU_RUNTIME_DIRECTORY
        or pointer["qualification_path"]
        != f"{GPU_QUALIFICATION_DIRECTORY}/qualification.json"
        or any(
            not isinstance(pointer[name], str)
            or _SHA256.fullmatch(str(pointer[name])) is None
            for name in (
                "package_sha256",
                "cpu_composition_manifest_sha256",
                "gpu_runtime_installation_sha256",
                "qualification_sha256",
                "model_manifest_sha256",
                "worker_source_sha256",
            )
        )
    ):
        raise GpuAddonError(
            "active GPU overlay pointer is invalid",
            error_code="gpu_overlay_invalid",
            stage="status",
        )
    gpu_runtime = (runtimes / GPU_RUNTIME_DIRECTORY).resolve(strict=True)
    qualification = (
        runtimes / GPU_QUALIFICATION_DIRECTORY / "qualification.json"
    ).resolve(strict=True)
    if (
        gpu_runtime.parent != runtimes
        or qualification.parent.parent != runtimes
        or _is_link_or_reparse(gpu_runtime)
        or _sha256_file(gpu_runtime / "runtime-installation.json")
        != pointer["gpu_runtime_installation_sha256"]
        or _sha256_file(qualification) != pointer["qualification_sha256"]
        or _sha256_file(cpu_root / "composition-manifest.json")
        != pointer["cpu_composition_manifest_sha256"]
        or _sha256_file(cpu.models_dir / "model-manifest.json")
        != pointer["model_manifest_sha256"]
    ):
        raise GpuAddonError(
            "active GPU overlay evidence changed",
            error_code="gpu_overlay_invalid",
            stage="status",
        )
    runtime_payload = _read_json(
        gpu_runtime / "runtime-installation.json",
        code="gpu_overlay_invalid",
        stage="status",
    )
    if runtime_payload.get("worker_source_sha256") != pointer["worker_source_sha256"]:
        raise GpuAddonError(
            "active GPU worker source changed",
            error_code="gpu_overlay_invalid",
            stage="status",
        )
    install_root = runtimes.parent
    try:
        version_pointer = read_version_pointer(install_root)
    except (OSError, ValueError) as exc:
        raise GpuAddonError(
            "installed application version cannot be verified",
            error_code="gpu_overlay_invalid",
            stage="status",
        ) from exc
    if pointer["application_version"] != version_pointer.version:
        raise GpuAddonError(
            "active GPU overlay belongs to another application version",
            error_code="gpu_application_version_mismatch",
            stage="status",
        )
    if not _qualification_matches_current_device(qualification):
        raise GpuAddonError(
            "GPU qualification no longer matches this computer",
            error_code="gpu_qualification_stale",
            stage="status",
        )
    return pointer, gpu_runtime, qualification


def resolve_gpu_overlay_composition(cpu_runtime_root: Path) -> ActiveOcrComposition:
    cpu = resolve_active_composition(cpu_runtime_root, allow_legacy=False)
    pointer, gpu_runtime, qualification = _validated_pointer(cpu_runtime_root)
    if pointer["generation_id"] != cpu.generation_id:
        raise GpuAddonError(
            "active GPU overlay generation changed",
            error_code="gpu_overlay_invalid",
            stage="status",
        )
    return ActiveOcrComposition(
        generation_id=cpu.generation_id,
        generation_dir=cpu.generation_dir,
        cpu_runtime=cpu.cpu_runtime,
        gpu_runtime=gpu_runtime,
        models_dir=cpu.models_dir,
        qualification_path=qualification,
    )


def gpu_addon_status(install_root: Path) -> GpuAddonStatus:
    try:
        root = install_root.resolve(strict=True)
        cpu_root = root / "runtimes" / "ocr-cpu"
        resolve_active_composition(cpu_root, allow_legacy=False)
    except (OSError, OcrRuntimeLayoutError):
        return GpuAddonStatus(
            state="cpu_unavailable",
            gpu_qualified=False,
            primary_runtime="none",
            cpu_fallback_available=False,
            package_version=None,
            diagnostic_code="ocr_cpu_unavailable",
        )
    pointer_path = root / "runtimes" / GPU_POINTER_NAME
    if not pointer_path.is_file():
        return GpuAddonStatus(
            state="not_installed",
            gpu_qualified=False,
            primary_runtime="cpu",
            cpu_fallback_available=True,
            package_version=None,
            diagnostic_code="gpu_addon_not_installed",
        )
    try:
        pointer, _gpu, _qualification = _validated_pointer(cpu_root)
    except GpuAddonError as exc:
        return GpuAddonStatus(
            state="invalid",
            gpu_qualified=False,
            primary_runtime="cpu",
            cpu_fallback_available=True,
            package_version=None,
            diagnostic_code=exc.error_code,
        )
    except (OcrRuntimeLayoutError, OSError):
        return GpuAddonStatus(
            state="invalid",
            gpu_qualified=False,
            primary_runtime="cpu",
            cpu_fallback_available=True,
            package_version=None,
            diagnostic_code="gpu_overlay_invalid",
        )
    return GpuAddonStatus(
        state="active",
        gpu_qualified=True,
        primary_runtime="gpu",
        cpu_fallback_available=True,
        package_version=str(pointer["application_version"]),
        diagnostic_code=None,
    )
