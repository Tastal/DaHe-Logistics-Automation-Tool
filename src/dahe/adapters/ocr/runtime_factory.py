from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from dahe.adapters.ocr.devices import (
    DeviceDiscoveryError,
    NvidiaDevice,
    discover_nvidia_devices,
)
from dahe.adapters.ocr.model_manifest import (
    ModelManifestVerificationError,
    VerifiedModelManifest,
    verify_model_manifest,
)
from dahe.adapters.ocr.profile_registry import (
    QualificationRegistryError,
    QualifiedRuntimeProfile,
    load_qualified_profiles,
)
from dahe.adapters.ocr.profiles import (
    ProfileQualification,
    RuntimeCandidate,
    RuntimeKind,
    RuntimeSelectionError,
    select_runtime,
)
from dahe.adapters.ocr.runtime_inventory import (
    RuntimeInventoryError,
    inventory_sha256,
    parse_exact_lock,
    query_installed_inventory,
    validate_runtime_inventory,
)
from dahe.adapters.ocr.runtime_layout import (
    COMPOSITION_MANIFEST_NAME,
    ActiveOcrComposition,
    OcrRuntimeLayoutError,
    resolve_active_composition,
)
from dahe.adapters.ocr.runtime_paths import (
    OcrRuntimePathError,
    choose_ocr_runtime_root,
)
from dahe.adapters.ocr.scheduled_gateway import NdjsonOcrRuntimeGateway
from dahe.adapters.ocr.source_fingerprint import (
    SourceFingerprintError,
    installed_worker_source_sha256,
    python_source_tree_sha256,
)
from dahe.adapters.ocr.worker_session import SupervisedNdjsonWorker
from dahe.config.paths import ConfigurationPathError, resolve_data_root
from dahe.config.schema import AppConfig, OcrPreference, RuntimeProfile
from dahe.diagnostics.runtime_log import RuntimeLogStore
from dahe.jobs.ocr_execution import (
    AsyncOcrExecutionBackend,
    OcrFormalAuthority,
    OcrRuntimeGateway,
    OcrRuntimeIdentity,
    RuntimeKindName,
)
from dahe.release.gpu_addon import (
    GpuAddonError,
    resolve_gpu_overlay_composition,
)

_WORKER_ENVIRONMENT = {
    "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK": "True",
    "PADDLE_PDX_DISABLE_DEVICE_FALLBACK": "True",
}


def _runtime_output_sink(
    store: RuntimeLogStore | None,
) -> Callable[[str, str, str, bool], None] | None:
    if store is None:
        return None

    def sink(worker_id: str, stream: str, text: str, protocol: bool) -> None:
        store.append_process_output(
            source=worker_id,
            stream=stream,
            text=text,
            protocol_stdout=protocol,
        )

    return sink


def _resolve_composition_with_optional_gpu_overlay(
    runtime_root: Path,
) -> ActiveOcrComposition:
    composition = resolve_active_composition(
        runtime_root,
        allow_legacy=False,
    )
    if composition.gpu_runtime is not None:
        return composition
    try:
        return resolve_gpu_overlay_composition(runtime_root)
    except (GpuAddonError, OcrRuntimeLayoutError, OSError):
        return composition


class OcrRuntimeCompositionError(RuntimeError):
    """Raised when no verified local OCR composition can be started safely."""


@dataclass(frozen=True, slots=True)
class _RuntimeArtifact:
    kind: RuntimeKind
    directory: Path
    python: Path
    python_version: str
    lock_sha256: str
    inventory_sha256: str
    worker_source_sha256: str


@dataclass(frozen=True, slots=True)
class _CompositionEvidence:
    artifact: _RuntimeArtifact
    profile: QualifiedRuntimeProfile


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _composition_evidence_sha256(
    *,
    composition: ActiveOcrComposition,
    selected_qualification_sha256: str,
    models: VerifiedModelManifest,
    worker_version: str,
    worker_source_sha256: str,
    runtime_order: tuple[RuntimeKind, ...],
    evidence_by_kind: dict[RuntimeKind, _CompositionEvidence],
    identities: tuple[OcrRuntimeIdentity, ...],
) -> str:
    if composition.generation_id is None or composition.generation_dir is None:
        raise OcrRuntimeCompositionError("verified OCR composition identity is unavailable")
    identity_by_kind = {identity.runtime_kind: identity for identity in identities}
    runtime_evidence: list[dict[str, object]] = []
    for kind in runtime_order:
        evidence = evidence_by_kind.get(kind)
        identity = identity_by_kind.get(kind.value)
        if evidence is None or identity is None:
            raise OcrRuntimeCompositionError("verified OCR composition evidence is incomplete")
        artifact = evidence.artifact
        runtime_evidence.append(
            {
                "dependency_lock_sha256": artifact.lock_sha256,
                "package_inventory_sha256": artifact.inventory_sha256,
                "profile_id": identity.profile_id,
                "profile_report_sha256": _canonical_sha256(
                    evidence.profile.report.model_dump(mode="json")
                ),
                "python_version": artifact.python_version,
                "runtime_fingerprint": identity.runtime_fingerprint,
                "runtime_kind": identity.runtime_kind,
                "worker_source_sha256": artifact.worker_source_sha256,
            }
        )
    return _canonical_sha256(
        {
            "active_composition": {
                "composition_manifest_sha256": _sha256_file(
                    composition.generation_dir / COMPOSITION_MANIFEST_NAME
                ),
                "generation_id": composition.generation_id,
                "qualification_sha256": _sha256_file(composition.qualification_path),
                "selected_qualification_sha256": (selected_qualification_sha256),
            },
            "model_set": {
                "file_count": models.file_count,
                "manifest_sha256": models.manifest_sha256,
                "model_set_id": models.model_set_id,
                "total_size_bytes": models.total_size_bytes,
            },
            "runtime_selection": {
                "fallback_runtime_kind": (
                    runtime_order[1].value if len(runtime_order) > 1 else None
                ),
                "primary_runtime_kind": runtime_order[0].value,
            },
            "runtimes": sorted(
                runtime_evidence,
                key=lambda item: (
                    str(item["runtime_kind"]),
                    str(item["profile_id"]),
                    str(item["runtime_fingerprint"]),
                ),
            ),
            "schema_version": 1,
            "worker_package": {
                "source_sha256": worker_source_sha256,
                "version": worker_version,
            },
        }
    )


def _worker_version(repository_root: Path) -> str:
    metadata_path = repository_root / "ocr-runtime" / "pyproject.toml"
    try:
        payload = tomllib.loads(metadata_path.read_text(encoding="utf-8"))
        version = payload["project"]["version"]
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise OcrRuntimeCompositionError("OCR worker package metadata is invalid") from exc
    if not isinstance(version, str) or not version.strip():
        raise OcrRuntimeCompositionError("OCR worker package version is invalid")
    return version


def _runtime_python(runtime_dir: Path) -> Path:
    portable = runtime_dir / "python.exe"
    python = portable if portable.is_file() else runtime_dir / "Scripts" / "python.exe"
    if not python.is_file():
        raise OcrRuntimeCompositionError(f"{runtime_dir.name} Python executable is missing")
    return python.resolve()


def _query_runtime_python_version(python: Path) -> str:
    completed = subprocess.run(
        (
            os.fspath(python),
            "-I",
            "-c",
            "import platform;print(platform.python_version())",
        ),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        shell=False,
    )
    version = completed.stdout.strip()
    if not version:
        raise OcrRuntimeCompositionError("OCR runtime Python version is unavailable")
    return version


def _inspect_runtime(
    *,
    kind: RuntimeKind,
    repository_root: Path,
    runtime_dir: Path,
    worker_version: str,
    expected_worker_source_sha256: str,
) -> _RuntimeArtifact:
    runtime_dir = runtime_dir.resolve()
    python = _runtime_python(runtime_dir)
    lock_path = (repository_root / "ocr-runtime" / f"requirements-{kind.value}.lock").resolve()
    try:
        locked = parse_exact_lock(lock_path)
        installed = query_installed_inventory(python)
        python_version = _query_runtime_python_version(python)
        validate_runtime_inventory(
            runtime_kind=kind,
            locked=locked,
            installed=installed,
            worker_version=worker_version,
        )
        lock_sha256 = _sha256_file(lock_path)
        package_inventory_sha256 = inventory_sha256(installed)
        installed_source_sha256 = installed_worker_source_sha256(
            python=python,
            runtime_dir=runtime_dir,
        )
        if installed_source_sha256 != expected_worker_source_sha256:
            raise SourceFingerprintError(
                "installed OCR worker source differs from the approved source"
            )
    except (
        json.JSONDecodeError,
        OSError,
        RuntimeInventoryError,
        SourceFingerprintError,
        subprocess.SubprocessError,
    ) as exc:
        raise OcrRuntimeCompositionError(
            f"{kind.value.upper()} OCR runtime inventory validation failed"
        ) from exc
    return _RuntimeArtifact(
        kind=kind,
        directory=runtime_dir,
        python=python,
        python_version=python_version,
        lock_sha256=lock_sha256,
        inventory_sha256=package_inventory_sha256,
        worker_source_sha256=installed_source_sha256,
    )


def _load_profile(
    *,
    kind: RuntimeKind,
    qualification_path: Path,
    artifact: _RuntimeArtifact,
    worker_source_sha256: str,
    models: VerifiedModelManifest,
    devices: tuple[NvidiaDevice, ...],
) -> QualifiedRuntimeProfile:
    profiles = load_qualified_profiles(
        qualification_path,
        expected_python_version={kind: artifact.python_version},
        expected_lock_sha256={kind: artifact.lock_sha256},
        expected_worker_source_sha256=worker_source_sha256,
        expected_model_manifest_sha256=models.manifest_sha256,
        expected_package_inventory_sha256={
            kind: artifact.inventory_sha256,
        },
        devices=devices,
        runtime_kinds=frozenset({kind}),
    )
    return profiles[kind]


def _unavailable_gpu(reason: str) -> RuntimeCandidate:
    return RuntimeCandidate(
        kind=RuntimeKind.GPU,
        runtime_fingerprint="0" * 64,
        profile_id="gpu-unavailable",
        qualification=ProfileQualification.UNAVAILABLE,
        failure_reason=reason,
        device=None,
    )


def _gpu_evidence(
    *,
    config: AppConfig,
    qualification_path: Path,
    repository_root: Path,
    runtime_dir: Path | None,
    worker_version: str,
    worker_source_sha256: str,
    models: VerifiedModelManifest,
    discovered_devices: tuple[NvidiaDevice, ...],
) -> tuple[_CompositionEvidence | None, RuntimeCandidate]:
    preferred_id = config.ocr.preferred_device_id
    eligible_devices = (
        discovered_devices
        if preferred_id is None
        else tuple(device for device in discovered_devices if device.stable_id == preferred_id)
    )
    if not eligible_devices:
        return None, _unavailable_gpu(
            "The selected GPU is not available on this computer."
            if preferred_id is not None
            else "No NVIDIA GPU is available."
        )
    if runtime_dir is None:
        return None, _unavailable_gpu("The active OCR composition has no GPU runtime.")
    try:
        artifact = _inspect_runtime(
            kind=RuntimeKind.GPU,
            repository_root=repository_root,
            runtime_dir=runtime_dir,
            worker_version=worker_version,
            expected_worker_source_sha256=worker_source_sha256,
        )
        profile = _load_profile(
            kind=RuntimeKind.GPU,
            qualification_path=qualification_path,
            artifact=artifact,
            worker_source_sha256=worker_source_sha256,
            models=models,
            devices=eligible_devices,
        )
    except (OcrRuntimeCompositionError, QualificationRegistryError) as exc:
        return None, _unavailable_gpu(str(exc))
    return _CompositionEvidence(artifact=artifact, profile=profile), profile.candidate


def _worker_argv(
    *,
    evidence: _CompositionEvidence,
    data_root: Path,
    models: VerifiedModelManifest,
) -> tuple[str, ...]:
    kind = evidence.artifact.kind
    report = evidence.profile.report
    candidate = evidence.profile.candidate
    argv = [
        os.fspath(evidence.artifact.python),
        "-I",
        "-B",
        "-m",
        "dahe_ocr_worker",
        "--runtime-kind",
        kind.value,
        "--data-root",
        os.fspath(data_root),
        "--models-dir",
        os.fspath(models.models_dir),
        "--model-manifest",
        os.fspath(models.models_dir / "model-manifest.json"),
        "--runtime-fingerprint",
        candidate.runtime_fingerprint,
        "--profile-id",
        candidate.profile_id,
        "--precision",
        report.precision,
        "--batch-size",
        str(report.batch_size),
    ]
    if kind is RuntimeKind.GPU:
        device = candidate.device
        if device is None:
            raise OcrRuntimeCompositionError(
                "qualified GPU profile lost its current device mapping"
            )
        # The index is deliberately ephemeral. Durable identity remains the
        # stable UUID validated by the local qualification registry.
        argv.extend(("--device-index", str(device.current_index)))
    return tuple(argv)


def _start_gateway(
    *,
    evidence: _CompositionEvidence,
    data_root: Path,
    models: VerifiedModelManifest,
    worker_runtime_root: Path,
    timeout_seconds: float,
    runtime_log_store: RuntimeLogStore | None,
    below_normal_priority: bool,
    idle_timeout_seconds: float | None,
) -> NdjsonOcrRuntimeGateway:
    kind = evidence.artifact.kind
    candidate = evidence.profile.candidate
    worker_id = f"ocr-{kind.value}-{uuid4().hex[:12]}"
    worker_argv = _worker_argv(
        evidence=evidence,
        data_root=data_root,
        models=models,
    )
    worker_directory = worker_runtime_root / kind.value
    worker_environment = dict(_WORKER_ENVIRONMENT)
    if runtime_log_store is None:
        if below_normal_priority or idle_timeout_seconds is not None:
            worker = SupervisedNdjsonWorker(
                worker_id=worker_id,
                argv=worker_argv,
                runtime_dir=worker_directory,
                environment=worker_environment,
                below_normal_priority=below_normal_priority,
                idle_timeout_seconds=idle_timeout_seconds,
            )
        else:
            worker = SupervisedNdjsonWorker(
                worker_id=worker_id,
                argv=worker_argv,
                runtime_dir=worker_directory,
                environment=worker_environment,
            )
    else:
        output_sink = _runtime_output_sink(runtime_log_store)
        if below_normal_priority or idle_timeout_seconds is not None:
            worker = SupervisedNdjsonWorker(
                worker_id=worker_id,
                argv=worker_argv,
                runtime_dir=worker_directory,
                environment=worker_environment,
                output_sink=output_sink,
                below_normal_priority=below_normal_priority,
                idle_timeout_seconds=idle_timeout_seconds,
            )
        else:
            worker = SupervisedNdjsonWorker(
                worker_id=worker_id,
                argv=worker_argv,
                runtime_dir=worker_directory,
                environment=worker_environment,
                output_sink=output_sink,
            )
    try:
        worker.hello(
            runtime_fingerprint=candidate.runtime_fingerprint,
            profile_id=candidate.profile_id,
            timeout_seconds=timeout_seconds,
        )
    except BaseException:
        with contextlib.suppress(Exception):
            worker.close()
        raise
    return NdjsonOcrRuntimeGateway(
        identity=OcrRuntimeIdentity(
            runtime_kind=kind.value,
            profile_id=candidate.profile_id,
            runtime_fingerprint=candidate.runtime_fingerprint,
        ),
        worker=worker,
        timeout_seconds=timeout_seconds,
    )


def build_ocr_execution_backend(
    *,
    config: AppConfig,
    repository_root: Path,
    runtime_root: Path | None = None,
    qualification_path: Path | None = None,
    timeout_seconds: float = 180,
    runtime_log_store: RuntimeLogStore | None = None,
) -> AsyncOcrExecutionBackend:
    """Compose verified local runtimes for the standard local console."""

    if timeout_seconds <= 0:
        raise OcrRuntimeCompositionError("OCR worker timeout must be positive")
    source_root = repository_root.resolve()
    try:
        selected_runtime_root = choose_ocr_runtime_root(
            repository_root=source_root,
            explicit_root=runtime_root.resolve() if runtime_root is not None else None,
            require_active_composition=runtime_root is None,
        ).resolve()
        data_root = resolve_data_root(config).resolve(strict=True)
        composition = _resolve_composition_with_optional_gpu_overlay(
            selected_runtime_root,
        )
    except (
        ConfigurationPathError,
        FileNotFoundError,
        OcrRuntimeLayoutError,
        OcrRuntimePathError,
    ) as exc:
        raise OcrRuntimeCompositionError(
            "OCR runtime or application data root is unavailable"
        ) from exc
    selected_qualification = (
        qualification_path.resolve()
        if qualification_path is not None
        else composition.qualification_path
    )
    try:
        selected_qualification_sha256 = _sha256_file(selected_qualification)
    except OSError as exc:
        raise OcrRuntimeCompositionError("OCR qualification evidence is unavailable") from exc
    models_dir = composition.models_dir
    try:
        models = verify_model_manifest(
            models_dir=models_dir,
            manifest_path=models_dir / "model-manifest.json",
        )
    except (FileNotFoundError, ModelManifestVerificationError, OSError) as exc:
        raise OcrRuntimeCompositionError("OCR model manifest verification failed") from exc

    worker_version = _worker_version(source_root)
    try:
        worker_source_sha256 = python_source_tree_sha256(
            source_root / "ocr-runtime" / "src" / "dahe_ocr_worker"
        )
    except SourceFingerprintError as exc:
        raise OcrRuntimeCompositionError("OCR worker source is missing or unsafe") from exc
    cpu_artifact = _inspect_runtime(
        kind=RuntimeKind.CPU,
        repository_root=source_root,
        runtime_dir=composition.cpu_runtime,
        worker_version=worker_version,
        expected_worker_source_sha256=worker_source_sha256,
    )
    try:
        cpu_profile = _load_profile(
            kind=RuntimeKind.CPU,
            qualification_path=selected_qualification,
            artifact=cpu_artifact,
            worker_source_sha256=worker_source_sha256,
            models=models,
            devices=(),
        )
    except QualificationRegistryError as exc:
        raise OcrRuntimeCompositionError("CPU OCR qualification is not current") from exc
    cpu_evidence = _CompositionEvidence(
        artifact=cpu_artifact,
        profile=cpu_profile,
    )

    gpu_evidence: _CompositionEvidence | None = None
    gpu_candidate: RuntimeCandidate | None = None
    if config.ocr.preference is not OcrPreference.CPU_ONLY:
        try:
            devices = discover_nvidia_devices()
        except DeviceDiscoveryError as exc:
            devices = ()
            gpu_candidate = _unavailable_gpu(str(exc))
        if gpu_candidate is None:
            gpu_evidence, gpu_candidate = _gpu_evidence(
                config=config,
                qualification_path=selected_qualification,
                repository_root=source_root,
                runtime_dir=composition.gpu_runtime,
                worker_version=worker_version,
                worker_source_sha256=worker_source_sha256,
                models=models,
                discovered_devices=devices,
            )

    try:
        selection = select_runtime(
            preference=config.ocr.preference,
            cpu=cpu_profile.candidate,
            gpu=gpu_candidate,
            allow_cpu_fallback=config.ocr.allow_cpu_fallback,
        )
    except RuntimeSelectionError as exc:
        raise OcrRuntimeCompositionError("OCR runtime policy cannot be satisfied") from exc

    evidence_by_kind = {
        RuntimeKind.CPU: cpu_evidence,
    }
    if gpu_evidence is not None:
        evidence_by_kind[RuntimeKind.GPU] = gpu_evidence
    runtime_order = [selection.primary.kind]
    if selection.fallback is not None:
        runtime_order.append(selection.fallback.kind)

    gateways: dict[RuntimeKindName, OcrRuntimeGateway] = {}
    worker_runtime_root = data_root / "runtime" / "ocr-workers"
    try:
        for kind in runtime_order:
            evidence = evidence_by_kind.get(kind)
            if evidence is None:
                raise OcrRuntimeCompositionError(
                    "selected OCR runtime has no verified composition evidence"
                )
            started_gateway = _start_gateway(
                evidence=evidence,
                data_root=data_root,
                models=models,
                worker_runtime_root=worker_runtime_root,
                timeout_seconds=timeout_seconds,
                runtime_log_store=runtime_log_store,
                below_normal_priority=(
                    config.runtime_profile is RuntimeProfile.PRODUCTION
                ),
                idle_timeout_seconds=(
                    10 * 60
                    if config.runtime_profile is RuntimeProfile.PRODUCTION
                    else None
                ),
            )
            gateways[kind.value] = started_gateway
        try:
            current_composition = _resolve_composition_with_optional_gpu_overlay(
                selected_runtime_root,
            )
            qualification_is_current = (
                _sha256_file(selected_qualification) == selected_qualification_sha256
            )
            model_manifest_is_current = (
                _sha256_file(models_dir / "model-manifest.json") == models.manifest_sha256
            )
            worker_source_is_current = (
                python_source_tree_sha256(source_root / "ocr-runtime" / "src" / "dahe_ocr_worker")
                == worker_source_sha256
            )
        except (OSError, OcrRuntimeLayoutError, SourceFingerprintError) as exc:
            raise OcrRuntimeCompositionError(
                "OCR composition evidence cannot be reverified"
            ) from exc
        if current_composition != composition:
            raise OcrRuntimeCompositionError("active OCR composition changed during startup")
        if (
            not qualification_is_current
            or not model_manifest_is_current
            or not worker_source_is_current
        ):
            raise OcrRuntimeCompositionError("OCR composition evidence changed during startup")
        identities = tuple(gateways[kind.value].identity for kind in runtime_order)
        try:
            composition_evidence_sha256 = _composition_evidence_sha256(
                composition=composition,
                selected_qualification_sha256=selected_qualification_sha256,
                models=models,
                worker_version=worker_version,
                worker_source_sha256=worker_source_sha256,
                runtime_order=tuple(runtime_order),
                evidence_by_kind=evidence_by_kind,
                identities=identities,
            )
        except OSError as exc:
            raise OcrRuntimeCompositionError("OCR composition evidence cannot be sealed") from exc
        formal_authority = OcrFormalAuthority._from_verified_composition(
            data_root=data_root,
            repository_root=source_root,
            runtime_identities=identities,
            composition_evidence_sha256=composition_evidence_sha256,
        )
        return AsyncOcrExecutionBackend._from_verified_composition(
            primary_runtime_kind=selection.primary.kind.value,
            gateways=gateways,
            formal_authority=formal_authority,
        )
    except BaseException as exc:
        for existing_gateway in reversed(tuple(gateways.values())):
            with contextlib.suppress(Exception):
                existing_gateway.close()
        if isinstance(exc, OcrRuntimeCompositionError):
            raise
        if isinstance(exc, Exception):
            raise OcrRuntimeCompositionError("OCR worker handshake failed") from exc
        raise
