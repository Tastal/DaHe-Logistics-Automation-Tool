from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

from dahe.adapters.ocr.devices import NvidiaDevice
from dahe.adapters.ocr.fingerprints import (
    RuntimeFingerprintInput,
    build_runtime_fingerprint,
    build_runtime_profile_id,
)
from dahe.adapters.ocr.profiles import (
    ProfileQualification,
    RuntimeCandidate,
    RuntimeKind,
)
from dahe.adapters.ocr.runtime_inventory import inventory_sha256

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class QualificationRegistryError(RuntimeError):
    """Raised when a local qualification cannot safely control OCR selection."""


class QualifiedImage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    image_id: Literal["loading", "unloading"]
    image_sha256: Sha256
    verified_image_sha256: Sha256
    elapsed_ms: float = Field(ge=0)
    role: Literal["loading", "unloading", "unknown"]
    field_reliable: bool

    @model_validator(mode="after")
    def require_verified_input_identity(self) -> QualifiedImage:
        if self.image_sha256 != self.verified_image_sha256:
            raise ValueError("qualification image identity changed")
        return self


class QualifiedRuntimeReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    runtime_kind: RuntimeKind
    status: Literal["qualified"]
    profile_id: str = Field(min_length=1)
    runtime_fingerprint: Sha256
    stable_device_id: str | None
    driver_version: str | None
    memory_mib: int | None = Field(default=None, gt=0)
    precision: Literal["fp32", "fp16"]
    batch_size: int = Field(ge=1, le=64)
    worker_count: Literal[1]
    memory_safety_ratio: Decimal = Field(gt=0, le=Decimal("0.95"))
    peak_memory_used_mib: int | None = Field(default=None, ge=0)
    dependency_lock_sha256: Sha256
    worker_source_sha256: Sha256
    model_manifest_sha256: Sha256
    packages: dict[str, str]
    package_inventory_sha256: Sha256
    images: tuple[QualifiedImage, ...]
    p50_ms: float = Field(ge=0)
    p95_ms: float = Field(ge=0)

    @model_validator(mode="after")
    def validate_profile_evidence(self) -> QualifiedRuntimeReport:
        if {image.image_id for image in self.images} != {"loading", "unloading"}:
            raise ValueError("qualification must contain two distinct role images")
        if any(image.image_id != image.role for image in self.images):
            raise ValueError("qualification image role does not match its fixture")
        if not all(image.field_reliable for image in self.images):
            raise ValueError("qualification images must contain all critical fields")
        if inventory_sha256(self.packages) != self.package_inventory_sha256:
            raise ValueError("qualification package inventory hash is invalid")
        if self.runtime_kind is RuntimeKind.CPU:
            if self.precision != "fp32" or self.batch_size != 1:
                raise ValueError("CPU qualification must use fp32 and batch size 1")
            if any(
                value is not None
                for value in (
                    self.stable_device_id,
                    self.driver_version,
                    self.memory_mib,
                    self.peak_memory_used_mib,
                )
            ):
                raise ValueError("CPU qualification cannot contain GPU evidence")
            if "paddlepaddle" not in self.packages or any(
                package == "paddlepaddle-gpu" or package.startswith("nvidia-")
                for package in self.packages
            ):
                raise ValueError("CPU qualification package inventory is invalid")
            return self
        if (
            not self.stable_device_id
            or not self.driver_version
            or self.memory_mib is None
            or self.peak_memory_used_mib is None
        ):
            raise ValueError("GPU qualification requires stable device and memory evidence")
        if "paddlepaddle-gpu" not in self.packages or "paddlepaddle" in self.packages:
            raise ValueError("GPU qualification package inventory is invalid")
        if Decimal(self.peak_memory_used_mib) / Decimal(
            self.memory_mib
        ) > self.memory_safety_ratio:
            raise ValueError("GPU qualification exceeds its memory safety ratio")
        return self


class RuntimeDifferenceItemEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    image_sha256: Sha256
    critical_fields_match: bool
    differences: tuple[
        Literal[
            "ordinary_net_amount",
            "ordinary_net_unit",
            "gross_amount",
            "tare_amount",
            "role",
            "role_reliable",
            "field_reliable",
        ],
        ...,
    ]
    cpu_elapsed_ms: float = Field(ge=0)
    gpu_elapsed_ms: float = Field(ge=0)

    @model_validator(mode="after")
    def match_flag_must_reflect_differences(
        self,
    ) -> RuntimeDifferenceItemEvidence:
        if self.critical_fields_match != (not self.differences):
            raise ValueError("runtime difference item is inconsistent")
        if len(set(self.differences)) != len(self.differences):
            raise ValueError("runtime difference item repeats a field")
        return self


class RuntimeDifferenceSummary(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_count: int = Field(ge=0)
    critical_match_count: int = Field(ge=0)
    all_critical_fields_match: bool
    items: tuple[RuntimeDifferenceItemEvidence, ...]

    @model_validator(mode="after")
    def validate_counts(self) -> RuntimeDifferenceSummary:
        actual_match_count = sum(
            item.critical_fields_match for item in self.items
        )
        if (
            len(self.items) != self.sample_count
            or actual_match_count != self.critical_match_count
        ):
            raise ValueError("runtime difference counts are inconsistent")
        expected_all_match = self.critical_match_count == self.sample_count
        if self.all_critical_fields_match != expected_all_match:
            raise ValueError("runtime difference summary is inconsistent")
        return self


class QualificationBundle(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal[2]
    reports: tuple[QualifiedRuntimeReport, ...] = Field(min_length=1)
    difference_report: RuntimeDifferenceSummary

    @model_validator(mode="after")
    def bind_difference_evidence_to_reports(self) -> QualificationBundle:
        by_kind = {report.runtime_kind: report for report in self.reports}
        if len(by_kind) != len(self.reports):
            raise ValueError("qualification has duplicate runtimes")
        cpu = by_kind.get(RuntimeKind.CPU)
        gpu = by_kind.get(RuntimeKind.GPU)
        if cpu is None or gpu is None:
            if self.difference_report.sample_count != 0:
                raise ValueError(
                    "single-runtime qualification cannot claim runtime parity"
                )
            return self
        cpu_hash_by_role = {
            image.image_id: image.image_sha256 for image in cpu.images
        }
        gpu_hash_by_role = {
            image.image_id: image.image_sha256 for image in gpu.images
        }
        item_hashes = {
            item.image_sha256 for item in self.difference_report.items
        }
        expected_hashes = set(cpu_hash_by_role.values())
        if (
            cpu_hash_by_role != gpu_hash_by_role
            or item_hashes != expected_hashes
            or self.difference_report.sample_count != len(expected_hashes)
        ):
            raise ValueError(
                "runtime difference images do not match qualification reports"
            )
        return self


@dataclass(frozen=True, slots=True)
class QualifiedRuntimeProfile:
    candidate: RuntimeCandidate
    report: QualifiedRuntimeReport


def load_qualification_bundle(path: Path) -> QualificationBundle:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise QualificationRegistryError(
            "qualification registry is unreadable"
        ) from exc
    try:
        return QualificationBundle.model_validate(payload)
    except ValidationError as exc:
        message = "qualification schema or profile evidence is invalid"
        lowered = str(exc).lower()
        for keyword in ("images", "memory", "driver", "worker", "model", "schema"):
            if keyword in lowered:
                message = f"qualification {keyword} evidence is invalid"
                break
        raise QualificationRegistryError(message) from exc


def load_qualified_profiles(
    path: Path,
    *,
    expected_python_version: Mapping[RuntimeKind, str],
    expected_lock_sha256: Mapping[RuntimeKind, str],
    expected_worker_source_sha256: str,
    expected_model_manifest_sha256: str,
    expected_package_inventory_sha256: Mapping[RuntimeKind, str],
    devices: tuple[NvidiaDevice, ...],
    runtime_kinds: frozenset[RuntimeKind] | None = None,
) -> dict[RuntimeKind, QualifiedRuntimeProfile]:
    bundle = load_qualification_bundle(path)
    by_kind: dict[RuntimeKind, QualifiedRuntimeReport] = {}
    for report in bundle.reports:
        if report.runtime_kind in by_kind:
            raise QualificationRegistryError("qualification has duplicate runtimes")
        by_kind[report.runtime_kind] = report
    selected_kinds = set(by_kind) if runtime_kinds is None else set(runtime_kinds)
    missing = selected_kinds - set(by_kind)
    if missing:
        raise QualificationRegistryError(
            "qualification is missing requested runtime evidence"
        )
    if RuntimeKind.GPU in selected_kinds and (
        bundle.difference_report.sample_count < 2
        or not bundle.difference_report.all_critical_fields_match
    ):
        raise QualificationRegistryError(
            "qualification runtime difference evidence is unsafe"
        )

    current_devices = {device.stable_id: device for device in devices}
    profiles: dict[RuntimeKind, QualifiedRuntimeProfile] = {}
    for runtime_kind in sorted(selected_kinds, key=lambda kind: kind.value):
        report = by_kind[runtime_kind]
        expected_lock = expected_lock_sha256.get(runtime_kind)
        if expected_lock is None or report.dependency_lock_sha256 != expected_lock:
            raise QualificationRegistryError("qualification dependency lock changed")
        if report.worker_source_sha256 != expected_worker_source_sha256:
            raise QualificationRegistryError("qualification worker source changed")
        if report.model_manifest_sha256 != expected_model_manifest_sha256:
            raise QualificationRegistryError("qualification model manifest changed")
        if (
            report.package_inventory_sha256
            != expected_package_inventory_sha256.get(runtime_kind)
        ):
            raise QualificationRegistryError(
                "qualification package inventory changed"
            )
        python_version = expected_python_version.get(runtime_kind)
        if python_version is None or not python_version.strip():
            raise QualificationRegistryError(
                "qualification Python runtime evidence is missing"
            )

        device: NvidiaDevice | None = None
        if runtime_kind is RuntimeKind.GPU:
            stable_id = report.stable_device_id
            if stable_id is None or stable_id not in current_devices:
                raise QualificationRegistryError(
                    "qualification stable GPU device is unavailable"
                )
            device = current_devices[stable_id]
            if device.driver_version != report.driver_version:
                raise QualificationRegistryError("qualification GPU driver changed")
            if device.memory_mib != report.memory_mib:
                raise QualificationRegistryError("qualification GPU memory changed")
        expected_profile_id = build_runtime_profile_id(
            runtime_kind=runtime_kind,
            stable_device_id=(
                device.stable_id if device is not None else None
            ),
            precision=report.precision,
            batch_size=report.batch_size,
            worker_count=report.worker_count,
        )
        if report.profile_id != expected_profile_id:
            raise QualificationRegistryError(
                "qualification profile identity changed"
            )
        expected_runtime_fingerprint = build_runtime_fingerprint(
            RuntimeFingerprintInput(
                runtime_kind=runtime_kind,
                python_version=python_version,
                paddle_version=str(
                    report.packages.get("paddlepaddle-gpu")
                    or report.packages.get("paddlepaddle")
                    or ""
                ),
                paddleocr_version=str(report.packages.get("paddleocr", "")),
                paddlex_version=str(report.packages.get("paddlex", "")),
                dependency_lock_sha256=report.dependency_lock_sha256,
                model_manifest_sha256=report.model_manifest_sha256,
                worker_build_sha256=report.worker_source_sha256,
                profile_id=expected_profile_id,
                profile_payload={
                    "precision": report.precision,
                    "batch_size": report.batch_size,
                    "worker_count": report.worker_count,
                    "memory_safety_ratio": str(report.memory_safety_ratio),
                    "hpi_enabled": False,
                    "tensorrt_enabled": False,
                },
                stable_device_id=(
                    device.stable_id if device is not None else None
                ),
                driver_version=(
                    device.driver_version if device is not None else None
                ),
            )
        )
        if report.runtime_fingerprint != expected_runtime_fingerprint:
            raise QualificationRegistryError(
                "qualification runtime fingerprint changed"
            )
        candidate = RuntimeCandidate(
            kind=runtime_kind,
            runtime_fingerprint=report.runtime_fingerprint,
            profile_id=report.profile_id,
            qualification=ProfileQualification.QUALIFIED,
            failure_reason=None,
            device=device,
        )
        profiles[runtime_kind] = QualifiedRuntimeProfile(
            candidate=candidate,
            report=report,
        )
    return profiles


def load_qualified_candidates(
    path: Path,
    *,
    expected_python_version: Mapping[RuntimeKind, str],
    expected_lock_sha256: Mapping[RuntimeKind, str],
    expected_worker_source_sha256: str,
    expected_model_manifest_sha256: str,
    expected_package_inventory_sha256: Mapping[RuntimeKind, str],
    devices: tuple[NvidiaDevice, ...],
) -> dict[RuntimeKind, RuntimeCandidate]:
    profiles = load_qualified_profiles(
        path,
        expected_python_version=expected_python_version,
        expected_lock_sha256=expected_lock_sha256,
        expected_worker_source_sha256=expected_worker_source_sha256,
        expected_model_manifest_sha256=expected_model_manifest_sha256,
        expected_package_inventory_sha256=expected_package_inventory_sha256,
        devices=devices,
    )
    return {
        runtime_kind: profile.candidate
        for runtime_kind, profile in profiles.items()
    }
