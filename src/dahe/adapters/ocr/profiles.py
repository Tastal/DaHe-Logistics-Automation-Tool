from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from dahe.adapters.ocr.devices import NvidiaDevice
from dahe.config.schema import OcrPreference


class RuntimeKind(StrEnum):
    CPU = "cpu"
    GPU = "gpu"


class ProfileQualification(StrEnum):
    QUALIFIED = "qualified"
    UNAVAILABLE = "unavailable"
    UNVERIFIED = "unverified"
    FAILED_SMOKE = "failed_smoke"


class RuntimeSelectionError(RuntimeError):
    """Raised when no safe OCR runtime can honor the selected policy."""


class DeviceProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    profile_id: str = Field(min_length=1)
    runtime_kind: RuntimeKind
    stable_device_id: str | None
    precision: Literal["fp32", "fp16"]
    recognition_batch_size: int = Field(ge=1, le=64)
    pipeline_batch_size: int = Field(ge=1, le=64)
    worker_count: Literal[1] = 1
    memory_safety_ratio: Decimal = Field(gt=0, le=Decimal("0.95"))
    hpi_enabled: bool = False
    tensorrt_enabled: bool = False

    @model_validator(mode="after")
    def validate_stable_device_identity(self) -> DeviceProfile:
        if self.runtime_kind is RuntimeKind.GPU and not self.stable_device_id:
            raise ValueError("a GPU profile requires a stable device identity")
        if self.runtime_kind is RuntimeKind.CPU and self.stable_device_id is not None:
            raise ValueError("a CPU profile cannot contain a stable device identity")
        return self


@dataclass(frozen=True, slots=True)
class RuntimeCandidate:
    kind: RuntimeKind
    runtime_fingerprint: str
    profile_id: str
    qualification: ProfileQualification
    failure_reason: str | None
    device: NvidiaDevice | None

    @property
    def qualified(self) -> bool:
        return self.qualification is ProfileQualification.QUALIFIED


@dataclass(frozen=True, slots=True)
class RuntimeSelection:
    primary: RuntimeCandidate
    fallback: RuntimeCandidate | None


def select_runtime(
    *,
    preference: OcrPreference,
    cpu: RuntimeCandidate,
    gpu: RuntimeCandidate | None,
    allow_cpu_fallback: bool,
) -> RuntimeSelection:
    if cpu.kind is not RuntimeKind.CPU or not cpu.qualified:
        raise RuntimeSelectionError("a qualified CPU OCR runtime is required")
    if gpu is not None and gpu.kind is not RuntimeKind.GPU:
        raise RuntimeSelectionError("the GPU candidate has the wrong runtime kind")
    if preference is OcrPreference.CPU_ONLY:
        return RuntimeSelection(primary=cpu, fallback=None)
    if gpu is not None and gpu.qualified:
        return RuntimeSelection(
            primary=gpu,
            fallback=cpu if allow_cpu_fallback else None,
        )
    if preference is OcrPreference.PREFER_GPU and not allow_cpu_fallback:
        reason = "GPU OCR is not qualified"
        if gpu is not None and gpu.failure_reason:
            reason = gpu.failure_reason
        raise RuntimeSelectionError(reason)
    return RuntimeSelection(primary=cpu, fallback=None)
