from __future__ import annotations

from enum import StrEnum


class OcrErrorKind(StrEnum):
    """Authoritative technical OCR failure taxonomy and fallback policy."""

    NO_GPU = "no_gpu"
    DRIVER_INCOMPATIBLE = "driver_incompatible"
    INSUFFICIENT_MEMORY = "insufficient_memory"
    OUT_OF_MEMORY = "out_of_memory"
    WORKER_CRASHED = "worker_crashed"
    WORKER_TIMEOUT = "worker_timeout"
    PROTOCOL_ERROR = "protocol_error"
    EVIDENCE_MISMATCH = "evidence_mismatch"
    RUNTIME_MISSING = "runtime_missing"
    MODEL_MANIFEST_INVALID = "model_manifest_invalid"
    SMOKE_FAILED = "smoke_failed"

    @property
    def gpu_fallback_allowed(self) -> bool:
        return self in {
            self.NO_GPU,
            self.DRIVER_INCOMPATIBLE,
            self.INSUFFICIENT_MEMORY,
            self.OUT_OF_MEMORY,
            self.WORKER_CRASHED,
            self.WORKER_TIMEOUT,
            self.SMOKE_FAILED,
        }
