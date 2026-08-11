from __future__ import annotations

from dataclasses import replace

import pytest
from pydantic import ValidationError

from dahe.adapters.ocr.devices import NvidiaDevice
from dahe.adapters.ocr.fingerprints import (
    RuntimeFingerprintInput,
    build_pipeline_fingerprint,
    build_runtime_fingerprint,
)
from dahe.adapters.ocr.profiles import (
    DeviceProfile,
    OcrPreference,
    ProfileQualification,
    RuntimeCandidate,
    RuntimeKind,
    RuntimeSelectionError,
    select_runtime,
)


def _gpu() -> NvidiaDevice:
    return NvidiaDevice(
        current_index=0,
        stable_id="GPU-stable",
        name="NVIDIA RTX Example",
        memory_mib=8192,
        driver_version="610.62",
        compute_capability="8.9",
    )


def _candidate(
    *,
    kind: RuntimeKind,
    qualified: bool = True,
) -> RuntimeCandidate:
    return RuntimeCandidate(
        kind=kind,
        runtime_fingerprint=f"{kind.value}-fingerprint",
        profile_id=f"{kind.value}-safe",
        qualification=(
            ProfileQualification.QUALIFIED
            if qualified
            else ProfileQualification.FAILED_SMOKE
        ),
        failure_reason=None if qualified else "smoke failed",
        device=_gpu() if kind is RuntimeKind.GPU else None,
    )


def test_auto_prefers_only_a_qualified_gpu_and_keeps_cpu_fallback() -> None:
    selection = select_runtime(
        preference=OcrPreference.AUTO,
        cpu=_candidate(kind=RuntimeKind.CPU),
        gpu=_candidate(kind=RuntimeKind.GPU),
        allow_cpu_fallback=True,
    )

    assert selection.primary.kind is RuntimeKind.GPU
    assert selection.fallback is not None
    assert selection.fallback.kind is RuntimeKind.CPU


def test_auto_uses_cpu_when_gpu_is_unavailable_or_failed_smoke() -> None:
    selection = select_runtime(
        preference=OcrPreference.AUTO,
        cpu=_candidate(kind=RuntimeKind.CPU),
        gpu=_candidate(kind=RuntimeKind.GPU, qualified=False),
        allow_cpu_fallback=True,
    )

    assert selection.primary.kind is RuntimeKind.CPU
    assert selection.fallback is None


def test_cpu_must_be_qualified_even_when_gpu_exists() -> None:
    with pytest.raises(RuntimeSelectionError, match="CPU"):
        select_runtime(
            preference=OcrPreference.PREFER_GPU,
            cpu=_candidate(kind=RuntimeKind.CPU, qualified=False),
            gpu=_candidate(kind=RuntimeKind.GPU),
            allow_cpu_fallback=True,
        )


def test_cpu_only_never_selects_or_starts_gpu() -> None:
    selection = select_runtime(
        preference=OcrPreference.CPU_ONLY,
        cpu=_candidate(kind=RuntimeKind.CPU),
        gpu=_candidate(kind=RuntimeKind.GPU),
        allow_cpu_fallback=True,
    )

    assert selection.primary.kind is RuntimeKind.CPU
    assert selection.fallback is None


def test_device_profile_never_persists_a_gpu_index() -> None:
    profile = DeviceProfile(
        profile_id="local-qualified",
        runtime_kind=RuntimeKind.GPU,
        stable_device_id="GPU-stable",
        precision="fp16",
        recognition_batch_size=6,
        pipeline_batch_size=6,
        worker_count=1,
        memory_safety_ratio="0.90",
        hpi_enabled=False,
        tensorrt_enabled=False,
    )

    assert "index" not in profile.model_dump()
    assert "gpu:0" not in profile.model_dump_json()


def test_device_profile_requires_a_stable_id_only_for_gpu() -> None:
    with pytest.raises(ValidationError, match="stable"):
        DeviceProfile(
            profile_id="gpu-without-identity",
            runtime_kind=RuntimeKind.GPU,
            stable_device_id=None,
            precision="fp16",
            recognition_batch_size=1,
            pipeline_batch_size=1,
            worker_count=1,
            memory_safety_ratio="0.90",
        )

    with pytest.raises(ValidationError, match="stable"):
        DeviceProfile(
            profile_id="cpu-with-gpu-identity",
            runtime_kind=RuntimeKind.CPU,
            stable_device_id="GPU-stable",
            precision="fp32",
            recognition_batch_size=1,
            pipeline_batch_size=1,
            worker_count=1,
            memory_safety_ratio="0.90",
        )


def test_runtime_fingerprint_changes_for_lock_model_profile_or_device() -> None:
    base = RuntimeFingerprintInput(
        runtime_kind=RuntimeKind.GPU,
        python_version="3.12.10",
        paddle_version="3.3.1",
        paddleocr_version="3.7.0",
        paddlex_version="3.7.2",
        dependency_lock_sha256="1" * 64,
        model_manifest_sha256="2" * 64,
        worker_build_sha256="3" * 64,
        profile_id="gpu-safe",
        profile_payload={"precision": "fp16", "batch_size": 6},
        stable_device_id="GPU-stable",
        driver_version="610.62",
    )
    original = build_runtime_fingerprint(base)

    assert build_runtime_fingerprint(base) == original
    assert (
        build_runtime_fingerprint(
            replace(base, dependency_lock_sha256="4" * 64)
        )
        != original
    )
    assert (
        build_runtime_fingerprint(replace(base, model_manifest_sha256="5" * 64))
        != original
    )
    assert (
        build_runtime_fingerprint(replace(base, stable_device_id="GPU-other"))
        != original
    )


def test_pipeline_fingerprint_includes_runtime_and_template_versions() -> None:
    first = build_pipeline_fingerprint(
        code_build="0.6.0",
        runtime_fingerprint="1" * 64,
        model_manifest_sha256="2" * 64,
        template_set_fingerprint="3" * 64,
        extraction_rule_version="ocr-extract-v1",
    )
    second = build_pipeline_fingerprint(
        code_build="0.6.0",
        runtime_fingerprint="1" * 64,
        model_manifest_sha256="2" * 64,
        template_set_fingerprint="4" * 64,
        extraction_rule_version="ocr-extract-v1",
    )

    assert first != second
