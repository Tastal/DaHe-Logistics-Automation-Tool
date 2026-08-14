from __future__ import annotations

import json
import os
import shutil
from decimal import Decimal
from pathlib import Path

from dahe import __version__
from dahe.adapters.ocr.coordinator import OcrImageOutput
from dahe.adapters.ocr.devices import discover_nvidia_devices
from dahe.adapters.ocr.profile_registry import load_qualification_bundle
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.runtime_layout import resolve_active_composition


class InstalledGpuQualificationError(RuntimeError):
    """Raised when an installed GPU cannot be safely paired with CPU fallback."""


def qualify_gpu_overlay(
    *,
    cpu_runtime_root: Path,
    gpu_runtime: Path,
    qualification_path: Path,
    source_root: Path,
    precision: str,
    batch_size: int,
    memory_safety_ratio: str,
) -> None:
    """Run the same synthetic CPU/GPU qualification used by development tools.

    The add-on is not activated until this function returns and the caller has
    atomically published the qualification and overlay pointer.
    """

    from tools import ocr_runtime_check as qualification_tool

    source = source_root.resolve(strict=True)
    cpu_root = cpu_runtime_root.resolve(strict=True)
    gpu = gpu_runtime.resolve(strict=True)
    composition = resolve_active_composition(cpu_root, allow_legacy=False)
    devices = discover_nvidia_devices()
    if not devices:
        raise InstalledGpuQualificationError("No NVIDIA GPU was discovered")
    device = max(devices, key=lambda item: (item.memory_mib, item.stable_id))
    try:
        ratio = Decimal(memory_safety_ratio)
    except Exception as exc:
        raise InstalledGpuQualificationError(
            "GPU memory safety ratio is invalid"
        ) from exc
    if precision not in {"fp32", "fp16"} or not 1 <= batch_size <= 64:
        raise InstalledGpuQualificationError("GPU qualification profile is invalid")
    if not Decimal("0") < ratio <= Decimal("0.95"):
        raise InstalledGpuQualificationError(
            "GPU memory safety ratio is invalid"
        )

    qualification_path.parent.mkdir(parents=True, exist_ok=True)
    work = qualification_path.parent / ".work"
    work.mkdir(parents=True, exist_ok=False)
    previous_root = qualification_tool.ROOT
    previous_version = qualification_tool.APPLICATION_VERSION
    try:
        qualification_tool.ROOT = source
        qualification_tool.APPLICATION_VERSION = __version__
        reports: list[dict[str, object]] = []
        outputs: dict[RuntimeKind, tuple[OcrImageOutput, ...]] = {}
        cpu_report, cpu_outputs = qualification_tool._run_one(
            runtime_kind=RuntimeKind.CPU,
            device=None,
            precision="fp32",
            batch_size=1,
            memory_safety_ratio=ratio,
            output_dir=work,
            runtime_root=cpu_root,
            runtime_dir=composition.cpu_runtime,
            models_dir=composition.models_dir,
        )
        reports.append(cpu_report)
        outputs[RuntimeKind.CPU] = cpu_outputs
        gpu_report, gpu_outputs = qualification_tool._run_one(
            runtime_kind=RuntimeKind.GPU,
            device=device,
            precision=precision,
            batch_size=batch_size,
            memory_safety_ratio=ratio,
            output_dir=work,
            runtime_root=cpu_root,
            runtime_dir=gpu,
            models_dir=composition.models_dir,
        )
        reports.append(gpu_report)
        outputs[RuntimeKind.GPU] = gpu_outputs
        payload = {
            "schema_version": 2,
            "reports": reports,
            "difference_report": qualification_tool._difference_payload(outputs),
        }
        temporary = qualification_path.with_name(
            f".{qualification_path.name}.tmp"
        )
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
            newline="\n",
        )
        os.replace(temporary, qualification_path)
        load_qualification_bundle(qualification_path)
    except BaseException as exc:
        qualification_path.unlink(missing_ok=True)
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise InstalledGpuQualificationError(
                "GPU qualification worker failed"
            ) from exc
        if isinstance(exc, InstalledGpuQualificationError):
            raise
        raise InstalledGpuQualificationError(
            "GPU qualification worker failed"
        ) from exc
    finally:
        qualification_tool.ROOT = previous_root
        qualification_tool.APPLICATION_VERSION = previous_version
        shutil.rmtree(work, ignore_errors=True)
