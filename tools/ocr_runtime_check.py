from __future__ import annotations

import argparse
import binascii
import hashlib
import json
import os
import shutil
import statistics
import struct
import subprocess
import sys
import threading
import tomllib
import zlib
from collections.abc import Mapping
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import uuid4

from dahe.adapters.ocr.coordinator import OcrImageOutput
from dahe.adapters.ocr.devices import NvidiaDevice, discover_nvidia_devices
from dahe.adapters.ocr.diff_report import compare_runtime_outputs
from dahe.adapters.ocr.fingerprints import (
    RuntimeFingerprintInput,
    build_pipeline_fingerprint,
    build_runtime_fingerprint,
    build_runtime_profile_id,
)
from dahe.adapters.ocr.model_manifest import verify_model_manifest
from dahe.adapters.ocr.profiles import RuntimeKind
from dahe.adapters.ocr.protocol import OcrCommand, OcrOperation, OcrResult, OcrResultStatus
from dahe.adapters.ocr.runtime_inventory import (
    inventory_sha256,
    parse_exact_lock,
    query_installed_inventory,
    validate_runtime_inventory,
)
from dahe.adapters.ocr.runtime_layout import (
    OcrRuntimeLayoutError,
    resolve_active_composition,
)
from dahe.adapters.ocr.runtime_paths import (
    OcrRuntimePathError,
    choose_ocr_runtime_root,
)
from dahe.adapters.ocr.source_fingerprint import (
    installed_worker_source_sha256,
    python_source_tree_sha256,
)
from dahe.adapters.ocr.worker_session import SupervisedNdjsonWorker
from dahe.domain.audit.ticket_roles import TicketRole

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_MAIN_PYTHON = (ROOT / ".venv" / "Scripts" / "python.exe").resolve()
APPLICATION_VERSION = str(
    json.loads((ROOT / "version-manifest.json").read_text(encoding="utf-8"))[
        "application_version"
    ]
)
QUALIFICATION_IMAGE_IDS = ("loading", "unloading")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Qualify isolated OCR runtimes.")
    parser.add_argument("runtime", choices=("cpu", "gpu", "all"))
    parser.add_argument(
        "--runtime-root",
        type=Path,
        help="ASCII install root used by bootstrap_ocr.py.",
    )
    parser.add_argument(
        "--runtime-dir",
        type=Path,
        help="Candidate environment for a single-runtime pre-activation smoke.",
    )
    parser.add_argument(
        "--cpu-runtime-dir",
        type=Path,
        help="Candidate CPU environment for an all-runtime composition smoke.",
    )
    parser.add_argument(
        "--gpu-runtime-dir",
        type=Path,
        help="Candidate GPU environment for an all-runtime composition smoke.",
    )
    parser.add_argument(
        "--models-dir",
        type=Path,
        help="Override the local approved model directory.",
    )
    parser.add_argument("--device-id")
    parser.add_argument("--precision", choices=("fp32", "fp16"), default="fp32")
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument(
        "--memory-safety-ratio",
        type=Decimal,
        default=Decimal("0.90"),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / ".runtime" / "qualification",
    )
    return parser


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _worker_version() -> str:
    payload = tomllib.loads(
        (ROOT / "ocr-runtime" / "pyproject.toml").read_text(encoding="utf-8")
    )
    return str(payload["project"]["version"])


def _chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = binascii.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)


FONT_5X7 = {
    " ": ("00000",) * 7,
    ".": ("00000", "00000", "00000", "00000", "00000", "01100", "01100"),
    "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
    "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
    "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
    "3": ("11110", "00001", "00001", "01110", "00001", "00001", "11110"),
    "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
    "5": ("11111", "10000", "10000", "11110", "00001", "00001", "11110"),
    "6": ("01110", "10000", "10000", "11110", "10001", "10001", "01110"),
    "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
    "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
    "9": ("01110", "10001", "10001", "01111", "00001", "00001", "01110"),
    "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
    "C": ("01110", "10001", "10000", "10000", "10000", "10001", "01110"),
    "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
    "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
    "G": ("01110", "10001", "10000", "10111", "10001", "10001", "01110"),
    "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
    "I": ("01110", "00100", "00100", "00100", "00100", "00100", "01110"),
    "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
    "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
    "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
    "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
    "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
    "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
    "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
    "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
    "W": ("10001", "10001", "10001", "10101", "10101", "10101", "01010"),
}


def _draw_text(
    pixels: bytearray,
    *,
    width: int,
    x: int,
    y: int,
    text: str,
    scale: int,
) -> None:
    cursor = x
    for character in text:
        glyph = FONT_5X7[character]
        for row_index, row in enumerate(glyph):
            for column_index, enabled in enumerate(row):
                if enabled != "1":
                    continue
                for offset_y in range(scale):
                    for offset_x in range(scale):
                        pixel_x = cursor + column_index * scale + offset_x
                        pixel_y = y + row_index * scale + offset_y
                        offset = (pixel_y * width + pixel_x) * 3
                        pixels[offset : offset + 3] = b"\0\0\0"
        cursor += 6 * scale


def _smoke_png(
    *,
    role: TicketRole,
    gross: str,
    tare: str,
    net: str,
) -> bytes:
    width, height = 1000, 560
    pixels = bytearray([255] * width * height * 3)
    heading = "LOADING TICKET" if role is TicketRole.LOADING else "UNLOADING TICKET"
    for y, text in (
        (55, heading),
        (180, f"GROSS WEIGHT {gross} T"),
        (305, f"TARE {tare} T"),
        (430, f"NET WEIGHT {net} T"),
    ):
        _draw_text(pixels, width=width, x=70, y=y, text=text, scale=7)
    rows: list[bytes] = []
    for y in range(height):
        start = y * width * 3
        rows.append(b"\0" + bytes(pixels[start : start + width * 3]))
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(b"".join(rows), level=9))
        + _chunk(b"IEND", b"")
    )


def _runtime_directory(
    runtime_kind: RuntimeKind,
    *,
    runtime_root: Path,
    candidate_dir: Path | None,
) -> Path:
    if candidate_dir is not None:
        return candidate_dir.resolve()
    try:
        composition = resolve_active_composition(
            runtime_root,
            allow_legacy=False,
        )
    except OcrRuntimeLayoutError as exc:
        raise SystemExit(str(exc)) from exc
    if runtime_kind is RuntimeKind.CPU:
        return composition.cpu_runtime
    if composition.gpu_runtime is None:
        raise SystemExit("GPU OCR runtime is not installed.")
    return composition.gpu_runtime


def _load_and_verify_installation(
    runtime_kind: RuntimeKind,
    *,
    runtime_dir: Path,
) -> tuple[Path, dict[str, object]]:
    portable = runtime_dir / "python.exe"
    python = (
        portable
        if portable.is_file()
        else runtime_dir / "Scripts" / "python.exe"
    )
    manifest_path = runtime_dir / "runtime-installation.json"
    if not python.is_file() or not manifest_path.is_file():
        raise SystemExit(f"{runtime_kind.value.upper()} OCR runtime is not installed.")
    try:
        installation = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit("OCR installation manifest is unreadable.") from exc
    if (
        not isinstance(installation, dict)
        or installation.get("schema_version") != 2
        or installation.get("runtime_kind") != runtime_kind.value
    ):
        raise SystemExit("OCR installation manifest is stale or invalid.")

    lock_path = ROOT / "ocr-runtime" / f"requirements-{runtime_kind.value}.lock"
    inventory = query_installed_inventory(python)
    validate_runtime_inventory(
        runtime_kind=runtime_kind,
        locked=parse_exact_lock(lock_path),
        installed=inventory,
        worker_version=_worker_version(),
    )
    approved_worker_source_sha256 = python_source_tree_sha256(
        ROOT / "ocr-runtime" / "src" / "dahe_ocr_worker"
    )
    installed_source_sha256 = installed_worker_source_sha256(
        python=python,
        runtime_dir=runtime_dir,
    )
    if installed_source_sha256 != approved_worker_source_sha256:
        raise SystemExit(
            "installed OCR worker source differs from the approved source"
        )
    expected = {
        "dependency_lock_sha256": _sha256(lock_path),
        "worker_source_sha256": installed_source_sha256,
        "package_inventory_sha256": inventory_sha256(inventory),
    }
    if any(installation.get(key) != value for key, value in expected.items()):
        raise SystemExit("OCR installation evidence no longer matches source or packages.")
    installation["packages"] = inventory
    return python, installation


def _choose_device(
    devices: tuple[NvidiaDevice, ...],
    stable_id: str | None,
) -> NvidiaDevice:
    if stable_id is not None:
        for device in devices:
            if device.stable_id == stable_id:
                return device
        raise SystemExit("The requested stable GPU identity is not present.")
    if not devices:
        raise SystemExit("No NVIDIA GPU was discovered.")
    return max(devices, key=lambda item: (item.memory_mib, item.stable_id))


def _query_device_memory_mib(stable_device_id: str) -> int:
    executable = shutil.which("nvidia-smi.exe") or shutil.which("nvidia-smi")
    if executable is None:
        raise RuntimeError("nvidia-smi is unavailable during GPU qualification")
    completed = subprocess.run(
        (
            executable,
            "--query-gpu=uuid,memory.used",
            "--format=csv,noheader,nounits",
        ),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="strict",
        timeout=5,
        shell=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("nvidia-smi failed during GPU qualification")
    for raw_line in completed.stdout.splitlines():
        parts = tuple(part.strip() for part in raw_line.split(","))
        if len(parts) == 2 and parts[0] == stable_device_id:
            return int(parts[1])
    raise RuntimeError("qualified GPU disappeared during memory sampling")


class _GpuMemorySampler:
    def __init__(self, stable_device_id: str) -> None:
        self._stable_device_id = stable_device_id
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="ocr-gpu-memory-sampler",
            daemon=True,
        )
        self._samples: list[int] = []
        self._error: BaseException | None = None

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._samples.append(
                    _query_device_memory_mib(self._stable_device_id)
                )
            except BaseException as exc:
                self._error = exc
                return
            self._stop.wait(0.1)

    def finish(self) -> int:
        self._stop.set()
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise RuntimeError("GPU memory sampler did not stop")
        if self._error is not None:
            raise RuntimeError("GPU memory evidence could not be collected") from self._error
        if not self._samples:
            raise RuntimeError("GPU memory evidence is empty")
        return max(self._samples)


def _role_from_result(result: OcrResult) -> tuple[TicketRole, bool]:
    fixed = (
        {item.upper() for item in result.role_observation.fixed_text}
        if result.role_observation is not None
        else set()
    )
    if "UNLOADING" in fixed:
        return TicketRole.UNLOADING, True
    if "LOADING" in fixed:
        return TicketRole.LOADING, True
    return TicketRole.UNKNOWN, False


def _output_fingerprint(
    *,
    result: OcrResult,
    role: TicketRole,
    runtime_kind: RuntimeKind,
) -> str:
    payload = {
        "runtime_kind": runtime_kind.value,
        "runtime_fingerprint": result.runtime_fingerprint,
        "fields": {
            key: value.model_dump(mode="json")
            for key, value in sorted(result.fields.items())
        },
        "role": role.value,
    }
    return hashlib.sha256(
        json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()


def _as_image_output(
    *,
    runtime_kind: RuntimeKind,
    result: OcrResult,
) -> OcrImageOutput:
    if result.verified_image_sha256 is None:
        raise SystemExit("OCR worker omitted the verified image identity.")
    role, role_reliable = _role_from_result(result)
    ordinary = result.fields.get("ordinary_net")
    gross = result.fields.get("gross")
    tare = result.fields.get("tare")
    required = (ordinary, gross, tare)
    field_reliable = all(
        value is not None and value.amount is not None and value.unit == "t"
        for value in required
    )
    return OcrImageOutput(
        image_sha256=result.verified_image_sha256,
        runtime_kind=runtime_kind,
        runtime_fingerprint=result.runtime_fingerprint,
        output_fingerprint=_output_fingerprint(
            result=result,
            role=role,
            runtime_kind=runtime_kind,
        ),
        ordinary_net_amount=(
            Decimal(ordinary.amount)
            if ordinary is not None and ordinary.amount is not None
            else None
        ),
        ordinary_net_unit=ordinary.unit if ordinary is not None else None,
        gross_amount=(
            Decimal(gross.amount)
            if gross is not None and gross.amount is not None
            else None
        ),
        tare_amount=(
            Decimal(tare.amount)
            if tare is not None and tare.amount is not None
            else None
        ),
        role=role,
        role_reliable=role_reliable,
        field_reliable=field_reliable,
        elapsed_ms=result.elapsed_ms,
    )


def _percentile_95(values: list[float]) -> float:
    if not values:
        raise ValueError("timing sample is empty")
    return max(values) if len(values) < 20 else statistics.quantiles(values, n=100)[94]


def _run_one(
    *,
    runtime_kind: RuntimeKind,
    device: NvidiaDevice | None,
    precision: str,
    batch_size: int,
    memory_safety_ratio: Decimal,
    output_dir: Path,
    runtime_root: Path,
    runtime_dir: Path | None,
    models_dir: Path,
) -> tuple[dict[str, object], tuple[OcrImageOutput, ...]]:
    selected_runtime_dir = _runtime_directory(
        runtime_kind,
        runtime_root=runtime_root,
        candidate_dir=runtime_dir,
    )
    python, installation = _load_and_verify_installation(
        runtime_kind,
        runtime_dir=selected_runtime_dir,
    )
    model_manifest_path = models_dir / "model-manifest.json"
    verified_models = verify_model_manifest(
        models_dir=models_dir,
        manifest_path=model_manifest_path,
    )
    model_manifest_sha256 = verified_models.manifest_sha256
    profile_id = build_runtime_profile_id(
        runtime_kind=runtime_kind,
        stable_device_id=device.stable_id if device is not None else None,
        precision=precision,
        batch_size=batch_size,
        worker_count=1,
    )
    packages_payload = installation["packages"]
    if not isinstance(packages_payload, Mapping):
        raise SystemExit("OCR installation package inventory is invalid.")
    packages = {
        str(package_name): str(package_version)
        for package_name, package_version in packages_payload.items()
    }
    fingerprint = build_runtime_fingerprint(
        RuntimeFingerprintInput(
            runtime_kind=runtime_kind,
            python_version=str(installation["python_version"]),
            paddle_version=str(
                packages.get("paddlepaddle-gpu")
                or packages.get("paddlepaddle")
                or ""
            ),
            paddleocr_version=str(packages.get("paddleocr", "")),
            paddlex_version=str(packages.get("paddlex", "")),
            dependency_lock_sha256=str(installation["dependency_lock_sha256"]),
            model_manifest_sha256=model_manifest_sha256,
            worker_build_sha256=str(installation["worker_source_sha256"]),
            profile_id=profile_id,
            profile_payload={
                "precision": precision,
                "batch_size": batch_size,
                "worker_count": 1,
                "memory_safety_ratio": str(memory_safety_ratio),
                "hpi_enabled": False,
                "tensorrt_enabled": False,
            },
            stable_device_id=device.stable_id if device is not None else None,
            driver_version=device.driver_version if device is not None else None,
        )
    )
    data_root = output_dir / f"{runtime_kind.value}-smoke-data-票据"
    evidence_dir = data_root / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    image_definitions = (
        ("loading", TicketRole.LOADING, "43.21", "30.87", "12.34", "装货-smoke.png"),
        (
            "unloading",
            TicketRole.UNLOADING,
            "41.19",
            "28.85",
            "12.34",
            "卸货-smoke.png",
        ),
    )
    image_inputs: list[tuple[str, TicketRole, Path, str]] = []
    for image_id, expected_role, gross, tare, net, filename in image_definitions:
        image_path = evidence_dir / filename
        image_path.write_bytes(
            _smoke_png(role=expected_role, gross=gross, tare=tare, net=net)
        )
        image_inputs.append(
            (
                image_id,
                expected_role,
                image_path,
                _sha256(image_path),
            )
        )

    pipeline = build_pipeline_fingerprint(
        code_build=APPLICATION_VERSION,
        runtime_fingerprint=fingerprint,
        model_manifest_sha256=model_manifest_sha256,
        template_set_fingerprint="0" * 64,
        extraction_rule_version="ocr-extract-v1",
    )
    argv = [
        os.fspath(python),
        "-I",
        "-B",
        "-m",
        "dahe_ocr_worker",
        "--runtime-kind",
        runtime_kind.value,
        "--data-root",
        os.fspath(data_root),
        "--models-dir",
        os.fspath(models_dir),
        "--model-manifest",
        os.fspath(model_manifest_path),
        "--runtime-fingerprint",
        fingerprint,
        "--profile-id",
        profile_id,
        "--precision",
        precision,
        "--batch-size",
        str(batch_size),
        "--cpu-threads",
        "4",
    ]
    if device is not None:
        argv.extend(("--device-index", str(device.current_index)))
    worker = SupervisedNdjsonWorker(
        worker_id=f"qualification-{runtime_kind.value}-{uuid4().hex[:8]}",
        argv=tuple(argv),
        runtime_dir=output_dir / f"{runtime_kind.value}-worker",
        environment={
            "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK": "True",
            "PADDLE_PDX_DISABLE_DEVICE_FALLBACK": "True",
        },
    )
    sampler = _GpuMemorySampler(device.stable_id) if device is not None else None
    outputs: list[OcrImageOutput] = []
    image_reports: list[dict[str, object]] = []
    sampler_started = False
    try:
        if sampler is not None:
            sampler.start()
            sampler_started = True
        worker.hello(
            runtime_fingerprint=fingerprint,
            profile_id=profile_id,
            timeout_seconds=30,
        )
        for image_id, expected_role, image_path, image_sha256 in image_inputs:
            result = worker.request(
                OcrCommand(
                    operation=OcrOperation.SMOKE,
                    command_id=f"smoke-{uuid4().hex}",
                    image_sha256=image_sha256,
                    relative_path=image_path.relative_to(data_root).as_posix(),
                    pipeline_fingerprint=pipeline,
                    runtime_fingerprint=fingerprint,
                    profile_id=profile_id,
                ),
                timeout_seconds=180,
            )
            if result.status is not OcrResultStatus.OK:
                error = result.error.kind if result.error is not None else "unknown"
                raise SystemExit(
                    f"{runtime_kind.value.upper()} smoke failed: {error}"
                )
            output = _as_image_output(runtime_kind=runtime_kind, result=result)
            if not output.field_reliable:
                raise SystemExit(
                    f"{runtime_kind.value.upper()} smoke missed a critical field."
                )
            if output.role is not expected_role or not output.role_reliable:
                raise SystemExit(
                    f"{runtime_kind.value.upper()} smoke misclassified {image_id}."
                )
            outputs.append(output)
            image_reports.append(
                {
                    "image_id": image_id,
                    "image_sha256": image_sha256,
                    "verified_image_sha256": result.verified_image_sha256,
                    "elapsed_ms": result.elapsed_ms,
                    "role": output.role.value,
                    "field_reliable": output.field_reliable,
                }
            )
        worker.heartbeat(
            runtime_fingerprint=fingerprint,
            profile_id=profile_id,
            timeout_seconds=30,
        )
    finally:
        try:
            peak_memory_used_mib = (
                sampler.finish()
                if sampler is not None and sampler_started
                else None
            )
        finally:
            worker.close()

    if (
        device is not None
        and peak_memory_used_mib is not None
        and Decimal(peak_memory_used_mib) / Decimal(device.memory_mib)
        > memory_safety_ratio
    ):
        raise SystemExit("GPU smoke exceeded the configured memory safety ratio.")
    elapsed = [output.elapsed_ms for output in outputs]
    return (
        {
            "runtime_kind": runtime_kind.value,
            "status": "qualified",
            "profile_id": profile_id,
            "runtime_fingerprint": fingerprint,
            "stable_device_id": device.stable_id if device is not None else None,
            "driver_version": device.driver_version if device is not None else None,
            "memory_mib": device.memory_mib if device is not None else None,
            "precision": precision,
            "batch_size": batch_size,
            "worker_count": 1,
            "memory_safety_ratio": str(memory_safety_ratio),
            "peak_memory_used_mib": peak_memory_used_mib,
            "dependency_lock_sha256": str(installation["dependency_lock_sha256"]),
            "worker_source_sha256": str(installation["worker_source_sha256"]),
            "model_manifest_sha256": model_manifest_sha256,
            "packages": packages,
            "package_inventory_sha256": inventory_sha256(packages),
            "images": image_reports,
            "p50_ms": statistics.median(elapsed),
            "p95_ms": _percentile_95(elapsed),
        },
        tuple(outputs),
    )


def _difference_payload(
    outputs_by_runtime: dict[RuntimeKind, tuple[OcrImageOutput, ...]],
) -> dict[str, object]:
    if set(outputs_by_runtime) != {RuntimeKind.CPU, RuntimeKind.GPU}:
        return {
            "sample_count": 0,
            "critical_match_count": 0,
            "all_critical_fields_match": True,
            "items": [],
        }
    difference = compare_runtime_outputs(
        cpu=outputs_by_runtime[RuntimeKind.CPU],
        gpu=outputs_by_runtime[RuntimeKind.GPU],
    )
    return asdict(difference)


def main() -> None:
    if Path(sys.executable).resolve() != EXPECTED_MAIN_PYTHON:
        raise SystemExit(f"Use the project interpreter: {EXPECTED_MAIN_PYTHON}")
    args = _parser().parse_args()
    if args.runtime_dir is not None and args.runtime == "all":
        raise SystemExit("--runtime-dir requires a single runtime kind")
    if (
        args.runtime != "all"
        and (
            args.cpu_runtime_dir is not None
            or args.gpu_runtime_dir is not None
        )
    ):
        raise SystemExit(
            "--cpu-runtime-dir and --gpu-runtime-dir require runtime=all"
        )
    if args.runtime == "all" and (
        (args.cpu_runtime_dir is None)
        != (args.gpu_runtime_dir is None)
    ):
        raise SystemExit(
            "all-runtime candidate smoke requires both runtime directories"
        )
    if args.batch_size < 1 or args.batch_size > 64:
        raise SystemExit("batch size must be between 1 and 64")
    if not Decimal("0") < args.memory_safety_ratio <= Decimal("0.95"):
        raise SystemExit("memory safety ratio must be above 0 and at most 0.95")
    try:
        runtime_root = choose_ocr_runtime_root(
            repository_root=ROOT,
            explicit_root=args.runtime_root.resolve()
            if args.runtime_root is not None
            else None,
        )
    except OcrRuntimePathError as exc:
        raise SystemExit(str(exc)) from exc
    output = (
        args.output.resolve()
        if args.output != ROOT / ".runtime" / "qualification"
        else runtime_root / "qualification"
    )
    output.mkdir(parents=True, exist_ok=True)
    if args.models_dir is not None:
        models_dir = args.models_dir.resolve()
    else:
        try:
            models_dir = resolve_active_composition(
                runtime_root,
                allow_legacy=False,
            ).models_dir
        except OcrRuntimeLayoutError as exc:
            raise SystemExit(str(exc)) from exc
    kinds = (
        (RuntimeKind.CPU, RuntimeKind.GPU)
        if args.runtime == "all"
        else (RuntimeKind(args.runtime),)
    )
    devices = discover_nvidia_devices() if RuntimeKind.GPU in kinds else ()
    reports: list[dict[str, object]] = []
    outputs_by_runtime: dict[RuntimeKind, tuple[OcrImageOutput, ...]] = {}
    for kind in kinds:
        device = (
            _choose_device(devices, args.device_id)
            if kind is RuntimeKind.GPU
            else None
        )
        precision = args.precision if kind is RuntimeKind.GPU else "fp32"
        batch_size = args.batch_size if kind is RuntimeKind.GPU else 1
        report, outputs = _run_one(
            runtime_kind=kind,
            device=device,
            precision=precision,
            batch_size=batch_size,
            memory_safety_ratio=args.memory_safety_ratio,
            output_dir=output,
            runtime_root=runtime_root,
            runtime_dir=(
                args.runtime_dir
                if args.runtime_dir is not None
                else (
                    args.cpu_runtime_dir
                    if kind is RuntimeKind.CPU
                    else args.gpu_runtime_dir
                )
            ),
            models_dir=models_dir,
        )
        reports.append(report)
        outputs_by_runtime[kind] = outputs
    payload: dict[str, Any] = {
        "schema_version": 2,
        "reports": reports,
        "difference_report": _difference_payload(outputs_by_runtime),
    }
    target = output / "qualification.json"
    temporary = target.with_suffix(".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)
    print(target)


if __name__ == "__main__":
    main()
