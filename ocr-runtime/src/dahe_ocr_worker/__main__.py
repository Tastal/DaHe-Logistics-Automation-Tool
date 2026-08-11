from __future__ import annotations

import argparse
import hashlib
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import cast
from uuid import uuid4

from dahe_ocr_worker.engine import EngineConfig, PaddleEngine
from dahe_ocr_worker.model_manifest import (
    ModelManifestError,
    load_and_verify_model_manifest,
)
from dahe_ocr_worker.network_guard import install_python_network_guard
from dahe_ocr_worker.protocol import (
    MAX_COMMAND_LINE_BYTES,
    WorkerCommand,
    WorkerProtocolViolation,
    decode_command_bytes,
    diagnostic_code,
    result_line,
)
from dahe_ocr_worker.protocol_stdout import (
    IsolatedProtocolStdout,
    isolated_protocol_stdout,
)

MAX_IMAGE_BYTES = 64 * 1024 * 1024
RUNTIME_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="DaHe isolated OCR worker")
    parser.add_argument("--runtime-kind", choices=("cpu", "gpu"), required=True)
    parser.add_argument("--data-root", type=Path, required=True)
    parser.add_argument("--models-dir", type=Path, required=True)
    parser.add_argument("--model-manifest", type=Path, required=True)
    parser.add_argument("--runtime-fingerprint", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--device-index", type=int)
    parser.add_argument("--precision", choices=("fp32", "fp16"), default="fp32")
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--cpu-threads", type=int, default=4)
    return parser


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = path.stat(follow_symlinks=False).st_file_attributes
    except AttributeError:
        return path.is_symlink()
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _resolve_image(data_root: Path, command: WorkerCommand) -> Path:
    if command.relative_path is None or command.image_sha256 is None:
        raise WorkerProtocolViolation("image command is missing evidence")
    current = data_root
    for part in Path(command.relative_path).parts:
        current = current / part
        if current.is_symlink() or _is_reparse_point(current):
            raise WorkerProtocolViolation("image path uses a link or reparse point")
    resolved = current.resolve(strict=True)
    try:
        resolved.relative_to(data_root)
    except ValueError as exc:
        raise WorkerProtocolViolation("image path escapes the data root") from exc
    if not resolved.is_file():
        raise WorkerProtocolViolation("image evidence is not a file")
    return resolved


def _read_verified_image(data_root: Path, command: WorkerCommand) -> bytes:
    """Capture, bound, and hash the exact immutable bytes sent to OCR."""

    resolved = _resolve_image(data_root, command)
    with resolved.open("rb") as image_stream:
        image_bytes = image_stream.read(MAX_IMAGE_BYTES + 1)
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise WorkerProtocolViolation("image evidence exceeds the byte limit")
    digest = hashlib.sha256(image_bytes).hexdigest()
    if digest != command.image_sha256:
        raise WorkerProtocolViolation("image evidence hash changed")
    return image_bytes


def _error_kind(exc: BaseException) -> str:
    text = f"{type(exc).__name__}:{exc}".lower()
    if "out of memory" in text or "resourceexhausted" in text:
        return "out_of_memory"
    if "cuda" in text or "cudnn" in text or "cublas" in text:
        return "driver_incompatible"
    if isinstance(exc, ModelManifestError):
        return "model_manifest_invalid"
    if isinstance(exc, WorkerProtocolViolation):
        return "protocol_error"
    return "smoke_failed"


def _base_result(
    *,
    command: WorkerCommand,
    worker_identity: str,
    runtime_fingerprint: str,
) -> dict[str, object]:
    return {
        "protocol_version": 1,
        "command_id": command.command_id,
        "status": "ok",
        "worker_identity": worker_identity,
        "runtime_fingerprint": runtime_fingerprint,
        "verified_image_sha256": command.image_sha256,
        "elapsed_ms": 0,
        "text_lines": [],
        "fields": {},
        "role_observation": None,
        "error": None,
    }


def _write(
    payload: dict[str, object],
    *,
    protocol_stdout: IsolatedProtocolStdout,
) -> None:
    protocol_stdout.write_line(result_line(payload))


def _run_worker(
    args: argparse.Namespace,
    *,
    protocol_stdout: IsolatedProtocolStdout,
) -> int:
    data_root = args.data_root.resolve(strict=True)
    models_dir = args.models_dir.resolve(strict=True)
    runtime_fingerprint = str(args.runtime_fingerprint)
    if RUNTIME_FINGERPRINT_PATTERN.fullmatch(runtime_fingerprint) is None:
        raise SystemExit("runtime fingerprint is invalid")
    if args.runtime_kind == "gpu" and args.device_index is None:
        raise SystemExit("GPU runtime requires a current device mapping")
    if args.runtime_kind == "cpu" and args.device_index is not None:
        raise SystemExit("CPU runtime cannot receive a GPU device mapping")
    os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "True"
    os.environ["PADDLE_PDX_DISABLE_DEVICE_FALLBACK"] = "True"
    install_python_network_guard()
    load_and_verify_model_manifest(
        models_dir=models_dir,
        manifest_path=args.model_manifest,
    )
    worker_identity = f"ocr-{os.getpid()}-{uuid4().hex[:8]}"
    engine = PaddleEngine(
        EngineConfig(
            runtime_kind=args.runtime_kind,
            current_device_index=args.device_index,
            models_dir=models_dir,
            precision=args.precision,
            batch_size=args.batch_size,
            cpu_threads=args.cpu_threads,
        )
    )

    input_stream = sys.stdin.buffer
    while True:
        raw_line = input_stream.readline(MAX_COMMAND_LINE_BYTES + 2)
        if not raw_line:
            break
        started = time.perf_counter()
        command: WorkerCommand | None = None
        try:
            command = decode_command_bytes(raw_line)
            if command.runtime_fingerprint != runtime_fingerprint:
                raise WorkerProtocolViolation("runtime fingerprint does not match worker")
            if command.profile_id != args.profile_id:
                raise WorkerProtocolViolation("profile identity does not match worker")
            payload = _base_result(
                command=command,
                worker_identity=worker_identity,
                runtime_fingerprint=runtime_fingerprint,
            )
            if command.operation == "shutdown":
                _write(
                    payload,
                    protocol_stdout=protocol_stdout,
                )
                return 0
            if command.operation in {"smoke", "extract"}:
                image_bytes = _read_verified_image(data_root, command)
                extraction = engine.extract(image_bytes)
                payload.update(extraction)
            payload["elapsed_ms"] = max(
                float(cast(float, payload["elapsed_ms"])),
                (time.perf_counter() - started) * 1000,
            )
            _write(
                payload,
                protocol_stdout=protocol_stdout,
            )
        except WorkerProtocolViolation as exc:
            if command is None:
                fallback_command_id = "unparsed-command"
                verified_image_sha256 = None
            else:
                fallback_command_id = command.command_id
                verified_image_sha256 = command.image_sha256
            kind = _error_kind(exc)
            _write(
                {
                    "protocol_version": 1,
                    "command_id": fallback_command_id,
                    "status": "error",
                    "worker_identity": worker_identity,
                    "runtime_fingerprint": runtime_fingerprint,
                    "verified_image_sha256": verified_image_sha256,
                    "elapsed_ms": (time.perf_counter() - started) * 1000,
                    "text_lines": [],
                    "fields": {},
                    "role_observation": None,
                    "error": {
                        "kind": kind,
                        "message": "The local OCR worker could not complete this image.",
                        "diagnostic_code": diagnostic_code(
                            kind,
                            runtime_fingerprint,
                            type(exc).__name__,
                        ),
                    },
                },
                protocol_stdout=protocol_stdout,
            )
            return 42
        except Exception as exc:
            if command is None:
                fallback_command_id = "unparsed-command"
                verified_image_sha256 = None
            else:
                fallback_command_id = command.command_id
                verified_image_sha256 = command.image_sha256
            kind = _error_kind(exc)
            _write(
                {
                    "protocol_version": 1,
                    "command_id": fallback_command_id,
                    "status": "error",
                    "worker_identity": worker_identity,
                    "runtime_fingerprint": runtime_fingerprint,
                    "verified_image_sha256": verified_image_sha256,
                    "elapsed_ms": (time.perf_counter() - started) * 1000,
                    "text_lines": [],
                    "fields": {},
                    "role_observation": None,
                    "error": {
                        "kind": kind,
                        "message": "The local OCR worker could not complete this image.",
                        "diagnostic_code": diagnostic_code(
                            kind,
                            runtime_fingerprint,
                            type(exc).__name__,
                        ),
                    },
                },
                protocol_stdout=protocol_stdout,
            )
            # Inference failures can leave a device allocator or Paddle
            # pipeline in an unknown state. Let the supervisor replace this
            # worker instead of accepting another image in the same process.
            return 43
    return 0


def main() -> int:
    args = _parser().parse_args()
    with isolated_protocol_stdout() as protocol_stdout:
        return _run_worker(
            args,
            protocol_stdout=protocol_stdout,
        )


if __name__ == "__main__":
    raise SystemExit(main())
