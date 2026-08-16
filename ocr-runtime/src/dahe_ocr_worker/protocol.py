from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

PROTOCOL_VERSION = 1
BATCH_PROTOCOL_VERSION = 2
MAX_COMMAND_LINE_BYTES = 64 * 1024
MAX_RESULT_LINE_BYTES = 4 * 1024 * 1024
MAX_COMMAND_ID_CHARS = 128
MAX_PROFILE_ID_CHARS = 128
MAX_RELATIVE_PATH_CHARS = 512
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OPERATIONS = {"hello", "smoke", "extract", "shutdown"}
COMMAND_FIELDS_V1 = {
    "protocol_version",
    "command_id",
    "operation",
    "image_sha256",
    "relative_path",
    "pipeline_fingerprint",
    "runtime_fingerprint",
    "profile_id",
}
# Kept for v1 conformance tests and older standalone tools.
COMMAND_FIELDS = COMMAND_FIELDS_V1
COMMAND_FIELDS_V2 = {
    "protocol_version",
    "command_id",
    "operation",
    "images",
    "pipeline_fingerprint",
    "runtime_fingerprint",
    "profile_id",
}
IMAGE_FIELDS_V2 = {"image_sha256", "relative_path", "role"}


class WorkerProtocolViolation(RuntimeError):
    """Raised when a command is not safe to execute."""


@dataclass(frozen=True, slots=True)
class WorkerBatchImage:
    image_sha256: str
    relative_path: str
    role: str


@dataclass(frozen=True, slots=True)
class WorkerCommand:
    command_id: str
    operation: str
    image_sha256: str | None
    relative_path: str | None
    pipeline_fingerprint: str | None
    runtime_fingerprint: str
    profile_id: str
    protocol_version: int = PROTOCOL_VERSION
    images: tuple[WorkerBatchImage, ...] = ()


def _require_sha(value: object, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise WorkerProtocolViolation(f"{field} must be a lowercase SHA-256")
    return value


def _require_text(value: object, field: str, *, max_chars: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise WorkerProtocolViolation(f"{field} must be non-empty text")
    normalized = value.strip()
    if len(normalized) > max_chars:
        raise WorkerProtocolViolation(f"{field} exceeds its character limit")
    try:
        normalized.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise WorkerProtocolViolation(f"{field} contains invalid Unicode") from exc
    return normalized


def _safe_relative_path(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or ":" in value
        or value.startswith("//")
        or len(value) > MAX_RELATIVE_PATH_CHARS
    ):
        raise WorkerProtocolViolation("relative_path is invalid")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise WorkerProtocolViolation("relative_path contains invalid Unicode") from exc
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise WorkerProtocolViolation("relative_path escapes the data root")
    return path.as_posix()


def parse_command(line: str) -> WorkerCommand:
    if "\n" in line or "\r" in line:
        raise WorkerProtocolViolation("command must contain exactly one JSON line")
    try:
        encoded = line.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise WorkerProtocolViolation("command contains invalid Unicode") from exc
    if len(encoded) > MAX_COMMAND_LINE_BYTES:
        raise WorkerProtocolViolation("command exceeds the line limit")
    try:
        payload = json.loads(line)
    except json.JSONDecodeError as exc:
        raise WorkerProtocolViolation("command is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise WorkerProtocolViolation("command must be an object")
    protocol_version = payload.get("protocol_version")
    if protocol_version == BATCH_PROTOCOL_VERSION:
        if set(payload) != COMMAND_FIELDS_V2:
            raise WorkerProtocolViolation("command fields do not match protocol version 2")
        if payload["operation"] != "extract_batch":
            raise WorkerProtocolViolation("protocol version 2 only accepts extract_batch")
        command_id = _require_text(
            payload["command_id"],
            "command_id",
            max_chars=MAX_COMMAND_ID_CHARS,
        )
        profile_id = _require_text(
            payload["profile_id"],
            "profile_id",
            max_chars=MAX_PROFILE_ID_CHARS,
        )
        runtime_fingerprint = _require_sha(
            payload["runtime_fingerprint"],
            "runtime_fingerprint",
        )
        pipeline_fingerprint = _require_sha(
            payload["pipeline_fingerprint"],
            "pipeline_fingerprint",
        )
        raw_images = payload["images"]
        if not isinstance(raw_images, list) or not 1 <= len(raw_images) <= 2:
            raise WorkerProtocolViolation("vehicle OCR batch must contain one or two images")
        images: list[WorkerBatchImage] = []
        roles: set[str] = set()
        for raw_image in raw_images:
            if not isinstance(raw_image, dict) or set(raw_image) != IMAGE_FIELDS_V2:
                raise WorkerProtocolViolation("batch image fields are invalid")
            role = raw_image["role"]
            if role not in {"loading", "unloading"} or role in roles:
                raise WorkerProtocolViolation("batch image roles must be unique")
            roles.add(str(role))
            images.append(
                WorkerBatchImage(
                    image_sha256=str(_require_sha(raw_image["image_sha256"], "image_sha256")),
                    relative_path=_safe_relative_path(raw_image["relative_path"]),
                    role=str(role),
                )
            )
        return WorkerCommand(
            command_id=command_id,
            operation="extract_batch",
            image_sha256=None,
            relative_path=None,
            pipeline_fingerprint=str(pipeline_fingerprint),
            runtime_fingerprint=str(runtime_fingerprint),
            profile_id=profile_id,
            protocol_version=BATCH_PROTOCOL_VERSION,
            images=tuple(images),
        )
    if protocol_version != PROTOCOL_VERSION or set(payload) != COMMAND_FIELDS_V1:
        raise WorkerProtocolViolation("command fields do not match a supported protocol version")
    operation = payload["operation"]
    if operation not in OPERATIONS:
        raise WorkerProtocolViolation("command operation is unsupported")
    command_id = _require_text(
        payload["command_id"],
        "command_id",
        max_chars=MAX_COMMAND_ID_CHARS,
    )
    profile_id = _require_text(
        payload["profile_id"],
        "profile_id",
        max_chars=MAX_PROFILE_ID_CHARS,
    )
    runtime_fingerprint = _require_sha(payload["runtime_fingerprint"], "runtime_fingerprint")
    image_operation = operation in {"smoke", "extract"}
    if image_operation:
        image_sha256 = _require_sha(payload["image_sha256"], "image_sha256")
        relative_path = _safe_relative_path(payload["relative_path"])
        pipeline_fingerprint = _require_sha(
            payload["pipeline_fingerprint"],
            "pipeline_fingerprint",
        )
    else:
        if any(
            payload[field] is not None
            for field in ("image_sha256", "relative_path", "pipeline_fingerprint")
        ):
            raise WorkerProtocolViolation("non-image command contains image evidence")
        image_sha256 = None
        relative_path = None
        pipeline_fingerprint = None
    return WorkerCommand(
        command_id=command_id,
        operation=operation,
        image_sha256=image_sha256,
        relative_path=relative_path,
        pipeline_fingerprint=pipeline_fingerprint,
        runtime_fingerprint=str(runtime_fingerprint),
        profile_id=profile_id,
        protocol_version=PROTOCOL_VERSION,
    )


def decode_command_bytes(raw_line: bytes) -> WorkerCommand:
    """Decode exactly one bounded UTF-8 NDJSON command without replacement."""
    if not raw_line:
        raise WorkerProtocolViolation("command stream closed")
    if len(raw_line) > MAX_COMMAND_LINE_BYTES + 2:
        raise WorkerProtocolViolation("command exceeds the line limit")
    if not raw_line.endswith(b"\n"):
        raise WorkerProtocolViolation("command is not newline terminated")
    body = raw_line[:-1]
    if body.endswith(b"\r"):
        body = body[:-1]
    if b"\n" in body or b"\r" in body:
        raise WorkerProtocolViolation("command must contain exactly one JSON line")
    try:
        line = body.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WorkerProtocolViolation("command is not strict UTF-8") from exc
    return parse_command(line)


def diagnostic_code(kind: str, runtime_fingerprint: str, error_type: str) -> str:
    digest = hashlib.sha256(f"{kind}:{runtime_fingerprint}:{error_type}".encode()).hexdigest()
    return f"OCR-{digest[:12].upper()}"


def result_line(payload: dict[str, Any]) -> str:
    try:
        line = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        encoded = line.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise WorkerProtocolViolation("result contains invalid Unicode") from exc
    if len(encoded) > MAX_RESULT_LINE_BYTES:
        raise WorkerProtocolViolation("result exceeds the line limit")
    return line
