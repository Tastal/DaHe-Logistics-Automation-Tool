from __future__ import annotations

import json
import re
from decimal import Decimal
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

OCR_PROTOCOL_VERSION: Literal[1] = 1
OCR_BATCH_PROTOCOL_VERSION: Literal[2] = 2
MAX_COMMAND_LINE_BYTES = 64 * 1024
MAX_RESULT_LINE_BYTES = 4 * 1024 * 1024
MAX_COMMAND_ID_CHARS = 128
MAX_PROFILE_ID_CHARS = 128
MAX_RELATIVE_PATH_CHARS = 512
MAX_WORKER_ID_CHARS = 128
MAX_TEXT_LINE_CHARS = 2048
MAX_TEXT_LINES = 2000
MAX_FIELD_COUNT = 64
MAX_FIELD_NAME_CHARS = 64
MAX_FIXED_TEXT_ITEMS = 128
MAX_ERROR_MESSAGE_CHARS = 512
MAX_DIAGNOSTIC_CODE_CHARS = 64
MAX_AMOUNT_CHARS = 64
MAX_UNIT_CHARS = 16
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonEmptyText = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
CommandId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_COMMAND_ID_CHARS),
]
ProfileId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_PROFILE_ID_CHARS),
]
WorkerId = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_WORKER_ID_CHARS),
]
RecognizedText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_TEXT_LINE_CHARS),
]


class OcrProtocolError(RuntimeError):
    """Raised when a worker message violates the versioned protocol."""


class OcrOperation(StrEnum):
    HELLO = "hello"
    SMOKE = "smoke"
    EXTRACT = "extract"
    EXTRACT_BATCH = "extract_batch"
    SHUTDOWN = "shutdown"


class OcrResultStatus(StrEnum):
    OK = "ok"
    ERROR = "error"


class NormalizedBox(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    x: Decimal = Field(ge=0, le=1)
    y: Decimal = Field(ge=0, le=1)
    width: Decimal = Field(gt=0, le=1)
    height: Decimal = Field(gt=0, le=1)

    @model_validator(mode="after")
    def stay_inside_image(self) -> Self:
        if self.x + self.width > 1 or self.y + self.height > 1:
            raise ValueError("normalized box must stay inside the image")
        return self


class OcrTextLine(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    text: RecognizedText
    confidence: Decimal = Field(ge=0, le=1)
    box: NormalizedBox


class OcrFieldValue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    raw_text: RecognizedText
    amount: Annotated[str, StringConstraints(max_length=MAX_AMOUNT_CHARS)] | None = None
    unit: Annotated[str, StringConstraints(max_length=MAX_UNIT_CHARS)] | None = None
    confidence: Decimal = Field(ge=0, le=1)


class OcrRoleObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    fixed_text: tuple[RecognizedText, ...] = Field(max_length=MAX_FIXED_TEXT_ITEMS)
    layout_fingerprint: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=128),
    ]
    orientation_degrees: Literal[0, 90, 180, 270]


class OcrWorkerError(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    kind: Annotated[
        str,
        StringConstraints(strip_whitespace=True, min_length=1, max_length=64),
    ]
    message: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=MAX_ERROR_MESSAGE_CHARS,
        ),
    ]
    diagnostic_code: Annotated[
        str,
        StringConstraints(
            strip_whitespace=True,
            min_length=1,
            max_length=MAX_DIAGNOSTIC_CODE_CHARS,
        ),
    ]


def _validated_relative_path(value: str | None) -> str | None:
    if value is None:
        return None
    if not value or "\\" in value or ":" in value or value.startswith("//"):
        raise ValueError("relative_path must use a safe POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise ValueError("relative_path must stay inside the data root")
    if any(not part for part in path.parts):
        raise ValueError("relative_path contains an empty component")
    return path.as_posix()


class OcrBatchImage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    image_sha256: Sha256
    relative_path: Annotated[str, StringConstraints(max_length=MAX_RELATIVE_PATH_CHARS)]
    role: Literal["loading", "unloading"]

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        validated = _validated_relative_path(value)
        assert validated is not None
        return validated


class OcrBatchCommand(BaseModel):
    """One vehicle-sized request containing at most one image per role."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[2] = 2
    command_id: CommandId
    operation: Literal[OcrOperation.EXTRACT_BATCH] = OcrOperation.EXTRACT_BATCH
    images: tuple[OcrBatchImage, ...] = Field(min_length=1, max_length=2)
    pipeline_fingerprint: Sha256
    runtime_fingerprint: Sha256
    profile_id: ProfileId

    @model_validator(mode="after")
    def require_unique_roles(self) -> Self:
        roles = tuple(image.role for image in self.images)
        if len(set(roles)) != len(roles):
            raise ValueError("vehicle OCR batch roles must be unique")
        return self

    def to_ndjson(self) -> str:
        return _serialize_command(self)


class OcrCommand(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[1] = 1
    command_id: CommandId
    operation: OcrOperation
    image_sha256: Sha256 | None = None
    relative_path: Annotated[str, StringConstraints(max_length=MAX_RELATIVE_PATH_CHARS)] | None = (
        None
    )
    pipeline_fingerprint: Sha256 | None = None
    runtime_fingerprint: Sha256
    profile_id: ProfileId

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str | None) -> str | None:
        return _validated_relative_path(value)

    @model_validator(mode="after")
    def require_image_fields_for_image_operations(self) -> Self:
        if self.operation is OcrOperation.EXTRACT_BATCH:
            raise ValueError("extract_batch requires the OCR protocol v2 command")
        image_operation = self.operation in {OcrOperation.SMOKE, OcrOperation.EXTRACT}
        image_values = (
            self.image_sha256,
            self.relative_path,
            self.pipeline_fingerprint,
        )
        if image_operation and any(value is None for value in image_values):
            raise ValueError("image operations require hash, relative path, and pipeline")
        if not image_operation and any(value is not None for value in image_values):
            raise ValueError("non-image operations cannot include image evidence")
        return self

    def to_ndjson(self) -> str:
        return _serialize_command(self)


class OcrResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[1] = 1
    command_id: CommandId
    status: OcrResultStatus
    worker_identity: WorkerId
    runtime_fingerprint: Sha256
    verified_image_sha256: Sha256 | None
    elapsed_ms: float = Field(ge=0)
    text_lines: tuple[OcrTextLine, ...] = Field(max_length=MAX_TEXT_LINES)
    fields: dict[str, OcrFieldValue] = Field(max_length=MAX_FIELD_COUNT)
    role_observation: OcrRoleObservation | None
    error: OcrWorkerError | None

    @model_validator(mode="after")
    def validate_status_payload(self) -> Self:
        if self.status is OcrResultStatus.OK and self.error is not None:
            raise ValueError("successful results cannot contain an error")
        if self.status is OcrResultStatus.ERROR and self.error is None:
            raise ValueError("failed results require an error")
        if self.status is OcrResultStatus.ERROR and (
            self.text_lines or self.fields or self.role_observation is not None
        ):
            raise ValueError("failed results cannot contain OCR business output")
        if any(
            not field_name
            or len(field_name) > MAX_FIELD_NAME_CHARS
            or re.fullmatch(r"[a-z][a-z0-9_]*", field_name) is None
            for field_name in self.fields
        ):
            raise ValueError("OCR field names must use bounded snake_case")
        return self


class OcrBatchResultItem(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    role: Literal["loading", "unloading"]
    verified_image_sha256: Sha256
    elapsed_ms: float = Field(ge=0)
    text_lines: tuple[OcrTextLine, ...] = Field(max_length=MAX_TEXT_LINES)
    fields: dict[str, OcrFieldValue] = Field(max_length=MAX_FIELD_COUNT)
    role_observation: OcrRoleObservation | None

    @field_validator("fields")
    @classmethod
    def validate_field_names(
        cls,
        value: dict[str, OcrFieldValue],
    ) -> dict[str, OcrFieldValue]:
        if any(
            not field_name
            or len(field_name) > MAX_FIELD_NAME_CHARS
            or re.fullmatch(r"[a-z][a-z0-9_]*", field_name) is None
            for field_name in value
        ):
            raise ValueError("OCR field names must use bounded snake_case")
        return value


class OcrBatchResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    protocol_version: Literal[2] = 2
    command_id: CommandId
    status: OcrResultStatus
    worker_identity: WorkerId
    runtime_fingerprint: Sha256
    elapsed_ms: float = Field(ge=0)
    items: tuple[OcrBatchResultItem, ...] = Field(max_length=2)
    error: OcrWorkerError | None

    @model_validator(mode="after")
    def validate_status_payload(self) -> Self:
        if self.status is OcrResultStatus.OK:
            if self.error is not None:
                raise ValueError("successful results cannot contain an error")
            if not self.items:
                raise ValueError("successful batch results require image output")
            roles = tuple(item.role for item in self.items)
            if len(set(roles)) != len(roles):
                raise ValueError("batch result roles must be unique")
        else:
            if self.error is None:
                raise ValueError("failed results require an error")
            if self.items:
                raise ValueError("failed batch results cannot contain OCR output")
        return self


OcrWorkerCommand = OcrCommand | OcrBatchCommand
OcrWorkerResult = OcrResult | OcrBatchResult


def _serialize_command(command: OcrWorkerCommand) -> str:
    try:
        line = (
            json.dumps(
                command.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
        encoded = line.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise OcrProtocolError("OCR command contains invalid Unicode") from exc
    if len(encoded) > MAX_COMMAND_LINE_BYTES:
        raise OcrProtocolError("OCR command exceeds the size limit")
    return line


def _parse_json_line(line: str) -> object:
    try:
        encoded = line.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise OcrProtocolError("OCR result contains invalid Unicode") from exc
    if len(encoded) > MAX_RESULT_LINE_BYTES:
        raise OcrProtocolError("OCR protocol line exceeds the size limit")
    if "\n" in line or "\r" in line:
        raise OcrProtocolError("OCR protocol accepts exactly one JSON line")
    try:
        return json.loads(line)
    except json.JSONDecodeError as exc:
        raise OcrProtocolError("OCR worker returned malformed JSON") from exc


def parse_result_line(line: str) -> OcrWorkerResult:
    payload = _parse_json_line(line)
    if not isinstance(payload, dict):
        raise OcrProtocolError("OCR worker result must be an object")
    try:
        if payload.get("protocol_version") == OCR_PROTOCOL_VERSION:
            return OcrResult.model_validate(payload)
        if payload.get("protocol_version") == OCR_BATCH_PROTOCOL_VERSION:
            return OcrBatchResult.model_validate(payload)
        raise ValueError("unsupported OCR protocol version")
    except (TypeError, ValueError) as exc:
        raise OcrProtocolError("OCR worker result does not match its protocol version") from exc


def validate_result_for_command(
    *,
    command: OcrWorkerCommand,
    result: OcrWorkerResult,
) -> None:
    if result.command_id != command.command_id:
        raise OcrProtocolError("OCR result command correlation failed")
    if result.runtime_fingerprint != command.runtime_fingerprint:
        raise OcrProtocolError("OCR result runtime fingerprint changed")
    if isinstance(command, OcrBatchCommand):
        if not isinstance(result, OcrBatchResult):
            raise OcrProtocolError("OCR batch result protocol changed")
        expected = tuple((image.role, image.image_sha256) for image in command.images)
        actual = tuple((item.role, item.verified_image_sha256) for item in result.items)
        if result.status is OcrResultStatus.OK and actual != expected:
            raise OcrProtocolError("OCR batch result image order or identity changed")
        return
    if not isinstance(result, OcrResult):
        raise OcrProtocolError("OCR single-image result protocol changed")
    if result.verified_image_sha256 != command.image_sha256:
        raise OcrProtocolError("OCR result image identity changed")
