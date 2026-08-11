from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum

from dahe.adapters.chengfeng.redaction import redact_text
from dahe.ports.chengfeng import (
    BrowserCommandAuthority,
    ChengfengOperation,
    ChengfengStage,
)

_IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}\Z")
_FENCING_TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,256}\Z")
_CREDENTIAL_REFERENCE_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_PAYLOAD_PATH_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,511}\Z")
_SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
_SENSITIVE_PARAMETER_KEYS = {
    "authorization",
    "cookie",
    "credential",
    "credentials",
    "password",
    "passwd",
    "phone",
    "mobile",
    "session",
    "sessionid",
    "sessiontoken",
    "token",
    "accesstoken",
    "refreshtoken",
    "signature",
    "sig",
    "accesskey",
    "secret",
}


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _require_identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{name} is not a valid connector identifier")
    return value


def _normalize_json_value(value: object, *, path: str) -> object:
    if value is None or isinstance(value, bool | int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"{path} must contain finite JSON numbers")
        return value
    if isinstance(value, str):
        if redact_text(value) != value:
            raise ValueError(f"{path} must not contain credentials or personal data")
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise ValueError(f"{path} must use non-empty string keys")
            if _normalized_key(key) in _SENSITIVE_PARAMETER_KEYS:
                raise ValueError(f"{path}.{key} is a forbidden sensitive parameter")
            normalized[key] = _normalize_json_value(child, path=f"{path}.{key}")
        return normalized
    if isinstance(value, Sequence) and not isinstance(
        value,
        (str, bytes, bytearray),
    ):
        return [
            _normalize_json_value(child, path=f"{path}[{index}]")
            for index, child in enumerate(value)
        ]
    raise TypeError(f"{path} is not JSON serializable")


def _validate_authority(authority: object) -> BrowserCommandAuthority:
    if not isinstance(authority, BrowserCommandAuthority):
        raise TypeError("authority must be BrowserCommandAuthority")
    for name in ("session_id", "instance_id", "worker_id", "job_id"):
        _require_identifier(name, getattr(authority, name))
    if (
        isinstance(authority.control_epoch, bool)
        or not isinstance(authority.control_epoch, int)
        or authority.control_epoch <= 0
    ):
        raise ValueError("control_epoch must be a positive integer")
    if _FENCING_TOKEN_PATTERN.fullmatch(authority.fencing_token) is None:
        raise ValueError("fencing_token is not a valid opaque connector token")
    return authority


@dataclass(frozen=True, slots=True)
class ConnectorCommand:
    """One strictly typed command for the isolated Chengfeng connector."""

    protocol_version: int
    command_id: str
    operation: ChengfengOperation
    authority: BrowserCommandAuthority
    parameters: Mapping[str, object]
    credential_reference: str | None

    def __post_init__(self) -> None:
        if (
            isinstance(self.protocol_version, bool)
            or not isinstance(self.protocol_version, int)
            or self.protocol_version != 1
        ):
            raise ValueError("only connector protocol version 1 is supported")
        _require_identifier("command_id", self.command_id)
        if not isinstance(self.operation, ChengfengOperation):
            raise TypeError("operation must be a ChengfengOperation")
        _validate_authority(self.authority)
        if not isinstance(self.parameters, Mapping):
            raise TypeError("parameters must be a mapping")
        normalized_parameters = _normalize_json_value(
            self.parameters,
            path="parameters",
        )
        assert isinstance(normalized_parameters, dict)
        _validate_operation_parameters(self.operation, normalized_parameters)
        object.__setattr__(self, "parameters", normalized_parameters)
        if self.credential_reference is not None and (
            not isinstance(self.credential_reference, str)
            or _CREDENTIAL_REFERENCE_PATTERN.fullmatch(self.credential_reference) is None
        ):
            raise ValueError("credential_reference is invalid")

    @classmethod
    def from_ndjson(cls, value: str | bytes) -> ConnectorCommand:
        payload = _parse_single_ndjson(value, record_name="connector command")
        _require_exact_fields(
            payload,
            expected=_COMMAND_FIELDS,
            path="connector_command",
        )

        authority_value = payload["authority"]
        if not isinstance(authority_value, Mapping):
            raise TypeError("authority must be a JSON object")
        _require_exact_fields(
            authority_value,
            expected=_AUTHORITY_FIELDS,
            path="authority",
        )
        authority = BrowserCommandAuthority(
            session_id=_require_string("authority.session_id", authority_value["session_id"]),
            instance_id=_require_string(
                "authority.instance_id",
                authority_value["instance_id"],
            ),
            worker_id=_require_string("authority.worker_id", authority_value["worker_id"]),
            job_id=_require_string("authority.job_id", authority_value["job_id"]),
            control_epoch=_require_integer(
                "authority.control_epoch",
                authority_value["control_epoch"],
            ),
            fencing_token=_require_string(
                "authority.fencing_token",
                authority_value["fencing_token"],
            ),
        )

        parameters_value = payload["parameters"]
        if not isinstance(parameters_value, Mapping):
            raise TypeError("parameters must be a JSON object")
        credential_reference_value = payload["credential_reference"]
        if credential_reference_value is not None and not isinstance(
            credential_reference_value,
            str,
        ):
            raise TypeError("credential_reference must be a string or null")
        return cls(
            protocol_version=_require_integer(
                "protocol_version",
                payload["protocol_version"],
            ),
            command_id=_require_string("command_id", payload["command_id"]),
            operation=_parse_enum(
                ChengfengOperation,
                payload["operation"],
                path="operation",
            ),
            authority=authority,
            parameters=parameters_value,
            credential_reference=credential_reference_value,
        )

    def to_ndjson(self) -> str:
        payload = {
            "protocol_version": self.protocol_version,
            "command_id": self.command_id,
            "operation": self.operation.value,
            "authority": {
                "session_id": self.authority.session_id,
                "instance_id": self.authority.instance_id,
                "worker_id": self.authority.worker_id,
                "job_id": self.authority.job_id,
                "control_epoch": self.authority.control_epoch,
                "fencing_token": self.authority.fencing_token,
            },
            "parameters": dict(self.parameters),
            "credential_reference": self.credential_reference,
        }
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )


class ConnectorResultOutcome(StrEnum):
    """Finite outcomes emitted by the isolated connector process."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"


class ConnectorDiagnosticClassification(StrEnum):
    """Safe error categories; raw exception or response text never crosses the boundary."""

    NONE = "none"
    LOGIN_REQUIRED = "login_required"
    PAGE_CONTRACT_CHANGED = "page_contract_changed"
    IMAGE_TIMEOUT = "image_timeout"
    TRANSIENT_NETWORK = "transient_network"
    BROWSER_CONTEXT_CLOSED = "browser_context_closed"
    IMAGE_CAPABILITY_EXPIRED = "image_capability_expired"
    DETAIL_CANDIDATE_UNAVAILABLE = "detail_candidate_unavailable"
    PROTOCOL_ERROR = "protocol_error"


class ConnectorPayloadKind(StrEnum):
    WAYBILL_PAGE = "waybill_page"
    WAYBILL_DETAIL = "waybill_detail"
    TICKET_IMAGE = "ticket_image"


_EXPECTED_STAGE = {
    ChengfengOperation.LIST_WAYBILLS: ChengfengStage.LIST_QUERY,
    ChengfengOperation.GET_WAYBILL_DETAIL: ChengfengStage.DETAIL_QUERY,
    ChengfengOperation.DOWNLOAD_TICKET_IMAGE: ChengfengStage.IMAGE_DOWNLOAD,
}
_EXPECTED_PAYLOAD_KIND = {
    ChengfengOperation.LIST_WAYBILLS: ConnectorPayloadKind.WAYBILL_PAGE,
    ChengfengOperation.GET_WAYBILL_DETAIL: ConnectorPayloadKind.WAYBILL_DETAIL,
    ChengfengOperation.DOWNLOAD_TICKET_IMAGE: ConnectorPayloadKind.TICKET_IMAGE,
}
_ALLOWED_MEDIA_TYPES = frozenset({"application/json", "image/jpeg", "image/png"})
_ALLOWED_MEDIA_TYPES_BY_PAYLOAD_KIND = {
    ConnectorPayloadKind.WAYBILL_PAGE: frozenset({"application/json"}),
    ConnectorPayloadKind.WAYBILL_DETAIL: frozenset({"application/json"}),
    ConnectorPayloadKind.TICKET_IMAGE: frozenset({"image/jpeg", "image/png"}),
}
_MAX_PAYLOAD_BYTES_BY_KIND = {
    ConnectorPayloadKind.WAYBILL_PAGE: 8 * 1024 * 1024,
    ConnectorPayloadKind.WAYBILL_DETAIL: 8 * 1024 * 1024,
    ConnectorPayloadKind.TICKET_IMAGE: 32 * 1024 * 1024,
}
_OPERATION_PARAMETER_FIELDS = {
    ChengfengOperation.LIST_WAYBILLS: frozenset({"scope", "page_number", "page_size"}),
    ChengfengOperation.GET_WAYBILL_DETAIL: frozenset({"platform_waybill_id"}),
    ChengfengOperation.DOWNLOAD_TICKET_IMAGE: frozenset({"ticket_ref"}),
}
_COMMAND_FIELDS = frozenset(
    {
        "protocol_version",
        "command_id",
        "operation",
        "authority",
        "parameters",
        "credential_reference",
    }
)
_AUTHORITY_FIELDS = frozenset(
    {
        "session_id",
        "instance_id",
        "worker_id",
        "job_id",
        "control_epoch",
        "fencing_token",
    }
)
_RESULT_FIELDS = frozenset(
    {
        "protocol_version",
        "command_id",
        "operation",
        "outcome",
        "stage",
        "diagnostic_classification",
        "payload_references",
    }
)
_PAYLOAD_REFERENCE_FIELDS = frozenset(
    {"kind", "relative_path", "sha256", "media_type", "byte_size"}
)


def _require_exact_fields(
    value: Mapping[object, object],
    *,
    expected: frozenset[str],
    path: str,
) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(str(item) for item in actual - expected)
        raise ValueError(f"{path} fields must match schema; missing={missing}, extra={extra}")


def _parse_enum[T: StrEnum](enum_type: type[T], value: object, *, path: str) -> T:
    if not isinstance(value, str):
        raise TypeError(f"{path} must be a string")
    try:
        return enum_type(value)
    except ValueError as error:
        raise ValueError(f"{path} is not supported") from error


def _parse_single_ndjson(
    value: str | bytes,
    *,
    record_name: str,
) -> Mapping[object, object]:
    if isinstance(value, bytes):
        try:
            text = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError(f"{record_name} must be valid UTF-8") from error
    elif isinstance(value, str):
        text = value
    else:
        raise TypeError(f"{record_name} NDJSON must be str or bytes")
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        raise ValueError(f"{record_name} must contain exactly one LF-terminated NDJSON record")

    def reject_duplicate_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, child in pairs:
            if key in result:
                raise ValueError(f"{record_name} contains a duplicate JSON field")
            result[key] = child
        return result

    try:
        payload = json.loads(text[:-1], object_pairs_hook=reject_duplicate_fields)
    except json.JSONDecodeError as error:
        raise ValueError(f"{record_name} must be valid JSON") from error
    if not isinstance(payload, Mapping):
        raise TypeError(f"{record_name} must be a JSON object")
    return payload


def _validate_operation_parameters(
    operation: ChengfengOperation,
    parameters: Mapping[object, object],
) -> None:
    _require_exact_fields(
        parameters,
        expected=_OPERATION_PARAMETER_FIELDS[operation],
        path=f"parameters.{operation.value}",
    )
    if operation is ChengfengOperation.LIST_WAYBILLS:
        _require_identifier("parameters.scope", parameters["scope"])
        page_number = _require_integer(
            "parameters.page_number",
            parameters["page_number"],
        )
        page_size = _require_integer("parameters.page_size", parameters["page_size"])
        if page_number < 1:
            raise ValueError("parameters.page_number must be positive")
        if page_size < 1:
            raise ValueError("parameters.page_size must be positive")
        return
    identifier_field = (
        "platform_waybill_id"
        if operation is ChengfengOperation.GET_WAYBILL_DETAIL
        else "ticket_ref"
    )
    _require_identifier(
        f"parameters.{identifier_field}",
        parameters[identifier_field],
    )


@dataclass(frozen=True, slots=True)
class ConnectorPayloadReference:
    """A small content-addressed reference, never an inline payload or remote URL."""

    kind: ConnectorPayloadKind
    relative_path: str
    sha256: str
    media_type: str
    byte_size: int

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ConnectorPayloadKind):
            raise TypeError("payload reference kind must be a ConnectorPayloadKind")
        if (
            not isinstance(self.relative_path, str)
            or _PAYLOAD_PATH_PATTERN.fullmatch(self.relative_path) is None
            or self.relative_path.startswith("/")
            or self.relative_path.endswith("/")
            or "//" in self.relative_path
            or any(part in {"", ".", ".."} for part in self.relative_path.split("/"))
        ):
            raise ValueError("payload relative_path must be a safe data-directory-relative path")
        if not isinstance(self.sha256, str) or _SHA256_PATTERN.fullmatch(self.sha256) is None:
            raise ValueError("payload sha256 must be a lowercase SHA-256 digest")
        if not isinstance(self.media_type, str) or self.media_type not in _ALLOWED_MEDIA_TYPES:
            raise ValueError("payload media_type is not supported")
        if self.media_type not in _ALLOWED_MEDIA_TYPES_BY_PAYLOAD_KIND[self.kind]:
            raise ValueError("payload media_type does not match payload kind")
        if (
            isinstance(self.byte_size, bool)
            or not isinstance(self.byte_size, int)
            or self.byte_size < 1
        ):
            raise ValueError("payload byte_size must be a positive integer")
        if self.byte_size > _MAX_PAYLOAD_BYTES_BY_KIND[self.kind]:
            raise ValueError("payload byte_size exceeds the v1 limit for payload kind")

    @classmethod
    def from_payload(cls, value: object) -> ConnectorPayloadReference:
        if not isinstance(value, Mapping):
            raise TypeError("payload_references items must be objects")
        _require_exact_fields(
            value,
            expected=_PAYLOAD_REFERENCE_FIELDS,
            path="payload_reference",
        )
        return cls(
            kind=_parse_enum(
                ConnectorPayloadKind,
                value["kind"],
                path="payload_reference.kind",
            ),
            relative_path=_require_string(
                "payload_reference.relative_path",
                value["relative_path"],
            ),
            sha256=_require_string("payload_reference.sha256", value["sha256"]),
            media_type=_require_string(
                "payload_reference.media_type",
                value["media_type"],
            ),
            byte_size=_require_integer(
                "payload_reference.byte_size",
                value["byte_size"],
            ),
        )

    def as_payload(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "media_type": self.media_type,
            "byte_size": self.byte_size,
        }


def _require_string(name: str, value: object) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    return value


def _require_integer(name: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    return value


@dataclass(frozen=True, slots=True)
class ConnectorResult:
    """Credential-free versioned result returned by the isolated connector."""

    protocol_version: int
    command_id: str
    operation: ChengfengOperation
    outcome: ConnectorResultOutcome
    stage: ChengfengStage
    diagnostic_classification: ConnectorDiagnosticClassification
    payload_references: tuple[ConnectorPayloadReference, ...]

    def __post_init__(self) -> None:
        if (
            isinstance(self.protocol_version, bool)
            or not isinstance(self.protocol_version, int)
            or self.protocol_version != 1
        ):
            raise ValueError("only connector result protocol version 1 is supported")
        _require_identifier("command_id", self.command_id)
        if not isinstance(self.operation, ChengfengOperation):
            raise TypeError("operation must be a ChengfengOperation")
        if not isinstance(self.outcome, ConnectorResultOutcome):
            raise TypeError("outcome must be a ConnectorResultOutcome")
        if not isinstance(self.stage, ChengfengStage):
            raise TypeError("stage must be a ChengfengStage")
        if self.stage is not _EXPECTED_STAGE[self.operation]:
            raise ValueError("stage does not match the read operation")
        if not isinstance(
            self.diagnostic_classification,
            ConnectorDiagnosticClassification,
        ):
            raise TypeError("diagnostic_classification must be a ConnectorDiagnosticClassification")
        if not isinstance(self.payload_references, tuple) or any(
            not isinstance(item, ConnectorPayloadReference) for item in self.payload_references
        ):
            raise TypeError("payload_references must be a tuple of ConnectorPayloadReference")

        if self.outcome is ConnectorResultOutcome.SUCCEEDED:
            if self.diagnostic_classification is not ConnectorDiagnosticClassification.NONE:
                raise ValueError("a successful result cannot contain a failure diagnostic")
            if len(self.payload_references) != 1:
                raise ValueError("a successful result must contain exactly one payload reference")
            expected_kind = _EXPECTED_PAYLOAD_KIND[self.operation]
            if self.payload_references[0].kind is not expected_kind:
                raise ValueError("payload kind does not match the read operation")
        else:
            if self.diagnostic_classification is ConnectorDiagnosticClassification.NONE:
                raise ValueError("a failed result requires a diagnostic classification")
            if self.payload_references:
                raise ValueError("a failed result cannot publish payload references")
            if (
                self.diagnostic_classification
                is ConnectorDiagnosticClassification.IMAGE_TIMEOUT
                and self.operation is not ChengfengOperation.DOWNLOAD_TICKET_IMAGE
            ):
                raise ValueError("image_timeout is valid only for an image download")

    def validate_for(self, command: ConnectorCommand) -> None:
        """Reject a valid result that belongs to a different connector command."""
        if not isinstance(command, ConnectorCommand):
            raise TypeError("command must be a ConnectorCommand")
        mismatches = [
            field_name
            for field_name in ("protocol_version", "command_id", "operation")
            if getattr(self, field_name) != getattr(command, field_name)
        ]
        if mismatches:
            joined = ", ".join(mismatches)
            raise ValueError(f"connector result does not match command fields: {joined}")

    @classmethod
    def from_ndjson(cls, value: str | bytes) -> ConnectorResult:
        payload = _parse_single_ndjson(value, record_name="connector result")
        _require_exact_fields(payload, expected=_RESULT_FIELDS, path="connector_result")

        references_value = payload["payload_references"]
        if not isinstance(references_value, list):
            raise TypeError("payload_references must be a JSON array")
        references = tuple(
            ConnectorPayloadReference.from_payload(reference) for reference in references_value
        )
        return cls(
            protocol_version=_require_integer(
                "protocol_version",
                payload["protocol_version"],
            ),
            command_id=_require_string("command_id", payload["command_id"]),
            operation=_parse_enum(
                ChengfengOperation,
                payload["operation"],
                path="operation",
            ),
            outcome=_parse_enum(
                ConnectorResultOutcome,
                payload["outcome"],
                path="outcome",
            ),
            stage=_parse_enum(ChengfengStage, payload["stage"], path="stage"),
            diagnostic_classification=_parse_enum(
                ConnectorDiagnosticClassification,
                payload["diagnostic_classification"],
                path="diagnostic_classification",
            ),
            payload_references=references,
        )

    def to_ndjson(self) -> str:
        payload = {
            "protocol_version": self.protocol_version,
            "command_id": self.command_id,
            "operation": self.operation.value,
            "outcome": self.outcome.value,
            "stage": self.stage.value,
            "diagnostic_classification": self.diagnostic_classification.value,
            "payload_references": [reference.as_payload() for reference in self.payload_references],
        }
        return (
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            + "\n"
        )
