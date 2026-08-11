from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Literal, Self
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator, model_validator

AllowedOperation = Literal[
    "list_waybills",
    "get_waybill_detail",
    "download_ticket_image",
]
ParameterLocation = Literal["json", "query"]
BodyEncoding = Literal["utf-8", "base64"]
ResponseMediaType = Literal["application/json", "text/html", "image/png"]
FaultResponseName = Literal["login_required", "page_contract_changed"]

EXPECTED_OPERATIONS: tuple[AllowedOperation, ...] = (
    "list_waybills",
    "get_waybill_detail",
    "download_ticket_image",
)
EXPECTED_FAULT_RESPONSES: frozenset[str] = frozenset({"login_required", "page_contract_changed"})
SHA256_PATTERN = r"^[0-9a-f]{64}$"
_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "password",
    "passwd",
    "phone",
    "mobile",
    "token",
    "accesstoken",
    "refreshtoken",
    "signature",
    "sig",
    "accesskey",
    "secret",
}
_SYNTHETIC_ID_KEYS = {
    "platformwaybillid",
    "waybillnumber",
    "vehiclenumber",
    "ticketref",
    "correlationid",
    "scope",
}
_PHONE_PATTERN = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)(?:password|passwd|token|signature|access[_-]?key|secret)"
    r"\s*[=:]\s*[^\s&\"'<>]+"
)
_SENSITIVE_HEADER_PATTERN = re.compile(r"(?i)(?:^|[\r\n; ])(?:cookie|set-cookie|authorization)\s*:")


class ManifestValidationError(ValueError):
    """Raised when a frozen fixture cannot be trusted as declared."""


class FrozenResponse(BaseModel):
    """One immutable response body declared by the frozen contract."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status_code: Literal[200]
    media_type: ResponseMediaType
    body_file: str = Field(min_length=1, max_length=240)
    body_encoding: BodyEncoding
    file_size: int = Field(gt=0)
    file_sha256: str = Field(pattern=SHA256_PATTERN)
    body_size: int | None = Field(default=None, ge=0)
    body_sha256: str | None = Field(default=None, pattern=SHA256_PATTERN)

    @field_validator("body_file")
    @classmethod
    def validate_body_file(cls, value: str) -> str:
        _validate_relative_fixture_path(value)
        return value

    @model_validator(mode="after")
    def validate_body_contract(self) -> Self:
        is_image = self.media_type.startswith("image/")
        if is_image:
            if self.body_encoding != "base64":
                raise ValueError("image fixture bodies must use base64 encoding")
            if self.body_size is None or self.body_sha256 is None:
                raise ValueError("image fixture bodies require decoded size and SHA-256")
        else:
            if self.body_encoding != "utf-8":
                raise ValueError("text fixture bodies must use UTF-8 encoding")
            if self.body_size is not None or self.body_sha256 is not None:
                raise ValueError("decoded body metadata is reserved for image fixtures")
        return self


class FrozenRequest(BaseModel):
    """One exact read request and its frozen response."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation: AllowedOperation
    method: Literal["GET", "POST"]
    path: str = Field(min_length=1, max_length=300)
    parameters_location: ParameterLocation
    parameters: Mapping[str, str | int]
    response: FrozenResponse

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        _validate_canonical_request_path(value)
        return value

    @field_validator("parameters")
    @classmethod
    def validate_parameters(
        cls,
        value: Mapping[str, str | int],
    ) -> Mapping[str, str | int]:
        if not value:
            raise ValueError("frozen request parameters cannot be empty")
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ValueError("frozen request parameter names must be non-empty strings")
            if type(item) not in {str, int}:
                raise ValueError(
                    "frozen request parameter values must be strict strings or integers"
                )
        return MappingProxyType(dict(value))

    @model_validator(mode="after")
    def validate_operation_shape(self) -> Self:
        if self.operation == "download_ticket_image":
            if self.method != "GET" or self.parameters_location != "query":
                raise ValueError("image downloads require the frozen GET query contract")
            if self.response.media_type != "image/png":
                raise ValueError("image downloads require an image response")
        else:
            if self.method != "POST" or self.parameters_location != "json":
                raise ValueError("waybill reads require the frozen POST JSON contract")
            if self.response.media_type != "application/json":
                raise ValueError("waybill reads require a JSON response")
        return self


class FrozenSafetyContract(BaseModel):
    """Safety declarations that cannot be relaxed by a fixture."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    real_platform_capture: Literal[False]
    real_host_or_path_verified: Literal[False]
    credentials_present: Literal[False]
    signed_urls_present: Literal[False]
    production_identifiers_present: Literal[False]
    network_allowed: Literal[False]


class FixtureVerificationReport(BaseModel):
    """Evidence that all manifest-declared files matched their identities."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    verified_files: tuple[str, ...]
    decoded_body_files: tuple[str, ...]
    total_file_bytes: int = Field(ge=0)


class FrozenContractManifest(BaseModel):
    """Strict synthetic contract used by the Loop 5 offline adapter."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1]
    request_contract_version: Literal["loop5.synthetic.v1"]
    fixture_kind: Literal["synthetic_sanitized"]
    origin: str
    allowed_operations: tuple[AllowedOperation, ...]
    requests: tuple[FrozenRequest, ...]
    fault_responses: Mapping[FaultResponseName, FrozenResponse]
    safety: FrozenSafetyContract

    _fixture_root: Path = PrivateAttr()

    @field_validator("fault_responses")
    @classmethod
    def freeze_fault_responses(
        cls,
        value: Mapping[FaultResponseName, FrozenResponse],
    ) -> Mapping[FaultResponseName, FrozenResponse]:
        return MappingProxyType(dict(value))

    @field_validator("origin")
    @classmethod
    def validate_synthetic_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("manifest origin has an invalid port") from exc
        hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or hostname.endswith(".")
            or hostname != hostname.casefold()
            or not hostname.endswith(".invalid")
            or value != f"https://{hostname}"
        ):
            raise ValueError(
                "manifest origin must be one normalized synthetic HTTPS .invalid origin"
            )
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("manifest origin cannot use an IP address")
        return value

    @model_validator(mode="after")
    def validate_manifest_contract(self) -> Self:
        if self.allowed_operations != EXPECTED_OPERATIONS:
            raise ValueError("allowed operations must be the exact Loop 5 read contract")
        if not self.requests:
            raise ValueError("frozen contract must declare read requests")
        if set(self.fault_responses) != EXPECTED_FAULT_RESPONSES:
            raise ValueError("fault responses must match the exact Loop 5 fault contract")

        represented = {request.operation for request in self.requests}
        if represented != set(self.allowed_operations):
            raise ValueError("every allowed operation must have at least one frozen request")

        identities: set[tuple[str, tuple[tuple[str, type, object], ...]]] = set()
        for request in self.requests:
            _verify_synthetic_value(
                request.parameters,
                path=f"request.{request.operation}.parameters",
            )
            identity = (
                request.operation,
                tuple(
                    sorted((key, type(value), value) for key, value in request.parameters.items())
                ),
            )
            if identity in identities:
                raise ValueError("frozen request operation and parameters must be unique")
            identities.add(identity)
        return self

    @property
    def fixture_root(self) -> Path:
        """Return the verified root used to load this manifest."""
        try:
            return self._fixture_root
        except AttributeError as exc:
            raise ManifestValidationError("manifest was not loaded from a fixture root") from exc

    @classmethod
    def load(cls, root: Path) -> FrozenContractManifest:
        """Load, strictly validate, and verify every declared fixture file."""
        resolved_root = root.resolve()
        if not resolved_root.is_dir():
            raise ManifestValidationError("frozen contract root is not a directory")
        manifest_path = resolved_root / "manifest.json"
        if not manifest_path.is_file() or manifest_path.is_symlink():
            raise ManifestValidationError("frozen contract manifest is missing or unsafe")
        try:
            raw_manifest = manifest_path.read_bytes()
        except OSError as exc:
            raise ManifestValidationError("frozen contract manifest cannot be read") from exc
        manifest = cls.model_validate_json(raw_manifest, strict=True)
        object.__setattr__(manifest, "_fixture_root", resolved_root)
        manifest.verify_fixture_files()
        return manifest

    def find_request(
        self,
        operation: str,
        parameters: Mapping[str, object],
    ) -> FrozenRequest | None:
        """Find one request only when keys, values, and value types match exactly."""
        matches = [
            request
            for request in self.requests
            if request.operation == operation
            and _typed_parameters_equal(parameters, request.parameters)
        ]
        if not matches:
            return None
        if len(matches) != 1:
            raise ManifestValidationError("frozen request identity is ambiguous")
        return matches[0]

    def request_for(
        self,
        operation: str,
        parameters: Mapping[str, object],
    ) -> FrozenRequest:
        """Return the exact declared request or reject the lookup."""
        request = self.find_request(operation, parameters)
        if request is None:
            raise LookupError("no exact frozen request matches the operation and parameters")
        return request

    def read_response_body(self, response: FrozenResponse) -> bytes:
        """Read a verified response body, decoding base64 image fixtures."""
        path = _resolve_fixture_file(self.fixture_root, response.body_file)
        raw = path.read_bytes()
        _verify_file_identity(response, raw)
        return _decode_response_body(response, raw)

    def verify_fixture_files(self) -> FixtureVerificationReport:
        """Verify paths, physical files, stored hashes, and decoded image hashes."""
        declarations = [
            *(request.response for request in self.requests),
            *self.fault_responses.values(),
        ]
        by_name: dict[str, FrozenResponse] = {}
        verified_files: list[str] = []
        decoded_body_files: list[str] = []
        total_file_bytes = 0

        for response in declarations:
            existing = by_name.get(response.body_file)
            if existing is not None:
                if existing != response:
                    raise ManifestValidationError(
                        "one fixture file has conflicting response declarations"
                    )
                continue
            by_name[response.body_file] = response
            path = _resolve_fixture_file(self.fixture_root, response.body_file)
            try:
                raw = path.read_bytes()
            except OSError as exc:
                raise ManifestValidationError("declared fixture file cannot be read") from exc
            _verify_file_identity(response, raw)
            decoded = _decode_response_body(response, raw)

            if response.media_type == "application/json":
                try:
                    payload = json.loads(decoded.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ManifestValidationError(
                        "declared JSON fixture is not valid UTF-8 JSON"
                    ) from exc
                if not isinstance(payload, dict):
                    raise ManifestValidationError("declared JSON fixture must contain an object")
                _verify_synthetic_value(
                    payload,
                    path=f"fixture.{response.body_file}",
                )
            elif response.body_encoding == "utf-8":
                try:
                    text_body = decoded.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ManifestValidationError(
                        "declared text fixture is not valid UTF-8"
                    ) from exc
                _verify_sanitized_text(
                    text_body,
                    path=f"fixture.{response.body_file}",
                )

            verified_files.append(response.body_file)
            total_file_bytes += len(raw)
            if response.body_encoding == "base64":
                decoded_body_files.append(response.body_file)

        return FixtureVerificationReport(
            verified_files=tuple(verified_files),
            decoded_body_files=tuple(decoded_body_files),
            total_file_bytes=total_file_bytes,
        )


def _validate_relative_fixture_path(value: str) -> None:
    if "\\" in value or "\x00" in value or "%" in value or ":" in value:
        raise ValueError("fixture body path must be a canonical relative POSIX path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or value != path.as_posix()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("fixture body path must be a canonical relative POSIX path")


def _validate_canonical_request_path(value: str) -> None:
    if (
        not value.startswith("/")
        or value == "/"
        or value.endswith("/")
        or "\\" in value
        or "%" in value
        or "?" in value
        or "#" in value
        or "\x00" in value
        or "//" in value
        or any(segment in {".", ".."} for segment in value.split("/"))
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError("request path must be canonical and unencoded")


def _resolve_fixture_file(root: Path, body_file: str) -> Path:
    _validate_relative_fixture_path(body_file)
    candidate = (root / Path(*PurePosixPath(body_file).parts)).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file() or candidate.is_symlink():
        raise ManifestValidationError("declared fixture path escapes its verified root")
    return candidate


def _verify_file_identity(response: FrozenResponse, raw: bytes) -> None:
    if len(raw) != response.file_size:
        raise ManifestValidationError("declared fixture file size does not match")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != response.file_sha256:
        raise ManifestValidationError("declared fixture file SHA-256 hash does not match")


def _decode_response_body(response: FrozenResponse, raw: bytes) -> bytes:
    if response.body_encoding == "utf-8":
        try:
            raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ManifestValidationError("declared fixture body is not valid UTF-8") from exc
        return raw

    try:
        encoded = b"".join(raw.split())
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ManifestValidationError("declared image fixture is not valid base64") from exc
    if response.body_size is None or len(decoded) != response.body_size:
        raise ManifestValidationError("decoded image body size does not match")
    if response.body_sha256 is None:
        raise ManifestValidationError("decoded image body SHA-256 is missing")
    if hashlib.sha256(decoded).hexdigest() != response.body_sha256:
        raise ManifestValidationError("decoded image body SHA-256 hash does not match")
    return decoded


def _typed_parameters_equal(
    left: Mapping[str, object],
    right: Mapping[str, object],
) -> bool:
    if set(left) != set(right):
        return False
    return all(type(left[key]) is type(right[key]) and left[key] == right[key] for key in left)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.casefold())


def _verify_sanitized_text(value: str, *, path: str) -> None:
    if (
        _PHONE_PATTERN.search(value) is not None
        or _SECRET_ASSIGNMENT_PATTERN.search(value) is not None
        or _SENSITIVE_HEADER_PATTERN.search(value) is not None
    ):
        raise ManifestValidationError(f"sanitized fixture contains sensitive content at {path}")


def _verify_synthetic_value(value: object, *, path: str) -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if not isinstance(key, str) or not key:
                raise ManifestValidationError(f"fixture contains an invalid key at {path}")
            normalized = _normalized_key(key)
            if normalized in _SENSITIVE_KEYS:
                raise ManifestValidationError(
                    f"sanitized fixture contains a sensitive field at {path}"
                )
            if normalized in _SYNTHETIC_ID_KEYS and isinstance(child, str):
                marker = child.casefold()
                if "synthetic" not in marker and not marker.startswith("syn-"):
                    raise ManifestValidationError(
                        f"synthetic fixture contains a production-like identifier at {path}.{key}"
                    )
            _verify_synthetic_value(child, path=f"{path}.{key}")
        return
    if isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _verify_synthetic_value(child, path=f"{path}[{index}]")
        return
    if isinstance(value, str):
        _verify_sanitized_text(value, path=path)
        return
    if value is None or type(value) in {bool, int, float}:
        return
    raise ManifestValidationError(f"fixture contains an unsupported value at {path}")
