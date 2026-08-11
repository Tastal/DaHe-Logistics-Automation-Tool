from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import Literal, Self
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from dahe.adapters.chengfeng.policy import ReadRequest, RequestDeniedError

EXPECTED_OPERATIONS = (
    "list_waybills",
    "get_waybill_detail",
    "download_ticket_image",
)
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
FIELD_PATH_PATTERN = re.compile(
    r"^\$(?:\[\])?(?:\.[^\x00-\x1f\x7f.]{1,120}(?:\[\])?)*$"
)


class LiveContractError(RuntimeError):
    """Raised when a Loop 9 live contract cannot be trusted."""


class LiveParameterRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["string", "integer", "empty_list"]
    constant: str | int | None = None
    minimum: int | None = Field(default=None, ge=0)
    maximum: int | None = Field(default=None, ge=1)
    allow_empty: bool = False

    @model_validator(mode="after")
    def validate_rule(self) -> Self:
        if self.constant is not None:
            expected = str if self.type == "string" else int
            if type(self.constant) is not expected:
                raise ValueError("parameter constant does not match its declared type")
        if (self.minimum is not None or self.maximum is not None) and self.type != "integer":
            raise ValueError("parameter bounds are valid only for integers")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("parameter minimum cannot exceed its maximum")
        if self.allow_empty and self.type != "string":
            raise ValueError("allow_empty is valid only for strings")
        if self.type == "empty_list" and self.constant is not None:
            raise ValueError("empty-list parameters cannot declare a constant")
        return self


class LiveResponseField(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str
    types: tuple[
        Literal[
            "null",
            "boolean",
            "integer",
            "number",
            "string",
            "empty_array",
        ],
        ...,
    ]

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not FIELD_PATH_PATTERN.fullmatch(value):
            raise ValueError("response field path is invalid")
        return value

    @field_validator("types")
    @classmethod
    def validate_types(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if not values or values != tuple(sorted(set(values))):
            raise ValueError("response field types must be sorted, non-empty, and unique")
        return values


class LiveReadDeclaration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    operation: Literal[
        "list_waybills",
        "get_waybill_detail",
        "download_ticket_image",
    ]
    method: Literal["GET", "POST"]
    path: str = Field(min_length=2, max_length=300)
    parameters_location: Literal["form", "json", "query"]
    parameters: Mapping[str, LiveParameterRule]
    response_fields: tuple[LiveResponseField, ...]

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if (
            not value.startswith("/")
            or value.endswith("/")
            or "\\" in value
            or "%" in value
            or "?" in value
            or "#" in value
            or "\x00" in value
            or "//" in value
            or any(part in {"", ".", ".."} for part in value.split("/")[1:])
            or any(ord(character) < 32 or ord(character) == 127 for character in value)
        ):
            raise ValueError("request path must be canonical and unencoded")
        return value

    @field_validator("parameters")
    @classmethod
    def freeze_parameters(
        cls,
        value: Mapping[str, LiveParameterRule],
    ) -> Mapping[str, LiveParameterRule]:
        if not value or any(not isinstance(key, str) or not key for key in value):
            raise ValueError("request parameters must have non-empty string keys")
        return MappingProxyType(dict(value))

    @model_validator(mode="after")
    def validate_operation_shape(self) -> Self:
        if self.operation == "download_ticket_image":
            if self.method != "GET" or self.parameters_location != "query":
                raise ValueError("ticket image reads require GET query parameters")
            if self.response_fields:
                raise ValueError("response-derived image reads cannot declare JSON fields")
        elif self.operation == "list_waybills":
            if self.method != "POST" or self.parameters_location != "json":
                raise ValueError("waybill lists require POST JSON parameters")
            if not self.response_fields:
                raise ValueError("waybill reads require response field guards")
        else:
            # JSON is retained only so historical frozen evidence remains
            # replayable. Newly frozen detail contracts use form encoding and
            # the live request builder refuses the historical JSON variant.
            if (
                self.method != "POST"
                or self.parameters_location not in {"form", "json"}
            ):
                raise ValueError(
                    "waybill details require POST form parameters"
                )
            if not self.response_fields:
                raise ValueError("waybill reads require response field guards")
        return self


class LiveReadContractManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1]
    contract_kind: Literal["loop9_read_only"]
    run_mode: Literal["shadow"]
    origin: str
    image_origins: tuple[str, ...]
    source_discovery_sha256: str
    source_observation_count: int = Field(ge=1, le=200)
    requests: tuple[LiveReadDeclaration, ...]

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        try:
            parsed = urlsplit(value)
            port = parsed.port
        except ValueError as exc:
            raise ValueError("contract origin is invalid") from exc
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
            or value != f"https://{hostname}"
        ):
            raise ValueError("contract origin must be one normalized HTTPS origin")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            return value
        raise ValueError("contract origin cannot use an IP address")

    @field_validator("image_origins")
    @classmethod
    def validate_image_origins(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(_normalized_https_origin(value) for value in values)
        if not normalized or normalized != tuple(sorted(set(normalized))):
            raise ValueError("image origins must be sorted, non-empty, and unique")
        return normalized

    @field_validator("source_discovery_sha256")
    @classmethod
    def validate_source_discovery_sha256(cls, value: str) -> str:
        if not SHA256_PATTERN.fullmatch(value):
            raise ValueError("source discovery SHA-256 is invalid")
        return value

    @model_validator(mode="after")
    def validate_complete_surface(self) -> Self:
        operations = tuple(request.operation for request in self.requests)
        if operations != EXPECTED_OPERATIONS:
            raise ValueError("contract must declare the exact ordered read surface")
        if len({request.path for request in self.requests}) != len(self.requests):
            raise ValueError("contract request paths must be unique")
        return self

    @property
    def canonical_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "contract_kind": self.contract_kind,
            "run_mode": self.run_mode,
            "origin": self.origin,
            "image_origins": list(self.image_origins),
            "source_discovery_sha256": self.source_discovery_sha256,
            "source_observation_count": self.source_observation_count,
            "requests": [
                {
                    "operation": request.operation,
                    "method": request.method,
                    "path": request.path,
                    "parameters_location": request.parameters_location,
                    "parameters": {
                        key: rule.model_dump(mode="json")
                        for key, rule in request.parameters.items()
                    },
                    "response_fields": [
                        field.model_dump(mode="json")
                        for field in request.response_fields
                    ],
                }
                for request in self.requests
            ],
        }

    @property
    def canonical_sha256(self) -> str:
        payload = json.dumps(
            self.canonical_document,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    @staticmethod
    def file_sha256(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        allowed_root: Path,
        expected_sha256: str,
    ) -> LiveReadContractManifest:
        if not path.is_absolute() or not allowed_root.is_absolute():
            raise LiveContractError("contract and allowed root paths must be absolute")
        if not SHA256_PATTERN.fullmatch(expected_sha256):
            raise LiveContractError("expected contract SHA-256 is invalid")
        resolved_root = allowed_root.resolve()
        resolved_path = path.resolve()
        if (
            resolved_root not in resolved_path.parents
            or not resolved_path.is_file()
            or resolved_path.is_symlink()
        ):
            raise LiveContractError("contract path is outside its allowed root or unsafe")
        try:
            raw = resolved_path.read_bytes()
        except OSError as exc:
            raise LiveContractError("contract cannot be read") from exc
        if hashlib.sha256(raw).hexdigest() != expected_sha256:
            raise LiveContractError("contract SHA-256 does not match")
        try:
            return cls.model_validate_json(raw, strict=True)
        except ValueError as exc:
            raise LiveContractError("contract schema is invalid") from exc


class LiveAuthorizedRequest:
    __slots__ = ("declaration", "request")

    def __init__(
        self,
        request: ReadRequest,
        declaration: LiveReadDeclaration,
    ) -> None:
        self.request = request
        self.declaration = declaration

    @property
    def operation(self) -> str:
        return self.request.operation


@dataclass(frozen=True, slots=True)
class ImageReadCapability:
    """A short-lived proof for one exact response-derived image URL."""

    url_sha256: str
    source_request_sha256: str
    validated_response_sha256: str
    issued_at: datetime
    expires_at: datetime
    _origin: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class LiveAuthorizedImageRequest:
    """An authorized image read without a printable signed URL."""

    request: ReadRequest = field(repr=False)
    url_sha256: str

    @property
    def operation(self) -> str:
        return self.request.operation


class ImageReadCapabilityPolicy:
    """Authorize one exact dynamic image URL derived from a validated detail."""

    def __init__(
        self,
        *,
        allowed_origins: tuple[str, ...],
        maximum_lifetime: timedelta,
    ) -> None:
        if not allowed_origins or len(set(allowed_origins)) != len(allowed_origins):
            raise ValueError("image origins must be non-empty and unique")
        self._allowed_origins = frozenset(
            _normalized_https_origin(origin) for origin in allowed_origins
        )
        if maximum_lifetime <= timedelta(0) or maximum_lifetime > timedelta(minutes=10):
            raise ValueError("image capability maximum lifetime must be at most ten minutes")
        self._maximum_lifetime = maximum_lifetime

    def issue(
        self,
        *,
        source_request: LiveAuthorizedRequest,
        image_url: str,
        validated_response_sha256: str,
        issued_at: datetime,
        lifetime: timedelta,
    ) -> ImageReadCapability:
        if source_request.operation != "get_waybill_detail":
            raise _denied()
        if not SHA256_PATTERN.fullmatch(validated_response_sha256):
            raise _denied()
        issued = _aware_utc(issued_at)
        if lifetime <= timedelta(0) or lifetime > self._maximum_lifetime:
            raise _denied()
        origin = _image_url_origin(image_url)
        if origin not in self._allowed_origins:
            raise _denied()
        return ImageReadCapability(
            url_sha256=_sha256_text(image_url),
            source_request_sha256=_request_sha256(source_request.request),
            validated_response_sha256=validated_response_sha256,
            issued_at=issued,
            expires_at=issued + lifetime,
            _origin=origin,
        )

    def authorize(
        self,
        *,
        capability: ImageReadCapability,
        request: ReadRequest,
        now: datetime,
    ) -> LiveAuthorizedImageRequest:
        authorization_time = _aware_utc(now)
        if (
            authorization_time < capability.issued_at
            or authorization_time >= capability.expires_at
            or request.operation != "download_ticket_image"
            or request.method != "GET"
            or request.parameters_location != "query"
            or dict(request.parameters)
            or _sha256_text(request.url) != capability.url_sha256
            or _image_url_origin(request.url) != capability._origin
            or capability._origin not in self._allowed_origins
        ):
            raise _denied()
        return LiveAuthorizedImageRequest(
            request=ReadRequest(
                operation=request.operation,
                method=request.method,
                url=request.url,
                parameters_location=request.parameters_location,
                parameters=MappingProxyType({}),
            ),
            url_sha256=capability.url_sha256,
        )

    def authorize_redirect(
        self,
        capability: ImageReadCapability,
        *,
        location: str,
    ) -> LiveAuthorizedImageRequest:
        del capability, location
        raise _denied()


class LiveReadOnlyRequestFirewall:
    def __init__(self, manifest: LiveReadContractManifest) -> None:
        self._manifest = manifest

    def authorize(self, request: ReadRequest) -> LiveAuthorizedRequest:
        if request.operation == "download_ticket_image":
            # Signed image URLs must be authorized by ImageReadCapabilityPolicy
            # after they are obtained from a validated detail response.
            raise _denied()
        declaration = next(
            (
                item
                for item in self._manifest.requests
                if item.operation == request.operation
            ),
            None,
        )
        if declaration is None:
            raise _denied()
        parsed = urlsplit(request.url)
        if (
            request.method != declaration.method
            or request.parameters_location != declaration.parameters_location
            or request.url != f"{self._manifest.origin}{declaration.path}"
            or parsed.query
            or parsed.fragment
            or set(request.parameters) != set(declaration.parameters)
        ):
            raise _denied()
        for key, rule in declaration.parameters.items():
            value = request.parameters[key]
            if rule.type == "empty_list":
                if type(value) is not list or value:
                    raise _denied()
                continue
            expected = str if rule.type == "string" else int
            if type(value) is not expected:
                raise _denied()
            if rule.constant is not None and value != rule.constant:
                raise _denied()
            if rule.minimum is not None and isinstance(value, int) and value < rule.minimum:
                raise _denied()
            if rule.maximum is not None and isinstance(value, int) and value > rule.maximum:
                raise _denied()
            if isinstance(value, str):
                if not value and not rule.allow_empty and rule.constant != "":
                    raise _denied()
                if (
                    value != value.strip()
                    or "://" in value
                    or "?" in value
                    or "#" in value
                ):
                    raise _denied()
        canonical = ReadRequest(
            operation=request.operation,
            method=request.method,
            url=request.url,
            parameters_location=request.parameters_location,
            parameters=MappingProxyType(
                {
                    key: tuple(value) if type(value) is list else value
                    for key, value in request.parameters.items()
                }
            ),
        )
        return LiveAuthorizedRequest(canonical, declaration)

    def authorize_redirect(
        self,
        request: ReadRequest | LiveAuthorizedRequest,
        *,
        location: str,
    ) -> LiveAuthorizedRequest:
        del request, location
        raise _denied()


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise _denied()
    return value.astimezone(UTC)


def _sha256_text(value: object) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise _denied()
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _request_sha256(request: ReadRequest) -> str:
    parameters = dict(request.parameters)
    if any(
        type(key) is not str or type(value) not in {str, int}
        for key, value in parameters.items()
    ):
        raise _denied()
    payload = json.dumps(
        {
            "operation": request.operation,
            "method": request.method,
            "url": request.url,
            "parameters_location": request.parameters_location,
            "parameters": parameters,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _normalized_https_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("image origin is invalid") from exc
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
        or value != f"https://{hostname}"
    ):
        raise ValueError("image origin must be one normalized HTTPS origin")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return value
    raise ValueError("image origin cannot use an IP address")


def _image_url_origin(value: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise _denied()
    if "\\" in value or "\x00" in value:
        raise _denied()
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise _denied() from exc
    hostname = parsed.hostname
    decoded_path = unquote(parsed.path)
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.fragment
        or not parsed.path.startswith("/")
        or parsed.path.endswith("/")
        or hostname.endswith(".")
        or hostname != hostname.casefold()
        or any(segment in {"", ".", ".."} for segment in decoded_path.split("/")[1:])
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _denied()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return f"https://{hostname}"
    raise _denied()


def _denied() -> RequestDeniedError:
    return RequestDeniedError("request denied by the Loop 9 read-only contract")
