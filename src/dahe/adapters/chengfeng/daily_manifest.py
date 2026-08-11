from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Literal, Self

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

DAILY_ORIGIN: Literal["https://pc.chengfengkuaiyun.com"] = (
    "https://pc.chengfengkuaiyun.com"
)
DAILY_LIST_PATH: Literal["/api/hz/orderItem/queryOrderItemListPC"] = (
    "/api/hz/orderItem/queryOrderItemListPC"
)
DAILY_LIST_OPERATION: Literal["list_daily_waybills"] = "list_daily_waybills"

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_REQUEST_FIELD_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,79}$")
_RESPONSE_FIELD_PATTERN = re.compile(
    r"^\$(?:\[\])?(?:\.[A-Za-z][A-Za-z0-9]{0,79}(?:\[\])?)*$"
)
_SENSITIVE_FIELD_PATTERN = re.compile(
    r"(?i)(?:authorization|cookie|password|secret|signature|token)"
)
_CONTROLLED_FIELDS = {
    "loadStartTime",
    "loadEndTime",
    "receivePlace",
    "pageNumber",
    "pageSize",
}
_REQUIRED_RESPONSE_FIELDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        "$.data.list[].id": frozenset({"integer", "string"}),
        "$.data.list[].sn": frozenset({"string"}),
        "$.data.list[].carNumber": frozenset({"null", "string"}),
        "$.data.list[].loadPunchDate": frozenset({"null", "string"}),
        "$.data.total": frozenset({"integer"}),
    }
)


class DailyParameterRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    type: Literal["string", "integer", "empty_array", "null"]
    minimum: int | None = Field(default=None, ge=0)
    maximum: int | None = Field(default=None, ge=1)

    @model_validator(mode="after")
    def validate_bounds(self) -> Self:
        if self.type != "integer" and (
            self.minimum is not None or self.maximum is not None
        ):
            raise ValueError("only integer fields may declare bounds")
        if (
            self.minimum is not None
            and self.maximum is not None
            and self.minimum > self.maximum
        ):
            raise ValueError("field minimum cannot exceed its maximum")
        return self


class DailyResponseField(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: str
    types: tuple[
        Literal["null", "boolean", "integer", "number", "string", "empty_array"],
        ...,
    ]

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if (
            not _RESPONSE_FIELD_PATTERN.fullmatch(value)
            or _SENSITIVE_FIELD_PATTERN.search(value)
        ):
            raise ValueError("response field path is unsafe")
        return value

    @field_validator("types")
    @classmethod
    def validate_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or value != tuple(sorted(set(value))):
            raise ValueError("response field types must be sorted and unique")
        return value


class DailyReadContractManifest(BaseModel):
    """One exact read-only Chengfeng daily-list surface."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1]
    contract_kind: Literal["loop9_daily_read_only"]
    run_mode: Literal["shadow"]
    origin: Literal["https://pc.chengfengkuaiyun.com"]
    method: Literal["POST"]
    path: Literal["/api/hz/orderItem/queryOrderItemListPC"]
    parameters_location: Literal["json"]
    source_discovery_sha256: str
    source_observation_count: int = Field(ge=1, le=200)
    request_fields: Mapping[str, DailyParameterRule]
    response_fields: tuple[DailyResponseField, ...]

    @property
    def operation(self) -> str:
        return DAILY_LIST_OPERATION

    @field_validator("source_discovery_sha256")
    @classmethod
    def validate_source_sha256(cls, value: str) -> str:
        if not _SHA256_PATTERN.fullmatch(value):
            raise ValueError("source discovery SHA-256 is invalid")
        return value

    @field_validator("request_fields")
    @classmethod
    def validate_and_freeze_request_fields(
        cls,
        value: Mapping[str, DailyParameterRule],
    ) -> Mapping[str, DailyParameterRule]:
        if not value:
            raise ValueError("request field contract cannot be empty")
        frozen: dict[str, DailyParameterRule] = {}
        for name, rule in value.items():
            if (
                type(name) is not str
                or not _REQUEST_FIELD_PATTERN.fullmatch(name)
                or _SENSITIVE_FIELD_PATTERN.search(name)
            ):
                raise ValueError("request field name is unsafe")
            if name not in _CONTROLLED_FIELDS and rule.type == "integer":
                raise ValueError("baseline request fields must have safe empty types")
            frozen[name] = rule
        return MappingProxyType(dict(sorted(frozen.items())))

    @model_validator(mode="after")
    def validate_complete_shape(self) -> Self:
        if not _CONTROLLED_FIELDS.issubset(self.request_fields):
            raise ValueError("controlled request fields are incomplete")
        for name in ("loadStartTime", "loadEndTime", "receivePlace"):
            if self.request_fields[name].type != "string":
                raise ValueError("daily business fields must be strings")
        page_number = self.request_fields["pageNumber"]
        if (
            page_number.type != "integer"
            or page_number.minimum != 1
            or page_number.maximum != 10_000
        ):
            raise ValueError("pageNumber must be bounded from 1 to 10000")
        page_size = self.request_fields["pageSize"]
        if (
            page_size.type != "integer"
            or page_size.minimum != 1
            or page_size.maximum != 100
        ):
            raise ValueError("pageSize must be bounded from 1 to 100")

        if tuple(field.path for field in self.response_fields) != tuple(
            sorted(field.path for field in self.response_fields)
        ):
            raise ValueError("response fields must be sorted by path")
        if len({field.path for field in self.response_fields}) != len(
            self.response_fields
        ):
            raise ValueError("response field paths must be unique")
        observed = {field.path: frozenset(field.types) for field in self.response_fields}
        for path, allowed_types in _REQUIRED_RESPONSE_FIELDS.items():
            types = observed.get(path)
            if types is None or not types.issubset(allowed_types):
                raise ValueError("required response field shape is missing or unsafe")
        return self

    @property
    def canonical_document(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "contract_kind": self.contract_kind,
            "run_mode": self.run_mode,
            "origin": self.origin,
            "method": self.method,
            "path": self.path,
            "parameters_location": self.parameters_location,
            "source_discovery_sha256": self.source_discovery_sha256,
            "source_observation_count": self.source_observation_count,
            "request_fields": {
                name: rule.model_dump(mode="json", exclude_none=True)
                for name, rule in self.request_fields.items()
            },
            "response_fields": [
                field.model_dump(mode="json") for field in self.response_fields
            ],
        }

    @property
    def canonical_sha256(self) -> str:
        return hashlib.sha256(_canonical_bytes(self.canonical_document)).hexdigest()


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
