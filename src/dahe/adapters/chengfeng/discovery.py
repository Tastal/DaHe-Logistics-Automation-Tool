from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PATH = re.compile(r"^/[^\x00-\x1f\x7f?#]{0,500}$")
_SAFE_FIELD_PATH = re.compile(r"^\$(?:\[\])?(?:\.[^\x00-\x1f\x7f.]{1,120}(?:\[\])?)*$")
_SAFE_QUERY_KEY = re.compile(r"^[^\x00-\x1f\x7f=&?#]{1,120}$")
_SENSITIVE_FIELD = re.compile(
    r"(?i)(?:password|passwd|cookie|authorization|token|secret|signature|accesskey)"
)


class DiscoveryEvidenceError(RuntimeError):
    """Raised when captured discovery data is unsafe or cannot be sealed."""


class FieldShape(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    path: str
    type: Literal[
        "null",
        "boolean",
        "integer",
        "number",
        "string",
        "unknown",
        "empty_array",
    ]

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        if not _SAFE_FIELD_PATH.fullmatch(value) or _SENSITIVE_FIELD.search(value):
            raise ValueError("field path is unsafe")
        return value


class DiscoveryObservation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    method: Literal["GET", "POST"]
    origin: str
    path: str | None
    path_sha256: str | None
    query_keys: tuple[str, ...] = Field(max_length=100)
    request_fields: tuple[FieldShape, ...] = Field(max_length=500)
    resource_kind: Literal["json_api", "image"]
    response_status: int | None = Field(default=None, ge=100, le=599)
    content_kind: Literal["json", "image", "other"] | None
    response_fields: tuple[FieldShape, ...] = Field(max_length=500)

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is not None
            or parsed.path
            or parsed.query
            or parsed.fragment
            or value != f"https://{parsed.hostname.casefold()}"
        ):
            raise ValueError("origin is not a normalized HTTPS origin")
        return value

    @field_validator("query_keys")
    @classmethod
    def validate_query_keys(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(values))) != values:
            raise ValueError("query keys must be sorted and unique")
        if any(not _SAFE_QUERY_KEY.fullmatch(value) for value in values):
            raise ValueError("query key is unsafe")
        return values

    @model_validator(mode="after")
    def validate_resource_identity(self) -> DiscoveryObservation:
        if self.resource_kind == "image":
            if self.path is not None or self.path_sha256 is None:
                raise ValueError("image paths must be represented only by a hash")
            if not _SHA256.fullmatch(self.path_sha256):
                raise ValueError("image path hash is invalid")
            if self.request_fields or self.response_fields:
                raise ValueError("image observations cannot contain JSON fields")
        else:
            if (
                self.path is None
                or not _SAFE_PATH.fullmatch(self.path)
                or self.path_sha256 is not None
            ):
                raise ValueError("JSON API path identity is invalid")
        return self


@dataclass(frozen=True, slots=True)
class DiscoveryEvidenceResult:
    evidence_id: str
    path: Path
    canonical_sha256: str
    observation_count: int


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class DiscoveryEvidenceStore:
    """Seal development-only request shapes without retaining platform values."""

    def __init__(self, data_root: Path) -> None:
        root = data_root.resolve()
        if not root.is_absolute() or data_root.is_symlink():
            raise DiscoveryEvidenceError("data root must be an absolute regular directory")
        self._root = root / "platform-contract-discovery"

    def seal(
        self,
        *,
        observations: list[dict[str, object]],
        build_sha256: str,
        access_window_id: str,
        captured_at: datetime,
    ) -> DiscoveryEvidenceResult:
        if not _SHA256.fullmatch(build_sha256):
            raise DiscoveryEvidenceError("build identity is invalid")
        if (
            not access_window_id
            or len(access_window_id) > 32
            or any(ord(character) < 33 or ord(character) > 126 for character in access_window_id)
        ):
            raise DiscoveryEvidenceError("access window identity is invalid")
        if captured_at.tzinfo is None or captured_at.utcoffset() is None:
            raise DiscoveryEvidenceError("capture time must include a timezone")
        try:
            validated = tuple(
                DiscoveryObservation.model_validate(observation)
                for observation in observations
            )
        except ValidationError as exc:
            raise DiscoveryEvidenceError("discovery observation is unsafe") from exc
        canonical_observations = sorted(
            (
                item.model_dump(mode="json")
                for item in validated
            ),
            key=lambda item: _canonical_bytes(item),
        )
        body: dict[str, object] = {
            "schema_version": 1,
            "kind": "chengfeng_contract_discovery",
            "classification": "development_only",
            "status": "captured" if canonical_observations else "insufficient",
            "build_sha256": build_sha256,
            "access_window_id": access_window_id,
            "captured_at": captured_at.astimezone(UTC).isoformat(),
            "observation_count": len(canonical_observations),
            "observations": canonical_observations,
            "excluded_data": [
                "credential_material",
                "request_header_values",
                "response_header_values",
                "session_material",
                "request_values",
                "response_values",
                "signed_image_paths",
                "raw_responses",
            ],
        }
        canonical_sha256 = hashlib.sha256(_canonical_bytes(body)).hexdigest()
        document = {**body, "canonical_sha256": canonical_sha256}
        self._root.mkdir(parents=True, exist_ok=True)
        if self._root.is_symlink():
            raise DiscoveryEvidenceError("discovery evidence root cannot be a symbolic link")
        path = self._root / f"{canonical_sha256}.json"
        if path.exists():
            if path.is_symlink() or path.read_bytes() != _canonical_bytes(document) + b"\n":
                raise DiscoveryEvidenceError("existing discovery evidence does not match")
            return DiscoveryEvidenceResult(
                evidence_id=canonical_sha256,
                path=path,
                canonical_sha256=canonical_sha256,
                observation_count=len(canonical_observations),
            )
        temporary = self._root / f".{canonical_sha256}.{uuid4().hex}.tmp"
        try:
            with temporary.open("x", encoding="utf-8", newline="\n") as handle:
                handle.write((_canonical_bytes(document) + b"\n").decode("utf-8"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except OSError as exc:
            raise DiscoveryEvidenceError("discovery evidence could not be sealed") from exc
        finally:
            temporary.unlink(missing_ok=True)
        return DiscoveryEvidenceResult(
            evidence_id=canonical_sha256,
            path=path,
            canonical_sha256=canonical_sha256,
            observation_count=len(canonical_observations),
        )

    def existing_for_access_window(
        self,
        access_window_id: str,
    ) -> DiscoveryEvidenceResult | None:
        if not self._root.is_dir():
            return None
        matches: list[DiscoveryEvidenceResult] = []
        for path in self._root.glob("*.json"):
            if path.is_symlink() or not path.is_file():
                raise DiscoveryEvidenceError("discovery evidence contains an unsafe file")
            try:
                document = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise DiscoveryEvidenceError("discovery evidence is unreadable") from exc
            if (
                not isinstance(document, dict)
                or document.get("access_window_id") != access_window_id
            ):
                continue
            declared = document.get("canonical_sha256")
            body = {key: value for key, value in document.items() if key != "canonical_sha256"}
            if (
                not isinstance(declared, str)
                or declared != hashlib.sha256(_canonical_bytes(body)).hexdigest()
                or path.name != f"{declared}.json"
            ):
                raise DiscoveryEvidenceError("discovery evidence integrity check failed")
            observation_count = document.get("observation_count")
            if not isinstance(observation_count, int) or observation_count < 0:
                raise DiscoveryEvidenceError("discovery evidence count is invalid")
            matches.append(
                DiscoveryEvidenceResult(
                    evidence_id=declared,
                    path=path,
                    canonical_sha256=declared,
                    observation_count=observation_count,
                )
            )
        if len(matches) > 1:
            raise DiscoveryEvidenceError("access window has multiple discovery results")
        return matches[0] if matches else None
