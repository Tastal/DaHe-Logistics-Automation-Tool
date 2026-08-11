from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import ClassVar

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class ApplicationBuildManifestError(ValueError):
    """Raised when application-build evidence is incomplete or non-canonical."""


@dataclass(frozen=True, slots=True)
class ApplicationBuildSource:
    path: str
    sha256: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.path, str)
            or not self.path
            or len(self.path) > 256
            or "\\" in self.path
            or ":" in self.path
        ):
            raise ApplicationBuildManifestError("application build source path is invalid")
        parsed = PurePosixPath(self.path)
        if (
            parsed.is_absolute()
            or parsed.as_posix() != self.path
            or any(part in {"", ".", ".."} for part in parsed.parts)
        ):
            raise ApplicationBuildManifestError("application build source path is unsafe")
        if (
            not isinstance(self.sha256, str)
            or SHA256_PATTERN.fullmatch(self.sha256) is None
        ):
            raise ApplicationBuildManifestError(
                "application build source fingerprint is invalid"
            )

    def to_payload(self) -> dict[str, str]:
        return {
            "path": self.path,
            "sha256": self.sha256,
        }

    @classmethod
    def from_payload(cls, payload: object) -> ApplicationBuildSource:
        if not isinstance(payload, Mapping) or set(payload) != {"path", "sha256"}:
            raise ApplicationBuildManifestError(
                "application build source evidence is invalid"
            )
        path = payload.get("path")
        sha256 = payload.get("sha256")
        if not isinstance(path, str) or not isinstance(sha256, str):
            raise ApplicationBuildManifestError(
                "application build source evidence is invalid"
            )
        return cls(path=path, sha256=sha256)


@dataclass(frozen=True, slots=True)
class ApplicationBuildManifest:
    SCHEMA_VERSION: ClassVar[int] = 1
    MAX_SOURCES: ClassVar[int] = 256

    application_version: str
    sources: tuple[ApplicationBuildSource, ...]

    def __post_init__(self) -> None:
        if (
            not isinstance(self.application_version, str)
            or not self.application_version
            or self.application_version != self.application_version.strip()
            or len(self.application_version) > 128
            or any(ord(character) < 32 for character in self.application_version)
        ):
            raise ApplicationBuildManifestError("application build version is invalid")
        if (
            not isinstance(self.sources, tuple)
            or not self.sources
            or len(self.sources) > self.MAX_SOURCES
            or any(not isinstance(source, ApplicationBuildSource) for source in self.sources)
        ):
            raise ApplicationBuildManifestError("application build sources are invalid")
        paths = tuple(source.path for source in self.sources)
        if len(set(paths)) != len(paths) or paths != tuple(sorted(paths)):
            raise ApplicationBuildManifestError(
                "application build sources must be unique and sorted"
            )

    def to_payload(self) -> dict[str, object]:
        return {
            "application_version": self.application_version,
            "schema_version": self.SCHEMA_VERSION,
            "sources": [source.to_payload() for source in self.sources],
        }

    @property
    def canonical_sha256(self) -> str:
        encoded = json.dumps(
            self.to_payload(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def from_payload(cls, payload: object) -> ApplicationBuildManifest:
        expected_fields = {
            "application_version",
            "schema_version",
            "sources",
        }
        if not isinstance(payload, Mapping) or set(payload) != expected_fields:
            raise ApplicationBuildManifestError(
                "application build manifest fields are invalid"
            )
        schema_version = payload.get("schema_version")
        if (
            not isinstance(schema_version, int)
            or isinstance(schema_version, bool)
            or schema_version != cls.SCHEMA_VERSION
        ):
            raise ApplicationBuildManifestError(
                "application build manifest version is unsupported"
            )
        application_version = payload.get("application_version")
        raw_sources = payload.get("sources")
        if not isinstance(application_version, str) or not isinstance(raw_sources, list):
            raise ApplicationBuildManifestError(
                "application build manifest payload is invalid"
            )
        return cls(
            application_version=application_version,
            sources=tuple(
                ApplicationBuildSource.from_payload(source)
                for source in raw_sources
            ),
        )
