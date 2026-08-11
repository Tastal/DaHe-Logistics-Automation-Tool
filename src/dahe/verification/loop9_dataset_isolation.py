from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import combinations
from pathlib import Path
from typing import cast

from dahe.application.chengfeng.shadow_batch import (
    chengfeng_shadow_identity_digest,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
    find_near_duplicate_candidates,
)

SCHEMA_VERSION = 1
DATASET_MANIFEST_SCHEMA_VERSION = 2
EXCLUSION_INVENTORY_SCHEMA_VERSION = 2
EXCLUSION_SOURCE_BOUNDARY_SCHEMA_VERSION = 1
EXCLUSION_CHILD_INDEX_NODE_SCHEMA_VERSION = 1
FULL_HISTORY_EXCLUSION_AUTHORITY_SCHEMA_VERSION = 2
ISOLATION_EVIDENCE_SCHEMA_VERSION = 3
_MAX_JSON_BYTES = 10 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class Loop9DatasetIsolationError(ValueError):
    """Raised when Loop 9 dataset independence cannot be proven."""


class DatasetKind(StrEnum):
    DISCOVERY_DEVELOPMENT = "discovery_development"
    CURRENT_LOCKED_50 = "current_locked_50"
    REAL_SHADOW_30 = "real_shadow_30"
    DAILY_VALIDATION = "daily_validation"


class ExclusionKind(StrEnum):
    DEVELOPMENT = "development"
    LEGACY_LOOP7 = "legacy_loop7"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_text(
    value: object,
    *,
    label: str,
    maximum: int,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise Loop9DatasetIsolationError(f"{label} is invalid")
    return value


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise Loop9DatasetIsolationError(f"{label} must be a lowercase SHA-256")
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise Loop9DatasetIsolationError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _reject_duplicate_json_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise Loop9DatasetIsolationError(
                "persisted isolation artifact contains duplicate JSON fields"
            )
        result[key] = value
    return result


def _sequence(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise Loop9DatasetIsolationError(f"{label} must be an array")
    return cast(Sequence[object], value)


def platform_identity_sha256(
    *,
    identity_salt: bytes,
    identity_namespace: str,
    source_identity: str,
) -> str:
    """Return the shared HMAC identity used for every Loop 9 dataset class."""

    if not isinstance(identity_salt, bytes) or len(identity_salt) < 16:
        raise Loop9DatasetIsolationError(
            "platform identity key must contain at least 16 bytes"
        )
    namespace = _required_text(
        identity_namespace,
        label="platform identity namespace",
        maximum=100,
    )
    identity = _required_text(
        source_identity,
        label="platform identity",
        maximum=500,
    )
    return chengfeng_shadow_identity_digest(
        salt=identity_salt,
        namespace=namespace,
        field_name="platform_waybill_id",
        value=identity,
    )


def discovery_scope_exclusion_token(
    *,
    source_job_id: str,
    source_snapshot_sha256: str,
) -> str:
    """Bind an unidentified discovery row to its whole machine-verifiable scope."""

    job_id = _required_text(
        source_job_id,
        label="source job ID",
        maximum=100,
    )
    snapshot_sha256 = _required_sha256(
        source_snapshot_sha256,
        label="source snapshot SHA-256",
    )
    return _canonical_sha256(
        {
            "purpose": "loop9_discovery_scope_exclusion",
            "schema_version": SCHEMA_VERSION,
            "source_job_id": job_id,
            "source_snapshot_sha256": snapshot_sha256,
        }
    )


@dataclass(frozen=True, slots=True)
class Loop9DatasetImage:
    image_sha256: str
    perceptual_fingerprint: ImagePerceptualFingerprint | None

    def __post_init__(self) -> None:
        _required_sha256(self.image_sha256, label="dataset image SHA-256")
        fingerprint = self.perceptual_fingerprint
        if fingerprint is None:
            return
        if not isinstance(fingerprint, ImagePerceptualFingerprint):
            raise Loop9DatasetIsolationError("perceptual fingerprint is invalid")
        try:
            fingerprint.verify_integrity()
        except ImageSimilarityContractError as exc:
            raise Loop9DatasetIsolationError(
                "perceptual fingerprint integrity is invalid"
            ) from exc
        if fingerprint.content_sha256 != self.image_sha256:
            raise Loop9DatasetIsolationError(
                "perceptual fingerprint does not match the image SHA-256"
            )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "image_sha256": self.image_sha256,
            "perceptual_fingerprint": (
                None
                if self.perceptual_fingerprint is None
                else self.perceptual_fingerprint.to_record()
            ),
        }

    @classmethod
    def from_payload(cls, value: object) -> Loop9DatasetImage:
        raw = _mapping(value, label="dataset image")
        if set(raw) != {"image_sha256", "perceptual_fingerprint"}:
            raise Loop9DatasetIsolationError("dataset image contract is invalid")
        raw_fingerprint = raw.get("perceptual_fingerprint")
        fingerprint: ImagePerceptualFingerprint | None
        if raw_fingerprint is None:
            fingerprint = None
        else:
            try:
                fingerprint = ImagePerceptualFingerprint.from_record(
                    _mapping(
                        raw_fingerprint,
                        label="perceptual fingerprint",
                    )
                )
            except ImageSimilarityContractError as exc:
                raise Loop9DatasetIsolationError(
                    "perceptual fingerprint integrity is invalid"
                ) from exc
        return cls(
            image_sha256=_required_sha256(
                raw.get("image_sha256"),
                label="dataset image SHA-256",
            ),
            perceptual_fingerprint=fingerprint,
        )


@dataclass(frozen=True, slots=True)
class Loop9DatasetEntry:
    platform_identity_sha256: str | None
    scope_exclusion_token: str | None
    images: tuple[Loop9DatasetImage, ...]

    def __post_init__(self) -> None:
        if self.platform_identity_sha256 is not None:
            _required_sha256(
                self.platform_identity_sha256,
                label="platform identity digest",
            )
        if self.scope_exclusion_token is not None:
            _required_sha256(
                self.scope_exclusion_token,
                label="scope exclusion token",
            )
        if (self.platform_identity_sha256 is None) == (
            self.scope_exclusion_token is None
        ):
            raise Loop9DatasetIsolationError(
                "entry requires exactly one platform identity digest or scope exclusion token"
            )
        if (
            not isinstance(self.images, tuple)
            or not 1 <= len(self.images) <= 2
            or any(not isinstance(image, Loop9DatasetImage) for image in self.images)
        ):
            raise Loop9DatasetIsolationError("dataset entry must contain one or two images")
        fingerprints_by_image: dict[str, str] = {}
        for image in self.images:
            if image.perceptual_fingerprint is None:
                continue
            fingerprint_sha256 = image.perceptual_fingerprint.canonical_sha256
            existing = fingerprints_by_image.setdefault(
                image.image_sha256,
                fingerprint_sha256,
            )
            if existing != fingerprint_sha256:
                raise Loop9DatasetIsolationError(
                    "one image has conflicting perceptual fingerprints"
                )

    def _canonical_payload(self) -> dict[str, object]:
        images = sorted(
            (image._canonical_payload() for image in self.images),
            key=_canonical_json,
        )
        return {
            "images": images,
            "platform_identity_sha256": self.platform_identity_sha256,
            "scope_exclusion_token": self.scope_exclusion_token,
        }

    @classmethod
    def from_payload(cls, value: object) -> Loop9DatasetEntry:
        raw = _mapping(value, label="dataset entry")
        if set(raw) != {
            "images",
            "platform_identity_sha256",
            "scope_exclusion_token",
        }:
            raise Loop9DatasetIsolationError("dataset entry contract is invalid")
        identity = raw.get("platform_identity_sha256")
        scope_token = raw.get("scope_exclusion_token")
        if identity is not None and not isinstance(identity, str):
            raise Loop9DatasetIsolationError("platform identity digest is invalid")
        if scope_token is not None and not isinstance(scope_token, str):
            raise Loop9DatasetIsolationError("scope exclusion token is invalid")
        return cls(
            platform_identity_sha256=identity,
            scope_exclusion_token=scope_token,
            images=tuple(
                Loop9DatasetImage.from_payload(image)
                for image in _sequence(raw.get("images"), label="dataset entry images")
            ),
        )


@dataclass(frozen=True, slots=True)
class Loop9DatasetManifest:
    dataset_id: str
    dataset_kind: DatasetKind
    build_sha256: str
    contract_sha256: str
    source_job_id: str
    source_snapshot_sha256: str
    entries: tuple[Loop9DatasetEntry, ...]
    identity_context_sha256: str | None = None
    formal_selection_sha256: str | None = None
    locked_gate_evidence_sha256: str | None = None
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_text(self.dataset_id, label="dataset ID", maximum=100)
        if not isinstance(self.dataset_kind, DatasetKind):
            raise Loop9DatasetIsolationError("dataset classification is invalid")
        _required_sha256(self.build_sha256, label="build SHA-256")
        _required_sha256(self.contract_sha256, label="contract SHA-256")
        _required_text(self.source_job_id, label="source job ID", maximum=100)
        _required_sha256(
            self.source_snapshot_sha256,
            label="source snapshot SHA-256",
        )
        if (
            not isinstance(self.entries, tuple)
            or not self.entries
            or any(not isinstance(entry, Loop9DatasetEntry) for entry in self.entries)
        ):
            raise Loop9DatasetIsolationError("dataset entries are invalid")
        _required_sha256(
            self.identity_context_sha256,
            label="dataset identity context SHA-256",
        )
        identities = [
            entry.platform_identity_sha256
            for entry in self.entries
            if entry.platform_identity_sha256 is not None
        ]
        if len(identities) != len(set(identities)):
            raise Loop9DatasetIsolationError(
                "dataset contains a duplicate platform identity digest"
            )
        self._validate_classification()
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _validate_classification(self) -> None:
        if self.dataset_kind in {
            DatasetKind.DISCOVERY_DEVELOPMENT,
            DatasetKind.DAILY_VALIDATION,
        }:
            if (
                self.formal_selection_sha256 is not None
                or self.locked_gate_evidence_sha256 is not None
            ):
                raise Loop9DatasetIsolationError(
                    "non-formal dataset must not bind a formal selection"
                )
        else:
            _required_sha256(
                self.formal_selection_sha256,
                label="formal selection SHA-256",
            )
            if self.dataset_kind is DatasetKind.CURRENT_LOCKED_50:
                if self.locked_gate_evidence_sha256 is not None:
                    raise Loop9DatasetIsolationError(
                        "current_locked_50 must not bind its own Gate"
                    )
            else:
                _required_sha256(
                    self.locked_gate_evidence_sha256,
                    label="current locked Gate SHA-256",
                )
        expected_scope_token = discovery_scope_exclusion_token(
            source_job_id=self.source_job_id,
            source_snapshot_sha256=self.source_snapshot_sha256,
        )
        if self.dataset_kind is DatasetKind.DISCOVERY_DEVELOPMENT:
            for entry in self.entries:
                if (
                    entry.platform_identity_sha256 is None
                    and entry.scope_exclusion_token != expected_scope_token
                ):
                    raise Loop9DatasetIsolationError(
                        "discovery scope exclusion token is not machine-verifiable"
                    )
        elif any(entry.platform_identity_sha256 is None for entry in self.entries):
            raise Loop9DatasetIsolationError(
                "formal dataset classification requires platform identity digests"
            )

        if self.dataset_kind is DatasetKind.CURRENT_LOCKED_50:
            images = [image for entry in self.entries for image in entry.images]
            if len(self.entries) != 50:
                raise Loop9DatasetIsolationError(
                    "current_locked_50 must contain exactly 50 entries"
                )
            if (
                any(len(entry.images) != 2 for entry in self.entries)
                or len(images) != 100
                or len({image.image_sha256 for image in images}) != 100
            ):
                raise Loop9DatasetIsolationError(
                    "current_locked_50 must contain exactly 100 unique images"
                )
        elif self.dataset_kind is DatasetKind.REAL_SHADOW_30:
            images = [image for entry in self.entries for image in entry.images]
            if len(self.entries) != 30:
                raise Loop9DatasetIsolationError(
                    "real_shadow_30 must contain exactly 30 entries"
                )
            if (
                any(len(entry.images) != 2 for entry in self.entries)
                or len(images) != 60
                or len({image.image_sha256 for image in images}) != 60
            ):
                raise Loop9DatasetIsolationError(
                    "real_shadow_30 must contain exactly 60 unique images"
                )

    def _canonical_payload(self) -> dict[str, object]:
        entries = sorted(
            (entry._canonical_payload() for entry in self.entries),
            key=_canonical_json,
        )
        return {
            "build_sha256": self.build_sha256,
            "contract_sha256": self.contract_sha256,
            "dataset_id": self.dataset_id,
            "dataset_kind": self.dataset_kind.value,
            "entries": entries,
            "formal_selection_sha256": self.formal_selection_sha256,
            "identity_context_sha256": self.identity_context_sha256,
            "locked_gate_evidence_sha256": (
                self.locked_gate_evidence_sha256
            ),
            "schema_version": DATASET_MANIFEST_SCHEMA_VERSION,
            "source_job_id": self.source_job_id,
            "source_snapshot_sha256": self.source_snapshot_sha256,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise Loop9DatasetIsolationError("dataset manifest integrity is invalid")

    @property
    def image_count(self) -> int:
        return sum(len(entry.images) for entry in self.entries)

    @property
    def image_sha256s(self) -> frozenset[str]:
        return frozenset(
            image.image_sha256 for entry in self.entries for image in entry.images
        )

    @property
    def platform_identity_sha256s(self) -> frozenset[str]:
        return frozenset(
            identity
            for entry in self.entries
            if (identity := entry.platform_identity_sha256) is not None
        )

    @property
    def scope_exclusion_tokens(self) -> frozenset[str]:
        return frozenset(
            token
            for entry in self.entries
            if (token := entry.scope_exclusion_token) is not None
        )

    @property
    def perceptual_fingerprints(self) -> tuple[ImagePerceptualFingerprint, ...]:
        return _unique_fingerprints(
            image.perceptual_fingerprint
            for entry in self.entries
            for image in entry.images
        )

    @classmethod
    def from_payload(cls, value: object) -> Loop9DatasetManifest:
        raw = _mapping(value, label="dataset manifest")
        expected_keys = {
            "build_sha256",
            "canonical_sha256",
            "contract_sha256",
            "dataset_id",
            "dataset_kind",
            "entries",
            "formal_selection_sha256",
            "identity_context_sha256",
            "locked_gate_evidence_sha256",
            "schema_version",
            "source_job_id",
            "source_snapshot_sha256",
        }
        if (
            set(raw) != expected_keys
            or raw.get("schema_version")
            != DATASET_MANIFEST_SCHEMA_VERSION
        ):
            raise Loop9DatasetIsolationError("dataset manifest contract is invalid")
        raw_kind = raw.get("dataset_kind")
        if not isinstance(raw_kind, str):
            raise Loop9DatasetIsolationError(
                "dataset classification is invalid"
            )
        try:
            dataset_kind = DatasetKind(raw_kind)
        except (TypeError, ValueError) as exc:
            raise Loop9DatasetIsolationError(
                "dataset classification is invalid"
            ) from exc
        manifest = cls(
            dataset_id=_required_text(
                raw.get("dataset_id"),
                label="dataset ID",
                maximum=100,
            ),
            dataset_kind=dataset_kind,
            build_sha256=_required_sha256(
                raw.get("build_sha256"),
                label="build SHA-256",
            ),
            contract_sha256=_required_sha256(
                raw.get("contract_sha256"),
                label="contract SHA-256",
            ),
            source_job_id=_required_text(
                raw.get("source_job_id"),
                label="source job ID",
                maximum=100,
            ),
            source_snapshot_sha256=_required_sha256(
                raw.get("source_snapshot_sha256"),
                label="source snapshot SHA-256",
            ),
            entries=tuple(
                Loop9DatasetEntry.from_payload(entry)
                for entry in _sequence(raw.get("entries"), label="dataset entries")
            ),
            identity_context_sha256=(
                None
                if raw.get("identity_context_sha256") is None
                else _required_sha256(
                    raw.get("identity_context_sha256"),
                    label="formal identity context SHA-256",
                )
            ),
            formal_selection_sha256=(
                None
                if raw.get("formal_selection_sha256") is None
                else _required_sha256(
                    raw.get("formal_selection_sha256"),
                    label="formal selection SHA-256",
                )
            ),
            locked_gate_evidence_sha256=(
                None
                if raw.get("locked_gate_evidence_sha256") is None
                else _required_sha256(
                    raw.get("locked_gate_evidence_sha256"),
                    label="current locked Gate SHA-256",
                )
            ),
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="dataset manifest canonical SHA-256",
        )
        if declared != manifest.canonical_sha256:
            raise Loop9DatasetIsolationError("dataset manifest integrity is invalid")
        return manifest


@dataclass(frozen=True, slots=True)
class Loop9DatasetExclusionInventory:
    inventory_id: str
    exclusion_kind: ExclusionKind
    platform_identity_sha256s: tuple[str, ...]
    image_sha256s: tuple[str, ...]
    scope_exclusion_tokens: tuple[str, ...]
    perceptual_fingerprints: tuple[ImagePerceptualFingerprint, ...]
    identity_context_sha256: str | None
    artifact_schema_version: int = EXCLUSION_INVENTORY_SCHEMA_VERSION
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_text(self.inventory_id, label="exclusion inventory ID", maximum=100)
        if not isinstance(self.exclusion_kind, ExclusionKind):
            raise Loop9DatasetIsolationError("exclusion inventory classification is invalid")
        if self.artifact_schema_version == EXCLUSION_INVENTORY_SCHEMA_VERSION:
            _required_sha256(
                self.identity_context_sha256,
                label="exclusion inventory identity context SHA-256",
            )
        elif self.artifact_schema_version == 1:
            if self.identity_context_sha256 is not None:
                raise Loop9DatasetIsolationError(
                    "legacy exclusion inventory cannot claim an identity context"
                )
        else:
            raise Loop9DatasetIsolationError(
                "exclusion inventory schema version is invalid"
            )
        for label, values in (
            ("excluded platform identities", self.platform_identity_sha256s),
            ("excluded images", self.image_sha256s),
            ("scope exclusion tokens", self.scope_exclusion_tokens),
        ):
            if not isinstance(values, tuple):
                raise Loop9DatasetIsolationError(f"{label} must be immutable")
            for value in values:
                _required_sha256(value, label=label)
            if len(values) != len(set(values)):
                raise Loop9DatasetIsolationError(f"{label} contains duplicates")
        if (
            not isinstance(self.perceptual_fingerprints, tuple)
            or any(
                not isinstance(fingerprint, ImagePerceptualFingerprint)
                for fingerprint in self.perceptual_fingerprints
            )
        ):
            raise Loop9DatasetIsolationError("excluded perceptual fingerprints are invalid")
        image_hashes = set(self.image_sha256s)
        fingerprint_hashes: set[str] = set()
        for fingerprint in self.perceptual_fingerprints:
            try:
                fingerprint.verify_integrity()
            except ImageSimilarityContractError as exc:
                raise Loop9DatasetIsolationError(
                    "excluded perceptual fingerprint integrity is invalid"
                ) from exc
            if fingerprint.content_sha256 not in image_hashes:
                raise Loop9DatasetIsolationError(
                    "excluded perceptual fingerprint has no image identity"
                )
            if fingerprint.content_sha256 in fingerprint_hashes:
                raise Loop9DatasetIsolationError(
                    "excluded perceptual fingerprint identity is duplicated"
                )
            fingerprint_hashes.add(fingerprint.content_sha256)
        if (
            self.exclusion_kind is ExclusionKind.LEGACY_LOOP7
            and self.scope_exclusion_tokens
        ):
            raise Loop9DatasetIsolationError(
                "legacy Loop 7 exclusions cannot contain Loop 9 scope tokens"
            )
        if not (
            self.platform_identity_sha256s
            or self.image_sha256s
            or self.scope_exclusion_tokens
        ):
            raise Loop9DatasetIsolationError("exclusion inventory cannot be empty")
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        fingerprints = sorted(
            (
                fingerprint.to_record()
                for fingerprint in self.perceptual_fingerprints
            ),
            key=_canonical_json,
        )
        payload: dict[str, object] = {
            "exclusion_kind": self.exclusion_kind.value,
            "image_sha256s": sorted(self.image_sha256s),
            "inventory_id": self.inventory_id,
            "perceptual_fingerprints": fingerprints,
            "platform_identity_sha256s": sorted(
                self.platform_identity_sha256s
            ),
            "schema_version": self.artifact_schema_version,
            "scope_exclusion_tokens": sorted(self.scope_exclusion_tokens),
        }
        if self.artifact_schema_version == EXCLUSION_INVENTORY_SCHEMA_VERSION:
            payload["identity_context_sha256"] = (
                self.identity_context_sha256
            )
        return payload

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise Loop9DatasetIsolationError(
                "exclusion inventory integrity is invalid"
            )

    @classmethod
    def from_payload(cls, value: object) -> Loop9DatasetExclusionInventory:
        raw = _mapping(value, label="exclusion inventory")
        schema_version = raw.get("schema_version")
        expected_keys = {
            "canonical_sha256",
            "exclusion_kind",
            "image_sha256s",
            "inventory_id",
            "perceptual_fingerprints",
            "platform_identity_sha256s",
            "schema_version",
            "scope_exclusion_tokens",
        }
        if schema_version == EXCLUSION_INVENTORY_SCHEMA_VERSION:
            expected_keys.add("identity_context_sha256")
        elif schema_version != 1:
            raise Loop9DatasetIsolationError(
                "exclusion inventory contract is invalid"
            )
        if set(raw) != expected_keys:
            raise Loop9DatasetIsolationError(
                "exclusion inventory contract is invalid"
            )
        raw_kind = raw.get("exclusion_kind")
        if not isinstance(raw_kind, str):
            raise Loop9DatasetIsolationError(
                "exclusion inventory classification is invalid"
            )
        try:
            exclusion_kind = ExclusionKind(raw_kind)
        except (TypeError, ValueError) as exc:
            raise Loop9DatasetIsolationError(
                "exclusion inventory classification is invalid"
            ) from exc
        fingerprints: list[ImagePerceptualFingerprint] = []
        for value in _sequence(
            raw.get("perceptual_fingerprints"),
            label="excluded perceptual fingerprints",
        ):
            try:
                fingerprints.append(
                    ImagePerceptualFingerprint.from_record(
                        _mapping(value, label="excluded perceptual fingerprint")
                    )
                )
            except ImageSimilarityContractError as exc:
                raise Loop9DatasetIsolationError(
                    "excluded perceptual fingerprint integrity is invalid"
                ) from exc
        inventory = cls(
            inventory_id=_required_text(
                raw.get("inventory_id"),
                label="exclusion inventory ID",
                maximum=100,
            ),
            exclusion_kind=exclusion_kind,
            platform_identity_sha256s=tuple(
                _required_sha256(value, label="excluded platform identity")
                for value in _sequence(
                    raw.get("platform_identity_sha256s"),
                    label="excluded platform identities",
                )
            ),
            image_sha256s=tuple(
                _required_sha256(value, label="excluded image")
                for value in _sequence(
                    raw.get("image_sha256s"),
                    label="excluded images",
                )
            ),
            scope_exclusion_tokens=tuple(
                _required_sha256(value, label="scope exclusion token")
                for value in _sequence(
                    raw.get("scope_exclusion_tokens"),
                    label="scope exclusion tokens",
                )
            ),
            perceptual_fingerprints=tuple(fingerprints),
            identity_context_sha256=(
                None
                if schema_version == 1
                else _required_sha256(
                    raw.get("identity_context_sha256"),
                    label="exclusion inventory identity context SHA-256",
                )
            ),
            artifact_schema_version=schema_version,
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="exclusion inventory canonical SHA-256",
        )
        if declared != inventory.canonical_sha256:
            raise Loop9DatasetIsolationError(
                "exclusion inventory integrity is invalid"
            )
        return inventory


@dataclass(frozen=True, slots=True)
class Loop9ExclusionSourceBoundary:
    """Canonical completeness boundary derived from the persisted source authority."""

    source_authority_sha256: str
    source_exclusion_snapshot_sha256: str
    source_inventory_high_watermark: int
    image_sha256s: tuple[str, ...]
    platform_identity_count: int
    perceptual_fingerprints: tuple[ImagePerceptualFingerprint, ...]
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_sha256(
            self.source_authority_sha256,
            label="exclusion source authority SHA-256",
        )
        _required_sha256(
            self.source_exclusion_snapshot_sha256,
            label="exclusion source snapshot SHA-256",
        )
        if (
            isinstance(self.source_inventory_high_watermark, bool)
            or not isinstance(self.source_inventory_high_watermark, int)
            or self.source_inventory_high_watermark < 1
        ):
            raise Loop9DatasetIsolationError(
                "exclusion source inventory high watermark is invalid"
            )
        if (
            not isinstance(self.image_sha256s, tuple)
            or not self.image_sha256s
        ):
            raise Loop9DatasetIsolationError(
                "exclusion source image inventory is incomplete"
            )
        for image_sha256 in self.image_sha256s:
            _required_sha256(
                image_sha256,
                label="exclusion source image SHA-256",
            )
        if (
            tuple(sorted(self.image_sha256s)) != self.image_sha256s
            or len(set(self.image_sha256s)) != len(self.image_sha256s)
        ):
            raise Loop9DatasetIsolationError(
                "exclusion source image inventory must be sorted and unique"
            )
        if (
            isinstance(self.platform_identity_count, bool)
            or not isinstance(self.platform_identity_count, int)
            or self.platform_identity_count < 1
        ):
            raise Loop9DatasetIsolationError(
                "exclusion source platform identity count is invalid"
            )
        if (
            not isinstance(self.perceptual_fingerprints, tuple)
            or any(
                not isinstance(fingerprint, ImagePerceptualFingerprint)
                for fingerprint in self.perceptual_fingerprints
            )
        ):
            raise Loop9DatasetIsolationError(
                "exclusion source perceptual fingerprints are invalid"
            )
        fingerprint_by_image: dict[str, ImagePerceptualFingerprint] = {}
        for fingerprint in self.perceptual_fingerprints:
            try:
                fingerprint.verify_integrity()
            except ImageSimilarityContractError as exc:
                raise Loop9DatasetIsolationError(
                    "exclusion source perceptual fingerprint integrity is invalid"
                ) from exc
            if fingerprint.content_sha256 in fingerprint_by_image:
                raise Loop9DatasetIsolationError(
                    "exclusion source perceptual fingerprint is duplicated"
                )
            fingerprint_by_image[fingerprint.content_sha256] = fingerprint
        if set(fingerprint_by_image) != set(self.image_sha256s):
            raise Loop9DatasetIsolationError(
                "exclusion source requires one fingerprint for every image"
            )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "image_count": len(self.image_sha256s),
            "image_sha256s": list(self.image_sha256s),
            "kind": "loop9_exclusion_source_boundary",
            "perceptual_fingerprint_count": len(
                self.perceptual_fingerprints
            ),
            "perceptual_fingerprints": [
                fingerprint.to_record()
                for fingerprint in self.perceptual_fingerprints
            ],
            "platform_identity_count": self.platform_identity_count,
            "schema_version": EXCLUSION_SOURCE_BOUNDARY_SCHEMA_VERSION,
            "source_authority_sha256": self.source_authority_sha256,
            "source_exclusion_snapshot_sha256": (
                self.source_exclusion_snapshot_sha256
            ),
            "source_inventory_high_watermark": (
                self.source_inventory_high_watermark
            ),
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise Loop9DatasetIsolationError(
                "exclusion source boundary integrity is invalid"
            )

    @classmethod
    def from_payload(cls, value: object) -> Loop9ExclusionSourceBoundary:
        raw = _mapping(value, label="exclusion source boundary")
        expected = {
            "canonical_sha256",
            "image_count",
            "image_sha256s",
            "kind",
            "perceptual_fingerprint_count",
            "perceptual_fingerprints",
            "platform_identity_count",
            "schema_version",
            "source_authority_sha256",
            "source_exclusion_snapshot_sha256",
            "source_inventory_high_watermark",
        }
        if (
            set(raw) != expected
            or raw.get("schema_version")
            != EXCLUSION_SOURCE_BOUNDARY_SCHEMA_VERSION
            or raw.get("kind") != "loop9_exclusion_source_boundary"
        ):
            raise Loop9DatasetIsolationError(
                "exclusion source boundary contract is invalid"
            )
        images = tuple(
            _required_sha256(
                item,
                label="exclusion source image SHA-256",
            )
            for item in _sequence(
                raw.get("image_sha256s"),
                label="exclusion source images",
            )
        )
        fingerprints: list[ImagePerceptualFingerprint] = []
        for item in _sequence(
            raw.get("perceptual_fingerprints"),
            label="exclusion source perceptual fingerprints",
        ):
            try:
                fingerprints.append(
                    ImagePerceptualFingerprint.from_record(
                        _mapping(
                            item,
                            label="exclusion source perceptual fingerprint",
                        )
                    )
                )
            except ImageSimilarityContractError as exc:
                raise Loop9DatasetIsolationError(
                    "exclusion source perceptual fingerprint integrity is invalid"
                ) from exc
        image_count = raw.get("image_count")
        fingerprint_count = raw.get("perceptual_fingerprint_count")
        platform_identity_count = raw.get("platform_identity_count")
        high_watermark = raw.get("source_inventory_high_watermark")
        if (
            type(image_count) is not int
            or image_count != len(images)
            or type(fingerprint_count) is not int
            or fingerprint_count != len(fingerprints)
            or type(platform_identity_count) is not int
            or type(high_watermark) is not int
        ):
            raise Loop9DatasetIsolationError(
                "exclusion source boundary counts are incomplete"
            )
        boundary = cls(
            source_authority_sha256=_required_sha256(
                raw.get("source_authority_sha256"),
                label="exclusion source authority SHA-256",
            ),
            source_exclusion_snapshot_sha256=_required_sha256(
                raw.get("source_exclusion_snapshot_sha256"),
                label="exclusion source snapshot SHA-256",
            ),
            source_inventory_high_watermark=high_watermark,
            image_sha256s=images,
            platform_identity_count=platform_identity_count,
            perceptual_fingerprints=tuple(fingerprints),
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="exclusion source boundary canonical SHA-256",
        )
        if declared != boundary.canonical_sha256:
            raise Loop9DatasetIsolationError(
                "exclusion source boundary integrity is invalid"
            )
        return boundary


@dataclass(frozen=True, slots=True)
class Loop9ExclusionChildIndexNode:
    """One immutable link in the append-only exclusion child history."""

    sequence: int
    previous_head_sha256: str | None
    source_boundary_sha256: str
    source_inventory_high_watermark: int
    identity_context_sha256: str
    expected_current_build_sha256: str
    expected_settlement_contract_sha256: str
    expected_daily_contract_sha256: str
    expected_settlement_selection_sha256: str
    expected_daily_selection_sha256: str
    child_inventory_sha256: str
    child_exclusion_kind: ExclusionKind
    child_platform_identity_count: int
    child_image_count: int
    child_scope_exclusion_token_count: int
    child_perceptual_fingerprint_count: int
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            isinstance(self.sequence, bool)
            or not isinstance(self.sequence, int)
            or self.sequence < 1
            or (
                self.sequence == 1
                and self.previous_head_sha256 is not None
            )
            or (
                self.sequence > 1
                and self.previous_head_sha256 is None
            )
        ):
            raise Loop9DatasetIsolationError(
                "exclusion child index sequence is invalid"
            )
        if self.previous_head_sha256 is not None:
            _required_sha256(
                self.previous_head_sha256,
                label="exclusion child previous head SHA-256",
            )
        for value, label in (
            (
                self.source_boundary_sha256,
                "exclusion child source boundary SHA-256",
            ),
            (
                self.identity_context_sha256,
                "exclusion child identity context SHA-256",
            ),
            (
                self.expected_current_build_sha256,
                "exclusion child current build SHA-256",
            ),
            (
                self.expected_settlement_contract_sha256,
                "exclusion child settlement contract SHA-256",
            ),
            (
                self.expected_daily_contract_sha256,
                "exclusion child daily contract SHA-256",
            ),
            (
                self.expected_settlement_selection_sha256,
                "exclusion child settlement selection SHA-256",
            ),
            (
                self.expected_daily_selection_sha256,
                "exclusion child daily selection SHA-256",
            ),
            (
                self.child_inventory_sha256,
                "exclusion child inventory SHA-256",
            ),
        ):
            _required_sha256(value, label=label)
        if (
            isinstance(self.source_inventory_high_watermark, bool)
            or not isinstance(self.source_inventory_high_watermark, int)
            or self.source_inventory_high_watermark < 1
        ):
            raise Loop9DatasetIsolationError(
                "exclusion child source high-water mark is invalid"
            )
        if not isinstance(self.child_exclusion_kind, ExclusionKind):
            raise Loop9DatasetIsolationError(
                "exclusion child classification is invalid"
            )
        for count, count_label in (
            (
                self.child_platform_identity_count,
                "exclusion child platform identity count",
            ),
            (self.child_image_count, "exclusion child image count"),
            (
                self.child_scope_exclusion_token_count,
                "exclusion child scope token count",
            ),
            (
                self.child_perceptual_fingerprint_count,
                "exclusion child fingerprint count",
            ),
        ):
            if (
                isinstance(count, bool)
                or not isinstance(count, int)
                or count < 0
            ):
                raise Loop9DatasetIsolationError(
                    f"{count_label} is invalid"
                )
        if (
            self.child_perceptual_fingerprint_count
            != self.child_image_count
            or (
                self.child_image_count == 0
                and self.child_exclusion_kind
                is not ExclusionKind.DEVELOPMENT
            )
        ):
            raise Loop9DatasetIsolationError(
                "exclusion child image completeness is invalid"
            )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "child_exclusion_kind": self.child_exclusion_kind.value,
            "child_image_count": self.child_image_count,
            "child_inventory_sha256": self.child_inventory_sha256,
            "child_perceptual_fingerprint_count": (
                self.child_perceptual_fingerprint_count
            ),
            "child_platform_identity_count": (
                self.child_platform_identity_count
            ),
            "child_scope_exclusion_token_count": (
                self.child_scope_exclusion_token_count
            ),
            "expected_current_build_sha256": (
                self.expected_current_build_sha256
            ),
            "expected_daily_contract_sha256": (
                self.expected_daily_contract_sha256
            ),
            "expected_daily_selection_sha256": (
                self.expected_daily_selection_sha256
            ),
            "expected_settlement_contract_sha256": (
                self.expected_settlement_contract_sha256
            ),
            "expected_settlement_selection_sha256": (
                self.expected_settlement_selection_sha256
            ),
            "identity_context_sha256": self.identity_context_sha256,
            "kind": "loop9_exclusion_child_index_node",
            "previous_head_sha256": self.previous_head_sha256,
            "schema_version": EXCLUSION_CHILD_INDEX_NODE_SCHEMA_VERSION,
            "sequence": self.sequence,
            "source_boundary_sha256": self.source_boundary_sha256,
            "source_inventory_high_watermark": (
                self.source_inventory_high_watermark
            ),
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise Loop9DatasetIsolationError(
                "exclusion child index node integrity is invalid"
            )

    def verify_bindings(
        self,
        *,
        source_boundary: Loop9ExclusionSourceBoundary,
        child_inventory: Loop9DatasetExclusionInventory,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
        expected_daily_contract_sha256: str,
        expected_settlement_selection_sha256: str,
        expected_daily_selection_sha256: str,
    ) -> None:
        self.verify_integrity()
        child_inventory.verify_integrity()
        expected_context = child_inventory.identity_context_sha256
        if expected_context is None:
            raise Loop9DatasetIsolationError(
                "legacy exclusion child cannot enter the current index"
            )
        if (
            self.source_boundary_sha256
            != source_boundary.canonical_sha256
            or self.source_inventory_high_watermark
            != source_boundary.source_inventory_high_watermark
            or self.identity_context_sha256 != expected_context
            or self.expected_current_build_sha256
            != expected_current_build_sha256
            or self.expected_settlement_contract_sha256
            != expected_settlement_contract_sha256
            or self.expected_daily_contract_sha256
            != expected_daily_contract_sha256
            or self.expected_settlement_selection_sha256
            != expected_settlement_selection_sha256
            or self.expected_daily_selection_sha256
            != expected_daily_selection_sha256
            or self.child_inventory_sha256
            != child_inventory.canonical_sha256
            or self.child_exclusion_kind
            is not child_inventory.exclusion_kind
            or self.child_platform_identity_count
            != len(child_inventory.platform_identity_sha256s)
            or self.child_image_count != len(child_inventory.image_sha256s)
            or self.child_scope_exclusion_token_count
            != len(child_inventory.scope_exclusion_tokens)
            or self.child_perceptual_fingerprint_count
            != len(child_inventory.perceptual_fingerprints)
        ):
            raise Loop9DatasetIsolationError(
                "exclusion child index node binding is invalid"
            )

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        previous_head_sha256: str | None,
        source_boundary: Loop9ExclusionSourceBoundary,
        child_inventory: Loop9DatasetExclusionInventory,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
        expected_daily_contract_sha256: str,
        expected_settlement_selection_sha256: str,
        expected_daily_selection_sha256: str,
    ) -> Loop9ExclusionChildIndexNode:
        source_boundary.verify_integrity()
        child_inventory.verify_integrity()
        identity_context = child_inventory.identity_context_sha256
        if (
            child_inventory.artifact_schema_version
            != EXCLUSION_INVENTORY_SCHEMA_VERSION
            or identity_context is None
        ):
            raise Loop9DatasetIsolationError(
                "legacy exclusion child cannot enter the current index"
            )
        return cls(
            sequence=sequence,
            previous_head_sha256=previous_head_sha256,
            source_boundary_sha256=source_boundary.canonical_sha256,
            source_inventory_high_watermark=(
                source_boundary.source_inventory_high_watermark
            ),
            identity_context_sha256=identity_context,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
            child_inventory_sha256=child_inventory.canonical_sha256,
            child_exclusion_kind=child_inventory.exclusion_kind,
            child_platform_identity_count=len(
                child_inventory.platform_identity_sha256s
            ),
            child_image_count=len(child_inventory.image_sha256s),
            child_scope_exclusion_token_count=len(
                child_inventory.scope_exclusion_tokens
            ),
            child_perceptual_fingerprint_count=len(
                child_inventory.perceptual_fingerprints
            ),
        )

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> Loop9ExclusionChildIndexNode:
        raw = _mapping(value, label="exclusion child index node")
        expected = {
            "canonical_sha256",
            "child_exclusion_kind",
            "child_image_count",
            "child_inventory_sha256",
            "child_perceptual_fingerprint_count",
            "child_platform_identity_count",
            "child_scope_exclusion_token_count",
            "expected_current_build_sha256",
            "expected_daily_contract_sha256",
            "expected_daily_selection_sha256",
            "expected_settlement_contract_sha256",
            "expected_settlement_selection_sha256",
            "identity_context_sha256",
            "kind",
            "previous_head_sha256",
            "schema_version",
            "sequence",
            "source_boundary_sha256",
            "source_inventory_high_watermark",
        }
        if (
            set(raw) != expected
            or raw.get("schema_version")
            != EXCLUSION_CHILD_INDEX_NODE_SCHEMA_VERSION
            or raw.get("kind") != "loop9_exclusion_child_index_node"
        ):
            raise Loop9DatasetIsolationError(
                "exclusion child index node contract is invalid"
            )
        sequence = raw.get("sequence")
        high_watermark = raw.get("source_inventory_high_watermark")
        platform_identity_count = raw.get(
            "child_platform_identity_count"
        )
        image_count = raw.get("child_image_count")
        scope_token_count = raw.get(
            "child_scope_exclusion_token_count"
        )
        fingerprint_count = raw.get(
            "child_perceptual_fingerprint_count"
        )
        if (
            type(sequence) is not int
            or type(high_watermark) is not int
            or type(platform_identity_count) is not int
            or type(image_count) is not int
            or type(scope_token_count) is not int
            or type(fingerprint_count) is not int
        ):
            raise Loop9DatasetIsolationError(
                "exclusion child index node counts are invalid"
            )
        previous = raw.get("previous_head_sha256")
        if previous is not None:
            previous = _required_sha256(
                previous,
                label="exclusion child previous head SHA-256",
            )
        try:
            exclusion_kind = ExclusionKind(
                _required_text(
                    raw.get("child_exclusion_kind"),
                    label="exclusion child classification",
                    maximum=32,
                )
            )
        except ValueError as exc:
            raise Loop9DatasetIsolationError(
                "exclusion child classification is invalid"
            ) from exc
        node = cls(
            sequence=sequence,
            previous_head_sha256=previous,
            source_boundary_sha256=_required_sha256(
                raw.get("source_boundary_sha256"),
                label="exclusion child source boundary SHA-256",
            ),
            source_inventory_high_watermark=high_watermark,
            identity_context_sha256=_required_sha256(
                raw.get("identity_context_sha256"),
                label="exclusion child identity context SHA-256",
            ),
            expected_current_build_sha256=_required_sha256(
                raw.get("expected_current_build_sha256"),
                label="exclusion child current build SHA-256",
            ),
            expected_settlement_contract_sha256=_required_sha256(
                raw.get("expected_settlement_contract_sha256"),
                label="exclusion child settlement contract SHA-256",
            ),
            expected_daily_contract_sha256=_required_sha256(
                raw.get("expected_daily_contract_sha256"),
                label="exclusion child daily contract SHA-256",
            ),
            expected_settlement_selection_sha256=_required_sha256(
                raw.get("expected_settlement_selection_sha256"),
                label="exclusion child settlement selection SHA-256",
            ),
            expected_daily_selection_sha256=_required_sha256(
                raw.get("expected_daily_selection_sha256"),
                label="exclusion child daily selection SHA-256",
            ),
            child_inventory_sha256=_required_sha256(
                raw.get("child_inventory_sha256"),
                label="exclusion child inventory SHA-256",
            ),
            child_exclusion_kind=exclusion_kind,
            child_platform_identity_count=platform_identity_count,
            child_image_count=image_count,
            child_scope_exclusion_token_count=scope_token_count,
            child_perceptual_fingerprint_count=fingerprint_count,
        )
        if (
            _required_sha256(
                raw.get("canonical_sha256"),
                label="exclusion child index node SHA-256",
            )
            != node.canonical_sha256
            or dict(raw) != node.to_payload()
        ):
            raise Loop9DatasetIsolationError(
                "exclusion child index node integrity is invalid"
            )
        return node


def loop9_exclusion_child_index_nodes(
    *,
    source_boundary: Loop9ExclusionSourceBoundary,
    child_inventories: Sequence[Loop9DatasetExclusionInventory],
    expected_current_build_sha256: str,
    expected_settlement_contract_sha256: str,
    expected_daily_contract_sha256: str,
    expected_settlement_selection_sha256: str,
    expected_daily_selection_sha256: str,
) -> tuple[Loop9ExclusionChildIndexNode, ...]:
    nodes: list[Loop9ExclusionChildIndexNode] = []
    previous: str | None = None
    for sequence, child in enumerate(child_inventories, start=1):
        node = Loop9ExclusionChildIndexNode.create(
            sequence=sequence,
            previous_head_sha256=previous,
            source_boundary=source_boundary,
            child_inventory=child,
            expected_current_build_sha256=(
                expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                expected_daily_selection_sha256
            ),
        )
        nodes.append(node)
        previous = node.canonical_sha256
    return tuple(nodes)


def _merged_exclusion_inventory(
    *,
    kind: ExclusionKind,
    children: Sequence[Loop9DatasetExclusionInventory],
) -> Loop9DatasetExclusionInventory:
    matching = tuple(
        child for child in children if child.exclusion_kind is kind
    )
    if not matching:
        raise Loop9DatasetIsolationError(
            "full-history exclusion authority does not cover the complete "
            f"source history: missing {kind.value}"
        )
    if len(matching) == 1:
        return matching[0]
    identity_contexts = {
        child.identity_context_sha256 for child in matching
    }
    if len(identity_contexts) != 1 or None in identity_contexts:
        raise Loop9DatasetIsolationError(
            "full-history exclusion children use different identity contexts"
        )
    fingerprint_by_image: dict[str, ImagePerceptualFingerprint] = {}
    for child in matching:
        for fingerprint in child.perceptual_fingerprints:
            existing = fingerprint_by_image.get(fingerprint.content_sha256)
            if (
                existing is not None
                and existing.to_record() != fingerprint.to_record()
            ):
                raise Loop9DatasetIsolationError(
                    "full-history exclusion children contain conflicting "
                    "perceptual fingerprints"
                )
            fingerprint_by_image[fingerprint.content_sha256] = fingerprint
    child_sha256s = tuple(
        sorted(child.canonical_sha256 for child in matching)
    )
    merged_id_sha256 = _canonical_sha256(
        {
            "child_inventory_sha256s": list(child_sha256s),
            "exclusion_kind": kind.value,
            "purpose": "loop9_full_history_exclusion_merge",
        }
    )
    return Loop9DatasetExclusionInventory(
        inventory_id=(
            f"loop9-full-history-{kind.value}-{merged_id_sha256[:16]}"
        ),
        exclusion_kind=kind,
        platform_identity_sha256s=tuple(
            sorted(
                {
                    identity_sha256
                    for child in matching
                    for identity_sha256 in child.platform_identity_sha256s
                }
            )
        ),
        image_sha256s=tuple(
            sorted(
                {
                    image_sha256
                    for child in matching
                    for image_sha256 in child.image_sha256s
                }
            )
        ),
        scope_exclusion_tokens=tuple(
            sorted(
                {
                    token
                    for child in matching
                    for token in child.scope_exclusion_tokens
                }
            )
        ),
        perceptual_fingerprints=tuple(
            fingerprint_by_image[key]
            for key in sorted(fingerprint_by_image)
        ),
        identity_context_sha256=next(iter(identity_contexts)),
    )


@dataclass(frozen=True, slots=True)
class Loop9FullHistoryExclusionAuthority:
    """A durable chain from the complete source boundary to every child inventory."""

    source_boundary: Loop9ExclusionSourceBoundary
    child_inventories: tuple[Loop9DatasetExclusionInventory, ...]
    expected_current_build_sha256: str
    expected_settlement_contract_sha256: str
    expected_daily_contract_sha256: str
    expected_settlement_selection_sha256: str
    expected_daily_selection_sha256: str
    child_index_head_sha256: str
    canonical_sha256: str = field(init=False)
    _development_exclusions: Loop9DatasetExclusionInventory = field(init=False)
    _legacy_loop7_exclusions: Loop9DatasetExclusionInventory = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.source_boundary, Loop9ExclusionSourceBoundary):
            raise Loop9DatasetIsolationError(
                "full-history exclusion source boundary is invalid"
            )
        self.source_boundary.verify_integrity()
        for value, label in (
            (
                self.expected_current_build_sha256,
                "full-history current build SHA-256",
            ),
            (
                self.expected_settlement_contract_sha256,
                "full-history settlement contract SHA-256",
            ),
            (
                self.expected_daily_contract_sha256,
                "full-history daily contract SHA-256",
            ),
            (
                self.expected_settlement_selection_sha256,
                "full-history settlement selection SHA-256",
            ),
            (
                self.expected_daily_selection_sha256,
                "full-history daily selection SHA-256",
            ),
        ):
            _required_sha256(value, label=label)
        if (
            not isinstance(self.child_inventories, tuple)
            or not self.child_inventories
            or any(
                not isinstance(child, Loop9DatasetExclusionInventory)
                for child in self.child_inventories
            )
        ):
            raise Loop9DatasetIsolationError(
                "full-history exclusion child inventory is incomplete"
            )
        _required_sha256(
            self.child_index_head_sha256,
            label="full-history exclusion child index head SHA-256",
        )
        child_sha256s: set[str] = set()
        child_ids: set[str] = set()
        identity_contexts: set[str | None] = set()
        fingerprint_by_image: dict[str, ImagePerceptualFingerprint] = {}
        for child in self.child_inventories:
            child.verify_integrity()
            if (
                child.artifact_schema_version
                != EXCLUSION_INVENTORY_SCHEMA_VERSION
            ):
                raise Loop9DatasetIsolationError(
                    "full-history exclusion child uses a legacy schema"
                )
            if (
                child.canonical_sha256 in child_sha256s
                or child.inventory_id in child_ids
            ):
                raise Loop9DatasetIsolationError(
                    "full-history exclusion child inventory is duplicated"
                )
            child_sha256s.add(child.canonical_sha256)
            child_ids.add(child.inventory_id)
            identity_contexts.add(child.identity_context_sha256)
            for fingerprint in child.perceptual_fingerprints:
                existing = fingerprint_by_image.get(
                    fingerprint.content_sha256
                )
                if (
                    existing is not None
                    and existing.to_record() != fingerprint.to_record()
                ):
                    raise Loop9DatasetIsolationError(
                        "full-history exclusion children contain conflicting "
                        "perceptual fingerprints"
                    )
                fingerprint_by_image[
                    fingerprint.content_sha256
                ] = fingerprint
        if len(identity_contexts) != 1 or None in identity_contexts:
            raise Loop9DatasetIsolationError(
                "full-history exclusion children use different identity contexts"
            )
        development = _merged_exclusion_inventory(
            kind=ExclusionKind.DEVELOPMENT,
            children=self.child_inventories,
        )
        loop7 = _merged_exclusion_inventory(
            kind=ExclusionKind.LEGACY_LOOP7,
            children=self.child_inventories,
        )
        all_images = {
            image_sha256
            for child in self.child_inventories
            for image_sha256 in child.image_sha256s
        }
        all_identities = {
            identity_sha256
            for child in self.child_inventories
            for identity_sha256 in child.platform_identity_sha256s
        }
        source_fingerprints = {
            fingerprint.content_sha256: fingerprint.to_record()
            for fingerprint in self.source_boundary.perceptual_fingerprints
        }
        child_fingerprints = {
            key: fingerprint.to_record()
            for key, fingerprint in fingerprint_by_image.items()
        }
        source_images = set(self.source_boundary.image_sha256s)
        if (
            not source_images.issubset(all_images)
            or len(all_identities)
            < self.source_boundary.platform_identity_count
            or any(
                child_fingerprints.get(image_sha256)
                != source_fingerprints[image_sha256]
                for image_sha256 in source_images
            )
        ):
            raise Loop9DatasetIsolationError(
                "full-history exclusion children do not cover the complete "
                "source history"
            )
        child_nodes = loop9_exclusion_child_index_nodes(
            source_boundary=self.source_boundary,
            child_inventories=self.child_inventories,
            expected_current_build_sha256=(
                self.expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                self.expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                self.expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                self.expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                self.expected_daily_selection_sha256
            ),
        )
        if (
            not child_nodes
            or child_nodes[-1].canonical_sha256
            != self.child_index_head_sha256
        ):
            raise Loop9DatasetIsolationError(
                "full-history exclusion child index head is invalid"
            )
        object.__setattr__(self, "_development_exclusions", development)
        object.__setattr__(self, "_legacy_loop7_exclusions", loop7)
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    @property
    def child_inventory_count(self) -> int:
        return len(self.child_inventories)

    @property
    def child_index_length(self) -> int:
        return len(self.child_inventories)

    @property
    def source_inventory_high_watermark(self) -> int:
        return self.source_boundary.source_inventory_high_watermark

    @property
    def identity_context_sha256(self) -> str:
        context = self.child_inventories[0].identity_context_sha256
        if context is None:
            raise Loop9DatasetIsolationError(
                "full-history exclusion identity context is unavailable"
            )
        return context

    @property
    def development_exclusions(self) -> Loop9DatasetExclusionInventory:
        return self._development_exclusions

    @property
    def legacy_loop7_exclusions(self) -> Loop9DatasetExclusionInventory:
        return self._legacy_loop7_exclusions

    @property
    def development_exclusion_sha256(self) -> str:
        return self.development_exclusions.canonical_sha256

    @property
    def legacy_loop7_exclusion_sha256(self) -> str:
        return self.legacy_loop7_exclusions.canonical_sha256

    @property
    def source_completeness_sha256(self) -> str:
        return _canonical_sha256(
            {
                "child_inventory_bindings": self._child_bindings(),
                "child_index_head_sha256": self.child_index_head_sha256,
                "child_index_length": self.child_index_length,
                "source_boundary_sha256": (
                    self.source_boundary.canonical_sha256
                ),
                "source_inventory_high_watermark": (
                    self.source_inventory_high_watermark
                ),
            }
        )

    def _child_bindings(self) -> list[dict[str, object]]:
        nodes = loop9_exclusion_child_index_nodes(
            source_boundary=self.source_boundary,
            child_inventories=self.child_inventories,
            expected_current_build_sha256=(
                self.expected_current_build_sha256
            ),
            expected_settlement_contract_sha256=(
                self.expected_settlement_contract_sha256
            ),
            expected_daily_contract_sha256=(
                self.expected_daily_contract_sha256
            ),
            expected_settlement_selection_sha256=(
                self.expected_settlement_selection_sha256
            ),
            expected_daily_selection_sha256=(
                self.expected_daily_selection_sha256
            ),
        )
        return [
                {
                    "canonical_sha256": child.canonical_sha256,
                    "exclusion_kind": child.exclusion_kind.value,
                    "image_count": len(child.image_sha256s),
                    "inventory_id": child.inventory_id,
                    "perceptual_fingerprint_count": len(
                        child.perceptual_fingerprints
                    ),
                    "platform_identity_count": len(
                        child.platform_identity_sha256s
                    ),
                    "scope_exclusion_token_count": len(
                        child.scope_exclusion_tokens
                    ),
                    "index_node_sha256": node.canonical_sha256,
                    "sequence": node.sequence,
                }
                for child, node in zip(
                    self.child_inventories,
                    nodes,
                    strict=True,
                )
            ]

    def _canonical_payload(self) -> dict[str, object]:
        children = [
            child.to_payload() for child in self.child_inventories
        ]
        return {
            "child_inventory_bindings": self._child_bindings(),
            "child_inventory_count": self.child_inventory_count,
            "child_inventories": children,
            "child_index_head_sha256": self.child_index_head_sha256,
            "child_index_length": self.child_index_length,
            "development_exclusion_sha256": (
                self.development_exclusion_sha256
            ),
            "expected_current_build_sha256": (
                self.expected_current_build_sha256
            ),
            "expected_daily_contract_sha256": (
                self.expected_daily_contract_sha256
            ),
            "expected_daily_selection_sha256": (
                self.expected_daily_selection_sha256
            ),
            "expected_settlement_contract_sha256": (
                self.expected_settlement_contract_sha256
            ),
            "expected_settlement_selection_sha256": (
                self.expected_settlement_selection_sha256
            ),
            "identity_context_sha256": self.identity_context_sha256,
            "kind": "loop9_full_history_exclusion_authority",
            "legacy_loop7_exclusion_sha256": (
                self.legacy_loop7_exclusion_sha256
            ),
            "schema_version": (
                FULL_HISTORY_EXCLUSION_AUTHORITY_SCHEMA_VERSION
            ),
            "source_boundary": self.source_boundary.to_payload(),
            "source_completeness_sha256": (
                self.source_completeness_sha256
            ),
            "source_inventory_high_watermark": (
                self.source_inventory_high_watermark
            ),
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise Loop9DatasetIsolationError(
                "full-history exclusion authority integrity is invalid"
            )

    def verify_bindings(
        self,
        *,
        source_boundary: Loop9ExclusionSourceBoundary,
        expected_current_build_sha256: str,
        expected_settlement_contract_sha256: str,
        expected_daily_contract_sha256: str,
        expected_settlement_selection_sha256: str,
        expected_daily_selection_sha256: str,
    ) -> None:
        self.verify_integrity()
        source_boundary.verify_integrity()
        if (
            source_boundary.canonical_sha256
            != self.source_boundary.canonical_sha256
            or source_boundary.to_payload()
            != self.source_boundary.to_payload()
        ):
            raise Loop9DatasetIsolationError(
                "full-history exclusion source boundary does not match "
                "the expected source boundary"
            )
        expected = (
            expected_current_build_sha256,
            expected_settlement_contract_sha256,
            expected_daily_contract_sha256,
            expected_settlement_selection_sha256,
            expected_daily_selection_sha256,
        )
        actual = (
            self.expected_current_build_sha256,
            self.expected_settlement_contract_sha256,
            self.expected_daily_contract_sha256,
            self.expected_settlement_selection_sha256,
            self.expected_daily_selection_sha256,
        )
        if actual != expected:
            raise Loop9DatasetIsolationError(
                "full-history exclusion authority does not match the current "
                "build or contract authority"
            )

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> Loop9FullHistoryExclusionAuthority:
        raw = _mapping(value, label="full-history exclusion authority")
        expected = {
            "canonical_sha256",
            "child_inventory_bindings",
            "child_inventory_count",
            "child_inventories",
            "child_index_head_sha256",
            "child_index_length",
            "development_exclusion_sha256",
            "expected_current_build_sha256",
            "expected_daily_contract_sha256",
            "expected_daily_selection_sha256",
            "expected_settlement_contract_sha256",
            "expected_settlement_selection_sha256",
            "identity_context_sha256",
            "kind",
            "legacy_loop7_exclusion_sha256",
            "schema_version",
            "source_boundary",
            "source_completeness_sha256",
            "source_inventory_high_watermark",
        }
        if (
            set(raw) != expected
            or raw.get("schema_version")
            != FULL_HISTORY_EXCLUSION_AUTHORITY_SCHEMA_VERSION
            or raw.get("kind")
            != "loop9_full_history_exclusion_authority"
        ):
            raise Loop9DatasetIsolationError(
                "full-history exclusion authority contract is invalid"
            )
        child_count = raw.get("child_inventory_count")
        child_index_length = raw.get("child_index_length")
        high_watermark = raw.get("source_inventory_high_watermark")
        if (
            type(child_count) is not int
            or type(child_index_length) is not int
            or type(high_watermark) is not int
        ):
            raise Loop9DatasetIsolationError(
                "full-history exclusion authority counts are invalid"
            )
        authority = cls(
            source_boundary=Loop9ExclusionSourceBoundary.from_payload(
                raw.get("source_boundary")
            ),
            child_inventories=tuple(
                Loop9DatasetExclusionInventory.from_payload(child)
                for child in _sequence(
                    raw.get("child_inventories"),
                    label="full-history exclusion child inventories",
                )
            ),
            expected_current_build_sha256=_required_sha256(
                raw.get("expected_current_build_sha256"),
                label="full-history current build SHA-256",
            ),
            expected_settlement_contract_sha256=_required_sha256(
                raw.get("expected_settlement_contract_sha256"),
                label="full-history settlement contract SHA-256",
            ),
            expected_daily_contract_sha256=_required_sha256(
                raw.get("expected_daily_contract_sha256"),
                label="full-history daily contract SHA-256",
            ),
            expected_settlement_selection_sha256=_required_sha256(
                raw.get("expected_settlement_selection_sha256"),
                label="full-history settlement selection SHA-256",
            ),
            expected_daily_selection_sha256=_required_sha256(
                raw.get("expected_daily_selection_sha256"),
                label="full-history daily selection SHA-256",
            ),
            child_index_head_sha256=_required_sha256(
                raw.get("child_index_head_sha256"),
                label="full-history exclusion child index head SHA-256",
            ),
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="full-history exclusion authority canonical SHA-256",
        )
        if (
            declared != authority.canonical_sha256
            or dict(raw) != authority.to_payload()
            or child_count != authority.child_inventory_count
            or child_index_length != authority.child_index_length
            or high_watermark
            != authority.source_inventory_high_watermark
        ):
            raise Loop9DatasetIsolationError(
                "full-history exclusion authority integrity is invalid"
            )
        return authority


def build_loop9_full_history_exclusion_authority(
    *,
    source_boundary: Loop9ExclusionSourceBoundary,
    child_inventories: Sequence[Loop9DatasetExclusionInventory],
    expected_current_build_sha256: object,
    expected_settlement_contract_sha256: object,
    expected_daily_contract_sha256: object,
    expected_settlement_selection_sha256: object,
    expected_daily_selection_sha256: object,
) -> Loop9FullHistoryExclusionAuthority:
    if not isinstance(source_boundary, Loop9ExclusionSourceBoundary):
        raise Loop9DatasetIsolationError(
            "full-history exclusion source boundary is invalid"
        )
    normalized_children = tuple(child_inventories)
    build_sha256 = _required_sha256(
        expected_current_build_sha256,
        label="full-history current build SHA-256",
    )
    settlement_contract_sha256 = _required_sha256(
        expected_settlement_contract_sha256,
        label="full-history settlement contract SHA-256",
    )
    daily_contract_sha256 = _required_sha256(
        expected_daily_contract_sha256,
        label="full-history daily contract SHA-256",
    )
    settlement_selection_sha256 = _required_sha256(
        expected_settlement_selection_sha256,
        label="full-history settlement selection SHA-256",
    )
    daily_selection_sha256 = _required_sha256(
        expected_daily_selection_sha256,
        label="full-history daily selection SHA-256",
    )
    nodes = loop9_exclusion_child_index_nodes(
        source_boundary=source_boundary,
        child_inventories=normalized_children,
        expected_current_build_sha256=build_sha256,
        expected_settlement_contract_sha256=(
            settlement_contract_sha256
        ),
        expected_daily_contract_sha256=daily_contract_sha256,
        expected_settlement_selection_sha256=(
            settlement_selection_sha256
        ),
        expected_daily_selection_sha256=daily_selection_sha256,
    )
    if not nodes:
        raise Loop9DatasetIsolationError(
            "full-history exclusion child inventory is incomplete"
        )
    return Loop9FullHistoryExclusionAuthority(
        source_boundary=source_boundary,
        child_inventories=normalized_children,
        expected_current_build_sha256=build_sha256,
        expected_settlement_contract_sha256=settlement_contract_sha256,
        expected_daily_contract_sha256=daily_contract_sha256,
        expected_settlement_selection_sha256=(
            settlement_selection_sha256
        ),
        expected_daily_selection_sha256=daily_selection_sha256,
        child_index_head_sha256=nodes[-1].canonical_sha256,
    )


@dataclass(frozen=True, slots=True)
class Loop9DatasetBinding:
    dataset_kind: DatasetKind
    dataset_id: str
    manifest_sha256: str
    build_sha256: str
    contract_sha256: str
    contract_selection_sha256: str
    source_job_id: str
    source_snapshot_sha256: str
    identity_context_sha256: str | None
    entry_count: int
    image_count: int
    formal_selection_sha256: str | None
    locked_gate_evidence_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.dataset_kind, DatasetKind):
            raise Loop9DatasetIsolationError(
                "dataset isolation binding classification is invalid"
            )
        _required_sha256(
            self.identity_context_sha256,
            label="dataset isolation identity context SHA-256",
        )
        _required_sha256(
            self.contract_selection_sha256,
            label="dataset isolation contract selection SHA-256",
        )
        if self.dataset_kind in {
            DatasetKind.CURRENT_LOCKED_50,
            DatasetKind.REAL_SHADOW_30,
        }:
            _required_sha256(
                self.formal_selection_sha256,
                label="dataset isolation formal selection SHA-256",
            )
            if self.dataset_kind is DatasetKind.REAL_SHADOW_30:
                _required_sha256(
                    self.locked_gate_evidence_sha256,
                    label="dataset isolation current locked Gate SHA-256",
                )
            elif self.locked_gate_evidence_sha256 is not None:
                raise Loop9DatasetIsolationError(
                    "current_locked_50 isolation binding must not bind its own Gate"
                )
        elif (
            self.formal_selection_sha256 is not None
            or self.locked_gate_evidence_sha256 is not None
        ):
            raise Loop9DatasetIsolationError(
                "non-formal isolation binding must not bind a formal selection"
            )

    @classmethod
    def from_manifest(
        cls,
        manifest: Loop9DatasetManifest,
        *,
        contract_selection_sha256: str,
    ) -> Loop9DatasetBinding:
        return cls(
            dataset_kind=manifest.dataset_kind,
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            build_sha256=manifest.build_sha256,
            contract_sha256=manifest.contract_sha256,
            contract_selection_sha256=contract_selection_sha256,
            source_job_id=manifest.source_job_id,
            source_snapshot_sha256=manifest.source_snapshot_sha256,
            identity_context_sha256=manifest.identity_context_sha256,
            entry_count=len(manifest.entries),
            image_count=manifest.image_count,
            formal_selection_sha256=manifest.formal_selection_sha256,
            locked_gate_evidence_sha256=(
                manifest.locked_gate_evidence_sha256
            ),
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "build_sha256": self.build_sha256,
            "contract_sha256": self.contract_sha256,
            "contract_selection_sha256": self.contract_selection_sha256,
            "dataset_id": self.dataset_id,
            "dataset_kind": self.dataset_kind.value,
            "entry_count": self.entry_count,
            "formal_selection_sha256": self.formal_selection_sha256,
            "image_count": self.image_count,
            "identity_context_sha256": self.identity_context_sha256,
            "manifest_sha256": self.manifest_sha256,
            "locked_gate_evidence_sha256": (
                self.locked_gate_evidence_sha256
            ),
            "source_job_id": self.source_job_id,
            "source_snapshot_sha256": self.source_snapshot_sha256,
        }

    @classmethod
    def from_payload(cls, value: object) -> Loop9DatasetBinding:
        raw = _mapping(value, label="dataset isolation binding")
        expected = {
            "build_sha256",
            "contract_sha256",
            "contract_selection_sha256",
            "dataset_id",
            "dataset_kind",
            "entry_count",
            "formal_selection_sha256",
            "image_count",
            "identity_context_sha256",
            "manifest_sha256",
            "locked_gate_evidence_sha256",
            "source_job_id",
            "source_snapshot_sha256",
        }
        if set(raw) != expected:
            raise Loop9DatasetIsolationError(
                "dataset isolation binding contract is invalid"
            )
        raw_kind = raw.get("dataset_kind")
        if not isinstance(raw_kind, str):
            raise Loop9DatasetIsolationError(
                "dataset isolation binding classification is invalid"
            )
        try:
            dataset_kind = DatasetKind(raw_kind)
        except ValueError as exc:
            raise Loop9DatasetIsolationError(
                "dataset isolation binding classification is invalid"
            ) from exc
        entry_count = raw.get("entry_count")
        image_count = raw.get("image_count")
        if (
            type(entry_count) is not int
            or entry_count < 1
            or type(image_count) is not int
            or image_count < 0
        ):
            raise Loop9DatasetIsolationError(
                "dataset isolation binding counts are invalid"
            )
        return cls(
            dataset_kind=dataset_kind,
            dataset_id=_required_text(
                raw.get("dataset_id"),
                label="dataset isolation binding ID",
                maximum=100,
            ),
            manifest_sha256=_required_sha256(
                raw.get("manifest_sha256"),
                label="dataset isolation manifest SHA-256",
            ),
            build_sha256=_required_sha256(
                raw.get("build_sha256"),
                label="dataset isolation build SHA-256",
            ),
            contract_sha256=_required_sha256(
                raw.get("contract_sha256"),
                label="dataset isolation contract SHA-256",
            ),
            contract_selection_sha256=_required_sha256(
                raw.get("contract_selection_sha256"),
                label="dataset isolation contract selection SHA-256",
            ),
            source_job_id=_required_text(
                raw.get("source_job_id"),
                label="dataset isolation source Job ID",
                maximum=100,
            ),
            source_snapshot_sha256=_required_sha256(
                raw.get("source_snapshot_sha256"),
                label="dataset isolation source snapshot SHA-256",
            ),
            identity_context_sha256=(
                None
                if raw.get("identity_context_sha256") is None
                else _required_sha256(
                    raw.get("identity_context_sha256"),
                    label="dataset isolation identity context SHA-256",
                )
            ),
            entry_count=entry_count,
            image_count=image_count,
            formal_selection_sha256=(
                None
                if raw.get("formal_selection_sha256") is None
                else _required_sha256(
                    raw.get("formal_selection_sha256"),
                    label="dataset isolation formal selection SHA-256",
                )
            ),
            locked_gate_evidence_sha256=(
                None
                if raw.get("locked_gate_evidence_sha256") is None
                else _required_sha256(
                    raw.get("locked_gate_evidence_sha256"),
                    label="dataset isolation current locked Gate SHA-256",
                )
            ),
        )


@dataclass(frozen=True, slots=True)
class Loop9DatasetIsolationEvidence:
    dataset_bindings: tuple[Loop9DatasetBinding, ...]
    development_exclusion_sha256: str
    legacy_loop7_exclusion_sha256: str
    full_history_exclusion_authority_sha256: str
    exclusion_source_boundary_sha256: str
    source_inventory_high_watermark: int
    expected_current_build_sha256: str
    expected_settlement_contract_sha256: str
    expected_daily_contract_sha256: str
    expected_settlement_selection_sha256: str
    expected_daily_selection_sha256: str
    expected_identity_context_sha256: str
    perceptual_fingerprint_count: int
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if (
            not isinstance(self.dataset_bindings, tuple)
            or any(
                not isinstance(binding, Loop9DatasetBinding)
                for binding in self.dataset_bindings
            )
            or tuple(
                binding.dataset_kind for binding in self.dataset_bindings
            )
            != tuple(DatasetKind)
        ):
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence bindings are incomplete"
            )
        _required_sha256(
            self.development_exclusion_sha256,
            label="development exclusion SHA-256",
        )
        _required_sha256(
            self.legacy_loop7_exclusion_sha256,
            label="legacy Loop 7 exclusion SHA-256",
        )
        _required_sha256(
            self.full_history_exclusion_authority_sha256,
            label="full-history exclusion authority SHA-256",
        )
        _required_sha256(
            self.exclusion_source_boundary_sha256,
            label="exclusion source boundary SHA-256",
        )
        if (
            isinstance(self.source_inventory_high_watermark, bool)
            or not isinstance(self.source_inventory_high_watermark, int)
            or self.source_inventory_high_watermark < 1
        ):
            raise Loop9DatasetIsolationError(
                "source inventory high watermark is invalid"
            )
        _required_sha256(
            self.expected_current_build_sha256,
            label="expected current build SHA-256",
        )
        _required_sha256(
            self.expected_settlement_contract_sha256,
            label="expected settlement contract SHA-256",
        )
        _required_sha256(
            self.expected_daily_contract_sha256,
            label="expected daily contract SHA-256",
        )
        _required_sha256(
            self.expected_settlement_selection_sha256,
            label="expected settlement selection SHA-256",
        )
        _required_sha256(
            self.expected_daily_selection_sha256,
            label="expected daily selection SHA-256",
        )
        _required_sha256(
            self.expected_identity_context_sha256,
            label="expected identity context SHA-256",
        )
        binding_by_kind = {
            binding.dataset_kind: binding for binding in self.dataset_bindings
        }
        for kind in (
            DatasetKind.CURRENT_LOCKED_50,
            DatasetKind.REAL_SHADOW_30,
            DatasetKind.DAILY_VALIDATION,
        ):
            if (
                binding_by_kind[kind].build_sha256
                != self.expected_current_build_sha256
            ):
                raise Loop9DatasetIsolationError(
                    "dataset isolation evidence current build binding is invalid"
                )
        for kind in DatasetKind:
            if (
                binding_by_kind[kind].identity_context_sha256
                != self.expected_identity_context_sha256
            ):
                raise Loop9DatasetIsolationError(
                    "dataset isolation evidence identity context binding is invalid"
                )
        for kind in (
            DatasetKind.CURRENT_LOCKED_50,
            DatasetKind.REAL_SHADOW_30,
        ):
            if (
                binding_by_kind[kind].contract_sha256
                != self.expected_settlement_contract_sha256
            ):
                raise Loop9DatasetIsolationError(
                    "dataset isolation evidence settlement contract binding is invalid"
                )
            if (
                binding_by_kind[kind].contract_selection_sha256
                != self.expected_settlement_selection_sha256
            ):
                raise Loop9DatasetIsolationError(
                    "dataset isolation evidence settlement selection binding is invalid"
                )
        if (
            binding_by_kind[
                DatasetKind.DISCOVERY_DEVELOPMENT
            ].contract_selection_sha256
            != self.expected_settlement_selection_sha256
        ):
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence settlement selection binding is invalid"
            )
        if (
            binding_by_kind[DatasetKind.DAILY_VALIDATION].contract_sha256
            != self.expected_daily_contract_sha256
        ):
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence daily contract binding is invalid"
            )
        if (
            binding_by_kind[
                DatasetKind.DAILY_VALIDATION
            ].contract_selection_sha256
            != self.expected_daily_selection_sha256
        ):
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence daily selection binding is invalid"
            )
        if (
            isinstance(self.perceptual_fingerprint_count, bool)
            or self.perceptual_fingerprint_count < 0
        ):
            raise Loop9DatasetIsolationError(
                "perceptual fingerprint count is invalid"
            )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        binding_by_kind = {
            binding.dataset_kind: binding for binding in self.dataset_bindings
        }
        locked = binding_by_kind[DatasetKind.CURRENT_LOCKED_50]
        shadow = binding_by_kind[DatasetKind.REAL_SHADOW_30]
        return {
            "current_locked_image_count": locked.image_count,
            "dataset_bindings": [
                binding.to_payload() for binding in self.dataset_bindings
            ],
            "development_exclusion_sha256": (
                self.development_exclusion_sha256
            ),
            "exclusion_source_boundary_sha256": (
                self.exclusion_source_boundary_sha256
            ),
            "discovery_development_binding_policy": (
                "recorded_source_authority_only"
            ),
            "exact_identity_overlap_count": 0,
            "exact_image_overlap_count": 0,
            "expected_current_build_sha256": (
                self.expected_current_build_sha256
            ),
            "expected_daily_contract_sha256": (
                self.expected_daily_contract_sha256
            ),
            "expected_daily_selection_sha256": (
                self.expected_daily_selection_sha256
            ),
            "expected_identity_context_sha256": (
                self.expected_identity_context_sha256
            ),
            "expected_settlement_contract_sha256": (
                self.expected_settlement_contract_sha256
            ),
            "expected_settlement_selection_sha256": (
                self.expected_settlement_selection_sha256
            ),
            "full_history_exclusion_authority_sha256": (
                self.full_history_exclusion_authority_sha256
            ),
            "isolation_passed": True,
            "legacy_loop7_exclusion_sha256": (
                self.legacy_loop7_exclusion_sha256
            ),
            "perceptual_fingerprint_count": self.perceptual_fingerprint_count,
            "perceptual_overlap_count": 0,
            "real_shadow_entry_count": shadow.entry_count,
            "schema_version": ISOLATION_EVIDENCE_SCHEMA_VERSION,
            "source_inventory_high_watermark": (
                self.source_inventory_high_watermark
            ),
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    @classmethod
    def from_payload(
        cls,
        value: object,
    ) -> Loop9DatasetIsolationEvidence:
        raw = _mapping(value, label="dataset isolation evidence")
        if raw.get("schema_version") == 1:
            raise Loop9DatasetIsolationError(
                "legacy dataset isolation evidence is readable only as history "
                "and cannot satisfy the current identity or authority gate"
            )
        expected = {
            "canonical_sha256",
            "current_locked_image_count",
            "dataset_bindings",
            "development_exclusion_sha256",
            "discovery_development_binding_policy",
            "exclusion_source_boundary_sha256",
            "exact_identity_overlap_count",
            "exact_image_overlap_count",
            "expected_current_build_sha256",
            "expected_daily_contract_sha256",
            "expected_daily_selection_sha256",
            "expected_identity_context_sha256",
            "expected_settlement_contract_sha256",
            "expected_settlement_selection_sha256",
            "full_history_exclusion_authority_sha256",
            "isolation_passed",
            "legacy_loop7_exclusion_sha256",
            "perceptual_fingerprint_count",
            "perceptual_overlap_count",
            "real_shadow_entry_count",
            "schema_version",
            "source_inventory_high_watermark",
        }
        if (
            set(raw) != expected
            or raw.get("schema_version") != ISOLATION_EVIDENCE_SCHEMA_VERSION
            or raw.get("isolation_passed") is not True
            or raw.get("discovery_development_binding_policy")
            != "recorded_source_authority_only"
            or raw.get("exact_identity_overlap_count") != 0
            or raw.get("exact_image_overlap_count") != 0
            or raw.get("perceptual_overlap_count") != 0
        ):
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence contract is invalid"
            )
        fingerprint_count = raw.get("perceptual_fingerprint_count")
        if type(fingerprint_count) is not int or fingerprint_count < 0:
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence fingerprint count is invalid"
            )
        high_watermark = raw.get("source_inventory_high_watermark")
        if type(high_watermark) is not int:
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence source high-water mark is invalid"
            )
        evidence = cls(
            dataset_bindings=tuple(
                Loop9DatasetBinding.from_payload(binding)
                for binding in _sequence(
                    raw.get("dataset_bindings"),
                    label="dataset isolation bindings",
                )
            ),
            development_exclusion_sha256=_required_sha256(
                raw.get("development_exclusion_sha256"),
                label="development exclusion SHA-256",
            ),
            legacy_loop7_exclusion_sha256=_required_sha256(
                raw.get("legacy_loop7_exclusion_sha256"),
                label="legacy Loop 7 exclusion SHA-256",
            ),
            full_history_exclusion_authority_sha256=_required_sha256(
                raw.get("full_history_exclusion_authority_sha256"),
                label="full-history exclusion authority SHA-256",
            ),
            exclusion_source_boundary_sha256=_required_sha256(
                raw.get("exclusion_source_boundary_sha256"),
                label="exclusion source boundary SHA-256",
            ),
            source_inventory_high_watermark=high_watermark,
            expected_current_build_sha256=_required_sha256(
                raw.get("expected_current_build_sha256"),
                label="expected current build SHA-256",
            ),
            expected_settlement_contract_sha256=_required_sha256(
                raw.get("expected_settlement_contract_sha256"),
                label="expected settlement contract SHA-256",
            ),
            expected_daily_contract_sha256=_required_sha256(
                raw.get("expected_daily_contract_sha256"),
                label="expected daily contract SHA-256",
            ),
            expected_settlement_selection_sha256=_required_sha256(
                raw.get("expected_settlement_selection_sha256"),
                label="expected settlement selection SHA-256",
            ),
            expected_daily_selection_sha256=_required_sha256(
                raw.get("expected_daily_selection_sha256"),
                label="expected daily selection SHA-256",
            ),
            expected_identity_context_sha256=_required_sha256(
                raw.get("expected_identity_context_sha256"),
                label="expected identity context SHA-256",
            ),
            perceptual_fingerprint_count=fingerprint_count,
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="dataset isolation evidence canonical SHA-256",
        )
        if (
            evidence.canonical_sha256 != declared
            or evidence.to_payload() != dict(raw)
        ):
            raise Loop9DatasetIsolationError(
                "dataset isolation evidence integrity is invalid"
            )
        return evidence


def _unique_fingerprints(
    values: Iterable[ImagePerceptualFingerprint | None],
) -> tuple[ImagePerceptualFingerprint, ...]:
    fingerprints: dict[str, ImagePerceptualFingerprint] = {}
    for value in values:
        if value is None:
            continue
        existing = fingerprints.setdefault(value.content_sha256, value)
        if existing.canonical_sha256 != value.canonical_sha256:
            raise Loop9DatasetIsolationError(
                "one image has conflicting perceptual fingerprints"
            )
    return tuple(
        fingerprints[image_sha256] for image_sha256 in sorted(fingerprints)
    )


def _expected_kind(
    manifest: object,
    *,
    kind: DatasetKind,
) -> Loop9DatasetManifest:
    if (
        not isinstance(manifest, Loop9DatasetManifest)
        or manifest.dataset_kind is not kind
    ):
        raise Loop9DatasetIsolationError(
            f"{kind.value} dataset classification is invalid"
        )
    manifest.verify_integrity()
    return manifest


def _expected_exclusion_kind(
    inventory: object,
    *,
    kind: ExclusionKind,
) -> Loop9DatasetExclusionInventory:
    if (
        not isinstance(inventory, Loop9DatasetExclusionInventory)
        or inventory.exclusion_kind is not kind
    ):
        raise Loop9DatasetIsolationError(
            f"{kind.value} exclusion inventory classification is invalid"
        )
    inventory.verify_integrity()
    if set(inventory.image_sha256s) != {
        fingerprint.content_sha256
        for fingerprint in inventory.perceptual_fingerprints
    }:
        raise Loop9DatasetIsolationError(
            f"{kind.value} requires a perceptual fingerprint "
            "for every excluded image"
        )
    return inventory


def _require_formal_authority_bindings(
    *,
    discovery: Loop9DatasetManifest,
    locked: Loop9DatasetManifest,
    shadow: Loop9DatasetManifest,
    daily: Loop9DatasetManifest,
    expected_current_build_sha256: object,
    expected_settlement_contract_sha256: object,
    expected_daily_contract_sha256: object,
    expected_settlement_selection_sha256: object,
    expected_daily_selection_sha256: object,
) -> tuple[str, str, str, str, str, str]:
    current_build = _required_sha256(
        expected_current_build_sha256,
        label="expected current build SHA-256",
    )
    settlement_contract = _required_sha256(
        expected_settlement_contract_sha256,
        label="expected settlement contract SHA-256",
    )
    daily_contract = _required_sha256(
        expected_daily_contract_sha256,
        label="expected daily contract SHA-256",
    )
    settlement_selection = _required_sha256(
        expected_settlement_selection_sha256,
        label="expected settlement selection SHA-256",
    )
    daily_selection = _required_sha256(
        expected_daily_selection_sha256,
        label="expected daily selection SHA-256",
    )
    for manifest in (locked, shadow, daily):
        if manifest.build_sha256 != current_build:
            raise Loop9DatasetIsolationError(
                f"{manifest.dataset_kind.value} is not bound to the expected current build"
            )
    for manifest in (locked, shadow):
        if manifest.contract_sha256 != settlement_contract:
            raise Loop9DatasetIsolationError(
                f"{manifest.dataset_kind.value} is not bound to the expected "
                "settlement contract"
            )
    if daily.contract_sha256 != daily_contract:
        raise Loop9DatasetIsolationError(
            "daily_validation is not bound to the expected daily contract"
        )
    identity_context = locked.identity_context_sha256
    if identity_context is None:
        raise Loop9DatasetIsolationError(
            "current_locked_50 is missing the formal identity context"
        )
    for manifest in (discovery, shadow, daily):
        if manifest.identity_context_sha256 != identity_context:
            raise Loop9DatasetIsolationError(
                f"{manifest.dataset_kind.value} is not bound to the same "
                "formal identity context"
            )
    return (
        current_build,
        settlement_contract,
        daily_contract,
        settlement_selection,
        daily_selection,
        identity_context,
    )


def _require_formal_perceptual_fingerprints(
    manifests: Sequence[Loop9DatasetManifest],
) -> None:
    for manifest in manifests:
        missing_count = sum(
            image.perceptual_fingerprint is None
            for entry in manifest.entries
            for image in entry.images
        )
        if missing_count:
            raise Loop9DatasetIsolationError(
                f"{manifest.dataset_kind.value} requires a valid perceptual "
                "fingerprint for every image participating in cross-dataset exclusion"
            )


def _reject_exact_dataset_overlaps(
    manifests: Sequence[Loop9DatasetManifest],
) -> None:
    for first, second in combinations(manifests, 2):
        if first.platform_identity_sha256s.intersection(
            second.platform_identity_sha256s
        ):
            raise Loop9DatasetIsolationError(
                "exact platform identity overlap exists between dataset classes"
            )
        if first.image_sha256s.intersection(second.image_sha256s):
            raise Loop9DatasetIsolationError(
                "exact image overlap exists between dataset classes"
            )


def _reject_exclusion_overlaps(
    manifests: Sequence[Loop9DatasetManifest],
    inventories: Sequence[Loop9DatasetExclusionInventory],
) -> None:
    for manifest in manifests:
        for inventory in inventories:
            if manifest.platform_identity_sha256s.intersection(
                inventory.platform_identity_sha256s
            ):
                raise Loop9DatasetIsolationError(
                    "formal dataset overlaps a platform identity exclusion"
                )
            if manifest.image_sha256s.intersection(inventory.image_sha256s):
                raise Loop9DatasetIsolationError(
                    "formal dataset overlaps an image exclusion"
                )


def _reject_perceptual_overlap(
    *,
    first_label: str,
    first: Sequence[ImagePerceptualFingerprint],
    second_label: str,
    second: Sequence[ImagePerceptualFingerprint],
) -> None:
    if not first or not second:
        return
    try:
        for fingerprint in first:
            if find_near_duplicate_candidates(
                probe=fingerprint,
                inventory=second,
            ):
                raise Loop9DatasetIsolationError(
                    "perceptual near-overlap exists between "
                    f"{first_label} and {second_label}"
                )
    except ImageSimilarityContractError as exc:
        raise Loop9DatasetIsolationError(
            "perceptual overlap evidence is invalid"
        ) from exc


def _reject_all_perceptual_overlaps(
    *,
    manifests: Sequence[Loop9DatasetManifest],
    formal_manifests: Sequence[Loop9DatasetManifest],
    inventories: Sequence[Loop9DatasetExclusionInventory],
) -> None:
    for first, second in combinations(manifests, 2):
        _reject_perceptual_overlap(
            first_label=first.dataset_kind.value,
            first=first.perceptual_fingerprints,
            second_label=second.dataset_kind.value,
            second=second.perceptual_fingerprints,
        )
    locked = next(
        manifest
        for manifest in manifests
        if manifest.dataset_kind is DatasetKind.CURRENT_LOCKED_50
    )
    locked_fingerprints = locked.perceptual_fingerprints
    for index, fingerprint in enumerate(locked_fingerprints):
        _reject_perceptual_overlap(
            first_label=locked.dataset_kind.value,
            first=(fingerprint,),
            second_label=locked.dataset_kind.value,
            second=locked_fingerprints[index + 1 :],
        )
    for manifest in formal_manifests:
        for inventory in inventories:
            _reject_perceptual_overlap(
                first_label=manifest.dataset_kind.value,
                first=manifest.perceptual_fingerprints,
                second_label=inventory.exclusion_kind.value,
                second=inventory.perceptual_fingerprints,
            )


def validate_loop9_dataset_isolation(
    *,
    expected_current_build_sha256: object,
    expected_settlement_contract_sha256: object,
    expected_daily_contract_sha256: object,
    expected_settlement_selection_sha256: object,
    expected_daily_selection_sha256: object,
    discovery_development: object,
    current_locked_50: object,
    real_shadow_30: object,
    daily_validation: object,
    development_exclusions: object,
    legacy_loop7_exclusions: object,
    expected_exclusion_source_boundary: object,
    full_history_exclusion_authority: object,
) -> Loop9DatasetIsolationEvidence:
    """Validate all Loop 9 dataset boundaries without reading business systems."""

    discovery = _expected_kind(
        discovery_development,
        kind=DatasetKind.DISCOVERY_DEVELOPMENT,
    )
    locked = _expected_kind(
        current_locked_50,
        kind=DatasetKind.CURRENT_LOCKED_50,
    )
    shadow = _expected_kind(
        real_shadow_30,
        kind=DatasetKind.REAL_SHADOW_30,
    )
    daily = _expected_kind(
        daily_validation,
        kind=DatasetKind.DAILY_VALIDATION,
    )
    development = _expected_exclusion_kind(
        development_exclusions,
        kind=ExclusionKind.DEVELOPMENT,
    )
    loop7 = _expected_exclusion_kind(
        legacy_loop7_exclusions,
        kind=ExclusionKind.LEGACY_LOOP7,
    )
    if not isinstance(
        expected_exclusion_source_boundary,
        Loop9ExclusionSourceBoundary,
    ):
        raise Loop9DatasetIsolationError(
            "expected full-history exclusion source boundary is invalid"
        )
    if not isinstance(
        full_history_exclusion_authority,
        Loop9FullHistoryExclusionAuthority,
    ):
        raise Loop9DatasetIsolationError(
            "full-history exclusion authority is required"
        )
    full_history_exclusion_authority.verify_bindings(
        source_boundary=expected_exclusion_source_boundary,
        expected_current_build_sha256=_required_sha256(
            expected_current_build_sha256,
            label="expected current build SHA-256",
        ),
        expected_settlement_contract_sha256=_required_sha256(
            expected_settlement_contract_sha256,
            label="expected settlement contract SHA-256",
        ),
        expected_daily_contract_sha256=_required_sha256(
            expected_daily_contract_sha256,
            label="expected daily contract SHA-256",
        ),
        expected_settlement_selection_sha256=_required_sha256(
            expected_settlement_selection_sha256,
            label="expected settlement selection SHA-256",
        ),
        expected_daily_selection_sha256=_required_sha256(
            expected_daily_selection_sha256,
            label="expected daily selection SHA-256",
        ),
    )
    for inventory in (development, loop7):
        if (
            inventory.artifact_schema_version
            != EXCLUSION_INVENTORY_SCHEMA_VERSION
        ):
            raise Loop9DatasetIsolationError(
                "legacy exclusion inventory identity evidence cannot satisfy "
                "the current formal gate"
            )
        if (
            inventory.identity_context_sha256
            != full_history_exclusion_authority.identity_context_sha256
        ):
            raise Loop9DatasetIsolationError(
                f"{inventory.exclusion_kind.value} exclusion inventory is "
                "not bound to the full-history identity context"
            )
    if (
        development.canonical_sha256
        != full_history_exclusion_authority.development_exclusion_sha256
        or development.to_payload()
        != full_history_exclusion_authority.development_exclusions.to_payload()
        or loop7.canonical_sha256
        != full_history_exclusion_authority.legacy_loop7_exclusion_sha256
        or loop7.to_payload()
        != full_history_exclusion_authority.legacy_loop7_exclusions.to_payload()
    ):
        raise Loop9DatasetIsolationError(
            "caller exclusion inventory does not match the full-history "
            "exclusion authority"
        )
    (
        current_build_sha256,
        settlement_contract_sha256,
        daily_contract_sha256,
        settlement_selection_sha256,
        daily_selection_sha256,
        identity_context_sha256,
    ) = _require_formal_authority_bindings(
        discovery=discovery,
        locked=locked,
        shadow=shadow,
        daily=daily,
        expected_current_build_sha256=expected_current_build_sha256,
        expected_settlement_contract_sha256=(
            expected_settlement_contract_sha256
        ),
        expected_daily_contract_sha256=expected_daily_contract_sha256,
        expected_settlement_selection_sha256=(
            expected_settlement_selection_sha256
        ),
        expected_daily_selection_sha256=(
            expected_daily_selection_sha256
        ),
    )

    manifests = (discovery, locked, shadow, daily)
    formal_manifests = (locked, shadow, daily)
    inventories = (development, loop7)
    for inventory in inventories:
        if inventory.artifact_schema_version != (
            EXCLUSION_INVENTORY_SCHEMA_VERSION
        ):
            raise Loop9DatasetIsolationError(
                "legacy exclusion inventory identity evidence cannot satisfy "
                "the current formal gate"
            )
        if inventory.identity_context_sha256 != identity_context_sha256:
            raise Loop9DatasetIsolationError(
                f"{inventory.exclusion_kind.value} exclusion inventory is "
                "not bound to the same identity context"
            )
    _require_formal_perceptual_fingerprints(formal_manifests)
    _reject_exact_dataset_overlaps(manifests)
    _reject_exclusion_overlaps(formal_manifests, inventories)

    excluded_scopes = (
        discovery.scope_exclusion_tokens
        | frozenset(development.scope_exclusion_tokens)
    )
    for manifest in formal_manifests:
        source_scope = discovery_scope_exclusion_token(
            source_job_id=manifest.source_job_id,
            source_snapshot_sha256=manifest.source_snapshot_sha256,
        )
        if source_scope in excluded_scopes:
            raise Loop9DatasetIsolationError(
                "formal dataset overlaps a conservative discovery scope exclusion"
            )

    _reject_all_perceptual_overlaps(
        manifests=manifests,
        formal_manifests=formal_manifests,
        inventories=inventories,
    )
    fingerprint_count = sum(
        len(manifest.perceptual_fingerprints) for manifest in manifests
    ) + sum(len(inventory.perceptual_fingerprints) for inventory in inventories)
    return Loop9DatasetIsolationEvidence(
        dataset_bindings=tuple(
            Loop9DatasetBinding.from_manifest(
                manifest,
                contract_selection_sha256=(
                    daily_selection_sha256
                    if manifest.dataset_kind
                    is DatasetKind.DAILY_VALIDATION
                    else settlement_selection_sha256
                ),
            )
            for manifest in manifests
        ),
        development_exclusion_sha256=development.canonical_sha256,
        legacy_loop7_exclusion_sha256=loop7.canonical_sha256,
        full_history_exclusion_authority_sha256=(
            full_history_exclusion_authority.canonical_sha256
        ),
        exclusion_source_boundary_sha256=(
            expected_exclusion_source_boundary.canonical_sha256
        ),
        source_inventory_high_watermark=(
            expected_exclusion_source_boundary.source_inventory_high_watermark
        ),
        expected_current_build_sha256=current_build_sha256,
        expected_settlement_contract_sha256=settlement_contract_sha256,
        expected_daily_contract_sha256=daily_contract_sha256,
        expected_settlement_selection_sha256=(
            settlement_selection_sha256
        ),
        expected_daily_selection_sha256=daily_selection_sha256,
        expected_identity_context_sha256=identity_context_sha256,
        perceptual_fingerprint_count=fingerprint_count,
    )


def parse_loop9_dataset_manifest(value: object) -> Loop9DatasetManifest:
    return Loop9DatasetManifest.from_payload(value)


def parse_loop9_exclusion_inventory(
    value: object,
) -> Loop9DatasetExclusionInventory:
    return Loop9DatasetExclusionInventory.from_payload(value)


def parse_loop9_exclusion_source_boundary(
    value: object,
) -> Loop9ExclusionSourceBoundary:
    return Loop9ExclusionSourceBoundary.from_payload(value)


def parse_loop9_full_history_exclusion_authority(
    value: object,
) -> Loop9FullHistoryExclusionAuthority:
    return Loop9FullHistoryExclusionAuthority.from_payload(value)


def exclusion_source_boundary_from_formal_development_authority(
    value: object,
) -> Loop9ExclusionSourceBoundary:
    from dahe.application.template_studio.formal_development_authority import (
        FormalDevelopmentAuthority,
    )

    if not isinstance(value, FormalDevelopmentAuthority):
        raise Loop9DatasetIsolationError(
            "formal development source authority is invalid"
        )
    fingerprints = tuple(
        sorted(
            (
                persisted.to_image_fingerprint()
                for persisted in value.perceptual_fingerprints
            ),
            key=lambda fingerprint: fingerprint.content_sha256,
        )
    )
    return Loop9ExclusionSourceBoundary(
        source_authority_sha256=value.authority_sha256,
        source_exclusion_snapshot_sha256=(
            value.exclusion_snapshot.canonical_sha256
        ),
        source_inventory_high_watermark=value.inventory_high_watermark,
        image_sha256s=tuple(sorted(value.image_sha256s)),
        platform_identity_count=len(value.waybill_identity_sha256s),
        perceptual_fingerprints=fingerprints,
    )


def parse_loop9_dataset_isolation_evidence(
    value: object,
) -> Loop9DatasetIsolationEvidence:
    return Loop9DatasetIsolationEvidence.from_payload(value)


def _load_json(path: Path, *, label: str) -> object:
    if not isinstance(path, Path) or not path.is_absolute() or path.is_symlink():
        raise Loop9DatasetIsolationError(f"{label} path is unsafe")
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_file() or resolved.stat().st_size > _MAX_JSON_BYTES:
            raise Loop9DatasetIsolationError(f"{label} file is invalid")
        content = resolved.read_bytes()
    except OSError as exc:
        raise Loop9DatasetIsolationError(f"{label} file is unavailable") from exc
    if not content:
        raise Loop9DatasetIsolationError(f"{label} file is empty")
    try:
        return json.loads(
            content.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_json_keys,
        )
    except Loop9DatasetIsolationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Loop9DatasetIsolationError(f"{label} file is not UTF-8 JSON") from exc


def load_loop9_dataset_manifest(path: Path) -> Loop9DatasetManifest:
    return parse_loop9_dataset_manifest(
        _load_json(path, label="dataset manifest")
    )


def load_loop9_exclusion_inventory(
    path: Path,
) -> Loop9DatasetExclusionInventory:
    return parse_loop9_exclusion_inventory(
        _load_json(path, label="exclusion inventory")
    )


def load_loop9_full_history_exclusion_authority(
    path: Path,
) -> Loop9FullHistoryExclusionAuthority:
    return parse_loop9_full_history_exclusion_authority(
        _load_json(path, label="full-history exclusion authority")
    )


def load_loop9_dataset_isolation_evidence(
    path: Path,
) -> Loop9DatasetIsolationEvidence:
    return parse_loop9_dataset_isolation_evidence(
        _load_json(path, label="dataset isolation evidence")
    )
