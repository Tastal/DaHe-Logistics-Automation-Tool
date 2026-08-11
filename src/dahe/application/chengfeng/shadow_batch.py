from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import Protocol, cast

from dahe.application.chengfeng.durable_capture import (
    DurableCaptureCheckpoint,
    PersistedTicketImage,
)
from dahe.jobs.specs import ScheduledJobSpec, ScheduledWorkItemSpec
from dahe.ports.chengfeng import (
    CURRENT_PENDING_SETTLEMENT_SCOPE,
    HISTORICAL_SETTLED_SCOPE,
    ChengfengStage,
)
from dahe.verification.image_similarity import (
    ImagePerceptualFingerprint,
    ImageSimilarityContractError,
    build_image_fingerprint,
)

SCHEMA_VERSION = 2
LEGACY_SCHEMA_VERSION = 1
SOURCE_KIND = "chengfeng_shadow"
HISTORICAL_CAPTURE_PAGE_SIZE = 100
HISTORICAL_CAPTURE_MAX_PAGES = 2
HISTORICAL_CAPTURE_MAX_ITEMS = (
    HISTORICAL_CAPTURE_PAGE_SIZE * HISTORICAL_CAPTURE_MAX_PAGES
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PLAIN_WEIGHT = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_MAX_WEIGHT_LENGTH = 32


class ChengfengShadowBatchContractError(ValueError):
    """Raised when captured evidence cannot safely become a formal audit batch."""


class ShadowBatchTargetKind(StrEnum):
    CURRENT_LOCKED_50 = "current_locked_50"
    REAL_SHADOW_30 = "real_shadow_30"
    OPERATIONAL_COMPAT = "operational_compat"

    @property
    def expected_count(self) -> int | None:
        if self is self.CURRENT_LOCKED_50:
            return 50
        if self is self.REAL_SHADOW_30:
            return 30
        return None


class SafeImageReader(Protocol):
    """Read bytes only after the caller has applied its local path policy."""

    def read_verified_image(
        self,
        *,
        relative_path: str,
        expected_sha256: str,
    ) -> bytes: ...


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _required_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ChengfengShadowBatchContractError(
            f"{label} must be a lowercase SHA-256"
        )
    return value


def _required_text(value: object, *, label: str, maximum: int = 200) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ChengfengShadowBatchContractError(f"{label} is invalid")
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise ChengfengShadowBatchContractError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _array(value: object, *, label: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise ChengfengShadowBatchContractError(f"{label} must be an array")
    return cast(Sequence[object], value)


def _validate_shadow_request_audit(
    *,
    manifest: ChengfengShadowBatchManifest,
) -> dict[str, object]:
    assert manifest.request_audit_sha256 is not None
    assert manifest.request_audit_counts is not None
    assert manifest.source_capture_sha256 is not None
    _required_sha256(
        manifest.source_capture_sha256,
        label="source capture SHA-256",
    )
    audit_sha256 = _required_sha256(
        manifest.request_audit_sha256,
        label="request audit SHA-256",
    )
    raw = _mapping(
        manifest.request_audit_counts,
        label="request audit counts",
    )
    if (
        _canonical_sha256(raw) != audit_sha256
        or raw.get("kind") != "loop9_platform_read_audit"
        or raw.get("schema_version") != 1
        or raw.get("purpose") != manifest.target_kind.value
        or raw.get("platform_write_request_count") != 0
        or raw.get("redirect_count") != 0
    ):
        raise ChengfengShadowBatchContractError(
            "shadow batch request audit binding is invalid"
        )
    authority = _mapping(
        raw.get("authority"),
        label="request audit authority",
    )
    if (
        authority.get("build_sha256") != manifest.source_build_sha256
        or authority.get("settlement_contract_sha256")
        != manifest.contract_canonical_sha256
        or authority.get("settlement_contract_selection_sha256")
        != manifest.contract_selection_sha256
        or authority.get("daily_contract_sha256") is not None
        or authority.get("daily_contract_selection_sha256") is not None
    ):
        raise ChengfengShadowBatchContractError(
            "shadow batch request audit authority changed"
        )
    source_jobs = {source.job_id for source in manifest.sources}
    if (
        len(source_jobs) != 1
        or raw.get("job_id_sha256")
        != hashlib.sha256(next(iter(source_jobs)).encode("utf-8")).hexdigest()
    ):
        raise ChengfengShadowBatchContractError(
            "shadow batch request audit job identity changed"
        )
    request_counts = _mapping(
        raw.get("request_counts"),
        label="request audit counts",
    )
    expected = _mapping(
        raw.get("expected_succeeded_operations"),
        label="expected request audit counts",
    )
    operations = _mapping(
        raw.get("operation_counts"),
        label="request audit operation counts",
    )
    if (
        request_counts.get("denied") != 0
        or expected.get("list_waybills") != len(manifest.sources)
        or type(expected.get("get_waybill_detail")) is not int
        or cast(int, expected.get("get_waybill_detail"))
        < len(manifest.items)
        or type(expected.get("download_ticket_image")) is not int
        or cast(int, expected.get("download_ticket_image"))
        < len(manifest.items) * 2
    ):
        raise ChengfengShadowBatchContractError(
            "shadow batch request audit counts changed"
        )
    for operation in (
        "list_waybills",
        "get_waybill_detail",
        "download_ticket_image",
    ):
        counts = _mapping(
            operations.get(operation),
            label="request audit operation counts",
        )
        if (
            counts.get("succeeded") != expected.get(operation)
            or counts.get("denied") != 0
            or counts.get("redirect") != 0
        ):
            raise ChengfengShadowBatchContractError(
                "shadow batch request audit counts changed"
            )
    return cast(
        dict[str, object],
        json.loads(_canonical_json(raw)),
    )


def _required_positive_int(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ChengfengShadowBatchContractError(f"{label} must be positive")
    return value


def _content_addressed_path(sha256: str) -> str:
    return f"sha256/{sha256[:2]}/{sha256[2:4]}/{sha256}.blob"


def _required_weight(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_WEIGHT_LENGTH
        or _PLAIN_WEIGHT.fullmatch(value) is None
    ):
        raise ChengfengShadowBatchContractError(f"{label} weight is invalid")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise ChengfengShadowBatchContractError(
            f"{label} weight is invalid"
        ) from exc
    if not parsed.is_finite() or parsed < 0:
        raise ChengfengShadowBatchContractError(f"{label} weight is invalid")
    return value


def chengfeng_shadow_identity_context_sha256(
    *,
    salt: bytes,
    namespace: str,
) -> str:
    """Return the irreversible context binding used by shadow manifests."""

    return hashlib.sha256(
        b"dahe:chengfeng-shadow:identity-context:v1\0"
        + namespace.encode("utf-8")
        + b"\0"
        + hashlib.sha256(salt).digest()
    ).hexdigest()


def chengfeng_shadow_identity_digest(
    *,
    salt: bytes,
    namespace: str,
    field_name: str,
    value: str,
) -> str:
    """Return one irreversible identity digest used by shadow manifests."""

    identity = _required_text(
        value,
        label=f"{field_name} platform identity",
        maximum=500,
    )
    return hmac.new(
        salt,
        (
            "dahe:chengfeng-shadow:platform-identity:v1\0"
            f"{namespace}\0{field_name}\0{identity}"
        ).encode(),
        hashlib.sha256,
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ShadowCaptureBinding:
    checkpoint: DurableCaptureCheckpoint
    access_window_id: str
    source_build_sha256: str
    contract_canonical_sha256: str
    contract_file_sha256: str
    contract_selection_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.checkpoint, DurableCaptureCheckpoint):
            raise ChengfengShadowBatchContractError(
                "capture binding checkpoint is invalid"
            )
        _required_text(
            self.access_window_id,
            label="source access-window ID",
        )
        _required_sha256(
            self.source_build_sha256,
            label="source build SHA-256",
        )
        _required_sha256(
            self.contract_canonical_sha256,
            label="contract canonical SHA-256",
        )
        _required_sha256(
            self.contract_file_sha256,
            label="contract file SHA-256",
        )
        _required_sha256(
            self.contract_selection_sha256,
            label="contract selection SHA-256",
        )


@dataclass(frozen=True, slots=True)
class ShadowBatchSource:
    access_window_id: str
    job_id: str
    capture_id: str
    scope: str
    page_number: int
    page_size: int
    checkpoint_sha256: str

    def __post_init__(self) -> None:
        for label, value in (
            ("source access-window ID", self.access_window_id),
            ("source job ID", self.job_id),
            ("source capture ID", self.capture_id),
            ("source scope", self.scope),
        ):
            _required_text(value, label=label)
        _required_positive_int(self.page_number, label="source page number")
        _required_positive_int(self.page_size, label="source page size")
        _required_sha256(
            self.checkpoint_sha256,
            label="source checkpoint SHA-256",
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "access_window_id": self.access_window_id,
            "capture_id": self.capture_id,
            "checkpoint_sha256": self.checkpoint_sha256,
            "job_id": self.job_id,
            "page_number": self.page_number,
            "page_size": self.page_size,
            "scope": self.scope,
        }

    @classmethod
    def from_payload(cls, value: object) -> ShadowBatchSource:
        raw = _mapping(value, label="shadow batch source")
        expected = {
            "access_window_id",
            "capture_id",
            "checkpoint_sha256",
            "job_id",
            "page_number",
            "page_size",
            "scope",
        }
        if set(raw) != expected:
            raise ChengfengShadowBatchContractError(
                "shadow batch source contract is invalid"
            )
        return cls(
            access_window_id=cast(str, raw.get("access_window_id")),
            capture_id=cast(str, raw.get("capture_id")),
            checkpoint_sha256=cast(str, raw.get("checkpoint_sha256")),
            job_id=cast(str, raw.get("job_id")),
            page_number=cast(int, raw.get("page_number")),
            page_size=cast(int, raw.get("page_size")),
            scope=cast(str, raw.get("scope")),
        )


@dataclass(frozen=True, slots=True)
class ShadowBatchImage:
    slot: str
    sha256: str
    relative_path: str
    byte_size: int
    media_type: str
    perceptual_fingerprint: ImagePerceptualFingerprint

    def __post_init__(self) -> None:
        if self.slot not in {"loading", "unloading"}:
            raise ChengfengShadowBatchContractError(
                "shadow image slot must be loading or unloading"
            )
        _required_sha256(self.sha256, label="shadow image SHA-256")
        if self.relative_path != _content_addressed_path(self.sha256):
            raise ChengfengShadowBatchContractError(
                "shadow image path is not content-addressed"
            )
        _required_positive_int(self.byte_size, label="shadow image byte size")
        if self.media_type not in {"image/jpeg", "image/png"}:
            raise ChengfengShadowBatchContractError(
                "shadow image media type is unsupported"
            )
        if not isinstance(
            self.perceptual_fingerprint,
            ImagePerceptualFingerprint,
        ):
            raise ChengfengShadowBatchContractError(
                "shadow image perceptual fingerprint is invalid"
            )
        try:
            self.perceptual_fingerprint.verify_integrity()
        except ImageSimilarityContractError as exc:
            raise ChengfengShadowBatchContractError(
                "shadow image perceptual fingerprint is invalid"
            ) from exc
        if self.perceptual_fingerprint.content_sha256 != self.sha256:
            raise ChengfengShadowBatchContractError(
                "shadow image perceptual fingerprint has a different hash"
            )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "byte_size": self.byte_size,
            "media_type": self.media_type,
            "perceptual_fingerprint": self.perceptual_fingerprint.to_record(),
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "slot": self.slot,
        }

    @classmethod
    def from_payload(cls, value: object) -> ShadowBatchImage:
        raw = _mapping(value, label="shadow batch image")
        expected = {
            "byte_size",
            "media_type",
            "perceptual_fingerprint",
            "relative_path",
            "sha256",
            "slot",
        }
        if set(raw) != expected:
            raise ChengfengShadowBatchContractError(
                "shadow batch image contract is invalid"
            )
        try:
            fingerprint = ImagePerceptualFingerprint.from_record(
                _mapping(
                    raw.get("perceptual_fingerprint"),
                    label="shadow image perceptual fingerprint",
                )
            )
        except ImageSimilarityContractError as exc:
            raise ChengfengShadowBatchContractError(
                "shadow image perceptual fingerprint is invalid"
            ) from exc
        return cls(
            slot=cast(str, raw.get("slot")),
            sha256=cast(str, raw.get("sha256")),
            relative_path=cast(str, raw.get("relative_path")),
            byte_size=cast(int, raw.get("byte_size")),
            media_type=cast(str, raw.get("media_type")),
            perceptual_fingerprint=fingerprint,
        )


@dataclass(frozen=True, slots=True)
class ShadowBatchItem:
    platform_waybill_id_digest: str
    waybill_number_digest: str
    vehicle_number_digest: str | None
    platform_loading_net: str
    platform_unloading_net: str
    images: tuple[ShadowBatchImage, ShadowBatchImage]
    item_identity_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        _required_sha256(
            self.platform_waybill_id_digest,
            label="platform waybill identity digest",
        )
        _required_sha256(
            self.waybill_number_digest,
            label="waybill number identity digest",
        )
        if self.vehicle_number_digest is not None:
            _required_sha256(
                self.vehicle_number_digest,
                label="vehicle number identity digest",
            )
        _required_weight(
            self.platform_loading_net,
            label="platform loading",
        )
        _required_weight(
            self.platform_unloading_net,
            label="platform unloading",
        )
        if (
            not isinstance(self.images, tuple)
            or len(self.images) != 2
            or tuple(image.slot for image in self.images)
            != ("loading", "unloading")
        ):
            raise ChengfengShadowBatchContractError(
                "each waybill requires one loading and one unloading image"
            )
        object.__setattr__(
            self,
            "item_identity_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        return {
            "images": [image._canonical_payload() for image in self.images],
            "platform_loading_net": self.platform_loading_net,
            "platform_unloading_net": self.platform_unloading_net,
            "platform_waybill_id_digest": self.platform_waybill_id_digest,
            "vehicle_number_digest": self.vehicle_number_digest,
            "waybill_number_digest": self.waybill_number_digest,
        }

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "item_identity_sha256": self.item_identity_sha256,
        }

    @classmethod
    def from_payload(cls, value: object) -> ShadowBatchItem:
        raw = _mapping(value, label="shadow batch item")
        expected = {
            "images",
            "item_identity_sha256",
            "platform_loading_net",
            "platform_unloading_net",
            "platform_waybill_id_digest",
            "vehicle_number_digest",
            "waybill_number_digest",
        }
        if set(raw) != expected:
            raise ChengfengShadowBatchContractError(
                "shadow batch item contract is invalid"
            )
        images = tuple(
            ShadowBatchImage.from_payload(image)
            for image in _array(raw.get("images"), label="shadow batch images")
        )
        if len(images) != 2:
            raise ChengfengShadowBatchContractError(
                "each waybill requires one loading and one unloading image"
            )
        vehicle_digest = raw.get("vehicle_number_digest")
        if vehicle_digest is not None and not isinstance(vehicle_digest, str):
            raise ChengfengShadowBatchContractError(
                "vehicle number identity digest is invalid"
            )
        item = cls(
            platform_waybill_id_digest=cast(
                str,
                raw.get("platform_waybill_id_digest"),
            ),
            waybill_number_digest=cast(str, raw.get("waybill_number_digest")),
            vehicle_number_digest=vehicle_digest,
            platform_loading_net=cast(str, raw.get("platform_loading_net")),
            platform_unloading_net=cast(
                str,
                raw.get("platform_unloading_net"),
            ),
            images=images,
        )
        declared = _required_sha256(
            raw.get("item_identity_sha256"),
            label="shadow item identity SHA-256",
        )
        if declared != item.item_identity_sha256:
            raise ChengfengShadowBatchContractError(
                "shadow batch item integrity is invalid"
            )
        return item


@dataclass(frozen=True, slots=True)
class ChengfengShadowBatchManifest:
    target_kind: ShadowBatchTargetKind
    source_build_sha256: str
    contract_canonical_sha256: str
    contract_file_sha256: str
    contract_selection_sha256: str
    pipeline_fingerprint: str
    identity_context_sha256: str
    sources: tuple[ShadowBatchSource, ...]
    items: tuple[ShadowBatchItem, ...]
    source_capture_sha256: str | None = None
    request_audit_sha256: str | None = None
    request_audit_counts: Mapping[str, object] | None = None
    source_kind: str = SOURCE_KIND
    schema_version: int = LEGACY_SCHEMA_VERSION
    canonical_sha256: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.target_kind, ShadowBatchTargetKind):
            raise ChengfengShadowBatchContractError(
                "shadow batch target kind is invalid"
            )
        if (
            self.source_kind != SOURCE_KIND
            or type(self.schema_version) is not int
            or self.schema_version
            not in {LEGACY_SCHEMA_VERSION, SCHEMA_VERSION}
        ):
            raise ChengfengShadowBatchContractError(
                "shadow batch manifest version is unsupported"
            )
        for label, value in (
            ("source build SHA-256", self.source_build_sha256),
            ("contract canonical SHA-256", self.contract_canonical_sha256),
            ("contract file SHA-256", self.contract_file_sha256),
            ("contract selection SHA-256", self.contract_selection_sha256),
            ("pipeline fingerprint", self.pipeline_fingerprint),
            ("identity context SHA-256", self.identity_context_sha256),
        ):
            _required_sha256(value, label=label)
        if (
            not isinstance(self.sources, tuple)
            or not self.sources
            or any(not isinstance(source, ShadowBatchSource) for source in self.sources)
        ):
            raise ChengfengShadowBatchContractError(
                "shadow batch sources are invalid"
            )
        if len({source.capture_id for source in self.sources}) != len(self.sources):
            raise ChengfengShadowBatchContractError(
                "shadow batch sources contain duplicate capture IDs"
            )
        expected_count = self.target_kind.expected_count
        if expected_count is None:
            raise ChengfengShadowBatchContractError(
                "operational captures cannot become formal shadow batches"
            )
        if (
            not isinstance(self.items, tuple)
            or len(self.items) != expected_count
            or any(not isinstance(item, ShadowBatchItem) for item in self.items)
        ):
            raise ChengfengShadowBatchContractError(
                f"{self.target_kind.value} requires exactly "
                f"{expected_count} waybills"
            )
        platform_ids = [item.platform_waybill_id_digest for item in self.items]
        waybill_ids = [item.waybill_number_digest for item in self.items]
        image_ids = [
            image.sha256 for item in self.items for image in item.images
        ]
        if len(platform_ids) != len(set(platform_ids)):
            raise ChengfengShadowBatchContractError(
                "shadow batch contains duplicate platform identity"
            )
        if len(waybill_ids) != len(set(waybill_ids)):
            raise ChengfengShadowBatchContractError(
                "shadow batch contains duplicate waybill identity"
            )
        if len(image_ids) != len(set(image_ids)):
            raise ChengfengShadowBatchContractError(
                "shadow batch contains a duplicate image"
            )
        if self.schema_version == LEGACY_SCHEMA_VERSION:
            if (
                self.source_capture_sha256 is not None
                or self.request_audit_sha256 is not None
                or self.request_audit_counts is not None
            ):
                raise ChengfengShadowBatchContractError(
                    "legacy shadow batch cannot bind request audit"
                )
        else:
            if (
                self.source_capture_sha256 is None
                or self.request_audit_sha256 is None
                or self.request_audit_counts is None
            ):
                raise ChengfengShadowBatchContractError(
                    "formal shadow batch request audit is required"
                )
            object.__setattr__(
                self,
                "request_audit_counts",
                _validate_shadow_request_audit(manifest=self),
            )
        object.__setattr__(
            self,
            "canonical_sha256",
            _canonical_sha256(self._canonical_payload()),
        )

    def _canonical_payload(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "contract_canonical_sha256": self.contract_canonical_sha256,
            "contract_file_sha256": self.contract_file_sha256,
            "contract_selection_sha256": self.contract_selection_sha256,
            "identity_context_sha256": self.identity_context_sha256,
            "items": [
                item.to_payload()
                for item in sorted(
                    self.items,
                    key=lambda value: value.item_identity_sha256,
                )
            ],
            "pipeline_fingerprint": self.pipeline_fingerprint,
            "schema_version": self.schema_version,
            "source_build_sha256": self.source_build_sha256,
            "source_kind": self.source_kind,
            "sources": [
                source._canonical_payload()
                for source in sorted(
                    self.sources,
                    key=lambda value: (
                        value.job_id,
                        value.capture_id,
                        value.page_number,
                    ),
                )
            ],
            "target_kind": self.target_kind.value,
        }
        if self.schema_version == SCHEMA_VERSION:
            assert self.source_capture_sha256 is not None
            assert self.request_audit_sha256 is not None
            assert self.request_audit_counts is not None
            payload["request_audit_counts"] = dict(
                self.request_audit_counts
            )
            payload["request_audit_sha256"] = self.request_audit_sha256
            payload["source_capture_sha256"] = (
                self.source_capture_sha256
            )
        return payload

    def to_payload(self) -> dict[str, object]:
        return {
            **self._canonical_payload(),
            "canonical_sha256": self.canonical_sha256,
        }

    def verify_integrity(self) -> None:
        if _canonical_sha256(self._canonical_payload()) != self.canonical_sha256:
            raise ChengfengShadowBatchContractError(
                "shadow batch manifest integrity is invalid"
            )

    @classmethod
    def from_payload(cls, value: object) -> ChengfengShadowBatchManifest:
        raw = _mapping(value, label="shadow batch manifest")
        legacy_expected = {
            "canonical_sha256",
            "contract_canonical_sha256",
            "contract_file_sha256",
            "contract_selection_sha256",
            "identity_context_sha256",
            "items",
            "pipeline_fingerprint",
            "schema_version",
            "source_build_sha256",
            "source_kind",
            "sources",
            "target_kind",
        }
        schema_version = cast(int, raw.get("schema_version"))
        expected = {
            *legacy_expected,
            "request_audit_counts",
            "request_audit_sha256",
            "source_capture_sha256",
        }
        if (
            schema_version == LEGACY_SCHEMA_VERSION
            and set(raw) != legacy_expected
        ) or (
            schema_version == SCHEMA_VERSION
            and set(raw) != expected
        ):
            raise ChengfengShadowBatchContractError(
                "shadow batch manifest contract is invalid"
            )
        if schema_version not in {LEGACY_SCHEMA_VERSION, SCHEMA_VERSION}:
            raise ChengfengShadowBatchContractError(
                "shadow batch manifest version is unsupported"
            )
        raw_target = raw.get("target_kind")
        try:
            target_kind = ShadowBatchTargetKind(cast(str, raw_target))
        except (TypeError, ValueError) as exc:
            raise ChengfengShadowBatchContractError(
                "shadow batch target kind is invalid"
            ) from exc
        manifest = cls(
            target_kind=target_kind,
            source_build_sha256=cast(str, raw.get("source_build_sha256")),
            contract_canonical_sha256=cast(
                str,
                raw.get("contract_canonical_sha256"),
            ),
            contract_file_sha256=cast(
                str,
                raw.get("contract_file_sha256"),
            ),
            contract_selection_sha256=cast(
                str,
                raw.get("contract_selection_sha256"),
            ),
            pipeline_fingerprint=cast(str, raw.get("pipeline_fingerprint")),
            identity_context_sha256=cast(
                str,
                raw.get("identity_context_sha256"),
            ),
            sources=tuple(
                ShadowBatchSource.from_payload(source)
                for source in _array(
                    raw.get("sources"),
                    label="shadow batch sources",
                )
            ),
            items=tuple(
                ShadowBatchItem.from_payload(item)
                for item in _array(raw.get("items"), label="shadow batch items")
            ),
            source_capture_sha256=(
                None
                if schema_version == LEGACY_SCHEMA_VERSION
                else cast(str, raw.get("source_capture_sha256"))
            ),
            request_audit_sha256=(
                None
                if schema_version == LEGACY_SCHEMA_VERSION
                else cast(str, raw.get("request_audit_sha256"))
            ),
            request_audit_counts=(
                None
                if schema_version == LEGACY_SCHEMA_VERSION
                else _mapping(
                    raw.get("request_audit_counts"),
                    label="shadow batch request audit counts",
                )
            ),
            source_kind=cast(str, raw.get("source_kind")),
            schema_version=schema_version,
        )
        declared = _required_sha256(
            raw.get("canonical_sha256"),
            label="shadow batch canonical SHA-256",
        )
        if declared != manifest.canonical_sha256:
            raise ChengfengShadowBatchContractError(
                "shadow batch manifest integrity is invalid"
            )
        return manifest


@dataclass(frozen=True, slots=True)
class ChengfengShadowBatch:
    manifest: ChengfengShadowBatchManifest
    scheduled_job: ScheduledJobSpec


def _binding_authority(
    binding: ShadowCaptureBinding,
) -> tuple[str, str, str, str]:
    return (
        binding.source_build_sha256,
        binding.contract_canonical_sha256,
        binding.contract_file_sha256,
        binding.contract_selection_sha256,
    )


def _validate_authority(bindings: Sequence[ShadowCaptureBinding]) -> None:
    authorities = {_binding_authority(binding) for binding in bindings}
    if len(authorities) != 1:
        build_values = {binding.source_build_sha256 for binding in bindings}
        if len(build_values) != 1:
            raise ChengfengShadowBatchContractError(
                "capture source build bindings do not match"
            )
        raise ChengfengShadowBatchContractError(
            "capture source contract bindings do not match"
        )


def _validate_complete_pagination(
    bindings: Sequence[ShadowCaptureBinding],
) -> None:
    scopes = {binding.checkpoint.scope for binding in bindings}
    if scopes not in (
        {CURRENT_PENDING_SETTLEMENT_SCOPE},
        {HISTORICAL_SETTLED_SCOPE},
    ):
        raise ChengfengShadowBatchContractError(
            "capture scope bindings do not match"
        )
    grouped: dict[
        tuple[str, str, str],
        list[DurableCaptureCheckpoint],
    ] = defaultdict(list)
    for binding in bindings:
        checkpoint = binding.checkpoint
        grouped[
            (
                binding.access_window_id,
                checkpoint.job_id,
                checkpoint.scope,
            )
        ].append(checkpoint)

    for checkpoints in grouped.values():
        first_page = checkpoints[0].page
        if first_page is None:
            raise ChengfengShadowBatchContractError(
                "capture checkpoint has no completed list page"
            )
        totals = {checkpoint.page.total for checkpoint in checkpoints if checkpoint.page}
        page_sizes = {checkpoint.page_size for checkpoint in checkpoints}
        if len(totals) != 1 or len(page_sizes) != 1:
            raise ChengfengShadowBatchContractError(
                "capture pagination contract is inconsistent"
            )
        total = next(iter(totals))
        page_size = next(iter(page_sizes))
        scope = checkpoints[0].scope
        if scope == HISTORICAL_SETTLED_SCOPE:
            by_page = {
                checkpoint.page_number: checkpoint
                for checkpoint in checkpoints
            }
            expected_pages = min(
                max(1, (total + page_size - 1) // page_size),
                HISTORICAL_CAPTURE_MAX_PAGES,
            )
            if (
                page_size != HISTORICAL_CAPTURE_PAGE_SIZE
                or len(by_page) != len(checkpoints)
                or set(by_page) != set(range(1, expected_pages + 1))
            ):
                raise ChengfengShadowBatchContractError(
                    "bounded historical capture contract is invalid"
                )
            for page_number, checkpoint in sorted(by_page.items()):
                if checkpoint.page is None:
                    raise ChengfengShadowBatchContractError(
                        "bounded historical capture contract is invalid"
                    )
                expected_size = min(
                    page_size,
                    total - (page_size * (page_number - 1)),
                )
                if len(checkpoint.page.items) != expected_size:
                    raise ChengfengShadowBatchContractError(
                        "bounded historical capture contract is invalid"
                    )
            continue
        expected_pages = max(1, (total + page_size - 1) // page_size)
        by_page = {checkpoint.page_number: checkpoint for checkpoint in checkpoints}
        if (
            len(by_page) != len(checkpoints)
            or set(by_page) != set(range(1, expected_pages + 1))
        ):
            raise ChengfengShadowBatchContractError(
                "capture pagination is partial"
            )
        merged_count = 0
        for page_number, checkpoint in sorted(by_page.items()):
            assert checkpoint.page is not None
            expected_size = (
                page_size
                if page_number < expected_pages
                else total - (page_size * (expected_pages - 1))
            )
            if len(checkpoint.page.items) != expected_size:
                raise ChengfengShadowBatchContractError(
                    "capture pagination is partial"
                )
            merged_count += len(checkpoint.page.items)
        if merged_count != total:
            raise ChengfengShadowBatchContractError(
                "capture pagination is partial"
            )


def _checkpoint_source(
    binding: ShadowCaptureBinding,
) -> ShadowBatchSource:
    checkpoint = binding.checkpoint
    return ShadowBatchSource(
        access_window_id=binding.access_window_id,
        job_id=checkpoint.job_id,
        capture_id=checkpoint.capture_id,
        scope=checkpoint.scope,
        page_number=checkpoint.page_number,
        page_size=checkpoint.page_size,
        checkpoint_sha256=_canonical_sha256(checkpoint.to_payload()),
    )


def _read_and_fingerprint(
    *,
    image: PersistedTicketImage,
    image_reader: SafeImageReader,
) -> ImagePerceptualFingerprint:
    expected_path = _content_addressed_path(image.sha256)
    if image.relative_path != expected_path:
        raise ChengfengShadowBatchContractError(
            "persisted image path is not content-addressed"
        )
    try:
        content = image_reader.read_verified_image(
            relative_path=image.relative_path,
            expected_sha256=image.sha256,
        )
    except ChengfengShadowBatchContractError:
        raise
    except Exception as exc:
        raise ChengfengShadowBatchContractError(
            "safe image reader could not read persisted evidence"
        ) from exc
    if (
        not isinstance(content, bytes)
        or len(content) != image.byte_size
        or hashlib.sha256(content).hexdigest() != image.sha256
    ):
        raise ChengfengShadowBatchContractError(
            "safe image reader returned bytes with a different hash or size"
        )
    try:
        return build_image_fingerprint(content)
    except ImageSimilarityContractError as exc:
        raise ChengfengShadowBatchContractError(
            "persisted image cannot produce a perceptual fingerprint"
        ) from exc


def _checkpoint_items(
    *,
    checkpoint: DurableCaptureCheckpoint,
    salt: bytes,
    namespace: str,
    image_reader: SafeImageReader,
) -> tuple[ShadowBatchItem, ...]:
    page = checkpoint.page
    if checkpoint.stage is not ChengfengStage.IMAGE_DOWNLOAD:
        raise ChengfengShadowBatchContractError(
            "capture checkpoint has not reached the complete image stage"
        )
    if (
        not checkpoint.completed_list
        or page is None
        or len(checkpoint.details) != len(page.items)
        or len(checkpoint.completed_detail_ids) != len(page.items)
    ):
        raise ChengfengShadowBatchContractError(
            "capture requires exactly one detail per summary"
        )
    details_by_id = {
        detail.platform_waybill_id: detail for detail in checkpoint.details
    }
    if set(details_by_id) != {
        summary.platform_waybill_id for summary in page.items
    }:
        raise ChengfengShadowBatchContractError(
            "capture requires exactly one detail per summary"
        )
    referenced_ticket_refs = {
        ticket.ticket_ref
        for detail in checkpoint.details
        for ticket in detail.tickets
    }
    if set(checkpoint.ticket_images) != referenced_ticket_refs:
        raise ChengfengShadowBatchContractError(
            "capture does not contain every required ticket image"
        )

    items: list[ShadowBatchItem] = []
    for summary in page.items:
        detail = details_by_id[summary.platform_waybill_id]
        if detail.waybill_number != summary.waybill_number:
            raise ChengfengShadowBatchContractError(
                "detail and summary waybill identities differ"
            )
        if (
            summary.vehicle_number is not None
            and detail.vehicle_number is not None
            and summary.vehicle_number != detail.vehicle_number
        ):
            raise ChengfengShadowBatchContractError(
                "detail and summary vehicle identities differ"
            )
        tickets_by_slot = {ticket.slot: ticket for ticket in detail.tickets}
        if (
            len(detail.tickets) != 2
            or len(tickets_by_slot) != 2
            or set(tickets_by_slot) != {"loading", "unloading"}
        ):
            raise ChengfengShadowBatchContractError(
                "each waybill requires one loading and one unloading ticket image"
            )
        batch_images: list[ShadowBatchImage] = []
        for slot in ("loading", "unloading"):
            ticket = tickets_by_slot[slot]
            persisted = checkpoint.ticket_images.get(ticket.ticket_ref)
            if persisted is None:
                raise ChengfengShadowBatchContractError(
                    "capture does not contain every required ticket image"
                )
            if persisted.ticket_ref != ticket.ticket_ref:
                raise ChengfengShadowBatchContractError(
                    "persisted image identity does not match its ticket"
                )
            fingerprint = _read_and_fingerprint(
                image=persisted,
                image_reader=image_reader,
            )
            batch_images.append(
                ShadowBatchImage(
                    slot=slot,
                    sha256=persisted.sha256,
                    relative_path=persisted.relative_path,
                    byte_size=persisted.byte_size,
                    media_type=persisted.media_type,
                    perceptual_fingerprint=fingerprint,
                )
            )
        vehicle_number = detail.vehicle_number or summary.vehicle_number
        items.append(
            ShadowBatchItem(
                platform_waybill_id_digest=chengfeng_shadow_identity_digest(
                    salt=salt,
                    namespace=namespace,
                    field_name="platform_waybill_id",
                    value=detail.platform_waybill_id,
                ),
                waybill_number_digest=chengfeng_shadow_identity_digest(
                    salt=salt,
                    namespace=namespace,
                    field_name="waybill_number",
                    value=detail.waybill_number,
                ),
                vehicle_number_digest=(
                    None
                    if vehicle_number is None
                    else chengfeng_shadow_identity_digest(
                        salt=salt,
                        namespace=namespace,
                        field_name="vehicle_number",
                        value=vehicle_number,
                    )
                ),
                platform_loading_net=_required_weight(
                    detail.loading_net,
                    label="platform loading",
                ),
                platform_unloading_net=_required_weight(
                    detail.unloading_net,
                    label="platform unloading",
                ),
                images=cast(
                    tuple[ShadowBatchImage, ShadowBatchImage],
                    tuple(batch_images),
                ),
            )
        )
    return tuple(items)


def scheduled_job_from_shadow_manifest(
    manifest: ChengfengShadowBatchManifest,
) -> ScheduledJobSpec:
    """Build the one existing cooperative-scheduler contract for a sealed batch."""

    manifest.verify_integrity()
    items: list[ScheduledWorkItemSpec] = []
    for item in sorted(
        manifest.items,
        key=lambda value: value.item_identity_sha256,
    ):
        images = {image.slot: image for image in item.images}
        items.append(
            ScheduledWorkItemSpec(
                item_key=f"CF-{item.item_identity_sha256}",
                expected_outcome=None,
                loading_image_sha256=images["loading"].sha256,
                unloading_image_sha256=images["unloading"].sha256,
                loading_image_relative_path=(
                    f"evidence/{images['loading'].relative_path}"
                ),
                unloading_image_relative_path=(
                    f"evidence/{images['unloading'].relative_path}"
                ),
                platform_loading_net=item.platform_loading_net,
                platform_unloading_net=item.platform_unloading_net,
            )
        )
    content_identity = manifest.canonical_sha256
    return ScheduledJobSpec(
        fixture_id=(
            f"chengfeng-shadow:{manifest.target_kind.value}:{content_identity}"
        ),
        job_kind="business",
        task_type="audit",
        scope_label=manifest.target_kind.value,
        conflict_key=(
            f"audit:chengfeng-shadow:{manifest.target_kind.value}:"
            f"{content_identity}"
        ),
        items=tuple(items),
        pipeline_fingerprint=manifest.pipeline_fingerprint,
        ocr_execution_mode="local",
    )


def build_chengfeng_shadow_batch(
    *,
    bindings: Sequence[ShadowCaptureBinding],
    target_kind: ShadowBatchTargetKind,
    pipeline_fingerprint: str,
    identity_salt: bytes,
    identity_namespace: str,
    image_reader: SafeImageReader,
) -> ChengfengShadowBatch:
    """Convert complete read-only captures into one immutable local OCR job."""

    if (
        not isinstance(bindings, Sequence)
        or isinstance(bindings, (str, bytes))
        or not bindings
        or any(not isinstance(binding, ShadowCaptureBinding) for binding in bindings)
    ):
        raise ChengfengShadowBatchContractError(
            "one or more capture bindings are required"
        )
    if not isinstance(target_kind, ShadowBatchTargetKind):
        raise ChengfengShadowBatchContractError(
            "shadow batch target kind is invalid"
        )
    _required_sha256(pipeline_fingerprint, label="pipeline fingerprint")
    if (
        not isinstance(identity_salt, bytes)
        or len(identity_salt) < 16
    ):
        raise ChengfengShadowBatchContractError(
            "identity salt must contain at least 16 bytes"
        )
    namespace = _required_text(
        identity_namespace,
        label="identity namespace",
        maximum=100,
    )
    if not hasattr(image_reader, "read_verified_image"):
        raise ChengfengShadowBatchContractError("safe image reader is invalid")

    normalized_bindings = tuple(bindings)
    _validate_authority(normalized_bindings)
    _validate_complete_pagination(normalized_bindings)

    capture_ids = [
        binding.checkpoint.capture_id for binding in normalized_bindings
    ]
    if len(capture_ids) != len(set(capture_ids)):
        raise ChengfengShadowBatchContractError(
            "capture bindings contain duplicate capture IDs"
        )

    items = tuple(
        item
        for binding in normalized_bindings
        for item in _checkpoint_items(
            checkpoint=binding.checkpoint,
            salt=identity_salt,
            namespace=namespace,
            image_reader=image_reader,
        )
    )
    authority = _binding_authority(normalized_bindings[0])
    manifest = ChengfengShadowBatchManifest(
        target_kind=target_kind,
        source_build_sha256=authority[0],
        contract_canonical_sha256=authority[1],
        contract_file_sha256=authority[2],
        contract_selection_sha256=authority[3],
        pipeline_fingerprint=pipeline_fingerprint,
        identity_context_sha256=chengfeng_shadow_identity_context_sha256(
            salt=identity_salt,
            namespace=namespace,
        ),
        sources=tuple(
            _checkpoint_source(binding) for binding in normalized_bindings
        ),
        items=items,
    )
    return ChengfengShadowBatch(
        manifest=manifest,
        scheduled_job=scheduled_job_from_shadow_manifest(manifest),
    )
