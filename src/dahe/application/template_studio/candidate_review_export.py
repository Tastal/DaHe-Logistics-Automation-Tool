from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import cast

from dahe.adapters.sqlite.locked_set_review import LockedSetReviewRecord
from dahe.application.template_studio.candidate_review_semantics import (
    candidate_review_manifest_payload,
    candidate_review_waybill_membership_sha256,
)
from dahe.domain.audit.ticket_roles import TicketRole, TicketSlot
from dahe.verification.locked_set import (
    LockedSetManifest,
    LockedTicketImage,
    LockedWaybill,
)
from dahe.verification.locked_set_acceptance import (
    REQUIRED_NATURAL_QUALITY_CONDITIONS,
    SUPPORTED_QUALITY_CONDITIONS,
    build_locked_set_derived_adversarial_suite,
    locked_set_quality_coverage_sha256,
    quality_review_evidence_sha256,
)
from dahe.verification.locked_set_review_package import (
    LockedSetReviewImage,
    LockedSetReviewImageChangedError,
    LockedSetReviewItem,
    LockedSetReviewPackage,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SLOTS = ("loading", "unloading")
_SLOT_ORDER = {value: index for index, value in enumerate(_SLOTS)}
_ROLES = frozenset({"loading", "unloading", "unknown"})
_ROTATIONS = frozenset({"rotation_0", "rotation_90", "rotation_180", "rotation_270"})
_UNKNOWN_QUALITY = frozenset({"non_ticket", "unknown_layout"})
_QUALITY_ORDER = {
    value: index
    for index, value in enumerate(
        (
            "blur",
            "glare",
            "crop",
            "rotation_0",
            "rotation_90",
            "rotation_180",
            "rotation_270",
            "screen",
            "printed",
            "unknown_layout",
            "non_ticket",
        )
    )
}
_PAIR_ORDER = {
    value: index
    for index, value in enumerate(
        (
            "normal_pair",
            "swapped_pair",
            "same_role_pair",
            "duplicate_upload",
            "pair_unknown",
        )
    )
}
_PRIMARY_PAIR_CONDITIONS = frozenset(
    {"normal_pair", "swapped_pair", "same_role_pair", "pair_unknown"}
)
_REVIEW_PAYLOAD_FIELDS = frozenset(
    {
        "reviewer_id",
        "decision",
        "images",
        "pair_conditions",
        "pair_notes",
        "replace_reason",
    }
)
_IMAGE_REVIEW_FIELDS = frozenset(
    {
        "submitted_slot",
        "role",
        "ordinary_net",
        "quality_conditions",
        "notes",
    }
)


class CandidateReviewExportError(ValueError):
    """Raised when reviewed candidate evidence cannot become a formal export."""


@dataclass(frozen=True, slots=True)
class CandidateReviewFormalExport:
    """Deterministic, unsealed evidence prepared for the formal release flow."""

    manifest: LockedSetManifest
    manifest_payload: dict[str, object]
    manifest_sha256: str
    source_authority_payload: dict[str, object]
    source_authority_sha256: str
    record_set_sha256: str
    quality_coverage_payload: dict[str, object]
    quality_coverage_sha256: str


@dataclass(frozen=True, slots=True)
class _NormalizedImageReview:
    submitted_slot: str
    role: str
    ordinary_net: str | None
    quality_conditions: tuple[str, ...]
    notes: str | None

    def to_payload(self) -> dict[str, object]:
        return {
            "submitted_slot": self.submitted_slot,
            "role": self.role,
            "ordinary_net": self.ordinary_net,
            "quality_conditions": list(self.quality_conditions),
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class _NormalizedReviewRecord:
    sample_id: str
    record_version: int
    review_status: str
    decision: str
    reviewer_id: str
    images: tuple[_NormalizedImageReview, _NormalizedImageReview]
    pair_conditions: tuple[str, ...]
    pair_notes: str | None
    created_at: str
    updated_at: str
    review_payload: dict[str, object]
    record_evidence_sha256: str


@dataclass(frozen=True, slots=True)
class _QualityCandidate:
    sample_id: str
    image: LockedSetReviewImage
    review: _NormalizedImageReview
    reviewed_at: str

    @property
    def sort_key(self) -> tuple[str, int, str]:
        return (
            self.sample_id,
            _SLOT_ORDER[self.image.submitted_slot],
            self.image.image_sha256,
        )


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _required_text(
    value: object,
    *,
    label: str,
    maximum: int,
    require_canonical: bool = False,
) -> str:
    if not isinstance(value, str):
        raise CandidateReviewExportError(f"{label} is required")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or (require_canonical and normalized != value):
        raise CandidateReviewExportError(f"{label} is invalid")
    return normalized


def _optional_text(
    value: object,
    *,
    label: str,
    maximum: int,
) -> str | None:
    if value is None:
        return None
    return _required_text(
        value,
        label=label,
        maximum=maximum,
        require_canonical=True,
    )


def _sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        raise CandidateReviewExportError(f"{label} must be a lowercase SHA-256")
    return value


def _timestamp(value: object, *, label: str) -> tuple[str, datetime]:
    text = _required_text(
        value,
        label=label,
        maximum=40,
        require_canonical=True,
    )
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CandidateReviewExportError(f"{label} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise CandidateReviewExportError(f"{label} must include a timezone")
    return text, parsed


def _ordinary_net(value: object, *, role: str) -> str | None:
    if role == "unknown":
        if value is not None:
            raise CandidateReviewExportError("unknown role requires an empty ordinary net")
        return None
    if not isinstance(value, str):
        raise CandidateReviewExportError(
            "known role requires an ordinary net with two decimal places"
        )
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise CandidateReviewExportError("ordinary net must use two decimal places") from exc
    if (
        not amount.is_finite()
        or amount <= 0
        or amount.as_tuple().exponent != -2
        or format(amount, "f") != value
    ):
        raise CandidateReviewExportError("ordinary net must be positive with two decimal places")
    return value


def _normalize_quality_conditions(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CandidateReviewExportError("quality conditions must be a text list")
    conditions = cast(list[str], value)
    if len(conditions) != len(set(conditions)) or any(
        item not in SUPPORTED_QUALITY_CONDITIONS for item in conditions
    ):
        raise CandidateReviewExportError("quality conditions are invalid")
    if len(_ROTATIONS.intersection(conditions)) != 1:
        raise CandidateReviewExportError("quality conditions require exactly one rotation")
    canonical = tuple(sorted(conditions, key=_QUALITY_ORDER.__getitem__))
    if tuple(conditions) != canonical:
        raise CandidateReviewExportError("quality conditions are not in canonical order")
    return canonical


def _normalize_image_review(value: object) -> _NormalizedImageReview:
    if not isinstance(value, Mapping) or set(value) != _IMAGE_REVIEW_FIELDS:
        raise CandidateReviewExportError("stored review image contains unexpected fields")
    slot = value.get("submitted_slot")
    if slot not in _SLOTS:
        raise CandidateReviewExportError("stored review image submitted slot is invalid")
    role = value.get("role")
    if role not in _ROLES:
        raise CandidateReviewExportError("stored review image role is invalid")
    quality_conditions = _normalize_quality_conditions(value.get("quality_conditions"))
    if _UNKNOWN_QUALITY.intersection(quality_conditions) and role != "unknown":
        raise CandidateReviewExportError(
            "unknown-layout or non-ticket evidence requires an unknown role"
        )
    return _NormalizedImageReview(
        submitted_slot=cast(str, slot),
        role=cast(str, role),
        ordinary_net=_ordinary_net(
            value.get("ordinary_net"),
            role=cast(str, role),
        ),
        quality_conditions=quality_conditions,
        notes=_optional_text(
            value.get("notes"),
            label="stored review image notes",
            maximum=1000,
        ),
    )


def _normalize_pair_conditions(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise CandidateReviewExportError("pair conditions must be a text list")
    conditions = cast(list[str], value)
    if len(conditions) != len(set(conditions)) or any(
        item not in _PAIR_ORDER for item in conditions
    ):
        raise CandidateReviewExportError("pair conditions are invalid")
    canonical = tuple(sorted(conditions, key=_PAIR_ORDER.__getitem__))
    if tuple(conditions) != canonical:
        raise CandidateReviewExportError("pair conditions are not in canonical order")
    primary = _PRIMARY_PAIR_CONDITIONS.intersection(canonical)
    if len(primary) != 1:
        raise CandidateReviewExportError("confirmed review requires one primary pair condition")
    return canonical


def _validate_pair_roles(
    *,
    pair_conditions: tuple[str, ...],
    images: tuple[_NormalizedImageReview, _NormalizedImageReview],
) -> None:
    roles = {image.submitted_slot: image.role for image in images}
    primary = next(
        condition for condition in pair_conditions if condition in _PRIMARY_PAIR_CONDITIONS
    )
    valid = False
    if primary == "normal_pair":
        valid = roles == {
            "loading": "loading",
            "unloading": "unloading",
        }
    elif primary == "swapped_pair":
        valid = roles == {
            "loading": "unloading",
            "unloading": "loading",
        }
    elif primary == "same_role_pair":
        valid = roles["loading"] == roles["unloading"] and roles["loading"] in {
            "loading",
            "unloading",
        }
    elif primary == "pair_unknown":
        valid = "unknown" in roles.values()
    if not valid:
        raise CandidateReviewExportError("pair condition does not match human-confirmed pair roles")


def _normalize_record(
    record: LockedSetReviewRecord,
    *,
    package_sha256: str,
    configured_reviewer_id: str,
) -> _NormalizedReviewRecord:
    if not isinstance(record, LockedSetReviewRecord):
        raise CandidateReviewExportError("candidate review record type is invalid")
    sample_id = _required_text(
        record.sample_id,
        label="candidate review sample ID",
        maximum=100,
        require_canonical=True,
    )
    if record.review_status != "confirmed" or record.decision != "confirmed":
        raise CandidateReviewExportError("every candidate review record must be confirmed")
    if (
        isinstance(record.record_version, bool)
        or not isinstance(record.record_version, int)
        or record.record_version < 1
    ):
        raise CandidateReviewExportError("candidate review record version is invalid")
    if (
        not isinstance(record.review_payload, Mapping)
        or set(record.review_payload) != _REVIEW_PAYLOAD_FIELDS
    ):
        raise CandidateReviewExportError("stored review payload contains unexpected fields")
    payload = record.review_payload
    reviewer_id = _required_text(
        payload.get("reviewer_id"),
        label="stored review reviewer",
        maximum=100,
        require_canonical=True,
    )
    if reviewer_id != configured_reviewer_id:
        raise CandidateReviewExportError("stored review does not match the configured reviewer")
    if payload.get("decision") != "confirmed":
        raise CandidateReviewExportError("stored review decision must be confirmed")
    if payload.get("replace_reason") is not None:
        raise CandidateReviewExportError("confirmed review cannot contain a replacement reason")
    raw_images = payload.get("images")
    if not isinstance(raw_images, list) or len(raw_images) != 2:
        raise CandidateReviewExportError("confirmed review requires exactly two image records")
    images = tuple(_normalize_image_review(value) for value in raw_images)
    if tuple(image.submitted_slot for image in images) != _SLOTS:
        raise CandidateReviewExportError(
            "stored review submitted slots must be loading then unloading"
        )
    normalized_images = cast(
        tuple[_NormalizedImageReview, _NormalizedImageReview],
        images,
    )
    pair_conditions = _normalize_pair_conditions(payload.get("pair_conditions"))
    _validate_pair_roles(
        pair_conditions=pair_conditions,
        images=normalized_images,
    )
    pair_notes = _optional_text(
        payload.get("pair_notes"),
        label="stored review pair notes",
        maximum=1000,
    )
    created_at, created_time = _timestamp(
        record.created_at,
        label="candidate review creation time",
    )
    updated_at, updated_time = _timestamp(
        record.updated_at,
        label="candidate review update time",
    )
    if updated_time < created_time:
        raise CandidateReviewExportError("candidate review update time precedes creation time")
    normalized_payload: dict[str, object] = {
        "reviewer_id": reviewer_id,
        "decision": "confirmed",
        "images": [image.to_payload() for image in normalized_images],
        "pair_conditions": list(pair_conditions),
        "pair_notes": pair_notes,
        "replace_reason": None,
    }
    evidence_payload: dict[str, object] = {
        "schema_version": 1,
        "package_sha256": package_sha256,
        "sample_id": sample_id,
        "record_version": record.record_version,
        "review_status": "confirmed",
        "decision": "confirmed",
        "review_payload": normalized_payload,
        "created_at": created_at,
        "updated_at": updated_at,
    }
    return _NormalizedReviewRecord(
        sample_id=sample_id,
        record_version=record.record_version,
        review_status="confirmed",
        decision="confirmed",
        reviewer_id=reviewer_id,
        images=normalized_images,
        pair_conditions=pair_conditions,
        pair_notes=pair_notes,
        created_at=created_at,
        updated_at=updated_at,
        review_payload=normalized_payload,
        record_evidence_sha256=_canonical_sha256(evidence_payload),
    )


def _validate_package(
    package: LockedSetReviewPackage,
) -> tuple[LockedSetReviewItem, ...]:
    if not isinstance(package, LockedSetReviewPackage):
        raise CandidateReviewExportError("candidate review package type is invalid")
    _required_text(
        package.package_id,
        label="candidate review package ID",
        maximum=200,
        require_canonical=True,
    )
    _sha256(
        package.canonical_sha256,
        label="candidate review package SHA-256",
    )
    if len(package.items) != 50:
        raise CandidateReviewExportError("candidate package requires exactly 50 samples")
    sample_ids = [item.sample_id for item in package.items]
    candidate_ids = [item.candidate_id for item in package.items]
    waybill_ids = [item.waybill_identity_sha256 for item in package.items]
    if (
        len(set(sample_ids)) != 50
        or len(set(candidate_ids)) != 50
        or len(set(waybill_ids)) != 50
        or {item.position for item in package.items} != set(range(1, 51))
        or set(package.items_by_sample_id) != set(sample_ids)
        or any(package.items_by_sample_id.get(item.sample_id) != item for item in package.items)
    ):
        raise CandidateReviewExportError("candidate package sample authority is inconsistent")
    images = [image for item in package.items for image in item.images]
    image_hashes = [image.image_sha256 for image in images]
    relative_paths = [image.relative_path for image in images]
    if (
        len(images) != 100
        or len(set(image_hashes)) != 100
        or len(set(relative_paths)) != 100
        or set(package.images_by_sha256) != set(image_hashes)
        or any(package.images_by_sha256.get(image.image_sha256) != image for image in images)
    ):
        raise CandidateReviewExportError("candidate package image authority is inconsistent")
    for item in package.items:
        _required_text(
            item.sample_id,
            label="candidate package sample ID",
            maximum=100,
            require_canonical=True,
        )
        _required_text(
            item.candidate_id,
            label="candidate package candidate ID",
            maximum=200,
            require_canonical=True,
        )
        _sha256(
            item.waybill_identity_sha256,
            label="candidate package waybill identity",
        )
        if {image.submitted_slot for image in item.images} != set(_SLOTS):
            raise CandidateReviewExportError("candidate package submitted slots are inconsistent")
        for image in item.images:
            _sha256(
                image.image_sha256,
                label="candidate package image SHA-256",
            )
    return package.items


def _verified_images(
    package: LockedSetReviewPackage,
    items: tuple[LockedSetReviewItem, ...],
) -> list[dict[str, object]]:
    verified: list[dict[str, object]] = []
    for item in items:
        for image in sorted(
            item.images,
            key=lambda value: _SLOT_ORDER[value.submitted_slot],
        ):
            try:
                content, media_type = package.read_verified_image(image.image_sha256)
            except (KeyError, LockedSetReviewImageChangedError) as exc:
                raise CandidateReviewExportError(
                    "candidate review image changed or is unavailable"
                ) from exc
            if not content or media_type != image.media_type:
                raise CandidateReviewExportError("candidate review image changed or is unavailable")
            verified.append(
                {
                    "sample_id": item.sample_id,
                    "submitted_slot": image.submitted_slot,
                    "image_sha256": image.image_sha256,
                    "relative_path": image.relative_path,
                    "width": image.width,
                    "height": image.height,
                    "media_type": image.media_type,
                    "byte_count": len(content),
                }
            )
    if len(verified) != 100:
        raise CandidateReviewExportError("candidate review image verification did not reconcile")
    return verified


def _manifest_payload(
    manifest: LockedSetManifest,
) -> dict[str, object]:
    return candidate_review_manifest_payload(manifest)


def _truth_manifest_payload(
    manifest: LockedSetManifest,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "waybill_count": manifest.waybill_count,
        "image_count": manifest.image_count,
        "pairs": [
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "truth_role": image.role.value,
                    }
                    for image in waybill.images
                ],
                "submitted_slots": {
                    image.slot.value: image.image_sha256 for image in waybill.images
                },
            }
            for waybill in manifest.waybills
        ],
    }


def _select_quality_candidates(
    candidates: Mapping[str, list[_QualityCandidate]],
) -> dict[str, _QualityCandidate]:
    missing = sorted(
        condition
        for condition in REQUIRED_NATURAL_QUALITY_CONDITIONS
        if not candidates.get(condition)
    )
    if missing:
        raise CandidateReviewExportError(
            "candidate review quality coverage is incomplete: " + ", ".join(missing)
        )
    ordered = {
        condition: sorted(
            candidates[condition],
            key=lambda candidate: candidate.sort_key,
        )
        for condition in REQUIRED_NATURAL_QUALITY_CONDITIONS
    }
    selected = {
        condition: values[0]
        for condition, values in ordered.items()
        if condition not in {"printed", "screen"}
    }
    medium_pair = next(
        (
            (printed, screen)
            for printed in ordered["printed"]
            for screen in ordered["screen"]
            if printed.image.image_sha256 != screen.image.image_sha256
        ),
        None,
    )
    if medium_pair is None:
        raise CandidateReviewExportError(
            "printed and screen quality evidence require distinct images"
        )
    selected["printed"], selected["screen"] = medium_pair
    rotation_hashes = {selected[condition].image.image_sha256 for condition in _ROTATIONS}
    if len(rotation_hashes) != len(_ROTATIONS):
        raise CandidateReviewExportError("rotation quality evidence requires four distinct images")
    return selected


def _quality_coverage(
    *,
    manifest: LockedSetManifest,
    quality_candidates: Mapping[str, list[_QualityCandidate]],
    configured_reviewer_id: str,
) -> dict[str, object]:
    selected = _select_quality_candidates(quality_candidates)
    entries: list[dict[str, object]] = []
    for condition in sorted(REQUIRED_NATURAL_QUALITY_CONDITIONS):
        candidate = selected[condition]
        entry: dict[str, object] = {
            "condition": condition,
            "image_sha256": candidate.image.image_sha256,
            "reviewer_id": configured_reviewer_id,
            "reviewed_at": candidate.reviewed_at,
        }
        if candidate.review.notes is not None:
            entry["notes"] = candidate.review.notes
        entry["review_evidence_sha256"] = quality_review_evidence_sha256(
            dataset_id=manifest.dataset_id,
            manifest_sha256=manifest.canonical_sha256,
            entry=entry,
        )
        entries.append(entry)
    coverage: dict[str, object] = {
        "schema_version": 2,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "required_conditions": sorted(REQUIRED_NATURAL_QUALITY_CONDITIONS),
        "entries": entries,
        "derived_adversarial_suite": (
            build_locked_set_derived_adversarial_suite(_truth_manifest_payload(manifest))
        ),
    }
    coverage["quality_coverage_sha256"] = locked_set_quality_coverage_sha256(coverage)
    return coverage


def build_candidate_review_formal_export(
    *,
    package: LockedSetReviewPackage,
    records: Sequence[LockedSetReviewRecord],
    configured_reviewer_id: str,
    dataset_id: str,
) -> CandidateReviewFormalExport:
    """Build deterministic unsealed formal evidence without persistence or OCR."""

    reviewer_id = _required_text(
        configured_reviewer_id,
        label="configured reviewer",
        maximum=100,
    )
    normalized_dataset_id = _required_text(
        dataset_id,
        label="formal locked-set dataset ID",
        maximum=200,
    )
    items = tuple(
        sorted(
            _validate_package(package),
            key=lambda item: item.sample_id,
        )
    )
    if len(records) != 50:
        raise CandidateReviewExportError("review records must exactly match the candidate package")
    normalized_by_sample: dict[str, _NormalizedReviewRecord] = {}
    for record in records:
        normalized = _normalize_record(
            record,
            package_sha256=package.canonical_sha256,
            configured_reviewer_id=reviewer_id,
        )
        if normalized.sample_id in normalized_by_sample:
            raise CandidateReviewExportError(
                "review records must exactly match the candidate package"
            )
        normalized_by_sample[normalized.sample_id] = normalized
    package_sample_ids = {item.sample_id for item in items}
    if set(normalized_by_sample) != package_sample_ids:
        raise CandidateReviewExportError("review records must exactly match the candidate package")

    verified_images = _verified_images(package, items)
    waybills: list[LockedWaybill] = []
    quality_candidates: dict[str, list[_QualityCandidate]] = {
        condition: [] for condition in SUPPORTED_QUALITY_CONDITIONS
    }
    source_records: list[dict[str, object]] = []
    record_identities: list[dict[str, object]] = []
    waybill_membership: list[dict[str, object]] = []
    for item in items:
        normalized_record = normalized_by_sample[item.sample_id]
        review_by_slot = {image.submitted_slot: image for image in normalized_record.images}
        package_by_slot = {image.submitted_slot: image for image in item.images}
        if set(review_by_slot) != set(_SLOTS) or set(package_by_slot) != set(_SLOTS):
            raise CandidateReviewExportError("review and package submitted slots do not reconcile")
        locked_images: list[LockedTicketImage] = []
        membership_images: list[dict[str, object]] = []
        for slot in _SLOTS:
            image = package_by_slot[slot]
            review = review_by_slot[slot]
            role = TicketRole(review.role)
            locked_images.append(
                LockedTicketImage(
                    image_sha256=image.image_sha256,
                    relative_path=image.relative_path,
                    slot=TicketSlot(slot),
                    role=role,
                    ordinary_net=(
                        None if review.ordinary_net is None else Decimal(review.ordinary_net)
                    ),
                )
            )
            membership_images.append(
                {
                    "submitted_slot": slot,
                    "image_sha256": image.image_sha256,
                    "relative_path": image.relative_path,
                    "ticket_role": review.role,
                    "ordinary_net_kg": (
                        None
                        if review.ordinary_net is None
                        else str(int(Decimal(review.ordinary_net) * Decimal(1000)))
                    ),
                }
            )
            candidate = _QualityCandidate(
                sample_id=item.sample_id,
                image=image,
                review=review,
                reviewed_at=normalized_record.updated_at,
            )
            for condition in review.quality_conditions:
                quality_candidates[condition].append(candidate)
        waybills.append(
            LockedWaybill(
                sample_id=item.sample_id,
                waybill_identity_sha256=item.waybill_identity_sha256,
                images=cast(
                    tuple[LockedTicketImage, LockedTicketImage],
                    tuple(locked_images),
                ),
            )
        )
        waybill_membership.append(
            {
                "sample_id": item.sample_id,
                "waybill_identity_sha256": (item.waybill_identity_sha256),
                "images": membership_images,
            }
        )
        source_records.append(
            {
                "sample_id": normalized_record.sample_id,
                "record_version": normalized_record.record_version,
                "review_status": normalized_record.review_status,
                "decision": normalized_record.decision,
                "review_payload": normalized_record.review_payload,
                "created_at": normalized_record.created_at,
                "updated_at": normalized_record.updated_at,
                "record_evidence_sha256": (normalized_record.record_evidence_sha256),
            }
        )
        record_identities.append(
            {
                "sample_id": normalized_record.sample_id,
                "record_version": normalized_record.record_version,
                "record_evidence_sha256": (normalized_record.record_evidence_sha256),
            }
        )

    manifest = LockedSetManifest(
        dataset_id=normalized_dataset_id,
        dataset_kind="locked",
        tuning_prohibited=True,
        waybills=tuple(waybills),
    )
    manifest_payload = _manifest_payload(manifest)
    record_set_sha256 = _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package.canonical_sha256,
            "configured_reviewer_id": reviewer_id,
            "records": record_identities,
        }
    )
    verified_image_set_sha256 = _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package.canonical_sha256,
            "images": verified_images,
        }
    )
    waybill_membership_sha256 = candidate_review_waybill_membership_sha256(
        package_sha256=package.canonical_sha256,
        waybills=waybill_membership,
    )
    source_authority: dict[str, object] = {
        "schema_version": 2,
        "kind": "candidate_review_formal_source_authority",
        "authority_scope": "computed_unsealed_snapshot",
        "persistent_seal": False,
        "dataset_id": manifest.dataset_id,
        "manifest_sha256": manifest.canonical_sha256,
        "package_id": package.package_id,
        "package_sha256": package.canonical_sha256,
        "configured_reviewer_id": reviewer_id,
        "record_count": len(source_records),
        "record_set_sha256": record_set_sha256,
        "records": source_records,
        "verified_image_count": len(verified_images),
        "verified_image_set_sha256": verified_image_set_sha256,
        "verified_images": verified_images,
        "waybill_membership_count": len(waybill_membership),
        "waybill_membership_sha256": (waybill_membership_sha256),
        "waybill_membership": waybill_membership,
    }
    source_authority_sha256 = _canonical_sha256(source_authority)
    source_authority["source_authority_sha256"] = source_authority_sha256
    quality_coverage = _quality_coverage(
        manifest=manifest,
        quality_candidates=quality_candidates,
        configured_reviewer_id=reviewer_id,
    )
    quality_coverage_sha256 = cast(
        str,
        quality_coverage["quality_coverage_sha256"],
    )
    return CandidateReviewFormalExport(
        manifest=manifest,
        manifest_payload=manifest_payload,
        manifest_sha256=manifest.canonical_sha256,
        source_authority_payload=source_authority,
        source_authority_sha256=source_authority_sha256,
        record_set_sha256=record_set_sha256,
        quality_coverage_payload=quality_coverage,
        quality_coverage_sha256=quality_coverage_sha256,
    )
