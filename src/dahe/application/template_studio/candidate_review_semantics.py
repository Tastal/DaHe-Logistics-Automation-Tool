from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from decimal import Decimal, InvalidOperation
from typing import cast

from dahe.verification.locked_set import LockedSetManifest

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SLOTS = ("loading", "unloading")
_SLOT_ORDER = {slot: index for index, slot in enumerate(_SLOTS)}
_ROLES = frozenset({"loading", "unloading", "unknown"})
_MANIFEST_FIELDS = frozenset(
    {
        "schema_version",
        "dataset_id",
        "dataset_kind",
        "tuning_prohibited",
        "waybills",
    }
)
_MANIFEST_WAYBILL_FIELDS = frozenset(
    {
        "sample_id",
        "waybill_identity_sha256",
        "human_confirmed",
        "label_source",
        "images",
    }
)
_MANIFEST_IMAGE_FIELDS = frozenset(
    {
        "image_sha256",
        "relative_path",
        "submitted_slot",
        "role",
        "ordinary_net",
    }
)
_MEMBERSHIP_FIELDS = frozenset(
    {
        "sample_id",
        "waybill_identity_sha256",
        "images",
    }
)
_MEMBERSHIP_IMAGE_FIELDS = frozenset(
    {
        "submitted_slot",
        "image_sha256",
        "relative_path",
        "ticket_role",
        "ordinary_net_kg",
    }
)
_VERIFIED_IMAGE_FIELDS = frozenset(
    {
        "sample_id",
        "submitted_slot",
        "image_sha256",
        "relative_path",
        "width",
        "height",
        "media_type",
        "byte_count",
    }
)
_SOURCE_RECORD_FIELDS = frozenset(
    {
        "sample_id",
        "record_version",
        "review_status",
        "decision",
        "review_payload",
        "created_at",
        "updated_at",
        "record_evidence_sha256",
    }
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
_REVIEW_IMAGE_FIELDS = frozenset(
    {
        "submitted_slot",
        "role",
        "ordinary_net",
        "quality_conditions",
        "notes",
    }
)

CANDIDATE_REVIEW_SOURCE_AUTHORITY_V2_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "authority_scope",
        "persistent_seal",
        "dataset_id",
        "manifest_sha256",
        "package_id",
        "package_sha256",
        "configured_reviewer_id",
        "record_count",
        "record_set_sha256",
        "records",
        "verified_image_count",
        "verified_image_set_sha256",
        "verified_images",
        "waybill_membership_count",
        "waybill_membership_sha256",
        "waybill_membership",
        "source_authority_sha256",
    }
)
CANDIDATE_REVIEW_SOURCE_AUTHORITY_V3_FIELDS = frozenset(
    {
        *CANDIDATE_REVIEW_SOURCE_AUTHORITY_V2_FIELDS,
        "quality_coverage_sha256",
    }
)


class CandidateReviewSemanticError(ValueError):
    """Raised when independently bound review authorities disagree."""


def _canonical_sha256(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CandidateReviewSemanticError(
            "candidate-review semantic authority is not canonical JSON"
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def _object(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CandidateReviewSemanticError(f"{label} must be an object")
    return value


def _objects(value: object, *, label: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise CandidateReviewSemanticError(f"{label} must be an object list")
    return cast(list[Mapping[str, object]], value)


def _text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise CandidateReviewSemanticError(f"{label} is invalid")
    return value


def _sha256(value: object, *, label: str) -> str:
    text = _text(value, label=label)
    if _SHA256_PATTERN.fullmatch(text) is None:
        raise CandidateReviewSemanticError(f"{label} must be a lowercase SHA-256")
    return text


def _positive_count(value: object, *, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CandidateReviewSemanticError(f"{label} is invalid")
    return value


def _tonnes_to_kg(
    value: object,
    *,
    role: str,
    label: str,
) -> str | None:
    if role == "unknown":
        if value is not None:
            raise CandidateReviewSemanticError(f"{label} must be empty for an unknown ticket role")
        return None
    if not isinstance(value, str):
        raise CandidateReviewSemanticError(f"{label} is invalid")
    try:
        tonnes = Decimal(value)
    except InvalidOperation as exc:
        raise CandidateReviewSemanticError(f"{label} is invalid") from exc
    if (
        not tonnes.is_finite()
        or tonnes <= 0
        or tonnes.as_tuple().exponent != -2
        or format(tonnes, "f") != value
    ):
        raise CandidateReviewSemanticError(f"{label} is invalid")
    kilograms = tonnes * Decimal(1000)
    if kilograms != kilograms.to_integral_value():
        raise CandidateReviewSemanticError(f"{label} cannot be expressed in whole kilograms")
    return str(int(kilograms))


def _membership_kg(
    value: object,
    *,
    role: str,
    label: str,
) -> str | None:
    if role == "unknown":
        if value is not None:
            raise CandidateReviewSemanticError(f"{label} must be empty for an unknown ticket role")
        return None
    if (
        not isinstance(value, str)
        or not value.isascii()
        or not value.isdecimal()
        or value.startswith("0")
    ):
        raise CandidateReviewSemanticError(f"{label} is invalid")
    return value


def candidate_review_manifest_payload(
    manifest: LockedSetManifest,
) -> dict[str, object]:
    """Serialize the formal manifest with required human-label assertions."""

    return {
        "schema_version": 1,
        "dataset_id": manifest.dataset_id,
        "dataset_kind": manifest.dataset_kind,
        "tuning_prohibited": manifest.tuning_prohibited,
        "waybills": [
            {
                "sample_id": waybill.sample_id,
                "waybill_identity_sha256": (waybill.waybill_identity_sha256),
                "human_confirmed": True,
                "label_source": "direct_image_review",
                "images": [
                    {
                        "image_sha256": image.image_sha256,
                        "relative_path": image.relative_path,
                        "submitted_slot": image.slot.value,
                        "role": image.role.value,
                        "ordinary_net": (
                            None if image.ordinary_net is None else format(image.ordinary_net, "f")
                        ),
                    }
                    for image in waybill.images
                ],
            }
            for waybill in manifest.waybills
        ],
    }


def candidate_review_waybill_membership_sha256(
    *,
    package_sha256: str,
    waybills: Sequence[Mapping[str, object]],
) -> str:
    """Hash canonical independent package/review membership."""

    package_identity = _sha256(
        package_sha256,
        label="candidate package SHA-256",
    )
    return _canonical_sha256(
        {
            "schema_version": 1,
            "package_sha256": package_identity,
            "waybills": list(waybills),
        }
    )


def _manifest_semantics(
    manifest_payload: Mapping[str, object],
) -> tuple[
    str,
    str,
    dict[
        tuple[str, str],
        tuple[str, str, str, str, str | None],
    ],
]:
    if (
        set(manifest_payload) != _MANIFEST_FIELDS
        or type(manifest_payload.get("schema_version")) is not int
        or manifest_payload.get("schema_version") != 1
        or manifest_payload.get("dataset_kind") != "locked"
        or manifest_payload.get("tuning_prohibited") is not True
    ):
        raise CandidateReviewSemanticError("candidate-review manifest contract is invalid")
    dataset_id = _text(
        manifest_payload.get("dataset_id"),
        label="candidate-review manifest dataset ID",
    )
    waybills = _objects(
        manifest_payload.get("waybills"),
        label="candidate-review manifest waybills",
    )
    if len(waybills) != 50:
        raise CandidateReviewSemanticError("candidate-review manifest requires exactly 50 waybills")
    semantic_images: dict[
        tuple[str, str],
        tuple[str, str, str, str, str | None],
    ] = {}
    canonical_waybills: list[dict[str, object]] = []
    sample_ids: list[str] = []
    waybill_identities: set[str] = set()
    image_hashes: set[str] = set()
    relative_paths: set[str] = set()
    for raw_waybill in waybills:
        if (
            set(raw_waybill) != _MANIFEST_WAYBILL_FIELDS
            or raw_waybill.get("human_confirmed") is not True
            or raw_waybill.get("label_source") != "direct_image_review"
        ):
            raise CandidateReviewSemanticError(
                "candidate-review manifest waybill contract is invalid"
            )
        sample_id = _text(
            raw_waybill.get("sample_id"),
            label="candidate-review manifest sample ID",
        )
        waybill_identity = _sha256(
            raw_waybill.get("waybill_identity_sha256"),
            label="candidate-review manifest waybill identity",
        )
        raw_images = _objects(
            raw_waybill.get("images"),
            label="candidate-review manifest images",
        )
        if len(raw_images) != 2:
            raise CandidateReviewSemanticError(
                "candidate-review manifest waybill requires two images"
            )
        canonical_images: list[dict[str, object]] = []
        slots: list[str] = []
        for raw_image in raw_images:
            if set(raw_image) != _MANIFEST_IMAGE_FIELDS:
                raise CandidateReviewSemanticError(
                    "candidate-review manifest image contract is invalid"
                )
            slot = raw_image.get("submitted_slot")
            role = raw_image.get("role")
            if slot not in _SLOTS or role not in _ROLES:
                raise CandidateReviewSemanticError(
                    "candidate-review manifest image role or slot is invalid"
                )
            slot_text = slot
            role_text = role
            image_sha256 = _sha256(
                raw_image.get("image_sha256"),
                label="candidate-review manifest image identity",
            )
            relative_path = _text(
                raw_image.get("relative_path"),
                label="candidate-review manifest image path",
            )
            ordinary_net_kg = _tonnes_to_kg(
                raw_image.get("ordinary_net"),
                role=role_text,
                label="candidate-review manifest ordinary net",
            )
            key = (sample_id, slot_text)
            if (
                key in semantic_images
                or image_sha256 in image_hashes
                or relative_path in relative_paths
            ):
                raise CandidateReviewSemanticError(
                    "candidate-review manifest image membership is duplicated"
                )
            slots.append(slot_text)
            image_hashes.add(image_sha256)
            relative_paths.add(relative_path)
            semantic_images[key] = (
                waybill_identity,
                image_sha256,
                relative_path,
                role_text,
                ordinary_net_kg,
            )
            canonical_images.append(
                {
                    "image_sha256": image_sha256,
                    "ordinary_net": raw_image.get("ordinary_net"),
                    "relative_path": relative_path,
                    "role": role_text,
                    "submitted_slot": slot_text,
                }
            )
        if tuple(slots) != _SLOTS:
            raise CandidateReviewSemanticError(
                "candidate-review manifest submitted slots are not canonical"
            )
        if sample_id in sample_ids or waybill_identity in waybill_identities:
            raise CandidateReviewSemanticError(
                "candidate-review manifest waybill membership is duplicated"
            )
        sample_ids.append(sample_id)
        waybill_identities.add(waybill_identity)
        canonical_waybills.append(
            {
                "images": canonical_images,
                "sample_id": sample_id,
                "waybill_identity_sha256": waybill_identity,
            }
        )
    if sample_ids != sorted(sample_ids) or len(semantic_images) != 100:
        raise CandidateReviewSemanticError("candidate-review manifest membership is not canonical")
    manifest_sha256 = _canonical_sha256(
        {
            "dataset_id": dataset_id,
            "dataset_kind": "locked",
            "schema_version": 1,
            "tuning_prohibited": True,
            "waybills": canonical_waybills,
        }
    )
    return dataset_id, manifest_sha256, semantic_images


def candidate_review_manifest_sha256(
    manifest_payload: Mapping[str, object],
) -> str:
    """Compute the domain manifest identity, excluding fixed assertions."""

    return _manifest_semantics(manifest_payload)[1]


def _review_truth(
    source: Mapping[str, object],
) -> dict[tuple[str, str], tuple[str, str | None]]:
    records = _objects(
        source.get("records"),
        label="candidate-review source records",
    )
    if source.get("record_count") != 50 or len(records) != 50:
        raise CandidateReviewSemanticError("candidate-review source record counts do not reconcile")
    truth: dict[tuple[str, str], tuple[str, str | None]] = {}
    sample_ids: list[str] = []
    configured_reviewer = _text(
        source.get("configured_reviewer_id"),
        label="candidate-review configured reviewer",
    )
    for record in records:
        if (
            set(record) != _SOURCE_RECORD_FIELDS
            or record.get("review_status") != "confirmed"
            or record.get("decision") != "confirmed"
        ):
            raise CandidateReviewSemanticError("candidate-review source record contract is invalid")
        sample_id = _text(
            record.get("sample_id"),
            label="candidate-review source record sample ID",
        )
        payload = _object(
            record.get("review_payload"),
            label="candidate-review source review payload",
        )
        if (
            set(payload) != _REVIEW_PAYLOAD_FIELDS
            or payload.get("reviewer_id") != configured_reviewer
            or payload.get("decision") != "confirmed"
            or payload.get("replace_reason") is not None
        ):
            raise CandidateReviewSemanticError("candidate-review source review payload is invalid")
        images = _objects(
            payload.get("images"),
            label="candidate-review source review images",
        )
        if len(images) != 2:
            raise CandidateReviewSemanticError("candidate-review source review requires two images")
        slots: list[str] = []
        roles: dict[str, str] = {}
        for image in images:
            if set(image) != _REVIEW_IMAGE_FIELDS:
                raise CandidateReviewSemanticError(
                    "candidate-review source review image is invalid"
                )
            slot = image.get("submitted_slot")
            role = image.get("role")
            if slot not in _SLOTS or role not in _ROLES:
                raise CandidateReviewSemanticError(
                    "candidate-review source review role or slot is invalid"
                )
            slot_text = slot
            role_text = role
            key = (sample_id, slot_text)
            if key in truth:
                raise CandidateReviewSemanticError(
                    "candidate-review source review membership is duplicated"
                )
            slots.append(slot_text)
            roles[slot_text] = role_text
            truth[key] = (
                role_text,
                _tonnes_to_kg(
                    image.get("ordinary_net"),
                    role=role_text,
                    label="candidate-review source ordinary net",
                ),
            )
        if tuple(slots) != _SLOTS:
            raise CandidateReviewSemanticError(
                "candidate-review source review slots are not canonical"
            )
        pair_conditions = payload.get("pair_conditions")
        if not isinstance(pair_conditions, list) or any(
            not isinstance(item, str) for item in pair_conditions
        ):
            raise CandidateReviewSemanticError("candidate-review source pair condition is invalid")
        primary = [
            item
            for item in pair_conditions
            if item
            in {
                "normal_pair",
                "swapped_pair",
                "same_role_pair",
                "pair_unknown",
            }
        ]
        if len(primary) != 1:
            raise CandidateReviewSemanticError("candidate-review source pair condition is invalid")
        expected_roles = {
            "normal_pair": ("loading", "unloading"),
            "swapped_pair": ("unloading", "loading"),
        }
        if primary[0] in expected_roles:
            expected = expected_roles[primary[0]]
            if (
                roles["loading"],
                roles["unloading"],
            ) != expected:
                raise CandidateReviewSemanticError(
                    "candidate-review source pair condition disagrees with roles"
                )
        elif primary[0] == "same_role_pair":
            if roles["loading"] != roles["unloading"] or roles["loading"] == "unknown":
                raise CandidateReviewSemanticError(
                    "candidate-review source pair condition disagrees with roles"
                )
        elif "unknown" not in roles.values():
            raise CandidateReviewSemanticError(
                "candidate-review source pair condition disagrees with roles"
            )
        sample_ids.append(sample_id)
    if sample_ids != sorted(sample_ids) or len(set(sample_ids)) != 50:
        raise CandidateReviewSemanticError("candidate-review source records are not canonical")
    return truth


def _verified_bindings(
    source: Mapping[str, object],
) -> dict[tuple[str, str], tuple[str, str]]:
    verified = _objects(
        source.get("verified_images"),
        label="candidate-review verified images",
    )
    if source.get("verified_image_count") != 100 or len(verified) != 100:
        raise CandidateReviewSemanticError(
            "candidate-review verified image counts do not reconcile"
        )
    bindings: dict[tuple[str, str], tuple[str, str]] = {}
    image_hashes: set[str] = set()
    relative_paths: set[str] = set()
    ordered_keys: list[tuple[str, int]] = []
    for image in verified:
        if set(image) != _VERIFIED_IMAGE_FIELDS:
            raise CandidateReviewSemanticError(
                "candidate-review verified image contract is invalid"
            )
        sample_id = _text(
            image.get("sample_id"),
            label="candidate-review verified image sample ID",
        )
        slot = image.get("submitted_slot")
        if slot not in _SLOTS:
            raise CandidateReviewSemanticError("candidate-review verified image slot is invalid")
        slot_text = slot
        image_sha256 = _sha256(
            image.get("image_sha256"),
            label="candidate-review verified image identity",
        )
        relative_path = _text(
            image.get("relative_path"),
            label="candidate-review verified image path",
        )
        for field in ("width", "height", "byte_count"):
            _positive_count(
                image.get(field),
                label=f"candidate-review verified image {field}",
            )
        _text(
            image.get("media_type"),
            label="candidate-review verified image media type",
        )
        key = (sample_id, slot_text)
        if key in bindings or image_sha256 in image_hashes or relative_path in relative_paths:
            raise CandidateReviewSemanticError(
                "candidate-review verified image binding is duplicated"
            )
        bindings[key] = (image_sha256, relative_path)
        image_hashes.add(image_sha256)
        relative_paths.add(relative_path)
        ordered_keys.append((sample_id, _SLOT_ORDER[slot_text]))
    if ordered_keys != sorted(ordered_keys):
        raise CandidateReviewSemanticError(
            "candidate-review verified image bindings are not canonical"
        )
    return bindings


def _source_membership(
    source: Mapping[str, object],
) -> dict[
    tuple[str, str],
    tuple[str, str, str, str, str | None],
]:
    waybills = _objects(
        source.get("waybill_membership"),
        label="candidate-review source waybill membership",
    )
    if source.get("waybill_membership_count") != 50 or len(waybills) != 50:
        raise CandidateReviewSemanticError(
            "candidate-review waybill membership counts do not reconcile"
        )
    declared_sha256 = _sha256(
        source.get("waybill_membership_sha256"),
        label="candidate-review waybill membership SHA-256",
    )
    package_sha256 = _sha256(
        source.get("package_sha256"),
        label="candidate-review package SHA-256",
    )
    if (
        candidate_review_waybill_membership_sha256(
            package_sha256=package_sha256,
            waybills=waybills,
        )
        != declared_sha256
    ):
        raise CandidateReviewSemanticError(
            "candidate-review waybill membership SHA-256 is inconsistent"
        )
    membership: dict[
        tuple[str, str],
        tuple[str, str, str, str, str | None],
    ] = {}
    sample_ids: list[str] = []
    waybill_identities: set[str] = set()
    image_hashes: set[str] = set()
    relative_paths: set[str] = set()
    for waybill in waybills:
        if set(waybill) != _MEMBERSHIP_FIELDS:
            raise CandidateReviewSemanticError(
                "candidate-review waybill membership contract is invalid"
            )
        sample_id = _text(
            waybill.get("sample_id"),
            label="candidate-review membership sample ID",
        )
        waybill_identity = _sha256(
            waybill.get("waybill_identity_sha256"),
            label="candidate-review membership waybill identity",
        )
        images = _objects(
            waybill.get("images"),
            label="candidate-review membership images",
        )
        if len(images) != 2:
            raise CandidateReviewSemanticError(
                "candidate-review membership waybill requires two images"
            )
        slots: list[str] = []
        for image in images:
            if set(image) != _MEMBERSHIP_IMAGE_FIELDS:
                raise CandidateReviewSemanticError(
                    "candidate-review membership image contract is invalid"
                )
            slot = image.get("submitted_slot")
            role = image.get("ticket_role")
            if slot not in _SLOTS or role not in _ROLES:
                raise CandidateReviewSemanticError(
                    "candidate-review membership image role or slot is invalid"
                )
            slot_text = slot
            role_text = role
            image_sha256 = _sha256(
                image.get("image_sha256"),
                label="candidate-review membership image identity",
            )
            relative_path = _text(
                image.get("relative_path"),
                label="candidate-review membership image path",
            )
            key = (sample_id, slot_text)
            if key in membership or image_sha256 in image_hashes or relative_path in relative_paths:
                raise CandidateReviewSemanticError(
                    "candidate-review membership image is duplicated"
                )
            slots.append(slot_text)
            image_hashes.add(image_sha256)
            relative_paths.add(relative_path)
            membership[key] = (
                waybill_identity,
                image_sha256,
                relative_path,
                role_text,
                _membership_kg(
                    image.get("ordinary_net_kg"),
                    role=role_text,
                    label="candidate-review membership ordinary net",
                ),
            )
        if tuple(slots) != _SLOTS:
            raise CandidateReviewSemanticError(
                "candidate-review membership slots are not canonical"
            )
        if sample_id in sample_ids or waybill_identity in waybill_identities:
            raise CandidateReviewSemanticError("candidate-review waybill membership is duplicated")
        sample_ids.append(sample_id)
        waybill_identities.add(waybill_identity)
    if sample_ids != sorted(sample_ids) or len(membership) != 100:
        raise CandidateReviewSemanticError("candidate-review waybill membership is not canonical")
    return membership


def validate_candidate_review_semantic_authority(
    *,
    manifest_payload: Mapping[str, object],
    source_authority_payload: Mapping[str, object],
) -> str:
    """Cross-check manifest, package membership, verified files, and review truth."""

    source = _object(
        source_authority_payload,
        label="candidate-review source authority",
    )
    schema_version = source.get("schema_version")
    expected_fields = (
        CANDIDATE_REVIEW_SOURCE_AUTHORITY_V2_FIELDS
        if schema_version == 2
        else CANDIDATE_REVIEW_SOURCE_AUTHORITY_V3_FIELDS
        if schema_version == 3
        else frozenset()
    )
    if (
        set(source) != expected_fields
        or type(schema_version) is not int
        or source.get("kind") != "candidate_review_formal_source_authority"
        or source.get("authority_scope") != "computed_unsealed_snapshot"
        or source.get("persistent_seal") is not False
    ):
        raise CandidateReviewSemanticError("candidate-review source authority contract is invalid")
    dataset_id, manifest_sha256, manifest_semantics = _manifest_semantics(manifest_payload)
    if schema_version == 3:
        _sha256(
            source.get("quality_coverage_sha256"),
            label="candidate-review quality coverage hash",
        )
    if source.get("dataset_id") != dataset_id or source.get("manifest_sha256") != manifest_sha256:
        raise CandidateReviewSemanticError(
            "candidate-review source authority does not bind the manifest"
        )
    review_truth = _review_truth(source)
    verified = _verified_bindings(source)
    membership = _source_membership(source)
    if (
        set(review_truth) != set(membership)
        or set(verified) != set(membership)
        or set(manifest_semantics) != set(membership)
    ):
        raise CandidateReviewSemanticError(
            "candidate-review sample and slot memberships do not reconcile"
        )
    for key, member in membership.items():
        waybill_identity, image_sha256, relative_path, role, net_kg = member
        if verified[key] != (image_sha256, relative_path):
            raise CandidateReviewSemanticError(
                "candidate-review verified image binding does not reconcile"
            )
        if review_truth[key] != (role, net_kg):
            raise CandidateReviewSemanticError("candidate-review human truth does not reconcile")
        if manifest_semantics[key] != (
            waybill_identity,
            image_sha256,
            relative_path,
            role,
            net_kg,
        ):
            raise CandidateReviewSemanticError(
                "candidate-review manifest semantics do not reconcile"
            )
    return manifest_sha256
