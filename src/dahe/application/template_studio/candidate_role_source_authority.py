from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

from dahe.application.template_studio.candidate_review_semantics import (
    CandidateReviewSemanticError,
    validate_candidate_review_semantic_authority,
)
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.verification.locked_set_acceptance import (
    locked_set_quality_coverage_sha256,
)

_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_SOURCE_FIELDS = frozenset(
    {
        "manifest_payload",
        "manifest_sha256",
        "package_id",
        "package_sha256",
        "quality_coverage_payload",
        "quality_coverage_sha256",
        "record_set_sha256",
        "review_history_authority_payload",
        "review_history_authority_sha256",
        "source_authority_payload",
        "source_authority_sha256",
    }
)
_REVIEW_HISTORY_FIELDS = frozenset(
    {
        "schema_version",
        "kind",
        "package_sha256",
        "sample_count",
        "latest_record_count",
        "history_record_count",
        "idempotency_record_count",
        "latest_records",
        "history_records",
        "idempotency_records",
    }
)
_HISTORY_RECORD_FIELDS = frozenset(
    {
        "sample_id",
        "record_version",
        "review_status",
        "decision",
        "review_payload",
        "created_at",
        "updated_at",
    }
)
_SOURCE_RECORD_FIELDS = _HISTORY_RECORD_FIELDS | {
    "record_evidence_sha256",
}
_HISTORY_IDEMPOTENCY_FIELDS = frozenset(
    {
        "sample_id",
        "resulting_record_version",
        "idempotency_key",
        "request_hash",
        "created_at",
    }
)


class CandidateRoleEvaluationError(RuntimeError):
    """Raised when development role evidence cannot be evaluated safely."""

    __module__ = "dahe.application.template_studio.candidate_role_evaluation"


@dataclass(frozen=True, slots=True)
class _TruthImage:
    sample_id: str
    waybill_identity_sha256: str
    image_sha256: str
    submitted_slot: str
    role: TicketRole
    orientation_degrees: int

    @property
    def subject_sha256(self) -> str:
        return _canonical_sha256(
            {
                "image_sha256": self.image_sha256,
                "kind": "candidate_review_development_subject",
                "waybill_identity_sha256": (self.waybill_identity_sha256),
            }
        )


@dataclass(frozen=True, slots=True)
class _TruthPair:
    sample_id: str
    waybill_identity_sha256: str
    loading_image_sha256: str
    unloading_image_sha256: str
    expected_status: str

    @property
    def subject_sha256(self) -> str:
        return _canonical_sha256(
            {
                "kind": "candidate_review_development_pair",
                "waybill_identity_sha256": (self.waybill_identity_sha256),
            }
        )


def _canonical_json(value: object) -> str:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError) as exc:
        raise CandidateRoleEvaluationError("candidate role evidence contains invalid JSON") from exc


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _mapping(
    value: object,
    *,
    label: str,
) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise CandidateRoleEvaluationError(f"{label} must be an object")
    return cast(Mapping[str, object], value)


def _objects(
    value: object,
    *,
    label: str,
) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise CandidateRoleEvaluationError(f"{label} must be an object list")
    return cast(list[Mapping[str, object]], value)


def _required_text(
    value: object,
    *,
    label: str,
    maximum: int = 500,
) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or len(value) > maximum:
        raise CandidateRoleEvaluationError(f"{label} is invalid")
    return value


def _sha256(
    value: object,
    *,
    label: str,
) -> str:
    text = _required_text(
        value,
        label=label,
        maximum=64,
    )
    if _SHA256_PATTERN.fullmatch(text) is None:
        raise CandidateRoleEvaluationError(f"{label} must be a lowercase SHA-256")
    return text


def _positive_count(
    value: object,
    *,
    label: str,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise CandidateRoleEvaluationError(f"{label} is invalid")
    return value


def _extract_truth(
    *,
    manifest_payload: Mapping[str, object],
    source_authority_payload: Mapping[str, object],
) -> tuple[tuple[_TruthImage, ...], tuple[_TruthPair, ...]]:
    manifest_waybills = _objects(
        manifest_payload.get("waybills"),
        label="candidate manifest waybills",
    )
    manifest_by_sample: dict[
        str,
        tuple[str, dict[str, str]],
    ] = {}
    for waybill in manifest_waybills:
        sample_id = _required_text(
            waybill.get("sample_id"),
            label="candidate manifest sample ID",
            maximum=100,
        )
        waybill_identity = _sha256(
            waybill.get("waybill_identity_sha256"),
            label="candidate waybill identity",
        )
        images = _objects(
            waybill.get("images"),
            label="candidate manifest images",
        )
        by_slot = {
            _required_text(
                image.get("submitted_slot"),
                label="candidate manifest slot",
                maximum=20,
            ): _sha256(
                image.get("image_sha256"),
                label="candidate manifest image identity",
            )
            for image in images
        }
        if set(by_slot) != {"loading", "unloading"}:
            raise CandidateRoleEvaluationError("candidate manifest pair membership is invalid")
        manifest_by_sample[sample_id] = (
            waybill_identity,
            by_slot,
        )

    records = _objects(
        source_authority_payload.get("records"),
        label="candidate source records",
    )
    truth_images: list[_TruthImage] = []
    truth_pairs: list[_TruthPair] = []
    seen_images: set[str] = set()
    for record in records:
        sample_id = _required_text(
            record.get("sample_id"),
            label="candidate source sample ID",
            maximum=100,
        )
        membership = manifest_by_sample.get(sample_id)
        if membership is None:
            raise CandidateRoleEvaluationError("candidate source sample membership is invalid")
        waybill_identity, images_by_slot = membership
        review_payload = _mapping(
            record.get("review_payload"),
            label="candidate source review payload",
        )
        reviewed_images = _objects(
            review_payload.get("images"),
            label="candidate source reviewed images",
        )
        reviewed_roles: dict[str, TicketRole] = {}
        for reviewed_image in reviewed_images:
            slot = _required_text(
                reviewed_image.get("submitted_slot"),
                label="candidate reviewed slot",
                maximum=20,
            )
            try:
                role = TicketRole(
                    _required_text(
                        reviewed_image.get("role"),
                        label="candidate reviewed role",
                        maximum=20,
                    )
                )
            except ValueError as exc:
                raise CandidateRoleEvaluationError("candidate reviewed role is invalid") from exc
            raw_conditions = reviewed_image.get("quality_conditions")
            if not isinstance(raw_conditions, list) or any(
                not isinstance(value, str) for value in raw_conditions
            ):
                raise CandidateRoleEvaluationError("candidate orientation authority is invalid")
            rotations = [
                value
                for value in raw_conditions
                if value
                in {
                    "rotation_0",
                    "rotation_90",
                    "rotation_180",
                    "rotation_270",
                }
            ]
            if len(rotations) != 1 or slot not in images_by_slot:
                raise CandidateRoleEvaluationError("candidate orientation authority is invalid")
            orientation = int(rotations[0].split("_")[1])
            image_sha256 = images_by_slot[slot]
            if image_sha256 in seen_images or slot in reviewed_roles:
                raise CandidateRoleEvaluationError("candidate truth membership is duplicated")
            seen_images.add(image_sha256)
            reviewed_roles[slot] = role
            truth_images.append(
                _TruthImage(
                    sample_id=sample_id,
                    waybill_identity_sha256=waybill_identity,
                    image_sha256=image_sha256,
                    submitted_slot=slot,
                    role=role,
                    orientation_degrees=orientation,
                )
            )
        if set(reviewed_roles) != {"loading", "unloading"}:
            raise CandidateRoleEvaluationError("candidate reviewed pair membership is invalid")
        pair_conditions = review_payload.get("pair_conditions")
        if not isinstance(pair_conditions, list) or any(
            not isinstance(value, str) for value in pair_conditions
        ):
            raise CandidateRoleEvaluationError("candidate pair truth is invalid")
        primary = [
            value
            for value in pair_conditions
            if value
            in {
                "normal_pair",
                "swapped_pair",
                "same_role_pair",
                "pair_unknown",
            }
        ]
        if len(primary) != 1:
            raise CandidateRoleEvaluationError("candidate pair truth is invalid")
        expected_status = {
            "normal_pair": "normal",
            "pair_unknown": "unknown",
            "same_role_pair": "same_role",
            "swapped_pair": "swapped",
        }[primary[0]]
        truth_pairs.append(
            _TruthPair(
                sample_id=sample_id,
                waybill_identity_sha256=waybill_identity,
                loading_image_sha256=images_by_slot["loading"],
                unloading_image_sha256=(images_by_slot["unloading"]),
                expected_status=expected_status,
            )
        )
    if (
        len(truth_images) != 100
        or len(seen_images) != 100
        or len(truth_pairs) != 50
        or set(manifest_by_sample) != {pair.sample_id for pair in truth_pairs}
    ):
        raise CandidateRoleEvaluationError("candidate truth authority is incomplete")
    return (
        tuple(
            sorted(
                truth_images,
                key=lambda item: item.image_sha256,
            )
        ),
        tuple(
            sorted(
                truth_pairs,
                key=lambda item: item.subject_sha256,
            )
        ),
    )


def _history_record_key(
    record: Mapping[str, object],
    *,
    label: str,
) -> tuple[str, int]:
    if set(record) != _HISTORY_RECORD_FIELDS:
        raise CandidateRoleEvaluationError(f"{label} contract is invalid")
    sample_id = _required_text(
        record.get("sample_id"),
        label=f"{label} sample ID",
        maximum=100,
    )
    record_version = _positive_count(
        record.get("record_version"),
        label=f"{label} version",
    )
    _required_text(
        record.get("review_status"),
        label=f"{label} status",
        maximum=50,
    )
    _required_text(
        record.get("decision"),
        label=f"{label} decision",
        maximum=50,
    )
    _mapping(
        record.get("review_payload"),
        label=f"{label} payload",
    )
    _required_text(
        record.get("created_at"),
        label=f"{label} creation time",
        maximum=100,
    )
    _required_text(
        record.get("updated_at"),
        label=f"{label} update time",
        maximum=100,
    )
    return sample_id, record_version


def _validate_review_history_authority(
    value: Mapping[str, object],
    *,
    declared_sha256: str,
    source_authority: Mapping[str, object],
    package_sha256: str,
    record_set_sha256: str,
) -> None:
    history = dict(value)
    if (
        set(history) != _REVIEW_HISTORY_FIELDS
        or type(history.get("schema_version")) is not int
        or history.get("schema_version") != 1
        or history.get("kind") != "locked_set_review_authority_snapshot"
        or history.get("package_sha256") != package_sha256
        or _canonical_sha256(history) != declared_sha256
    ):
        raise CandidateRoleEvaluationError("candidate review history authority contract is invalid")
    latest_records = _objects(
        history.get("latest_records"),
        label="candidate review history latest records",
    )
    history_records = _objects(
        history.get("history_records"),
        label="candidate review history records",
    )
    idempotency_records = _objects(
        history.get("idempotency_records"),
        label="candidate review history idempotency records",
    )
    for field, expected in (
        ("sample_count", len(latest_records)),
        ("latest_record_count", len(latest_records)),
        ("history_record_count", len(history_records)),
        ("idempotency_record_count", len(idempotency_records)),
    ):
        if type(history.get(field)) is not int or history.get(field) != expected:
            raise CandidateRoleEvaluationError(
                "candidate review history authority counts do not reconcile"
            )
    if len(latest_records) != 50 or len(history_records) < 50:
        raise CandidateRoleEvaluationError("candidate review history authority is incomplete")

    history_keys: list[tuple[str, int]] = []
    history_by_sample: dict[str, list[Mapping[str, object]]] = {}
    for record in history_records:
        key = _history_record_key(
            record,
            label="candidate review history record",
        )
        history_keys.append(key)
        history_by_sample.setdefault(key[0], []).append(record)
    if (
        history_keys != sorted(history_keys)
        or len(set(history_keys)) != len(history_keys)
        or len(history_by_sample) != 50
    ):
        raise CandidateRoleEvaluationError("candidate review history record membership is invalid")
    expected_latest: list[Mapping[str, object]] = []
    for sample_id in sorted(history_by_sample):
        records = history_by_sample[sample_id]
        versions = [
            cast(
                int,
                record["record_version"],
            )
            for record in records
        ]
        if versions != list(range(1, len(records) + 1)):
            raise CandidateRoleEvaluationError(
                "candidate review history versions are not consecutive"
            )
        expected_latest.append(records[-1])
    if latest_records != expected_latest:
        raise CandidateRoleEvaluationError(
            "candidate review history latest records do not reconcile"
        )

    idempotency_targets: list[tuple[str, int]] = []
    idempotency_order: list[tuple[str, int, str]] = []
    for record in idempotency_records:
        if set(record) != _HISTORY_IDEMPOTENCY_FIELDS:
            raise CandidateRoleEvaluationError(
                "candidate review history idempotency contract is invalid"
            )
        sample_id = _required_text(
            record.get("sample_id"),
            label="candidate review idempotency sample ID",
            maximum=100,
        )
        version = _positive_count(
            record.get("resulting_record_version"),
            label="candidate review idempotency version",
        )
        idempotency_key = _required_text(
            record.get("idempotency_key"),
            label="candidate review idempotency key",
            maximum=200,
        )
        _sha256(
            record.get("request_hash"),
            label="candidate review idempotency request hash",
        )
        _required_text(
            record.get("created_at"),
            label="candidate review idempotency creation time",
            maximum=100,
        )
        idempotency_targets.append((sample_id, version))
        idempotency_order.append(
            (
                sample_id,
                version,
                idempotency_key,
            )
        )
    if (
        idempotency_order != sorted(idempotency_order)
        or len(set(idempotency_targets)) != len(idempotency_targets)
        or set(idempotency_targets) != set(history_keys)
    ):
        raise CandidateRoleEvaluationError(
            "candidate review history idempotency authority is invalid"
        )

    source_records = _objects(
        source_authority.get("records"),
        label="candidate source authority records",
    )
    if len(source_records) != 50:
        raise CandidateRoleEvaluationError("candidate source record authority is incomplete")
    source_latest: list[dict[str, object]] = []
    record_identities: list[dict[str, object]] = []
    for source_record in source_records:
        if set(source_record) != _SOURCE_RECORD_FIELDS:
            raise CandidateRoleEvaluationError(
                "candidate source record authority contract is invalid"
            )
        record_without_hash = {key: source_record[key] for key in _HISTORY_RECORD_FIELDS}
        evidence_sha256 = _sha256(
            source_record.get("record_evidence_sha256"),
            label="candidate source record evidence SHA-256",
        )
        expected_evidence_sha256 = _canonical_sha256(
            {
                "schema_version": 1,
                "package_sha256": package_sha256,
                **record_without_hash,
            }
        )
        if evidence_sha256 != expected_evidence_sha256:
            raise CandidateRoleEvaluationError(
                "candidate source record evidence does not reconcile"
            )
        source_latest.append(record_without_hash)
        record_identities.append(
            {
                "record_evidence_sha256": evidence_sha256,
                "record_version": source_record["record_version"],
                "sample_id": source_record["sample_id"],
            }
        )
    if source_latest != latest_records:
        raise CandidateRoleEvaluationError(
            "candidate review history does not bind the source truth"
        )
    expected_record_set_sha256 = _canonical_sha256(
        {
            "configured_reviewer_id": source_authority.get("configured_reviewer_id"),
            "package_sha256": package_sha256,
            "records": record_identities,
            "schema_version": 1,
        }
    )
    if expected_record_set_sha256 != record_set_sha256:
        raise CandidateRoleEvaluationError(
            "candidate source record-set authority does not reconcile"
        )


def _validate_source(
    value: object,
) -> tuple[
    dict[str, object],
    tuple[_TruthImage, ...],
    tuple[_TruthPair, ...],
]:
    source = dict(
        _mapping(
            value,
            label="candidate OCR source",
        )
    )
    if set(source) != _SOURCE_FIELDS:
        raise CandidateRoleEvaluationError("candidate OCR source contract is invalid")
    manifest_payload = _mapping(
        source["manifest_payload"],
        label="candidate manifest",
    )
    source_authority = _mapping(
        source["source_authority_payload"],
        label="candidate source authority",
    )
    try:
        semantic_manifest_sha256 = validate_candidate_review_semantic_authority(
            manifest_payload=manifest_payload,
            source_authority_payload=source_authority,
        )
    except CandidateReviewSemanticError as exc:
        raise CandidateRoleEvaluationError(
            "candidate source semantic authority is invalid"
        ) from exc
    manifest_sha256 = _sha256(
        source["manifest_sha256"],
        label="candidate manifest SHA-256",
    )
    source_authority_sha256 = _sha256(
        source["source_authority_sha256"],
        label="candidate source authority SHA-256",
    )
    authority_without_hash = dict(source_authority)
    authority_without_hash.pop(
        "source_authority_sha256",
        None,
    )
    review_history_payload = _mapping(
        source["review_history_authority_payload"],
        label="candidate review history authority",
    )
    review_history_sha256 = _sha256(
        source["review_history_authority_sha256"],
        label="candidate review history SHA-256",
    )
    quality_payload = _mapping(
        source["quality_coverage_payload"],
        label="candidate quality coverage",
    )
    quality_sha256 = _sha256(
        source["quality_coverage_sha256"],
        label="candidate quality coverage SHA-256",
    )
    package_sha256 = _sha256(
        source["package_sha256"],
        label="candidate package SHA-256",
    )
    record_set_sha256 = _sha256(
        source["record_set_sha256"],
        label="candidate record-set SHA-256",
    )
    if (
        semantic_manifest_sha256 != manifest_sha256
        or source_authority.get("manifest_sha256") != manifest_sha256
        or source_authority.get("package_id") != source["package_id"]
        or source_authority.get("package_sha256") != package_sha256
        or source_authority.get("record_set_sha256") != record_set_sha256
        or source_authority.get("source_authority_sha256") != source_authority_sha256
        or _canonical_sha256(authority_without_hash) != source_authority_sha256
        or review_history_payload.get("package_sha256") != package_sha256
        or _canonical_sha256(review_history_payload) != review_history_sha256
        or quality_payload.get("manifest_sha256") != manifest_sha256
        or quality_payload.get("dataset_id") != source_authority.get("dataset_id")
        or quality_payload.get("quality_coverage_sha256") != quality_sha256
        or locked_set_quality_coverage_sha256(quality_payload) != quality_sha256
    ):
        raise CandidateRoleEvaluationError("candidate source authority hashes do not reconcile")
    _validate_review_history_authority(
        review_history_payload,
        declared_sha256=review_history_sha256,
        source_authority=source_authority,
        package_sha256=package_sha256,
        record_set_sha256=record_set_sha256,
    )
    truth_images, truth_pairs = _extract_truth(
        manifest_payload=manifest_payload,
        source_authority_payload=source_authority,
    )
    return source, truth_images, truth_pairs
