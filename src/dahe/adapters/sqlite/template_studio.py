from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import PurePosixPath
from typing import cast
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.engine import Connection, RowMapping

from dahe.adapters.sqlite.candidate_development_ocr import (
    CandidateDevelopmentOcrRunPersistenceError,
    SqliteCandidateDevelopmentOcrRunRepository,
)
from dahe.adapters.sqlite.locked_set import register_exclusion_identity
from dahe.adapters.sqlite.runtime import SqliteRuntime
from dahe.adapters.sqlite.template_lifecycle_attempts import (
    CompositeLifecycleAttemptRecord,
    CompositeLifecycleAttemptScope,
    TemplateLifecycleAttemptError,
    build_composite_lifecycle_attempt_scope,
    lifecycle_attempt_record_from_mapping,
    lifecycle_attempt_row,
    validate_composite_lifecycle_attempt_scope,
)
from dahe.domain.audit.ticket_roles import TicketRole
from dahe.domain.ticket.templates import (
    AnchorMatchKind,
    NormalizedRect,
    RecognitionRegion,
    TemplateAnchor,
    TemplateDefinition,
    TemplateLifecycle,
    TemplateTransitionError,
    TemplateVersion,
    TicketField,
    canonical_template_hash,
    transition_template_version,
)


class TemplatePersistenceError(RuntimeError):
    """Base error for durable template-studio operations."""


class TemplateNotFoundError(TemplatePersistenceError, LookupError):
    """Raised when a template family or version does not exist."""


class TemplateFamilyConflictError(TemplatePersistenceError):
    """Raised when an operation conflicts with an existing family identity."""


class TemplateIdempotencyConflictError(TemplatePersistenceError):
    """Raised when an idempotency key is reused for different input."""


class TemplateRecordVersionConflictError(TemplatePersistenceError):
    """Raised when a mutation uses a stale record version."""


class TemplateLifecycleTransitionError(TemplatePersistenceError):
    """Raised when a durable lifecycle transition is not permitted."""


class TemplateAuthorizationError(TemplatePersistenceError):
    """Raised when a protected lifecycle operation lacks authorization evidence."""


class TemplateReferenceEvidenceError(TemplatePersistenceError):
    """Raised when an immutable template reference cannot be held safely."""


class TemplateReferenceUploadError(TemplatePersistenceError):
    """Raised when a staged template reference cannot be finalized safely."""


class TemplateEvaluationContractError(TemplatePersistenceError):
    """Raised when completed evaluation evidence is incomplete or inconsistent."""


class TemplateEvaluationGateError(TemplatePersistenceError):
    """Raised when an evaluation cannot authorize a lifecycle transition."""


class TemplateUnknownSampleError(TemplatePersistenceError):
    """Raised when unknown-layout evidence is unsafe to retain for tuning."""


@dataclass(frozen=True, slots=True)
class ShadowPointerRecord:
    family_id: str
    version_id: str
    record_version: int


@dataclass(frozen=True, slots=True)
class TemplateFamilySummary:
    family_id: str
    name: str
    role: TicketRole
    latest_version_id: str
    latest_version_number: int
    lifecycle: TemplateLifecycle
    record_version: int
    shadow_version_id: str | None


@dataclass(frozen=True, slots=True)
class TemplateFamilyCurrent:
    summary: TemplateFamilySummary
    version: TemplateVersion
    reference_image_sha256: str
    reference_mask_sha256: str
    alignment_fingerprint: str
    reference_image_width: int | None
    reference_image_height: int | None


@dataclass(frozen=True, slots=True)
class TemplateFamilyVersionSummary:
    version_id: str
    version_number: int
    lifecycle: TemplateLifecycle
    record_version: int


@dataclass(frozen=True, slots=True)
class TemplateEvaluationCandidateInput:
    version_id: str
    content_sha256: str


@dataclass(frozen=True, slots=True)
class TemplateEvaluationItemInput:
    sample_id: str
    waybill_id: str
    waybill_identity_sha256: str
    image_sha256: str
    truth: TicketRole
    prediction: TicketRole
    confidence: Decimal
    high_confidence: bool
    orientation_degrees: int
    evidence: Mapping[str, object]
    assessment_fingerprint: str
    elapsed_ms: Decimal
    pair_issue: str | None
    unknown_reason: str | None


@dataclass(frozen=True, slots=True)
class TemplateEvaluationPairInput:
    case_id: str
    expected_issue: str | None
    result_issue: str | None
    expected_matches_result: bool


@dataclass(frozen=True, slots=True)
class TemplateEvaluationRecord:
    evaluation_id: str
    dataset_kind: str
    dataset_id: str
    dataset_manifest_sha256: str
    template_set_fingerprint: str
    matcher_fingerprint: str
    policy_fingerprint: str
    build_fingerprint: str
    runtime_fingerprint: str
    verification_source: str
    stable_outcome_sha256: str | None
    expected_count: int
    result_count: int
    metrics: Mapping[str, object]
    metrics_sha256: str
    gate_passed: bool
    actor_id: str
    completed_at: str


@dataclass(frozen=True, slots=True)
class TemplateEligibilityContract:
    dataset_manifest_sha256: str
    matcher_fingerprint: str
    policy_fingerprint: str
    build_fingerprint: str
    runtime_fingerprint: str


@dataclass(frozen=True, slots=True)
class ShadowTemplatePublicationAuthority:
    version: TemplateVersion
    pointer_record_version: int
    publication_event_id: str
    publication_event_record_version: int
    publication_evaluation: TemplateEvaluationRecord
    lifecycle_attempt: CompositeLifecycleAttemptRecord


@dataclass(frozen=True, slots=True)
class TemplateEvaluationInvalidationRecord:
    invalidation_id: str
    evaluation_id: str
    reason: str
    actor_id: str
    created_at: str


@dataclass(frozen=True, slots=True)
class TemplateUnknownSampleRecord:
    sample_id: str
    image_sha256: str
    source_kind: str
    source_evaluation_id: str | None
    unknown_reason: str
    actor_id: str
    created_at: str


@dataclass(frozen=True, slots=True)
class TemplateReferenceUploadRecord:
    staged_reference_id: str
    image_sha256: str
    media_type: str
    width: int
    height: int
    state: str
    record_version: int
    actor_id: str
    created_at: str
    updated_at: str


@dataclass(frozen=True, slots=True)
class TemplateEvidenceRecord:
    sha256: str
    relative_path: str
    byte_size: int
    media_type: str
    record_version: int
    created_at: str
    verified_at: str


@dataclass(frozen=True, slots=True)
class TemplateReferenceOriginInput:
    """Verified development-only authority for one template reference."""

    candidate_evidence_sha256: str
    candidate_record_blob_sha256: str
    candidate_record_relative_path: str
    candidate_record_byte_size: int
    source_image_sha256: str
    source_image_relative_path: str
    source_image_byte_size: int
    source_image_media_type: str
    waybill_identity_sha256: str
    sample_id: str
    submitted_slot: str
    confirmed_role: TicketRole
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    review_record_evidence_sha256: str


@dataclass(frozen=True, slots=True)
class TemplateReferenceOriginRecord:
    version_id: str
    candidate_evidence_sha256: str
    candidate_record_blob_sha256: str
    source_image_sha256: str
    waybill_identity_sha256: str
    sample_id: str
    submitted_slot: str
    confirmed_role: TicketRole
    package_sha256: str
    review_history_authority_sha256: str
    source_authority_sha256: str
    review_record_evidence_sha256: str
    origin_sha256: str
    created_at: str


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _json_dump(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _request_hash(value: object) -> str:
    return hashlib.sha256(_json_dump(value).encode("utf-8")).hexdigest()


def _required_text(value: str, name: str, *, maximum: int = 200) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} is required")
    if len(normalized) > maximum:
        raise ValueError(f"{name} is too long")
    return normalized


def _required_sha256(value: str, name: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{name} must be a SHA-256 hexadecimal digest")
    return normalized


def _required_positive_integer(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _required_evidence_relative_path(value: str, sha256: str) -> str:
    normalized = _required_text(value, "relative_path", maximum=500).replace(
        "\\",
        "/",
    )
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or ":" in normalized
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("relative_path must remain inside the evidence data directory")
    canonical = PurePosixPath(
        "sha256",
        sha256[:2],
        sha256[2:4],
        f"{sha256}.blob",
    )
    if path != canonical:
        raise ValueError("relative_path must match the content-addressed identity")
    return canonical.as_posix()


def _required_reference_media_type(value: str) -> str:
    normalized = _required_text(value, "media_type", maximum=100).lower()
    if normalized not in {"image/jpeg", "image/png"}:
        raise ValueError("media_type must be image/jpeg or image/png")
    return normalized


def _reference_origin_payload(
    origin: TemplateReferenceOriginInput,
) -> dict[str, object]:
    if not isinstance(origin, TemplateReferenceOriginInput):
        raise ValueError("template reference origin is invalid")
    confirmed_role = origin.confirmed_role
    if confirmed_role not in {TicketRole.LOADING, TicketRole.UNLOADING}:
        raise ValueError("template reference origin confirmed role is invalid")
    submitted_slot = _required_text(
        origin.submitted_slot,
        "template reference origin submitted slot",
        maximum=20,
    )
    if submitted_slot not in {"loading", "unloading"}:
        raise ValueError("template reference origin submitted slot is invalid")
    candidate_record = _required_sha256(
        origin.candidate_record_blob_sha256,
        "candidate record blob SHA-256",
    )
    source_image = _required_sha256(
        origin.source_image_sha256,
        "template reference origin image SHA-256",
    )
    return {
        "candidate_evidence_sha256": _required_sha256(
            origin.candidate_evidence_sha256,
            "candidate development evidence SHA-256",
        ),
        "candidate_record_blob": {
            "byte_size": _required_positive_integer(
                origin.candidate_record_byte_size,
                "candidate record byte size",
            ),
            "relative_path": _required_evidence_relative_path(
                origin.candidate_record_relative_path,
                candidate_record,
            ),
            "sha256": candidate_record,
        },
        "confirmed_role": confirmed_role.value,
        "development_only": True,
        "kind": "candidate_development_template_reference_origin",
        "package_sha256": _required_sha256(
            origin.package_sha256,
            "candidate package SHA-256",
        ),
        "review_history_authority_sha256": _required_sha256(
            origin.review_history_authority_sha256,
            "candidate review history authority SHA-256",
        ),
        "review_record_evidence_sha256": _required_sha256(
            origin.review_record_evidence_sha256,
            "candidate review record evidence SHA-256",
        ),
        "sample_id": _required_text(
            origin.sample_id,
            "template reference origin sample ID",
            maximum=100,
        ),
        "schema_version": 1,
        "source_authority_sha256": _required_sha256(
            origin.source_authority_sha256,
            "candidate source authority SHA-256",
        ),
        "source_image": {
            "byte_size": _required_positive_integer(
                origin.source_image_byte_size,
                "template reference origin image byte size",
            ),
            "media_type": _required_reference_media_type(
                origin.source_image_media_type,
            ),
            "relative_path": _required_evidence_relative_path(
                origin.source_image_relative_path,
                source_image,
            ),
            "sha256": source_image,
        },
        "submitted_slot": submitted_slot,
        "waybill_identity_sha256": _required_sha256(
            origin.waybill_identity_sha256,
            "template reference origin waybill identity SHA-256",
        ),
    }


def _required_authorization(value: str) -> str:
    try:
        return _required_text(value, "developer_authorization_id")
    except (AttributeError, ValueError) as exc:
        raise TemplateAuthorizationError(
            "protected template operation requires developer authorization"
        ) from exc


def _required_count(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise TemplateEvaluationContractError(f"{name} must be a positive integer")
    return value


def _optional_text(
    value: str | None,
    name: str,
    *,
    maximum: int = 200,
) -> str | None:
    if value is None:
        return None
    try:
        return _required_text(value, name, maximum=maximum)
    except (AttributeError, ValueError) as exc:
        raise TemplateEvaluationContractError(f"{name} is invalid") from exc


def _required_evaluation_sha256(value: str, name: str) -> str:
    try:
        return _required_sha256(value, name)
    except (AttributeError, ValueError) as exc:
        raise TemplateEvaluationContractError(f"{name} is invalid") from exc


def _evaluation_record_from_row(row: RowMapping) -> TemplateEvaluationRecord:
    try:
        metrics = _mapping(
            json.loads(str(row["metrics_json"])),
            "evaluation metrics",
        )
    except (TypeError, json.JSONDecodeError) as exc:
        raise TemplatePersistenceError("stored evaluation metrics are invalid") from exc
    metrics_sha256 = hashlib.sha256(_json_dump(metrics).encode("utf-8")).hexdigest()
    if metrics_sha256 != str(row["metrics_sha256"]):
        raise TemplatePersistenceError("stored evaluation metrics hash does not match")
    return TemplateEvaluationRecord(
        evaluation_id=str(row["evaluation_id"]),
        dataset_kind=str(row["dataset_kind"]),
        dataset_id=str(row["dataset_id"]),
        dataset_manifest_sha256=str(row["dataset_manifest_sha256"]),
        template_set_fingerprint=str(row["template_set_fingerprint"]),
        matcher_fingerprint=str(row["matcher_fingerprint"]),
        policy_fingerprint=str(row["policy_fingerprint"]),
        build_fingerprint=str(row["build_fingerprint"]),
        runtime_fingerprint=str(row["runtime_fingerprint"]),
        verification_source=str(row["verification_source"]),
        stable_outcome_sha256=(
            None if row["stable_outcome_sha256"] is None else str(row["stable_outcome_sha256"])
        ),
        expected_count=int(row["expected_count"]),
        result_count=int(row["result_count"]),
        metrics=dict(metrics),
        metrics_sha256=metrics_sha256,
        gate_passed=bool(row["gate_passed"]),
        actor_id=str(row["actor_id"]),
        completed_at=str(row["completed_at"]),
    )


def _invalidation_record_from_row(
    row: RowMapping,
) -> TemplateEvaluationInvalidationRecord:
    return TemplateEvaluationInvalidationRecord(
        invalidation_id=str(row["invalidation_id"]),
        evaluation_id=str(row["evaluation_id"]),
        reason=str(row["reason"]),
        actor_id=str(row["actor_id"]),
        created_at=str(row["created_at"]),
    )


def _unknown_sample_record_from_row(row: RowMapping) -> TemplateUnknownSampleRecord:
    return TemplateUnknownSampleRecord(
        sample_id=str(row["sample_id"]),
        image_sha256=str(row["image_sha256"]),
        source_kind=str(row["source_kind"]),
        source_evaluation_id=(
            None if row["source_evaluation_id"] is None else str(row["source_evaluation_id"])
        ),
        unknown_reason=str(row["unknown_reason"]),
        actor_id=str(row["actor_id"]),
        created_at=str(row["created_at"]),
    )


def _reference_upload_record_from_row(
    row: RowMapping,
) -> TemplateReferenceUploadRecord:
    return TemplateReferenceUploadRecord(
        staged_reference_id=str(row["staged_reference_id"]),
        image_sha256=str(row["image_sha256"]),
        media_type=str(row["media_type"]),
        width=int(row["width"]),
        height=int(row["height"]),
        state=str(row["state"]),
        record_version=int(row["record_version"]),
        actor_id=str(row["actor_id"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _template_evidence_record_from_row(row: RowMapping) -> TemplateEvidenceRecord:
    if row["verified_at"] is None:
        raise TemplateReferenceEvidenceError("template evidence has not been verified")
    return TemplateEvidenceRecord(
        sha256=str(row["sha256"]),
        relative_path=str(row["relative_path"]),
        byte_size=int(row["byte_size"]),
        media_type=str(row["media_type"]),
        record_version=int(row["record_version"]),
        created_at=str(row["created_at"]),
        verified_at=str(row["verified_at"]),
    )


def _reference_origin_record_from_row(
    row: RowMapping,
) -> TemplateReferenceOriginRecord:
    try:
        payload = _mapping(
            json.loads(str(row["origin_payload_json"])),
            "template reference origin",
        )
        candidate_record = _mapping(
            payload.get("candidate_record_blob"),
            "template reference origin record blob",
        )
        source_image = _mapping(
            payload.get("source_image"),
            "template reference origin image",
        )
        normalized = _reference_origin_payload(
            TemplateReferenceOriginInput(
                candidate_evidence_sha256=_string(
                    payload,
                    "candidate_evidence_sha256",
                ),
                candidate_record_blob_sha256=_string(
                    candidate_record,
                    "sha256",
                ),
                candidate_record_relative_path=_string(
                    candidate_record,
                    "relative_path",
                ),
                candidate_record_byte_size=_integer(
                    candidate_record,
                    "byte_size",
                ),
                source_image_sha256=_string(source_image, "sha256"),
                source_image_relative_path=_string(
                    source_image,
                    "relative_path",
                ),
                source_image_byte_size=_integer(
                    source_image,
                    "byte_size",
                ),
                source_image_media_type=_string(
                    source_image,
                    "media_type",
                ),
                waybill_identity_sha256=_string(
                    payload,
                    "waybill_identity_sha256",
                ),
                sample_id=_string(payload, "sample_id"),
                submitted_slot=_string(payload, "submitted_slot"),
                confirmed_role=TicketRole(_string(payload, "confirmed_role")),
                package_sha256=_string(payload, "package_sha256"),
                review_history_authority_sha256=_string(
                    payload,
                    "review_history_authority_sha256",
                ),
                source_authority_sha256=_string(
                    payload,
                    "source_authority_sha256",
                ),
                review_record_evidence_sha256=_string(
                    payload,
                    "review_record_evidence_sha256",
                ),
            )
        )
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise TemplatePersistenceError("stored template reference origin is invalid") from exc
    origin_sha256 = str(row["origin_sha256"])
    if (
        payload != normalized
        or _request_hash(normalized) != origin_sha256
        or payload.get("kind") != "candidate_development_template_reference_origin"
        or payload.get("development_only") is not True
        or payload.get("schema_version") != 1
    ):
        raise TemplatePersistenceError("stored template reference origin identity is invalid")
    column_bindings = {
        "candidate_evidence_sha256": normalized["candidate_evidence_sha256"],
        "candidate_record_blob_sha256": candidate_record["sha256"],
        "source_image_sha256": source_image["sha256"],
        "waybill_identity_sha256": normalized["waybill_identity_sha256"],
        "sample_id": normalized["sample_id"],
        "submitted_slot": normalized["submitted_slot"],
        "confirmed_role": normalized["confirmed_role"],
        "package_sha256": normalized["package_sha256"],
        "review_history_authority_sha256": normalized["review_history_authority_sha256"],
        "source_authority_sha256": normalized["source_authority_sha256"],
        "review_record_evidence_sha256": normalized["review_record_evidence_sha256"],
    }
    if any(str(row[column]) != value for column, value in column_bindings.items()):
        raise TemplatePersistenceError("stored template reference origin columns do not reconcile")
    return TemplateReferenceOriginRecord(
        version_id=str(row["version_id"]),
        candidate_evidence_sha256=str(normalized["candidate_evidence_sha256"]),
        candidate_record_blob_sha256=str(candidate_record["sha256"]),
        source_image_sha256=str(source_image["sha256"]),
        waybill_identity_sha256=str(normalized["waybill_identity_sha256"]),
        sample_id=str(normalized["sample_id"]),
        submitted_slot=str(normalized["submitted_slot"]),
        confirmed_role=TicketRole(str(normalized["confirmed_role"])),
        package_sha256=str(normalized["package_sha256"]),
        review_history_authority_sha256=str(normalized["review_history_authority_sha256"]),
        source_authority_sha256=str(normalized["source_authority_sha256"]),
        review_record_evidence_sha256=str(normalized["review_record_evidence_sha256"]),
        origin_sha256=origin_sha256,
        created_at=str(row["created_at"]),
    )


def _decimal_text(value: Decimal) -> str:
    return format(value, "f")


def _normalized_decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


def _nearest_rank(values: Sequence[Decimal], percentile: int) -> Decimal:
    ordered = sorted(values)
    index = max(0, ((percentile * len(ordered) + 99) // 100) - 1)
    return ordered[index]


def _pair_inputs_from_metrics(
    metrics: Mapping[str, object],
) -> tuple[TemplateEvaluationPairInput, ...]:
    raw_pairs = metrics.get("pair_results")
    if not isinstance(raw_pairs, Sequence) or isinstance(
        raw_pairs,
        (str, bytes, bytearray),
    ):
        raise TemplateEvaluationContractError("evaluation metrics require pair results")
    if not raw_pairs:
        raise TemplateEvaluationContractError("evaluation metrics require at least one pair result")
    case_ids: set[str] = set()
    pairs: list[TemplateEvaluationPairInput] = []
    for raw_pair in raw_pairs:
        if not isinstance(raw_pair, Mapping):
            raise TemplateEvaluationContractError("evaluation pair result is invalid")
        try:
            case_id = _required_text(
                cast(str, raw_pair.get("case_id")),
                "evaluation pair case_id",
            )
        except (AttributeError, ValueError) as exc:
            raise TemplateEvaluationContractError("evaluation pair identity is invalid") from exc
        if case_id in case_ids:
            raise TemplateEvaluationContractError("evaluation pair identifiers must be unique")
        case_ids.add(case_id)
        expected_issue = raw_pair.get("expected_issue")
        result_issue = raw_pair.get("result_issue")
        if expected_issue is not None and not isinstance(expected_issue, str):
            raise TemplateEvaluationContractError("evaluation pair expected issue is invalid")
        if result_issue is not None and not isinstance(result_issue, str):
            raise TemplateEvaluationContractError("evaluation pair result issue is invalid")
        stated_match = raw_pair.get("expected_matches_result")
        if not isinstance(stated_match, bool):
            raise TemplateEvaluationContractError("evaluation pair reconciliation flag is invalid")
        actual_match = expected_issue == result_issue
        if stated_match is not actual_match:
            raise TemplateEvaluationContractError("evaluation pair reconciliation is inconsistent")
        pairs.append(
            TemplateEvaluationPairInput(
                case_id=case_id,
                expected_issue=expected_issue,
                result_issue=result_issue,
                expected_matches_result=stated_match,
            )
        )
    return tuple(pairs)


def _pair_payload(pair: TemplateEvaluationPairInput) -> dict[str, object]:
    return {
        "case_id": pair.case_id,
        "expected_issue": pair.expected_issue,
        "expected_matches_result": pair.expected_matches_result,
        "result_issue": pair.result_issue,
    }


def _validated_pair_gate(
    metrics: Mapping[str, object],
    pairs: Sequence[TemplateEvaluationPairInput],
) -> bool:
    if not pairs:
        raise TemplateEvaluationContractError("evaluation requires pair evidence")
    expected_payload = [_pair_payload(pair) for pair in pairs]
    if metrics.get("pair_results") != expected_payload:
        raise TemplateEvaluationContractError(
            "evaluation pair metrics do not match persisted pair evidence"
        )
    case_ids: set[str] = set()
    gate_passed = True
    for pair in pairs:
        if not isinstance(pair, TemplateEvaluationPairInput):
            raise TemplateEvaluationContractError("evaluation pair is invalid")
        try:
            case_id = _required_text(
                pair.case_id,
                "evaluation pair case_id",
            )
        except (AttributeError, ValueError) as exc:
            raise TemplateEvaluationContractError("evaluation pair identity is invalid") from exc
        if case_id in case_ids:
            raise TemplateEvaluationContractError("evaluation pair identifiers must be unique")
        case_ids.add(case_id)
        expected_issue = _optional_text(
            pair.expected_issue,
            "evaluation pair expected_issue",
            maximum=100,
        )
        result_issue = _optional_text(
            pair.result_issue,
            "evaluation pair result_issue",
            maximum=100,
        )
        actual_match = expected_issue == result_issue
        if pair.expected_matches_result is not actual_match:
            raise TemplateEvaluationContractError("evaluation pair reconciliation is inconsistent")
        gate_passed = gate_passed and actual_match
    return gate_passed


def _validate_evaluation_aggregates(
    *,
    metrics: Mapping[str, object],
    items: Sequence[TemplateEvaluationItemInput],
    pairs: Sequence[TemplateEvaluationPairInput],
    gate_passed: bool,
) -> None:
    roles = tuple(role.value for role in TicketRole)
    confusion = {truth: {prediction: 0 for prediction in roles} for truth in roles}
    unknown_count = 0
    high_confidence_error_count = 0
    item_gate_passed = True
    elapsed: list[Decimal] = []
    for item in items:
        confusion[item.truth.value][item.prediction.value] += 1
        if item.prediction is TicketRole.UNKNOWN:
            unknown_count += 1
        matches = item.truth is item.prediction
        item_gate_passed = item_gate_passed and matches
        if item.high_confidence and not matches:
            high_confidence_error_count += 1
        elapsed.append(item.elapsed_ms)

    expected_metrics: dict[str, object] = {
        "confusion_matrix": confusion,
        "high_confidence_error_count": high_confidence_error_count,
        "p50_elapsed_ms": _normalized_decimal_text(_nearest_rank(elapsed, 50)),
        "p95_elapsed_ms": _normalized_decimal_text(_nearest_rank(elapsed, 95)),
        "sample_count": len(items),
        "unknown_rate": _normalized_decimal_text(Decimal(unknown_count) / Decimal(len(items))),
    }
    for metric_id, expected_value in expected_metrics.items():
        if metrics.get(metric_id) != expected_value:
            raise TemplateEvaluationContractError(
                f"evaluation metric {metric_id} does not match item evidence"
            )

    recomputed_gate = (
        item_gate_passed
        and high_confidence_error_count == 0
        and _validated_pair_gate(metrics, pairs)
    )
    if gate_passed is not recomputed_gate:
        raise TemplateEvaluationContractError(
            "evaluation gate result does not match item and pair evidence"
        )


def _rect_payload(rect: NormalizedRect) -> dict[str, str]:
    return {
        "height": _decimal_text(rect.height),
        "width": _decimal_text(rect.width),
        "x": _decimal_text(rect.x),
        "y": _decimal_text(rect.y),
    }


def serialize_template_definition(
    definition: TemplateDefinition,
) -> dict[str, object]:
    """Return the stable persistence/API representation of a template definition."""

    return {
        "anchors": [
            {
                "anchor_id": anchor.anchor_id,
                "box": _rect_payload(anchor.box),
                "expected_text": anchor.expected_text,
                "loading_evidence": _decimal_text(anchor.loading_evidence),
                "match_kind": anchor.match_kind.value,
                "max_edit_distance": _decimal_text(anchor.max_edit_distance),
                "required": anchor.required,
                "unloading_evidence": _decimal_text(anchor.unloading_evidence),
                "weight": _decimal_text(anchor.weight),
            }
            for anchor in definition.anchors
        ],
        "family_id": definition.family_id,
        "name": definition.name,
        "regions": [
            {
                "box": _rect_payload(region.box),
                "field": region.field.value,
                "format_pattern": region.format_pattern,
                "layout_scope": region.layout_scope,
                "region_id": region.region_id,
                "relative_to_anchor_id": region.relative_to_anchor_id,
                "required": region.required,
                "unit": region.unit,
            }
            for region in definition.regions
        ],
        "role": definition.role.value,
    }


def deserialize_template_definition(
    payload: Mapping[str, object],
) -> TemplateDefinition:
    """Parse the stable template representation through persistence validation."""

    try:
        encoded = json.dumps(
            dict(payload),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    except (TypeError, ValueError) as exc:
        raise TemplatePersistenceError("template definition payload is not canonical JSON") from exc
    return _definition_from_json(encoded)


def _definition_payload(definition: TemplateDefinition) -> dict[str, object]:
    return serialize_template_definition(definition)


def _mapping(value: object, name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TemplatePersistenceError(f"stored {name} must be an object")
    return cast(Mapping[str, object], value)


def _sequence(value: object, name: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise TemplatePersistenceError(f"stored {name} must be an array")
    return cast(Sequence[object], value)


def _string(mapping: Mapping[str, object], name: str) -> str:
    value = mapping.get(name)
    if not isinstance(value, str):
        raise TemplatePersistenceError(f"stored {name} must be text")
    return value


def _boolean(mapping: Mapping[str, object], name: str) -> bool:
    value = mapping.get(name)
    if not isinstance(value, bool):
        raise TemplatePersistenceError(f"stored {name} must be boolean")
    return value


def _integer(mapping: Mapping[str, object], name: str) -> int:
    value = mapping.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise TemplatePersistenceError(f"stored {name} must be an integer")
    return value


def _rect_from_payload(value: object) -> NormalizedRect:
    payload = _mapping(value, "template rectangle")
    return NormalizedRect(
        x=Decimal(_string(payload, "x")),
        y=Decimal(_string(payload, "y")),
        width=Decimal(_string(payload, "width")),
        height=Decimal(_string(payload, "height")),
    )


def _definition_from_json(value: object) -> TemplateDefinition:
    try:
        payload = _mapping(json.loads(str(value)), "template definition")
        anchors = tuple(
            TemplateAnchor(
                anchor_id=_string(anchor_payload, "anchor_id"),
                expected_text=_string(anchor_payload, "expected_text"),
                box=_rect_from_payload(anchor_payload.get("box")),
                required=_boolean(anchor_payload, "required"),
                weight=Decimal(_string(anchor_payload, "weight")),
                max_edit_distance=Decimal(_string(anchor_payload, "max_edit_distance")),
                loading_evidence=Decimal(_string(anchor_payload, "loading_evidence")),
                unloading_evidence=Decimal(_string(anchor_payload, "unloading_evidence")),
                match_kind=AnchorMatchKind(_string(anchor_payload, "match_kind")),
            )
            for anchor_payload in (
                _mapping(item, "template anchor")
                for item in _sequence(payload.get("anchors"), "template anchors")
            )
        )
        regions = tuple(
            RecognitionRegion(
                region_id=_string(region_payload, "region_id"),
                field=TicketField(_string(region_payload, "field")),
                box=_rect_from_payload(region_payload.get("box")),
                relative_to_anchor_id=(
                    None
                    if region_payload.get("relative_to_anchor_id") is None
                    else _string(region_payload, "relative_to_anchor_id")
                ),
                unit=(
                    None if region_payload.get("unit") is None else _string(region_payload, "unit")
                ),
                format_pattern=_string(region_payload, "format_pattern"),
                required=_boolean(region_payload, "required"),
                layout_scope=_string(region_payload, "layout_scope"),
            )
            for region_payload in (
                _mapping(item, "recognition region")
                for item in _sequence(payload.get("regions"), "recognition regions")
            )
        )
        return TemplateDefinition(
            family_id=_string(payload, "family_id"),
            name=_string(payload, "name"),
            role=TicketRole(_string(payload, "role")),
            anchors=anchors,
            regions=regions,
        )
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise TemplatePersistenceError("stored template definition is invalid") from exc


def _version_result_payload(version: TemplateVersion) -> dict[str, object]:
    return {
        "lifecycle": version.lifecycle.value,
        "record_version": version.record_version,
        "version_id": version.version_id,
    }


def _pointer_result_payload(pointer: ShadowPointerRecord) -> dict[str, object]:
    return {
        "family_id": pointer.family_id,
        "record_version": pointer.record_version,
        "version_id": pointer.version_id,
    }


def _reference_upload_result_payload(
    upload: TemplateReferenceUploadRecord,
) -> dict[str, object]:
    return {
        "actor_id": upload.actor_id,
        "created_at": upload.created_at,
        "height": upload.height,
        "image_sha256": upload.image_sha256,
        "media_type": upload.media_type,
        "record_version": upload.record_version,
        "staged_reference_id": upload.staged_reference_id,
        "state": upload.state,
        "updated_at": upload.updated_at,
        "width": upload.width,
    }


def _template_evidence_result_payload(
    evidence: TemplateEvidenceRecord,
) -> dict[str, object]:
    return {
        "byte_size": evidence.byte_size,
        "created_at": evidence.created_at,
        "media_type": evidence.media_type,
        "record_version": evidence.record_version,
        "relative_path": evidence.relative_path,
        "sha256": evidence.sha256,
        "verified_at": evidence.verified_at,
    }


class SqliteTemplateRepository:
    """Persist immutable template definitions and append-only shadow decisions."""

    def __init__(
        self,
        *,
        runtime: SqliteRuntime,
        accepted_build_fingerprint: str,
        accepted_runtime_fingerprint: str | None = None,
        accepted_development_manifest_sha256: str | None = None,
        accepted_matcher_fingerprint: str | None = None,
        accepted_policy_fingerprint: str | None = None,
        failpoint: Callable[[str], None] | None = None,
    ) -> None:
        self.runtime = runtime
        self.accepted_build_fingerprint = _required_evaluation_sha256(
            accepted_build_fingerprint,
            "accepted_build_fingerprint",
        )
        self.accepted_runtime_fingerprint = (
            None
            if accepted_runtime_fingerprint is None
            else _required_evaluation_sha256(
                accepted_runtime_fingerprint,
                "accepted_runtime_fingerprint",
            )
        )
        stored_manifest_sha256 = accepted_development_manifest_sha256
        if stored_manifest_sha256 is None:
            with self.runtime.engine.connect() as connection:
                value = connection.execute(
                    text(
                        """
                        SELECT development_manifest_sha256
                        FROM template_development_contract_state
                        WHERE singleton_id = 1
                        """
                    )
                ).scalar_one_or_none()
            stored_manifest_sha256 = None if value is None else str(value)
        self.accepted_development_manifest_sha256 = (
            None
            if stored_manifest_sha256 is None
            else _required_evaluation_sha256(
                stored_manifest_sha256,
                "accepted_development_manifest_sha256",
            )
        )
        self.accepted_matcher_fingerprint = (
            None
            if accepted_matcher_fingerprint is None
            else _required_evaluation_sha256(
                accepted_matcher_fingerprint,
                "accepted_matcher_fingerprint",
            )
        )
        self.accepted_policy_fingerprint = (
            None
            if accepted_policy_fingerprint is None
            else _required_evaluation_sha256(
                accepted_policy_fingerprint,
                "accepted_policy_fingerprint",
            )
        )
        self._failpoint = failpoint

    @staticmethod
    def _load_version_row(connection: Connection, version_id: str) -> RowMapping:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        version.version_id,
                        version.family_id,
                        version.version_number,
                        version.parent_version_id,
                        version.definition_json,
                        version.content_sha256,
                        state.lifecycle,
                        state.record_version
                    FROM template_versions AS version
                    JOIN template_version_states AS state
                      ON state.version_id = version.version_id
                    WHERE version.version_id = :version_id
                    """
                ),
                {"version_id": version_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise TemplateNotFoundError("template version does not exist")
        return row

    @staticmethod
    def _version_from_row(row: RowMapping) -> TemplateVersion:
        definition = _definition_from_json(row["definition_json"])
        if canonical_template_hash(definition) != str(row["content_sha256"]):
            raise TemplatePersistenceError("stored template definition hash does not match")
        return TemplateVersion(
            version_id=str(row["version_id"]),
            version_number=int(row["version_number"]),
            definition=definition,
            lifecycle=TemplateLifecycle(str(row["lifecycle"])),
            parent_version_id=(
                None if row["parent_version_id"] is None else str(row["parent_version_id"])
            ),
            record_version=int(row["record_version"]),
        )

    @classmethod
    def _load_version(cls, connection: Connection, version_id: str) -> TemplateVersion:
        return cls._version_from_row(cls._load_version_row(connection, version_id))

    @staticmethod
    def _load_pointer(connection: Connection, family_id: str) -> ShadowPointerRecord:
        row = (
            connection.execute(
                text(
                    """
                    SELECT family_id, version_id, record_version
                    FROM template_shadow_pointers
                    WHERE family_id = :family_id
                    """
                ),
                {"family_id": family_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise TemplateNotFoundError("template family has no shadow publication")
        return ShadowPointerRecord(
            family_id=str(row["family_id"]),
            version_id=str(row["version_id"]),
            record_version=int(row["record_version"]),
        )

    @staticmethod
    def _load_reference_upload(
        connection: Connection,
        staged_reference_id: str,
    ) -> TemplateReferenceUploadRecord:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        staged_reference_id, image_sha256, media_type,
                        width, height, state, record_version, actor_id,
                        created_at, updated_at
                    FROM template_reference_uploads
                    WHERE staged_reference_id = :staged_reference_id
                    """
                ),
                {"staged_reference_id": staged_reference_id},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise TemplateNotFoundError("staged template reference does not exist")
        return _reference_upload_record_from_row(row)

    @staticmethod
    def _load_template_evidence(
        connection: Connection,
        sha256: str,
    ) -> TemplateEvidenceRecord:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        sha256, relative_path, byte_size, media_type,
                        record_version, created_at, verified_at
                    FROM evidence_blobs
                    WHERE sha256 = :sha256
                      AND storage_state = 'available'
                    """
                ),
                {"sha256": sha256},
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            raise TemplateReferenceEvidenceError("template evidence is not available")
        return _template_evidence_record_from_row(row)

    @staticmethod
    def _replay(
        connection: Connection,
        *,
        operation: str,
        idempotency_key: str,
        request_hash: str,
    ) -> tuple[str, Mapping[str, object]] | None:
        row = (
            connection.execute(
                text(
                    """
                    SELECT request_hash, result_kind, result_json
                    FROM template_idempotency_records
                    WHERE operation = :operation
                      AND idempotency_key = :idempotency_key
                    """
                ),
                {
                    "operation": operation,
                    "idempotency_key": idempotency_key,
                },
            )
            .mappings()
            .one_or_none()
        )
        if row is None:
            return None
        if str(row["request_hash"]) != request_hash:
            raise TemplateIdempotencyConflictError(
                "idempotency key belongs to different template input"
            )
        try:
            result = _mapping(json.loads(str(row["result_json"])), "idempotency result")
        except (TypeError, json.JSONDecodeError) as exc:
            raise TemplatePersistenceError("stored idempotency result is invalid") from exc
        return str(row["result_kind"]), result

    @staticmethod
    def _save_idempotency(
        connection: Connection,
        *,
        operation: str,
        idempotency_key: str,
        request_hash: str,
        result_kind: str,
        result: Mapping[str, object],
        now: str,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO template_idempotency_records (
                    operation, idempotency_key, request_hash,
                    result_kind, result_json, created_at
                ) VALUES (
                    :operation, :idempotency_key, :request_hash,
                    :result_kind, :result_json, :created_at
                )
                """
            ),
            {
                "operation": operation,
                "idempotency_key": idempotency_key,
                "request_hash": request_hash,
                "result_kind": result_kind,
                "result_json": _json_dump(result),
                "created_at": now,
            },
        )

    @staticmethod
    def _insert_lifecycle_event(
        connection: Connection,
        *,
        version_id: str,
        operation: str,
        from_lifecycle: TemplateLifecycle | None,
        to_lifecycle: TemplateLifecycle,
        record_version: int,
        evaluation_id: str | None,
        developer_authorization_id: str | None,
        actor_id: str,
        now: str,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO template_lifecycle_events (
                    event_id, version_id, operation, from_lifecycle,
                    to_lifecycle, record_version, evaluation_id,
                    developer_authorization_id, actor_id, created_at
                ) VALUES (
                    :event_id, :version_id, :operation, :from_lifecycle,
                    :to_lifecycle, :record_version, :evaluation_id,
                    :developer_authorization_id, :actor_id, :created_at
                )
                """
            ),
            {
                "event_id": uuid4().hex,
                "version_id": version_id,
                "operation": operation,
                "from_lifecycle": (None if from_lifecycle is None else from_lifecycle.value),
                "to_lifecycle": to_lifecycle.value,
                "record_version": record_version,
                "evaluation_id": evaluation_id,
                "developer_authorization_id": developer_authorization_id,
                "actor_id": actor_id,
                "created_at": now,
            },
        )

    @staticmethod
    def _insert_audit(
        connection: Connection,
        *,
        event_kind: str,
        family_id: str,
        version_id: str | None,
        actor_id: str,
        developer_authorization_id: str | None,
        detail: Mapping[str, object],
        now: str,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO template_audit_events (
                    audit_id, event_kind, family_id, version_id, actor_id,
                    developer_authorization_id, detail_json, created_at
                ) VALUES (
                    :audit_id, :event_kind, :family_id, :version_id, :actor_id,
                    :developer_authorization_id, :detail_json, :created_at
                )
                """
            ),
            {
                "audit_id": uuid4().hex,
                "event_kind": event_kind,
                "family_id": family_id,
                "version_id": version_id,
                "actor_id": actor_id,
                "developer_authorization_id": developer_authorization_id,
                "detail_json": _json_dump(detail),
                "created_at": now,
            },
        )

    @classmethod
    def _replayed_version(
        cls,
        connection: Connection,
        replay: tuple[str, Mapping[str, object]],
    ) -> TemplateVersion:
        result_kind, result = replay
        if result_kind != "version":
            raise TemplatePersistenceError("idempotency result kind is invalid")
        current = cls._load_version(connection, _string(result, "version_id"))
        record_version = result.get("record_version")
        if not isinstance(record_version, int) or isinstance(record_version, bool):
            raise TemplatePersistenceError("stored template result record version is invalid")
        try:
            lifecycle = TemplateLifecycle(_string(result, "lifecycle"))
        except ValueError as exc:
            raise TemplatePersistenceError("stored template result lifecycle is invalid") from exc
        return TemplateVersion(
            version_id=current.version_id,
            version_number=current.version_number,
            definition=current.definition,
            lifecycle=lifecycle,
            parent_version_id=current.parent_version_id,
            record_version=record_version,
        )

    @staticmethod
    def _replayed_pointer(
        replay: tuple[str, Mapping[str, object]],
    ) -> ShadowPointerRecord:
        result_kind, result = replay
        if result_kind != "shadow_pointer":
            raise TemplatePersistenceError("idempotency result kind is invalid")
        record_version = result.get("record_version")
        if not isinstance(record_version, int) or isinstance(record_version, bool):
            raise TemplatePersistenceError("stored shadow pointer record version is invalid")
        return ShadowPointerRecord(
            family_id=_string(result, "family_id"),
            version_id=_string(result, "version_id"),
            record_version=record_version,
        )

    @staticmethod
    def _replayed_reference_upload(
        replay: tuple[str, Mapping[str, object]],
    ) -> TemplateReferenceUploadRecord:
        result_kind, result = replay
        if result_kind != "reference_upload":
            raise TemplatePersistenceError("idempotency result kind is invalid")
        width = result.get("width")
        height = result.get("height")
        record_version = result.get("record_version")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (width, height, record_version)
        ):
            raise TemplatePersistenceError("stored staged reference numeric fields are invalid")
        state = _string(result, "state")
        if state not in {"staged", "consumed", "abandoned"}:
            raise TemplatePersistenceError("stored staged reference state is invalid")
        return TemplateReferenceUploadRecord(
            staged_reference_id=_string(result, "staged_reference_id"),
            image_sha256=_string(result, "image_sha256"),
            media_type=_string(result, "media_type"),
            width=cast(int, width),
            height=cast(int, height),
            state=state,
            record_version=cast(int, record_version),
            actor_id=_string(result, "actor_id"),
            created_at=_string(result, "created_at"),
            updated_at=_string(result, "updated_at"),
        )

    @staticmethod
    def _replayed_template_evidence(
        replay: tuple[str, Mapping[str, object]],
    ) -> TemplateEvidenceRecord:
        result_kind, result = replay
        if result_kind != "template_evidence":
            raise TemplatePersistenceError("idempotency result kind is invalid")
        byte_size = result.get("byte_size")
        record_version = result.get("record_version")
        if any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (byte_size, record_version)
        ):
            raise TemplatePersistenceError("stored template evidence numeric fields are invalid")
        return TemplateEvidenceRecord(
            sha256=_string(result, "sha256"),
            relative_path=_string(result, "relative_path"),
            byte_size=cast(int, byte_size),
            media_type=_string(result, "media_type"),
            record_version=cast(int, record_version),
            created_at=_string(result, "created_at"),
            verified_at=_string(result, "verified_at"),
        )

    def get_version(self, version_id: str) -> TemplateVersion:
        with self.runtime.engine.connect() as connection:
            return self._load_version(
                connection,
                _required_text(version_id, "version_id", maximum=32),
            )

    def get_reference_origin(
        self,
        version_id: str,
    ) -> TemplateReferenceOriginRecord:
        identity = _required_text(
            version_id,
            "version_id",
            maximum=32,
        )
        with self.runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            version_id, candidate_evidence_sha256,
                            candidate_record_blob_sha256,
                            source_image_sha256,
                            waybill_identity_sha256, sample_id,
                            submitted_slot, confirmed_role,
                            package_sha256,
                            review_history_authority_sha256,
                            source_authority_sha256,
                            review_record_evidence_sha256,
                            origin_payload_json, origin_sha256,
                            created_at
                        FROM template_reference_origins
                        WHERE version_id = :version_id
                        """
                    ),
                    {"version_id": identity},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise TemplateNotFoundError("template reference origin does not exist")
        return _reference_origin_record_from_row(row)

    def get_reference_upload(
        self,
        staged_reference_id: str,
    ) -> TemplateReferenceUploadRecord:
        staged_id = _required_text(
            staged_reference_id,
            "staged_reference_id",
            maximum=32,
        )
        with self.runtime.engine.connect() as connection:
            return self._load_reference_upload(connection, staged_id)

    def get_shadow_pointer(self, family_id: str) -> ShadowPointerRecord:
        with self.runtime.engine.connect() as connection:
            pointer = self._load_pointer(
                connection,
                _required_text(family_id, "family_id", maximum=100),
            )
            self._validate_shadow_version(
                connection,
                version_id=pointer.version_id,
            )
            return pointer

    @staticmethod
    def current_shadow_eligibility_contract(
        runtime: SqliteRuntime,
    ) -> TemplateEligibilityContract:
        """Read the single contract shared by every current shadow publication."""

        with runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT DISTINCT
                            evaluation.dataset_manifest_sha256,
                            evaluation.matcher_fingerprint,
                            evaluation.policy_fingerprint,
                            evaluation.build_fingerprint,
                            evaluation.runtime_fingerprint
                        FROM template_shadow_pointers AS pointer
                        JOIN template_lifecycle_events AS event
                          ON event.event_id = (
                              SELECT current.event_id
                              FROM template_lifecycle_events AS current
                              WHERE current.version_id = pointer.version_id
                                AND current.operation = 'publish_shadow'
                                AND current.to_lifecycle = 'shadow'
                              ORDER BY current.created_at DESC, current.event_id DESC
                              LIMIT 1
                          )
                        JOIN template_evaluations AS evaluation
                          ON evaluation.evaluation_id = event.evaluation_id
                        ORDER BY
                            evaluation.dataset_manifest_sha256,
                            evaluation.matcher_fingerprint,
                            evaluation.policy_fingerprint,
                            evaluation.build_fingerprint,
                            evaluation.runtime_fingerprint
                        """
                    )
                )
                .mappings()
                .all()
            )
        if len(rows) != 1:
            raise TemplateEvaluationGateError(
                "current shadow publications do not share one eligibility contract"
            )
        row = rows[0]
        return TemplateEligibilityContract(
            dataset_manifest_sha256=_required_evaluation_sha256(
                str(row["dataset_manifest_sha256"]),
                "dataset_manifest_sha256",
            ),
            matcher_fingerprint=_required_evaluation_sha256(
                str(row["matcher_fingerprint"]),
                "matcher_fingerprint",
            ),
            policy_fingerprint=_required_evaluation_sha256(
                str(row["policy_fingerprint"]),
                "policy_fingerprint",
            ),
            build_fingerprint=_required_evaluation_sha256(
                str(row["build_fingerprint"]),
                "build_fingerprint",
            ),
            runtime_fingerprint=_required_evaluation_sha256(
                str(row["runtime_fingerprint"]),
                "runtime_fingerprint",
            ),
        )

    def list_current_shadow_publication_authorities(
        self,
    ) -> tuple[ShadowTemplatePublicationAuthority, ...]:
        """Export current shadow definitions with their validated publication gate."""

        with self.runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT family_id, version_id, record_version
                        FROM template_shadow_pointers
                        ORDER BY family_id
                        """
                    )
                )
                .mappings()
                .all()
            )
            authorities: list[ShadowTemplatePublicationAuthority] = []
            for row in rows:
                version_id = str(row["version_id"])
                self._validate_shadow_version(
                    connection,
                    version_id=version_id,
                )
                version = self._load_version(connection, version_id)
                event_row = (
                    connection.execute(
                    text(
                        """
                        SELECT event_id, evaluation_id, record_version
                        FROM template_lifecycle_events
                        WHERE version_id = :version_id
                          AND operation = 'publish_shadow'
                          AND to_lifecycle = 'shadow'
                        ORDER BY created_at DESC, event_id DESC
                        LIMIT 1
                        """
                    ),
                        {"version_id": version_id},
                    )
                    .mappings()
                    .one()
                )
                evaluation_id = str(event_row["evaluation_id"])
                latest_row = self._latest_development_evaluation_row(
                    connection,
                    version=version,
                )
                evaluation = (
                    None
                    if latest_row is None
                    else self._accepted_development_evaluation_from_row(
                        connection,
                        latest_row,
                        version=version,
                    )
                )
                if (
                    evaluation is None
                    or evaluation.evaluation_id != evaluation_id
                    or not evaluation.gate_passed
                ):
                    raise TemplateEvaluationGateError(
                        "shadow publication evaluation is no longer authoritative"
                    )
                expected_scope = (
                    self._current_composite_lifecycle_attempt_scope(
                        connection,
                        record=evaluation,
                    )
                )
                if expected_scope is None:
                    raise TemplateEvaluationGateError(
                        "shadow publication lifecycle scope is unavailable"
                    )
                attempt_row = (
                    connection.execute(
                        text(
                            """
                            SELECT *
                            FROM template_lifecycle_attempts
                            WHERE scope_sha256 = :scope_sha256
                            ORDER BY attempt_sequence DESC
                            LIMIT 1
                            """
                        ),
                        {"scope_sha256": expected_scope.scope_sha256},
                    )
                    .mappings()
                    .one_or_none()
                )
                if attempt_row is None:
                    raise TemplateEvaluationGateError(
                        "shadow publication lifecycle attempt is unavailable"
                    )
                try:
                    lifecycle_attempt = lifecycle_attempt_record_from_mapping(
                        dict(attempt_row)
                    )
                except TemplateLifecycleAttemptError as exc:
                    raise TemplateEvaluationGateError(
                        "shadow publication lifecycle attempt is invalid"
                    ) from exc
                if (
                    lifecycle_attempt.evaluation_id != evaluation_id
                    or lifecycle_attempt.terminal_status != "succeeded"
                    or self._scope_from_attempt_record(
                        lifecycle_attempt
                    )
                    != expected_scope
                ):
                    raise TemplateEvaluationGateError(
                        "shadow publication lifecycle attempt does not reconcile"
                    )
                authorities.append(
                    ShadowTemplatePublicationAuthority(
                        version=version,
                        pointer_record_version=int(row["record_version"]),
                        publication_event_id=str(event_row["event_id"]),
                        publication_event_record_version=int(
                            event_row["record_version"]
                        ),
                        publication_evaluation=evaluation,
                        lifecycle_attempt=lifecycle_attempt,
                    )
                )
        if not authorities:
            raise TemplateEvaluationGateError(
                "formal authority requires at least one shadow template"
            )
        return tuple(authorities)

    def list_current_eligible_shadow_versions(self) -> tuple[TemplateVersion, ...]:
        """Load only current, evidence-valid shadow pointers for runtime matching."""

        with self.runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT family_id, version_id
                        FROM template_shadow_pointers
                        ORDER BY family_id
                        """
                    )
                )
                .mappings()
                .all()
            )
            versions: list[TemplateVersion] = []
            seen_families: set[str] = set()
            for row in rows:
                family_id = str(row["family_id"])
                version_id = str(row["version_id"])
                if family_id in seen_families:
                    raise TemplatePersistenceError(
                        "runtime shadow set contains a duplicate family pointer"
                    )
                seen_families.add(family_id)
                self._validate_shadow_version(
                    connection,
                    version_id=version_id,
                )
                version = self._load_version(connection, version_id)
                if version.definition.family_id != family_id:
                    raise TemplatePersistenceError(
                        "runtime shadow pointer family does not match its version"
                    )
                versions.append(version)
            return tuple(versions)

    def list_current_shadow_versions_for_development_evaluation(
        self,
        *,
        candidates: Sequence[TemplateVersion],
    ) -> tuple[TemplateVersion, ...]:
        """Load the current shadow set under explicit candidate replacement.

        A stored candidate may replace the current pointer for its own family,
        even when that pointer's publication evidence is stale. Every pointer
        remains structurally validated, while unrelated families must still
        satisfy the complete runtime eligibility contract.
        """

        with self.runtime.engine.connect() as connection:
            return self._load_current_shadow_versions_for_development_evaluation(
                connection,
                candidates=candidates,
            )

    def _load_current_shadow_versions_for_development_evaluation(
        self,
        connection: Connection,
        *,
        candidates: Sequence[TemplateVersion],
    ) -> tuple[TemplateVersion, ...]:
        candidate_versions = tuple(candidates)
        if not candidate_versions:
            raise TemplateEvaluationContractError(
                "development evaluation requires at least one candidate"
            )
        candidate_family_ids: set[str] = set()
        for candidate in candidate_versions:
            if not isinstance(candidate, TemplateVersion):
                raise TemplateEvaluationContractError(
                    "development evaluation candidate is invalid"
                )
            try:
                stored_candidate = self._load_version(
                    connection,
                    candidate.version_id,
                )
            except TemplateNotFoundError as exc:
                raise TemplateEvaluationContractError(
                    "development evaluation candidate is not stored"
                ) from exc
            if stored_candidate != candidate:
                raise TemplateEvaluationContractError(
                    "development evaluation candidate changed before selection"
                )
            if candidate.lifecycle not in {
                TemplateLifecycle.DRAFT,
                TemplateLifecycle.DEVELOPMENT_TESTED,
            }:
                raise TemplateEvaluationContractError(
                    "development evaluation candidates must be draft or "
                    "development_tested"
                )
            family_id = candidate.definition.family_id
            if family_id in candidate_family_ids:
                raise TemplateEvaluationContractError(
                    "development evaluation candidates require one version per family"
                )
            candidate_family_ids.add(family_id)

        rows = (
            connection.execute(
                text(
                    """
                    SELECT family_id, version_id
                    FROM template_shadow_pointers
                    ORDER BY family_id
                    """
                )
            )
            .mappings()
            .all()
        )
        versions: list[TemplateVersion] = []
        seen_families: set[str] = set()
        for row in rows:
            family_id = str(row["family_id"])
            version_id = str(row["version_id"])
            if family_id in seen_families:
                raise TemplatePersistenceError(
                    "development shadow set contains a duplicate family pointer"
                )
            seen_families.add(family_id)
            version = self._load_version(connection, version_id)
            if version.lifecycle is not TemplateLifecycle.SHADOW:
                raise TemplateEvaluationGateError(
                    "runtime template pointer does not reference a shadow version"
                )
            if version.definition.family_id != family_id:
                raise TemplatePersistenceError(
                    "development shadow pointer family does not match its version"
                )
            if family_id not in candidate_family_ids:
                self._validate_shadow_version(
                    connection,
                    version_id=version_id,
                )
            versions.append(version)
        return tuple(versions)

    def _summary_with_usable_shadow(
        self,
        connection: Connection,
        row: RowMapping,
    ) -> TemplateFamilySummary:
        summary = self._family_summary_from_row(row)
        if summary.shadow_version_id is None:
            return summary
        try:
            self._validate_shadow_version(
                connection,
                version_id=summary.shadow_version_id,
            )
        except TemplateEvaluationGateError:
            return replace(summary, shadow_version_id=None)
        return summary

    def list_families(self) -> tuple[TemplateFamilySummary, ...]:
        with self.runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT
                            family.family_id,
                            family.name,
                            family.role,
                            version.version_id,
                            version.version_number,
                            state.lifecycle,
                            state.record_version,
                            pointer.version_id AS shadow_version_id
                        FROM template_families AS family
                        JOIN template_versions AS version
                          ON version.family_id = family.family_id
                        JOIN template_version_states AS state
                          ON state.version_id = version.version_id
                        LEFT JOIN template_shadow_pointers AS pointer
                          ON pointer.family_id = family.family_id
                        WHERE NOT EXISTS (
                            SELECT 1
                            FROM template_versions AS newer
                            WHERE newer.family_id = version.family_id
                              AND newer.version_number > version.version_number
                        )
                        ORDER BY family.name, family.family_id
                        """
                    )
                )
                .mappings()
                .all()
            )
            return tuple(self._summary_with_usable_shadow(connection, row) for row in rows)

    def list_family_versions(
        self,
        family_id: str,
    ) -> tuple[TemplateFamilyVersionSummary, ...]:
        family = _required_text(family_id, "family_id", maximum=100)
        with self.runtime.engine.connect() as connection:
            rows = (
                connection.execute(
                    text(
                        """
                        SELECT
                            version.version_id,
                            version.version_number,
                            state.lifecycle,
                            state.record_version
                        FROM template_versions AS version
                        JOIN template_version_states AS state
                          ON state.version_id = version.version_id
                        WHERE version.family_id = :family_id
                        ORDER BY version.version_number DESC
                        """
                    ),
                    {"family_id": family},
                )
                .mappings()
                .all()
            )
            if not rows:
                raise TemplateNotFoundError("template family does not exist")
            return tuple(
                TemplateFamilyVersionSummary(
                    version_id=str(row["version_id"]),
                    version_number=int(row["version_number"]),
                    lifecycle=TemplateLifecycle(str(row["lifecycle"])),
                    record_version=int(row["record_version"]),
                )
                for row in rows
            )

    def get_family_current(self, family_id: str) -> TemplateFamilyCurrent:
        family = _required_text(family_id, "family_id", maximum=100)
        with self.runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            family.family_id,
                            family.name,
                            family.role,
                            version.version_id,
                            version.version_number,
                            version.parent_version_id,
                            version.definition_json,
                            version.content_sha256,
                            version.reference_image_sha256,
                            version.reference_mask_sha256,
                            version.alignment_fingerprint,
                            (
                                SELECT upload.width
                                FROM template_reference_uploads AS upload
                                WHERE upload.image_sha256 =
                                    version.reference_image_sha256
                                  AND upload.state = 'consumed'
                                ORDER BY upload.updated_at DESC
                                LIMIT 1
                            ) AS reference_image_width,
                            (
                                SELECT upload.height
                                FROM template_reference_uploads AS upload
                                WHERE upload.image_sha256 =
                                    version.reference_image_sha256
                                  AND upload.state = 'consumed'
                                ORDER BY upload.updated_at DESC
                                LIMIT 1
                            ) AS reference_image_height,
                            state.lifecycle,
                            state.record_version,
                            pointer.version_id AS shadow_version_id
                        FROM template_families AS family
                        JOIN template_versions AS version
                          ON version.family_id = family.family_id
                        JOIN template_version_states AS state
                          ON state.version_id = version.version_id
                        LEFT JOIN template_shadow_pointers AS pointer
                          ON pointer.family_id = family.family_id
                        WHERE family.family_id = :family_id
                        ORDER BY version.version_number DESC
                        LIMIT 1
                        """
                    ),
                    {"family_id": family},
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise TemplateNotFoundError("template family does not exist")
            return TemplateFamilyCurrent(
                summary=self._summary_with_usable_shadow(connection, row),
                version=self._version_from_row(row),
                reference_image_sha256=str(row["reference_image_sha256"]),
                reference_mask_sha256=str(row["reference_mask_sha256"]),
                alignment_fingerprint=str(row["alignment_fingerprint"]),
                reference_image_width=(
                    None
                    if row["reference_image_width"] is None
                    else int(row["reference_image_width"])
                ),
                reference_image_height=(
                    None
                    if row["reference_image_height"] is None
                    else int(row["reference_image_height"])
                ),
            )

    @staticmethod
    def _family_summary_from_row(row: RowMapping) -> TemplateFamilySummary:
        return TemplateFamilySummary(
            family_id=str(row["family_id"]),
            name=str(row["name"]),
            role=TicketRole(str(row["role"])),
            latest_version_id=str(row["version_id"]),
            latest_version_number=int(row["version_number"]),
            lifecycle=TemplateLifecycle(str(row["lifecycle"])),
            record_version=int(row["record_version"]),
            shadow_version_id=(
                None if row["shadow_version_id"] is None else str(row["shadow_version_id"])
            ),
        )

    def get_evaluation(self, evaluation_id: str) -> TemplateEvaluationRecord:
        try:
            identity = _required_text(
                evaluation_id,
                "evaluation_id",
                maximum=100,
            )
        except (AttributeError, ValueError) as exc:
            raise TemplateEvaluationContractError("evaluation_id is invalid") from exc
        with self.runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            evaluation_id, dataset_kind, dataset_id,
                            dataset_manifest_sha256, template_set_fingerprint,
                            matcher_fingerprint, policy_fingerprint,
                            build_fingerprint, runtime_fingerprint,
                            verification_source, stable_outcome_sha256,
                            expected_count, result_count, metrics_json,
                            metrics_sha256,
                            gate_passed, actor_id, completed_at
                        FROM template_evaluations
                        WHERE evaluation_id = :evaluation_id
                        """
                    ),
                    {"evaluation_id": identity},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise TemplateEvaluationContractError("evaluation does not exist")
        return _evaluation_record_from_row(row)

    @staticmethod
    def _insert_composite_lifecycle_attempt(
        connection: Connection,
        *,
        scope: CompositeLifecycleAttemptScope,
        terminal_status: str,
        evaluation_id: str | None,
        failure_code: str | None,
        actor_id: str,
        now: str,
    ) -> CompositeLifecycleAttemptRecord:
        row = lifecycle_attempt_row(
            scope=scope,
            terminal_status=terminal_status,
            evaluation_id=evaluation_id,
            failure_code=failure_code,
            attempt_id=uuid4().hex,
            actor_id=actor_id,
            created_at=now,
        )
        result = connection.execute(
            text(
                """
                INSERT INTO template_lifecycle_attempts (
                    attempt_id, scope_sha256, terminal_status,
                    evaluation_id, failure_code, ocr_evidence_sha256,
                    package_sha256, review_history_authority_sha256,
                    source_authority_sha256, reviewer_id,
                    ocr_capture_build_sha256,
                    role_evaluator_build_sha256,
                    composition_evidence_sha256, runtime_set_sha256,
                    pipeline_contract_sha256, dataset_manifest_sha256,
                    candidate_set_sha256, matcher_fingerprint,
                    policy_fingerprint, template_set_fingerprint,
                    composite_policy_sha256, attempt_payload_json,
                    attempt_sha256, actor_id, created_at
                ) VALUES (
                    :attempt_id, :scope_sha256, :terminal_status,
                    :evaluation_id, :failure_code, :ocr_evidence_sha256,
                    :package_sha256, :review_history_authority_sha256,
                    :source_authority_sha256, :reviewer_id,
                    :ocr_capture_build_sha256,
                    :role_evaluator_build_sha256,
                    :composition_evidence_sha256, :runtime_set_sha256,
                    :pipeline_contract_sha256, :dataset_manifest_sha256,
                    :candidate_set_sha256, :matcher_fingerprint,
                    :policy_fingerprint, :template_set_fingerprint,
                    :composite_policy_sha256, :attempt_payload_json,
                    :attempt_sha256, :actor_id, :created_at
                )
                """
            ),
            row,
        )
        sequence = result.lastrowid
        persisted = (
            connection.execute(
                text(
                    """
                    SELECT *
                    FROM template_lifecycle_attempts
                    WHERE attempt_sequence = :attempt_sequence
                    """
                ),
                {"attempt_sequence": sequence},
            )
            .mappings()
            .one()
        )
        return lifecycle_attempt_record_from_mapping(dict(persisted))

    @staticmethod
    def _scope_from_attempt_record(
        record: CompositeLifecycleAttemptRecord,
    ) -> CompositeLifecycleAttemptScope:
        return validate_composite_lifecycle_attempt_scope(
            CompositeLifecycleAttemptScope(
                **{
                    field: getattr(record, field)
                    for field in (CompositeLifecycleAttemptScope.__dataclass_fields__)
                }
            )
        )

    def get_composite_lifecycle_attempt_scope(
        self,
        evaluation_id: str,
    ) -> CompositeLifecycleAttemptScope:
        identity = _required_text(
            evaluation_id,
            "evaluation_id",
            maximum=100,
        )
        with self.runtime.engine.connect() as connection:
            row = (
                connection.execute(
                    text(
                        """
                        SELECT *
                        FROM template_lifecycle_attempts
                        WHERE evaluation_id = :evaluation_id
                          AND terminal_status = 'succeeded'
                        ORDER BY attempt_sequence DESC
                        LIMIT 1
                        """
                    ),
                    {"evaluation_id": identity},
                )
                .mappings()
                .one_or_none()
            )
        if row is None:
            raise TemplateEvaluationContractError(
                "successful composite lifecycle attempt does not exist"
            )
        try:
            return self._scope_from_attempt_record(lifecycle_attempt_record_from_mapping(dict(row)))
        except TemplateLifecycleAttemptError as exc:
            raise TemplateEvaluationContractError(str(exc)) from exc

    def record_composite_lifecycle_failure(
        self,
        *,
        scope: CompositeLifecycleAttemptScope,
        terminal_status: str,
        failure_code: str,
        actor_id: str,
    ) -> CompositeLifecycleAttemptRecord:
        if terminal_status not in {"business_failed", "technical_failed"}:
            raise TemplateEvaluationContractError("composite lifecycle failure status is invalid")
        try:
            validated_scope = validate_composite_lifecycle_attempt_scope(scope)
            actor = _required_text(actor_id, "actor_id")
            code = _required_text(
                failure_code,
                "failure_code",
                maximum=100,
            )
        except (TemplateLifecycleAttemptError, ValueError) as exc:
            raise TemplateEvaluationContractError(
                "composite lifecycle failure attempt is invalid"
            ) from exc
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            attempt = self._insert_composite_lifecycle_attempt(
                connection,
                scope=validated_scope,
                terminal_status=terminal_status,
                evaluation_id=None,
                failure_code=code,
                actor_id=actor,
                now=now,
            )
            withdrawn = (
                connection.execute(
                    text(
                        """
                        SELECT DISTINCT
                            pointer.family_id,
                            pointer.version_id,
                            pointer.record_version,
                            event.evaluation_id
                        FROM template_shadow_pointers AS pointer
                        JOIN template_lifecycle_events AS event
                          ON event.version_id = pointer.version_id
                         AND event.operation = 'publish_shadow'
                         AND event.to_lifecycle = 'shadow'
                        JOIN template_lifecycle_attempts AS succeeded
                          ON succeeded.evaluation_id = event.evaluation_id
                         AND succeeded.terminal_status = 'succeeded'
                         AND succeeded.scope_sha256 = :scope_sha256
                        """
                    ),
                    {"scope_sha256": validated_scope.scope_sha256},
                )
                .mappings()
                .all()
            )
            for shadow in withdrawn:
                connection.execute(
                    text(
                        """
                        DELETE FROM template_shadow_pointers
                        WHERE family_id = :family_id
                          AND version_id = :version_id
                          AND record_version = :record_version
                        """
                    ),
                    {
                        "family_id": str(shadow["family_id"]),
                        "version_id": str(shadow["version_id"]),
                        "record_version": int(shadow["record_version"]),
                    },
                )
                self._insert_audit(
                    connection,
                    event_kind=("template.shadow_withdrawn_after_terminal_failure"),
                    family_id=str(shadow["family_id"]),
                    version_id=str(shadow["version_id"]),
                    actor_id=actor,
                    developer_authorization_id=None,
                    detail={
                        "attempt_sequence": attempt.attempt_sequence,
                        "evaluation_id": str(shadow["evaluation_id"]),
                        "failure_code": code,
                        "terminal_status": terminal_status,
                    },
                    now=now,
                )
            return attempt

    @staticmethod
    def _latest_development_evaluation_row(
        connection: Connection,
        *,
        version: TemplateVersion,
    ) -> RowMapping | None:
        return (
            connection.execute(
                text(
                    """
                    SELECT
                        evaluation.evaluation_id,
                        evaluation.dataset_kind,
                        evaluation.dataset_id,
                        evaluation.dataset_manifest_sha256,
                        evaluation.template_set_fingerprint,
                        evaluation.matcher_fingerprint,
                        evaluation.policy_fingerprint,
                        evaluation.build_fingerprint,
                        evaluation.runtime_fingerprint,
                        evaluation.verification_source,
                        evaluation.stable_outcome_sha256,
                        evaluation.expected_count,
                        evaluation.result_count,
                        evaluation.metrics_json,
                        evaluation.metrics_sha256,
                        evaluation.gate_passed,
                        evaluation.actor_id,
                        evaluation.completed_at,
                        attempt.attempt_sequence
                            AS terminal_attempt_sequence,
                        attempt.scope_sha256
                            AS terminal_attempt_scope_sha256,
                        candidate.content_sha256 AS candidate_content_sha256,
                        invalidation.invalidation_id,
                        (
                            SELECT count(*)
                            FROM template_evaluation_items AS item
                            WHERE item.evaluation_id = evaluation.evaluation_id
                        ) AS item_count,
                        (
                            SELECT count(*)
                            FROM template_evaluation_pairs AS pair
                            WHERE pair.evaluation_id = evaluation.evaluation_id
                        ) AS pair_count
                    FROM template_evaluations AS evaluation
                    JOIN template_evaluation_candidates AS candidate
                      ON candidate.evaluation_id = evaluation.evaluation_id
                     AND candidate.version_id = :version_id
                    JOIN template_lifecycle_attempts AS attempt
                      ON attempt.evaluation_id = evaluation.evaluation_id
                     AND attempt.terminal_status = 'succeeded'
                    LEFT JOIN template_evaluation_invalidations AS invalidation
                      ON invalidation.evaluation_id = evaluation.evaluation_id
                    WHERE evaluation.dataset_kind = 'development'
                      AND NOT EXISTS (
                          SELECT 1
                          FROM template_lifecycle_attempts
                              AS newer_attempt
                          WHERE newer_attempt.scope_sha256 =
                                attempt.scope_sha256
                            AND newer_attempt.attempt_sequence >
                                attempt.attempt_sequence
                      )
                    ORDER BY
                        attempt.attempt_sequence DESC
                    LIMIT 1
                    """
                ),
                {"version_id": version.version_id},
            )
            .mappings()
            .one_or_none()
        )

    def _accepted_development_evaluation_from_row(
        self,
        connection: Connection,
        row: RowMapping,
        *,
        version: TemplateVersion,
    ) -> TemplateEvaluationRecord | None:
        accepted_contract = (
            self.accepted_development_manifest_sha256,
            self.accepted_matcher_fingerprint,
            self.accepted_policy_fingerprint,
            self.accepted_runtime_fingerprint,
        )
        if any(value is None for value in accepted_contract):
            return None
        if (
            str(row["candidate_content_sha256"]) != version.content_sha256
            or str(row["verification_source"]) != "frozen_runner"
            or row["stable_outcome_sha256"] is None
            or str(row["dataset_manifest_sha256"]) != self.accepted_development_manifest_sha256
            or str(row["matcher_fingerprint"]) != self.accepted_matcher_fingerprint
            or str(row["policy_fingerprint"]) != self.accepted_policy_fingerprint
            or str(row["build_fingerprint"]) != self.accepted_build_fingerprint
            or str(row["runtime_fingerprint"]) != self.accepted_runtime_fingerprint
            or row["completed_at"] is None
            or row["invalidation_id"] is not None
            or int(row["expected_count"]) != int(row["result_count"])
            or int(row["result_count"]) != int(row["item_count"])
            or int(row["pair_count"]) < 1
        ):
            return None
        if not self._evaluation_template_set_is_current(
            connection,
            evaluation_id=str(row["evaluation_id"]),
            expected_fingerprint=str(row["template_set_fingerprint"]),
        ):
            return None
        try:
            _required_evaluation_sha256(
                str(row["stable_outcome_sha256"]),
                "stable_outcome_sha256",
            )
            record = _evaluation_record_from_row(row)
        except TemplatePersistenceError:
            return None
        pair_results = record.metrics.get("pair_results")
        if not isinstance(pair_results, list) or len(pair_results) != int(row["pair_count"]):
            return None
        expected_scope = self._current_composite_lifecycle_attempt_scope(
            connection,
            record=record,
        )
        if expected_scope is None:
            return None
        latest_terminal_attempt = (
            connection.execute(
                text(
                    """
                    SELECT *
                    FROM template_lifecycle_attempts
                    WHERE scope_sha256 = :scope_sha256
                    ORDER BY attempt_sequence DESC
                    LIMIT 1
                    """
                ),
                {"scope_sha256": expected_scope.scope_sha256},
            )
            .mappings()
            .one_or_none()
        )
        if latest_terminal_attempt is None:
            return None
        try:
            terminal_attempt = lifecycle_attempt_record_from_mapping(
                dict(latest_terminal_attempt)
            )
        except TemplateLifecycleAttemptError:
            return None
        if (
            terminal_attempt.terminal_status != "succeeded"
            or terminal_attempt.evaluation_id != record.evaluation_id
            or self._scope_from_attempt_record(terminal_attempt)
            != expected_scope
        ):
            return None
        return record

    def _current_composite_lifecycle_attempt_scope(
        self,
        connection: Connection,
        *,
        record: TemplateEvaluationRecord,
    ) -> CompositeLifecycleAttemptScope | None:
        if record.metrics.get("lifecycle_authorization_schema_version") != 2:
            return None
        payload = record.metrics.get("composite_lifecycle")
        if not isinstance(payload, Mapping):
            return None
        component_evidence = record.metrics.get("composite_lifecycle_components")
        if not isinstance(component_evidence, Mapping):
            return None
        real_component = component_evidence.get("real_candidate_roles")
        synthetic_component = component_evidence.get("frozen_synthetic")
        if not isinstance(real_component, Mapping) or not isinstance(
            synthetic_component,
            Mapping,
        ):
            return None
        candidate_rows = (
            connection.execute(
                text(
                    """
                    SELECT version_id, content_sha256
                    FROM template_evaluation_candidates
                    WHERE evaluation_id = :evaluation_id
                    ORDER BY version_id
                    """
                ),
                {"evaluation_id": record.evaluation_id},
            )
            .mappings()
            .all()
        )
        if not candidate_rows:
            return None
        candidate_set_sha256 = _request_hash(
            [
                {
                    "content_sha256": str(row["content_sha256"]),
                    "version_id": str(row["version_id"]),
                }
                for row in candidate_rows
            ]
        )
        try:
            from dahe.application.template_studio.composite_lifecycle_evaluation import (
                CompositeLifecycleEvaluationError,
                validate_persisted_candidate_role_lifecycle_component,
                validate_persisted_composite_lifecycle_evaluation,
            )

            validate_persisted_composite_lifecycle_evaluation(
                cast(Mapping[str, object], payload),
                persisted_real_component=cast(
                    Mapping[str, object],
                    real_component,
                ),
                expected_evaluation_id=record.evaluation_id,
                expected_dataset_id=record.dataset_id,
                expected_dataset_manifest_sha256=(record.dataset_manifest_sha256),
                expected_stable_outcome_sha256=cast(
                    str,
                    record.stable_outcome_sha256,
                ),
                expected_role_evaluator_build_sha256=(record.build_fingerprint),
                expected_runtime_set_sha256=(record.runtime_fingerprint),
                expected_matcher_fingerprint=(record.matcher_fingerprint),
                expected_policy_fingerprint=(record.policy_fingerprint),
                expected_template_set_fingerprint=(record.template_set_fingerprint),
                expected_candidate_set_sha256=(candidate_set_sha256),
            )
            parent_components = payload.get("components")
            if not isinstance(parent_components, Mapping):
                return None
            parent_real = parent_components.get("real_candidate_roles")
            parent_synthetic = parent_components.get("frozen_synthetic")
            if not isinstance(parent_real, Mapping) or not isinstance(
                parent_synthetic,
                Mapping,
            ):
                return None
            real_evaluation_sha256 = parent_real.get("evaluation_sha256")
            if (
                not isinstance(real_evaluation_sha256, str)
                or real_component.get("evaluation_sha256") != real_evaluation_sha256
                or synthetic_component
                != {
                    "dataset_id": parent_synthetic.get("dataset_id"),
                    "dataset_manifest_sha256": (parent_synthetic.get("dataset_manifest_sha256")),
                    "stable_outcome_sha256": (parent_synthetic.get("stable_outcome_sha256")),
                }
            ):
                return None
            validate_persisted_candidate_role_lifecycle_component(
                cast(Mapping[str, object], real_component),
                expected_evaluation_sha256=(real_evaluation_sha256),
                expected_role_evaluator_build_sha256=(record.build_fingerprint),
                expected_runtime_set_sha256=(record.runtime_fingerprint),
                expected_matcher_fingerprint=(record.matcher_fingerprint),
                expected_policy_fingerprint=(record.policy_fingerprint),
                expected_template_set_fingerprint=(record.template_set_fingerprint),
                expected_candidate_set_sha256=(candidate_set_sha256),
            )
            real_source = real_component.get("source")
            if not isinstance(real_source, Mapping):
                return None
            evidence_sha256 = real_source.get("ocr_evidence_sha256")
            if not isinstance(evidence_sha256, str):
                return None
            ocr_repository = SqliteCandidateDevelopmentOcrRunRepository(runtime=self.runtime)
            ocr_run_authority = ocr_repository.get(evidence_sha256)
            ocr_repository.require_latest_success(evidence_sha256)
            expected_ocr_authority_bindings = {
                "application_build_sha256": real_source.get("ocr_capture_build_sha256"),
                "composition_evidence_sha256": real_source.get("composition_evidence_sha256"),
                "evidence_sha256": evidence_sha256,
                "package_sha256": real_source.get("package_sha256"),
                "pipeline_contract_sha256": real_source.get("ocr_pipeline_contract_sha256"),
                "review_history_authority_sha256": (
                    real_source.get("review_history_authority_sha256")
                ),
                "runtime_set_sha256": real_source.get("runtime_set_sha256"),
                "source_authority_sha256": real_source.get("source_authority_sha256"),
            }
            if any(
                getattr(ocr_run_authority, field) != expected
                for field, expected in (expected_ocr_authority_bindings.items())
            ):
                return None
            return build_composite_lifecycle_attempt_scope(
                metrics=dict(record.metrics),
                dataset_manifest_sha256=(
                    record.dataset_manifest_sha256
                ),
                template_set_fingerprint=(
                    record.template_set_fingerprint
                ),
                matcher_fingerprint=record.matcher_fingerprint,
                policy_fingerprint=record.policy_fingerprint,
                role_evaluator_build_sha256=(
                    record.build_fingerprint
                ),
                runtime_set_sha256=record.runtime_fingerprint,
                ocr_authority=ocr_run_authority,
            )
        except (
            CandidateDevelopmentOcrRunPersistenceError,
            CompositeLifecycleEvaluationError,
            TemplateLifecycleAttemptError,
            TypeError,
            ValueError,
        ):
            return None

    def _evaluation_template_set_is_current(
        self,
        connection: Connection,
        *,
        evaluation_id: str,
        expected_fingerprint: str,
    ) -> bool:
        from dahe.application.template_studio.matcher import (
            build_development_evaluation_template_set,
        )

        candidate_rows = (
            connection.execute(
                text(
                    """
                    SELECT
                        version_id, content_sha256, evaluated_lifecycle
                    FROM template_evaluation_candidates
                    WHERE evaluation_id = :evaluation_id
                    ORDER BY family_id, version_id
                    """
                ),
                {"evaluation_id": evaluation_id},
            )
            .mappings()
            .all()
        )
        if not candidate_rows:
            return False
        candidates: list[TemplateVersion] = []
        try:
            for candidate_row in candidate_rows:
                candidate = self._load_version(
                    connection,
                    str(candidate_row["version_id"]),
                )
                if candidate.content_sha256 != str(candidate_row["content_sha256"]):
                    return False
                evaluated_lifecycle = TemplateLifecycle(str(candidate_row["evaluated_lifecycle"]))
                if evaluated_lifecycle not in {
                    TemplateLifecycle.DRAFT,
                    TemplateLifecycle.DEVELOPMENT_TESTED,
                }:
                    return False
                candidates.append(replace(candidate, lifecycle=evaluated_lifecycle))
            current_shadow: list[TemplateVersion] = []
            shadow_version_ids = connection.execute(
                text(
                    """
                    SELECT version_id
                    FROM template_shadow_pointers
                    ORDER BY family_id, version_id
                    """
                )
            ).scalars()
            for shadow_version_id in shadow_version_ids:
                shadow = self._load_version(
                    connection,
                    str(shadow_version_id),
                )
                if shadow.lifecycle is not TemplateLifecycle.SHADOW:
                    return False
                current_shadow.append(shadow)
            current_set = build_development_evaluation_template_set(
                candidates=tuple(candidates),
                current_shadow=tuple(current_shadow),
            )
        except (TemplatePersistenceError, ValueError):
            return False
        return current_set.fingerprint == expected_fingerprint

    def get_latest_valid_development_evaluation(
        self,
        version_id: str,
    ) -> TemplateEvaluationRecord | None:
        try:
            version_identity = _required_text(
                version_id,
                "version_id",
                maximum=32,
            )
        except (AttributeError, ValueError) as exc:
            raise TemplateEvaluationContractError(
                "evaluation candidate version is invalid"
            ) from exc
        with self.runtime.engine.connect() as connection:
            version = self._load_version(connection, version_identity)
            row = self._latest_development_evaluation_row(
                connection,
                version=version,
            )
            if row is None:
                return None
            return self._accepted_development_evaluation_from_row(
                connection,
                row,
                version=version,
            )

    def record_completed_evaluation(
        self,
        *,
        evaluation_id: str,
        dataset_kind: str,
        dataset_id: str,
        dataset_manifest_sha256: str,
        template_set_fingerprint: str,
        matcher_fingerprint: str,
        policy_fingerprint: str,
        build_fingerprint: str,
        runtime_fingerprint: str,
        expected_count: int,
        result_count: int,
        metrics: Mapping[str, object],
        metrics_sha256: str,
        gate_passed: bool,
        candidates: Sequence[TemplateEvaluationCandidateInput],
        items: Sequence[TemplateEvaluationItemInput],
        actor_id: str,
    ) -> TemplateEvaluationRecord:
        """Record diagnostic evidence that cannot authorize a lifecycle change.

        Only the code-owned frozen runner uses the private verified boundary.
        Keeping untrusted records queryable is useful for diagnostics, while
        making accidental caller-assembled evidence fail closed.
        """

        return self._record_completed_evaluation(
            evaluation_id=evaluation_id,
            dataset_kind=dataset_kind,
            dataset_id=dataset_id,
            dataset_manifest_sha256=dataset_manifest_sha256,
            template_set_fingerprint=template_set_fingerprint,
            matcher_fingerprint=matcher_fingerprint,
            policy_fingerprint=policy_fingerprint,
            build_fingerprint=build_fingerprint,
            runtime_fingerprint=runtime_fingerprint,
            expected_count=expected_count,
            result_count=result_count,
            metrics=metrics,
            metrics_sha256=metrics_sha256,
            gate_passed=gate_passed,
            candidates=candidates,
            items=items,
            pairs=_pair_inputs_from_metrics(metrics),
            actor_id=actor_id,
            verification_source="untrusted_record",
            stable_outcome_sha256=None,
        )

    def _record_frozen_development_evaluation(
        self,
        *,
        evaluation_id: str,
        dataset_id: str,
        dataset_manifest_sha256: str,
        template_set_fingerprint: str,
        matcher_fingerprint: str,
        policy_fingerprint: str,
        build_fingerprint: str,
        runtime_fingerprint: str,
        expected_count: int,
        result_count: int,
        metrics: Mapping[str, object],
        metrics_sha256: str,
        gate_passed: bool,
        candidates: Sequence[TemplateEvaluationCandidateInput],
        items: Sequence[TemplateEvaluationItemInput],
        pairs: Sequence[TemplateEvaluationPairInput],
        stable_outcome_sha256: str,
        actor_id: str,
    ) -> TemplateEvaluationRecord:
        """Persist only evidence produced by the code-owned frozen runner."""

        return self._record_completed_evaluation(
            evaluation_id=evaluation_id,
            dataset_kind="development",
            dataset_id=dataset_id,
            dataset_manifest_sha256=dataset_manifest_sha256,
            template_set_fingerprint=template_set_fingerprint,
            matcher_fingerprint=matcher_fingerprint,
            policy_fingerprint=policy_fingerprint,
            build_fingerprint=build_fingerprint,
            runtime_fingerprint=runtime_fingerprint,
            expected_count=expected_count,
            result_count=result_count,
            metrics=metrics,
            metrics_sha256=metrics_sha256,
            gate_passed=gate_passed,
            candidates=candidates,
            items=items,
            pairs=pairs,
            actor_id=actor_id,
            verification_source="frozen_runner",
            stable_outcome_sha256=stable_outcome_sha256,
        )

    def _record_completed_evaluation(
        self,
        *,
        evaluation_id: str,
        dataset_kind: str,
        dataset_id: str,
        dataset_manifest_sha256: str,
        template_set_fingerprint: str,
        matcher_fingerprint: str,
        policy_fingerprint: str,
        build_fingerprint: str,
        runtime_fingerprint: str,
        expected_count: int,
        result_count: int,
        metrics: Mapping[str, object],
        metrics_sha256: str,
        gate_passed: bool,
        candidates: Sequence[TemplateEvaluationCandidateInput],
        items: Sequence[TemplateEvaluationItemInput],
        pairs: Sequence[TemplateEvaluationPairInput],
        actor_id: str,
        verification_source: str,
        stable_outcome_sha256: str | None,
    ) -> TemplateEvaluationRecord:
        try:
            identity = _required_text(
                evaluation_id,
                "evaluation_id",
                maximum=100,
            )
            dataset = _required_text(dataset_id, "dataset_id")
            actor = _required_text(actor_id, "actor_id")
        except (AttributeError, ValueError) as exc:
            raise TemplateEvaluationContractError("evaluation identity is invalid") from exc
        if dataset_kind not in {"development", "locked", "shadow"}:
            raise TemplateEvaluationContractError("evaluation dataset kind is invalid")
        manifest_sha = _required_evaluation_sha256(
            dataset_manifest_sha256,
            "dataset_manifest_sha256",
        )
        template_set_sha = _required_evaluation_sha256(
            template_set_fingerprint,
            "template_set_fingerprint",
        )
        matcher_sha = _required_evaluation_sha256(
            matcher_fingerprint,
            "matcher_fingerprint",
        )
        policy_sha = _required_evaluation_sha256(
            policy_fingerprint,
            "policy_fingerprint",
        )
        build_sha = _required_evaluation_sha256(
            build_fingerprint,
            "build_fingerprint",
        )
        runtime_sha = _required_evaluation_sha256(
            runtime_fingerprint,
            "runtime_fingerprint",
        )
        if verification_source not in {"untrusted_record", "frozen_runner"}:
            raise TemplateEvaluationContractError("evaluation verification source is invalid")
        stable_outcome_sha = (
            None
            if stable_outcome_sha256 is None
            else _required_evaluation_sha256(
                stable_outcome_sha256,
                "stable_outcome_sha256",
            )
        )
        if verification_source == "untrusted_record":
            if stable_outcome_sha is not None:
                raise TemplateEvaluationContractError(
                    "untrusted evaluation cannot carry a verified outcome"
                )
        else:
            accepted_contract = (
                self.accepted_development_manifest_sha256,
                self.accepted_matcher_fingerprint,
                self.accepted_policy_fingerprint,
                self.accepted_runtime_fingerprint,
            )
            if any(value is None for value in accepted_contract):
                raise TemplateEvaluationContractError(
                    "frozen evaluation contract is not configured"
                )
            if dataset_kind != "development":
                raise TemplateEvaluationContractError(
                    "frozen runner can record development evidence only"
                )
            if manifest_sha != self.accepted_development_manifest_sha256:
                raise TemplateEvaluationContractError(
                    "development fixture manifest is not approved"
                )
            if matcher_sha != self.accepted_matcher_fingerprint:
                raise TemplateEvaluationContractError("development matcher contract has changed")
            if policy_sha != self.accepted_policy_fingerprint:
                raise TemplateEvaluationContractError("development policy contract has changed")
            if build_sha != self.accepted_build_fingerprint:
                raise TemplateEvaluationContractError("development build contract has changed")
            if runtime_sha != self.accepted_runtime_fingerprint:
                raise TemplateEvaluationContractError(
                    "development OCR runtime contract has changed"
                )
            if stable_outcome_sha is None:
                raise TemplateEvaluationContractError(
                    "frozen evaluation requires a stable outcome hash"
                )
        expected = _required_count(expected_count, "expected_count")
        result = _required_count(result_count, "result_count")
        if expected != result or result != len(items):
            raise TemplateEvaluationContractError(
                "evaluation counts must reconcile with item count"
            )
        if not isinstance(gate_passed, bool):
            raise TemplateEvaluationContractError("evaluation gate result is invalid")
        if not isinstance(metrics, Mapping):
            raise TemplateEvaluationContractError("evaluation metrics must be an object")
        try:
            metrics_json = _json_dump(metrics)
        except (TypeError, ValueError) as exc:
            raise TemplateEvaluationContractError(
                "evaluation metrics are not canonical JSON"
            ) from exc
        expected_metrics_sha = hashlib.sha256(metrics_json.encode("utf-8")).hexdigest()
        provided_metrics_sha = _required_evaluation_sha256(
            metrics_sha256,
            "metrics_sha256",
        )
        if provided_metrics_sha != expected_metrics_sha:
            raise TemplateEvaluationContractError(
                "evaluation metrics hash does not match canonical metrics JSON"
            )
        if metrics.get("sample_count") != result:
            raise TemplateEvaluationContractError(
                "evaluation metrics sample count does not match result count"
            )
        if not candidates:
            raise TemplateEvaluationContractError("evaluation requires at least one candidate")

        candidate_inputs: list[tuple[str, str]] = []
        candidate_version_ids: set[str] = set()
        for candidate in candidates:
            if not isinstance(candidate, TemplateEvaluationCandidateInput):
                raise TemplateEvaluationContractError("evaluation candidate is invalid")
            try:
                version_identity = _required_text(
                    candidate.version_id,
                    "candidate version_id",
                    maximum=32,
                )
            except (AttributeError, ValueError) as exc:
                raise TemplateEvaluationContractError(
                    "evaluation candidate version is invalid"
                ) from exc
            content_sha = _required_evaluation_sha256(
                candidate.content_sha256,
                "candidate content_sha256",
            )
            if version_identity in candidate_version_ids:
                raise TemplateEvaluationContractError(
                    "evaluation candidate versions must be unique"
                )
            candidate_version_ids.add(version_identity)
            candidate_inputs.append((version_identity, content_sha))

        item_payloads: list[dict[str, object]] = []
        sample_ids: set[str] = set()
        for item in items:
            if not isinstance(item, TemplateEvaluationItemInput):
                raise TemplateEvaluationContractError("evaluation item is invalid")
            try:
                sample_id = _required_text(
                    item.sample_id,
                    "evaluation sample_id",
                )
                waybill_id = _required_text(
                    item.waybill_id,
                    "evaluation waybill_id",
                )
            except (AttributeError, ValueError) as exc:
                raise TemplateEvaluationContractError(
                    "evaluation item identity is invalid"
                ) from exc
            if sample_id in sample_ids:
                raise TemplateEvaluationContractError(
                    "evaluation sample identifiers must be unique"
                )
            sample_ids.add(sample_id)
            image_sha = _required_evaluation_sha256(
                item.image_sha256,
                "evaluation image_sha256",
            )
            waybill_identity_sha = _required_evaluation_sha256(
                item.waybill_identity_sha256,
                "evaluation waybill_identity_sha256",
            )
            if not isinstance(item.truth, TicketRole) or not isinstance(
                item.prediction,
                TicketRole,
            ):
                raise TemplateEvaluationContractError("evaluation item role is invalid")
            if (
                not isinstance(item.confidence, Decimal)
                or not item.confidence.is_finite()
                or not Decimal(0) <= item.confidence <= Decimal(1)
            ):
                raise TemplateEvaluationContractError("evaluation item confidence is invalid")
            if not isinstance(item.high_confidence, bool):
                raise TemplateEvaluationContractError("evaluation high-confidence flag is invalid")
            if item.orientation_degrees not in {0, 90, 180, 270}:
                raise TemplateEvaluationContractError("evaluation item orientation is invalid")
            if not isinstance(item.evidence, Mapping):
                raise TemplateEvaluationContractError("evaluation item evidence must be an object")
            try:
                evidence_json = _json_dump(item.evidence)
            except (TypeError, ValueError) as exc:
                raise TemplateEvaluationContractError(
                    "evaluation item evidence is not canonical JSON"
                ) from exc
            assessment_sha = _required_evaluation_sha256(
                item.assessment_fingerprint,
                "assessment_fingerprint",
            )
            if (
                not isinstance(item.elapsed_ms, Decimal)
                or not item.elapsed_ms.is_finite()
                or item.elapsed_ms < 0
            ):
                raise TemplateEvaluationContractError("evaluation item elapsed time is invalid")
            pair_issue = _optional_text(item.pair_issue, "pair_issue", maximum=100)
            unknown_reason = _optional_text(
                item.unknown_reason,
                "unknown_reason",
            )
            if item.prediction is TicketRole.UNKNOWN and unknown_reason is None:
                raise TemplateEvaluationContractError(
                    "unknown prediction requires an unknown reason"
                )
            if item.prediction is not TicketRole.UNKNOWN and unknown_reason is not None:
                raise TemplateEvaluationContractError(
                    "known prediction cannot carry an unknown reason"
                )
            item_payloads.append(
                {
                    "item_id": uuid4().hex,
                    "sample_id": sample_id,
                    "waybill_id": waybill_id,
                    "waybill_identity_sha256": waybill_identity_sha,
                    "image_sha256": image_sha,
                    "truth": item.truth.value,
                    "prediction": item.prediction.value,
                    "confidence": _decimal_text(item.confidence),
                    "high_confidence": int(item.high_confidence),
                    "orientation_degrees": item.orientation_degrees,
                    "evidence_json": evidence_json,
                    "assessment_fingerprint": assessment_sha,
                    "elapsed_ms": _decimal_text(item.elapsed_ms),
                    "pair_issue": pair_issue,
                    "unknown_reason": unknown_reason,
                }
            )

        _validate_evaluation_aggregates(
            metrics=metrics,
            items=items,
            pairs=pairs,
            gate_passed=gate_passed,
        )
        pair_payloads = [
            {
                "pair_id": uuid4().hex,
                **_pair_payload(pair),
            }
            for pair in pairs
        ]
        completed_at = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            exists = connection.execute(
                text("SELECT 1 FROM template_evaluations WHERE evaluation_id = :evaluation_id"),
                {"evaluation_id": identity},
            ).scalar_one_or_none()
            if exists is not None:
                raise TemplateEvaluationContractError("evaluation identity already exists")
            candidate_rows: list[tuple[str, str, str, str]] = []
            candidate_versions: list[TemplateVersion] = []
            candidate_family_ids: set[str] = set()
            for version_identity, content_sha in candidate_inputs:
                row = (
                    connection.execute(
                        text(
                            """
                            SELECT family_id, content_sha256
                            FROM template_versions
                            WHERE version_id = :version_id
                            """
                        ),
                        {"version_id": version_identity},
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise TemplateEvaluationContractError(
                        "evaluation candidate version does not exist"
                    )
                stored_content_sha = str(row["content_sha256"])
                if stored_content_sha != content_sha:
                    raise TemplateEvaluationContractError(
                        "evaluation candidate content does not match stored version"
                    )
                family_id = str(row["family_id"])
                if family_id in candidate_family_ids:
                    raise TemplateEvaluationContractError(
                        "evaluation candidates must contain one version per family"
                    )
                candidate_family_ids.add(family_id)
                candidate_version = self._load_version(
                    connection,
                    version_identity,
                )
                candidate_rows.append(
                    (
                        family_id,
                        version_identity,
                        content_sha,
                        candidate_version.lifecycle.value,
                    )
                )
                candidate_versions.append(candidate_version)

            if verification_source == "frozen_runner":
                from dahe.application.template_studio.matcher import (
                    build_development_evaluation_template_set,
                )

                try:
                    current_shadow = (
                        self._load_current_shadow_versions_for_development_evaluation(
                            connection,
                            candidates=candidate_versions,
                        )
                    )
                    persisted_template_set = build_development_evaluation_template_set(
                        candidates=tuple(candidate_versions),
                        current_shadow=current_shadow,
                    )
                except TemplatePersistenceError as exc:
                    raise TemplateEvaluationContractError(
                        "development current shadow set is invalid"
                    ) from exc
                except ValueError as exc:
                    raise TemplateEvaluationContractError(
                        "development template set is invalid"
                    ) from exc
                if persisted_template_set.fingerprint != template_set_sha:
                    raise TemplateEvaluationContractError(
                        "development template set changed before persistence"
                    )

            connection.execute(
                text(
                    """
                    INSERT INTO template_evaluations (
                        evaluation_id, dataset_kind, dataset_id,
                        dataset_manifest_sha256, template_set_fingerprint,
                        matcher_fingerprint, policy_fingerprint,
                        build_fingerprint, runtime_fingerprint,
                        verification_source, stable_outcome_sha256,
                        expected_count, result_count, metrics_json,
                        metrics_sha256, gate_passed, actor_id, completed_at
                    ) VALUES (
                        :evaluation_id, :dataset_kind, :dataset_id,
                        :dataset_manifest_sha256, :template_set_fingerprint,
                        :matcher_fingerprint, :policy_fingerprint,
                        :build_fingerprint, :runtime_fingerprint,
                        :verification_source, :stable_outcome_sha256,
                        :expected_count, :result_count, :metrics_json,
                        :metrics_sha256, :gate_passed, :actor_id, :completed_at
                    )
                    """
                ),
                {
                    "evaluation_id": identity,
                    "dataset_kind": dataset_kind,
                    "dataset_id": dataset,
                    "dataset_manifest_sha256": manifest_sha,
                    "template_set_fingerprint": template_set_sha,
                    "matcher_fingerprint": matcher_sha,
                    "policy_fingerprint": policy_sha,
                    "build_fingerprint": build_sha,
                    "runtime_fingerprint": runtime_sha,
                    "verification_source": verification_source,
                    "stable_outcome_sha256": stable_outcome_sha,
                    "expected_count": expected,
                    "result_count": result,
                    "metrics_json": metrics_json,
                    "metrics_sha256": expected_metrics_sha,
                    "gate_passed": int(gate_passed),
                    "actor_id": actor,
                    "completed_at": completed_at,
                },
            )
            for (
                family_id,
                version_identity,
                content_sha,
                evaluated_lifecycle,
            ) in candidate_rows:
                connection.execute(
                    text(
                        """
                        INSERT INTO template_evaluation_candidates (
                            evaluation_id, family_id, version_id,
                            content_sha256, evaluated_lifecycle
                        ) VALUES (
                            :evaluation_id, :family_id, :version_id,
                            :content_sha256, :evaluated_lifecycle
                        )
                        """
                    ),
                    {
                        "evaluation_id": identity,
                        "family_id": family_id,
                        "version_id": version_identity,
                        "content_sha256": content_sha,
                        "evaluated_lifecycle": evaluated_lifecycle,
                    },
                )
            for payload in item_payloads:
                connection.execute(
                    text(
                        """
                        INSERT INTO template_evaluation_items (
                            item_id, evaluation_id, sample_id, waybill_id,
                            image_sha256, truth, prediction, confidence,
                            high_confidence, orientation_degrees, evidence_json,
                            assessment_fingerprint, elapsed_ms, pair_issue,
                            unknown_reason
                        ) VALUES (
                            :item_id, :evaluation_id, :sample_id, :waybill_id,
                            :image_sha256, :truth, :prediction, :confidence,
                            :high_confidence, :orientation_degrees, :evidence_json,
                            :assessment_fingerprint, :elapsed_ms, :pair_issue,
                            :unknown_reason
                        )
                        """
                    ),
                    {"evaluation_id": identity, **payload},
                )
                image_is_evidence_backed = (
                    connection.execute(
                        text(
                            """
                            SELECT 1
                            FROM evidence_blobs
                            WHERE sha256 = :image_sha256
                              AND storage_state = 'available'
                            """
                        ),
                        {
                            "image_sha256": cast(
                                str,
                                payload["image_sha256"],
                            )
                        },
                    ).scalar_one_or_none()
                    is not None
                )
                if dataset_kind in {"development", "locked", "shadow"} and image_is_evidence_backed:
                    register_exclusion_identity(
                        connection,
                        category=(
                            "prior_locked_image"
                            if dataset_kind == "locked"
                            else f"{dataset_kind}_image"
                        ),
                        identity_sha256=cast(str, payload["image_sha256"]),
                        source_kind=f"{dataset_kind}_evaluation",
                        source_id=(f"{identity}:{cast(str, payload['sample_id'])}"),
                        created_at=completed_at,
                    )
                register_exclusion_identity(
                    connection,
                    category="prior_waybill_identity",
                    identity_sha256=cast(
                        str,
                        payload["waybill_identity_sha256"],
                    ),
                    source_kind=f"{dataset_kind}_evaluation_waybill",
                    source_id=(f"{identity}:{cast(str, payload['waybill_id'])}"),
                    created_at=completed_at,
                )
            for payload in pair_payloads:
                connection.execute(
                    text(
                        """
                        INSERT INTO template_evaluation_pairs (
                            pair_id, evaluation_id, case_id,
                            expected_issue, result_issue,
                            expected_matches_result
                        ) VALUES (
                            :pair_id, :evaluation_id, :case_id,
                            :expected_issue, :result_issue,
                            :expected_matches_result
                        )
                        """
                    ),
                    {
                        "evaluation_id": identity,
                        **payload,
                        "expected_matches_result": int(
                            cast(bool, payload["expected_matches_result"])
                        ),
                    },
                )
            persisted_item_count = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_evaluation_items "
                        "WHERE evaluation_id = :evaluation_id"
                    ),
                    {"evaluation_id": identity},
                ).scalar_one()
            )
            if persisted_item_count != expected or persisted_item_count != result:
                raise TemplateEvaluationContractError(
                    "evaluation persisted item counts do not reconcile"
                )
            persisted_pair_count = int(
                connection.execute(
                    text(
                        "SELECT count(*) FROM template_evaluation_pairs "
                        "WHERE evaluation_id = :evaluation_id"
                    ),
                    {"evaluation_id": identity},
                ).scalar_one()
            )
            if persisted_pair_count != len(pair_payloads):
                raise TemplateEvaluationContractError(
                    "evaluation persisted pair counts do not reconcile"
                )
            if verification_source == "frozen_runner":
                connection.execute(
                    text(
                        """
                        INSERT INTO template_development_contract_state (
                            singleton_id, development_manifest_sha256,
                            evaluation_id, actor_id, record_version, updated_at
                        ) VALUES (
                            1, :development_manifest_sha256,
                            :evaluation_id, :actor_id, 1, :updated_at
                        )
                        ON CONFLICT(singleton_id) DO UPDATE SET
                            development_manifest_sha256 =
                                excluded.development_manifest_sha256,
                            evaluation_id = excluded.evaluation_id,
                            actor_id = excluded.actor_id,
                            record_version =
                                template_development_contract_state.record_version + 1,
                            updated_at = excluded.updated_at
                        """
                    ),
                    {
                        "development_manifest_sha256": manifest_sha,
                        "evaluation_id": identity,
                        "actor_id": actor,
                        "updated_at": completed_at,
                    },
                )
            if (
                verification_source == "frozen_runner"
                and metrics.get("lifecycle_authorization_schema_version") == 2
            ):
                try:
                    component_evidence = metrics.get("composite_lifecycle_components")
                    if not isinstance(component_evidence, dict):
                        raise TemplateLifecycleAttemptError(
                            "composite lifecycle components are missing"
                        )
                    real_component = component_evidence.get("real_candidate_roles")
                    if not isinstance(real_component, dict):
                        raise TemplateLifecycleAttemptError("real candidate component is missing")
                    real_source = real_component.get("source")
                    if not isinstance(real_source, dict):
                        raise TemplateLifecycleAttemptError("real candidate source is missing")
                    ocr_evidence_sha256 = _required_evaluation_sha256(
                        cast(str, real_source.get("ocr_evidence_sha256")),
                        "ocr_evidence_sha256",
                    )
                    ocr_repository = SqliteCandidateDevelopmentOcrRunRepository(
                        runtime=self.runtime
                    )
                    ocr_authority = ocr_repository.get(ocr_evidence_sha256)
                    ocr_repository.require_latest_success(ocr_evidence_sha256)
                    attempt_scope = build_composite_lifecycle_attempt_scope(
                        metrics=dict(metrics),
                        dataset_manifest_sha256=manifest_sha,
                        template_set_fingerprint=template_set_sha,
                        matcher_fingerprint=matcher_sha,
                        policy_fingerprint=policy_sha,
                        role_evaluator_build_sha256=build_sha,
                        runtime_set_sha256=runtime_sha,
                        ocr_authority=ocr_authority,
                    )
                    self._insert_composite_lifecycle_attempt(
                        connection,
                        scope=attempt_scope,
                        terminal_status="succeeded",
                        evaluation_id=identity,
                        failure_code=None,
                        actor_id=actor,
                        now=completed_at,
                    )
                except CandidateDevelopmentOcrRunPersistenceError:
                    # The evaluation remains diagnostic-only. Without an
                    # exact OCR terminal authority no successful lifecycle
                    # attempt is appended, so reads and promotion fail closed.
                    pass
                except (
                    TemplateLifecycleAttemptError,
                    TypeError,
                    ValueError,
                ) as exc:
                    raise TemplateEvaluationContractError(
                        "composite lifecycle terminal attempt could not be recorded"
                    ) from exc
            if self._failpoint is not None:
                self._failpoint("after_evaluation_items")
            row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            evaluation_id, dataset_kind, dataset_id,
                            dataset_manifest_sha256, template_set_fingerprint,
                            matcher_fingerprint, policy_fingerprint,
                            build_fingerprint, runtime_fingerprint,
                            verification_source, stable_outcome_sha256,
                            expected_count, result_count, metrics_json,
                            metrics_sha256,
                            gate_passed, actor_id, completed_at
                        FROM template_evaluations
                        WHERE evaluation_id = :evaluation_id
                        """
                    ),
                    {"evaluation_id": identity},
                )
                .mappings()
                .one()
            )
            return _evaluation_record_from_row(row)

    def invalidate_evaluation(
        self,
        *,
        evaluation_id: str,
        reason: str,
        actor_id: str,
    ) -> tuple[TemplateEvaluationInvalidationRecord, bool]:
        try:
            identity = _required_text(
                evaluation_id,
                "evaluation_id",
                maximum=100,
            )
            invalidation_reason = _required_text(
                reason,
                "invalidation reason",
                maximum=500,
            )
            actor = _required_text(actor_id, "actor_id")
        except (AttributeError, ValueError) as exc:
            raise TemplateEvaluationContractError("evaluation invalidation is invalid") from exc
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            exists = connection.execute(
                text("SELECT 1 FROM template_evaluations WHERE evaluation_id = :evaluation_id"),
                {"evaluation_id": identity},
            ).scalar_one_or_none()
            if exists is None:
                raise TemplateEvaluationContractError("evaluation does not exist")
            existing = (
                connection.execute(
                    text(
                        """
                        SELECT
                            invalidation_id, evaluation_id, reason,
                            actor_id, created_at
                        FROM template_evaluation_invalidations
                        WHERE evaluation_id = :evaluation_id
                        """
                    ),
                    {"evaluation_id": identity},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                replay = _invalidation_record_from_row(existing)
                if replay.reason != invalidation_reason or replay.actor_id != actor:
                    raise TemplateEvaluationContractError(
                        "evaluation already has a different invalidation"
                    )
                return replay, False
            invalidation_id = uuid4().hex
            connection.execute(
                text(
                    """
                    INSERT INTO template_evaluation_invalidations (
                        invalidation_id, evaluation_id, reason, actor_id, created_at
                    ) VALUES (
                        :invalidation_id, :evaluation_id, :reason, :actor_id, :created_at
                    )
                    """
                ),
                {
                    "invalidation_id": invalidation_id,
                    "evaluation_id": identity,
                    "reason": invalidation_reason,
                    "actor_id": actor,
                    "created_at": now,
                },
            )
            withdrawn_shadows = (
                connection.execute(
                    text(
                        """
                        SELECT
                            pointer.family_id,
                            pointer.version_id,
                            pointer.record_version
                        FROM template_shadow_pointers AS pointer
                        JOIN template_lifecycle_events AS event
                          ON event.version_id = pointer.version_id
                         AND event.operation = 'publish_shadow'
                         AND event.to_lifecycle = 'shadow'
                        WHERE event.evaluation_id = :evaluation_id
                        """
                    ),
                    {"evaluation_id": identity},
                )
                .mappings()
                .all()
            )
            for shadow in withdrawn_shadows:
                connection.execute(
                    text(
                        """
                        DELETE FROM template_shadow_pointers
                        WHERE family_id = :family_id
                          AND version_id = :version_id
                          AND record_version = :record_version
                        """
                    ),
                    {
                        "family_id": str(shadow["family_id"]),
                        "version_id": str(shadow["version_id"]),
                        "record_version": int(shadow["record_version"]),
                    },
                )
                self._insert_audit(
                    connection,
                    event_kind=("template.shadow_withdrawn_after_evaluation_invalidation"),
                    family_id=str(shadow["family_id"]),
                    version_id=str(shadow["version_id"]),
                    actor_id=actor,
                    developer_authorization_id=None,
                    detail={
                        "evaluation_id": identity,
                        "reason": invalidation_reason,
                    },
                    now=now,
                )
            return (
                TemplateEvaluationInvalidationRecord(
                    invalidation_id=invalidation_id,
                    evaluation_id=identity,
                    reason=invalidation_reason,
                    actor_id=actor,
                    created_at=now,
                ),
                True,
            )

    def add_unknown_sample(
        self,
        *,
        image_sha256: str,
        source_kind: str,
        source_evaluation_id: str | None,
        unknown_reason: str,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[TemplateUnknownSampleRecord, bool]:
        if source_kind not in {"development", "calibration"}:
            raise TemplateUnknownSampleError(
                "unknown samples accept development or calibration sources only"
            )
        try:
            image_sha = _required_sha256(image_sha256, "image_sha256")
            reason = _required_text(
                unknown_reason,
                "unknown_reason",
                maximum=500,
            )
            actor = _required_text(actor_id, "actor_id")
            key = _required_text(idempotency_key, "idempotency_key")
            source_evaluation = (
                None
                if source_evaluation_id is None
                else _required_text(
                    source_evaluation_id,
                    "source_evaluation_id",
                    maximum=100,
                )
            )
        except (AttributeError, ValueError) as exc:
            raise TemplateUnknownSampleError("unknown sample input is invalid") from exc
        if source_kind == "calibration" and source_evaluation is not None:
            raise TemplateUnknownSampleError(
                "calibration samples cannot cite a non-calibration evaluation"
            )
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "image_sha256": image_sha,
                "source_evaluation_id": source_evaluation,
                "source_kind": source_kind,
                "unknown_reason": reason,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            existing = (
                connection.execute(
                    text(
                        """
                        SELECT
                            sample_id, image_sha256, source_kind,
                            source_evaluation_id, unknown_reason, actor_id,
                            request_hash, created_at
                        FROM template_unknown_samples
                        WHERE idempotency_key = :idempotency_key
                        """
                    ),
                    {"idempotency_key": key},
                )
                .mappings()
                .one_or_none()
            )
            if existing is not None:
                if str(existing["request_hash"]) != request_hash:
                    raise TemplateIdempotencyConflictError(
                        "idempotency key belongs to different unknown sample input"
                    )
                return _unknown_sample_record_from_row(existing), False
            if source_evaluation is not None:
                evaluation_kind = connection.execute(
                    text(
                        "SELECT dataset_kind FROM template_evaluations "
                        "WHERE evaluation_id = :evaluation_id"
                    ),
                    {"evaluation_id": source_evaluation},
                ).scalar_one_or_none()
                if evaluation_kind is None:
                    raise TemplateUnknownSampleError("source development evaluation does not exist")
                if source_kind != "development" or str(evaluation_kind) != "development":
                    raise TemplateUnknownSampleError(
                        "unknown sample source evaluation is not development data"
                    )
            evidence_record_version = self._unknown_evidence_version(
                connection,
                image_sha,
            )
            sample_id = uuid4().hex
            connection.execute(
                text(
                    """
                    INSERT INTO template_unknown_samples (
                        sample_id, image_sha256, source_kind,
                        source_evaluation_id, unknown_reason, actor_id,
                        idempotency_key, request_hash, created_at
                    ) VALUES (
                        :sample_id, :image_sha256, :source_kind,
                        :source_evaluation_id, :unknown_reason, :actor_id,
                        :idempotency_key, :request_hash, :created_at
                    )
                    """
                ),
                {
                    "sample_id": sample_id,
                    "image_sha256": image_sha,
                    "source_kind": source_kind,
                    "source_evaluation_id": source_evaluation,
                    "unknown_reason": reason,
                    "actor_id": actor,
                    "idempotency_key": key,
                    "request_hash": request_hash,
                    "created_at": now,
                },
            )
            self._insert_unknown_sample_hold(
                connection,
                sample_id=sample_id,
                image_sha256=image_sha,
                expected_evidence_record_version=evidence_record_version,
                now=now,
            )
            register_exclusion_identity(
                connection,
                category=f"{source_kind}_image",
                identity_sha256=image_sha,
                source_kind="template_unknown_sample",
                source_id=sample_id,
                created_at=now,
            )
            if self._failpoint is not None:
                self._failpoint("after_unknown_sample_hold")
            return (
                TemplateUnknownSampleRecord(
                    sample_id=sample_id,
                    image_sha256=image_sha,
                    source_kind=source_kind,
                    source_evaluation_id=source_evaluation,
                    unknown_reason=reason,
                    actor_id=actor,
                    created_at=now,
                ),
                True,
            )

    @staticmethod
    def _unknown_evidence_version(
        connection: Connection,
        image_sha256: str,
    ) -> int:
        evidence = (
            connection.execute(
                text(
                    """
                    SELECT storage_state, record_version
                    FROM evidence_blobs
                    WHERE sha256 = :sha256
                    """
                ),
                {"sha256": image_sha256},
            )
            .mappings()
            .one_or_none()
        )
        if evidence is None:
            raise TemplateUnknownSampleError("unknown sample image is not registered evidence")
        if str(evidence["storage_state"]) != "available":
            raise TemplateUnknownSampleError("unknown sample image is not available")
        cleanup_claim = connection.execute(
            text(
                """
                SELECT claim_id
                FROM evidence_cleanup_claims
                WHERE sha256 = :sha256
                  AND status = 'active'
                """
            ),
            {"sha256": image_sha256},
        ).scalar_one_or_none()
        if cleanup_claim is not None:
            raise TemplateUnknownSampleError("unknown sample image is already claimed for cleanup")
        return int(evidence["record_version"])

    @staticmethod
    def _insert_unknown_sample_hold(
        connection: Connection,
        *,
        sample_id: str,
        image_sha256: str,
        expected_evidence_record_version: int,
        now: str,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO evidence_holds (
                    hold_id, sha256, hold_kind, owner_id, reason,
                    idempotency_key, record_version, created_at, released_at
                ) VALUES (
                    :hold_id, :sha256, 'template_unknown_sample',
                    :owner_id, :reason, :idempotency_key,
                    1, :created_at, NULL
                )
                """
            ),
            {
                "hold_id": uuid4().hex,
                "sha256": image_sha256,
                "owner_id": sample_id,
                "reason": "Protect unknown template-layout sample",
                "idempotency_key": f"template-unknown:{sample_id}",
                "created_at": now,
            },
        )
        result = connection.execute(
            text(
                """
                UPDATE evidence_blobs
                SET record_version = record_version + 1
                WHERE sha256 = :sha256
                  AND record_version = :expected_record_version
                  AND storage_state = 'available'
                """
            ),
            {
                "sha256": image_sha256,
                "expected_record_version": expected_evidence_record_version,
            },
        )
        if result.rowcount != 1:
            raise TemplateUnknownSampleError(
                "unknown sample evidence changed before it could be held"
            )

    @classmethod
    def _register_template_evidence(
        cls,
        connection: Connection,
        *,
        sha256: str,
        relative_path: str,
        byte_size: int,
        media_type: str,
        now: str,
    ) -> tuple[TemplateEvidenceRecord, bool]:
        row = (
            connection.execute(
                text(
                    """
                    SELECT
                        sha256, relative_path, byte_size, media_type,
                        storage_state, record_version, created_at, verified_at
                    FROM evidence_blobs
                    WHERE sha256 = :sha256
                    """
                ),
                {"sha256": sha256},
            )
            .mappings()
            .one_or_none()
        )
        created = row is None
        if row is None:
            path_owner = connection.execute(
                text("SELECT sha256 FROM evidence_blobs WHERE relative_path = :relative_path"),
                {"relative_path": relative_path},
            ).scalar_one_or_none()
            if path_owner is not None:
                raise TemplateReferenceEvidenceError(
                    "template evidence path belongs to different content"
                )
            connection.execute(
                text(
                    """
                    INSERT INTO evidence_blobs (
                        sha256, relative_path, byte_size, media_type,
                        storage_state, record_version, created_at, verified_at
                    ) VALUES (
                        :sha256, :relative_path, :byte_size, :media_type,
                        'available', 1, :created_at, :verified_at
                    )
                    """
                ),
                {
                    "sha256": sha256,
                    "relative_path": relative_path,
                    "byte_size": byte_size,
                    "media_type": media_type,
                    "created_at": now,
                    "verified_at": now,
                },
            )
            row = (
                connection.execute(
                    text(
                        """
                        SELECT
                            sha256, relative_path, byte_size, media_type,
                            storage_state, record_version, created_at, verified_at
                        FROM evidence_blobs
                        WHERE sha256 = :sha256
                        """
                    ),
                    {"sha256": sha256},
                )
                .mappings()
                .one()
            )
        if str(row["storage_state"]) != "available":
            raise TemplateReferenceEvidenceError("template evidence is not available")
        if (
            str(row["relative_path"]) != relative_path
            or int(row["byte_size"]) != byte_size
            or str(row["media_type"]) != media_type
        ):
            raise TemplateReferenceEvidenceError(
                "existing template evidence metadata conflicts with its SHA-256"
            )
        cleanup_claim = connection.execute(
            text(
                """
                SELECT claim_id
                FROM evidence_cleanup_claims
                WHERE sha256 = :sha256
                  AND status = 'active'
                """
            ),
            {"sha256": sha256},
        ).scalar_one_or_none()
        if cleanup_claim is not None:
            raise TemplateReferenceEvidenceError("template evidence is already claimed for cleanup")
        return _template_evidence_record_from_row(row), created

    @staticmethod
    def _insert_template_evidence_hold(
        connection: Connection,
        *,
        sha256: str,
        hold_kind: str,
        owner_id: str,
        reason: str,
        idempotency_key: str,
        expected_evidence_record_version: int,
        now: str,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO evidence_holds (
                    hold_id, sha256, hold_kind, owner_id, reason,
                    idempotency_key, record_version, created_at, released_at
                ) VALUES (
                    :hold_id, :sha256, :hold_kind, :owner_id, :reason,
                    :idempotency_key, 1, :created_at, NULL
                )
                """
            ),
            {
                "hold_id": uuid4().hex,
                "sha256": sha256,
                "hold_kind": hold_kind,
                "owner_id": owner_id,
                "reason": reason,
                "idempotency_key": idempotency_key,
                "created_at": now,
            },
        )
        result = connection.execute(
            text(
                """
                UPDATE evidence_blobs
                SET record_version = record_version + 1
                WHERE sha256 = :sha256
                  AND record_version = :expected_record_version
                  AND storage_state = 'available'
                """
            ),
            {
                "sha256": sha256,
                "expected_record_version": expected_evidence_record_version,
            },
        )
        if result.rowcount != 1:
            raise TemplateReferenceEvidenceError(
                "template evidence changed before it could be held"
            )

    @classmethod
    def _release_reference_upload_hold(
        cls,
        connection: Connection,
        *,
        upload: TemplateReferenceUploadRecord,
        now: str,
    ) -> None:
        hold = (
            connection.execute(
                text(
                    """
                    SELECT hold_id, record_version
                    FROM evidence_holds
                    WHERE sha256 = :sha256
                      AND hold_kind = 'template_reference_upload'
                      AND owner_id = :owner_id
                      AND released_at IS NULL
                    """
                ),
                {
                    "sha256": upload.image_sha256,
                    "owner_id": upload.staged_reference_id,
                },
            )
            .mappings()
            .one_or_none()
        )
        if hold is None:
            raise TemplateReferenceUploadError(
                "staged template reference has no active evidence hold"
            )
        evidence_record_version = cls._reference_evidence_version(
            connection,
            upload.image_sha256,
        )
        released = connection.execute(
            text(
                """
                UPDATE evidence_holds
                SET released_at = :released_at,
                    record_version = record_version + 1
                WHERE hold_id = :hold_id
                  AND record_version = :expected_record_version
                  AND released_at IS NULL
                """
            ),
            {
                "released_at": now,
                "hold_id": str(hold["hold_id"]),
                "expected_record_version": int(hold["record_version"]),
            },
        )
        if released.rowcount != 1:
            raise TemplateReferenceUploadError(
                "staged template reference hold changed before release"
            )
        evidence_updated = connection.execute(
            text(
                """
                UPDATE evidence_blobs
                SET record_version = record_version + 1
                WHERE sha256 = :sha256
                  AND record_version = :expected_record_version
                  AND storage_state = 'available'
                """
            ),
            {
                "sha256": upload.image_sha256,
                "expected_record_version": evidence_record_version,
            },
        )
        if evidence_updated.rowcount != 1:
            raise TemplateReferenceUploadError(
                "staged template evidence changed before hold release"
            )

    @classmethod
    def _finalize_reference_upload(
        cls,
        connection: Connection,
        *,
        upload: TemplateReferenceUploadRecord,
        target_state: str,
        now: str,
    ) -> TemplateReferenceUploadRecord:
        if upload.state != "staged":
            raise TemplateReferenceUploadError("only a staged template reference can be finalized")
        if target_state not in {"consumed", "abandoned"}:
            raise TemplateReferenceUploadError("staged template reference target state is invalid")
        cls._release_reference_upload_hold(
            connection,
            upload=upload,
            now=now,
        )
        updated = connection.execute(
            text(
                """
                UPDATE template_reference_uploads
                SET state = :state,
                    record_version = record_version + 1,
                    updated_at = :updated_at
                WHERE staged_reference_id = :staged_reference_id
                  AND state = 'staged'
                  AND record_version = :expected_record_version
                """
            ),
            {
                "state": target_state,
                "updated_at": now,
                "staged_reference_id": upload.staged_reference_id,
                "expected_record_version": upload.record_version,
            },
        )
        if updated.rowcount != 1:
            raise TemplateRecordVersionConflictError(
                "staged template reference changed before it was finalized"
            )
        return cls._load_reference_upload(
            connection,
            upload.staged_reference_id,
        )

    def register_derived_template_mask(
        self,
        *,
        sha256: str,
        relative_path: str,
        byte_size: int,
        media_type: str = "image/png",
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[TemplateEvidenceRecord, bool]:
        operation = "register_derived_template_mask"
        evidence_sha256 = _required_sha256(sha256, "sha256")
        evidence_path = _required_evidence_relative_path(
            relative_path,
            evidence_sha256,
        )
        evidence_size = _required_positive_integer(byte_size, "byte_size")
        evidence_media_type = _required_reference_media_type(media_type)
        if evidence_media_type != "image/png":
            raise ValueError("derived template mask must be image/png")
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "byte_size": evidence_size,
                "media_type": evidence_media_type,
                "relative_path": evidence_path,
                "sha256": evidence_sha256,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = self._replay(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._replayed_template_evidence(replay), False
            evidence, created = self._register_template_evidence(
                connection,
                sha256=evidence_sha256,
                relative_path=evidence_path,
                byte_size=evidence_size,
                media_type=evidence_media_type,
                now=now,
            )
            if self._failpoint is not None:
                self._failpoint("after_derived_template_mask_registration")
            self._save_idempotency(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
                result_kind="template_evidence",
                result=_template_evidence_result_payload(evidence),
                now=now,
            )
            return evidence, created

    def stage_reference_upload(
        self,
        *,
        image_sha256: str,
        relative_path: str,
        byte_size: int,
        media_type: str,
        width: int,
        height: int,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[TemplateReferenceUploadRecord, bool]:
        operation = "stage_reference_upload"
        image = _required_sha256(image_sha256, "image_sha256")
        evidence_path = _required_evidence_relative_path(relative_path, image)
        evidence_size = _required_positive_integer(byte_size, "byte_size")
        evidence_media_type = _required_reference_media_type(media_type)
        image_width = _required_positive_integer(width, "width")
        image_height = _required_positive_integer(height, "height")
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "byte_size": evidence_size,
                "height": image_height,
                "image_sha256": image,
                "media_type": evidence_media_type,
                "relative_path": evidence_path,
                "width": image_width,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = self._replay(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._replayed_reference_upload(replay), False
            evidence, _ = self._register_template_evidence(
                connection,
                sha256=image,
                relative_path=evidence_path,
                byte_size=evidence_size,
                media_type=evidence_media_type,
                now=now,
            )
            staged_reference_id = uuid4().hex
            connection.execute(
                text(
                    """
                    INSERT INTO template_reference_uploads (
                        staged_reference_id, image_sha256, media_type,
                        width, height, state, record_version, actor_id,
                        created_at, updated_at
                    ) VALUES (
                        :staged_reference_id, :image_sha256, :media_type,
                        :width, :height, 'staged', 1, :actor_id,
                        :created_at, :updated_at
                    )
                    """
                ),
                {
                    "staged_reference_id": staged_reference_id,
                    "image_sha256": image,
                    "media_type": evidence_media_type,
                    "width": image_width,
                    "height": image_height,
                    "actor_id": actor,
                    "created_at": now,
                    "updated_at": now,
                },
            )
            self._insert_template_evidence_hold(
                connection,
                sha256=image,
                hold_kind="template_reference_upload",
                owner_id=staged_reference_id,
                reason="Protect staged template reference image",
                idempotency_key=f"template-reference-upload:{staged_reference_id}",
                expected_evidence_record_version=evidence.record_version,
                now=now,
            )
            if self._failpoint is not None:
                self._failpoint("after_reference_upload_hold")
            staged = self._load_reference_upload(connection, staged_reference_id)
            self._save_idempotency(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
                result_kind="reference_upload",
                result=_reference_upload_result_payload(staged),
                now=now,
            )
            return staged, True

    def abandon_reference_upload(
        self,
        *,
        staged_reference_id: str,
        expected_record_version: int,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[TemplateReferenceUploadRecord, bool]:
        operation = "abandon_reference_upload"
        staged_id = _required_text(
            staged_reference_id,
            "staged_reference_id",
            maximum=32,
        )
        expected_version = _required_positive_integer(
            expected_record_version,
            "expected_record_version",
        )
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "expected_record_version": expected_version,
                "staged_reference_id": staged_id,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = self._replay(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._replayed_reference_upload(replay), False
            upload = self._load_reference_upload(connection, staged_id)
            if upload.state != "staged":
                raise TemplateReferenceUploadError(
                    "only a staged template reference can be abandoned"
                )
            if upload.record_version != expected_version:
                raise TemplateRecordVersionConflictError(
                    "staged template reference changed before it was abandoned"
                )
            abandoned = self._finalize_reference_upload(
                connection,
                upload=upload,
                target_state="abandoned",
                now=now,
            )
            if self._failpoint is not None:
                self._failpoint("after_reference_upload_abandoned")
            self._save_idempotency(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
                result_kind="reference_upload",
                result=_reference_upload_result_payload(abandoned),
                now=now,
            )
            return abandoned, True

    def expire_staged_reference_uploads(
        self,
        *,
        older_than: datetime,
    ) -> int:
        """Release abandoned workbench holds after the recovery window."""

        if older_than.tzinfo is None or older_than.utcoffset() is None:
            raise ValueError("reference upload expiry cutoff must be timezone-aware")
        cutoff = older_than.astimezone(UTC).isoformat()
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            staged_ids = tuple(
                str(value)
                for value in connection.execute(
                    text(
                        """
                        SELECT staged_reference_id
                        FROM template_reference_uploads
                        WHERE state = 'staged'
                          AND updated_at < :cutoff
                        ORDER BY updated_at, staged_reference_id
                        """
                    ),
                    {"cutoff": cutoff},
                ).scalars()
            )
            for staged_id in staged_ids:
                upload = self._load_reference_upload(connection, staged_id)
                self._finalize_reference_upload(
                    connection,
                    upload=upload,
                    target_state="abandoned",
                    now=now,
                )
            return len(staged_ids)

    def _insert_reference_origin(
        self,
        connection: Connection,
        *,
        version_id: str,
        origin_payload: Mapping[str, object],
        now: str,
    ) -> None:
        candidate_record = _mapping(
            origin_payload.get("candidate_record_blob"),
            "template reference origin record blob",
        )
        source_image = _mapping(
            origin_payload.get("source_image"),
            "template reference origin image",
        )
        candidate_record_evidence, _ = self._register_template_evidence(
            connection,
            sha256=_string(candidate_record, "sha256"),
            relative_path=_string(candidate_record, "relative_path"),
            byte_size=_integer(candidate_record, "byte_size"),
            media_type="application/json",
            now=now,
        )
        source_image_evidence, _ = self._register_template_evidence(
            connection,
            sha256=_string(source_image, "sha256"),
            relative_path=_string(source_image, "relative_path"),
            byte_size=_integer(source_image, "byte_size"),
            media_type=_string(source_image, "media_type"),
            now=now,
        )
        origin_sha256 = _request_hash(origin_payload)
        connection.execute(
            text(
                """
                INSERT INTO template_reference_origins (
                    version_id, candidate_evidence_sha256,
                    candidate_record_blob_sha256,
                    source_image_sha256,
                    waybill_identity_sha256, sample_id,
                    submitted_slot, confirmed_role,
                    package_sha256,
                    review_history_authority_sha256,
                    source_authority_sha256,
                    review_record_evidence_sha256,
                    origin_payload_json, origin_sha256,
                    created_at
                ) VALUES (
                    :version_id, :candidate_evidence_sha256,
                    :candidate_record_blob_sha256,
                    :source_image_sha256,
                    :waybill_identity_sha256, :sample_id,
                    :submitted_slot, :confirmed_role,
                    :package_sha256,
                    :review_history_authority_sha256,
                    :source_authority_sha256,
                    :review_record_evidence_sha256,
                    :origin_payload_json, :origin_sha256,
                    :created_at
                )
                """
            ),
            {
                "version_id": version_id,
                "candidate_evidence_sha256": (origin_payload["candidate_evidence_sha256"]),
                "candidate_record_blob_sha256": candidate_record["sha256"],
                "source_image_sha256": source_image["sha256"],
                "waybill_identity_sha256": origin_payload["waybill_identity_sha256"],
                "sample_id": origin_payload["sample_id"],
                "submitted_slot": origin_payload["submitted_slot"],
                "confirmed_role": origin_payload["confirmed_role"],
                "package_sha256": origin_payload["package_sha256"],
                "review_history_authority_sha256": origin_payload[
                    "review_history_authority_sha256"
                ],
                "source_authority_sha256": origin_payload["source_authority_sha256"],
                "review_record_evidence_sha256": origin_payload["review_record_evidence_sha256"],
                "origin_payload_json": _json_dump(origin_payload),
                "origin_sha256": origin_sha256,
                "created_at": now,
            },
        )
        image_exclusion_created = register_exclusion_identity(
            connection,
            category="development_image",
            identity_sha256=_string(source_image, "sha256"),
            source_kind="template_reference_origin",
            source_id=version_id,
            created_at=now,
        )
        waybill_exclusion_created = register_exclusion_identity(
            connection,
            category="prior_waybill_identity",
            identity_sha256=str(origin_payload["waybill_identity_sha256"]),
            source_kind="template_reference_origin",
            source_id=version_id,
            created_at=now,
        )
        if not image_exclusion_created or not waybill_exclusion_created:
            raise TemplateReferenceEvidenceError(
                "template reference origin exclusion already exists"
            )
        self._insert_template_evidence_hold(
            connection,
            sha256=_string(source_image, "sha256"),
            hold_kind="template_reference_origin_image",
            owner_id=version_id,
            reason="Protect original development template source image",
            idempotency_key=f"template-reference-origin-image:{version_id}",
            expected_evidence_record_version=(source_image_evidence.record_version),
            now=now,
        )
        self._insert_template_evidence_hold(
            connection,
            sha256=_string(candidate_record, "sha256"),
            hold_kind="template_reference_origin_record",
            owner_id=version_id,
            reason="Protect development template source authority",
            idempotency_key=f"template-reference-origin-record:{version_id}",
            expected_evidence_record_version=(candidate_record_evidence.record_version),
            now=now,
        )

    def create_draft(
        self,
        *,
        definition: TemplateDefinition,
        reference_image_sha256: str,
        reference_mask_sha256: str,
        alignment_fingerprint: str,
        actor_id: str,
        idempotency_key: str,
        staged_reference_id: str | None = None,
        expected_staged_reference_record_version: int | None = None,
        reference_origin: TemplateReferenceOriginInput | None = None,
    ) -> tuple[TemplateVersion, bool]:
        operation = "create_draft"
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        reference_image = _required_sha256(
            reference_image_sha256,
            "reference_image_sha256",
        )
        reference_mask = _required_sha256(
            reference_mask_sha256,
            "reference_mask_sha256",
        )
        alignment = _required_sha256(
            alignment_fingerprint,
            "alignment_fingerprint",
        )
        if reference_image == reference_mask:
            raise TemplateReferenceEvidenceError(
                "template reference image and mask must be different evidence"
            )
        staged_id = (
            None
            if staged_reference_id is None
            else _required_text(
                staged_reference_id,
                "staged_reference_id",
                maximum=32,
            )
        )
        expected_staged_version = (
            None
            if expected_staged_reference_record_version is None
            else _required_positive_integer(
                expected_staged_reference_record_version,
                "expected_staged_reference_record_version",
            )
        )
        if (staged_id is None) != (expected_staged_version is None):
            raise TemplateReferenceUploadError(
                "staged reference identity and record version must be supplied together"
            )
        origin_payload = (
            None if reference_origin is None else _reference_origin_payload(reference_origin)
        )
        if origin_payload is not None and origin_payload["confirmed_role"] != definition.role.value:
            raise ValueError(
                "template reference origin confirmed role must match the template role"
            )
        definition_payload = _definition_payload(definition)
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "alignment_fingerprint": alignment,
                "definition": definition_payload,
                "reference_image_sha256": reference_image,
                "reference_mask_sha256": reference_mask,
                "expected_staged_reference_record_version": expected_staged_version,
                "reference_origin": origin_payload,
                "staged_reference_id": staged_id,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = self._replay(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._replayed_version(connection, replay), False
            family_exists = connection.execute(
                text("SELECT 1 FROM template_families WHERE family_id = :family_id"),
                {"family_id": definition.family_id},
            ).scalar_one_or_none()
            if family_exists is not None:
                raise TemplateFamilyConflictError(
                    "template family already exists; create a revision instead"
                )
            staged_upload = (
                None if staged_id is None else self._load_reference_upload(connection, staged_id)
            )
            if staged_upload is not None:
                if staged_upload.state != "staged":
                    raise TemplateReferenceUploadError(
                        "template reference upload is no longer staged"
                    )
                if staged_upload.record_version != expected_staged_version:
                    raise TemplateRecordVersionConflictError(
                        "staged template reference changed before draft creation"
                    )
                if staged_upload.image_sha256 != reference_image:
                    raise TemplateReferenceUploadError(
                        "staged reference image does not match the draft"
                    )
            evidence_record_version = self._reference_evidence_version(
                connection,
                reference_image,
            )
            mask_evidence_record_version = self._reference_evidence_version(
                connection,
                reference_mask,
                required_media_type="image/png",
            )
            version_id = uuid4().hex
            connection.execute(
                text(
                    """
                    INSERT INTO template_families (
                        family_id, name, role, created_by, created_at
                    ) VALUES (
                        :family_id, :name, :role, :created_by, :created_at
                    )
                    """
                ),
                {
                    "family_id": definition.family_id,
                    "name": definition.name,
                    "role": definition.role.value,
                    "created_by": actor,
                    "created_at": now,
                },
            )
            self._insert_version(
                connection,
                version_id=version_id,
                version_number=1,
                parent_version_id=None,
                definition=definition,
                definition_payload=definition_payload,
                reference_image_sha256=reference_image,
                reference_mask_sha256=reference_mask,
                alignment_fingerprint=alignment,
                actor_id=actor,
                now=now,
            )
            register_exclusion_identity(
                connection,
                category="template_reference_image",
                identity_sha256=reference_image,
                source_kind="template_version",
                source_id=version_id,
                created_at=now,
            )
            self._insert_template_evidence_hold(
                connection,
                sha256=reference_image,
                hold_kind="template_reference",
                owner_id=version_id,
                reason="Protect immutable template reference image",
                idempotency_key=f"template-reference:{version_id}",
                expected_evidence_record_version=evidence_record_version,
                now=now,
            )
            self._insert_template_evidence_hold(
                connection,
                sha256=reference_mask,
                hold_kind="template_reference_mask",
                owner_id=version_id,
                reason="Protect immutable template reference mask",
                idempotency_key=f"template-reference-mask:{version_id}",
                expected_evidence_record_version=mask_evidence_record_version,
                now=now,
            )
            if self._failpoint is not None:
                self._failpoint("after_reference_hold")
            if reference_origin is not None:
                assert origin_payload is not None
                self._insert_reference_origin(
                    connection,
                    version_id=version_id,
                    origin_payload=origin_payload,
                    now=now,
                )
                if self._failpoint is not None:
                    self._failpoint("after_reference_origin")
            if staged_upload is not None:
                self._finalize_reference_upload(
                    connection,
                    upload=staged_upload,
                    target_state="consumed",
                    now=now,
                )
                if self._failpoint is not None:
                    self._failpoint("after_reference_upload_consumed")
            self._insert_lifecycle_event(
                connection,
                version_id=version_id,
                operation=operation,
                from_lifecycle=None,
                to_lifecycle=TemplateLifecycle.DRAFT,
                record_version=1,
                evaluation_id=None,
                developer_authorization_id=None,
                actor_id=actor,
                now=now,
            )
            self._insert_audit(
                connection,
                event_kind="template.draft_created",
                family_id=definition.family_id,
                version_id=version_id,
                actor_id=actor,
                developer_authorization_id=None,
                detail={"content_sha256": canonical_template_hash(definition)},
                now=now,
            )
            created_version = self._load_version(connection, version_id)
            self._save_idempotency(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
                result_kind="version",
                result=_version_result_payload(created_version),
                now=now,
            )
            return created_version, True

    @staticmethod
    def _reference_evidence_version(
        connection: Connection,
        reference_image_sha256: str,
        *,
        required_media_type: str | None = None,
    ) -> int:
        evidence = (
            connection.execute(
                text(
                    """
                    SELECT
                        media_type, storage_state, record_version, verified_at
                    FROM evidence_blobs
                    WHERE sha256 = :sha256
                    """
                ),
                {"sha256": reference_image_sha256},
            )
            .mappings()
            .one_or_none()
        )
        if evidence is None:
            raise TemplateReferenceEvidenceError(
                "template reference image is not registered evidence"
            )
        if str(evidence["storage_state"]) != "available":
            raise TemplateReferenceEvidenceError("template reference image is not available")
        if evidence["verified_at"] is None:
            raise TemplateReferenceEvidenceError(
                "template reference evidence has not been verified"
            )
        if required_media_type is not None and str(evidence["media_type"]) != required_media_type:
            raise TemplateReferenceEvidenceError(
                "template reference evidence has an unexpected media type"
            )
        cleanup_claim = connection.execute(
            text(
                """
                SELECT claim_id
                FROM evidence_cleanup_claims
                WHERE sha256 = :sha256
                  AND status = 'active'
                """
            ),
            {"sha256": reference_image_sha256},
        ).scalar_one_or_none()
        if cleanup_claim is not None:
            raise TemplateReferenceEvidenceError(
                "template reference image is already claimed for cleanup"
            )
        return int(evidence["record_version"])

    @staticmethod
    def _insert_version(
        connection: Connection,
        *,
        version_id: str,
        version_number: int,
        parent_version_id: str | None,
        definition: TemplateDefinition,
        definition_payload: Mapping[str, object],
        reference_image_sha256: str,
        reference_mask_sha256: str,
        alignment_fingerprint: str,
        actor_id: str,
        now: str,
    ) -> None:
        connection.execute(
            text(
                """
                INSERT INTO template_versions (
                    version_id, family_id, version_number, parent_version_id,
                    definition_json, content_sha256, reference_image_sha256,
                    reference_mask_sha256, alignment_fingerprint,
                    created_by, created_at
                ) VALUES (
                    :version_id, :family_id, :version_number, :parent_version_id,
                    :definition_json, :content_sha256, :reference_image_sha256,
                    :reference_mask_sha256, :alignment_fingerprint,
                    :created_by, :created_at
                )
                """
            ),
            {
                "version_id": version_id,
                "family_id": definition.family_id,
                "version_number": version_number,
                "parent_version_id": parent_version_id,
                "definition_json": _json_dump(definition_payload),
                "content_sha256": canonical_template_hash(definition),
                "reference_image_sha256": reference_image_sha256,
                "reference_mask_sha256": reference_mask_sha256,
                "alignment_fingerprint": alignment_fingerprint,
                "created_by": actor_id,
                "created_at": now,
            },
        )
        connection.execute(
            text(
                """
                INSERT INTO template_version_states (
                    version_id, lifecycle, record_version, updated_at
                ) VALUES (
                    :version_id, 'draft', 1, :updated_at
                )
                """
            ),
            {"version_id": version_id, "updated_at": now},
        )

    def revise_draft(
        self,
        *,
        source_version_id: str,
        definition: TemplateDefinition,
        reference_image_sha256: str,
        reference_mask_sha256: str,
        alignment_fingerprint: str,
        expected_record_version: int,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[TemplateVersion, bool]:
        operation = "revise_draft"
        source_id = _required_text(source_version_id, "source_version_id", maximum=32)
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        reference_image = _required_sha256(
            reference_image_sha256,
            "reference_image_sha256",
        )
        reference_mask = _required_sha256(
            reference_mask_sha256,
            "reference_mask_sha256",
        )
        alignment = _required_sha256(
            alignment_fingerprint,
            "alignment_fingerprint",
        )
        if reference_image == reference_mask:
            raise TemplateReferenceEvidenceError(
                "template reference image and mask must be different evidence"
            )
        definition_payload = _definition_payload(definition)
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "alignment_fingerprint": alignment,
                "definition": definition_payload,
                "expected_record_version": expected_record_version,
                "reference_image_sha256": reference_image,
                "reference_mask_sha256": reference_mask,
                "source_version_id": source_id,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = self._replay(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._replayed_version(connection, replay), False
            source = self._load_version(connection, source_id)
            if source.record_version != expected_record_version:
                raise TemplateRecordVersionConflictError("template version changed before revision")
            if (
                source.definition.family_id != definition.family_id
                or source.definition.name != definition.name
                or source.definition.role is not definition.role
            ):
                raise TemplateFamilyConflictError(
                    "a revision cannot change template family identity"
                )
            latest_number = int(
                connection.execute(
                    text(
                        "SELECT COALESCE(MAX(version_number), 0) "
                        "FROM template_versions WHERE family_id = :family_id"
                    ),
                    {"family_id": definition.family_id},
                ).scalar_one()
            )
            if source.version_number != latest_number:
                raise TemplateRecordVersionConflictError(
                    "template family has a newer immutable version"
                )
            evidence_record_version = self._reference_evidence_version(
                connection,
                reference_image,
            )
            mask_evidence_record_version = self._reference_evidence_version(
                connection,
                reference_mask,
                required_media_type="image/png",
            )
            next_number = latest_number + 1
            version_id = uuid4().hex
            self._insert_version(
                connection,
                version_id=version_id,
                version_number=next_number,
                parent_version_id=source.version_id,
                definition=definition,
                definition_payload=definition_payload,
                reference_image_sha256=reference_image,
                reference_mask_sha256=reference_mask,
                alignment_fingerprint=alignment,
                actor_id=actor,
                now=now,
            )
            register_exclusion_identity(
                connection,
                category="template_reference_image",
                identity_sha256=reference_image,
                source_kind="template_version",
                source_id=version_id,
                created_at=now,
            )
            self._insert_template_evidence_hold(
                connection,
                sha256=reference_image,
                hold_kind="template_reference",
                owner_id=version_id,
                reason="Protect immutable template reference image",
                idempotency_key=f"template-reference:{version_id}",
                expected_evidence_record_version=evidence_record_version,
                now=now,
            )
            self._insert_template_evidence_hold(
                connection,
                sha256=reference_mask,
                hold_kind="template_reference_mask",
                owner_id=version_id,
                reason="Protect immutable template reference mask",
                idempotency_key=f"template-reference-mask:{version_id}",
                expected_evidence_record_version=mask_evidence_record_version,
                now=now,
            )
            if self._failpoint is not None:
                self._failpoint("after_reference_hold")
            self._insert_lifecycle_event(
                connection,
                version_id=version_id,
                operation=operation,
                from_lifecycle=None,
                to_lifecycle=TemplateLifecycle.DRAFT,
                record_version=1,
                evaluation_id=None,
                developer_authorization_id=None,
                actor_id=actor,
                now=now,
            )
            self._insert_audit(
                connection,
                event_kind="template.draft_revised",
                family_id=definition.family_id,
                version_id=version_id,
                actor_id=actor,
                developer_authorization_id=None,
                detail={
                    "content_sha256": canonical_template_hash(definition),
                    "parent_version_id": source.version_id,
                },
                now=now,
            )
            revised_version = self._load_version(connection, version_id)
            self._save_idempotency(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
                result_kind="version",
                result=_version_result_payload(revised_version),
                now=now,
            )
            return revised_version, True

    def _validate_lifecycle_evaluation(
        self,
        connection: Connection,
        *,
        evaluation_id: str,
        version: TemplateVersion,
    ) -> None:
        latest_row = self._latest_development_evaluation_row(
            connection,
            version=version,
        )
        if latest_row is None or str(latest_row["evaluation_id"]) != evaluation_id:
            raise TemplateEvaluationGateError(
                "latest development evaluation is unverified, invalidated, or superseded"
            )
        evaluation = self._accepted_development_evaluation_from_row(
            connection,
            latest_row,
            version=version,
        )
        if evaluation is None:
            raise TemplateEvaluationGateError(
                "lifecycle evaluation is unverified, stale, incomplete, or invalidated"
            )
        if not evaluation.gate_passed:
            raise TemplateEvaluationGateError("lifecycle evaluation did not pass its gate")

    def _validate_shadow_version(
        self,
        connection: Connection,
        *,
        version_id: str,
    ) -> None:
        version = self._load_version(connection, version_id)
        if version.lifecycle is not TemplateLifecycle.SHADOW:
            raise TemplateEvaluationGateError(
                "runtime template pointer does not reference a shadow version"
            )
        evaluation_id = connection.execute(
            text(
                """
                SELECT evaluation_id
                FROM template_lifecycle_events
                WHERE version_id = :version_id
                  AND operation = 'publish_shadow'
                  AND to_lifecycle = 'shadow'
                ORDER BY created_at DESC, event_id DESC
                LIMIT 1
                """
            ),
            {"version_id": version_id},
        ).scalar_one_or_none()
        if evaluation_id is None:
            raise TemplateEvaluationGateError("shadow version has no publication evaluation")
        self._validate_lifecycle_evaluation(
            connection,
            evaluation_id=str(evaluation_id),
            version=version,
        )

    def mark_development_tested(
        self,
        *,
        version_id: str,
        expected_record_version: int,
        evaluation_id: str,
        developer_authorization_id: str,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[TemplateVersion, bool]:
        return self._advance_lifecycle(
            operation="mark_development_tested",
            version_id=version_id,
            expected_record_version=expected_record_version,
            target=TemplateLifecycle.DEVELOPMENT_TESTED,
            evaluation_id=evaluation_id,
            developer_authorization_id=developer_authorization_id,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            publish_shadow=False,
        )

    def publish_shadow(
        self,
        *,
        version_id: str,
        expected_record_version: int,
        evaluation_id: str,
        developer_authorization_id: str,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[TemplateVersion, bool]:
        return self._advance_lifecycle(
            operation="publish_shadow",
            version_id=version_id,
            expected_record_version=expected_record_version,
            target=TemplateLifecycle.SHADOW,
            evaluation_id=evaluation_id,
            developer_authorization_id=developer_authorization_id,
            actor_id=actor_id,
            idempotency_key=idempotency_key,
            publish_shadow=True,
        )

    def _advance_lifecycle(
        self,
        *,
        operation: str,
        version_id: str,
        expected_record_version: int,
        target: TemplateLifecycle,
        evaluation_id: str,
        developer_authorization_id: str,
        actor_id: str,
        idempotency_key: str,
        publish_shadow: bool,
    ) -> tuple[TemplateVersion, bool]:
        version_identity = _required_text(version_id, "version_id", maximum=32)
        evaluation = _required_text(evaluation_id, "evaluation_id", maximum=100)
        authorization = _required_authorization(developer_authorization_id)
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "developer_authorization_id": authorization,
                "evaluation_id": evaluation,
                "expected_record_version": expected_record_version,
                "target": target.value,
                "version_id": version_identity,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = self._replay(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._replayed_version(connection, replay), False
            current = self._load_version(connection, version_identity)
            if current.record_version != expected_record_version:
                raise TemplateRecordVersionConflictError(
                    "template lifecycle record version is stale"
                )
            if current.lifecycle is target:
                raise TemplateLifecycleTransitionError(
                    "template version is already in the requested lifecycle"
                )
            try:
                transitioned = transition_template_version(
                    current,
                    target=target,
                    development_evaluation_passed=True,
                    authorized=True,
                )
            except TemplateTransitionError as exc:
                raise TemplateLifecycleTransitionError(
                    "template lifecycle transition is not permitted"
                ) from exc
            self._validate_lifecycle_evaluation(
                connection,
                evaluation_id=evaluation,
                version=current,
            )
            result = connection.execute(
                text(
                    """
                    UPDATE template_version_states
                    SET lifecycle = :lifecycle,
                        record_version = :next_record_version,
                        updated_at = :updated_at
                    WHERE version_id = :version_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "lifecycle": transitioned.lifecycle.value,
                    "next_record_version": transitioned.record_version,
                    "updated_at": now,
                    "version_id": version_identity,
                    "expected_record_version": expected_record_version,
                },
            )
            if result.rowcount != 1:
                raise TemplateRecordVersionConflictError("template lifecycle changed concurrently")
            self._insert_lifecycle_event(
                connection,
                version_id=version_identity,
                operation=operation,
                from_lifecycle=current.lifecycle,
                to_lifecycle=transitioned.lifecycle,
                record_version=transitioned.record_version,
                evaluation_id=evaluation,
                developer_authorization_id=authorization,
                actor_id=actor,
                now=now,
            )
            pointer_before: ShadowPointerRecord | None = None
            if publish_shadow:
                pointer_before = self._publish_pointer(
                    connection,
                    family_id=current.definition.family_id,
                    version_id=version_identity,
                    now=now,
                )
            self._insert_audit(
                connection,
                event_kind=(
                    "template.shadow_published" if publish_shadow else "template.development_tested"
                ),
                family_id=current.definition.family_id,
                version_id=version_identity,
                actor_id=actor,
                developer_authorization_id=authorization,
                detail={
                    "evaluation_id": evaluation,
                    "from_lifecycle": current.lifecycle.value,
                    "previous_shadow_version_id": (
                        None if pointer_before is None else pointer_before.version_id
                    ),
                    "to_lifecycle": transitioned.lifecycle.value,
                },
                now=now,
            )
            persisted_transition = self._load_version(
                connection,
                version_identity,
            )
            self._save_idempotency(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
                result_kind="version",
                result=_version_result_payload(persisted_transition),
                now=now,
            )
            return persisted_transition, True

    @staticmethod
    def _publish_pointer(
        connection: Connection,
        *,
        family_id: str,
        version_id: str,
        now: str,
    ) -> ShadowPointerRecord | None:
        existing = (
            connection.execute(
                text(
                    """
                    SELECT family_id, version_id, record_version
                    FROM template_shadow_pointers
                    WHERE family_id = :family_id
                    """
                ),
                {"family_id": family_id},
            )
            .mappings()
            .one_or_none()
        )
        if existing is None:
            connection.execute(
                text(
                    """
                    INSERT INTO template_shadow_pointers (
                        family_id, version_id, record_version, updated_at
                    ) VALUES (
                        :family_id, :version_id, 1, :updated_at
                    )
                    """
                ),
                {
                    "family_id": family_id,
                    "version_id": version_id,
                    "updated_at": now,
                },
            )
            return None
        previous = ShadowPointerRecord(
            family_id=str(existing["family_id"]),
            version_id=str(existing["version_id"]),
            record_version=int(existing["record_version"]),
        )
        result = connection.execute(
            text(
                """
                UPDATE template_shadow_pointers
                SET version_id = :version_id,
                    record_version = :next_record_version,
                    updated_at = :updated_at
                WHERE family_id = :family_id
                  AND record_version = :expected_record_version
                """
            ),
            {
                "version_id": version_id,
                "next_record_version": previous.record_version + 1,
                "updated_at": now,
                "family_id": family_id,
                "expected_record_version": previous.record_version,
            },
        )
        if result.rowcount != 1:
            raise TemplateRecordVersionConflictError("shadow pointer changed concurrently")
        return previous

    def rollback_shadow(
        self,
        *,
        family_id: str,
        target_version_id: str,
        expected_record_version: int,
        reason: str,
        developer_authorization_id: str,
        actor_id: str,
        idempotency_key: str,
    ) -> tuple[ShadowPointerRecord, bool]:
        operation = "rollback_shadow"
        family = _required_text(family_id, "family_id", maximum=100)
        target_id = _required_text(
            target_version_id,
            "target_version_id",
            maximum=32,
        )
        rollback_reason = _required_text(reason, "reason")
        authorization = _required_authorization(developer_authorization_id)
        actor = _required_text(actor_id, "actor_id")
        key = _required_text(idempotency_key, "idempotency_key")
        request_hash = _request_hash(
            {
                "actor_id": actor,
                "developer_authorization_id": authorization,
                "expected_record_version": expected_record_version,
                "family_id": family,
                "reason": rollback_reason,
                "target_version_id": target_id,
            }
        )
        now = _utc_now()
        with self.runtime.commit_gate.transaction(self.runtime.engine) as connection:
            replay = self._replay(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
            )
            if replay is not None:
                return self._replayed_pointer(replay), False
            current = self._load_pointer(connection, family)
            if current.record_version != expected_record_version:
                raise TemplateRecordVersionConflictError("shadow pointer record version is stale")
            target = self._load_version(connection, target_id)
            if (
                target.definition.family_id != family
                or target.lifecycle is not TemplateLifecycle.SHADOW
            ):
                raise TemplateLifecycleTransitionError(
                    "rollback target is not a shadow version in this family"
                )
            if current.version_id == target_id:
                raise TemplateLifecycleTransitionError(
                    "rollback target is already the current shadow version"
                )
            self._validate_shadow_version(
                connection,
                version_id=target_id,
            )
            next_version = current.record_version + 1
            result = connection.execute(
                text(
                    """
                    UPDATE template_shadow_pointers
                    SET version_id = :target_version_id,
                        record_version = :next_record_version,
                        updated_at = :updated_at
                    WHERE family_id = :family_id
                      AND record_version = :expected_record_version
                    """
                ),
                {
                    "target_version_id": target_id,
                    "next_record_version": next_version,
                    "updated_at": now,
                    "family_id": family,
                    "expected_record_version": expected_record_version,
                },
            )
            if result.rowcount != 1:
                raise TemplateRecordVersionConflictError("shadow pointer changed concurrently")
            pointer = ShadowPointerRecord(
                family_id=family,
                version_id=target_id,
                record_version=next_version,
            )
            self._insert_audit(
                connection,
                event_kind="template.shadow_rolled_back",
                family_id=family,
                version_id=target_id,
                actor_id=actor,
                developer_authorization_id=authorization,
                detail={
                    "from_version_id": current.version_id,
                    "reason": rollback_reason,
                    "to_version_id": target_id,
                },
                now=now,
            )
            self._save_idempotency(
                connection,
                operation=operation,
                idempotency_key=key,
                request_hash=request_hash,
                result_kind="shadow_pointer",
                result=_pointer_result_payload(pointer),
                now=now,
            )
            return pointer, True
