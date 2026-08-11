from __future__ import annotations

import math
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from typing import cast

from dahe.application.template_studio.candidate_role_ocr_evidence import (
    _ValidatedEvidence,
)
from dahe.application.template_studio.candidate_role_source_authority import (
    CandidateRoleEvaluationError,
    _canonical_sha256,
    _TruthImage,
    _TruthPair,
)
from dahe.application.template_studio.development_evaluation import (
    default_development_policy,
)
from dahe.application.template_studio.matcher import (
    match_ticket_role_for_development_evaluation,
)
from dahe.domain.audit.errors import (
    DomainContractError,
    SystemEvidenceError,
)
from dahe.domain.audit.evidence import (
    EvidenceQuality,
    TicketEvidence,
    TicketWeightEvidence,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import (
    RoleIssue,
    TicketRole,
    TicketSlot,
    assess_ticket_roles,
)
from dahe.domain.ticket.role_assessment import (
    LabeledRoleResult,
    RoleEvidenceSource,
    TicketRoleAssessment,
    summarize_role_metrics,
)
from dahe.domain.ticket.templates import TemplateVersion

_RUNTIME_KINDS = ("cpu", "gpu")
_ROLES = ("loading", "unknown", "unloading")
_ORIENTATIONS = (0, 90, 180, 270)
_PAIR_STATUSES = (
    "duplicate",
    "normal",
    "same_role",
    "swapped",
    "unknown",
)


@dataclass(frozen=True, slots=True)
class _EvaluatedImage:
    truth: _TruthImage
    assessment: TicketRoleAssessment
    detected_orientation_degrees: int
    matcher_elapsed_ms: Decimal
    worker_elapsed_ms: Decimal
    wall_elapsed_ms: Decimal


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


def _rate(
    count: int,
    sample_count: int,
) -> str:
    if sample_count <= 0:
        raise CandidateRoleEvaluationError("metric sample count must be positive")
    return _decimal_text(Decimal(count) / Decimal(sample_count))


def _nearest_rank(
    values: Sequence[Decimal],
    percentile: Decimal,
) -> Decimal:
    if not values:
        raise CandidateRoleEvaluationError("latency metric requires samples")
    rank = max(
        1,
        math.ceil(float(percentile * Decimal(len(values)))),
    )
    return sorted(values)[rank - 1]


def _latency(
    values: Sequence[Decimal],
) -> dict[str, object]:
    return {
        "p50": _decimal_text(_nearest_rank(values, Decimal("0.50"))),
        "p95": _decimal_text(_nearest_rank(values, Decimal("0.95"))),
        "sample_count": len(values),
    }


def _missing_weights() -> TicketWeightEvidence:
    missing = WeightFieldEvidence(
        reading=None,
        quality=EvidenceQuality.MISSING,
    )
    return TicketWeightEvidence(
        ordinary_net=missing,
        factory_net=missing,
        gross=missing,
        tare=missing,
    )


def _pair_ticket(
    *,
    result: _EvaluatedImage,
    slot: TicketSlot,
) -> TicketEvidence:
    return TicketEvidence(
        slot=slot,
        image_sha256=result.truth.image_sha256,
        machine_role=result.assessment.role,
        role_quality=result.assessment.quality,
        weights=_missing_weights(),
        extraction_fingerprint=_canonical_sha256(
            {
                "image_sha256": result.truth.image_sha256,
                "purpose": ("candidate_development_role_pair"),
            }
        ),
        role_fingerprint=result.assessment.fingerprint,
    )


def _pair_status(
    issue: RoleIssue | None,
) -> str:
    if issue is None:
        return "normal"
    if issue is RoleIssue.DUPLICATE_IMAGE:
        return "duplicate"
    if issue is RoleIssue.SUSPECTED_SWAPPED:
        return "swapped"
    if issue in {
        RoleIssue.BOTH_LOADING,
        RoleIssue.BOTH_UNLOADING,
    }:
        return "same_role"
    return "unknown"


def _orientation_metrics(
    results: Sequence[_EvaluatedImage],
) -> dict[str, object]:
    confusion = {
        str(expected): {str(predicted): 0 for predicted in _ORIENTATIONS}
        for expected in _ORIENTATIONS
    }
    match_count = 0
    for result in results:
        expected = result.truth.orientation_degrees
        predicted = result.detected_orientation_degrees
        confusion[str(expected)][str(predicted)] += 1
        match_count += expected == predicted
    return {
        "agreement_rate": _rate(
            match_count,
            len(results),
        ),
        "confusion_matrix": confusion,
        "match_count": match_count,
        "mismatch_count": len(results) - match_count,
        "sample_count": len(results),
    }


def _pair_metrics(
    pairs: Sequence[_TruthPair],
    *,
    results_by_image: Mapping[str, _EvaluatedImage],
) -> dict[str, object]:
    expected_counts: Counter[str] = Counter()
    predicted_counts: Counter[str] = Counter()
    confusion = {
        expected: {predicted: 0 for predicted in _PAIR_STATUSES} for expected in _PAIR_STATUSES
    }
    rows: list[dict[str, object]] = []
    for pair in pairs:
        try:
            loading = results_by_image[pair.loading_image_sha256]
            unloading = results_by_image[pair.unloading_image_sha256]
            assessment = assess_ticket_roles(
                _pair_ticket(
                    result=loading,
                    slot=TicketSlot.LOADING,
                ),
                _pair_ticket(
                    result=unloading,
                    slot=TicketSlot.UNLOADING,
                ),
            )
        except (
            DomainContractError,
            KeyError,
            SystemEvidenceError,
        ) as exc:
            raise CandidateRoleEvaluationError(
                "candidate role pair evaluation failed technically"
            ) from exc
        predicted = _pair_status(assessment.issue)
        expected_counts[pair.expected_status] += 1
        predicted_counts[predicted] += 1
        confusion[pair.expected_status][predicted] += 1
        rows.append(
            {
                "domain_issue": (None if assessment.issue is None else assessment.issue.value),
                "expected_status": pair.expected_status,
                "matches_truth": (predicted == pair.expected_status),
                "pair_sha256": pair.subject_sha256,
                "predicted_status": predicted,
            }
        )
    return {
        "confusion_matrix": confusion,
        "expected_counts": {status: expected_counts[status] for status in _PAIR_STATUSES},
        "mismatch_count": sum(
            not cast(bool, row["matches_truth"])
            for row in rows
        ),
        "predicted_counts": {status: predicted_counts[status] for status in _PAIR_STATUSES},
        "results": sorted(
            rows,
            key=lambda row: cast(str, row["pair_sha256"]),
        ),
        "sample_count": len(rows),
    }


def _direct_loading_unloading_error_count(
    results: Sequence[_EvaluatedImage],
) -> int:
    direct_roles = {TicketRole.LOADING, TicketRole.UNLOADING}
    return sum(
        result.truth.role in direct_roles
        and result.assessment.role in direct_roles
        and result.truth.role is not result.assessment.role
        for result in results
    )


def _candidate_support(
    results: Sequence[_EvaluatedImage],
    *,
    candidates: Sequence[TemplateVersion],
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    supported_count = 0
    for candidate in sorted(
        candidates,
        key=lambda item: item.version_id,
    ):
        subjects = sorted(
            result.truth.subject_sha256
            for result in results
            if result.truth.role is candidate.definition.role
            and result.assessment.role is result.truth.role
            and any(
                evidence.source is RoleEvidenceSource.TEMPLATE
                and candidate.version_id in evidence.matched_ids
                for evidence in result.assessment.evidence
            )
        )
        supported_count += bool(subjects)
        rows.append(
            {
                "candidate_version_id": candidate.version_id,
                "support_count": len(subjects),
                "supporting_subject_sha256s": subjects,
            }
        )
    return {
        "results": rows,
        "support_contract": (
            "human_role_correct_and_template_evidence_hit_and_"
            "final_role_correct"
        ),
        "supported_candidate_count": supported_count,
    }


def _runtime_payload(
    runtime_kind: str,
    *,
    validated: _ValidatedEvidence,
    candidates: tuple[TemplateVersion, ...],
    current_shadow: tuple[TemplateVersion, ...],
) -> tuple[
    dict[str, object],
    dict[str, _EvaluatedImage],
]:
    policy = default_development_policy()
    evaluated: list[_EvaluatedImage] = []
    by_image: dict[str, _EvaluatedImage] = {}
    try:
        for truth in validated.truth_images:
            attempt = validated.attempts[(truth.image_sha256, runtime_kind)]
            run = match_ticket_role_for_development_evaluation(
                attempt.role_input,
                candidates=candidates,
                current_shadow=current_shadow,
                policy=policy,
            )
            result = _EvaluatedImage(
                truth=truth,
                assessment=run.assessment,
                detected_orientation_degrees=(run.observation.orientation_degrees),
                matcher_elapsed_ms=run.elapsed_ms,
                worker_elapsed_ms=attempt.worker_elapsed_ms,
                wall_elapsed_ms=attempt.wall_elapsed_ms,
            )
            evaluated.append(result)
            by_image[truth.image_sha256] = result
    except (
        DomainContractError,
        KeyError,
        ValueError,
    ) as exc:
        raise CandidateRoleEvaluationError("candidate role matcher failed technically") from exc
    if len(evaluated) != 100 or len(by_image) != 100:
        raise CandidateRoleEvaluationError("candidate role result coverage is incomplete")
    labeled = tuple(
        LabeledRoleResult(
            sample_id=result.truth.subject_sha256,
            truth=result.truth.role,
            assessment=result.assessment,
            elapsed_ms=result.matcher_elapsed_ms,
        )
        for result in evaluated
    )
    try:
        role_metrics = summarize_role_metrics(labeled)
    except DomainContractError as exc:
        raise CandidateRoleEvaluationError("candidate role metrics failed technically") from exc
    subject_rows = [
        {
            "assessment_sha256": result.assessment.fingerprint,
            "confidence": _decimal_text(result.assessment.confidence),
            "detected_orientation_degrees": (result.detected_orientation_degrees),
            "expected_orientation_degrees": (result.truth.orientation_degrees),
            "high_confidence": (result.assessment.high_confidence),
            "matched_template_version_ids": sorted(
                {
                    matched_id
                    for evidence in result.assessment.evidence
                    if evidence.source is RoleEvidenceSource.TEMPLATE
                    for matched_id in evidence.matched_ids
                }
            ),
            "prediction": result.assessment.role.value,
            "subject_sha256": result.truth.subject_sha256,
            "truth": result.truth.role.value,
        }
        for result in evaluated
    ]
    return (
        {
            "candidate_support": _candidate_support(
                evaluated,
                candidates=candidates,
            ),
            "matcher_latency_ms": {
                "p50": _decimal_text(role_metrics.p50_elapsed_ms),
                "p95": _decimal_text(role_metrics.p95_elapsed_ms),
                "sample_count": role_metrics.sample_count,
            },
            "ocr_latency_ms": {
                "wall": _latency([result.wall_elapsed_ms for result in evaluated]),
                "worker": _latency([result.worker_elapsed_ms for result in evaluated]),
            },
            "orientation": _orientation_metrics(evaluated),
            "pair_status": _pair_metrics(
                validated.truth_pairs,
                results_by_image=by_image,
            ),
            "role": {
                "confusion_matrix": (role_metrics.confusion_matrix),
                "direct_loading_unloading_error_count": (
                    _direct_loading_unloading_error_count(evaluated)
                ),
                "high_confidence_error_count": (role_metrics.high_confidence_error_count),
                "results": sorted(
                    subject_rows,
                    key=lambda row: cast(
                        str,
                        row["subject_sha256"],
                    ),
                ),
                "unknown_rate": _decimal_text(role_metrics.unknown_rate),
            },
            "runtime_kind": runtime_kind,
            "sample_count": role_metrics.sample_count,
        },
        by_image,
    )


def _role_consistency(
    *,
    cpu: Mapping[str, _EvaluatedImage],
    gpu: Mapping[str, _EvaluatedImage],
) -> dict[str, object]:
    if set(cpu) != set(gpu) or len(cpu) != 100:
        raise CandidateRoleEvaluationError("CPU/GPU role result membership is incomplete")
    mismatches: list[dict[str, object]] = []
    match_count = 0
    for image_sha256 in sorted(cpu):
        cpu_result = cpu[image_sha256]
        gpu_result = gpu[image_sha256]
        if cpu_result.assessment.role is gpu_result.assessment.role:
            match_count += 1
            continue
        mismatches.append(
            {
                "cpu_role": cpu_result.assessment.role.value,
                "gpu_role": gpu_result.assessment.role.value,
                "subject_sha256": (cpu_result.truth.subject_sha256),
            }
        )
    return {
        "agreement_rate": _rate(match_count, len(cpu)),
        "match_count": match_count,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "sample_count": len(cpu),
    }
