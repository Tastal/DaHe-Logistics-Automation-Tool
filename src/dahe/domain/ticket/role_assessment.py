from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum

from dahe.domain.audit.errors import DomainContractError
from dahe.domain.audit.evidence import EvidenceQuality
from dahe.domain.audit.ticket_roles import TicketRole

SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ROLE_ASSESSMENT_ALGORITHM_VERSION = "source-consensus-v2"


class RoleEvidenceSource(StrEnum):
    FIXED_TEXT = "fixed_text"
    TEMPLATE = "template"
    LAYOUT = "layout"


def _require_text(value: str, label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise DomainContractError(f"{label} is required")


def _require_sha256(value: str, label: str) -> None:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise DomainContractError(f"{label} must be a lowercase SHA-256")


def _require_probability(value: Decimal, label: str) -> None:
    if (
        not isinstance(value, Decimal)
        or not value.is_finite()
        or not 0 <= value <= 1
    ):
        raise DomainContractError(f"{label} must be a decimal between zero and one")


def _decimal_text(value: Decimal) -> str:
    normalized = value.normalize()
    if normalized == 0:
        return "0"
    return format(normalized, "f")


@dataclass(frozen=True, slots=True)
class RoleEvidence:
    source: RoleEvidenceSource
    loading_score: Decimal
    unloading_score: Decimal
    matched_ids: tuple[str, ...]
    evidence_fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.source, RoleEvidenceSource):
            raise DomainContractError("role evidence source is invalid")
        _require_probability(self.loading_score, "loading score")
        _require_probability(self.unloading_score, "unloading score")
        if any(not isinstance(item, str) or not item.strip() for item in self.matched_ids):
            raise DomainContractError("matched role evidence identifiers are invalid")
        if len(set(self.matched_ids)) != len(self.matched_ids):
            raise DomainContractError("matched role evidence identifiers must be unique")
        _require_sha256(self.evidence_fingerprint, "role evidence fingerprint")


@dataclass(frozen=True, slots=True)
class RoleObservation:
    image_sha256: str
    orientation_degrees: int
    ticket_likelihood: Decimal
    evidence: tuple[RoleEvidence, ...]

    def __post_init__(self) -> None:
        _require_sha256(self.image_sha256, "role observation image identity")
        if self.orientation_degrees not in {0, 90, 180, 270}:
            raise DomainContractError("role observation orientation is invalid")
        _require_probability(self.ticket_likelihood, "ticket likelihood")
        sources = tuple(item.source for item in self.evidence)
        if len(set(sources)) != len(sources):
            raise DomainContractError(
                "a role observation can contain only one result per evidence source"
            )


@dataclass(frozen=True, slots=True)
class RoleAssessmentPolicy:
    minimum_score: Decimal
    minimum_margin: Decimal
    minimum_sources: int
    minimum_ticket_likelihood: Decimal
    high_confidence_score: Decimal
    version: str

    def __post_init__(self) -> None:
        _require_probability(self.minimum_score, "minimum role score")
        _require_probability(self.minimum_margin, "minimum role margin")
        _require_probability(
            self.minimum_ticket_likelihood,
            "minimum ticket likelihood",
        )
        _require_probability(
            self.high_confidence_score,
            "high confidence role score",
        )
        if (
            not isinstance(self.minimum_sources, int)
            or not 1 <= self.minimum_sources <= len(RoleEvidenceSource)
        ):
            raise DomainContractError("minimum role evidence sources are invalid")
        if self.high_confidence_score < self.minimum_score:
            raise DomainContractError(
                "high confidence role score cannot be below the minimum score"
            )
        _require_text(self.version, "role assessment policy version")


@dataclass(frozen=True, slots=True)
class TicketRoleAssessment:
    role: TicketRole
    quality: EvidenceQuality
    confidence: Decimal
    high_confidence: bool
    evidence: tuple[RoleEvidence, ...]
    rule_version: str
    fingerprint: str

    def __post_init__(self) -> None:
        if not isinstance(self.role, TicketRole):
            raise DomainContractError("assessed ticket role is invalid")
        if not isinstance(self.quality, EvidenceQuality):
            raise DomainContractError("ticket role quality is invalid")
        _require_probability(self.confidence, "ticket role confidence")
        if not isinstance(self.high_confidence, bool):
            raise DomainContractError("ticket role confidence flag is invalid")
        if self.role is TicketRole.UNKNOWN:
            if self.quality is EvidenceQuality.RELIABLE or self.high_confidence:
                raise DomainContractError(
                    "an unknown ticket role cannot be reliable or high confidence"
                )
        elif self.quality is not EvidenceQuality.RELIABLE:
            raise DomainContractError("a classified ticket role must be reliable")
        _require_text(self.rule_version, "ticket role rule version")
        _require_sha256(self.fingerprint, "ticket role assessment fingerprint")


def _average(values: tuple[Decimal, ...]) -> Decimal:
    if not values:
        return Decimal(0)
    return sum(values, start=Decimal(0)) / Decimal(len(values))


def _evidence_payload(evidence: RoleEvidence) -> dict[str, object]:
    return {
        "evidence_fingerprint": evidence.evidence_fingerprint,
        "loading_score": _decimal_text(evidence.loading_score),
        "matched_ids": sorted(evidence.matched_ids),
        "source": evidence.source.value,
        "unloading_score": _decimal_text(evidence.unloading_score),
    }


def _assessment_fingerprint(
    *,
    observation: RoleObservation,
    policy: RoleAssessmentPolicy,
    role: TicketRole,
    confidence: Decimal,
) -> str:
    payload = {
        "evidence": [
            _evidence_payload(item)
            for item in sorted(observation.evidence, key=lambda value: value.source.value)
        ],
        "image_sha256": observation.image_sha256,
        "orientation_degrees": observation.orientation_degrees,
        "outcome": {
            "confidence": _decimal_text(confidence),
            "role": role.value,
        },
        "policy": {
            "high_confidence_score": _decimal_text(policy.high_confidence_score),
            "minimum_margin": _decimal_text(policy.minimum_margin),
            "minimum_score": _decimal_text(policy.minimum_score),
            "minimum_sources": policy.minimum_sources,
            "minimum_ticket_likelihood": _decimal_text(
                policy.minimum_ticket_likelihood
            ),
            "version": policy.version,
        },
        "schema_version": 1,
        "assessment_algorithm": ROLE_ASSESSMENT_ALGORITHM_VERSION,
        "ticket_likelihood": _decimal_text(observation.ticket_likelihood),
    }
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _supported_role(
    evidence: RoleEvidence,
    policy: RoleAssessmentPolicy,
) -> TicketRole | None:
    loading_credible = evidence.loading_score >= policy.minimum_score
    unloading_credible = evidence.unloading_score >= policy.minimum_score
    if loading_credible and unloading_credible:
        return TicketRole.UNKNOWN
    if not loading_credible and not unloading_credible:
        return None
    if abs(evidence.loading_score - evidence.unloading_score) < policy.minimum_margin:
        return None
    return TicketRole.LOADING if loading_credible else TicketRole.UNLOADING


def assess_ticket_role(
    observation: RoleObservation,
    policy: RoleAssessmentPolicy,
) -> TicketRoleAssessment:
    if not isinstance(observation, RoleObservation):
        raise DomainContractError("ticket role observation is invalid")
    if not isinstance(policy, RoleAssessmentPolicy):
        raise DomainContractError("ticket role assessment policy is invalid")

    supported = tuple(
        (item, _supported_role(item, policy))
        for item in observation.evidence
    )
    internally_conflicting = any(
        role is TicketRole.UNKNOWN
        for _, role in supported
    )
    directional_roles = {
        role
        for _, role in supported
        if role in {TicketRole.LOADING, TicketRole.UNLOADING}
    }
    sources_conflict = len(directional_roles) > 1
    effective_evidence = tuple(
        item
        for item, role in supported
        if role in {TicketRole.LOADING, TicketRole.UNLOADING}
    )
    loading_score = _average(
        tuple(item.loading_score for item in effective_evidence)
    )
    unloading_score = _average(
        tuple(item.unloading_score for item in effective_evidence)
    )
    source_count = len(effective_evidence)
    winner = max(loading_score, unloading_score)
    margin = abs(loading_score - unloading_score)
    eligible = (
        not internally_conflicting
        and not sources_conflict
        and observation.ticket_likelihood >= policy.minimum_ticket_likelihood
        and source_count >= policy.minimum_sources
        and winner >= policy.minimum_score
        and margin >= policy.minimum_margin
    )
    if not eligible:
        role = TicketRole.UNKNOWN
        quality = EvidenceQuality.UNCERTAIN
        confidence = winner
        high_confidence = False
    else:
        role = (
            TicketRole.LOADING
            if loading_score > unloading_score
            else TicketRole.UNLOADING
        )
        quality = EvidenceQuality.RELIABLE
        confidence = winner
        high_confidence = confidence >= policy.high_confidence_score
    ordered_evidence = tuple(
        sorted(observation.evidence, key=lambda value: value.source.value)
    )
    return TicketRoleAssessment(
        role=role,
        quality=quality,
        confidence=confidence,
        high_confidence=high_confidence,
        evidence=ordered_evidence,
        rule_version=policy.version,
        fingerprint=_assessment_fingerprint(
            observation=observation,
            policy=policy,
            role=role,
            confidence=confidence,
        ),
    )


@dataclass(frozen=True, slots=True)
class LabeledRoleResult:
    sample_id: str
    truth: TicketRole
    assessment: TicketRoleAssessment
    elapsed_ms: Decimal

    def __post_init__(self) -> None:
        _require_text(self.sample_id, "role evaluation sample_id")
        if not isinstance(self.truth, TicketRole):
            raise DomainContractError("role evaluation truth is invalid")
        if not isinstance(self.assessment, TicketRoleAssessment):
            raise DomainContractError("role evaluation assessment is invalid")
        if (
            not isinstance(self.elapsed_ms, Decimal)
            or not self.elapsed_ms.is_finite()
            or self.elapsed_ms < 0
        ):
            raise DomainContractError("role evaluation elapsed time is invalid")


@dataclass(frozen=True, slots=True)
class RoleMetrics:
    sample_count: int
    confusion_matrix: dict[str, dict[str, int]]
    unknown_rate: Decimal
    high_confidence_error_count: int
    p50_elapsed_ms: Decimal
    p95_elapsed_ms: Decimal


def _nearest_rank(values: tuple[Decimal, ...], percentile: Decimal) -> Decimal:
    rank = max(1, math.ceil(float(percentile * Decimal(len(values)))))
    return sorted(values)[rank - 1]


def summarize_role_metrics(
    results: tuple[LabeledRoleResult, ...],
) -> RoleMetrics:
    if not results:
        raise DomainContractError("role metrics require at least one labeled result")
    if any(not isinstance(item, LabeledRoleResult) for item in results):
        raise DomainContractError("role metrics contain an invalid result")
    sample_ids = tuple(item.sample_id for item in results)
    if len(set(sample_ids)) != len(sample_ids):
        raise DomainContractError("role metrics sample identifiers must be unique")

    role_names = tuple(role.value for role in TicketRole)
    confusion = {
        truth: {prediction: 0 for prediction in role_names}
        for truth in role_names
    }
    unknown_count = 0
    high_confidence_error_count = 0
    elapsed: list[Decimal] = []
    for item in results:
        prediction = item.assessment.role
        confusion[item.truth.value][prediction.value] += 1
        if prediction is TicketRole.UNKNOWN:
            unknown_count += 1
        if item.assessment.high_confidence and prediction is not item.truth:
            high_confidence_error_count += 1
        elapsed.append(item.elapsed_ms)

    elapsed_values = tuple(elapsed)
    return RoleMetrics(
        sample_count=len(results),
        confusion_matrix=confusion,
        unknown_rate=Decimal(unknown_count) / Decimal(len(results)),
        high_confidence_error_count=high_confidence_error_count,
        p50_elapsed_ms=_nearest_rank(elapsed_values, Decimal("0.50")),
        p95_elapsed_ms=_nearest_rank(elapsed_values, Decimal("0.95")),
    )
