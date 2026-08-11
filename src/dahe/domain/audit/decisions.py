from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from dahe.domain.audit.errors import DomainContractError, SystemEvidenceError
from dahe.domain.audit.evidence import (
    AuditEvidence,
    EvidenceQuality,
    WeightEvidenceIssue,
    WeightFieldEvidence,
)
from dahe.domain.audit.ticket_roles import RoleIssue, assess_ticket_roles
from dahe.domain.audit.weights import (
    WeightComparison,
    WeightComparisonPolicy,
    WeightUnit,
    compare_weights,
    normalize_weight,
)


class AuditDecisionKind(StrEnum):
    PASS = "pass"
    REVIEW = "review"
    WEIGHT_MISMATCH = "weight_mismatch"
    SUSPECTED_PROBLEM = "suspected_problem"


class BusinessOutcome(StrEnum):
    NORMAL_READY = "normal_ready"
    AWAITING_REVIEW = "awaiting_review"
    CONFIRMED_PROBLEM = "confirmed_problem"


class DecisionReason(StrEnum):
    DUPLICATE_IMAGE = "duplicate_image"
    SUSPECTED_SWAPPED = "suspected_swapped"
    ROLE_CONFLICT = "role_conflict"
    ROLE_UNKNOWN = "role_unknown"
    ROLE_UNRELIABLE = "role_unreliable"
    MISSING_TICKET = "missing_ticket"
    PLATFORM_WEIGHT_MISSING = "platform_weight_missing"
    PLATFORM_WEIGHT_UNRELIABLE = "platform_weight_unreliable"
    PLATFORM_WEIGHT_UNIT_REQUIRES_REVIEW = "platform_weight_unit_requires_review"
    PLATFORM_WEIGHT_PRECISION_REQUIRES_REVIEW = (
        "platform_weight_precision_requires_review"
    )
    TICKET_NET_MISSING = "ticket_net_missing"
    TICKET_NET_UNRELIABLE = "ticket_net_unreliable"
    TICKET_WEIGHT_UNIT_REQUIRES_REVIEW = "ticket_weight_unit_requires_review"
    TICKET_WEIGHT_PRECISION_REQUIRES_REVIEW = (
        "ticket_weight_precision_requires_review"
    )
    TICKET_WEIGHT_FORMAT_SUSPICIOUS = "ticket_weight_format_suspicious"
    OCR_WEIGHT_DISAGREEMENT = "ocr_weight_disagreement"
    WEIGHT_MISMATCH = "weight_mismatch"


@dataclass(frozen=True, slots=True)
class AuditDecision:
    kind: AuditDecisionKind
    business_outcome: BusinessOutcome
    reasons: tuple[DecisionReason, ...]
    loading_comparison: WeightComparison | None
    unloading_comparison: WeightComparison | None

    def __post_init__(self) -> None:
        comparisons_present = (
            self.loading_comparison is not None
            and self.unloading_comparison is not None
        )
        if self.kind is AuditDecisionKind.PASS:
            if (
                self.business_outcome is not BusinessOutcome.NORMAL_READY
                or self.reasons
                or not comparisons_present
            ):
                raise DomainContractError("an automatic pass is internally inconsistent")
            assert self.loading_comparison is not None
            assert self.unloading_comparison is not None
            if (
                not self.loading_comparison.matches
                or not self.unloading_comparison.matches
            ):
                raise DomainContractError("an automatic pass requires two exact matches")
            return
        if self.business_outcome is not BusinessOutcome.AWAITING_REVIEW:
            raise DomainContractError(
                "a non-pass machine decision must await human review"
            )
        if not self.reasons:
            raise DomainContractError("a non-pass machine decision requires a reason")
        if self.kind is AuditDecisionKind.WEIGHT_MISMATCH:
            if not comparisons_present or DecisionReason.WEIGHT_MISMATCH not in self.reasons:
                raise DomainContractError(
                    "a weight mismatch requires completed comparisons"
                )
        elif comparisons_present:
            raise DomainContractError(
                "role or evidence review cannot contain final weight comparisons"
            )


def _ensure_no_required_system_failure(evidence: AuditEvidence) -> None:
    if evidence.loading_ticket_quality is EvidenceQuality.SYSTEM_FAILURE:
        raise SystemEvidenceError("loading ticket acquisition failed")
    if evidence.unloading_ticket_quality is EvidenceQuality.SYSTEM_FAILURE:
        raise SystemEvidenceError("unloading ticket acquisition failed")
    fields: tuple[tuple[str, WeightFieldEvidence], ...] = (
        ("platform loading weight", evidence.platform_loading_net),
        ("platform unloading weight", evidence.platform_unloading_net),
    )
    for label, field in fields:
        if field.quality is EvidenceQuality.SYSTEM_FAILURE:
            raise SystemEvidenceError(f"{label} acquisition failed")
    for label, ticket in (
        ("loading ticket", evidence.loading_ticket),
        ("unloading ticket", evidence.unloading_ticket),
    ):
        if ticket is None:
            continue
        if ticket.role_quality is EvidenceQuality.SYSTEM_FAILURE:
            raise SystemEvidenceError(f"{label} role classification failed")
        if ticket.weights.ordinary_net.quality is EvidenceQuality.SYSTEM_FAILURE:
            raise SystemEvidenceError(f"{label} ordinary net extraction failed")


def _role_decision(issue: RoleIssue) -> AuditDecision:
    if issue is RoleIssue.DUPLICATE_IMAGE:
        kind = AuditDecisionKind.SUSPECTED_PROBLEM
        reason = DecisionReason.DUPLICATE_IMAGE
    elif issue is RoleIssue.SUSPECTED_SWAPPED:
        kind = AuditDecisionKind.SUSPECTED_PROBLEM
        reason = DecisionReason.SUSPECTED_SWAPPED
    elif issue in {RoleIssue.BOTH_LOADING, RoleIssue.BOTH_UNLOADING}:
        kind = AuditDecisionKind.SUSPECTED_PROBLEM
        reason = DecisionReason.ROLE_CONFLICT
    elif issue is RoleIssue.ROLE_UNKNOWN:
        kind = AuditDecisionKind.REVIEW
        reason = DecisionReason.ROLE_UNKNOWN
    elif issue is RoleIssue.ROLE_UNRELIABLE:
        kind = AuditDecisionKind.REVIEW
        reason = DecisionReason.ROLE_UNRELIABLE
    else:
        kind = AuditDecisionKind.REVIEW
        reason = DecisionReason.MISSING_TICKET
    return AuditDecision(
        kind=kind,
        business_outcome=BusinessOutcome.AWAITING_REVIEW,
        reasons=(reason,),
        loading_comparison=None,
        unloading_comparison=None,
    )


def _weight_review_reasons(
    evidence: AuditEvidence,
    policy: WeightComparisonPolicy,
) -> tuple[DecisionReason, ...]:
    reasons: list[DecisionReason] = []
    for field in (evidence.platform_loading_net, evidence.platform_unloading_net):
        if field.quality is EvidenceQuality.MISSING:
            reasons.append(DecisionReason.PLATFORM_WEIGHT_MISSING)
        elif field.quality is not EvidenceQuality.RELIABLE:
            reasons.append(DecisionReason.PLATFORM_WEIGHT_UNRELIABLE)
        else:
            assert field.reading is not None
            if field.reading.unit is not WeightUnit.TONNE:
                reasons.append(
                    DecisionReason.PLATFORM_WEIGHT_UNIT_REQUIRES_REVIEW
                )
            elif normalize_weight(field.reading, policy).comparison_tonnes is None:
                reasons.append(
                    DecisionReason.PLATFORM_WEIGHT_PRECISION_REQUIRES_REVIEW
                )
    for ticket in (evidence.loading_ticket, evidence.unloading_ticket):
        if ticket is None:
            continue
        field = ticket.weights.ordinary_net
        if field.issue is WeightEvidenceIssue.FORMAT_SUSPICIOUS:
            reasons.append(DecisionReason.TICKET_WEIGHT_FORMAT_SUSPICIOUS)
        elif field.issue is WeightEvidenceIssue.RUNTIME_DISAGREEMENT:
            reasons.append(DecisionReason.OCR_WEIGHT_DISAGREEMENT)
        elif field.quality is EvidenceQuality.MISSING:
            reasons.append(DecisionReason.TICKET_NET_MISSING)
        elif field.quality is not EvidenceQuality.RELIABLE:
            reasons.append(DecisionReason.TICKET_NET_UNRELIABLE)
        else:
            assert field.reading is not None
            if field.reading.unit is not WeightUnit.TONNE:
                reasons.append(DecisionReason.TICKET_WEIGHT_UNIT_REQUIRES_REVIEW)
            elif normalize_weight(field.reading, policy).comparison_tonnes is None:
                reasons.append(
                    DecisionReason.TICKET_WEIGHT_PRECISION_REQUIRES_REVIEW
                )
    return tuple(dict.fromkeys(reasons))


def _ticket_acquisition_decision(evidence: AuditEvidence) -> AuditDecision | None:
    if (
        evidence.loading_ticket_quality is EvidenceQuality.RELIABLE
        and evidence.unloading_ticket_quality is EvidenceQuality.RELIABLE
    ):
        return None
    return AuditDecision(
        kind=AuditDecisionKind.REVIEW,
        business_outcome=BusinessOutcome.AWAITING_REVIEW,
        reasons=(DecisionReason.MISSING_TICKET,),
        loading_comparison=None,
        unloading_comparison=None,
    )


def _evaluate_weights(
    evidence: AuditEvidence,
    policy: WeightComparisonPolicy,
) -> AuditDecision:
    review_reasons = _weight_review_reasons(evidence, policy)
    if review_reasons:
        return AuditDecision(
            kind=AuditDecisionKind.REVIEW,
            business_outcome=BusinessOutcome.AWAITING_REVIEW,
            reasons=review_reasons,
            loading_comparison=None,
            unloading_comparison=None,
        )

    assert evidence.loading_ticket is not None
    assert evidence.unloading_ticket is not None
    platform_loading = evidence.platform_loading_net.reading
    platform_unloading = evidence.platform_unloading_net.reading
    ticket_loading = evidence.loading_ticket.weights.ordinary_net.reading
    ticket_unloading = evidence.unloading_ticket.weights.ordinary_net.reading
    assert platform_loading is not None
    assert platform_unloading is not None
    assert ticket_loading is not None
    assert ticket_unloading is not None

    loading_comparison = compare_weights(
        platform=platform_loading,
        ticket=ticket_loading,
        policy=policy,
    )
    unloading_comparison = compare_weights(
        platform=platform_unloading,
        ticket=ticket_unloading,
        policy=policy,
    )
    if not loading_comparison.matches or not unloading_comparison.matches:
        return AuditDecision(
            kind=AuditDecisionKind.WEIGHT_MISMATCH,
            business_outcome=BusinessOutcome.AWAITING_REVIEW,
            reasons=(DecisionReason.WEIGHT_MISMATCH,),
            loading_comparison=loading_comparison,
            unloading_comparison=unloading_comparison,
        )
    return AuditDecision(
        kind=AuditDecisionKind.PASS,
        business_outcome=BusinessOutcome.NORMAL_READY,
        reasons=(),
        loading_comparison=loading_comparison,
        unloading_comparison=unloading_comparison,
    )


def evaluate_audit(
    evidence: AuditEvidence,
    policy: WeightComparisonPolicy,
) -> AuditDecision:
    _ensure_no_required_system_failure(evidence)
    acquisition_decision = _ticket_acquisition_decision(evidence)
    if acquisition_decision is not None:
        return acquisition_decision
    roles = assess_ticket_roles(evidence.loading_ticket, evidence.unloading_ticket)
    if roles.issue is not None:
        return _role_decision(roles.issue)
    return _evaluate_weights(evidence, policy)
